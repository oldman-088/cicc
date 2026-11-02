"""Synthetic contract fixtures; no call to the live CISA service is made."""
from datetime import datetime, timezone
import json
import httpx
import pytest
from app.connectors.cisa_kev import ConnectorError, FEED_URL, MAX_FEED_BYTES, fetch_snapshot, parse_snapshot

COLLECTED = datetime(2026, 1, 2, tzinfo=timezone.utc)

def feed():
    return {'catalogVersion':'test-fixture', 'dateReleased':'2026-01-01T10:00:00Z', 'count':1,
        'vulnerabilities':[{'cveID':'CVE-2099-0001', 'vendorProject':'Synthetic vendor', 'product':'Synthetic product',
        'vulnerabilityName':'Synthetic vulnerability', 'dateAdded':'2026-01-01', 'shortDescription':'Synthetic fixture only.',
        'requiredAction':'Review the synthetic fixture.', 'dueDate':'2026-02-01', 'knownRansomwareCampaignUse':'Unknown'}]}

def encoded(doc): return json.dumps(doc).encode()

def test_parse_preserves_source_and_dates_without_inventing_confidence():
    snapshot = parse_snapshot(encoded(feed()), collected_at=COLLECTED)
    assert snapshot.catalog_version == 'test-fixture' and snapshot.collected_at == COLLECTED
    assert snapshot.records[0].cve_id == 'CVE-2099-0001'
    assert snapshot.records[0].source_reference == FEED_URL
    assert snapshot.records[0].ransomware_use == 'Unknown'
    assert not hasattr(snapshot.records[0], 'confidence')

@pytest.mark.parametrize('mutation', ['bad_count', 'bad_cve', 'duplicate', 'bad_date', 'bad_ransomware', 'missing_source_field'])
def test_invalid_feed_fails_entire_snapshot(mutation):
    doc = feed()
    if mutation == 'bad_count': doc['count'] = 2
    elif mutation == 'bad_cve': doc['vulnerabilities'][0]['cveID'] = 'CVE-not-valid'
    elif mutation == 'duplicate': doc['vulnerabilities'].append(doc['vulnerabilities'][0].copy()); doc['count'] = 2
    elif mutation == 'bad_date': doc['vulnerabilities'][0]['dateAdded'] = '2026-02-31'
    elif mutation == 'bad_ransomware': doc['vulnerabilities'][0]['knownRansomwareCampaignUse'] = 'maybe'
    else: doc['vulnerabilities'][0].pop('vendorProject')
    with pytest.raises(ConnectorError): parse_snapshot(encoded(doc), collected_at=COLLECTED)

def test_fetch_uses_fixed_url_retries_and_returns_fixture():
    calls, sleeps = [], []
    def handler(request):
        calls.append(request)
        if len(calls) == 1: return httpx.Response(429, headers={'Retry-After':'2'})
        return httpx.Response(200, json=feed())
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        snapshot = fetch_snapshot(client=client, sleep=sleeps.append)
    assert snapshot.records[0].cve_id == 'CVE-2099-0001'
    assert all(str(r.url) == FEED_URL and r.method == 'GET' for r in calls)
    assert sleeps == [2]

def test_redirect_is_not_followed_even_with_client_setting():
    calls = []
    def handler(request):
        calls.append(request); return httpx.Response(302, headers={'Location':'http://127.0.0.1/secret'})
    with httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
        with pytest.raises(ConnectorError, match='HTTP 302'): fetch_snapshot(client=client, sleep=lambda _: None)
    assert len(calls) == 1

def test_size_limit_and_safe_errors():
    def too_large(request): return httpx.Response(200, headers={'Content-Length':str(MAX_FEED_BYTES+1)}, content=b'')
    with httpx.Client(transport=httpx.MockTransport(too_large)) as client:
        with pytest.raises(ConnectorError, match='size limit'): fetch_snapshot(client=client, sleep=lambda _:None)
    with pytest.raises(ConnectorError, match='JSON'): parse_snapshot(b'not json', collected_at=COLLECTED)
    with pytest.raises(ValueError): parse_snapshot(encoded(feed()), collected_at=datetime(2026,1,1))

def test_failure_and_network_retry_are_not_faked():
    calls, sleeps = [], []
    def handler(request):
        calls.append(request); raise httpx.ConnectError('private diagnostic', request=request)
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ConnectorError, match='Source connection failed') as error:
            fetch_snapshot(client=client, sleep=sleeps.append)
    assert len(calls) == 3 and sleeps == [1,2]
    assert 'private diagnostic' not in str(error.value)

def test_streamed_content_limit_and_status_failure(monkeypatch):
    import app.connectors.cisa_kev as connector
    monkeypatch.setattr(connector, 'MAX_FEED_BYTES', 10)
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b'12345678901', headers={'Content-Length':'1'}))) as client:
        with pytest.raises(ConnectorError, match='size limit'): fetch_snapshot(client=client, sleep=lambda _: None)
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(503))) as client:
        with pytest.raises(ConnectorError, match='HTTP 503'): fetch_snapshot(client=client, sleep=lambda _:None, max_attempts=1)

def test_timeout_is_retried_and_ambiguous_timestamp_is_rejected():
    calls = []
    def handler(request):
        calls.append(request)
        if len(calls) == 1: raise httpx.ReadTimeout('private timeout', request=request)
        return httpx.Response(200, json=feed())
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert fetch_snapshot(client=client, sleep=lambda _:None).catalog_version == 'test-fixture'
    doc = feed(); doc['dateReleased'] = '2026-01-01T10:00:00'
    with pytest.raises(ConnectorError, match='release timestamp'): parse_snapshot(encoded(doc), collected_at=COLLECTED)

def test_long_retry_after_fails_instead_of_retrying_early():
    calls=[]
    def handler(request):
        calls.append(request); return httpx.Response(429, headers={'Retry-After':'120'})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ConnectorError, match='retry delay'): fetch_snapshot(client=client, sleep=lambda _:None)
    assert len(calls) == 1

def test_fetch_budget_stops_slow_stream_and_retry_without_early_retry():
    from app.connectors.cisa_kev import FETCH_BUDGET_SECONDS
    clock = [0.0]
    class SlowStream(httpx.SyncByteStream):
        def __iter__(self):
            clock[0] = FETCH_BUDGET_SECONDS + 1
            yield b'{}'
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, stream=SlowStream()))) as client:
        with pytest.raises(ConnectorError, match='time budget'):
            fetch_snapshot(client=client, monotonic=lambda:clock[0])
    clock[0] = 0.0
    sleeps, calls = [], []
    def retry(request):
        calls.append(request)
        clock[0] = FETCH_BUDGET_SECONDS - 1
        return httpx.Response(429, headers={'Retry-After':'2'})
    with httpx.Client(transport=httpx.MockTransport(retry)) as client:
        with pytest.raises(ConnectorError, match='time budget'):
            fetch_snapshot(client=client, sleep=sleeps.append, monotonic=lambda:clock[0])
    assert len(calls) == 1 and sleeps == []
