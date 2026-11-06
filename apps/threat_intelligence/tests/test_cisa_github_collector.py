"""Tests use EXPERIMENTAL_DEMO_DATA_ONLY synthetic data unless live opt-in."""
import base64
import hashlib
import json
import os
from urllib.error import HTTPError, URLError

import pytest
from apps.threat_intelligence.cisa_github_collector import (
    API, METADATA_URL, CollectionError, fetch_catalog, parse_catalog,
)


def sample():
    return {'title':'EXPERIMENTAL_DEMO_DATA_ONLY', 'catalogVersion':'fixture',
        'dateReleased':'2026-01-01T00:00:00Z', 'count':1,
        'vulnerabilities':[{'cveID':'CVE-2099-0001', 'vendorProject':'fixture', 'product':'fixture',
            'vulnerabilityName':'fixture', 'dateAdded':'2026-01-01', 'shortDescription':'fixture',
            'requiredAction':'fixture', 'dueDate':'2026-02-01', 'knownRansomwareCampaignUse':'Unknown',
            'experimental_label':'EXPERIMENTAL_DEMO_DATA_ONLY', 'futureField':'preserved'}]}


def fixture_transport(data):
    raw = json.dumps(data).encode()
    sha = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    responses = {METADATA_URL: json.dumps({'sha':sha,'type':'file','path':'known_exploited_vulnerabilities.json','size':len(raw)}).encode(), API + '/git/blobs/' + sha:
        json.dumps({'sha':sha, 'encoding':'base64', 'content':base64.b64encode(raw).decode(), 'size':len(raw)}).encode()}
    def transport(url, timeout): return responses[url]
    return transport, sha


def test_fixture_parsing_preserves_unknown_content_and_no_live_claim():
    catalog = parse_catalog(json.dumps(sample()).encode())
    assert catalog.count == 1 and catalog.vulnerabilities[0].model_extra['futureField'] == 'preserved'
    assert catalog.vulnerabilities[0].model_extra['experimental_label'] == 'EXPERIMENTAL_DEMO_DATA_ONLY'
    assert not hasattr(catalog, 'origin')


def test_collector_uses_only_fixed_urls_and_validates_blob():
    transport, sha = fixture_transport(sample()); calls = []
    def tracked(url, timeout): calls.append(url); return transport(url, timeout)
    got = fetch_catalog(transport=tracked, sleep=lambda _: None, min_interval=0)
    assert calls == [METADATA_URL, API + '/git/blobs/' + sha]
    assert got.github_blob_sha == sha and got.collected_at.tzinfo and got.catalog.count == 1
    assert got.origin == 'EXPERIMENTAL_DEMO_DATA_ONLY'


def test_duplicate_json_keys_cves_and_malformed_feed_rejected():
    with pytest.raises(CollectionError): parse_catalog(b'{"count":0,"count":1}')
    data=sample(); data['vulnerabilities'].append(data['vulnerabilities'][0]); data['count']=2
    with pytest.raises(CollectionError): parse_catalog(json.dumps(data).encode())
    data=sample(); data['vulnerabilities'][0]['cveID']='not-a-cve'
    with pytest.raises(CollectionError): parse_catalog(json.dumps(data).encode())
    data=sample(); data['count']=2
    with pytest.raises(CollectionError): parse_catalog(json.dumps(data).encode())
    with pytest.raises(CollectionError): parse_catalog(b'\xff')


def test_untrusted_blob_and_source_url_are_rejected():
    def invalid(url, timeout): return b'{"sha":"../../attacker"}'
    with pytest.raises(CollectionError, match='metadata'): fetch_catalog(transport=invalid, min_interval=0)
    transport, _ = fixture_transport(sample())
    def corrupt(url, timeout):
        response=transport(url,timeout)
        if '/git/blobs/' in url:
            obj=json.loads(response); original=base64.b64decode(obj['content']); obj['content']=base64.b64encode(b'X'+original[1:]).decode()
            return json.dumps(obj).encode()
        return response
    with pytest.raises(CollectionError, match='digest'): fetch_catalog(transport=corrupt, min_interval=0)


def test_retry_exhaustion_and_sanitized_errors():
    calls=[]
    def broken(url, timeout): calls.append(url); raise URLError('secret fixture')
    with pytest.raises(CollectionError) as exc: fetch_catalog(transport=broken, sleep=lambda _:None, min_interval=0, retries=2)
    assert len(calls)==3 and 'secret fixture' not in str(exc.value)
    def forbidden(url,timeout): raise HTTPError(url,403,'fixture private detail',{},None)
    with pytest.raises(CollectionError): fetch_catalog(transport=forbidden, retries=2, min_interval=0)
    with pytest.raises(ValueError): fetch_catalog(timeout=0)


@pytest.mark.skipif(os.getenv('CICC_TEST_LIVE_CISA_GITHUB') != '1', reason='live source test not enabled')
def test_live_official_cisa_github_mirror():
    got = fetch_catalog(timeout=10, retries=1)
    assert got.origin == 'FETCHED_FROM_GITHUB_CISA_REPO'
    assert got.catalog.count == len(got.catalog.vulnerabilities) > 0
    assert len(got.github_blob_sha) == 40 and len(got.content_sha256) == 64


def test_transient_retry_then_success_without_relabeling_fixture():
    transport, _ = fixture_transport(sample())
    attempts = []
    def flaky(url, timeout):
        attempts.append(url)
        if len(attempts) == 1:
            raise HTTPError(url, 429, 'rate limited', {}, None)
        return transport(url, timeout)
    result = fetch_catalog(transport=flaky, sleep=lambda _: None, min_interval=0, retries=1)
    assert len(attempts) == 3 and result.origin == 'EXPERIMENTAL_DEMO_DATA_ONLY'


def test_input_size_and_redirect_policy():
    from apps.threat_intelligence.cisa_github_collector import MAX_CATALOG_BYTES, _NoRedirect
    with pytest.raises(CollectionError):
        parse_catalog(b' ' * (MAX_CATALOG_BYTES + 1))
    assert _NoRedirect().redirect_request(None, None, 302, '', {}, 'https://attacker.invalid') is None


def test_invalid_feed_traceback_does_not_expose_input():
    import traceback
    data = sample(); data['vulnerabilities'][0]['cveID'] = 'SECRET-FIXTURE-CONTENT'
    try:
        parse_catalog(json.dumps(data).encode())
    except CollectionError as error:
        assert 'SECRET-FIXTURE-CONTENT' not in ''.join(traceback.format_exception(error))
    else:
        pytest.fail('invalid CVE accepted')


def test_bounded_retry_after_respects_server_request():
    transport, _ = fixture_transport(sample()); sleeps = []; calls = []
    def limited(url, timeout):
        calls.append(url)
        if len(calls) == 1: raise HTTPError(url,429,'rate limit',{'Retry-After':'2'},None)
        return transport(url,timeout)
    fetch_catalog(transport=limited,sleep=sleeps.append,min_interval=0,retries=1)
    assert sleeps == [2]
    def long_delay(url, timeout):
        raise HTTPError(url,429,'rate limit',{'Retry-After':'90'},None)
    with pytest.raises(CollectionError,match='delay'):
        fetch_catalog(transport=long_delay,sleep=lambda _:pytest.fail('should defer to scheduler'),min_interval=0,retries=1)
