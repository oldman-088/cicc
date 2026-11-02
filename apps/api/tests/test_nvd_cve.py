"""Only synthetic fixtures and mocked transport; no live NVD access."""
from datetime import datetime, timezone
import json
import httpx
import pytest
from app.connectors.nvd_cve import API_URL, DETAIL_URL, MAX_RESPONSE_BYTES, NvdError, fetch_cve, parse_response

CVE='CVE-2099-0001'
COLLECTED=datetime(2026,1,2,tzinfo=timezone.utc)
def fixture():
    return {'startIndex':0,'totalResults':1,'vulnerabilities':[{'cve':{'id':CVE,
        'published':'2026-01-01T10:00:00.000','lastModified':'2026-01-02T10:00:00.000',
        'vulnStatus':'Analyzed','descriptions':[{'lang':'en','value':'Synthetic fixture only.'}]}}]}
def encoded(doc): return json.dumps(doc).encode()

def test_parse_source_attribution_and_no_invented_confidence():
    result=parse_response(encoded(fixture()),cve_id=CVE,collected_at=COLLECTED)
    assert result.cve_id==CVE and result.source_reference==DETAIL_URL+CVE and result.collected_at==COLLECTED
    assert result.descriptions[0].text=='Synthetic fixture only.' and result.published=='2026-01-01T10:00:00.000'
    assert not hasattr(result,'confidence')
    assert parse_response(encoded({'startIndex':0,'totalResults':0,'vulnerabilities':[]}),cve_id=CVE,collected_at=COLLECTED) is None

@pytest.mark.parametrize('mutation',['mismatch','duplicates','bad_timestamp','bad_language','bad_status','bad_description','bad_start'])
def test_invalid_source_fails_closed(mutation):
    doc=fixture(); cve=doc['vulnerabilities'][0]['cve']
    if mutation=='mismatch': cve['id']='CVE-2099-0002'
    elif mutation=='duplicates': doc['vulnerabilities'].append(doc['vulnerabilities'][0]); doc['totalResults']=2
    elif mutation=='bad_timestamp': cve['published']='bad'
    elif mutation=='bad_language': cve['descriptions'][0]['lang']='../'
    elif mutation=='bad_status': cve['vulnStatus']=''
    elif mutation=='bad_description': cve['descriptions'][0]['value']='\x00'
    else: doc['startIndex']=1
    with pytest.raises(NvdError): parse_response(encoded(doc),cve_id=CVE,collected_at=COLLECTED)

def test_fixed_url_and_no_redirect_or_retry():
    calls=[]
    def handler(request): calls.append(request); return httpx.Response(200,json=fixture())
    with httpx.Client(transport=httpx.MockTransport(handler),follow_redirects=True) as client:
        result=fetch_cve(CVE,client=client)
    assert result.cve_id==CVE and len(calls)==1 and str(calls[0].url).startswith(API_URL+'?')
    assert dict(calls[0].url.params)=={'cveId':CVE,'resultsPerPage':'1','startIndex':'0'}
    for status in (302,429,503):
        calls=[]
        def rejected(request): calls.append(request); return httpx.Response(status,headers={'Location':'http://127.0.0.1/secret'},text='private body')
        with httpx.Client(transport=httpx.MockTransport(rejected),follow_redirects=True) as client:
            with pytest.raises(NvdError,match=f'HTTP {status}') as err: fetch_cve(CVE,client=client)
        assert len(calls)==1 and 'private body' not in str(err.value)

def test_invalid_inputs_size_and_transport_errors():
    with pytest.raises(ValueError): fetch_cve('https://example.test/')
    with pytest.raises(ValueError): parse_response(encoded(fixture()),cve_id=CVE,collected_at=datetime(2026,1,1))
    with pytest.raises(NvdError): parse_response(b'{',cve_id=CVE,collected_at=COLLECTED)
    with httpx.Client(transport=httpx.MockTransport(lambda _:httpx.Response(200,headers={'Content-Length':str(MAX_RESPONSE_BYTES+1)}))) as client:
        with pytest.raises(NvdError,match='size limit'): fetch_cve(CVE,client=client)
    def failure(request): raise httpx.ConnectError('private address',request=request)
    with httpx.Client(transport=httpx.MockTransport(failure)) as client:
        with pytest.raises(NvdError,match='connection failed') as err: fetch_cve(CVE,client=client)
    assert 'private address' not in str(err.value)


def test_stream_limit_and_checkpointed_time_budget(monkeypatch):
    import app.connectors.nvd_cve as connector
    class SlowStream(httpx.SyncByteStream):
        def __iter__(self):
            clock[0]=connector.FETCH_BUDGET_SECONDS+1
            yield b'{}'
    clock=[0.0]
    with httpx.Client(transport=httpx.MockTransport(lambda _:httpx.Response(200,stream=SlowStream()))) as client:
        with pytest.raises(NvdError,match='time budget'): fetch_cve(CVE,client=client,monotonic=lambda:clock[0])
    monkeypatch.setattr(connector,'MAX_RESPONSE_BYTES',10)
    with httpx.Client(transport=httpx.MockTransport(lambda _:httpx.Response(200,headers={'Content-Length':'1'},content=b'x'*11))) as client:
        with pytest.raises(NvdError,match='size limit'): fetch_cve(CVE,client=client)
    with httpx.Client(transport=httpx.MockTransport(lambda _:httpx.Response(200,headers={'Content-Length':'9'*5000}))) as client:
        with pytest.raises(NvdError,match='size limit'): fetch_cve(CVE,client=client)
