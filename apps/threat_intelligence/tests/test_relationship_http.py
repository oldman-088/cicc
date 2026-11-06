"""Application-level ASGI requests against the real FastAPI app (offline)."""
import asyncio
import json
from urllib.parse import urlencode
from uuid import uuid4

import pytest
from fastapi import HTTPException
from apps.threat_intelligence.api import app
from apps.threat_intelligence.relationship_api import (
    InMemoryRelationshipStore, Principal, get_principal,
)


def request(method, path, body=None, headers=None, query=None, application=app, include_headers=False):
    async def call():
        messages = []
        data = json.dumps(body).encode() if body is not None else b''
        delivered = False
        async def receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {'type': 'http.request', 'body': data, 'more_body': False}
            return {'type': 'http.disconnect'}
        async def send(message):
            messages.append(message)
        hdrs = [(b'content-type', b'application/json')]
        hdrs += [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
        scope = {'type': 'http', 'asgi': {'version': '3.0', 'spec_version': '2.3'},
                 'http_version': '1.1', 'method': method, 'scheme': 'http', 'path': path,
                 'raw_path': path.encode(), 'query_string': urlencode(query or {}, doseq=True).encode(),
                 'headers': hdrs, 'client': ('test', 1), 'server': ('test', 80), 'root_path': ''}
        try:
            await application(scope, receive, send)
        except Exception:
            # Starlette re-raises after sending the configured 500 response.
            if not any(m["type"] == "http.response.start" for m in messages):
                raise
        status = next(m['status'] for m in messages if m['type'] == 'http.response.start')
        raw = b''.join(m.get('body', b'') for m in messages if m['type'] == 'http.response.body')
        response = (status, json.loads(raw) if raw else None)
        if include_headers:
            response += (dict(next(m['headers'] for m in messages if m['type'] == 'http.response.start')), )
        return response
    return asyncio.run(call())

BASE = '/api/v1/threat-intelligence'
LABEL = 'EXPERIMENTAL_DEMO_DATA_ONLY'

def payload(source='a', target='b', kind='USES'):
    return {'source_entity': {'entity_id': source, 'entity_type': 'Actor'},
            'target_entity': {'entity_id': target, 'entity_type': 'Actor'},
            'relationship_type': kind, 'confidence': 'HIGH', 'confirmed': True,
            'provenance': 'fixture source', 'experimental_label': LABEL,
            'evidence': [{'source': 'fixture', 'timestamp': '2026-01-01T00:00:00Z',
                          'description': 'test evidence', 'confidence': 'HIGH', 'provenance': 'fixture'}]}

@pytest.fixture
def env():
    app.dependency_overrides.clear()
    app.state.relationship_store = InMemoryRelationshipStore()
    events = []
    app.state.relationship_audit = events.append
    def identity(tenant='one', permissions=('threat:read', 'threat:write')):
        app.dependency_overrides[get_principal] = lambda: Principal(subject='test', tenant_id=tenant, permissions=frozenset(permissions))
    identity()
    yield identity, events
    app.dependency_overrides.clear()
    del app.state.relationship_store
    del app.state.relationship_audit


def create(data, key):
    return request('POST', BASE + '/relationships', data, {'Idempotency-Key': key})


def test_fail_closed_and_real_route(env):
    app.dependency_overrides.clear()
    code, _ = request('GET', BASE + '/relationships')
    assert code == 503
    env[0]()
    code, data = request('GET', BASE + '/relationships')
    assert code == 200 and data['items'] == [] and data['total'] == 0
    assert request('GET', BASE + '/not-a-route')[0] == 404
    del app.state.relationship_store
    assert request('GET', BASE + '/relationships')[0] == 503
    app.state.relationship_store = InMemoryRelationshipStore()


def test_auth_permissions_and_tenant_isolation(env):
    identity, _ = env
    created = create(payload(), 'key')[1]
    rid = created['relationship_id']
    identity('one', ('threat:read',))
    assert create(payload('b', 'c'), 'no-write')[0] == 403
    identity('two')
    assert request('GET', BASE + '/relationships/' + rid)[0] == 404
    assert request('GET', BASE + '/relationships')[1]['items'] == []
    other = create(payload(), 'key')[1]
    assert other['relationship_id'] != rid
    identity('one', ())
    assert request('GET', BASE + '/relationships')[0] == 403
    def unauthenticated():
        raise HTTPException(status_code=401, detail='Unauthorized')
    app.dependency_overrides[get_principal] = unauthenticated
    assert request('GET', BASE + '/relationships')[0] == 401


def test_create_idempotency_dedup_and_provenance(env):
    code, first = create(payload(), 'one')
    assert code == 201 and first['experimental_label'] == LABEL
    assert first['provenance'] == 'fixture source' and first['evidence'][0]['source'] == 'fixture'
    assert first['confirmed'] is True and first['confidence'] == 'HIGH'
    assert create(payload(), 'one') == (200, first)
    assert create(payload(), 'two') == (200, first)
    assert create(payload('x', 'y'), 'one')[0] == 409
    changed = payload(); changed['provenance'] = 'another observation'
    assert create(changed, 'three')[0] == 201
    assert request('GET', BASE + '/relationships')[1]['total'] == 2
    assert all('evidence' not in event for event in env[1])


def test_invalid_missing_and_safe_validation(env):
    assert create(payload(), '')[0] == 422
    invalid = payload(); invalid['confidence'] = 'made-up-secret-value'
    code, data = create(invalid, 'x')
    assert code == 422 and 'made-up-secret-value' not in json.dumps(data)
    bad = payload(); bad['evidence'] = []
    assert create(bad, 'x')[0] == 422
    bad = payload(); bad['evidence'][0]['timestamp'] = '2026-01-01T00:00:00'
    assert create(bad, 'x')[0] == 422
    assert request('GET', BASE + '/relationships/not-a-uuid')[0] == 422
    assert request('GET', BASE + '/relationships/' + str(uuid4()))[0] == 404
    assert request('GET', BASE + '/relationships', query={'entity_id': 'a'})[0] == 422
    assert request('POST', BASE + '/relationship-analysis/traverse', {'entity_id': 'missing', 'entity_type': 'Actor'})[0] == 404


def test_real_traversal_cycles_filters_and_pagination(env):
    for i, item in enumerate([payload('a','b'), payload('b','c','TARGETS'), payload('c','a')]):
        assert create(item, str(i))[0] == 201
    code, page = request('POST', BASE + '/relationship-analysis/traverse', {'entity_id':'a', 'entity_type':'Actor', 'max_depth':2, 'limit':2})
    assert code == 200 and page['total'] == 3 and page['has_more'] and page['visited_entities'] == 3
    assert len({x['relationship']['relationship_id'] for x in page['items']}) == 2
    assert page['items'][0]['relationship']['evidence'][0]['source'] == 'fixture'
    second = request('POST', BASE + '/relationship-analysis/traverse', {'entity_id':'a', 'entity_type':'Actor', 'max_depth':2, 'limit':2, 'offset':2})[1]
    assert len(second['items']) == 1 and not second['has_more']
    filtered = request('POST', BASE + '/relationship-analysis/traverse', {'entity_id':'a', 'entity_type':'Actor', 'relationship_types':['USES']})[1]
    assert filtered['total'] == 2
    listing = request('GET', BASE + '/relationships', query={'relationship_type':'TARGETS', 'limit':1})[1]
    assert listing['total'] == 1 and listing['items'][0]['relationship_type'] == 'TARGETS'
    assert request('POST', BASE + '/relationship-analysis/traverse', {'entity_id':'a', 'entity_type':'Actor', 'max_depth':0})[1]['total'] == 0


def test_audit_failure_is_closed_and_sanitized(env):
    def broken(event):
        raise RuntimeError('secret-token')
    app.state.relationship_audit = broken
    code, result = create(payload(), 'key')
    assert code == 503 and 'secret-token' not in json.dumps(result)
    app.state.relationship_audit = env[1].append
    assert request('GET', BASE + '/relationships')[1]['total'] == 0


def test_storage_failure_is_sanitized(env):
    class BrokenStore(InMemoryRelationshipStore):
        def engine(self, tenant):
            raise RuntimeError('secret-storage-password')
    app.state.relationship_store = BrokenStore()
    code, body = request('GET', BASE + '/relationships')
    assert code == 500 and 'secret-storage-password' not in json.dumps(body)


def test_concurrent_idempotency_and_literal_entity_identity(env):
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: create(payload(), 'same'), range(8)))
    assert sorted(code for code, _ in results) == [200] * 7 + [201]
    assert len({body['relationship_id'] for _, body in results}) == 1
    special = payload('c', 'd')
    special['source_entity'] = {'entity_type': 'Actor:x', 'entity_id': 'y'}
    assert create(special, 'special')[0] == 201
    assert request('POST', BASE + '/relationship-analysis/traverse', {'entity_type': 'Actor', 'entity_id': 'x:y'})[0] == 404
    assert request('POST', BASE + '/relationship-analysis/traverse', {'entity_type': 'Actor:x', 'entity_id': 'y'})[1]['total'] == 1


def test_independent_fastapi_host_can_mount_router():
    from fastapi import FastAPI
    from apps.threat_intelligence.relationship_api import router
    host = FastAPI()
    host.include_router(router)
    host.state.relationship_store = InMemoryRelationshipStore()
    host.state.relationship_audit = lambda event: None
    host.dependency_overrides[get_principal] = lambda: Principal(subject='fixture', tenant_id='test-tenant', permissions=frozenset({'threat:read'}))
    code, body = request('GET', BASE + '/relationships', application=host)
    assert code == 200 and body['total'] == 0
    assert request('POST', BASE + '/relationships', payload(), {'Idempotency-Key': 'key'}, application=host)[0] == 403


def test_openapi_describes_real_routes(env):
    code, spec = request('GET', '/openapi.json')
    assert code == 200
    assert set(spec['paths'][BASE + '/relationships']) == {'get', 'post'}
    assert 'post' in spec['paths'][BASE + '/relationship-analysis/traverse']
