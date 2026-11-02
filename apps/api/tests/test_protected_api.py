import base64
from uuid import uuid4
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from app.experimental_config import configure_experimental
from app.models import Base, Entity, SecurityAuditEvent, Tenant, User
from app.protected_api import protected_router
from app.security import hash_password

@pytest.fixture
def api(tmp_path):
    engine = create_engine(f'sqlite:///{tmp_path / "api.db"}')
    @event.listens_for(engine, 'connect')
    def foreign_keys(conn, _): conn.execute('PRAGMA foreign_keys=ON')
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    a, b = uuid4(), uuid4()
    with factory.begin() as db:
        db.add_all([Tenant(id=a, name='a'), Tenant(id=b, name='b')]); db.flush()
        db.add_all([User(tenant_id=a, username='analyst', role='analyst', active=True, password_hash=hash_password('a long password')),
                    Entity(tenant_id=a, kind='indicator', title='tenant a', source='test'), Entity(tenant_id=b, kind='indicator', title='tenant b', source='test')])
    app = FastAPI(); app.include_router(protected_router(factory, b'x'*32))
    with TestClient(app, base_url='https://testserver', client=('192.0.2.1', 1234)) as client:
        yield client, factory, a, b
    engine.dispose()

def test_login_read_isolation_and_logout(api):
    client, factory, a, _ = api
    assert client.get('/api/v1/secure/entities').status_code == 401
    assert client.post('/api/v1/secure/login', json={'tenant_id':str(a), 'username':'analyst', 'password':'bad'}).status_code == 401
    result = client.post('/api/v1/secure/login', json={'tenant_id':str(a), 'username':'analyst', 'password':'a long password'})
    assert result.status_code == 200 and result.headers['cache-control'] == 'no-store'
    token = result.json()['access_token']; headers = {'Authorization':f'Bearer {token}'}
    result = client.get('/api/v1/secure/entities', headers=headers)
    assert result.status_code == 200 and [x['title'] for x in result.json()['items']] == ['tenant a']
    assert result.json()['truncated'] is False
    assert client.post('/api/v1/secure/logout', headers=headers).status_code == 200
    assert client.get('/api/v1/secure/entities', headers=headers).status_code == 401
    with factory() as db:
        events = list(db.scalars(select(SecurityAuditEvent.event_type)))
        assert 'login_failed' in events and 'login_succeeded' in events and 'intelligence_read' in events and 'session_revoked' in events

def test_reject_http_and_invalid_auth(api):
    client, _, a, _ = api
    assert client.get('http://testserver/api/v1/secure/entities').status_code == 400
    assert client.get('/api/v1/secure/entities', headers={'Authorization':'Bearer garbage'}).status_code == 401
    assert client.post('http://testserver/api/v1/secure/login', json={'tenant_id':str(a), 'username':'analyst', 'password':'a long password'}).status_code == 400

def test_default_disabled_and_configuration_fails_closed():
    app = FastAPI(); configure_experimental(app, {})
    assert TestClient(app).get('/api/v1/secure/entities').status_code == 404
    for env in [{'CICC_EXPERIMENTAL_AUTH':'yes'}, {'CICC_EXPERIMENTAL_AUTH':'true'},
                {'CICC_EXPERIMENTAL_AUTH':'true', 'DATABASE_URL':'sqlite://', 'CICC_RATE_LIMIT_KEY_BASE64':base64.b64encode(b'x'*32).decode()},
                {'CICC_EXPERIMENTAL_AUTH':'true', 'DATABASE_URL':'sqlite://', 'CICC_RATE_LIMIT_KEY_BASE64':'bad'}]:
        with pytest.raises(RuntimeError): configure_experimental(FastAPI(), env)

def test_request_cannot_select_other_tenant(api):
    client, _, a, b = api
    token = client.post('/api/v1/secure/login', json={'tenant_id':str(a), 'username':'analyst', 'password':'a long password'}).json()['access_token']
    response = client.get(f'/api/v1/secure/entities?tenant_id={b}', headers={'Authorization':f'Bearer {token}'})
    assert [item['title'] for item in response.json()['items']] == ['tenant a']

def test_login_is_throttled(api, monkeypatch):
    from app.rate_limit import consume
    monkeypatch.setattr('app.login_service.consume', lambda db, **kwargs: consume(db, **kwargs, now=120))
    client, _, a, _ = api
    payload = {'tenant_id':str(a), 'username':'analyst', 'password':'wrong'}
    assert [client.post('/api/v1/secure/login', json=payload).status_code for _ in range(6)] == [401]*5 + [429]

def test_audit_failure_does_not_return_data(api, monkeypatch):
    client, _, a, _ = api
    token = client.post('/api/v1/secure/login', json={'tenant_id':str(a), 'username':'analyst', 'password':'a long password'}).json()['access_token']
    def fail(*args, **kwargs): raise RuntimeError('audit failure')
    monkeypatch.setattr('app.protected_api.record_event', fail)
    with pytest.raises(RuntimeError, match='audit failure'):
        client.get('/api/v1/secure/entities', headers={'Authorization':f'Bearer {token}'})

def test_validation_errors_do_not_echo_password(api):
    client, _, a, _ = api
    password = 'sensitive-secret-' + 'x' * 1100
    response = client.post('/api/v1/secure/login', json={'tenant_id':str(a), 'username':'analyst', 'password':password})
    assert response.status_code == 422
    assert password not in response.text
    assert response.headers['cache-control'] == 'no-store'

def test_account_admin_workflows_enforce_tenant_and_audit(api):
    client, factory, a, b = api
    from app.models import User
    with factory.begin() as db:
        admin = User(tenant_id=a, username='admin', role='admin', active=True, password_hash=hash_password('another long password'))
        foreign = User(tenant_id=b, username='foreign', role='viewer', active=True, password_hash=hash_password('another long password'))
        db.add_all([admin, foreign]); db.flush(); foreign_id = foreign.id
    def auth(username, password):
        r = client.post('/api/v1/secure/login', json={'tenant_id':str(a), 'username':username, 'password':password})
        assert r.status_code == 200
        return {'Authorization':'Bearer '+r.json()['access_token']}
    admin_headers = auth('admin', 'another long password')
    analyst_headers = auth('analyst', 'a long password')
    payload = {'username':'newuser', 'password':'new strong password', 'role':'analyst'}
    assert client.post('/api/v1/secure/users', json=payload).status_code == 401
    assert client.post('/api/v1/secure/users', json=payload, headers=analyst_headers).status_code == 403
    result = client.post('/api/v1/secure/users', json=payload, headers=admin_headers)
    assert result.status_code == 201
    target = result.json()['id']
    assert 'new strong password' not in result.text
    assert client.post('/api/v1/secure/users', json=payload, headers=admin_headers).status_code == 409
    assert client.patch(f'/api/v1/secure/users/{foreign_id}/role', json={'role':'admin'}, headers=admin_headers).status_code == 403
    assert client.patch(f'/api/v1/secure/users/{target}/role', json={'role':'viewer'}, headers=admin_headers).status_code == 200
    assert client.post(f'/api/v1/secure/users/{target}/disable', headers=admin_headers).status_code == 200
    with factory() as db:
        audit = db.scalar(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type == 'user_role_changed'))
        assert audit.previous_role == 'analyst' and audit.new_role == 'viewer' and str(audit.target_user_id) == target
        assert db.get(User, foreign_id).role == 'viewer'

def test_create_user_validation_never_echoes_password(api):
    client, _, _, _ = api
    password = 'private-value-' * 100
    r = client.post('/api/v1/secure/users', json={'username':'x', 'password':password, 'role':'admin'}, headers={'Authorization': 'Bearer fake'})
    assert r.status_code == 422 and password not in r.text

def test_create_entity_permissions_provenance_and_tenant_scope(api):
    client, factory, a, b = api
    with factory.begin() as db:
        db.add(User(tenant_id=a, username='viewer', role='viewer', active=True, password_hash=hash_password('viewer safe password')))
    def token(username, password):
        result = client.post('/api/v1/secure/login', json={'tenant_id':str(a), 'username':username, 'password':password})
        return {'Authorization':'Bearer '+result.json()['access_token']}
    analyst = token('analyst', 'a long password')
    viewer = token('viewer', 'viewer safe password')
    payload = {'kind':'indicator', 'title':'Example indicator', 'source':'Analyst report', 'source_reference':'case-reference', 'confidence':67}
    assert client.post('/api/v1/secure/entities', json=payload).status_code == 401
    assert client.post('/api/v1/secure/entities', json=payload, headers=viewer).status_code == 403
    assert client.post('/api/v1/secure/entities', json={**payload, 'tenant_id':str(b)}, headers=analyst).status_code == 422
    assert client.post('/api/v1/secure/entities', json={**payload, 'confidence':101}, headers=analyst).status_code == 422
    assert client.post('/api/v1/secure/entities', json={**payload, 'source':'  '}, headers=analyst).status_code == 422
    result = client.post('/api/v1/secure/entities', json=payload, headers=analyst)
    assert result.status_code == 201 and result.json()['verification_status'] == 'unverified'
    entity_id = result.json()['id']
    response = client.get('/api/v1/secure/entities', headers=analyst)
    record = next(x for x in response.json()['items'] if x['id'] == entity_id)
    assert record['source'] == 'Analyst report' and record['source_reference'] == 'case-reference'
    assert record['confidence'] == 67 and record['verification_status'] == 'unverified' and record['created_by']
    with factory() as db:
        event = db.scalar(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type == 'intelligence_created'))
        assert str(event.target_entity_id) == entity_id and event.tenant_id == a

def test_creation_is_rolled_back_when_audit_fails(api, monkeypatch):
    client, factory, a, _ = api
    result = client.post('/api/v1/secure/login', json={'tenant_id':str(a), 'username':'analyst', 'password':'a long password'})
    headers = {'Authorization':'Bearer '+result.json()['access_token']}
    def fail(*args, **kwargs): raise RuntimeError('audit failure')
    monkeypatch.setattr('app.protected_api.record_event', fail)
    with pytest.raises(RuntimeError):
        client.post('/api/v1/secure/entities', json={'kind':'indicator','title':'rollback me','source':'test'}, headers=headers)
    with factory() as db: assert db.scalar(select(Entity).where(Entity.title == 'rollback me')) is None

def test_evidence_reference_authorization_and_isolation(api):
    client, factory, a, b = api
    with factory.begin() as db:
        viewer = User(tenant_id=a, username='viewer', role='viewer', active=True, password_hash=hash_password('viewer safe password'))
        own = Entity(tenant_id=a, kind='indicator', title='own', source='test')
        foreign = Entity(tenant_id=b, kind='indicator', title='foreign', source='test')
        db.add_all([viewer, own, foreign]); db.flush(); own_id, foreign_id = own.id, foreign.id
    def headers(username, password):
        token = client.post('/api/v1/secure/login', json={'tenant_id':str(a),'username':username,'password':password}).json()['access_token']
        return {'Authorization':'Bearer '+token}
    analyst = headers('analyst', 'a long password'); viewer_headers = headers('viewer', 'viewer safe password')
    payload = {'description':'Analyst note', 'source':'Report', 'reference':'offline-ref', 'sha256':'a'*64}
    url = f'/api/v1/secure/entities/{own_id}/evidence'
    assert client.post(url, json=payload, headers=viewer_headers).status_code == 403
    assert client.post(f'/api/v1/secure/entities/{foreign_id}/evidence', json=payload, headers=analyst).status_code == 404
    assert client.get(f'/api/v1/secure/entities/{foreign_id}/evidence', headers=analyst).status_code == 404
    assert client.post(url, json={**payload, 'sha256':'z'*64}, headers=analyst).status_code == 422
    assert client.post(url, json={**payload, 'tenant_id':str(b)}, headers=analyst).status_code == 422
    result = client.post(url, json=payload, headers=analyst)
    assert result.status_code == 201 and result.json()['status'] == 'analyst_entered_unverified'
    response = client.get(url, headers=viewer_headers)
    assert response.status_code == 200 and response.json()['items'][0]['sha256'] == 'a'*64
    assert response.json()['items'][0]['status'] == 'analyst_entered_unverified'
    with factory() as db:
        assert {'evidence_created','evidence_read'} <= set(db.scalars(select(SecurityAuditEvent.event_type)))

def test_evidence_audit_failure_rolls_back(api, monkeypatch):
    from app.models import EvidenceReference
    client, factory, a, _ = api
    with factory.begin() as db:
        entity = Entity(tenant_id=a, kind='indicator', title='own', source='test'); db.add(entity); db.flush(); entity_id = entity.id
    token = client.post('/api/v1/secure/login', json={'tenant_id':str(a),'username':'analyst','password':'a long password'}).json()['access_token']
    def fail(*args, **kwargs): raise RuntimeError('audit failure')
    monkeypatch.setattr('app.protected_api.record_event', fail)
    with pytest.raises(RuntimeError):
        client.post(f'/api/v1/secure/entities/{entity_id}/evidence', json={'description':'note','source':'test'}, headers={'Authorization':'Bearer '+token})
    with factory() as db: assert db.scalar(select(EvidenceReference)) is None

def test_provenance_records_new_actions_and_preserves_missing_history_notice(api):
    client, factory, a, b = api
    token = client.post('/api/v1/secure/login', json={'tenant_id':str(a), 'username':'analyst', 'password':'a long password'}).json()['access_token']
    headers = {'Authorization':'Bearer '+token}
    entity = client.post('/api/v1/secure/entities', json={'kind':'indicator','title':'sample','source':'report','confidence':45}, headers=headers).json()
    evidence = client.post(f"/api/v1/secure/entities/{entity['id']}/evidence", json={'description':'note','source':'report','sha256':'a'*64}, headers=headers).json()
    history = client.get(f"/api/v1/secure/entities/{entity['id']}/provenance", headers=headers)
    assert history.status_code == 200
    data = history.json(); assert 'earlier history may be missing' in data['notice']
    assert [e['event_type'] for e in data['items']] == ['manual_entity_created', 'evidence_reference_added']
    assert data['items'][0]['details']['confidence'] == 45
    assert data['items'][1]['evidence_id'] == evidence['id'] and data['items'][1]['details']['status'] == 'analyst_entered_unverified'
    with factory() as db:
        foreign = db.scalar(select(Entity).where(Entity.tenant_id == b))
        foreign_id = foreign.id
        assert 'provenance_read' in list(db.scalars(select(SecurityAuditEvent.event_type)))
    assert client.get(f'/api/v1/secure/entities/{foreign_id}/provenance', headers=headers).status_code == 404

def test_audit_api_admin_only_and_tenant_scoped(api):
    from app.audit import AuditType, record_event
    client, factory, a, b = api
    with factory.begin() as db:
        db.add(User(tenant_id=a, username='admin', role='admin', active=True, password_hash=hash_password('another long password')))
        record_event(db, b, AuditType.LOGIN_FAILED)
    def auth(username, password):
        result = client.post('/api/v1/secure/login', json={'tenant_id':str(a), 'username':username, 'password':password})
        return {'Authorization':'Bearer '+result.json()['access_token']}
    admin = auth('admin','another long password'); analyst = auth('analyst','a long password')
    assert client.get('/api/v1/secure/audit').status_code == 401
    assert client.get('/api/v1/secure/audit', headers=analyst).status_code == 403
    response = client.get('/api/v1/secure/audit', headers=admin)
    assert response.status_code == 200 and response.json()['limit'] == 100
    assert all(item['event_type'] != 'login_failed' for item in response.json()['items'])
    with factory() as db:
        assert db.scalar(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type == 'audit_read', SecurityAuditEvent.tenant_id == a)) is not None

def test_entity_update_version_provenance_and_authorization(api):
    client, factory, a, b = api
    with factory.begin() as db:
        db.add(User(tenant_id=a, username='viewer', role='viewer', active=True, password_hash=hash_password('viewer safe password')))
        foreign = Entity(tenant_id=b, kind='indicator', title='foreign', source='test'); db.add(foreign); db.flush(); foreign_id = foreign.id
    def headers(username, password):
        result = client.post('/api/v1/secure/login', json={'tenant_id':str(a), 'username':username, 'password':password})
        return {'Authorization':'Bearer '+result.json()['access_token']}
    analyst = headers('analyst','a long password'); viewer = headers('viewer','viewer safe password')
    result = client.post('/api/v1/secure/entities', json={'kind':'indicator', 'title':'Original', 'source':'test', 'confidence':30}, headers=analyst)
    item = result.json(); entity_id = item['id']; assert item['version'] == 1
    payload = {'expected_version':1, 'title':'Updated', 'confidence':60}
    assert client.patch(f'/api/v1/secure/entities/{entity_id}', json=payload, headers=viewer).status_code == 403
    assert client.patch(f'/api/v1/secure/entities/{foreign_id}', json=payload, headers=analyst).status_code == 404
    assert client.patch(f'/api/v1/secure/entities/{entity_id}', json={**payload, 'tenant_id':str(b)}, headers=analyst).status_code == 422
    response = client.patch(f'/api/v1/secure/entities/{entity_id}', json=payload, headers=analyst)
    assert response.status_code == 200 and response.json()['version'] == 2
    assert client.patch(f'/api/v1/secure/entities/{entity_id}', json=payload, headers=analyst).status_code == 409
    data = client.get(f'/api/v1/secure/entities/{entity_id}/provenance', headers=analyst).json()['items']
    change = next(x for x in data if x['event_type'] == 'manual_entity_updated')
    assert change['details']['before']['title'] == 'Original' and change['details']['after']['confidence'] == 60
    with factory() as db:
        assert db.scalar(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type == 'intelligence_updated')) is not None

def test_entity_update_audit_failure_rolls_back(api, monkeypatch):
    client, factory, a, _ = api
    token = client.post('/api/v1/secure/login', json={'tenant_id':str(a), 'username':'analyst', 'password':'a long password'}).json()['access_token']
    headers = {'Authorization':'Bearer '+token}
    entity_id = client.post('/api/v1/secure/entities', json={'kind':'indicator','title':'Original','source':'test'}, headers=headers).json()['id']
    def fail(*args, **kwargs): raise RuntimeError('audit failure')
    monkeypatch.setattr('app.protected_api.record_event', fail)
    with pytest.raises(RuntimeError):
        client.patch(f'/api/v1/secure/entities/{entity_id}', json={'expected_version':1,'title':'Lost','confidence':None}, headers=headers)
    with factory() as db:
        entity = db.scalar(select(Entity).where(Entity.title == 'Original'))
        assert entity.version == 1

def test_relationships_preserve_evidence_tenant_and_permissions(api):
    client, factory, a, b = api
    with factory.begin() as db:
        db.add(User(tenant_id=a, username='viewer', role='viewer', active=True, password_hash=hash_password('viewer safe password')))
        foreign = Entity(tenant_id=b, kind='indicator', title='foreign', source='test'); db.add(foreign); db.flush(); foreign_id = str(foreign.id)
    def headers(username, password):
        return {'Authorization':'Bearer '+client.post('/api/v1/secure/login', json={'tenant_id':str(a), 'username':username, 'password':password}).json()['access_token']}
    analyst = headers('analyst', 'a long password'); viewer = headers('viewer', 'viewer safe password')
    def entity(title):
        return client.post('/api/v1/secure/entities', headers=analyst, json={'kind':'indicator','title':title,'source':'test'}).json()['id']
    first, second = entity('first'), entity('second')
    evidence = client.post(f'/api/v1/secure/entities/{first}/evidence', headers=analyst, json={'description':'report reference','source':'test'}).json()['id']
    payload = {'subject_id':first, 'object_id':second, 'kind':'RELATED_TO', 'source':'test', 'evidence_id':evidence, 'confidence':70}
    assert client.post('/api/v1/secure/relationships', headers=viewer, json=payload).status_code == 403
    assert client.post('/api/v1/secure/relationships', headers=analyst, json={**payload, 'object_id':foreign_id}).status_code == 404
    assert client.post('/api/v1/secure/relationships', headers=analyst, json={**payload, 'subject_id':second, 'object_id':first}).status_code == 404
    assert client.post('/api/v1/secure/relationships', headers=analyst, json={**payload, 'object_id':first}).status_code == 422
    assert client.post('/api/v1/secure/relationships', headers=analyst, json={**payload, 'tenant_id':str(b)}).status_code == 422
    result = client.post('/api/v1/secure/relationships', headers=analyst, json=payload)
    assert result.status_code == 201 and result.json()['status'] == 'analyst_assertion_unverified'
    for entity_id in (first, second):
        items = client.get(f'/api/v1/secure/entities/{entity_id}/relationships', headers=viewer).json()['items']
        assert len(items) == 1 and items[0]['evidence_id'] == evidence and items[0]['confidence'] == 70
    assert client.get(f'/api/v1/secure/entities/{foreign_id}/relationships', headers=analyst).status_code == 404
    events = client.get(f'/api/v1/secure/entities/{first}/provenance', headers=analyst).json()['items']
    event = next(e for e in events if e['event_type'] == 'relationship_asserted')
    assert event['evidence_id'] == evidence and event['details']['status'] == 'analyst_assertion_unverified'

def test_relationship_write_rolls_back_on_audit_failure(api, monkeypatch):
    from app.models import Relationship
    client, factory, tenant, _ = api
    token = client.post('/api/v1/secure/login', json={'tenant_id':str(tenant),'username':'analyst','password':'a long password'}).json()['access_token']
    headers = {'Authorization':'Bearer '+token}
    def entity(title): return client.post('/api/v1/secure/entities', headers=headers, json={'kind':'indicator','title':title,'source':'test'}).json()['id']
    first, second = entity('x'), entity('y')
    def fail(*args, **kwargs): raise RuntimeError('audit failure')
    monkeypatch.setattr('app.protected_api.record_event', fail)
    with pytest.raises(RuntimeError):
        client.post('/api/v1/secure/relationships', headers=headers, json={'subject_id':first,'object_id':second,'kind':'RELATED_TO','source':'test'})
    with factory() as db: assert db.scalar(select(Relationship)) is None

def test_cisa_status_and_abandon_are_tenant_scoped(api):
    from app.connectors.cisa_sync import begin_sync
    client, factory, a, b = api
    with factory.begin() as db:
        db.add_all([User(tenant_id=a, username='admin', role='admin', active=True, password_hash=hash_password('a secure password')),
                    User(tenant_id=b, username='admin', role='admin', active=True, password_hash=hash_password('a secure password'))])
    def login(tenant, username, password):
        return client.post('/api/v1/secure/login', json={'tenant_id':str(tenant), 'username':username, 'password':password}).json()['access_token']
    admin = login(a,'admin','a secure password'); other = login(b,'admin','a secure password'); analyst = login(a,'analyst','a long password')
    def hdr(token): return {'Authorization':'Bearer '+token}
    url = '/api/v1/secure/sources/cisa-kev/status'
    assert client.get(url).status_code == 401
    assert client.get(url, headers=hdr(analyst)).status_code == 403
    status = client.get(url, headers=hdr(admin))
    assert status.status_code == 200 and status.json()['integration'] == 'experimental_not_live_verified'
    assert status.json()['last_attempt'] is None and status.json()['last_imported_snapshot_collected_at'] is None
    attempt = begin_sync(factory, admin_token=admin)
    assert client.get(url, headers=hdr(admin)).json()['last_attempt']['id'] == str(attempt)
    target = f'/api/v1/secure/sources/cisa-kev/attempts/{attempt}/abandon'
    assert client.post(target, headers=hdr(other)).status_code == 404
    assert client.post(target, headers=hdr(analyst)).status_code == 403
    result = client.post(target, headers=hdr(admin))
    assert result.status_code == 200 and result.json()['status'] == 'abandoned'
    assert client.get(url, headers=hdr(admin)).json()['last_attempt']['status'] == 'abandoned'
    assert client.post(target, headers=hdr(admin)).status_code == 404
    assert client.post('/api/v1/secure/sources/cisa-kev/sync', headers=hdr(admin)).status_code == 404

def test_entity_cursor_paginates_without_cross_tenant_leakage(api):
    client, factory, a, b = api
    with factory.begin() as db:
        db.add_all([Entity(tenant_id=a, kind='indicator', title=f'a-{i}', source='test') for i in range(204)])
        db.add_all([Entity(tenant_id=b, kind='indicator', title=f'foreign-{i}', source='test') for i in range(50)])
    token = client.post('/api/v1/secure/login', json={'tenant_id':str(a),'username':'analyst','password':'a long password'}).json()['access_token']
    headers = {'Authorization':'Bearer '+token}
    ids, cursor, pages = [], None, 0
    while True:
        response = client.get('/api/v1/secure/entities', headers=headers, params={'after':cursor} if cursor else {})
        assert response.status_code == 200
        page = response.json(); pages += 1
        assert all(not x['title'].startswith('foreign-') for x in page['items'])
        ids.extend(item['id'] for item in page['items'])
        cursor = page['next_cursor']
        if cursor is None:
            assert page['truncated'] is False
            break
        assert page['truncated'] is True and len(page['items']) == 100
        assert pages < 5
    assert pages == 3 and len(ids) == 205 and len(set(ids)) == 205
    assert client.get('/api/v1/secure/entities?after=not-a-uuid', headers=headers).status_code == 422

def test_audit_cursor_pagination_preserves_tenant_and_tie_order(api):
    from datetime import datetime, timezone
    client, factory, a, b = api
    timestamp = datetime(2026,1,1,tzinfo=timezone.utc)
    with factory.begin() as db:
        db.add(User(tenant_id=a, username='admin', role='admin', active=True, password_hash=hash_password('a secure password')))
        db.add_all([SecurityAuditEvent(tenant_id=a, event_type='fixture_marker', occurred_at=timestamp) for _ in range(205)])
        foreign = SecurityAuditEvent(tenant_id=b, event_type='foreign_marker', occurred_at=timestamp)
        db.add(foreign); db.flush(); foreign_id = foreign.id
    token = client.post('/api/v1/secure/login', json={'tenant_id':str(a),'username':'admin','password':'a secure password'}).json()['access_token']
    headers = {'Authorization':'Bearer '+token}
    assert client.get('/api/v1/secure/audit', headers=headers, params={'before':str(foreign_id)}).status_code == 404
    assert client.get('/api/v1/secure/audit', headers=headers, params={'before':'invalid'}).status_code == 422
    ids, marker_ids, cursor, pages = [], [], None, 0
    while True:
        response = client.get('/api/v1/secure/audit', headers=headers, params={'before':cursor} if cursor else {})
        assert response.status_code == 200
        page = response.json(); pages += 1
        assert all(item['event_type'] != 'foreign_marker' for item in page['items'])
        ids.extend(x['id'] for x in page['items'])
        marker_ids.extend(x['id'] for x in page['items'] if x['event_type'] == 'fixture_marker')
        cursor = page['next_cursor']
        if cursor is None: break
        assert pages < 5
    assert pages == 3 and len(marker_ids) == 205 and len(set(ids)) == len(ids)
