"""The PostgreSQL URL, if supplied, must point to an empty disposable test database."""
import os
from pathlib import Path
from uuid import UUID, uuid4
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.models import Entity, Relationship, Tenant
from app.rate_limit import consume
from app.audit import AuditType, record_event

HERE = Path(__file__).resolve().parents[1]

@pytest.fixture(params=['sqlite', 'postgres'])
def migration_db(request, monkeypatch, tmp_path):
    if request.param == 'postgres':
        url = os.environ.get('TEST_DATABASE_URL')
        if not url:
            pytest.skip('TEST_DATABASE_URL not configured (must be a disposable empty database)')
    else:
        url = f'sqlite:///{tmp_path / "migration.db"}'
    monkeypatch.setenv('DATABASE_URL', url)
    config = Config(str(HERE / 'alembic.ini'))
    engine = create_engine(url)
    if request.param == 'sqlite':
        @event.listens_for(engine, 'connect')
        def enable_foreign_keys(connection, _):
            connection.execute('PRAGMA foreign_keys=ON')
    assert not inspect(engine).get_table_names(), 'Test DB must be empty and disposable'
    try:
        command.upgrade(config, 'head')
        yield engine, config
    finally:
        command.downgrade(config, 'base')
        # Alembic leaves an empty version table after downgrade. The fixture
        # created it in a verified-empty disposable database, so remove it too.
        with engine.begin() as connection:
            connection.exec_driver_sql('DROP TABLE IF EXISTS alembic_version')
        engine.dispose()

def test_migration_and_tenant_constraint(migration_db):
    engine, _ = migration_db
    assert {'tenants', 'intelligence_entities', 'intelligence_relationships'} <= set(inspect(engine).get_table_names())
    with Session(engine) as db:
        a, b = Tenant(id=uuid4(), name='a'), Tenant(id=uuid4(), name='b')
        db.add_all([a, b]); db.flush()
        rate_args = dict(secret=b'x'*32, scope='test', identifier='login', limit=1, window_seconds=60, now=120)
        assert consume(db, **rate_args)
        assert not consume(db, **rate_args)
        record_event(db, a.id, AuditType.LOGIN_FAILED)
        x = Entity(id=uuid4(), tenant_id=a.id, kind='indicator', title='x', source='test')
        y = Entity(id=uuid4(), tenant_id=b.id, kind='indicator', title='y', source='test')
        db.add_all([x, y]); db.commit()
        db.add(Relationship(tenant_id=a.id, subject_id=x.id, object_id=y.id, kind='RELATED_TO', source='test'))
        with pytest.raises(IntegrityError): db.commit()
        db.rollback()

def test_downgrade_removes_tables(tmp_path, monkeypatch):
    url = f'sqlite:///{tmp_path / "rollback.db"}'
    monkeypatch.setenv('DATABASE_URL', url)
    config = Config(str(HERE / 'alembic.ini'))
    command.upgrade(config, 'head')
    command.downgrade(config, 'base')
    engine = create_engine(url)
    assert 'tenants' not in inspect(engine).get_table_names()
    engine.dispose()

def test_missing_database_url_fails_closed(monkeypatch):
    monkeypatch.delenv('DATABASE_URL', raising=False)
    with pytest.raises(RuntimeError, match='DATABASE_URL'):
        command.upgrade(Config(str(HERE / 'alembic.ini')), 'head')

def test_identity_upgrade_and_targeted_rollback(tmp_path, monkeypatch):
    url = f'sqlite:///{tmp_path / "identity.db"}'
    monkeypatch.setenv('DATABASE_URL', url)
    config = Config(str(HERE / 'alembic.ini'))
    command.upgrade(config, '0001_initial_graph')
    engine = create_engine(url)
    assert 'users' not in inspect(engine).get_table_names()
    command.upgrade(config, 'head')
    assert {'users', 'auth_sessions'} <= set(inspect(engine).get_table_names())
    command.downgrade(config, '0001_initial_graph')
    tables = set(inspect(engine).get_table_names())
    assert 'tenants' in tables and 'users' not in tables and 'auth_sessions' not in tables
    command.downgrade(config, 'base')
    engine.dispose()

def test_audit_rate_limit_revision_rollback(tmp_path, monkeypatch):
    url = f'sqlite:///{tmp_path / "audit.db"}'
    monkeypatch.setenv('DATABASE_URL', url)
    config = Config(str(HERE / 'alembic.ini'))
    command.upgrade(config, '0002_identity_sessions')
    engine = create_engine(url)
    assert 'security_audit_events' not in inspect(engine).get_table_names()
    command.upgrade(config, 'head')
    assert {'security_audit_events', 'rate_limit_buckets'} <= set(inspect(engine).get_table_names())
    command.downgrade(config, '0002_identity_sessions')
    tables = set(inspect(engine).get_table_names())
    assert 'users' in tables and 'security_audit_events' not in tables and 'rate_limit_buckets' not in tables
    command.downgrade(config, 'base')
    engine.dispose()

def test_migrated_database_login_concurrency(migration_db):
    from concurrent.futures import ThreadPoolExecutor
    from sqlalchemy.orm import sessionmaker
    from app.login_service import LoginPolicy, LoginStatus, login
    from app.models import User
    from app.security import hash_password
    engine, _ = migration_db
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant_id = uuid4()
    with factory.begin() as db:
        db.add(Tenant(id=tenant_id, name='test')); db.flush()
        db.add(User(id=uuid4(), tenant_id=tenant_id, username='analyst', password_hash=hash_password('a secure password'), role='analyst', active=True))
    policy = LoginPolicy(account_limit=2, source_limit=20, global_limit=100)
    def attempt(_):
        return login(factory, secret=b'x'*32, tenant_id=tenant_id, username='analyst', password='incorrect', source_ip='192.0.2.1', policy=policy).status
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(attempt, range(4)))
    assert results.count(LoginStatus.DENIED) == 2
    assert results.count(LoginStatus.THROTTLED) == 2

def test_audit_target_revision_rollback(tmp_path, monkeypatch):
    url = f'sqlite:///{tmp_path / "audit_target.db"}'
    monkeypatch.setenv('DATABASE_URL', url)
    config = Config(str(HERE / 'alembic.ini'))
    command.upgrade(config, '0003_audit_rate_limit')
    engine = create_engine(url)
    assert 'target_user_id' not in {c['name'] for c in inspect(engine).get_columns('security_audit_events')}
    command.upgrade(config, 'head')
    assert 'target_user_id' in {c['name'] for c in inspect(engine).get_columns('security_audit_events')}
    command.downgrade(config, '0003_audit_rate_limit')
    assert 'target_user_id' not in {c['name'] for c in inspect(engine).get_columns('security_audit_events')}
    command.downgrade(config, 'base')
    engine.dispose()

def test_migrated_database_account_audit(migration_db):
    from sqlalchemy.orm import sessionmaker
    from app.accounts import create_user, disable_user
    from app.models import User, SecurityAuditEvent
    from app.security import Role, hash_password
    from app.sessions import issue_session
    engine, _ = migration_db
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant_id = uuid4()
    with factory.begin() as db:
        db.add(Tenant(id=tenant_id, name='t')); db.flush()
        db.add(User(tenant_id=tenant_id, username='admin', password_hash=hash_password('a secure password'), role='admin', active=True))
    with factory.begin() as db:
        token = issue_session(db, tenant_id, 'admin', 'a secure password')
    user_id = create_user(factory, admin_token=token, username='analyst', password='another safe password', role=Role.ANALYST)
    disable_user(factory, admin_token=token, user_id=user_id)
    with factory() as db:
        assert db.get(User, user_id).active is False
        assert len(list(db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.target_user_id == user_id)))) == 2

def test_migrated_database_bootstrap(migration_db):
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.models import SecurityAuditEvent, User
    engine, _ = migration_db
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant_id, user_id = create_tenant_with_admin(factory, tenant_name='Test tenant', username='admin', password='a safe long password')
    with factory() as db:
        assert db.get(User, user_id).tenant_id == tenant_id
        assert db.scalar(select(SecurityAuditEvent).where(SecurityAuditEvent.target_user_id == user_id)).event_type == 'tenant_bootstrapped'

def test_migrated_protected_api(migration_db):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.protected_api import protected_router
    engine, _ = migration_db
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant_id, _ = create_tenant_with_admin(factory, tenant_name='Example', username='admin', password='a long safe password')
    app = FastAPI(); app.include_router(protected_router(factory, b'x'*32))
    with TestClient(app, base_url='https://testserver', client=('192.0.2.1', 1234)) as client:
        result = client.post('/api/v1/secure/login', json={'tenant_id':str(tenant_id), 'username':'admin', 'password':'a long safe password'})
        assert result.status_code == 200
        token = result.json()['access_token']
        headers = {'Authorization': f'Bearer {token}'}
        assert client.get('/api/v1/secure/entities', headers=headers).json() == {'items': [], 'truncated': False, 'next_cursor': None}
        entity = client.post('/api/v1/secure/entities', headers=headers, json={'kind':'indicator', 'title':'example', 'source':'manual', 'confidence':55})
        assert entity.status_code == 201 and entity.json()['verification_status'] == 'unverified'
        entity_id = entity.json()['id']
        evidence = client.post(f'/api/v1/secure/entities/{entity_id}/evidence', headers=headers, json={'description':'analyst note', 'source':'test'})
        assert evidence.status_code == 201
        assert len(client.get(f'/api/v1/secure/entities/{entity_id}/evidence', headers=headers).json()['items']) == 1
        other = client.post('/api/v1/secure/entities', headers=headers, json={'kind':'indicator', 'title':'other', 'source':'manual'}).json()['id']
        relation = client.post('/api/v1/secure/relationships', headers=headers, json={'subject_id':entity_id, 'object_id':other, 'kind':'RELATED_TO', 'source':'test', 'evidence_id':evidence.json()['id']})
        assert relation.status_code == 201
        assert len(client.get(f'/api/v1/secure/entities/{entity_id}/relationships', headers=headers).json()['items']) == 1
        assert any(x['id'] == entity_id and x['confidence'] == 55 for x in client.get('/api/v1/secure/entities', headers=headers).json()['items'])
        response = client.post('/api/v1/secure/users', headers=headers, json={'username':'analyst', 'password':'another long password', 'role':'analyst'})
        assert response.status_code == 201
        user_id = response.json()['id']
        assert client.patch(f'/api/v1/secure/users/{user_id}/role', headers=headers, json={'role':'viewer'}).status_code == 200
        assert client.post(f'/api/v1/secure/users/{user_id}/disable', headers=headers).status_code == 200
        status = client.get('/api/v1/secure/sources/cisa-kev/status', headers=headers)
        assert status.status_code == 200 and status.json()['last_attempt'] is None
        assert client.get('/api/v1/secure/audit', headers=headers).status_code == 200
        assert client.post('/api/v1/secure/logout', headers=headers).status_code == 200

def test_audit_roles_revision_rollback(tmp_path, monkeypatch):
    url = f'sqlite:///{tmp_path / "audit_roles.db"}'
    monkeypatch.setenv('DATABASE_URL', url)
    config = Config(str(HERE / 'alembic.ini'))
    command.upgrade(config, '0004_audit_target')
    engine = create_engine(url)
    assert 'previous_role' not in {c['name'] for c in inspect(engine).get_columns('security_audit_events')}
    command.upgrade(config, 'head')
    assert {'previous_role', 'new_role'} <= {c['name'] for c in inspect(engine).get_columns('security_audit_events')}
    command.downgrade(config, '0004_audit_target')
    assert 'previous_role' not in {c['name'] for c in inspect(engine).get_columns('security_audit_events')}
    command.downgrade(config, 'base')
    engine.dispose()

def test_entity_provenance_revision_rollback(tmp_path, monkeypatch):
    url = f'sqlite:///{tmp_path / "entity_provenance.db"}'
    monkeypatch.setenv('DATABASE_URL', url)
    config = Config(str(HERE / 'alembic.ini'))
    command.upgrade(config, '0005_audit_roles')
    engine = create_engine(url)
    assert 'confidence' not in {c['name'] for c in inspect(engine).get_columns('intelligence_entities')}
    command.upgrade(config, 'head')
    assert {'confidence', 'verification_status', 'created_by'} <= {c['name'] for c in inspect(engine).get_columns('intelligence_entities')}
    command.downgrade(config, '0005_audit_roles')
    assert 'confidence' not in {c['name'] for c in inspect(engine).get_columns('intelligence_entities')}
    command.downgrade(config, 'base')
    engine.dispose()

def test_evidence_revision_rollback(tmp_path, monkeypatch):
    url = f'sqlite:///{tmp_path / "evidence.db"}'
    monkeypatch.setenv('DATABASE_URL', url)
    config = Config(str(HERE / 'alembic.ini'))
    command.upgrade(config, '0006_entity_provenance')
    engine = create_engine(url)
    assert 'evidence_references' not in inspect(engine).get_table_names()
    command.upgrade(config, 'head')
    assert 'evidence_references' in inspect(engine).get_table_names()
    command.downgrade(config, '0006_entity_provenance')
    assert 'evidence_references' not in inspect(engine).get_table_names()
    command.downgrade(config, 'base')
    engine.dispose()

def test_migrated_schema_matches_model_metadata(migration_db):
    _, config = migration_db
    command.check(config)

def test_migrated_evidence_foreign_keys_block_cross_tenant(migration_db):
    from app.models import EvidenceReference, User
    engine, _ = migration_db
    a, b = uuid4(), uuid4()
    with Session(engine) as db:
        db.add_all([Tenant(id=a, name='a'), Tenant(id=b, name='b')]); db.flush()
        u = User(id=uuid4(), tenant_id=a, username='a', password_hash='not-used', role='analyst', active=True)
        own = Entity(id=uuid4(), tenant_id=a, kind='indicator', title='own', source='test')
        other = Entity(id=uuid4(), tenant_id=b, kind='indicator', title='other', source='test')
        db.add_all([u, own, other]); db.commit()
        db.add(EvidenceReference(tenant_id=a, entity_id=other.id, created_by=u.id, description='test', source='test'))
        with pytest.raises(IntegrityError): db.commit()
        db.rollback()

def test_migrated_provenance_links_exact_entity(migration_db):
    from app.models import EvidenceReference, ProvenanceEvent, User
    engine, _ = migration_db
    with Session(engine) as db:
        tenant = Tenant(id=uuid4(), name='t'); db.add(tenant); db.flush()
        user = User(id=uuid4(), tenant_id=tenant.id, username='user', password_hash='n/a', role='analyst', active=True)
        a = Entity(id=uuid4(), tenant_id=tenant.id, kind='indicator', title='a', source='test')
        b = Entity(id=uuid4(), tenant_id=tenant.id, kind='indicator', title='b', source='test')
        db.add_all([user,a,b]); db.flush()
        ev = EvidenceReference(id=uuid4(), tenant_id=tenant.id, entity_id=a.id, created_by=user.id, description='note', source='test')
        db.add(ev); db.commit()
        db.add(ProvenanceEvent(tenant_id=tenant.id, entity_id=b.id, actor_id=user.id, evidence_id=ev.id, event_type='test', details={}))
        with pytest.raises(IntegrityError): db.commit()
        db.rollback()

def test_provenance_revision_rollback(tmp_path, monkeypatch):
    url = f'sqlite:///{tmp_path / "provenance.db"}'
    monkeypatch.setenv('DATABASE_URL', url)
    config = Config(str(HERE / 'alembic.ini'))
    command.upgrade(config, '0007_evidence_reference')
    engine = create_engine(url)
    assert 'provenance_events' not in inspect(engine).get_table_names()
    command.upgrade(config, 'head')
    assert 'provenance_events' in inspect(engine).get_table_names()
    command.downgrade(config, '0007_evidence_reference')
    assert 'provenance_events' not in inspect(engine).get_table_names()
    command.downgrade(config, 'base')
    engine.dispose()

def test_postgres_concurrent_entity_edits(migration_db):
    from concurrent.futures import ThreadPoolExecutor
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.protected_api import protected_router
    engine, _ = migration_db
    if engine.dialect.name != 'postgresql':
        pytest.skip('PostgreSQL concurrency test')
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, _ = create_tenant_with_admin(factory, tenant_name='test', username='admin', password='a long safe password')
    app = FastAPI(); app.include_router(protected_router(factory, b'x'*32))
    with TestClient(app, base_url='https://testserver', client=('192.0.2.1',123)) as client:
        token = client.post('/api/v1/secure/login', json={'tenant_id':str(tenant),'username':'admin','password':'a long safe password'}).json()['access_token']
        headers = {'Authorization':'Bearer '+token}
        entity = client.post('/api/v1/secure/entities', json={'kind':'indicator','title':'before','source':'test'}, headers=headers).json()['id']
        def change(title):
            return client.patch(f'/api/v1/secure/entities/{entity}', json={'expected_version':1,'title':title,'confidence':50}, headers=headers).status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(change, ['first', 'second']))
        assert sorted(statuses) == [200, 409]
        events = client.get(f'/api/v1/secure/entities/{entity}/provenance', headers=headers).json()['items']
        assert len([event for event in events if event['event_type'] == 'manual_entity_updated']) == 1

def test_entity_version_revision_rollback(tmp_path, monkeypatch):
    url = f'sqlite:///{tmp_path / "version.db"}'
    monkeypatch.setenv('DATABASE_URL', url)
    config = Config(str(HERE / 'alembic.ini'))
    command.upgrade(config, '0008_provenance_events')
    engine = create_engine(url)
    assert 'version' not in {c['name'] for c in inspect(engine).get_columns('intelligence_entities')}
    command.upgrade(config, 'head')
    assert 'version' in {c['name'] for c in inspect(engine).get_columns('intelligence_entities')}
    command.downgrade(config, '0008_provenance_events')
    assert 'version' not in {c['name'] for c in inspect(engine).get_columns('intelligence_entities')}
    command.downgrade(config, 'base')
    engine.dispose()

def test_migrated_relationship_evidence_constraint(migration_db):
    from app.models import EvidenceReference, User
    engine, _ = migration_db
    with Session(engine) as db:
        tenant = Tenant(id=uuid4(), name='test'); db.add(tenant); db.flush()
        user = User(id=uuid4(), tenant_id=tenant.id, username='analyst', password_hash='n/a', role='analyst', active=True)
        a = Entity(id=uuid4(), tenant_id=tenant.id, kind='indicator', title='a', source='test')
        b = Entity(id=uuid4(), tenant_id=tenant.id, kind='indicator', title='b', source='test')
        db.add_all([user,a,b]); db.flush()
        evidence = EvidenceReference(id=uuid4(), tenant_id=tenant.id, entity_id=a.id, created_by=user.id, description='test', source='test')
        db.add(evidence); db.commit()
        db.add(Relationship(tenant_id=tenant.id, subject_id=b.id, object_id=a.id, created_by=user.id, evidence_id=evidence.id, kind='RELATED_TO', source='test'))
        with pytest.raises(IntegrityError): db.commit()
        db.rollback()

def test_relationship_revision_rollback(tmp_path, monkeypatch):
    url = f'sqlite:///{tmp_path / "relationship.db"}'
    monkeypatch.setenv('DATABASE_URL', url)
    config = Config(str(HERE / 'alembic.ini'))
    command.upgrade(config, '0009_entity_version')
    engine = create_engine(url)
    assert 'confidence' not in {c['name'] for c in inspect(engine).get_columns('intelligence_relationships')}
    command.upgrade(config, 'head')
    assert {'created_by','confidence','evidence_id'} <= {c['name'] for c in inspect(engine).get_columns('intelligence_relationships')}
    command.downgrade(config, '0009_entity_version')
    assert 'confidence' not in {c['name'] for c in inspect(engine).get_columns('intelligence_relationships')}
    command.downgrade(config, 'base')
    engine.dispose()

def test_postgres_concurrent_cisa_import_is_deduplicated(migration_db):
    import json
    from concurrent.futures import ThreadPoolExecutor
    from datetime import datetime, timezone
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.connectors.cisa_kev import parse_snapshot
    from app.connectors.cisa_import import import_snapshot
    from app.models import CisaCatalogRecord, Entity
    from app.sessions import issue_session
    engine, _ = migration_db
    if engine.dialect.name != 'postgresql': pytest.skip('PostgreSQL concurrency test')
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, _ = create_tenant_with_admin(factory, tenant_name='test', username='admin', password='a safe long password')
    with factory.begin() as db: token = issue_session(db, tenant, 'admin', 'a safe long password')
    fixture = {'catalogVersion':'test','dateReleased':'2026-01-01T00:00:00Z','count':1,'vulnerabilities':[{'cveID':'CVE-2099-0001',
        'vendorProject':'Fixture','product':'Fixture','vulnerabilityName':'Fixture','dateAdded':'2026-01-01',
        'shortDescription':'Fixture only','requiredAction':'Test','dueDate':'2026-02-01','knownRansomwareCampaignUse':'Unknown'}]}
    snapshot = parse_snapshot(json.dumps(fixture).encode(), collected_at=datetime(2026,1,2,tzinfo=timezone.utc))
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: import_snapshot(factory, admin_token=token, snapshot=snapshot), range(2)))
    assert sorted(r['created'] for r in results) == [0,1]
    with factory() as db:
        assert len(list(db.scalars(select(CisaCatalogRecord)))) == 1
        assert len(list(db.scalars(select(Entity)))) == 1

def test_cisa_revision_rollback(tmp_path, monkeypatch):
    url = f'sqlite:///{tmp_path / "cisa.db"}'
    monkeypatch.setenv('DATABASE_URL', url)
    config = Config(str(HERE / 'alembic.ini'))
    command.upgrade(config, '0010_relationship_attribution')
    engine = create_engine(url)
    assert 'cisa_catalog_records' not in inspect(engine).get_table_names()
    command.upgrade(config, 'head')
    assert {'cisa_catalog_records', 'cisa_catalog_states'} <= set(inspect(engine).get_table_names())
    command.downgrade(config, '0010_relationship_attribution')
    assert 'cisa_catalog_records' not in inspect(engine).get_table_names()
    command.downgrade(config, 'base')
    engine.dispose()

def test_postgres_concurrent_sync_attempts_are_serialized(migration_db):
    from concurrent.futures import ThreadPoolExecutor
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.connectors.cisa_sync import begin_sync, SyncBusy
    from app.sessions import issue_session
    engine, _ = migration_db
    if engine.dialect.name != 'postgresql': pytest.skip('PostgreSQL concurrency test')
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, _ = create_tenant_with_admin(factory, tenant_name='test', username='admin', password='a safe long password')
    with factory.begin() as db: token = issue_session(db, tenant, 'admin', 'a safe long password')
    def begin(_):
        try:
            begin_sync(factory, admin_token=token)
            return 'started'
        except SyncBusy:
            return 'busy'
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(begin, range(2))) == ['busy', 'started']

def test_sync_attempt_revision_rollback(tmp_path, monkeypatch):
    url = f'sqlite:///{tmp_path / "sync.db"}'
    monkeypatch.setenv('DATABASE_URL', url)
    config = Config(str(HERE / 'alembic.ini'))
    command.upgrade(config, '0011_cisa_catalog')
    engine = create_engine(url)
    assert 'cisa_sync_attempts' not in inspect(engine).get_table_names()
    command.upgrade(config, 'head')
    assert 'cisa_sync_attempts' in inspect(engine).get_table_names()
    command.downgrade(config, '0011_cisa_catalog')
    assert 'cisa_sync_attempts' not in inspect(engine).get_table_names()
    command.downgrade(config, 'base')
    engine.dispose()

def test_migrated_entity_pagination(migration_db):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.protected_api import protected_router
    engine, _ = migration_db
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, _ = create_tenant_with_admin(factory, tenant_name='test', username='admin', password='a safe long password')
    other, _ = create_tenant_with_admin(factory, tenant_name='other', username='admin', password='a safe long password')
    with factory.begin() as db:
        db.add_all([Entity(tenant_id=tenant, kind='indicator', title=f'test-{i}', source='fixture') for i in range(101)])
        foreign = Entity(tenant_id=other, kind='indicator', title='foreign', source='fixture'); db.add(foreign); db.flush(); foreign_id=foreign.id
    app = FastAPI(); app.include_router(protected_router(factory, b'x'*32))
    with TestClient(app, base_url='https://testserver', client=('192.0.2.1',123)) as client:
        result = client.post('/api/v1/secure/login', json={'tenant_id':str(tenant),'username':'admin','password':'a safe long password'})
        headers = {'Authorization':'Bearer '+result.json()['access_token']}
        first = client.get('/api/v1/secure/entities', headers=headers).json()
        assert len(first['items']) == 100 and first['next_cursor']
        second = client.get('/api/v1/secure/entities', params={'after':first['next_cursor']}, headers=headers).json()
        assert len(second['items']) == 1 and second['next_cursor'] is None
        assert second['items'][0]['id'] not in {x['id'] for x in first['items']}
        assert client.get('/api/v1/secure/entities',params={'after':str(foreign_id)},headers=headers).status_code==404
        assert client.get('/api/v1/secure/entities',params={'after':str(uuid4())},headers=headers).status_code==404
        filtered=client.get('/api/v1/secure/entities',params={'kind':'indicator'},headers=headers).json()
        assert len(filtered['items'])==100 and filtered['next_cursor']
        assert len(client.get('/api/v1/secure/entities',params={'kind':'indicator','after':filtered['next_cursor']},headers=headers).json()['items'])==1
        assert client.get('/api/v1/secure/entities',params={'kind':'asset','after':filtered['next_cursor']},headers=headers).status_code==404
        assert client.get('/api/v1/secure/entities',params={'kind':'asset'},headers=headers).json()['items']==[]
        assert client.get('/api/v1/secure/entities',params={'kind':'unknown'},headers=headers).status_code==422

def test_migrated_audit_cursor_pagination(migration_db):
    from datetime import datetime, timezone
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.models import SecurityAuditEvent
    from app.protected_api import protected_router
    engine, _ = migration_db
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, _ = create_tenant_with_admin(factory, tenant_name='test', username='admin', password='a safe long password')
    with factory.begin() as db:
        db.add_all([SecurityAuditEvent(tenant_id=tenant, event_type='fixture_marker', occurred_at=datetime(2026,1,1,tzinfo=timezone.utc)) for _ in range(101)])
    app = FastAPI(); app.include_router(protected_router(factory, b'x'*32))
    with TestClient(app, base_url='https://testserver', client=('192.0.2.1',123)) as client:
        token = client.post('/api/v1/secure/login', json={'tenant_id':str(tenant),'username':'admin','password':'a safe long password'}).json()['access_token']
        headers = {'Authorization':'Bearer '+token}
        first = client.get('/api/v1/secure/audit', headers=headers).json()
        assert len(first['items']) == 100 and first['next_cursor']
        second = client.get('/api/v1/secure/audit', params={'before':first['next_cursor']}, headers=headers).json()
        assert second['next_cursor'] is None
        ids = [x['id'] for x in first['items'] + second['items']]
        assert len(ids) == len(set(ids))
        assert len([x for x in first['items'] + second['items'] if x['event_type'] == 'fixture_marker']) == 101

def test_audit_index_revision_rollback(tmp_path, monkeypatch):
    url = f'sqlite:///{tmp_path / "audit_index.db"}'
    monkeypatch.setenv('DATABASE_URL', url)
    config = Config(str(HERE / 'alembic.ini'))
    command.upgrade(config, '0012_cisa_sync_attempts')
    engine = create_engine(url)
    assert 'ix_audit_tenant_time_id' not in {x['name'] for x in inspect(engine).get_indexes('security_audit_events')}
    command.upgrade(config, 'head')
    assert 'ix_audit_tenant_time_id' in {x['name'] for x in inspect(engine).get_indexes('security_audit_events')}
    command.downgrade(config, '0012_cisa_sync_attempts')
    assert 'ix_audit_tenant_time_id' not in {x['name'] for x in inspect(engine).get_indexes('security_audit_events')}
    command.downgrade(config, 'base')
    engine.dispose()

def test_migrated_graph_keyset_pagination_and_scope(migration_db):
    from datetime import datetime, timezone
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.models import EvidenceReference, ProvenanceEvent, Relationship
    from app.protected_api import protected_router
    engine, _ = migration_db
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, actor = create_tenant_with_admin(factory, tenant_name='test', username='admin', password='a safe long password')
    when = datetime(2026,1,1,tzinfo=timezone.utc)
    with factory.begin() as db:
        a, b, c = [Entity(tenant_id=tenant, kind='indicator', title=title, source='test') for title in ['a','b','c']]
        db.add_all([a,b,c]); db.flush(); entity_id,other_entity_id = a.id,c.id
        db.add_all([EvidenceReference(tenant_id=tenant, entity_id=a.id, created_by=actor, description='fixture', source='test', created_at=when) for _ in range(101)])
        db.add_all([ProvenanceEvent(tenant_id=tenant, entity_id=a.id, actor_id=actor, event_type='fixture', details={}, occurred_at=when) for _ in range(101)])
        db.add_all([Relationship(tenant_id=tenant, subject_id=a.id, object_id=b.id, kind='RELATED_TO', source='fixture', created_at=when) for _ in range(101)])
        unrelated = Relationship(tenant_id=tenant, subject_id=b.id, object_id=c.id, kind='RELATED_TO', source='fixture', created_at=when)
        db.add(unrelated); db.flush(); unrelated_id = unrelated.id
    app = FastAPI(); app.include_router(protected_router(factory, b'x'*32))
    with TestClient(app, base_url='https://testserver', client=('192.0.2.1',123)) as client:
        token = client.post('/api/v1/secure/login', json={'tenant_id':str(tenant),'username':'admin','password':'a safe long password'}).json()['access_token']
        headers = {'Authorization':'Bearer '+token}
        for category in ('evidence','provenance','relationships'):
            path = f'/api/v1/secure/entities/{entity_id}/{category}'
            first = client.get(path, headers=headers).json()
            assert len(first['items']) == 100 and first['next_cursor'] and first['truncated']
            second = client.get(path, headers=headers, params={'after':first['next_cursor']}).json()
            assert len(second['items']) == 1 and second['next_cursor'] is None and not second['truncated']
            ids = [x['id'] for x in first['items']+second['items']]
            assert len(set(ids)) == 101
        evidence_cursor = client.get(f'/api/v1/secure/entities/{entity_id}/evidence',headers=headers).json()['next_cursor']
        assert client.get(f'/api/v1/secure/entities/{other_entity_id}/evidence',headers=headers,params={'after':evidence_cursor}).status_code==404
        assert client.get(f'/api/v1/secure/entities/{entity_id}/evidence',headers=headers,params={'after':str(uuid4())}).status_code==404
        assert client.get(f'/api/v1/secure/entities/{entity_id}/relationships', headers=headers, params={'after':str(unrelated_id)}).status_code == 404
        assert client.get(f'/api/v1/secure/entities/{entity_id}/provenance', headers=headers, params={'after':str(unrelated_id)}).status_code == 404

@pytest.mark.parametrize('change,expected', [('demote',403), ('revoke',401)])
def test_postgres_mutation_rechecks_authorization_after_lock_wait(migration_db, change, expected):
    from concurrent.futures import ThreadPoolExecutor
    from datetime import datetime, timezone
    from threading import Event
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import event, select, update
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.models import AuthSession, User
    from app.protected_api import protected_router
    engine, _ = migration_db
    if engine.dialect.name != 'postgresql': pytest.skip('PostgreSQL row locks required')
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, actor = create_tenant_with_admin(factory, tenant_name='test', username='admin', password='a safe long password')
    app = FastAPI(); app.include_router(protected_router(factory, b'x'*32))
    with TestClient(app, base_url='https://testserver', client=('192.0.2.1',123)) as client:
        token = client.post('/api/v1/secure/login', json={'tenant_id':str(tenant),'username':'admin','password':'a safe long password'}).json()['access_token']
        waiting = Event()
        def observe(conn, cursor, statement, parameters, context, executemany):
            if 'FROM users' in statement and 'FOR UPDATE' in statement:
                waiting.set()
        with ThreadPoolExecutor(max_workers=1) as pool:
            with factory.begin() as blocker:
                blocker.scalar(select(User).where(User.id == actor).with_for_update())
                event.listen(engine, 'before_cursor_execute', observe)
                future = pool.submit(client.post, '/api/v1/secure/entities', headers={'Authorization':'Bearer '+token},
                    json={'kind':'indicator','title':'must not be created','source':'synthetic'})
                try:
                    assert waiting.wait(10), 'request did not attempt user row lock'
                    if change == 'demote':
                        blocker.execute(update(User).where(User.id == actor).values(role='viewer'))
                    else:
                        blocker.execute(update(AuthSession).where(AuthSession.user_id == actor).values(revoked_at=datetime.now(timezone.utc)))
                finally:
                    event.remove(engine, 'before_cursor_execute', observe)
            response = future.result(timeout=10)
        assert response.status_code == expected
        with factory() as db:
            assert not db.scalar(select(Entity.id).where(Entity.tenant_id == tenant, Entity.title == 'must not be created'))

def test_postgres_cisa_tenant_lock_allows_concurrent_audit_fk(migration_db):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from sqlalchemy import event, select, text
    from sqlalchemy.orm import sessionmaker
    from app.audit import AuditType, record_event
    from app.bootstrap import create_tenant_with_admin
    from app.connectors.cisa_sync import begin_sync
    from app.login_service import login
    from app.models import User
    engine, _ = migration_db
    if engine.dialect.name != 'postgresql': pytest.skip('PostgreSQL row locks required')
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, actor = create_tenant_with_admin(factory, tenant_name='test', username='admin', password='a safe long password')
    token = login(factory, secret=b'x'*32, tenant_id=tenant, username='admin', password='a safe long password', source_ip='192.0.2.1').token
    waiting = Event()
    def observe(conn, cursor, statement, parameters, context, executemany):
        if 'FROM users' in statement and 'FOR UPDATE' in statement:
            waiting.set()
    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory.begin() as db:
            db.execute(text("SET LOCAL lock_timeout = '3s'"))
            db.scalar(select(User).where(User.id == actor).with_for_update())
            event.listen(engine, 'before_cursor_execute', observe)
            future = pool.submit(begin_sync, factory, admin_token=token)
            try:
                assert waiting.wait(10), 'sync did not acquire tenant lock and reach actor lock'
                # Holds the actor lock while inserting an audit row referencing tenant.
                # A tenant FOR UPDATE would conflict with the FK's KEY SHARE lock.
                record_event(db, tenant, AuditType.INTELLIGENCE_READ, actor)
            finally:
                event.remove(engine, 'before_cursor_execute', observe)
        assert future.result(timeout=10) is not None

def test_postgres_mutual_admin_demotions_serialize_without_deadlock(migration_db):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from sqlalchemy import event
    from sqlalchemy.orm import sessionmaker
    from app.accounts import create_user, change_role
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.security import Role
    engine, _ = migration_db
    if engine.dialect.name != 'postgresql': pytest.skip('PostgreSQL row locks required')
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, first = create_tenant_with_admin(factory, tenant_name='test', username='adminone', password='a safe long password')
    def token(username):
        return login(factory, secret=b'x'*32, tenant_id=tenant, username=username, password='a safe long password', source_ip='192.0.2.1').token
    one = token('adminone')
    second = create_user(factory, admin_token=one, username='admintwo', password='a safe long password', role=Role.ADMIN)
    two = token('admintwo')
    barrier = Barrier(2)
    lock_barrier = Barrier(2)
    def observe(conn, cursor, statement, parameters, context, executemany):
        if 'FROM users' in statement and 'ORDER BY users.id' in statement and 'FOR UPDATE' in statement:
            lock_barrier.wait(timeout=10)
    def demote(token, target):
        barrier.wait(timeout=10)
        try:
            change_role(factory, admin_token=token, user_id=target, role=Role.VIEWER)
            return 'success'
        except PermissionError:
            return 'denied'
    event.listen(engine, 'before_cursor_execute', observe)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(demote, one, second)
            b = pool.submit(demote, two, first)
            assert sorted([a.result(timeout=20), b.result(timeout=20)]) == ['denied', 'success']
    finally:
        event.remove(engine, 'before_cursor_execute', observe)

def test_migrated_login_throttle_bounds_bucket_allocation(migration_db, monkeypatch):
    from sqlalchemy import func, select
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import LoginPolicy, LoginStatus, login
    from app.models import RateLimitBucket
    engine, _ = migration_db
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, _ = create_tenant_with_admin(factory, tenant_name='test', username='admin', password='a safe long password')
    policy = LoginPolicy(global_limit=1, source_limit=5, account_limit=5)
    from app import login_service
    original_consume = login_service.consume
    monkeypatch.setattr(login_service, 'consume', lambda db, **kwargs: original_consume(db, now=120, **kwargs))
    for i in range(4):
        result = login(factory, secret=b'x'*32, tenant_id=tenant, username=f'user{i}', password='wrong', source_ip=f'192.0.2.{i+1}', policy=policy)
        assert result.status == (LoginStatus.DENIED if i == 0 else LoginStatus.THROTTLED)
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(RateLimitBucket)) == 3
        assert db.scalar(select(func.max(RateLimitBucket.attempts))) == 2

def test_migrated_bounded_rate_cleanup_and_operator_command(migration_db, capsys):
    import time
    from sqlalchemy.orm import Session
    from app.maintenance import main
    from app.models import RateLimitBucket
    from app.rate_limit import cleanup_expired_batch
    engine, _ = migration_db
    now = int(time.time())
    with Session(engine) as db:
        db.add_all([RateLimitBucket(key_digest=f'{i:064x}', window_start=now - 90000 + i, attempts=1) for i in range(3)])
        db.add(RateLimitBucket(key_digest='f'*64, window_start=now, attempts=1)); db.commit()
        assert cleanup_expired_batch(db, batch_size=1, now=now) == 1
        db.rollback()
        assert len(list(db.scalars(select(RateLimitBucket)))) == 4
    assert main([]) == 2
    if engine.dialect.name == 'postgresql':
        assert main(['--confirm-cleanup','--batch-size','2']) == 0
        assert 'Deleted 2' in capsys.readouterr().out
        with Session(engine) as db:
            assert len(list(db.scalars(select(RateLimitBucket)))) == 2
    else:
        assert main(['--confirm-cleanup']) == 1
        assert 'Maintenance failed' in capsys.readouterr().err

def test_cisa_operator_command_synthetic_fixture_on_postgres(migration_db, monkeypatch, capsys):
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.connectors import cisa_cli, cisa_sync
    from app.connectors.cisa_sync import synchronize
    from app.login_service import login
    from app.models import CisaCatalogRecord
    from test_cisa_import import fixture_snapshot
    engine, _ = migration_db
    if engine.dialect.name != 'postgresql': pytest.skip('Operator command requires PostgreSQL')
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, _ = create_tenant_with_admin(factory, tenant_name='test', username='admin', password='a safe long password')
    token = login(factory, secret=b'x'*32, tenant_id=tenant, username='admin', password='a safe long password', source_ip='192.0.2.1').token
    monkeypatch.setattr(cisa_cli.sys.stdin, 'isatty', lambda: True)
    monkeypatch.setattr(cisa_cli.sys.stderr, 'isatty', lambda: True)
    monkeypatch.setattr(cisa_cli.getpass, 'getpass', lambda _: token)
    monkeypatch.setattr(cisa_cli, 'synchronize', lambda factory, admin_token: synchronize(factory, admin_token=admin_token, fetch=fixture_snapshot))
    assert cisa_cli.main(['--confirm-live-fetch']) == 0
    out = capsys.readouterr()
    assert token not in out.out + out.err
    with factory() as db:
        assert db.scalar(select(CisaCatalogRecord).where(CisaCatalogRecord.tenant_id == tenant)) is not None
    # A bearer from a non-admin cannot trigger even a fixture fetch.
    from app.accounts import create_user
    from app.security import Role
    create_user(factory, admin_token=token, username='viewer', password='a safe long password', role=Role.VIEWER)
    viewer = login(factory, secret=b'x'*32, tenant_id=tenant, username='viewer', password='a safe long password', source_ip='192.0.2.1').token
    monkeypatch.setattr(cisa_cli.getpass, 'getpass', lambda _: viewer)
    def must_not_fetch():
        raise AssertionError('unauthorized fetch')
    monkeypatch.setattr(cisa_cli, 'synchronize', lambda factory, admin_token: synchronize(factory, admin_token=admin_token, fetch=must_not_fetch))
    assert cisa_cli.main(['--confirm-live-fetch']) == 1
    out = capsys.readouterr()
    assert viewer not in out.out + out.err and 'unauthorized fetch' not in out.err

def test_migrated_cisa_import_budget_rolls_back(migration_db):
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.connectors.cisa_import import import_snapshot
    from app.login_service import login
    from app.models import CisaCatalogRecord, CisaCatalogState, ProvenanceEvent
    from test_cisa_import import fixture_snapshot
    engine, _ = migration_db
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, _ = create_tenant_with_admin(factory, tenant_name='test', username='admin', password='a safe long password')
    token = login(factory, secret=b'x'*32, tenant_id=tenant, username='admin', password='a safe long password', source_ip='192.0.2.1').token
    ticks = iter([0.0, 1.0, 121.0])
    with pytest.raises(TimeoutError):
        import_snapshot(factory, admin_token=token, snapshot=fixture_snapshot(), monotonic=lambda:next(ticks))
    with factory() as db:
        assert db.scalar(select(Entity.id).where(Entity.tenant_id == tenant)) is None
        assert db.scalar(select(CisaCatalogRecord.id).where(CisaCatalogRecord.tenant_id == tenant)) is None
        assert db.get(CisaCatalogState, tenant) is None
        assert db.scalar(select(ProvenanceEvent.id).where(ProvenanceEvent.tenant_id == tenant)) is None

def test_migrated_bounded_session_cleanup(migration_db, capsys):
    from datetime import datetime, timedelta, timezone
    from sqlalchemy.orm import Session
    from app.bootstrap import create_tenant_with_admin
    from app.maintenance import main
    from app.models import AuthSession, SecurityAuditEvent
    from app.sessions import cleanup_expired_sessions_batch
    from sqlalchemy.orm import sessionmaker
    engine, _ = migration_db
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, actor = create_tenant_with_admin(factory, tenant_name='test', username='admin', password='a safe long password')
    now = datetime.now(timezone.utc)
    with factory.begin() as db:
        for i, age in enumerate([50,49,24,1,-1]):
            db.add(AuthSession(tenant_id=tenant, user_id=actor, token_digest=f'{i:064x}', expires_at=now-timedelta(hours=age)))
    with Session(engine) as db:
        assert cleanup_expired_sessions_batch(db, batch_size=1, now=now) == 1
        db.rollback()
        assert len(list(db.scalars(select(AuthSession)))) == 5
        assert cleanup_expired_sessions_batch(db, batch_size=2, now=now) == 2
        db.commit()
        assert {x.token_digest for x in db.scalars(select(AuthSession))} == {f'{i:064x}' for i in [2,3,4]}
        with pytest.raises(ValueError): cleanup_expired_sessions_batch(db, batch_size=0)
        with pytest.raises(ValueError): cleanup_expired_sessions_batch(db, now=datetime(2026,1,1))
        assert db.scalar(select(SecurityAuditEvent.id)) is not None
    if engine.dialect.name == 'postgresql':
        assert main(['--confirm-cleanup','--kind','expired-sessions','--batch-size','1']) == 0
        assert 'Deleted 1 expired-sessions' in capsys.readouterr().out
        with factory() as db:
            assert len(list(db.scalars(select(AuthSession)))) == 2

def test_migrated_account_create_rechecks_after_hash(migration_db, monkeypatch):
    from sqlalchemy.orm import sessionmaker
    from app import accounts
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login, logout
    from app.models import User
    from app.security import Role, hash_password
    engine, _ = migration_db
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, _ = create_tenant_with_admin(factory, tenant_name='test', username='admin', password='a safe long password')
    token = login(factory, secret=b'x'*32, tenant_id=tenant, username='admin', password='a safe long password', source_ip='192.0.2.1').token
    def hash_after_revoke(password):
        assert logout(factory, token)
        return hash_password(password)
    monkeypatch.setattr(accounts, 'hash_password', hash_after_revoke)
    with pytest.raises(PermissionError):
        accounts.create_user(factory, admin_token=token, username='newuser', password='a safe long password', role=Role.VIEWER)
    with factory() as db:
        assert db.scalar(select(User.id).where(User.tenant_id == tenant, User.username == 'newuser')) is None

def test_migrated_investigation_authorization_history_and_rollback(migration_db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import protected_api
    from app.accounts import create_user
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import Investigation, InvestigationEvent
    from app.security import Role
    engine, _ = migration_db
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, actor = create_tenant_with_admin(factory, tenant_name='first', username='admin', password='a safe long password')
    other, _ = create_tenant_with_admin(factory, tenant_name='second', username='admin', password='a safe long password')
    def token(t, user):
        return login(factory, secret=b'x'*32, tenant_id=t, username=user, password='a safe long password', source_ip='192.0.2.1').token
    admin, foreign = token(tenant, 'admin'), token(other, 'admin')
    create_user(factory, admin_token=admin, username='viewer', password='a safe long password', role=Role.VIEWER)
    viewer = token(tenant, 'viewer')
    app = FastAPI(); app.include_router(protected_api.protected_router(factory, b'x'*32))
    with TestClient(app, base_url='https://testserver', client=('192.0.2.1',123), raise_server_exceptions=False) as client:
        def headers(t): return {'Authorization':'Bearer '+t}
        path = '/api/v1/secure/investigations'
        assert client.post(path, headers=headers(viewer), json={'title':'test','description':'test'}).status_code == 403
        assert client.post(path, json={'title':'test','description':'test'}).status_code == 401
        created = client.post(path, headers=headers(admin), json={'title':'Example','description':'Synthetic case'})
        assert created.status_code == 201
        case = created.json()['id']
        assert client.get(path, headers=headers(foreign)).json()['items'] == []
        assert client.get(f'{path}/{case}/events', headers=headers(foreign)).status_code == 404
        assert client.patch(f'{path}/{case}/status', headers=headers(foreign), json={'status':'closed','expected_version':1}).status_code == 404
        assert client.patch(f'{path}/{case}/status', headers=headers(viewer), json={'status':'closed','expected_version':1}).status_code == 403
        assert client.patch(f'{path}/{case}/status', headers=headers(admin), json={'status':'closed','expected_version':1}).json()['version'] == 2
        assert client.patch(f'{path}/{case}/status', headers=headers(admin), json={'status':'open','expected_version':1}).status_code == 409
        events = client.get(f'{path}/{case}/events', headers=headers(viewer)).json()['items']
        assert [e['event_type'] for e in events] == ['created','status_changed']
        assert events[-1]['details']['previous_status'] == 'open' and events[-1]['details']['status'] == 'closed'
        def fail(*args, **kwargs): raise RuntimeError('audit unavailable')
        monkeypatch.setattr(protected_api, 'record_event', fail)
        assert client.post(path, headers=headers(admin), json={'title':'Rollback','description':'test'}).status_code == 500
        assert client.patch(f'{path}/{case}/status', headers=headers(admin), json={'status':'open','expected_version':2}).status_code == 500
    with factory() as db:
        cases = list(db.scalars(select(Investigation).where(Investigation.tenant_id == tenant)))
        assert len(cases) == 1 and cases[0].status == 'closed' and cases[0].version == 2
        assert len(list(db.scalars(select(InvestigationEvent).where(InvestigationEvent.tenant_id == tenant)))) == 2

def test_migrated_investigation_pagination_and_cross_tenant_fk(migration_db):
    from datetime import datetime, timezone
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import Investigation, InvestigationEvent
    from app.protected_api import protected_router
    engine, _ = migration_db
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, actor = create_tenant_with_admin(factory, tenant_name='first', username='admin', password='a safe long password')
    other, other_actor = create_tenant_with_admin(factory, tenant_name='second', username='admin', password='a safe long password')
    with factory.begin() as db:
        cases = [Investigation(tenant_id=tenant, created_by=actor, title=f'case {i}', description='fixture') for i in range(101)]
        foreign = Investigation(tenant_id=other, created_by=other_actor, title='foreign', description='fixture')
        db.add_all(cases+[foreign]); db.flush(); case_id = cases[0].id; foreign_id = foreign.id
        db.add_all([InvestigationEvent(tenant_id=tenant, investigation_id=case_id, actor_id=actor, event_type='fixture', details={}, occurred_at=datetime(2026,1,1,tzinfo=timezone.utc)) for _ in range(101)])
    with factory.begin() as db:
        db.add(InvestigationEvent(tenant_id=tenant, investigation_id=foreign_id, actor_id=actor, event_type='wrong', details={}))
        with pytest.raises(IntegrityError): db.flush()
        db.rollback()
    token = login(factory, secret=b'x'*32, tenant_id=tenant, username='admin', password='a safe long password', source_ip='192.0.2.1').token
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        headers={'Authorization':'Bearer '+token}
        for path in ['/api/v1/secure/investigations',f'/api/v1/secure/investigations/{case_id}/events']:
            first = client.get(path, headers=headers).json()
            second = client.get(path, headers=headers, params={'after':first['next_cursor']}).json()
            ids=[x['id'] for x in first['items']+second['items']]
            assert len(ids)==101 and len(set(ids))==101 and second['next_cursor'] is None
        assert client.get(f'/api/v1/secure/investigations/{case_id}/events', headers=headers, params={'after':str(foreign_id)}).status_code == 404

def test_postgres_concurrent_investigation_status_changes(migration_db):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.accounts import create_user
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.protected_api import protected_router
    from app.security import Role
    engine, _ = migration_db
    if engine.dialect.name != 'postgresql': pytest.skip('PostgreSQL row locks required')
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, _ = create_tenant_with_admin(factory, tenant_name='test', username='admin', password='a safe long password')
    def token(name): return login(factory, secret=b'x'*32, tenant_id=tenant, username=name, password='a safe long password', source_ip='192.0.2.1').token
    admin = token('admin')
    create_user(factory, admin_token=admin, username='analyst', password='a safe long password', role=Role.ANALYST)
    analyst = token('analyst')
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        headers=lambda t:{'Authorization':'Bearer '+t}
        path='/api/v1/secure/investigations'
        case=client.post(path,headers=headers(admin),json={'title':'Synthetic','description':'Fixture'}).json()['id']
        barrier=Barrier(2)
        def change(t):
            barrier.wait(timeout=10)
            return client.patch(f'{path}/{case}/status',headers=headers(t),json={'status':'closed','expected_version':1}).status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            a=pool.submit(change,admin); b=pool.submit(change,analyst)
            assert sorted([a.result(timeout=20),b.result(timeout=20)]) == [200,409]
        events=client.get(f'{path}/{case}/events', headers=headers(admin)).json()['items']
        assert len(events)==2

def test_migrated_investigation_audit_target_and_tenant_constraint(migration_db):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import Investigation, SecurityAuditEvent
    from app.protected_api import protected_router
    engine, _ = migration_db
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, actor = create_tenant_with_admin(factory, tenant_name='first', username='admin', password='a safe long password')
    other, other_actor = create_tenant_with_admin(factory, tenant_name='second', username='admin', password='a safe long password')
    with factory.begin() as db:
        foreign = Investigation(tenant_id=other, created_by=other_actor, title='foreign', description='synthetic')
        db.add(foreign); db.flush(); foreign_id=foreign.id
    with factory() as db:
        db.add(SecurityAuditEvent(tenant_id=tenant, actor_id=actor, target_investigation_id=foreign_id, event_type='test'))
        with pytest.raises(IntegrityError): db.flush()
        db.rollback()
    token = login(factory, secret=b'x'*32, tenant_id=tenant, username='admin', password='a safe long password', source_ip='192.0.2.1').token
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        headers={'Authorization':'Bearer '+token}; path='/api/v1/secure/investigations'
        case=client.post(path, headers=headers, json={'title':'fixture','description':'fixture'}).json()['id']
        client.get(f'{path}/{case}/events',headers=headers)
        client.patch(f'{path}/{case}/status', headers=headers, json={'status':'closed','expected_version':1})
        audit=client.get('/api/v1/secure/audit',headers=headers).json()['items']
        assert {x['event_type'] for x in audit if x['target_investigation_id']==case} == {'investigation_created','investigation_read','investigation_updated'}

def test_investigation_audit_revision_preserves_existing_events(tmp_path, monkeypatch):
    url = f'sqlite:///{tmp_path / "audit_case.db"}'
    monkeypatch.setenv('DATABASE_URL', url)
    config = Config(str(HERE / 'alembic.ini'))
    command.upgrade(config, '0017_investigations')
    engine = create_engine(url)
    from sqlalchemy import text
    with engine.begin() as conn:
        tenant = uuid4().hex
        conn.execute(text('INSERT INTO tenants (id,name) VALUES (:id,:name)'), {'id':tenant,'name':'test'})
        conn.execute(text('INSERT INTO security_audit_events (id,tenant_id,event_type,occurred_at) VALUES (:id,:tenant,:event,:date)'), {'id':uuid4().hex,'tenant':tenant,'event':'fixture','date':'2026-01-01 00:00:00'})
    command.upgrade(config, 'head')
    with engine.connect() as conn: assert conn.execute(text('SELECT count(*) FROM security_audit_events')).scalar_one() == 1
    command.downgrade(config, '0017_investigations')
    with engine.connect() as conn: assert conn.execute(text('SELECT count(*) FROM security_audit_events')).scalar_one() == 1
    command.downgrade(config, 'base')
    engine.dispose()

def test_migrated_investigation_entity_link_security_and_rollback(migration_db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import protected_api
    from app.accounts import create_user
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import InvestigationEntityLink, InvestigationEvent, SecurityAuditEvent
    from app.security import Role
    engine, _ = migration_db
    factory=sessionmaker(engine,expire_on_commit=False)
    tenant, actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other, other_actor=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    def token(t,u): return login(factory,secret=b'x'*32,tenant_id=t,username=u,password='a safe long password',source_ip='192.0.2.1').token
    admin=token(tenant,'admin'); foreign=token(other,'admin')
    create_user(factory,admin_token=admin,username='viewer',password='a safe long password',role=Role.VIEWER)
    viewer=token(tenant,'viewer')
    with factory.begin() as db:
        own=Entity(tenant_id=tenant,kind='indicator',title='own fixture',source='test',created_by=actor)
        own2=Entity(tenant_id=tenant,kind='indicator',title='rollback fixture',source='test',created_by=actor)
        external=Entity(tenant_id=other,kind='indicator',title='foreign fixture',source='test',created_by=other_actor)
        db.add_all([own,own2,external]); db.flush(); a,b,c=own.id,own2.id,external.id
    app=FastAPI(); app.include_router(protected_api.protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123),raise_server_exceptions=False) as client:
        headers=lambda t:{'Authorization':'Bearer '+t}
        base='/api/v1/secure/investigations'
        case=client.post(base,headers=headers(admin),json={'title':'fixture','description':'fixture'}).json()['id']
        path=f'{base}/{case}/entities'
        assert client.post(path,headers=headers(viewer),json={'entity_id':str(a)}).status_code==403
        assert client.post(path,headers=headers(foreign),json={'entity_id':str(c)}).status_code==404
        assert client.post(path,headers=headers(admin),json={'entity_id':str(c)}).status_code==404
        response=client.post(path,headers=headers(admin),json={'entity_id':str(a)})
        assert response.status_code==201 and response.json()['status']=='analyst_association_unverified'
        assert client.post(path,headers=headers(admin),json={'entity_id':str(a)}).status_code==409
        assert client.get(path,headers=headers(viewer)).json()['items'][0]['entity_id']==str(a)
        assert client.get(path,headers=headers(foreign)).status_code==404
        original=protected_api.record_event
        def fail(*args,**kwargs): raise RuntimeError('audit failed')
        monkeypatch.setattr(protected_api,'record_event',fail)
        assert client.post(path,headers=headers(admin),json={'entity_id':str(b)}).status_code==500
        monkeypatch.setattr(protected_api,'record_event',original)
        events=client.get(f'{base}/{case}/events',headers=headers(admin)).json()['items']
        assert [e['event_type'] for e in events]==['created','entity_linked']
        audit=client.get('/api/v1/secure/audit',headers=headers(admin)).json()['items']
        assert any(x['event_type']=='investigation_entity_linked' and x['target_entity_id']==str(a) and x['target_investigation_id']==case for x in audit)
        assert client.patch(f'{base}/{case}/status',headers=headers(admin),json={'status':'closed','expected_version':1}).status_code==200
        assert client.post(path,headers=headers(admin),json={'entity_id':str(b)}).status_code==409
    with factory() as db:
        assert len(list(db.scalars(select(InvestigationEntityLink))))==1
    with factory() as db:
        from uuid import UUID
        db.add(InvestigationEntityLink(tenant_id=tenant, investigation_id=UUID(case),entity_id=c,created_by=actor))
        with pytest.raises(IntegrityError): db.flush()
        db.rollback()

def test_migrated_investigation_link_pagination(migration_db):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import Investigation, InvestigationEntityLink
    from app.protected_api import protected_router
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    with factory.begin() as db:
        case=Investigation(tenant_id=tenant,created_by=actor,title='case',description='test'); other_case=Investigation(tenant_id=tenant,created_by=actor,title='other',description='test'); db.add_all([case,other_case])
        entities=[Entity(tenant_id=tenant,kind='indicator',title=f'fixture {i}',source='test',created_by=actor) for i in range(101)]
        db.add_all(entities); db.flush(); case_id,other_case_id=case.id,other_case.id
        db.add_all([InvestigationEntityLink(tenant_id=tenant,investigation_id=case.id,entity_id=e.id,created_by=actor) for e in entities])
    token=login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        path=f'/api/v1/secure/investigations/{case_id}/entities'; headers={'Authorization':'Bearer '+token}
        first=client.get(path,headers=headers).json()
        second=client.get(path,headers=headers,params={'after':first['next_cursor']}).json()
        ids=[x['id'] for x in first['items']+second['items']]
        assert len(ids)==101 and len(set(ids))==101 and second['next_cursor'] is None
        assert client.get(path,headers=headers,params={'after':str(uuid4())}).status_code==404
        assert client.get(f'/api/v1/secure/investigations/{other_case_id}/entities',headers=headers,params={'after':first['next_cursor']}).status_code==404

@pytest.mark.parametrize('action', ['link','unlink'])
def test_postgres_link_waiting_on_case_close_is_denied(migration_db, action):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import event, update
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import Investigation, InvestigationEntityLink
    from app.protected_api import protected_router
    engine,_=migration_db
    if engine.dialect.name!='postgresql': pytest.skip('PostgreSQL row locks required')
    factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    with factory.begin() as db:
        case=Investigation(tenant_id=tenant,created_by=actor,title='case',description='test')
        entity=Entity(tenant_id=tenant,kind='indicator',title='fixture',source='test',created_by=actor)
        db.add_all([case,entity]); db.flush(); case_id,entity_id=case.id,entity.id
        link_id = None
        if action == 'unlink':
            link = InvestigationEntityLink(tenant_id=tenant,investigation_id=case_id,entity_id=entity_id,created_by=actor)
            db.add(link); db.flush(); link_id=link.id
    token=login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    waiting=Event()
    def observe(conn,cursor,statement,parameters,context,executemany):
        if 'FROM investigations' in statement and 'FOR UPDATE' in statement: waiting.set()
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with factory.begin() as blocker:
                blocker.scalar(select(Investigation).where(Investigation.id==case_id).with_for_update())
                event.listen(engine,'before_cursor_execute',observe)
                path=f'/api/v1/secure/investigations/{case_id}/entities'
                if action == 'link':
                    future=pool.submit(client.post,path,headers={'Authorization':'Bearer '+token},json={'entity_id':str(entity_id)})
                else:
                    future=pool.submit(client.delete,f'{path}/{link_id}',headers={'Authorization':'Bearer '+token})
                try:
                    assert waiting.wait(10)
                    blocker.execute(update(Investigation).where(Investigation.id==case_id).values(status='closed',version=2))
                finally:
                    event.remove(engine,'before_cursor_execute',observe)
            assert future.result(timeout=10).status_code==409
    with factory() as db:
        assert (db.scalar(select(InvestigationEntityLink.id)) is not None) == (action == 'unlink')

def test_migrated_investigation_unlink_permissions_history_and_rollback(migration_db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import protected_api
    from app.accounts import create_user
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import InvestigationEntityLink
    from app.security import Role
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,_=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    def token(t,u): return login(factory,secret=b'x'*32,tenant_id=t,username=u,password='a safe long password',source_ip='192.0.2.1').token
    admin=token(tenant,'admin'); foreign=token(other,'admin')
    create_user(factory,admin_token=admin,username='viewer',password='a safe long password',role=Role.VIEWER)
    viewer=token(tenant,'viewer')
    with factory.begin() as db:
        entity=Entity(tenant_id=tenant,kind='indicator',title='fixture',source='test',created_by=actor)
        db.add(entity); db.flush(); entity_id=entity.id
    app=FastAPI(); app.include_router(protected_api.protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123),raise_server_exceptions=False) as client:
        h=lambda t:{'Authorization':'Bearer '+t}
        base='/api/v1/secure/investigations'
        case=client.post(base,headers=h(admin),json={'title':'fixture','description':'fixture'}).json()['id']
        links=f'{base}/{case}/entities'
        link=client.post(links,headers=h(admin),json={'entity_id':str(entity_id)}).json()['id']
        path=f'{links}/{link}'
        assert client.delete(path,headers=h(viewer)).status_code==403
        assert client.delete(path,headers=h(foreign)).status_code==404
        original=protected_api.record_event
        monkeypatch.setattr(protected_api,'record_event',lambda *a,**k: (_ for _ in ()).throw(RuntimeError('audit failed')))
        assert client.delete(path,headers=h(admin)).status_code==500
        monkeypatch.setattr(protected_api,'record_event',original)
        assert len(client.get(links,headers=h(admin)).json()['items'])==1
        assert client.patch(f'{base}/{case}/status',headers=h(admin),json={'status':'closed','expected_version':1}).status_code==200
        assert client.delete(path,headers=h(admin)).status_code==409
        assert client.patch(f'{base}/{case}/status',headers=h(admin),json={'status':'open','expected_version':2}).status_code==200
        assert client.delete(path,headers=h(admin)).status_code==200
        assert client.delete(path,headers=h(admin)).status_code==404
        assert client.get(links,headers=h(admin)).json()['items']==[]
        events=client.get(f'{base}/{case}/events',headers=h(admin)).json()['items']
        assert [e['event_type'] for e in events]==['created','entity_linked','status_changed','status_changed','entity_unlinked']
        assert events[-1]['details']=={'entity_id':str(entity_id),'link_id':link}
        audit=client.get('/api/v1/secure/audit',headers=h(admin)).json()['items']
        assert any(x['event_type']=='investigation_entity_unlinked' and x['target_entity_id']==str(entity_id) and x['target_investigation_id']==case for x in audit)
        assert client.post(links,headers=h(admin),json={'entity_id':str(entity_id)}).status_code==201

def test_migrated_case_evidence_references_authorization_and_rollback(migration_db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import protected_api
    from app.accounts import create_user
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import EvidenceReference, InvestigationEvidenceLink
    from app.security import Role
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,other_actor=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    def token(t,u): return login(factory,secret=b'x'*32,tenant_id=t,username=u,password='a safe long password',source_ip='192.0.2.1').token
    admin=token(tenant,'admin'); foreign=token(other,'admin')
    create_user(factory,admin_token=admin,username='viewer',password='a safe long password',role=Role.VIEWER); viewer=token(tenant,'viewer')
    with factory.begin() as db:
        e=Entity(tenant_id=tenant,kind='indicator',title='fixture',source='test',created_by=actor)
        e2=Entity(tenant_id=tenant,kind='indicator',title='other fixture',source='test',created_by=actor)
        x=Entity(tenant_id=other,kind='indicator',title='foreign',source='test',created_by=other_actor)
        db.add_all([e,e2,x]); db.flush(); a,b,c=e.id,e2.id,x.id
        refs=[EvidenceReference(tenant_id=t,entity_id=i,created_by=u,description='fixture',source='test') for t,i,u in [(tenant,a,actor),(tenant,b,actor),(other,c,other_actor)]]
        db.add_all(refs); db.flush(); r1,r2,r3=[r.id for r in refs]
    app=FastAPI(); app.include_router(protected_api.protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123),raise_server_exceptions=False) as client:
        h=lambda t:{'Authorization':'Bearer '+t}; base='/api/v1/secure/investigations'
        case=client.post(base,headers=h(admin),json={'title':'case','description':'fixture'}).json()['id']
        path=f'{base}/{case}/evidence'; payload={'entity_id':str(a),'evidence_id':str(r1)}
        assert client.post(path,headers=h(viewer),json=payload).status_code==403
        assert client.post(path,headers=h(foreign),json=payload).status_code==404
        assert client.post(path,headers=h(admin),json=payload).status_code==404  # entity not yet linked
        entity_link=client.post(f'{base}/{case}/entities',headers=h(admin),json={'entity_id':str(a)}).json()['id']
        assert client.post(path,headers=h(admin),json={'entity_id':str(a),'evidence_id':str(r2)}).status_code==404
        assert client.post(path,headers=h(admin),json={'entity_id':str(c),'evidence_id':str(r3)}).status_code==404
        original=protected_api.record_event
        monkeypatch.setattr(protected_api,'record_event',lambda *a,**k: (_ for _ in ()).throw(RuntimeError('audit failed')))
        assert client.post(path,headers=h(admin),json=payload).status_code==500
        monkeypatch.setattr(protected_api,'record_event',original)
        result=client.post(path,headers=h(admin),json=payload)
        assert result.status_code==201 and result.json()['status']=='analyst_entered_unverified'
        link=result.json()['id']
        assert client.post(path,headers=h(admin),json=payload).status_code==409
        assert client.get(path,headers=h(viewer)).json()['items'][0]['evidence_id']==str(r1)
        assert client.get(path,headers=h(foreign)).status_code==404
        assert client.delete(f'{base}/{case}/entities/{entity_link}',headers=h(admin)).status_code==409
        assert client.delete(f'{path}/{link}',headers=h(viewer)).status_code==403
        assert client.delete(f'{path}/{link}',headers=h(foreign)).status_code==404
        monkeypatch.setattr(protected_api,'record_event',lambda *a,**k: (_ for _ in ()).throw(RuntimeError('audit failed')))
        assert client.delete(f'{path}/{link}',headers=h(admin)).status_code==500
        monkeypatch.setattr(protected_api,'record_event',original)
        assert len(client.get(path,headers=h(admin)).json()['items'])==1
        assert client.patch(f'{base}/{case}/status',headers=h(admin),json={'status':'closed','expected_version':1}).status_code==200
        assert client.delete(f'{path}/{link}',headers=h(admin)).status_code==409
        assert client.patch(f'{base}/{case}/status',headers=h(admin),json={'status':'open','expected_version':2}).status_code==200
        assert client.delete(f'{path}/{link}',headers=h(admin)).status_code==200
        assert client.delete(f'{path}/{link}',headers=h(admin)).status_code==404
        assert client.delete(f'{base}/{case}/entities/{entity_link}',headers=h(admin)).status_code==200
        events=client.get(f'{base}/{case}/events',headers=h(admin)).json()['items']
        assert [e['event_type'] for e in events]==['created','entity_linked','evidence_linked','status_changed','status_changed','evidence_unlinked','entity_unlinked']
        audit=client.get('/api/v1/secure/audit',headers=h(admin)).json()['items']
        assert {'investigation_evidence_linked','investigation_evidence_unlinked'} <= {x['event_type'] for x in audit if x['target_investigation_id']==case and x['target_entity_id']==str(a)}
        filtered=client.get('/api/v1/secure/audit',headers=h(admin),params={'investigation_id':case,'evidence_id':str(r1)}).json()['items']
        assert {'investigation_evidence_linked','investigation_evidence_unlinked'} <= {x['event_type'] for x in filtered}
        assert all(x['target_investigation_id']==case and x['target_entity_id']==str(a) and x['target_evidence_id']==str(r1) for x in filtered)
        assert client.get('/api/v1/secure/audit',headers=h(admin),params={'evidence_id':str(uuid4())}).json()['items']==[]
    with factory() as db: assert db.scalar(select(InvestigationEvidenceLink.id)) is None

def test_migrated_case_evidence_composite_fk_and_pagination(migration_db):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import EvidenceReference, Investigation, InvestigationEntityLink, InvestigationEvidenceLink
    from app.protected_api import protected_router
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    with factory.begin() as db:
        case=Investigation(tenant_id=tenant,created_by=actor,title='fixture',description='fixture')
        other_case=Investigation(tenant_id=tenant,created_by=actor,title='other',description='fixture')
        one=Entity(tenant_id=tenant,kind='indicator',title='one',source='test',created_by=actor)
        two=Entity(tenant_id=tenant,kind='indicator',title='two',source='test',created_by=actor)
        db.add_all([case,other_case,one,two]); db.flush(); case_id,other_case_id,one_id,two_id=case.id,other_case.id,one.id,two.id
        db.add(InvestigationEntityLink(tenant_id=tenant,investigation_id=case.id,entity_id=one.id,created_by=actor))
        refs=[EvidenceReference(tenant_id=tenant,entity_id=one.id,created_by=actor,description='fixture',source='test') for _ in range(101)]
        mismatch=EvidenceReference(tenant_id=tenant,entity_id=two.id,created_by=actor,description='fixture',source='test')
        db.add_all(refs+[mismatch]); db.flush(); mismatch_id=mismatch.id
        db.add_all([InvestigationEvidenceLink(tenant_id=tenant,investigation_id=case.id,entity_id=one.id,evidence_id=r.id,created_by=actor) for r in refs])
    with factory() as db:
        db.add(InvestigationEvidenceLink(tenant_id=tenant,investigation_id=case_id,entity_id=one_id,evidence_id=mismatch_id,created_by=actor))
        with pytest.raises(IntegrityError): db.flush()
        db.rollback()
    with factory() as db:
        db.add(InvestigationEvidenceLink(tenant_id=tenant,investigation_id=case_id,entity_id=two_id,evidence_id=mismatch_id,created_by=actor))
        with pytest.raises(IntegrityError): db.flush()  # entity not linked to case
        db.rollback()
    token=login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        path=f'/api/v1/secure/investigations/{case_id}/evidence'; headers={'Authorization':'Bearer '+token}
        first=client.get(path,headers=headers).json(); second=client.get(path,headers=headers,params={'after':first['next_cursor']}).json()
        ids=[x['id'] for x in first['items']+second['items']]
        assert len(ids)==101 and len(set(ids))==101 and second['next_cursor'] is None
        assert client.get(path,headers=headers,params={'after':str(uuid4())}).status_code==404
        assert client.get(f'/api/v1/secure/investigations/{other_case_id}/evidence',headers=headers,params={'after':first['next_cursor']}).status_code==404

@pytest.mark.parametrize('action', ['link', 'unlink', 'parent_unlink'])
def test_postgres_case_evidence_waits_for_case_mutations(migration_db, action):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import event, update
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import EvidenceReference, Investigation, InvestigationEntityLink, InvestigationEvidenceLink
    from app.protected_api import protected_router
    engine,_=migration_db
    if engine.dialect.name!='postgresql': pytest.skip('PostgreSQL row locks required')
    factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    with factory.begin() as db:
        case=Investigation(tenant_id=tenant,created_by=actor,title='case',description='test')
        entity=Entity(tenant_id=tenant,kind='indicator',title='fixture',source='test',created_by=actor)
        db.add_all([case,entity]); db.flush(); case_id,entity_id=case.id,entity.id
        reference=EvidenceReference(tenant_id=tenant,entity_id=entity_id,created_by=actor,description='fixture',source='test')
        parent=InvestigationEntityLink(tenant_id=tenant,investigation_id=case_id,entity_id=entity_id,created_by=actor)
        db.add_all([reference,parent]); db.flush(); ref_id,parent_id=reference.id,parent.id
        link_id=None
        if action=='unlink':
            link=InvestigationEvidenceLink(tenant_id=tenant,investigation_id=case_id,entity_id=entity_id,evidence_id=ref_id,created_by=actor)
            db.add(link); db.flush(); link_id=link.id
    token=login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32)); waiting=Event()
    def observe(conn,cursor,statement,parameters,context,executemany):
        if 'FROM investigations' in statement and 'FOR UPDATE' in statement: waiting.set()
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with factory.begin() as blocker:
                blocker.scalar(select(Investigation).where(Investigation.id==case_id).with_for_update())
                event.listen(engine,'before_cursor_execute',observe)
                path=f'/api/v1/secure/investigations/{case_id}/evidence'; headers={'Authorization':'Bearer '+token}
                if action=='unlink':
                    future=pool.submit(client.delete,f'{path}/{link_id}',headers=headers)
                else:
                    future=pool.submit(client.post,path,headers=headers,json={'entity_id':str(entity_id),'evidence_id':str(ref_id)})
                try:
                    assert waiting.wait(10)
                    if action=='parent_unlink':
                        blocker.delete(blocker.get(InvestigationEntityLink,parent_id)); blocker.flush()
                    else:
                        blocker.execute(update(Investigation).where(Investigation.id==case_id).values(status='closed',version=2))
                finally:
                    event.remove(engine,'before_cursor_execute',observe)
            assert future.result(timeout=10).status_code == (404 if action=='parent_unlink' else 409)
    with factory() as db:
        assert (db.scalar(select(InvestigationEvidenceLink.id)) is not None)==(action=='unlink')

def test_migrated_case_assignment_authorization_and_history(migration_db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import protected_api
    from app.accounts import create_user, disable_user
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import Investigation, InvestigationEvent
    from app.security import Role
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,foreign_user=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    def token(t,u): return login(factory,secret=b'x'*32,tenant_id=t,username=u,password='a safe long password',source_ip='192.0.2.1').token
    admin=token(tenant,'admin'); foreign=token(other,'admin')
    analyst_id=create_user(factory,admin_token=admin,username='analyst',password='a safe long password',role=Role.ANALYST)
    viewer_id=create_user(factory,admin_token=admin,username='viewer',password='a safe long password',role=Role.VIEWER)
    analyst=token(tenant,'analyst'); viewer=token(tenant,'viewer')
    app=FastAPI(); app.include_router(protected_api.protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123),raise_server_exceptions=False) as client:
        h=lambda t:{'Authorization':'Bearer '+t}; base='/api/v1/secure/investigations'
        case=client.post(base,headers=h(admin),json={'title':'case','description':'fixture'}).json()['id']; path=f'{base}/{case}/assignment'
        payload={'assignee_id':str(analyst_id),'expected_version':1}
        assert client.patch(path,headers=h(analyst),json=payload).status_code==403
        assert client.patch(path,headers=h(viewer),json=payload).status_code==403
        assert client.patch(path,headers=h(foreign),json={'assignee_id':str(foreign_user),'expected_version':1}).status_code==404
        assert client.patch(path,headers=h(admin),json={'assignee_id':str(foreign_user),'expected_version':1}).status_code==404
        assert client.patch(path,headers=h(admin),json={'assignee_id':str(viewer_id),'expected_version':1}).status_code==404
        assert client.patch(path,headers=h(admin),json=payload).json()['version']==2
        assert client.patch(path,headers=h(admin),json=payload).status_code==409
        assert client.get(base,headers=h(viewer)).json()['items'][0]['assignee_id']==str(analyst_id)
        original=protected_api.record_event
        monkeypatch.setattr(protected_api,'record_event',lambda *a,**k: (_ for _ in ()).throw(RuntimeError('audit failed')))
        assert client.patch(path,headers=h(admin),json={'assignee_id':None,'expected_version':2}).status_code==500
        monkeypatch.setattr(protected_api,'record_event',original)
        assert client.get(base,headers=h(viewer)).json()['items'][0]['assignee_id']==str(analyst_id)
        assert client.patch(f'{base}/{case}/status',headers=h(admin),json={'status':'closed','expected_version':2}).status_code==200
        assert client.patch(path,headers=h(admin),json={'assignee_id':None,'expected_version':3}).status_code==409
        assert client.patch(f'{base}/{case}/status',headers=h(admin),json={'status':'open','expected_version':3}).status_code==200
        disable_user(factory,admin_token=admin,user_id=analyst_id)
        assert client.patch(path,headers=h(admin),json={'assignee_id':str(analyst_id),'expected_version':4}).status_code==404
        assert client.patch(path,headers=h(admin),json={'assignee_id':None,'expected_version':4}).json()['version']==5
        assert client.patch(path,headers=h(admin),json={'assignee_id':str(actor),'expected_version':5}).json()['version']==6
        events=client.get(f'{base}/{case}/events',headers=h(admin)).json()['items']
        assert [e['event_type'] for e in events]==['created','assignment_changed','status_changed','status_changed','assignment_changed','assignment_changed']
        audit=client.get('/api/v1/secure/audit',headers=h(admin)).json()['items']
        assert any(x['event_type']=='investigation_assigned' and x['target_user_id']==str(analyst_id) and x['target_investigation_id']==case for x in audit)
    with factory() as db:
        assert len(list(db.scalars(select(InvestigationEvent).where(InvestigationEvent.tenant_id==tenant))))==6
        db.add(Investigation(tenant_id=tenant,created_by=actor,assignee_id=foreign_user,title='bad',description='test'))
        with pytest.raises(IntegrityError): db.flush()
        db.rollback()

def test_postgres_assignment_rechecks_target_after_disable_lock_wait(migration_db):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import event, update
    from sqlalchemy.orm import sessionmaker
    from app.accounts import create_user
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import Investigation, User
    from app.protected_api import protected_router
    from app.security import Role
    engine,_=migration_db
    if engine.dialect.name!='postgresql': pytest.skip('PostgreSQL row locks required')
    factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    token=login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    target=create_user(factory,admin_token=token,username='analyst',password='a safe long password',role=Role.ANALYST)
    with factory.begin() as db:
        case=Investigation(tenant_id=tenant,created_by=actor,title='fixture',description='fixture'); db.add(case); db.flush(); case_id=case.id
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32)); waiting=Event()
    def observe(conn,cursor,statement,parameters,context,executemany):
        if 'FROM users' in statement and 'ORDER BY users.id' in statement and 'FOR UPDATE' in statement: waiting.set()
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with factory.begin() as blocker:
                blocker.scalar(select(User).where(User.id==target).with_for_update())
                event.listen(engine,'before_cursor_execute',observe)
                future=pool.submit(client.patch,f'/api/v1/secure/investigations/{case_id}/assignment',headers={'Authorization':'Bearer '+token},json={'assignee_id':str(target),'expected_version':1})
                try:
                    assert waiting.wait(10)
                    blocker.execute(update(User).where(User.id==target).values(active=False))
                finally:
                    event.remove(engine,'before_cursor_execute',observe)
            assert future.result(timeout=10).status_code==404
    with factory() as db: assert db.get(Investigation,case_id).assignee_id is None

def test_assignment_revision_preserves_cases_and_events(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    from sqlalchemy.orm import Session
    from app.models import Investigation, InvestigationEvent, User
    url=f'sqlite:///{tmp_path / "assignment.db"}'; monkeypatch.setenv('DATABASE_URL',url)
    config=Config(str(HERE / 'alembic.ini')); command.upgrade(config,'0020_investigation_evidence')
    engine=create_engine(url); tenant,user,case,event_id=[uuid4() for _ in range(4)]
    from sqlalchemy import text
    with engine.begin() as c:
        c.execute(text('INSERT INTO tenants (id,name) VALUES (:id,:name)'),{'id':tenant.hex,'name':'test'})
        c.execute(text('INSERT INTO users (id,tenant_id,username,password_hash,role,active) VALUES (:id,:tenant,:name,:hash,:role,1)'),{'id':user.hex,'tenant':tenant.hex,'name':'admin','hash':'fixture','role':'admin'})
        c.execute(text('INSERT INTO investigations (id,tenant_id,created_by,title,description,status,version,created_at) VALUES (:id,:tenant,:actor,:title,:description,:status,1,:date)'),{'id':case.hex,'tenant':tenant.hex,'actor':user.hex,'title':'fixture','description':'fixture','status':'open','date':'2026-01-01 00:00:00'})
        c.execute(text('INSERT INTO investigation_events (id,tenant_id,investigation_id,actor_id,event_type,details,occurred_at) VALUES (:id,:tenant,:case,:actor,:type,:details,:date)'),{'id':event_id.hex,'tenant':tenant.hex,'case':case.hex,'actor':user.hex,'type':'fixture','details':'{}','date':'2026-01-01 00:00:00'})
    command.upgrade(config,'head')
    with engine.connect() as c:
        assert c.execute(text('SELECT count(*) FROM investigations')).scalar_one()==1
        assert c.execute(text('SELECT count(*) FROM investigation_events')).scalar_one()==1
    command.downgrade(config,'0020_investigation_evidence')
    with engine.connect() as c:
        assert c.execute(text('SELECT count(*) FROM investigations')).scalar_one()==1
        assert c.execute(text('SELECT count(*) FROM investigation_events')).scalar_one()==1
    command.downgrade(config,'base'); engine.dispose()

def test_migrated_case_listing_shows_current_assignee_eligibility(migration_db):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.accounts import create_user, change_role, disable_user
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import Investigation
    from app.protected_api import protected_router
    from app.security import Role
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    token=login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    target=create_user(factory,admin_token=token,username='analyst',password='a safe long password',role=Role.ANALYST)
    with factory.begin() as db:
        db.add_all([Investigation(tenant_id=tenant,created_by=actor,title='assigned',description='fixture',assignee_id=target),
                    Investigation(tenant_id=tenant,created_by=actor,title='unassigned',description='fixture')])
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        def statuses():
            items=client.get('/api/v1/secure/investigations',headers={'Authorization':'Bearer '+token}).json()['items']
            return {x['title']:x['assignee_status'] for x in items}
        assert statuses()=={'assigned':'eligible','unassigned':'unassigned'}
        change_role(factory,admin_token=token,user_id=target,role=Role.VIEWER)
        assert statuses()['assigned']=='ineligible'
        change_role(factory,admin_token=token,user_id=target,role=Role.ANALYST)
        assert statuses()['assigned']=='eligible'
        disable_user(factory,admin_token=token,user_id=target)
        assert statuses()['assigned']=='ineligible'

def test_migrated_case_detail_and_filtered_listing(migration_db):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import Investigation
    from app.protected_api import protected_router
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,other_actor=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    with factory.begin() as db:
        a=Investigation(tenant_id=tenant,created_by=actor,assignee_id=actor,title='open',description='fixture')
        b=Investigation(tenant_id=tenant,created_by=actor,status='closed',title='closed',description='fixture')
        c=Investigation(tenant_id=other,created_by=other_actor,assignee_id=other_actor,title='foreign',description='fixture')
        db.add_all([a,b,c]); db.flush(); a_id,b_id,c_id=a.id,b.id,c.id
    token=login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        path='/api/v1/secure/investigations'; headers={'Authorization':'Bearer '+token}
        detail=client.get(f'{path}/{a_id}',headers=headers)
        assert detail.status_code==200 and detail.json()['assignee_status']=='eligible'
        assert client.get(f'{path}/{c_id}',headers=headers).status_code==404
        assert client.get(f'{path}/{a_id}').status_code==401
        assert [x['id'] for x in client.get(path,headers=headers,params={'status':'closed'}).json()['items']]==[str(b_id)]
        assert [x['id'] for x in client.get(path,headers=headers,params={'status':'open','assignee_id':str(actor)}).json()['items']]==[str(a_id)]
        assert client.get(path,headers=headers,params={'assignee_id':str(other_actor)}).json()['items']==[]
        assert client.get(path,headers=headers,params={'status':'invalid'}).status_code==422
        assert client.get(path,headers=headers,params={'after':str(c_id)}).status_code==404
        assert client.get(path,headers=headers,params={'after':str(uuid4())}).status_code==404
        assert client.get(path,headers=headers,params={'after':str(b_id),'status':'open'}).status_code==404
        assert client.get(path,headers=headers,params={'after':str(a_id),'assignee_id':str(other_actor)}).status_code==404
        assert client.get(path,headers=headers,params={'after':str(a_id),'status':'open','assignee_id':str(actor)}).status_code==200
        assert any(e['event_type']=='investigation_read' and e['target_investigation_id']==str(a_id) for e in client.get('/api/v1/secure/audit',headers=headers).json()['items'])

def test_migrated_investigation_notes_scope_and_atomicity(migration_db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import protected_api
    from app.accounts import create_user
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import InvestigationNote
    from app.security import Role
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,other_actor=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    def token(t,u): return login(factory,secret=b'x'*32,tenant_id=t,username=u,password='a safe long password',source_ip='192.0.2.1').token
    admin=token(tenant,'admin'); foreign=token(other,'admin')
    create_user(factory,admin_token=admin,username='viewer',password='a safe long password',role=Role.VIEWER); viewer=token(tenant,'viewer')
    app=FastAPI(); app.include_router(protected_api.protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123),raise_server_exceptions=False) as client:
        h=lambda t:{'Authorization':'Bearer '+t}; base='/api/v1/secure/investigations'
        case=client.post(base,headers=h(admin),json={'title':'case','description':'fixture'}).json()['id']; path=f'{base}/{case}/notes'
        assert client.post(path,headers=h(viewer),json={'body':'fixture'}).status_code==403
        assert client.post(path,headers=h(foreign),json={'body':'fixture'}).status_code==404
        invalid=client.post(path,headers=h(admin),json={'body':'secret\u0000value'})
        assert invalid.status_code==422 and 'secret' not in invalid.text
        original=protected_api.record_event
        monkeypatch.setattr(protected_api,'record_event',lambda *a,**k: (_ for _ in ()).throw(RuntimeError('audit failed')))
        assert client.post(path,headers=h(admin),json={'body':'rollback'}).status_code==500
        monkeypatch.setattr(protected_api,'record_event',original)
        result=client.post(path,headers=h(admin),json={'body':' line one\nline two '})
        assert result.status_code==201 and result.json()['status']=='analyst_entered_unverified'
        note_id=result.json()['id']
        assert client.get(path,headers=h(foreign)).status_code==404
        notes=client.get(path,headers=h(viewer)).json()['items']; assert len(notes)==1 and notes[0]['body']=='line one\nline two'
        assert client.get(path,headers=h(viewer),params={'after':str(other_actor)}).status_code==404
        events=client.get(f'{base}/{case}/events',headers=h(admin)).json()['items']
        assert events[-1]['event_type']=='note_added' and events[-1]['details']['note_id']==note_id
        audit=client.get('/api/v1/secure/audit',headers=h(admin)).json()['items']
        assert any(x['event_type']=='investigation_note_created' and x['target_investigation_id']==case for x in audit)
        assert client.patch(f'{base}/{case}/status',headers=h(admin),json={'status':'closed','expected_version':1}).status_code==200
        assert client.post(path,headers=h(admin),json={'body':'not allowed'}).status_code==409
    with factory() as db:
        assert len(list(db.scalars(select(InvestigationNote))))==1
        from uuid import UUID
        db.add(InvestigationNote(tenant_id=other,investigation_id=UUID(case),author_id=other_actor,body='foreign'))
        with pytest.raises(IntegrityError): db.flush()
        db.rollback()

def test_migrated_investigation_notes_pagination_with_equal_timestamps(migration_db):
    from datetime import datetime, timezone
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import Investigation, InvestigationNote
    from app.protected_api import protected_router
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    with factory.begin() as db:
        case=Investigation(tenant_id=tenant,created_by=actor,title='fixture',description='fixture'); db.add(case); db.flush(); case_id=case.id
        db.add_all([InvestigationNote(tenant_id=tenant,investigation_id=case_id,author_id=actor,body='fixture',created_at=datetime(2026,1,1,tzinfo=timezone.utc)) for _ in range(101)])
    token=login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        path=f'/api/v1/secure/investigations/{case_id}/notes'; headers={'Authorization':'Bearer '+token}
        first=client.get(path,headers=headers).json(); second=client.get(path,headers=headers,params={'after':first['next_cursor']}).json()
        ids=[x['id'] for x in first['items']+second['items']]
        assert len(ids)==101 and len(set(ids))==101 and second['next_cursor'] is None

def test_postgres_note_waiting_on_case_close_is_denied(migration_db):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import event, update
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import Investigation, InvestigationNote
    from app.protected_api import protected_router
    engine,_=migration_db
    if engine.dialect.name!='postgresql': pytest.skip('PostgreSQL row locks required')
    factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    with factory.begin() as db:
        case=Investigation(tenant_id=tenant,created_by=actor,title='fixture',description='fixture'); db.add(case); db.flush(); case_id=case.id
    token=login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32)); waiting=Event()
    def observe(conn,cursor,statement,parameters,context,executemany):
        if 'FROM investigations' in statement and 'FOR UPDATE' in statement: waiting.set()
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with factory.begin() as blocker:
                blocker.scalar(select(Investigation).where(Investigation.id==case_id).with_for_update())
                event.listen(engine,'before_cursor_execute',observe)
                future=pool.submit(client.post,f'/api/v1/secure/investigations/{case_id}/notes',headers={'Authorization':'Bearer '+token},json={'body':'fixture'})
                try:
                    assert waiting.wait(10)
                    blocker.execute(update(Investigation).where(Investigation.id==case_id).values(status='closed',version=2))
                finally:
                    event.remove(engine,'before_cursor_execute',observe)
            assert future.result(timeout=10).status_code==409
    with factory() as db: assert db.scalar(select(InvestigationNote.id)) is None

def test_migrated_note_detail_and_audit_target_constraints(migration_db):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import Investigation, InvestigationNote, SecurityAuditEvent
    from app.protected_api import protected_router
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,other_actor=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    with factory.begin() as db:
        cases=[Investigation(tenant_id=t,created_by=u,title='fixture',description='fixture') for t,u in [(tenant,actor),(tenant,actor),(other,other_actor)]]
        db.add_all(cases); db.flush(); a,b,c=[x.id for x in cases]
        notes=[InvestigationNote(tenant_id=t,investigation_id=i,author_id=u,body='fixture') for t,i,u in [(tenant,a,actor),(other,c,other_actor)]]
        db.add_all(notes); db.flush(); own,foreign=[n.id for n in notes]
    for bad_case,bad_note in [(None,own),(b,own),(a,foreign)]:
        with factory() as db:
            db.add(SecurityAuditEvent(tenant_id=tenant,actor_id=actor,target_investigation_id=bad_case,target_note_id=bad_note,event_type='fixture'))
            with pytest.raises(IntegrityError): db.flush()
            db.rollback()
    token=login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        headers={'Authorization':'Bearer '+token}; base='/api/v1/secure/investigations'
        assert client.get(f'{base}/{a}/notes/{own}').status_code==401
        assert client.get(f'{base}/{b}/notes/{own}',headers=headers).status_code==404
        assert client.get(f'{base}/{c}/notes/{foreign}',headers=headers).status_code==404
        assert client.get(f'{base}/{a}/notes/{own}',headers=headers).json()['body']=='fixture'
        created=client.post(f'{base}/{a}/notes',headers=headers,json={'body':'new fixture'}).json()['id']
        audit=client.get('/api/v1/secure/audit',headers=headers).json()['items']
        assert any(x['event_type']=='investigation_read' and x['target_note_id']==str(own) and x['target_investigation_id']==str(a) for x in audit)
        assert any(x['event_type']=='investigation_note_created' and x['target_note_id']==created and x['target_investigation_id']==str(a) for x in audit)

def test_migrated_audit_case_filters_pagination_and_scope(migration_db):
    from datetime import datetime,timezone
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.accounts import create_user
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import Investigation, SecurityAuditEvent
    from app.protected_api import protected_router
    from app.security import Role
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,other_actor=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    with factory.begin() as db:
        a=Investigation(tenant_id=tenant,created_by=actor,title='a',description='fixture')
        b=Investigation(tenant_id=tenant,created_by=actor,title='b',description='fixture')
        c=Investigation(tenant_id=other,created_by=other_actor,title='c',description='fixture')
        db.add_all([a,b,c]); db.flush(); a_id,b_id,c_id=a.id,b.id,c.id
        now=datetime(2026,1,1,tzinfo=timezone.utc)
        db.add_all([SecurityAuditEvent(tenant_id=tenant,actor_id=actor,target_investigation_id=a_id,event_type='investigation_read',occurred_at=now) for _ in range(101)])
        outside=SecurityAuditEvent(tenant_id=tenant,actor_id=actor,target_investigation_id=b_id,event_type='investigation_read',occurred_at=now)
        db.add_all([outside,SecurityAuditEvent(tenant_id=tenant,actor_id=actor,target_investigation_id=a_id,event_type='investigation_updated',occurred_at=now)]); db.flush(); outside_id=outside.id
    def login_as(name): return login(factory,secret=b'x'*32,tenant_id=tenant,username=name,password='a safe long password',source_ip='192.0.2.1').token
    token=login_as('admin'); create_user(factory,admin_token=token,username='viewer',password='a safe long password',role=Role.VIEWER); viewer=login_as('viewer')
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        path='/api/v1/secure/audit'; headers={'Authorization':'Bearer '+token}; filters={'investigation_id':str(a_id),'event_type':'investigation_read'}
        assert client.get(path,headers={'Authorization':'Bearer '+viewer},params=filters).status_code==403
        assert client.get(path,headers=headers,params={'investigation_id':str(c_id)}).json()['items']==[]
        assert client.get(path,headers=headers,params={**filters,'before':str(outside_id)}).status_code==404
        assert client.get(path,headers=headers,params={'event_type':'unknown'}).status_code==422
        first=client.get(path,headers=headers,params=filters).json(); second=client.get(path,headers=headers,params={**filters,'before':first['next_cursor']}).json()
        items=first['items']+second['items']
        assert len(items)==101 and len({x['id'] for x in items})==101 and second['next_cursor'] is None
        assert all(x['target_investigation_id']==str(a_id) and x['event_type']=='investigation_read' for x in items)

def test_migrated_case_details_update_scope_version_history_and_rollback(migration_db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import protected_api
    from app.accounts import create_user
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import Investigation, InvestigationEvent, SecurityAuditEvent
    from app.security import Role
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,_=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    def token(t,user): return login(factory,secret=b'x'*32,tenant_id=t,username=user,password='a safe long password',source_ip='192.0.2.1').token
    admin,foreign=token(tenant,'admin'),token(other,'admin')
    create_user(factory,admin_token=admin,username='viewer',password='a safe long password',role=Role.VIEWER)
    viewer=token(tenant,'viewer')
    headers=lambda t:{'Authorization':'Bearer '+t}
    app=FastAPI(); app.include_router(protected_api.protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123),raise_server_exceptions=False) as client:
        root='/api/v1/secure/investigations'
        case=client.post(root,headers=headers(admin),json={'title':'old','description':'old description'}).json()['id']
        path=f'{root}/{case}'; payload={'title':' new ','description':' new description ','expected_version':1}
        assert client.patch(path,json=payload).status_code==401
        assert client.patch(path,headers=headers(viewer),json=payload).status_code==403
        assert client.patch(path,headers=headers(foreign),json=payload).status_code==404
        assert client.patch(path,headers=headers(admin),json={**payload,'tenant_id':str(other)}).status_code==422
        assert client.patch(path,headers=headers(admin),json={**payload,'title':'  '}).status_code==422
        assert client.patch(path,headers=headers(admin),json=payload).json()['version']==2
        assert client.patch(path,headers=headers(admin),json=payload).status_code==409
        details=client.get(path,headers=headers(viewer)).json()
        assert (details['title'],details['description'],details['version'])==('new','new description',2)
        events=client.get(path+'/events',headers=headers(viewer)).json()['items']
        assert events[-1]['event_type']=='details_changed'
        assert events[-1]['details']['previous']=={'title':'old','description':'old description'}
        assert events[-1]['details']['current']=={'title':'new','description':'new description'}
        def fail(*args,**kwargs): raise RuntimeError('audit failure')
        with monkeypatch.context() as patch:
            patch.setattr(protected_api,'record_event',fail)
            assert client.patch(path,headers=headers(admin),json={'title':'rollback','description':'rollback','expected_version':2}).status_code==500
        assert client.patch(path+'/status',headers=headers(admin),json={'status':'closed','expected_version':2}).status_code==200
        assert client.patch(path,headers=headers(admin),json={'title':'closed','description':'closed','expected_version':3}).status_code==409
    with factory() as db:
        case_row=db.scalar(select(Investigation).where(Investigation.id==UUID(case)))
        assert (case_row.title,case_row.description,case_row.version)==('new','new description',3)
        assert len(list(db.scalars(select(InvestigationEvent).where(InvestigationEvent.event_type=='details_changed'))))==1
        audit=db.scalar(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type=='investigation_updated',SecurityAuditEvent.target_investigation_id==case_row.id))
        assert audit is not None and audit.tenant_id==tenant and audit.actor_id==actor


@pytest.mark.parametrize("intervening", ["close", "edit"])
def test_postgres_case_details_waiting_on_concurrent_change_is_denied(migration_db, intervening):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import event, update
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import Investigation, InvestigationEvent
    from app.protected_api import protected_router
    engine,_=migration_db
    if engine.dialect.name!='postgresql': pytest.skip('PostgreSQL row locks required')
    factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    with factory.begin() as db:
        case=Investigation(tenant_id=tenant,created_by=actor,title='old',description='old'); db.add(case); db.flush(); case_id=case.id
    token=login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32)); waiting=Event()
    def observe(conn,cursor,statement,parameters,context,executemany):
        if 'FROM investigations' in statement and 'FOR UPDATE' in statement: waiting.set()
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with factory.begin() as blocker:
                blocker.scalar(select(Investigation).where(Investigation.id==case_id).with_for_update())
                event.listen(engine,'before_cursor_execute',observe)
                future=pool.submit(client.patch,f'/api/v1/secure/investigations/{case_id}',headers={'Authorization':'Bearer '+token},json={'title':'new','description':'new','expected_version':1})
                try:
                    assert waiting.wait(10)
                    changes = {'status':'closed','version':2} if intervening == 'close' else {'title':'other update','version':2}
                    blocker.execute(update(Investigation).where(Investigation.id==case_id).values(**changes))
                finally: event.remove(engine,'before_cursor_execute',observe)
            assert future.result(timeout=10).status_code==409
    with factory() as db:
        assert db.get(Investigation,case_id).title==('old' if intervening == 'close' else 'other update')
        assert db.scalar(select(InvestigationEvent.id)) is None


def test_migrated_admin_revokes_account_sessions_scope_and_rollback(migration_db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import accounts
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import AuthSession, SecurityAuditEvent
    from app.protected_api import protected_router
    from app.security import Role
    from app.sessions import authenticate_session
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    foreign,foreign_user=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    def token(t,user): return login(factory,secret=b'x'*32,tenant_id=t,username=user,password='a safe long password',source_ip='192.0.2.1').token
    admin=token(tenant,'admin')
    target=accounts.create_user(factory,admin_token=admin,username='analyst',password='a safe long password',role=Role.ANALYST)
    viewer_id=accounts.create_user(factory,admin_token=admin,username='viewer',password='a safe long password',role=Role.VIEWER)
    a,b,viewer=token(tenant,'analyst'),token(tenant,'analyst'),token(tenant,'viewer')
    headers=lambda t:{'Authorization':'Bearer '+t}
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123),raise_server_exceptions=False) as client:
        path=f'/api/v1/secure/users/{target}/revoke-sessions'
        assert client.post(path).status_code==401
        assert client.post(path,headers=headers(viewer)).status_code==403
        assert client.post(f'/api/v1/secure/users/{foreign_user}/revoke-sessions',headers=headers(admin)).status_code==403
        assert client.post(f'/api/v1/secure/users/{actor}/revoke-sessions',headers=headers(admin)).status_code==403
        def fail(*args,**kwargs): raise RuntimeError('audit unavailable')
        with monkeypatch.context() as patch:
            patch.setattr(accounts,'record_event',fail)
            assert client.post(path,headers=headers(admin)).status_code==500
        with factory() as db:
            assert authenticate_session(db,a) is not None and authenticate_session(db,b) is not None
        response=client.post(path,headers=headers(admin))
        assert response.status_code==200 and response.json()['count']==2
        assert response.headers['cache-control']=='no-store'
        assert client.get('/api/v1/secure/entities',headers=headers(a)).status_code==401
        assert client.get('/api/v1/secure/entities',headers=headers(b)).status_code==401
        assert client.get('/api/v1/secure/entities',headers=headers(viewer)).status_code==200
        assert client.post(path,headers=headers(admin)).json()['count']==0
        fresh=token(tenant,'analyst')
        assert fresh and client.get('/api/v1/secure/entities',headers=headers(fresh)).status_code==200
        events=client.get('/api/v1/secure/audit',headers=headers(admin),params={'event_type':'user_sessions_revoked'}).json()['items']
        assert len(events)==2 and all(e['target_user_id']==str(target) and e['actor_id']==str(actor) for e in events)
    with factory() as db:
        assert db.scalar(select(AuthSession.id).where(AuthSession.user_id==viewer_id,AuthSession.revoked_at.is_(None))) is not None
        assert len(list(db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type=='user_sessions_revoked'))))==2


def test_postgres_admin_session_revocation_waits_for_target_login(migration_db):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from sqlalchemy import event
    from sqlalchemy.orm import sessionmaker
    from app.accounts import create_user, revoke_user_sessions
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import User
    from app.security import Role
    from app.sessions import issue_session, authenticate_session
    engine,_=migration_db
    if engine.dialect.name!='postgresql': pytest.skip('PostgreSQL row locks required')
    factory=sessionmaker(engine,expire_on_commit=False)
    tenant,_=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    admin=login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    target=create_user(factory,admin_token=admin,username='analyst',password='a safe long password',role=Role.ANALYST)
    waiting=Event()
    def observe(conn,cursor,statement,parameters,context,executemany):
        if 'FROM users' in statement and 'FOR UPDATE' in statement: waiting.set()
    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory.begin() as blocker:
            blocker.scalar(select(User).where(User.id==target).with_for_update())
            session=issue_session(blocker,tenant,'analyst','a safe long password')
            event.listen(engine,'before_cursor_execute',observe)
            future=pool.submit(revoke_user_sessions,factory,admin_token=admin,user_id=target)
            try: assert waiting.wait(10)
            finally: event.remove(engine,'before_cursor_execute',observe)
        assert future.result(timeout=10)==1
    with factory() as db: assert authenticate_session(db,session) is None


def test_migrated_self_password_change_revokes_sessions_and_rolls_back(migration_db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import accounts
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login, LoginStatus
    from app.models import SecurityAuditEvent
    from app.protected_api import protected_router
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    def login_with(pw): return login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password=pw,source_ip='192.0.2.1')
    a,b=login_with('a safe long password').token,login_with('a safe long password').token
    headers=lambda t:{'Authorization':'Bearer '+t}
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    payload={'current_password':'a safe long password','new_password':'a new safe password'}
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123),raise_server_exceptions=False) as client:
        path='/api/v1/secure/password'
        assert client.post(path,json=payload).status_code==401
        assert client.post(path,headers=headers(a),json={**payload,'new_password':'short'}).status_code==422
        assert client.post(path,headers=headers(a),json={**payload,'current_password':'wrong password'}).status_code==403
        assert client.post(path,headers=headers(a),json={**payload,'tenant_id':str(tenant)}).status_code==422
        def fail(*args,**kwargs): raise RuntimeError('audit unavailable')
        with monkeypatch.context() as patch:
            patch.setattr(accounts,'record_event',fail)
            assert client.post(path,headers=headers(a),json=payload).status_code==500
        assert client.get('/api/v1/secure/entities',headers=headers(a)).status_code==200
        response=client.post(path,headers=headers(a),json=payload)
        assert response.status_code==200 and response.headers['cache-control']=='no-store'
        assert payload['current_password'] not in response.text and payload['new_password'] not in response.text
        assert client.get('/api/v1/secure/entities',headers=headers(a)).status_code==401
        assert client.get('/api/v1/secure/entities',headers=headers(b)).status_code==401
        assert login_with('a safe long password').status==LoginStatus.DENIED
        fresh=login_with('a new safe password').token
        assert fresh and client.get('/api/v1/secure/entities',headers=headers(fresh)).status_code==200
        audit=client.get('/api/v1/secure/audit',headers=headers(fresh),params={'event_type':'user_password_changed'}).json()['items']
        assert len(audit)==1 and audit[0]['target_user_id']==str(actor)
        assert payload['new_password'] not in str(audit) and payload['current_password'] not in str(audit)
    with factory() as db: assert len(list(db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type=='user_password_changed'))))==1


def test_password_change_rechecks_session_and_hash_after_hashing(migration_db, monkeypatch):
    from sqlalchemy.orm import sessionmaker
    from app import accounts
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login, logout
    from app.models import User, SecurityAuditEvent
    from app.security import hash_password, verify_password
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    def token(): return login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    first=token()
    def revoke_then_hash(password):
        assert logout(factory,first)
        return hash_password(password)
    with monkeypatch.context() as patch:
        patch.setattr(accounts,'hash_password',revoke_then_hash)
        with pytest.raises(PermissionError): accounts.change_own_password(factory,token=first,secret=b'x'*32,current_password='a safe long password',new_password='new password long')
    second=token()
    def change_hash_before_return(password):
        with factory.begin() as db: db.get(User,actor).password_hash=hash_password('intervening password')
        return hash_password(password)
    with monkeypatch.context() as patch:
        patch.setattr(accounts,'hash_password',change_hash_before_return)
        with pytest.raises(PermissionError): accounts.change_own_password(factory,token=second,secret=b'x'*32,current_password='a safe long password',new_password='new password long')
    with factory() as db:
        assert verify_password('intervening password',db.get(User,actor).password_hash)
        assert db.scalar(select(SecurityAuditEvent.id).where(SecurityAuditEvent.event_type=='user_password_changed')) is None


def test_password_change_attempts_are_throttled_before_verification(migration_db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import accounts
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.protected_api import protected_router
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,_=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    token=login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    calls=[]
    from app.rate_limit import consume
    monkeypatch.setattr(accounts,'consume',lambda db,**kwargs:consume(db,**kwargs,now=120))
    def verify(*args): calls.append(1); return False
    monkeypatch.setattr(accounts,'verify_password',verify)
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        payload={'current_password':'wrong password','new_password':'a new safe password'}
        statuses=[client.post('/api/v1/secure/password',headers={'Authorization':'Bearer '+token},json=payload).status_code for _ in range(6)]
        assert statuses==[403]*5+[429]
        assert len(calls)==5
        events=client.get('/api/v1/secure/audit',headers={'Authorization':'Bearer '+token}).json()['items']
        assert sum(e['event_type']=='user_password_change_failed' for e in events)==5
        assert sum(e['event_type']=='user_password_change_throttled' for e in events)==1
        assert 'wrong password' not in str(events) and 'a new safe password' not in str(events)


def test_postgres_concurrent_self_password_changes_only_one_commits(migration_db, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from sqlalchemy.orm import sessionmaker
    from app import accounts
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import User, SecurityAuditEvent
    from app.security import hash_password, verify_password
    from app.sessions import authenticate_session
    engine,_=migration_db
    if engine.dialect.name!='postgresql': pytest.skip('PostgreSQL row locks required')
    factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    def login_token(): return login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    tokens=[login_token(),login_token()]
    barrier=Barrier(2)
    def parallel_hash(password):
        encoded=hash_password(password)
        barrier.wait(timeout=20)
        return encoded
    monkeypatch.setattr(accounts,'hash_password',parallel_hash)
    passwords=['new safe password one','new safe password two']
    def change(index):
        try:
            accounts.change_own_password(factory,token=tokens[index],secret=b'x'*32,current_password='a safe long password',new_password=passwords[index])
            return 'success'
        except PermissionError: return 'denied'
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(change,range(2)))
    assert sorted(results)==['denied','success']
    with factory() as db:
        assert verify_password(passwords[results.index('success')],db.get(User,actor).password_hash)
        assert all(authenticate_session(db,token) is None for token in tokens)
        assert len(list(db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type=='user_password_changed'))))==1


def test_migrated_current_user_is_locked_audited_and_tenant_scoped(migration_db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import protected_api
    from app.accounts import create_user, change_role, disable_user
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import SecurityAuditEvent
    from app.security import Role
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,other_actor=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    def token(t,user): return login(factory,secret=b'x'*32,tenant_id=t,username=user,password='a safe long password',source_ip='192.0.2.1').token
    admin,foreign=token(tenant,'admin'),token(other,'admin')
    target=create_user(factory,admin_token=admin,username='analyst',password='a safe long password',role=Role.ANALYST)
    analyst=token(tenant,'analyst')
    app=FastAPI(); app.include_router(protected_api.protected_router(factory,b'x'*32))
    h=lambda t:{'Authorization':'Bearer '+t}
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123),raise_server_exceptions=False) as client:
        path='/api/v1/secure/me'
        assert client.get(path).status_code==401
        r=client.get(path,headers=h(analyst)); assert r.status_code==200 and r.headers['cache-control']=='no-store'
        assert r.json()=={'id':str(target),'tenant_id':str(tenant),'username':'analyst','role':'analyst'}
        assert client.get(path,headers=h(foreign)).json()['tenant_id']==str(other)
        assert client.get(path,headers=h(foreign)).json()['id']==str(other_actor)
        change_role(factory,admin_token=admin,user_id=target,role=Role.VIEWER)
        assert client.get(path,headers=h(analyst)).json()['role']=='viewer'
        def fail(*args,**kwargs): raise RuntimeError('audit unavailable')
        with monkeypatch.context() as patch:
            patch.setattr(protected_api,'record_event',fail)
            assert client.get(path,headers=h(analyst)).status_code==500
        disable_user(factory,admin_token=admin,user_id=target)
        assert client.get(path,headers=h(analyst)).status_code==401
    with factory() as db:
        rows=list(db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type=='user_self_read',SecurityAuditEvent.tenant_id==tenant)))
        assert len(rows)==2 and all(row.target_user_id==target and row.actor_id==target for row in rows)


def test_migrated_user_directory_rbac_scope_cursor_and_audit(migration_db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import protected_api
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import SecurityAuditEvent, User
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,foreign_actor=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    with factory.begin() as db:
        db.add_all([User(tenant_id=tenant,username=f'user{i}',role='viewer',active=(i%2==0),password_hash='fixture-not-a-hash') for i in range(100)])
    admin=login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    app=FastAPI(); app.include_router(protected_api.protected_router(factory,b'x'*32))
    h={'Authorization':'Bearer '+admin}
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123),raise_server_exceptions=False) as client:
        path='/api/v1/secure/users'
        assert client.get(path).status_code==401
        r=client.get(path,headers=h); assert r.status_code==200 and r.headers['cache-control']=='no-store'
        first=r.json(); assert len(first['items'])==100 and first['next_cursor']
        second=client.get(path,headers=h,params={'after':first['next_cursor']}).json()
        items=first['items']+second['items']; assert len(items)==101 and len({x['id'] for x in items})==101
        assert all(set(x)=={'id','username','role','active'} for x in items)
        assert 'fixture-not-a-hash' not in str(items) and str(foreign_actor) not in str(items)
        assert client.get(path,headers=h,params={'after':str(foreign_actor)}).status_code==404
        assert client.get(path,headers=h,params={'after':str(uuid4())}).status_code==404
        def fail(*args,**kwargs): raise RuntimeError('audit unavailable')
        with monkeypatch.context() as patch:
            patch.setattr(protected_api,'record_event',fail)
            assert client.get(path,headers=h).status_code==500
        # Fresh role state is used, not the role present at login.
        with factory.begin() as db: db.get(User,actor).role='viewer'
        assert client.get(path,headers=h).status_code==403
    with factory() as db:
        events=list(db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type=='user_directory_read')))
        assert len(events)==2 and all(e.tenant_id==tenant and e.actor_id==actor for e in events)


def test_migrated_self_session_management_and_audit_survives_cleanup(migration_db, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import protected_api
    from app.accounts import create_user
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import AuthSession, SecurityAuditEvent
    from app.security import Role
    from app.sessions import cleanup_expired_sessions_batch
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,_=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    def token(t,user): return login(factory,secret=b'x'*32,tenant_id=t,username=user,password='a safe long password',source_ip='192.0.2.1').token
    a,b,foreign=token(tenant,'admin'),token(tenant,'admin'),token(other,'admin')
    create_user(factory,admin_token=a,username='viewer',password='a safe long password',role=Role.VIEWER)
    viewer=token(tenant,'viewer')
    app=FastAPI(); app.include_router(protected_api.protected_router(factory,b'x'*32)); h=lambda t:{'Authorization':'Bearer '+t}
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123),raise_server_exceptions=False) as client:
        path='/api/v1/secure/sessions'
        assert client.get(path).status_code==401
        response=client.get(path,headers=h(a)); assert response.status_code==200 and response.headers['cache-control']=='no-store'
        items=response.json()['items']; assert len(items)==2
        assert all(set(item)=={'id','created_at','expires_at','revoked_at','current'} for item in items)
        current=next(x['id'] for x in items if x['current']); other_id=next(x['id'] for x in items if not x['current'])
        foreign_id=client.get(path,headers=h(foreign)).json()['items'][0]['id']
        viewer_id=client.get(path,headers=h(viewer)).json()['items'][0]['id']
        assert client.get(path,headers=h(a),params={'after':foreign_id}).status_code==404
        assert client.get(path,headers=h(a),params={'after':viewer_id}).status_code==404
        assert client.delete(path+'/'+foreign_id,headers=h(a)).status_code==404
        assert client.delete(path+'/'+viewer_id,headers=h(a)).status_code==404
        def fail(*args,**kwargs): raise RuntimeError('audit unavailable')
        with monkeypatch.context() as patch:
            patch.setattr(protected_api,'record_event',fail)
            assert client.delete(path+'/'+other_id,headers=h(a)).status_code==500
            assert client.get(path,headers=h(a)).status_code==500
        assert client.get('/api/v1/secure/me',headers=h(b)).status_code==200
        assert client.delete(path+'/'+other_id,headers=h(a)).status_code==200
        assert client.delete(path+'/'+other_id,headers=h(a)).status_code==404
        assert client.get('/api/v1/secure/me',headers=h(b)).status_code==401
        audit=client.get('/api/v1/secure/audit',headers=h(a),params={'event_type':'session_single_revoked'}).json()['items']
        assert len(audit)==1 and audit[0]['target_session_id']==other_id and audit[0]['target_user_id']==str(actor)
        assert a not in str(items) and b not in str(items)
        assert client.delete(path+'/'+current,headers=h(a)).status_code==200
        assert client.get('/api/v1/secure/me',headers=h(a)).status_code==401
    with factory.begin() as db:
        db.get(AuthSession,UUID(other_id)).expires_at=datetime.now(timezone.utc)-timedelta(days=2)
    with factory.begin() as db: assert cleanup_expired_sessions_batch(db)>=1
    with factory() as db:
        assert db.get(AuthSession,UUID(other_id)) is None
        assert db.scalar(select(SecurityAuditEvent.id).where(SecurityAuditEvent.target_session_id==UUID(other_id))) is not None
    with factory.begin() as db:
        db.add(SecurityAuditEvent(tenant_id=tenant,event_type='test',target_session_id=uuid4()))
        with pytest.raises(IntegrityError): db.flush()
        db.rollback()


def test_postgres_single_session_concurrent_revokes_are_serialized(migration_db):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event, Lock
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import event
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import User, SecurityAuditEvent
    from app.protected_api import protected_router
    engine,_=migration_db
    if engine.dialect.name!='postgresql': pytest.skip('PostgreSQL row locks required')
    factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    def token(): return login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    a,b,c=token(),token(),token()
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    waiting=Event(); guard=Lock(); count=[0]
    def observe(conn,cursor,statement,parameters,context,executemany):
        if 'FROM users' in statement and 'FOR UPDATE' in statement:
            with guard:
                count[0]+=1
                if count[0]>=2: waiting.set()
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        c_id=next(x['id'] for x in client.get('/api/v1/secure/sessions',headers={'Authorization':'Bearer '+c}).json()['items'] if x['current'])
        with ThreadPoolExecutor(max_workers=2) as pool:
            with factory.begin() as blocker:
                blocker.scalar(select(User).where(User.id==actor).with_for_update())
                event.listen(engine,'before_cursor_execute',observe)
                futures=[pool.submit(client.delete,f'/api/v1/secure/sessions/{c_id}',headers={'Authorization':'Bearer '+t}) for t in (a,b)]
                try: assert waiting.wait(10)
                finally: event.remove(engine,'before_cursor_execute',observe)
            assert sorted(f.result(timeout=10).status_code for f in futures)==[200,404]
    with factory() as db:
        events=list(db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type=='session_single_revoked')))
        assert len(events)==1 and events[0].target_session_id==UUID(c_id)


def test_migrated_self_session_pagination(migration_db):
    from datetime import datetime, timedelta, timezone
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import AuthSession
    from app.protected_api import protected_router
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    token=login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    with factory.begin() as db:
        db.add_all([AuthSession(tenant_id=tenant,user_id=actor,token_digest=f'{i:064x}',
            created_at=datetime.now(timezone.utc),expires_at=datetime.now(timezone.utc)+timedelta(hours=1)) for i in range(101)])
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        path='/api/v1/secure/sessions'; h={'Authorization':'Bearer '+token}
        first=client.get(path,headers=h).json(); assert len(first['items'])==100 and first['next_cursor']
        second=client.get(path,headers=h,params={'after':first['next_cursor']}).json()
        rows=first['items']+second['items']; assert len(rows)==102 and len({row['id'] for row in rows})==102
        assert sum(row['current'] for row in rows)==1 and second['next_cursor'] is None
        assert client.get(path,headers=h,params={'after':str(uuid4())}).status_code==404


def test_session_audit_revision_preserves_existing_rows(tmp_path, monkeypatch):
    url=f'sqlite:///{tmp_path / "session-audit.db"}'
    monkeypatch.setenv('DATABASE_URL',url)
    config=Config(str(HERE/'alembic.ini')); command.upgrade(config,'0024_audit_case_index')
    engine=create_engine(url)
    tenant, audit=uuid4(),uuid4()
    with engine.begin() as conn:
        conn.exec_driver_sql('INSERT INTO tenants (id,name) VALUES (?,?)',(tenant.hex,'fixture'))
        conn.exec_driver_sql('INSERT INTO security_audit_events (id,tenant_id,event_type,occurred_at) VALUES (?,?,?,?)',(audit.hex,tenant.hex,'fixture','2026-01-01 00:00:00'))
    command.upgrade(config,'head')
    with engine.begin() as conn:
        assert conn.exec_driver_sql('SELECT event_type,target_session_id FROM security_audit_events').all()==[('fixture',None)]
    command.downgrade(config,'0024_audit_case_index')
    with engine.begin() as conn:
        assert conn.exec_driver_sql('SELECT event_type FROM security_audit_events').all()==[('fixture',)]
    command.downgrade(config,'base'); engine.dispose()


@pytest.mark.parametrize('operation',['list','revoke'])
def test_postgres_self_sessions_recheck_disable_after_lock_wait(migration_db, operation):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import event, update
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import User, AuthSession, SecurityAuditEvent
    from app.protected_api import protected_router
    engine,_=migration_db
    if engine.dialect.name!='postgresql': pytest.skip('PostgreSQL row locks required')
    factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    def login_token(): return login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    a,b=login_token(),login_token()
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32)); waiting=Event()
    def observe(conn,cursor,statement,parameters,context,executemany):
        if 'FROM users' in statement and 'FOR UPDATE' in statement: waiting.set()
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        h={'Authorization':'Bearer '+a}
        b_id=next(x['id'] for x in client.get('/api/v1/secure/sessions',headers={'Authorization':'Bearer '+b}).json()['items'] if x['current'])
        with ThreadPoolExecutor(max_workers=1) as pool:
            with factory.begin() as blocker:
                blocker.scalar(select(User).where(User.id==actor).with_for_update())
                event.listen(engine,'before_cursor_execute',observe)
                if operation=='list': future=pool.submit(client.get,'/api/v1/secure/sessions',headers=h)
                else: future=pool.submit(client.delete,f'/api/v1/secure/sessions/{b_id}',headers=h)
                try:
                    assert waiting.wait(10)
                    blocker.execute(update(User).where(User.id==actor).values(active=False))
                finally: event.remove(engine,'before_cursor_execute',observe)
            assert future.result(timeout=10).status_code==401
    with factory() as db:
        assert db.get(AuthSession,UUID(b_id)).revoked_at is None
        assert db.scalar(select(SecurityAuditEvent.id).where(SecurityAuditEvent.event_type=='session_single_revoked')) is None


def test_migrated_entity_detail_scoped_audited_and_fail_closed(migration_db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import protected_api
    from app.accounts import create_user
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import SecurityAuditEvent
    from app.security import Role
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,other_actor=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    def token(t,user): return login(factory,secret=b'x'*32,tenant_id=t,username=user,password='a safe long password',source_ip='192.0.2.1').token
    admin,foreign=token(tenant,'admin'),token(other,'admin')
    create_user(factory,admin_token=admin,username='viewer',password='a safe long password',role=Role.VIEWER)
    viewer=token(tenant,'viewer')
    with factory.begin() as db:
        a=Entity(tenant_id=tenant,created_by=actor,kind='indicator',title='fixture',source='manual',properties={'private_extra':'not returned'})
        b=Entity(tenant_id=other,created_by=other_actor,kind='indicator',title='foreign',source='manual')
        db.add_all([a,b]); db.flush(); a_id,b_id=a.id,b.id
    app=FastAPI(); app.include_router(protected_api.protected_router(factory,b'x'*32)); h=lambda t:{'Authorization':'Bearer '+t}
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123),raise_server_exceptions=False) as client:
        path=f'/api/v1/secure/entities/{a_id}'
        assert client.get(path).status_code==401
        assert client.get(path,headers=h(foreign)).status_code==404
        assert client.get(f'/api/v1/secure/entities/{b_id}',headers=h(viewer)).status_code==404
        response=client.get(path,headers=h(viewer)); assert response.status_code==200 and response.headers['cache-control']=='no-store'
        detail=response.json(); listed=client.get('/api/v1/secure/entities',headers=h(viewer)).json()['items'][0]
        assert {k:v for k,v in detail.items() if k!='notice'}==listed
        assert detail['verification_status']=='unverified' and 'private_extra' not in str(detail)
        def fail(*args,**kwargs): raise RuntimeError('audit unavailable')
        with monkeypatch.context() as patch:
            patch.setattr(protected_api,'record_event',fail)
            assert client.get(path,headers=h(viewer)).status_code==500
    with factory() as db:
        events=list(db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type=='intelligence_read',SecurityAuditEvent.target_entity_id==a_id)))
        assert len(events)==1 and events[0].tenant_id==tenant


def test_migrated_evidence_detail_scope_and_audit_constraints(migration_db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import protected_api
    from app.accounts import create_user
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import EvidenceReference, SecurityAuditEvent
    from app.security import Role
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,other_actor=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    def token(t,user): return login(factory,secret=b'x'*32,tenant_id=t,username=user,password='a safe long password',source_ip='192.0.2.1').token
    admin,foreign=token(tenant,'admin'),token(other,'admin')
    create_user(factory,admin_token=admin,username='viewer',password='a safe long password',role=Role.VIEWER)
    viewer=token(tenant,'viewer')
    with factory.begin() as db:
        entities=[Entity(tenant_id=t,created_by=u,kind='indicator',title='fixture',source='manual') for t,u in [(tenant,actor),(tenant,actor),(other,other_actor)]]
        db.add_all(entities); db.flush(); a,b,c=[e.id for e in entities]
        refs=[EvidenceReference(tenant_id=t,entity_id=e,created_by=u,description='unverified fixture',source='manual') for t,e,u in [(tenant,a,actor),(tenant,b,actor),(other,c,other_actor)]]
        db.add_all(refs); db.flush(); ar,br,cr=[r.id for r in refs]
    app=FastAPI(); app.include_router(protected_api.protected_router(factory,b'x'*32)); h=lambda t:{'Authorization':'Bearer '+t}
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123),raise_server_exceptions=False) as client:
        base='/api/v1/secure/entities'; path=f'{base}/{a}/evidence/{ar}'
        assert client.get(path).status_code==401
        assert client.get(path,headers=h(foreign)).status_code==404
        assert client.get(f'{base}/{a}/evidence/{br}',headers=h(viewer)).status_code==404
        assert client.get(f'{base}/{a}/evidence/{cr}',headers=h(viewer)).status_code==404
        response=client.get(path,headers=h(viewer)); assert response.status_code==200 and response.headers['cache-control']=='no-store'
        detail=response.json(); listed=client.get(f'{base}/{a}/evidence',headers=h(viewer)).json()['items'][0]
        assert {k:v for k,v in detail.items() if k!='notice'}==listed
        assert detail['status']=='analyst_entered_unverified'
        created=client.post(f'{base}/{a}/evidence',headers=h(admin),json={'description':'fixture','source':'manual'}); assert created.status_code==201
        audit=client.get('/api/v1/secure/audit',headers=h(admin)).json()['items']
        assert any(e['event_type']=='evidence_read' and e['target_entity_id']==str(a) and e['target_evidence_id']==str(ar) for e in audit)
        assert any(e['event_type']=='evidence_created' and e['target_evidence_id']==created.json()['id'] for e in audit)
        def fail(*args,**kwargs): raise RuntimeError('audit unavailable')
        with monkeypatch.context() as patch:
            patch.setattr(protected_api,'record_event',fail)
            assert client.get(path,headers=h(viewer)).status_code==500
    for kwargs in [dict(target_evidence_id=ar),dict(target_entity_id=a,target_evidence_id=br),dict(target_entity_id=a,target_evidence_id=cr)]:
        with factory.begin() as db:
            db.add(SecurityAuditEvent(tenant_id=tenant,actor_id=actor,event_type='fixture',**kwargs))
            with pytest.raises(IntegrityError): db.flush()
            db.rollback()


def test_evidence_audit_revision_preserves_existing_rows(tmp_path, monkeypatch):
    url=f'sqlite:///{tmp_path / "evidence-audit.db"}'
    monkeypatch.setenv('DATABASE_URL',url)
    config=Config(str(HERE/'alembic.ini')); command.upgrade(config,'0026_entity_kind_index')
    engine=create_engine(url); tenant,audit=uuid4(),uuid4()
    with engine.begin() as conn:
        conn.exec_driver_sql('INSERT INTO tenants (id,name) VALUES (?,?)',(tenant.hex,'fixture'))
        conn.exec_driver_sql('INSERT INTO security_audit_events (id,tenant_id,event_type,occurred_at) VALUES (?,?,?,?)',(audit.hex,tenant.hex,'fixture','2026-01-01 00:00:00'))
    command.upgrade(config,'head')
    with engine.begin() as conn: assert conn.exec_driver_sql('SELECT event_type,target_evidence_id FROM security_audit_events').all()==[('fixture',None)]
    command.downgrade(config,'0026_entity_kind_index')
    with engine.begin() as conn: assert conn.exec_driver_sql('SELECT event_type FROM security_audit_events').all()==[('fixture',)]
    command.downgrade(config,'base'); engine.dispose()


def test_migrated_evidence_audit_filter_cursor_and_tenant_scope(migration_db):
    from datetime import datetime,timezone
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import EvidenceReference, SecurityAuditEvent
    from app.protected_api import protected_router
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,other_actor=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    with factory.begin() as db:
        a=Entity(tenant_id=tenant,created_by=actor,kind='indicator',title='a',source='fixture')
        b=Entity(tenant_id=other,created_by=other_actor,kind='indicator',title='b',source='fixture')
        db.add_all([a,b]); db.flush()
        ar=EvidenceReference(tenant_id=tenant,entity_id=a.id,created_by=actor,description='fixture',source='manual')
        br=EvidenceReference(tenant_id=other,entity_id=b.id,created_by=other_actor,description='fixture',source='manual')
        db.add_all([ar,br]); db.flush(); a_id,ar_id,br_id=a.id,ar.id,br.id
        now=datetime(2026,1,1,tzinfo=timezone.utc)
        db.add_all([SecurityAuditEvent(tenant_id=tenant,actor_id=actor,target_entity_id=a_id,target_evidence_id=ar_id,event_type='evidence_read',occurred_at=now) for _ in range(101)])
        outside=SecurityAuditEvent(tenant_id=tenant,actor_id=actor,event_type='intelligence_read',occurred_at=now)
        db.add(outside); db.flush(); outside_id=outside.id
    token=login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        path='/api/v1/secure/audit'; h={'Authorization':'Bearer '+token}; filters={'evidence_id':str(ar_id),'event_type':'evidence_read'}
        assert client.get(path,headers=h,params={'evidence_id':str(br_id)}).json()['items']==[]
        assert client.get(path,headers=h,params={**filters,'before':str(outside_id)}).status_code==404
        assert client.get(path,headers=h,params={'entity_id':str(b.id)}).json()['items']==[]
        entity_filters={'entity_id':str(a_id),'event_type':'evidence_read'}
        assert client.get(path,headers=h,params={**entity_filters,'before':str(outside_id)}).status_code==404
        ef=client.get(path,headers=h,params=entity_filters).json(); es=client.get(path,headers=h,params={**entity_filters,'before':ef['next_cursor']}).json()
        assert len(ef['items']+es['items'])==101 and all(row['target_entity_id']==str(a_id) for row in ef['items']+es['items'])
        first=client.get(path,headers=h,params=filters).json(); second=client.get(path,headers=h,params={**filters,'before':first['next_cursor']}).json()
        rows=first['items']+second['items']; assert len(rows)==101 and len({r['id'] for r in rows})==101 and second['next_cursor'] is None
        assert all(r['target_evidence_id']==str(ar_id) and r['event_type']=='evidence_read' for r in rows)


def test_migrated_case_evidence_detail_scope_and_audit(migration_db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import protected_api
    from app.accounts import create_user
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import EvidenceReference, Investigation, InvestigationEntityLink, InvestigationEvidenceLink, SecurityAuditEvent
    from app.security import Role
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,other_actor=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    def token(t,u): return login(factory,secret=b'x'*32,tenant_id=t,username=u,password='a safe long password',source_ip='192.0.2.1').token
    admin,foreign=token(tenant,'admin'),token(other,'admin')
    create_user(factory,admin_token=admin,username='viewer',password='a safe long password',role=Role.VIEWER); viewer=token(tenant,'viewer')
    with factory.begin() as db:
        cases=[Investigation(tenant_id=t,created_by=u,title='fixture',description='fixture') for t,u in [(tenant,actor),(tenant,actor),(other,other_actor)]]
        entities=[Entity(tenant_id=t,created_by=u,kind='indicator',title='fixture',source='manual') for t,u in [(tenant,actor),(tenant,actor),(other,other_actor)]]
        db.add_all(cases+entities); db.flush()
        refs=[EvidenceReference(tenant_id=t,entity_id=e.id,created_by=u,description='fixture',source='manual') for t,e,u in zip((tenant,tenant,other),entities,(actor,actor,other_actor))]
        entity_links=[InvestigationEntityLink(tenant_id=t,investigation_id=c.id,entity_id=e.id,created_by=u) for t,c,e,u in zip((tenant,tenant,other),cases,entities,(actor,actor,other_actor))]
        db.add_all(refs+entity_links); db.flush(); entity_link_ids=[item.id for item in entity_links]
        links=[InvestigationEvidenceLink(tenant_id=t,investigation_id=c.id,entity_id=e.id,evidence_id=r.id,created_by=u) for t,c,e,r,u in zip((tenant,tenant,other),cases,entities,refs,(actor,actor,other_actor))]
        db.add_all(links); db.flush(); case_ids=[c.id for c in cases]; entity_id,evidence_id=entities[0].id,refs[0].id; link_ids=[l.id for l in links]
    app=FastAPI(); app.include_router(protected_api.protected_router(factory,b'x'*32)); h=lambda t:{'Authorization':'Bearer '+t}
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123),raise_server_exceptions=False) as client:
        base='/api/v1/secure/investigations'; path=f'{base}/{case_ids[0]}/evidence/{link_ids[0]}'
        assert client.get(path).status_code==401
        assert client.get(path,headers=h(foreign)).status_code==404
        assert client.get(f'{base}/{case_ids[1]}/evidence/{link_ids[0]}',headers=h(viewer)).status_code==404
        assert client.get(f'{base}/{case_ids[0]}/evidence/{link_ids[2]}',headers=h(viewer)).status_code==404
        response=client.get(path,headers=h(viewer)); assert response.status_code==200 and response.headers['cache-control']=='no-store'
        item=client.get(f'{base}/{case_ids[0]}/evidence',headers=h(viewer)).json()['items'][0]
        assert {k:v for k,v in response.json().items() if k!='notice'}==item
        assert response.json()['status']=='analyst_entered_unverified'
        entity_path=f'{base}/{case_ids[0]}/entities/{entity_link_ids[0]}'
        assert client.get(entity_path).status_code==401
        assert client.get(entity_path,headers=h(foreign)).status_code==404
        assert client.get(f'{base}/{case_ids[1]}/entities/{entity_link_ids[0]}',headers=h(viewer)).status_code==404
        assert client.get(f'{base}/{case_ids[0]}/entities/{entity_link_ids[2]}',headers=h(viewer)).status_code==404
        entity_result=client.get(entity_path,headers=h(viewer)); assert entity_result.status_code==200
        entity_item=client.get(f'{base}/{case_ids[0]}/entities',headers=h(viewer)).json()['items'][0]
        assert {k:v for k,v in entity_result.json().items() if k!='notice'}==entity_item
        assert entity_result.json()['status']=='analyst_association_unverified'
        def fail(*args,**kwargs): raise RuntimeError('audit unavailable')
        with monkeypatch.context() as patch:
            patch.setattr(protected_api,'record_event',fail)
            assert client.get(path,headers=h(viewer)).status_code==500
            assert client.get(entity_path,headers=h(viewer)).status_code==500
    with factory() as db:
        events=list(db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type=='investigation_read',SecurityAuditEvent.target_evidence_id==evidence_id)))
        assert len(events)==1 and events[0].tenant_id==tenant and events[0].target_investigation_id==case_ids[0] and events[0].target_entity_id==entity_id
        entity_events=list(db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type=='investigation_read',SecurityAuditEvent.target_entity_id==entity_id,SecurityAuditEvent.target_evidence_id.is_(None))))
        assert len(entity_events)==1 and entity_events[0].target_investigation_id==case_ids[0]


def test_postgres_login_waiting_for_password_change_rechecks_hash(migration_db):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from sqlalchemy import event, update
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login, LoginStatus
    from app.models import User, AuthSession
    from app.security import hash_password
    engine,_=migration_db
    if engine.dialect.name!='postgresql': pytest.skip('PostgreSQL row locks required')
    factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    changed_hash=hash_password('a different long password'); waiting=Event()
    def observe(conn,cursor,statement,parameters,context,executemany):
        if 'FROM users' in statement and 'FOR UPDATE' in statement: waiting.set()
    def attempt():
        return login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1')
    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory.begin() as blocker:
            blocker.scalar(select(User).where(User.id==actor).with_for_update())
            event.listen(engine,'before_cursor_execute',observe)
            future=pool.submit(attempt)
            try:
                assert waiting.wait(10)
                blocker.execute(update(User).where(User.id==actor).values(password_hash=changed_hash))
            finally: event.remove(engine,'before_cursor_execute',observe)
        assert future.result(timeout=10).status==LoginStatus.DENIED
    with factory() as db: assert db.scalar(select(AuthSession.id).where(AuthSession.user_id==actor)) is None


def test_migrated_audit_user_filter_and_cursor_scope(migration_db):
    from datetime import datetime,timezone
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.accounts import create_user
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import SecurityAuditEvent
    from app.protected_api import protected_router
    from app.security import Role
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,foreign_actor=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    admin=login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    viewer_id=create_user(factory,admin_token=admin,username='viewer',password='a safe long password',role=Role.VIEWER)
    viewer=login(factory,secret=b'x'*32,tenant_id=tenant,username='viewer',password='a safe long password',source_ip='192.0.2.1').token
    with factory.begin() as db:
        now=datetime(2026,1,1,tzinfo=timezone.utc)
        db.add_all([SecurityAuditEvent(tenant_id=tenant,actor_id=actor,target_user_id=viewer_id,event_type='user_self_read',occurred_at=now) for _ in range(101)])
        outside=SecurityAuditEvent(tenant_id=tenant,actor_id=actor,target_user_id=actor,event_type='user_self_read',occurred_at=now)
        db.add(outside); db.flush(); outside_id=outside.id
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32)); h={'Authorization':'Bearer '+admin}
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        path='/api/v1/secure/audit'; filters={'user_id':str(viewer_id),'event_type':'user_self_read'}
        assert client.get(path,headers={'Authorization':'Bearer '+viewer},params=filters).status_code==403
        assert client.get(path,headers=h,params={'user_id':str(foreign_actor)}).json()['items']==[]
        assert client.get(path,headers=h,params={**filters,'before':str(outside_id)}).status_code==404
        first=client.get(path,headers=h,params=filters).json(); second=client.get(path,headers=h,params={**filters,'before':first['next_cursor']}).json()
        rows=first['items']+second['items']; assert len(rows)==101 and len({row['id'] for row in rows})==101 and second['next_cursor'] is None
        assert all(row['target_user_id']==str(viewer_id) and row['event_type']=='user_self_read' for row in rows)


def test_migrated_entity_search_is_literal_tenant_scoped_and_cursor_checked(migration_db):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.protected_api import protected_router
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,other_actor=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    with factory.begin() as db:
        rows=[Entity(tenant_id=tenant,created_by=actor,kind='indicator',title=f'Needle fixture {i}',source='manual') for i in range(101)]
        literal=Entity(tenant_id=tenant,created_by=actor,kind='asset',title='literal 10%_ / fixture',source='manual')
        foreign=Entity(tenant_id=other,created_by=other_actor,kind='indicator',title='needle foreign',source='manual')
        db.add_all(rows+[literal,foreign]); db.flush(); literal_id,foreign_id=literal.id,foreign.id
    token=login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        path='/api/v1/secure/entities'; h={'Authorization':'Bearer '+token}; filters={'q':'needle','kind':'indicator'}
        first=client.get(path,headers=h,params=filters).json(); second=client.get(path,headers=h,params={**filters,'after':first['next_cursor']}).json()
        rows=first['items']+second['items']; assert len(rows)==101 and len({r['id'] for r in rows})==101
        assert str(foreign_id) not in str(rows)
        assert client.get(path,headers=h,params={'q':'%_'}).json()['items'][0]['id']==str(literal_id)
        assert len(client.get(path,headers=h,params={'q':'%_'}).json()['items'])==1
        assert client.get(path,headers=h,params={'q':' / fixture'}).json()['items'][0]['id']==str(literal_id)
        assert client.get(path,headers=h,params={'q':'zz','after':first['next_cursor']}).status_code==404
        assert client.get(path,headers=h,params={'q':'  '}).status_code==422
        assert client.get(path,headers=h,params={'q':'a\nb'}).status_code==422
        assert client.get(path,headers=h,params={'q':'x'*101}).status_code==422


def test_migrated_investigation_search_is_literal_and_scope_checked(migration_db):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.login_service import login
    from app.models import Investigation
    from app.protected_api import protected_router
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,other_actor=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    with factory.begin() as db:
        cases=[Investigation(tenant_id=tenant,created_by=actor,title=f'Needle case {i}',description='fixture') for i in range(101)]
        literal=Investigation(tenant_id=tenant,created_by=actor,title='case %_ / fixture',description='fixture')
        foreign=Investigation(tenant_id=other,created_by=other_actor,title='needle foreign',description='fixture')
        db.add_all(cases+[literal,foreign]); db.flush(); literal_id,foreign_id=literal.id,foreign.id
    token=login(factory,secret=b'x'*32,tenant_id=tenant,username='admin',password='a safe long password',source_ip='192.0.2.1').token
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',client=('192.0.2.1',123)) as client:
        path='/api/v1/secure/investigations'; h={'Authorization':'Bearer '+token}; filters={'q':'needle','status':'open'}
        first=client.get(path,headers=h,params=filters).json(); second=client.get(path,headers=h,params={**filters,'after':first['next_cursor']}).json()
        rows=first['items']+second['items']; assert len(rows)==101 and len({r['id'] for r in rows})==101
        assert str(foreign_id) not in str(rows)
        assert [r['id'] for r in client.get(path,headers=h,params={'q':'%_'}).json()['items']]==[str(literal_id)]
        assert [r['id'] for r in client.get(path,headers=h,params={'q':' / fixture'}).json()['items']]==[str(literal_id)]
        assert client.get(path,headers=h,params={'q':'zz','after':first['next_cursor']}).status_code==404
        assert client.get(path,headers=h,params={'q':'  '}).status_code==422
        assert client.get(path,headers=h,params={'q':'a\nb'}).status_code==422
        assert client.get(path,headers=h,params={'q':'x'*101}).status_code==422


def nvd_fixture(*, collected=None, text='Synthetic NVD fixture'):
    import json
    from datetime import datetime, timezone
    from app.connectors.nvd_cve import parse_response
    cve = {'id': 'CVE-2099-0001', 'published': '2026-01-01T10:00:00.000',
           'lastModified': '2026-01-02T10:00:00.000', 'vulnStatus': 'Analyzed',
           'descriptions': [{'lang': 'en', 'value': text}]}
    return parse_response(json.dumps({'startIndex': 0, 'totalResults': 1,
        'vulnerabilities': [{'cve': cve}]}).encode(), cve_id=cve['id'],
        collected_at=collected or datetime(2026, 1, 2, tzinfo=timezone.utc))


def test_migrated_nvd_import_isolation_history_and_rollback(migration_db, monkeypatch):
    from dataclasses import replace
    from datetime import datetime, timezone
    from sqlalchemy.orm import sessionmaker
    from app.connectors.nvd_import import import_record
    from app.models import User, NvdCatalogRecord, ProvenanceEvent, SecurityAuditEvent
    from app.security import hash_password
    from app.sessions import issue_session
    engine, _ = migration_db
    factory = sessionmaker(engine, expire_on_commit=False)
    a, b = uuid4(), uuid4()
    with factory.begin() as db:
        db.add_all([Tenant(id=a, name='a'), Tenant(id=b, name='b')]); db.flush()
        for tenant, role in ((a, 'admin'), (a, 'viewer'), (b, 'admin')):
            db.add(User(tenant_id=tenant, username=role, role=role, active=True,
                        password_hash=hash_password('a secure password')))
    with factory.begin() as db:
        admin = issue_session(db, a, 'admin', 'a secure password')
        viewer = issue_session(db, a, 'viewer', 'a secure password')
        other = issue_session(db, b, 'admin', 'a secure password')
    record = nvd_fixture()
    created = import_record(factory, admin_token=admin, record=record)
    assert created['created'] and not created['changed']
    assert not import_record(factory, admin_token=admin, record=record)['created']
    assert import_record(factory, admin_token=other, record=record)['created']
    with pytest.raises(PermissionError): import_record(factory, admin_token=viewer, record=record)
    with pytest.raises(PermissionError): import_record(factory, admin_token='invalid', record=record)
    with pytest.raises(ValueError, match='attribution'):
        import_record(factory, admin_token=admin, record=replace(record, source_reference='https://evil.test/'))
    with pytest.raises(ValueError, match='Invalid observation'):
        import_record(factory, admin_token=admin, record=replace(record, status=''))
    with factory.begin() as db:
        rows = list(db.scalars(select(NvdCatalogRecord)))
        assert len(rows) == 2 and {r.tenant_id for r in rows} == {a, b}
        entity = db.get(Entity, created['entity_id'])
        assert entity.confidence is None and entity.verification_status == 'unverified'
        entity.title = 'Analyst title'
    newer = nvd_fixture(collected=datetime(2026, 1, 3, tzinfo=timezone.utc), text='Updated synthetic fixture')
    assert import_record(factory, admin_token=admin, record=newer)['changed']
    with pytest.raises(ValueError, match='Older or conflicting'):
        import_record(factory, admin_token=admin, record=record)
    with pytest.raises(ValueError, match='Older or conflicting'):
        import_record(factory, admin_token=admin, record=replace(newer, status='Different'))
    with factory() as db:
        row = db.scalar(select(NvdCatalogRecord).where(NvdCatalogRecord.tenant_id == a))
        assert db.get(Entity, row.entity_id).title == 'Analyst title'
        events = list(db.scalars(select(ProvenanceEvent).where(ProvenanceEvent.tenant_id == a)))
        assert len(events) == 2
        assert {e.details['observation']['descriptions'][0]['text'] for e in events} == {'Synthetic NVD fixture', 'Updated synthetic fixture'}
        audits = list(db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type == 'nvd_record_imported', SecurityAuditEvent.tenant_id == a)))
        assert len(audits) == 3 and all(e.target_entity_id == created['entity_id'] for e in audits)
    def fail(*args, **kwargs): raise RuntimeError('audit unavailable')
    monkeypatch.setattr('app.connectors.nvd_import.record_event', fail)
    future = nvd_fixture(collected=datetime(2026, 1, 4, tzinfo=timezone.utc), text='Must roll back')
    with pytest.raises(RuntimeError, match='audit unavailable'):
        import_record(factory, admin_token=admin, record=future)
    with factory() as db:
        row = db.scalar(select(NvdCatalogRecord).where(NvdCatalogRecord.tenant_id == a))
        assert row.details['descriptions'][0]['text'] == 'Updated synthetic fixture'
        assert len(list(db.scalars(select(ProvenanceEvent).where(ProvenanceEvent.tenant_id == a)))) == 2


def test_migrated_nvd_foreign_key_rejects_cross_tenant(migration_db):
    from datetime import datetime, timezone
    from app.models import NvdCatalogRecord
    engine, _ = migration_db
    a, b = uuid4(), uuid4()
    with Session(engine) as db:
        db.add_all([Tenant(id=a, name='a'), Tenant(id=b, name='b')]); db.flush()
        entity = Entity(tenant_id=b, kind='vulnerability', title='fixture', source='fixture')
        db.add(entity); db.flush()
        db.add(NvdCatalogRecord(tenant_id=a, entity_id=entity.id, cve_id='CVE-2099-0001',
            details={}, first_collected_at=datetime.now(timezone.utc), last_collected_at=datetime.now(timezone.utc)))
        with pytest.raises(IntegrityError): db.flush()
        db.rollback()


def test_postgres_concurrent_nvd_import_is_deduplicated(migration_db):
    from concurrent.futures import ThreadPoolExecutor
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.connectors.nvd_import import import_record
    from app.models import NvdCatalogRecord, ProvenanceEvent
    from app.sessions import issue_session
    engine, _ = migration_db
    if engine.dialect.name != 'postgresql': pytest.skip('PostgreSQL concurrency test')
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, _ = create_tenant_with_admin(factory, tenant_name='test', username='admin', password='a safe long password')
    with factory.begin() as db: token = issue_session(db, tenant, 'admin', 'a safe long password')
    record = nvd_fixture()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: import_record(factory, admin_token=token, record=record), range(2)))
    assert sorted(r['created'] for r in results) == [False, True]
    assert len({r['entity_id'] for r in results}) == 1
    with factory() as db:
        assert len(list(db.scalars(select(NvdCatalogRecord)))) == 1
        assert len(list(db.scalars(select(Entity)))) == 1
        assert len(list(db.scalars(select(ProvenanceEvent)))) == 1


def test_nvd_revision_rollback(tmp_path, monkeypatch):
    url = f'sqlite:///{tmp_path / "nvd-revision.db"}'
    monkeypatch.setenv('DATABASE_URL', url)
    config = Config(str(HERE / 'alembic.ini'))
    command.upgrade(config, '0030_audit_user_index')
    engine = create_engine(url)
    assert 'nvd_catalog_records' not in inspect(engine).get_table_names()
    command.upgrade(config, 'head')
    assert 'nvd_catalog_records' in inspect(engine).get_table_names()
    command.downgrade(config, '0030_audit_user_index')
    assert 'nvd_catalog_records' not in inspect(engine).get_table_names()
    command.downgrade(config, 'base')
    engine.dispose()


def test_migrated_nvd_read_scoped_authorized_and_atomic(migration_db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import accounts, protected_api
    from app.bootstrap import create_tenant_with_admin
    from app.connectors.nvd_import import import_record
    from app.models import SecurityAuditEvent
    from app.protected_api import protected_router
    from app.security import Role
    from app.sessions import issue_session
    engine, _ = migration_db
    factory = sessionmaker(engine, expire_on_commit=False)
    a, _ = create_tenant_with_admin(factory, tenant_name='a', username='admin', password='a safe long password')
    b, _ = create_tenant_with_admin(factory, tenant_name='b', username='admin', password='a safe long password')
    with factory.begin() as db:
        admin = issue_session(db, a, 'admin', 'a safe long password')
        other = issue_session(db, b, 'admin', 'a safe long password')
    accounts.create_user(factory, admin_token=admin, username='viewer', password='a safe long password', role=Role.VIEWER)
    with factory.begin() as db: viewer = issue_session(db, a, 'viewer', 'a safe long password')
    imported = import_record(factory, admin_token=admin, record=nvd_fixture())
    app = FastAPI(); app.include_router(protected_router(factory, b'x'*32))
    headers = lambda t: {'Authorization':'Bearer '+t}
    path = '/api/v1/secure/sources/nvd/cves/CVE-2099-0001'
    with TestClient(app, base_url='https://testserver', raise_server_exceptions=False) as client:
        assert client.get(path).status_code == 401
        assert client.get(path, headers=headers(other)).status_code == 404
        assert client.get('/api/v1/secure/sources/nvd/cves/not-a-cve', headers=headers(viewer)).status_code == 422
        assert client.get('/api/v1/secure/sources/nvd/cves/CVE-2099-0002', headers=headers(viewer)).status_code == 404
        def fail(*args, **kwargs): raise RuntimeError('audit unavailable')
        with monkeypatch.context() as patch:
            patch.setattr(protected_api, 'record_event', fail)
            assert client.get(path, headers=headers(viewer)).status_code == 500
        response = client.get(path, headers=headers(viewer))
        assert response.status_code == 200 and response.headers['cache-control'] == 'no-store'
        body = response.json()
        assert body['entity_id'] == str(imported['entity_id']) and body['verification_status'] == 'unverified'
        assert body['observation']['descriptions'][0]['text'] == 'Synthetic NVD fixture'
        assert body['first_collected_at'] == '2026-01-02T00:00:00+00:00'
        assert body['last_collected_at'] == '2026-01-02T00:00:00+00:00'
        assert 'not independently verified' in body['notice']
        audit = client.get('/api/v1/secure/audit', headers=headers(admin), params={'event_type':'nvd_record_read', 'entity_id':str(imported['entity_id'])})
        assert len(audit.json()['items']) == 1
    with factory() as db:
        events = list(db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type == 'nvd_record_read')))
        assert len(events) == 1 and events[0].tenant_id == a and events[0].target_entity_id == imported['entity_id']


def test_nvd_sync_migrated_success_missing_failure_and_recovery(migration_db, monkeypatch):
    from uuid import UUID
    from sqlalchemy.orm import sessionmaker
    from app import accounts
    from app.bootstrap import create_tenant_with_admin
    from app.connectors.nvd_cve import NvdError
    from app.connectors import nvd_sync, nvd_import
    from app.models import NvdCatalogRecord, NvdSyncAttempt, SecurityAuditEvent
    from app.security import Role
    from app.sessions import issue_session
    engine, _ = migration_db
    factory = sessionmaker(engine, expire_on_commit=False)
    a, _ = create_tenant_with_admin(factory, tenant_name='a', username='admin', password='a safe long password')
    b, _ = create_tenant_with_admin(factory, tenant_name='b', username='admin', password='a safe long password')
    with factory.begin() as db:
        admin = issue_session(db, a, 'admin', 'a safe long password')
        other = issue_session(db, b, 'admin', 'a safe long password')
    accounts.create_user(factory, admin_token=admin, username='viewer', password='a safe long password', role=Role.VIEWER)
    with factory.begin() as db: viewer = issue_session(db, a, 'viewer', 'a safe long password')
    called = []
    def fetch(cve_id): called.append(cve_id); return nvd_fixture()
    with pytest.raises(PermissionError): nvd_sync.synchronize(factory, admin_token=viewer, cve_id='CVE-2099-0001', fetch=fetch)
    with pytest.raises(ValueError): nvd_sync.begin_sync(factory, admin_token=admin, cve_id='invalid')
    assert not called
    assert nvd_sync.get_status(factory, admin_token=admin)['last_attempt'] is None
    result = nvd_sync.synchronize(factory, admin_token=admin, cve_id='CVE-2099-0001', fetch=fetch)
    assert result['status'] == 'succeeded' and result['created'] and called == ['CVE-2099-0001']
    with factory() as db:
        attempt = db.get(NvdSyncAttempt, UUID(result['attempt_id']))
        assert attempt.status == 'succeeded' and attempt.finished_at is not None
        assert db.scalar(select(NvdCatalogRecord).where(NvdCatalogRecord.tenant_id == a)) is not None
    missing = nvd_sync.synchronize(factory, admin_token=admin, cve_id='CVE-2099-0002', fetch=lambda _: None)
    assert missing['status'] == 'not_found'
    with factory() as db:
        assert db.scalar(select(NvdCatalogRecord).where(NvdCatalogRecord.tenant_id == a)) is not None
    def bad_fetch(_): raise NvdError('secret upstream text')
    failed = nvd_sync.synchronize(factory, admin_token=admin, cve_id='CVE-2099-0002', fetch=bad_fetch)
    assert failed['status'] == 'failed' and failed['error_code'] == 'fetch_failed'
    assert 'secret' not in str(nvd_sync.get_status(factory, admin_token=admin))
    running = nvd_sync.begin_sync(factory, admin_token=admin, cve_id='CVE-2099-0001')
    with pytest.raises(nvd_sync.SyncBusy): nvd_sync.begin_sync(factory, admin_token=admin, cve_id='CVE-2099-0002')
    assert not nvd_sync.abandon_sync(factory, admin_token=other, attempt_id=running)
    with pytest.raises(PermissionError): nvd_sync.abandon_sync(factory, admin_token=viewer, attempt_id=running)
    assert nvd_sync.abandon_sync(factory, admin_token=admin, attempt_id=running)
    assert not nvd_sync.abandon_sync(factory, admin_token=admin, attempt_id=running)
    with pytest.raises(ValueError, match='not active'):
        nvd_import.import_record(factory, admin_token=admin, record=nvd_fixture(), attempt_id=running)
    assert not nvd_sync._fail(factory, running, a, db_actor(factory, a), 'fetch_failed')
    assert not nvd_sync._not_found(factory, admin_token=admin, attempt_id=running)
    with factory() as db:
        events = list(db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.tenant_id == a)))
        kinds = {e.event_type for e in events}
        assert {'nvd_sync_started', 'nvd_sync_succeeded', 'nvd_sync_not_found', 'nvd_sync_failed', 'nvd_sync_abandoned', 'nvd_status_read'} <= kinds


def db_actor(factory, tenant):
    from app.models import User
    with factory() as db:
        return db.scalar(select(User.id).where(User.tenant_id == tenant, User.username == 'admin'))


def test_nvd_sync_rolls_back_completion_and_rejects_wrong_cve(migration_db, monkeypatch):
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.connectors import nvd_sync, nvd_import
    from app.models import NvdSyncAttempt, NvdCatalogRecord, ProvenanceEvent
    from app.sessions import issue_session
    engine, _ = migration_db
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, _ = create_tenant_with_admin(factory, tenant_name='a', username='admin', password='a safe long password')
    with factory.begin() as db: token = issue_session(db, tenant, 'admin', 'a safe long password')
    attempt = nvd_sync.begin_sync(factory, admin_token=token, cve_id='CVE-2099-0002')
    with pytest.raises(ValueError, match='not active'):
        nvd_import.import_record(factory, admin_token=token, record=nvd_fixture(), attempt_id=attempt)
    nvd_sync.abandon_sync(factory, admin_token=token, attempt_id=attempt)
    def fail(*args, **kwargs): raise RuntimeError('audit unavailable')
    # Import+success audit must roll back all data, then coordinator marks failure.
    with monkeypatch.context() as patch:
        patch.setattr(nvd_import, 'record_event', fail)
        with pytest.raises(RuntimeError, match='audit unavailable'):
            nvd_sync.synchronize(factory, admin_token=token, cve_id='CVE-2099-0001', fetch=lambda _:nvd_fixture())
    with factory() as db:
        assert db.scalar(select(NvdCatalogRecord)) is None
        assert db.scalar(select(ProvenanceEvent)) is None
        failed = db.scalar(select(NvdSyncAttempt).where(NvdSyncAttempt.status == 'failed'))
        assert failed.error_code == 'import_failed'


def test_postgres_nvd_concurrent_starts_serialized(migration_db):
    from concurrent.futures import ThreadPoolExecutor
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.connectors import nvd_sync
    from app.sessions import issue_session
    engine, _ = migration_db
    if engine.dialect.name != 'postgresql': pytest.skip('PostgreSQL concurrency test')
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, _ = create_tenant_with_admin(factory, tenant_name='a', username='admin', password='a safe long password')
    with factory.begin() as db: token = issue_session(db, tenant, 'admin', 'a safe long password')
    def start(_):
        try:
            nvd_sync.begin_sync(factory, admin_token=token, cve_id='CVE-2099-0001')
            return 'started'
        except nvd_sync.SyncBusy: return 'busy'
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(start, range(2))) == ['busy', 'started']


@pytest.mark.parametrize('outcome', ['found', 'missing', 'fetch_error'])
def test_nvd_sync_abandoned_during_fetch_never_completes(migration_db, outcome):
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.connectors import nvd_sync
    from app.connectors.nvd_cve import NvdError
    from app.models import NvdSyncAttempt, NvdCatalogRecord
    from app.sessions import issue_session
    engine, _ = migration_db
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, _ = create_tenant_with_admin(factory, tenant_name='a', username='admin', password='a safe long password')
    with factory.begin() as db: token = issue_session(db, tenant, 'admin', 'a safe long password')
    def fetch(_):
        with factory() as db:
            attempt_id = db.scalar(select(NvdSyncAttempt.id).where(NvdSyncAttempt.tenant_id == tenant, NvdSyncAttempt.status == 'running'))
        assert nvd_sync.abandon_sync(factory, admin_token=token, attempt_id=attempt_id)
        if outcome == 'fetch_error': raise NvdError('synthetic')
        return nvd_fixture() if outcome == 'found' else None
    if outcome == 'found':
        with pytest.raises(ValueError, match='not active'):
            nvd_sync.synchronize(factory, admin_token=token, cve_id='CVE-2099-0001', fetch=fetch)
    else:
        assert nvd_sync.synchronize(factory, admin_token=token, cve_id='CVE-2099-0001', fetch=fetch)['status'] == 'inactive'
    with factory() as db:
        assert db.scalar(select(NvdSyncAttempt.status)) == 'abandoned'
        assert db.scalar(select(NvdCatalogRecord)) is None


def test_nvd_running_attempt_unique_constraint(migration_db):
    from datetime import datetime, timezone
    from app.models import NvdSyncAttempt, User
    engine, _ = migration_db
    tenant, actor = uuid4(), uuid4()
    with Session(engine) as db:
        db.add(Tenant(id=tenant, name='fixture')); db.flush()
        db.add(User(id=actor, tenant_id=tenant, username='admin', role='admin', active=True, password_hash='invalid-fixture')); db.flush()
        for _ in range(2):
            db.add(NvdSyncAttempt(tenant_id=tenant, actor_id=actor, cve_id='CVE-2099-0001', status='running', started_at=datetime.now(timezone.utc)))
        with pytest.raises(IntegrityError): db.flush()
        db.rollback()


def test_nvd_status_and_abandon_api_scope_auth_and_audit_rollback(migration_db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import accounts
    from app.bootstrap import create_tenant_with_admin
    from app.connectors import nvd_sync
    from app.models import NvdSyncAttempt, SecurityAuditEvent
    from app.protected_api import protected_router
    from app.security import Role
    from app.sessions import issue_session
    engine, _ = migration_db
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, _ = create_tenant_with_admin(factory, tenant_name='a', username='admin', password='a safe long password')
    foreign, _ = create_tenant_with_admin(factory, tenant_name='b', username='admin', password='a safe long password')
    with factory.begin() as db:
        admin = issue_session(db, tenant, 'admin', 'a safe long password')
        other = issue_session(db, foreign, 'admin', 'a safe long password')
    accounts.create_user(factory, admin_token=admin, username='viewer', password='a safe long password', role=Role.VIEWER)
    with factory.begin() as db: viewer = issue_session(db, tenant, 'viewer', 'a safe long password')
    attempt = nvd_sync.begin_sync(factory, admin_token=admin, cve_id='CVE-2099-0001')
    app = FastAPI(); app.include_router(protected_router(factory, b'x'*32))
    headers = lambda t: {'Authorization':'Bearer '+t}
    status_path='/api/v1/secure/sources/nvd/status'
    abandon_path=f'/api/v1/secure/sources/nvd/attempts/{attempt}/abandon'
    with TestClient(app, base_url='https://testserver', raise_server_exceptions=False) as client:
        assert client.get(status_path).status_code == 401
        assert client.get(status_path,headers=headers(viewer)).status_code == 403
        assert client.get(status_path,headers=headers(other)).json()['last_attempt'] is None
        assert client.post(abandon_path,headers=headers(other)).status_code == 404
        assert client.post(abandon_path,headers=headers(viewer)).status_code == 403
        def fail(*args, **kwargs): raise RuntimeError('audit unavailable')
        with monkeypatch.context() as patch:
            patch.setattr(nvd_sync, 'record_event', fail)
            assert client.get(status_path,headers=headers(admin)).status_code == 500
            assert client.post(abandon_path,headers=headers(admin)).status_code == 500
        with factory() as db: assert db.get(NvdSyncAttempt,attempt).status == 'running'
        result=client.get(status_path,headers=headers(admin))
        assert result.status_code == 200 and result.headers['cache-control'] == 'no-store'
        assert result.json()['integration'] == 'experimental_not_live_verified'
        assert result.json()['last_attempt']['id'] == str(attempt)
        assert result.json()['last_attempt']['started_at'].endswith('+00:00')
        response=client.post(abandon_path,headers=headers(admin))
        assert response.status_code == 200 and response.headers['cache-control'] == 'no-store'
        assert client.post(abandon_path,headers=headers(admin)).status_code == 404
        assert client.get(status_path,headers=headers(admin)).json()['last_attempt']['status'] == 'abandoned'
    with factory() as db:
        audits=list(db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.tenant_id==tenant)))
        assert sum(x.event_type=='nvd_sync_abandoned' for x in audits) == 1
        assert sum(x.event_type=='nvd_status_read' for x in audits) == 2


def test_postgres_nvd_cli_synthetic_fetch_and_admin_preflight(migration_db, monkeypatch, capsys):
    from sqlalchemy.orm import sessionmaker
    from app import accounts
    from app.bootstrap import create_tenant_with_admin
    from app.connectors import nvd_cli, nvd_sync
    from app.security import Role
    from app.sessions import issue_session
    engine, _ = migration_db
    if engine.dialect.name != 'postgresql': pytest.skip('CLI requires PostgreSQL')
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, _ = create_tenant_with_admin(factory, tenant_name='a', username='admin', password='a safe long password')
    with factory.begin() as db: admin = issue_session(db, tenant, 'admin', 'a safe long password')
    accounts.create_user(factory, admin_token=admin, username='viewer', password='a safe long password', role=Role.VIEWER)
    with factory.begin() as db: viewer = issue_session(db, tenant, 'viewer', 'a safe long password')
    monkeypatch.setattr(nvd_cli.sys.stdin, 'isatty', lambda: True)
    monkeypatch.setattr(nvd_cli.sys.stderr, 'isatty', lambda: True)
    calls=[]
    def sync(factory, *, admin_token, cve_id):
        return nvd_sync.synchronize(factory, admin_token=admin_token, cve_id=cve_id,
            fetch=lambda cve: (calls.append(cve), nvd_fixture())[1])
    with monkeypatch.context() as patch:
        patch.setattr(nvd_cli, 'create_engine', lambda *a, **k: engine)
        patch.setattr(engine, 'dispose', lambda: None)
        patch.setattr(nvd_cli, 'synchronize', sync)
        patch.setattr(nvd_cli.getpass, 'getpass', lambda _: viewer)
        assert nvd_cli.main(['CVE-2099-0001','--confirm-live-fetch']) == 1
        assert calls == []
        patch.setattr(nvd_cli.getpass, 'getpass', lambda _: admin)
        assert nvd_cli.main(['CVE-2099-0001','--confirm-live-fetch']) == 0
        output=capsys.readouterr()
        assert admin not in output.out+output.err and viewer not in output.out+output.err
        assert 'unverified' in output.out and calls == ['CVE-2099-0001']


@pytest.mark.parametrize('change', ['demote', 'disable', 'revoke'])
@pytest.mark.parametrize('outcome', ['found', 'missing'])
def test_postgres_nvd_sync_rechecks_authorization_after_fetch(migration_db, change, outcome):
    from concurrent.futures import ThreadPoolExecutor
    from datetime import datetime, timezone
    from threading import Event
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.connectors import nvd_sync
    from app.models import User, AuthSession, NvdCatalogRecord, NvdSyncAttempt, SecurityAuditEvent
    from app.sessions import issue_session, _digest
    engine, _ = migration_db
    if engine.dialect.name != 'postgresql': pytest.skip('PostgreSQL row locks required')
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, actor = create_tenant_with_admin(factory, tenant_name='a', username='admin', password='a safe long password')
    with factory.begin() as db: token = issue_session(db, tenant, 'admin', 'a safe long password')
    fetch_started, allow_fetch, lock_waiting = Event(), Event(), Event()
    def fetch(_):
        fetch_started.set()
        assert allow_fetch.wait(10)
        return nvd_fixture() if outcome == 'found' else None
    def observe(conn, cursor, statement, parameters, context, executemany):
        if 'FROM users' in statement and 'FOR UPDATE' in statement:
            lock_waiting.set()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(nvd_sync.synchronize, factory, admin_token=token, cve_id='CVE-2099-0001', fetch=fetch)
        try:
            assert fetch_started.wait(10)
            with factory.begin() as blocker:
                user = blocker.scalar(select(User).where(User.id == actor).with_for_update())
                if change == 'demote': user.role = 'viewer'
                elif change == 'disable': user.active = False
                else:
                    session = blocker.scalar(select(AuthSession).where(AuthSession.token_digest == _digest(token)).with_for_update())
                    session.revoked_at = datetime.now(timezone.utc)
                blocker.flush()
                event.listen(engine, 'before_cursor_execute', observe)
                try:
                    allow_fetch.set()
                    assert lock_waiting.wait(10)
                finally:
                    event.remove(engine, 'before_cursor_execute', observe)
            with pytest.raises(PermissionError): future.result(timeout=10)
        finally:
            allow_fetch.set()
    with factory() as db:
        assert db.scalar(select(NvdCatalogRecord)) is None
        attempt = db.scalar(select(NvdSyncAttempt).where(NvdSyncAttempt.tenant_id == tenant))
        assert attempt.status == 'failed' and attempt.error_code == 'import_failed'
        kinds = list(db.scalars(select(SecurityAuditEvent.event_type).where(SecurityAuditEvent.tenant_id == tenant)))
        assert 'nvd_sync_succeeded' not in kinds and 'nvd_sync_not_found' not in kinds


def test_nvd_attempt_list_scoped_filters_pagination_and_audit(migration_db, monkeypatch):
    from datetime import datetime, timezone
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import accounts, protected_api
    from app.bootstrap import create_tenant_with_admin
    from app.models import NvdSyncAttempt, SecurityAuditEvent
    from app.protected_api import protected_router
    from app.security import Role
    from app.sessions import issue_session
    engine, _ = migration_db
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, actor = create_tenant_with_admin(factory, tenant_name='a', username='admin', password='a safe long password')
    other, other_actor = create_tenant_with_admin(factory, tenant_name='b', username='admin', password='a safe long password')
    with factory.begin() as db:
        token = issue_session(db, tenant, 'admin', 'a safe long password')
    accounts.create_user(factory, admin_token=token, username='viewer', password='a safe long password', role=Role.VIEWER)
    with factory.begin() as db:
        viewer = issue_session(db, tenant, 'viewer', 'a safe long password')
        now = datetime(2026,1,1,tzinfo=timezone.utc)
        rows = [NvdSyncAttempt(tenant_id=tenant, actor_id=actor, cve_id='CVE-2099-0001', status='failed', started_at=now, finished_at=now, error_code='fetch_failed') for _ in range(101)]
        foreign = NvdSyncAttempt(tenant_id=other, actor_id=other_actor, cve_id='CVE-2099-0001', status='failed', started_at=now)
        mismatch = NvdSyncAttempt(tenant_id=tenant, actor_id=actor, cve_id='CVE-2099-0002', status='succeeded', started_at=now)
        db.add_all([*rows,foreign,mismatch]); db.flush(); foreign_id, mismatch_id = foreign.id, mismatch.id
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    headers=lambda t:{'Authorization':'Bearer '+t}
    path='/api/v1/secure/sources/nvd/attempts'
    with TestClient(app,base_url='https://testserver',raise_server_exceptions=False) as client:
        assert client.get(path).status_code==401
        assert client.get(path,headers=headers(viewer)).status_code==403
        assert client.get(path,headers=headers(token),params={'status':'invalid'}).status_code==422
        assert client.get(path,headers=headers(token),params={'cve_id':'invalid'}).status_code==422
        filters={'status':'failed','cve_id':'CVE-2099-0001'}
        assert client.get(path,headers=headers(token),params={**filters,'before':str(foreign_id)}).status_code==404
        assert client.get(path,headers=headers(token),params={**filters,'before':str(mismatch_id)}).status_code==404
        def fail(*args, **kwargs): raise RuntimeError('audit unavailable')
        with monkeypatch.context() as patch:
            patch.setattr(protected_api,'record_event',fail)
            assert client.get(path,headers=headers(token),params=filters).status_code==500
        first=client.get(path,headers=headers(token),params=filters)
        assert first.status_code==200 and first.headers['cache-control']=='no-store'
        second=client.get(path,headers=headers(token),params={**filters,'before':first.json()['next_cursor']})
        results=first.json()['items']+second.json()['items']
        assert len(results)==101 and len({item['id'] for item in results})==101 and second.json()['next_cursor'] is None
        assert all(item['status']=='failed' and item['cve_id']=='CVE-2099-0001' and item['started_at'].endswith('+00:00') for item in results)
    with factory() as db:
        assert len(list(db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.tenant_id==tenant,SecurityAuditEvent.event_type=='nvd_attempts_read'))))==2


def test_cisa_attempt_history_scoped_filters_pagination_and_audit(migration_db, monkeypatch):
    from datetime import datetime, timezone
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import accounts, protected_api
    from app.bootstrap import create_tenant_with_admin
    from app.models import CisaSyncAttempt, SecurityAuditEvent
    from app.protected_api import protected_router
    from app.security import Role
    from app.sessions import issue_session
    engine, _ = migration_db
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant, actor = create_tenant_with_admin(factory, tenant_name='a', username='admin', password='a safe long password')
    other, other_actor = create_tenant_with_admin(factory, tenant_name='b', username='admin', password='a safe long password')
    with factory.begin() as db: token = issue_session(db, tenant, 'admin', 'a safe long password')
    accounts.create_user(factory, admin_token=token, username='viewer', password='a safe long password', role=Role.VIEWER)
    with factory.begin() as db:
        viewer = issue_session(db, tenant, 'viewer', 'a safe long password')
        now = datetime(2026,1,1,tzinfo=timezone.utc)
        rows=[CisaSyncAttempt(tenant_id=tenant,actor_id=actor,status='failed',started_at=now,finished_at=now,error_code='fetch_failed') for _ in range(101)]
        foreign=CisaSyncAttempt(tenant_id=other,actor_id=other_actor,status='failed',started_at=now)
        mismatch=CisaSyncAttempt(tenant_id=tenant,actor_id=actor,status='succeeded',started_at=now)
        db.add_all([*rows,foreign,mismatch]); db.flush(); foreign_id,mismatch_id=foreign.id,mismatch.id
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    headers=lambda t:{'Authorization':'Bearer '+t}
    path='/api/v1/secure/sources/cisa-kev/attempts'
    with TestClient(app,base_url='https://testserver',raise_server_exceptions=False) as client:
        assert client.get(path).status_code==401
        assert client.get(path,headers=headers(viewer)).status_code==403
        assert client.get(path,headers=headers(token),params={'status':'invalid'}).status_code==422
        filters={'status':'failed'}
        assert client.get(path,headers=headers(token),params={**filters,'before':str(foreign_id)}).status_code==404
        assert client.get(path,headers=headers(token),params={**filters,'before':str(mismatch_id)}).status_code==404
        def fail(*args, **kwargs): raise RuntimeError('audit unavailable')
        with monkeypatch.context() as patch:
            patch.setattr(protected_api,'record_event',fail)
            assert client.get(path,headers=headers(token),params=filters).status_code==500
        first=client.get(path,headers=headers(token),params=filters)
        assert first.status_code==200 and first.headers['cache-control']=='no-store'
        second=client.get(path,headers=headers(token),params={**filters,'before':first.json()['next_cursor']})
        results=first.json()['items']+second.json()['items']
        assert len(results)==101 and len({item['id'] for item in results})==101 and second.json()['next_cursor'] is None
        assert all(item['status']=='failed' and item['started_at'].endswith('+00:00') for item in results)
    with factory() as db:
        assert len(list(db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.tenant_id==tenant,SecurityAuditEvent.event_type=='cisa_attempts_read'))))==2


def test_investigation_report_scoped_bounded_and_audited(migration_db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import accounts, protected_api
    from app.bootstrap import create_tenant_with_admin
    from app.models import Investigation, InvestigationEntityLink, InvestigationEvidenceLink, InvestigationNote, EvidenceReference, SecurityAuditEvent
    from app.protected_api import protected_router
    from app.security import Role
    from app.sessions import issue_session
    engine, _ = migration_db
    factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,other_actor=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    with factory.begin() as db:
        admin=issue_session(db,tenant,'admin','a safe long password')
        foreign=issue_session(db,other,'admin','a safe long password')
    accounts.create_user(factory,admin_token=admin,username='viewer',password='a safe long password',role=Role.VIEWER)
    with factory.begin() as db:
        viewer=issue_session(db,tenant,'viewer','a safe long password')
        case=Investigation(tenant_id=tenant,created_by=actor,title='synthetic case',description='fixture'); db.add(case); db.flush()
        entity=Entity(tenant_id=tenant,created_by=actor,kind='indicator',title='synthetic entity',source='fixture'); db.add(entity); db.flush()
        link=InvestigationEntityLink(tenant_id=tenant,investigation_id=case.id,entity_id=entity.id,created_by=actor); db.add(link); db.flush()
        evidence=EvidenceReference(tenant_id=tenant,entity_id=entity.id,created_by=actor,description='synthetic reference',source='fixture',sha256='0'*64); db.add(evidence); db.flush()
        db.add(InvestigationEvidenceLink(tenant_id=tenant,investigation_id=case.id,entity_id=entity.id,evidence_id=evidence.id,created_by=actor))
        db.add_all([InvestigationNote(tenant_id=tenant,investigation_id=case.id,author_id=actor,body=f'synthetic note {i}') for i in range(51)])
        foreign_case=Investigation(tenant_id=other,created_by=other_actor,title='private',description='private'); db.add(foreign_case); db.flush()
        case_id, foreign_id, evidence_id = case.id, foreign_case.id, evidence.id
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    headers=lambda t:{'Authorization':'Bearer '+t}
    path=f'/api/v1/secure/investigations/{case_id}/report'
    with TestClient(app,base_url='https://testserver',raise_server_exceptions=False) as client:
        assert client.get(path).status_code==401
        assert client.get(path,headers=headers(foreign)).status_code==404
        assert client.get(f'/api/v1/secure/investigations/{foreign_id}/report',headers=headers(viewer)).status_code==404
        def fail(*args,**kwargs): raise RuntimeError('audit unavailable')
        with monkeypatch.context() as patch:
            patch.setattr(protected_api,'record_event',fail)
            assert client.get(path,headers=headers(viewer)).status_code==500
        response=client.get(path,headers=headers(viewer))
        assert response.status_code==200 and response.headers['cache-control']=='no-store'
        report=response.json()
        assert report['investigation']['title']=='synthetic case'
        assert report['entities']['items'][0]['association_status']=='analyst_association_unverified'
        assert report['evidence']['items'][0]['evidence_id']==str(evidence_id)
        assert report['evidence']['items'][0]['status']=='analyst_entered_unverified'
        assert len(report['notes']['items'])==50 and report['notes']['truncated']
        assert not report['entities']['truncated'] and not report['evidence']['truncated']
        assert 'not a consistent snapshot' in report['notice'] and 'hashes are not verified' in report['notice']
    with factory() as db:
        events=list(db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type=='investigation_report_read')))
        assert len(events)==1 and events[0].tenant_id==tenant and events[0].target_investigation_id==case_id


def test_investigation_report_truncates_entity_and_evidence_sections(migration_db):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.models import Investigation, InvestigationEntityLink, InvestigationEvidenceLink, EvidenceReference
    from app.protected_api import protected_router
    from app.sessions import issue_session
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    with factory.begin() as db:
        token=issue_session(db,tenant,'admin','a safe long password')
        case=Investigation(tenant_id=tenant,created_by=actor,title='synthetic case',description='fixture'); db.add(case); db.flush()
        for i in range(51):
            entity=Entity(tenant_id=tenant,created_by=actor,kind='indicator',title=f'synthetic {i}',source='fixture')
            db.add(entity); db.flush()
            db.add(InvestigationEntityLink(tenant_id=tenant,investigation_id=case.id,entity_id=entity.id,created_by=actor)); db.flush()
            evidence=EvidenceReference(tenant_id=tenant,entity_id=entity.id,created_by=actor,description=f'fixture {i}',source='fixture',sha256='0'*64)
            db.add(evidence); db.flush()
            db.add(InvestigationEvidenceLink(tenant_id=tenant,investigation_id=case.id,entity_id=entity.id,evidence_id=evidence.id,created_by=actor))
        case_id=case.id
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver') as client:
        response=client.get(f'/api/v1/secure/investigations/{case_id}/report',headers={'Authorization':'Bearer '+token})
        assert response.status_code == 200
        result=response.json()
        assert len(result['entities']['items'])==50 and result['entities']['truncated']
        assert len(result['evidence']['items'])==50 and result['evidence']['truncated']
        assert all(item['status']=='analyst_entered_unverified' and item['sha256']=='0'*64 for item in result['evidence']['items'])
        assert not result['notes']['truncated'] and result['notes']['items']==[]


def test_investigation_event_detail_scope_and_case_audit(migration_db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import accounts, protected_api
    from app.bootstrap import create_tenant_with_admin
    from app.models import Investigation, InvestigationEvent, SecurityAuditEvent
    from app.protected_api import protected_router
    from app.security import Role
    from app.sessions import issue_session
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,other_actor=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    with factory.begin() as db:
        admin=issue_session(db,tenant,'admin','a safe long password')
        foreign=issue_session(db,other,'admin','a safe long password')
    accounts.create_user(factory,admin_token=admin,username='viewer',password='a safe long password',role=Role.VIEWER)
    with factory.begin() as db:
        viewer=issue_session(db,tenant,'viewer','a safe long password')
        one=Investigation(tenant_id=tenant,created_by=actor,title='fixture 1',description='fixture')
        two=Investigation(tenant_id=tenant,created_by=actor,title='fixture 2',description='fixture')
        outsider=Investigation(tenant_id=other,created_by=other_actor,title='foreign',description='fixture')
        db.add_all([one,two,outsider]); db.flush()
        event=InvestigationEvent(tenant_id=tenant,investigation_id=one.id,actor_id=actor,event_type='fixture',details={'synthetic':True})
        other_event=InvestigationEvent(tenant_id=other,investigation_id=outsider.id,actor_id=other_actor,event_type='fixture',details={'synthetic':True})
        db.add_all([event,other_event]); db.flush(); c1,c2,eid,foreign_eid=one.id,two.id,event.id,other_event.id
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    headers=lambda t:{'Authorization':'Bearer '+t}
    path=f'/api/v1/secure/investigations/{c1}/events/{eid}'
    with TestClient(app,base_url='https://testserver',raise_server_exceptions=False) as client:
        assert client.get(path).status_code==401
        assert client.get(path,headers=headers(foreign)).status_code==404
        assert client.get(f'/api/v1/secure/investigations/{c2}/events/{eid}',headers=headers(viewer)).status_code==404
        assert client.get(f'/api/v1/secure/investigations/{c1}/events/{foreign_eid}',headers=headers(viewer)).status_code==404
        def fail(*args,**kwargs): raise RuntimeError('audit unavailable')
        with monkeypatch.context() as patch:
            patch.setattr(protected_api,'record_event',fail)
            assert client.get(path,headers=headers(viewer)).status_code==500
        response=client.get(path,headers=headers(viewer))
        assert response.status_code==200 and response.headers['cache-control']=='no-store'
        assert response.json()['details']=={'synthetic':True} and 'not tamper-resistant' in response.json()['notice']
        audit=client.get('/api/v1/secure/audit',headers=headers(admin),params={'investigation_event_id':str(eid)})
        assert audit.status_code==200 and len(audit.json()['items'])==1
        assert audit.json()['items'][0]['target_investigation_event_id']==str(eid)
        assert client.get('/api/v1/secure/audit',headers=headers(admin),params={'investigation_event_id':str(foreign_eid)}).json()['items']==[]
    with factory() as db:
        events=list(db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type=='investigation_event_read')))
        assert len(events)==1 and events[0].tenant_id==tenant and events[0].target_investigation_id==c1 and events[0].target_investigation_event_id==eid


def test_investigation_event_audit_target_constraints(migration_db):
    from app.models import Investigation, InvestigationEvent, SecurityAuditEvent, User
    engine,_=migration_db
    a,b,actor_a,actor_b=uuid4(),uuid4(),uuid4(),uuid4()
    with Session(engine) as db:
        db.add_all([Tenant(id=a,name='a'),Tenant(id=b,name='b')]); db.flush()
        db.add_all([User(id=actor_a,tenant_id=a,username='a',role='admin',active=True,password_hash='fixture'),
                    User(id=actor_b,tenant_id=b,username='b',role='admin',active=True,password_hash='fixture')]); db.flush()
        c1=Investigation(tenant_id=a,created_by=actor_a,title='a1',description='fixture')
        c2=Investigation(tenant_id=a,created_by=actor_a,title='a2',description='fixture')
        c3=Investigation(tenant_id=b,created_by=actor_b,title='b',description='fixture')
        db.add_all([c1,c2,c3]); db.flush()
        e1=InvestigationEvent(tenant_id=a,investigation_id=c1.id,actor_id=actor_a,event_type='fixture',details={})
        e2=InvestigationEvent(tenant_id=b,investigation_id=c3.id,actor_id=actor_b,event_type='fixture',details={})
        db.add_all([e1,e2]); db.commit()
        for kwargs in (dict(target_investigation_event_id=e1.id),
                       dict(target_investigation_id=c2.id,target_investigation_event_id=e1.id),
                       dict(target_investigation_id=c1.id,target_investigation_event_id=e2.id)):
            db.add(SecurityAuditEvent(tenant_id=a,actor_id=actor_a,event_type='fixture',**kwargs))
            with pytest.raises(IntegrityError): db.flush()
            db.rollback()


def test_investigation_event_audit_filter_cursor_scope(migration_db):
    from datetime import datetime, timezone
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.models import Investigation, InvestigationEvent, SecurityAuditEvent
    from app.protected_api import protected_router
    from app.sessions import issue_session
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,other_actor=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    with factory.begin() as db:
        token=issue_session(db,tenant,'admin','a safe long password')
        c1=Investigation(tenant_id=tenant,created_by=actor,title='fixture a',description='fixture')
        c2=Investigation(tenant_id=other,created_by=other_actor,title='fixture b',description='fixture')
        db.add_all([c1,c2]); db.flush()
        event=InvestigationEvent(tenant_id=tenant,investigation_id=c1.id,actor_id=actor,event_type='fixture',details={})
        foreign=InvestigationEvent(tenant_id=other,investigation_id=c2.id,actor_id=other_actor,event_type='fixture',details={})
        db.add_all([event,foreign]); db.flush()
        now=datetime(2026,1,1,tzinfo=timezone.utc)
        db.add_all([SecurityAuditEvent(tenant_id=tenant,actor_id=actor,target_investigation_id=c1.id,target_investigation_event_id=event.id,event_type='investigation_event_read',occurred_at=now) for _ in range(101)])
        mismatch=SecurityAuditEvent(tenant_id=tenant,actor_id=actor,event_type='fixture',occurred_at=now)
        outside=SecurityAuditEvent(tenant_id=other,actor_id=other_actor,target_investigation_id=c2.id,target_investigation_event_id=foreign.id,event_type='investigation_event_read',occurred_at=now)
        db.add_all([mismatch,outside]); db.flush(); eid,foreign_id,mismatch_id,outside_id=event.id,foreign.id,mismatch.id,outside.id
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver') as client:
        path='/api/v1/secure/audit'; headers={'Authorization':'Bearer '+token}; filters={'investigation_event_id':str(eid),'event_type':'investigation_event_read'}
        assert client.get(path,headers=headers,params={'investigation_event_id':str(foreign_id)}).json()['items']==[]
        assert client.get(path,headers=headers,params={**filters,'before':str(mismatch_id)}).status_code==404
        assert client.get(path,headers=headers,params={**filters,'before':str(outside_id)}).status_code==404
        first=client.get(path,headers=headers,params=filters).json()
        second=client.get(path,headers=headers,params={**filters,'before':first['next_cursor']}).json()
        rows=first['items']+second['items']
        assert len(rows)==101 and len({row['id'] for row in rows})==101 and second['next_cursor'] is None
        assert all(row['target_investigation_event_id']==str(eid) for row in rows)


def test_investigation_event_audit_revision_preserves_existing_rows(tmp_path, monkeypatch):
    url=f'sqlite:///{tmp_path / "event-audit.db"}'
    monkeypatch.setenv('DATABASE_URL',url)
    config=Config(str(HERE/'alembic.ini')); command.upgrade(config,'0034_cisa_attempt_index')
    engine=create_engine(url); tenant,audit=uuid4(),uuid4()
    with engine.begin() as conn:
        conn.exec_driver_sql('INSERT INTO tenants (id,name) VALUES (?,?)',(tenant.hex,'fixture'))
        conn.exec_driver_sql('INSERT INTO security_audit_events (id,tenant_id,event_type,occurred_at) VALUES (?,?,?,?)',(audit.hex,tenant.hex,'fixture','2026-01-01 00:00:00'))
    command.upgrade(config,'head')
    with engine.begin() as conn: assert conn.exec_driver_sql('SELECT event_type,target_investigation_event_id FROM security_audit_events').all()==[('fixture',None)]
    command.downgrade(config,'0034_cisa_attempt_index')
    with engine.begin() as conn: assert conn.exec_driver_sql('SELECT event_type FROM security_audit_events').all()==[('fixture',)]
    command.downgrade(config,'base'); engine.dispose()


def test_postgres_report_discloses_mixed_time_reads(migration_db):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.models import Investigation, InvestigationNote, User
    from app.protected_api import protected_router
    from app.sessions import issue_session
    engine,_=migration_db
    if engine.dialect.name != 'postgresql': pytest.skip('PostgreSQL read-committed interleaving test')
    factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    with factory.begin() as db:
        token=issue_session(db,tenant,'admin','a safe long password')
        case=Investigation(tenant_id=tenant,created_by=actor,title='fixture',description='fixture'); db.add(case)
        other_actor=User(tenant_id=tenant,username='other',role='analyst',active=True,password_hash='fixture')
        db.add(other_actor); db.flush(); case_id, other_actor_id=case.id, other_actor.id
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    entities_read, proceed=Event(),Event()
    def observe(conn,cursor,statement,parameters,context,executemany):
        if 'FROM investigation_entity_links JOIN intelligence_entities' in statement:
            entities_read.set()
            if not proceed.wait(10): raise TimeoutError('test synchronization timed out')
    event.listen(engine,'after_cursor_execute',observe)
    try:
        with TestClient(app,base_url='https://testserver') as client, ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(client.get,f'/api/v1/secure/investigations/{case_id}/report',headers={'Authorization':'Bearer '+token})
            try:
                assert entities_read.wait(10)
                with factory.begin() as db:
                    db.add(InvestigationNote(tenant_id=tenant,investigation_id=case_id,author_id=other_actor_id,body='inserted after report started'))
                proceed.set()
                response=future.result(timeout=10)
            finally:
                proceed.set()
            assert response.status_code==200
            assert response.json()['notes']['items'][0]['body']=='inserted after report started'
            assert 'not a consistent snapshot' in response.json()['notice']
    finally:
        event.remove(engine,'after_cursor_execute',observe)


def test_investigation_history_type_filter_and_cursor_scope(migration_db):
    from datetime import datetime, timezone
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.bootstrap import create_tenant_with_admin
    from app.models import Investigation, InvestigationEvent
    from app.protected_api import protected_router
    from app.sessions import issue_session
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,other_actor=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    with factory.begin() as db:
        token=issue_session(db,tenant,'admin','a safe long password')
        case=Investigation(tenant_id=tenant,created_by=actor,title='a',description='fixture')
        foreign=Investigation(tenant_id=other,created_by=other_actor,title='b',description='fixture')
        db.add_all([case,foreign]); db.flush(); now=datetime(2026,1,1,tzinfo=timezone.utc)
        db.add_all([InvestigationEvent(tenant_id=tenant,investigation_id=case.id,actor_id=actor,event_type='note_added',details={'synthetic':True},occurred_at=now) for _ in range(101)])
        different=InvestigationEvent(tenant_id=tenant,investigation_id=case.id,actor_id=actor,event_type='created',details={},occurred_at=now)
        outside=InvestigationEvent(tenant_id=other,investigation_id=foreign.id,actor_id=other_actor,event_type='note_added',details={},occurred_at=now)
        db.add_all([different,outside]); db.flush(); cid,did,oid=case.id,different.id,outside.id
    app=FastAPI(); app.include_router(protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver') as client:
        path=f'/api/v1/secure/investigations/{cid}/events'; h={'Authorization':'Bearer '+token}; params={'event_type':'note_added'}
        assert client.get(path,headers=h,params={'event_type':'invalid%'}).status_code==422
        assert client.get(path,headers=h,params={**params,'after':str(did)}).status_code==404
        assert client.get(path,headers=h,params={**params,'after':str(oid)}).status_code==404
        first=client.get(path,headers=h,params=params).json()
        second=client.get(path,headers=h,params={**params,'after':first['next_cursor']}).json()
        rows=first['items']+second['items']
        assert len(rows)==101 and len({r['id'] for r in rows})==101 and second['next_cursor'] is None
        assert all(r['event_type']=='note_added' for r in rows)
        assert client.get(path,headers=h,params={'event_type':'unknown'}).json()['items']==[]


def test_investigation_notes_author_filter_scope_pagination_and_audit(migration_db, monkeypatch):
    from datetime import datetime, timezone
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import accounts, protected_api
    from app.bootstrap import create_tenant_with_admin
    from app.models import Investigation, InvestigationNote, SecurityAuditEvent
    from app.security import Role
    from app.sessions import issue_session
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,other_actor=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    with factory.begin() as db: admin=issue_session(db,tenant,'admin','a safe long password')
    viewer_id=accounts.create_user(factory,admin_token=admin,username='viewer',password='a safe long password',role=Role.VIEWER)
    with factory.begin() as db:
        viewer=issue_session(db,tenant,'viewer','a safe long password')
        case=Investigation(tenant_id=tenant,created_by=actor,title='a',description='fixture')
        foreign=Investigation(tenant_id=other,created_by=other_actor,title='b',description='fixture')
        db.add_all([case,foreign]); db.flush(); now=datetime(2026,1,1,tzinfo=timezone.utc)
        db.add_all([InvestigationNote(tenant_id=tenant,investigation_id=case.id,author_id=actor,body='fixture',created_at=now) for _ in range(101)])
        mismatch=InvestigationNote(tenant_id=tenant,investigation_id=case.id,author_id=viewer_id,body='fixture',created_at=now)
        outside=InvestigationNote(tenant_id=other,investigation_id=foreign.id,author_id=other_actor,body='fixture',created_at=now)
        db.add_all([mismatch,outside]); db.flush(); cid,mid,oid=case.id,mismatch.id,outside.id
    app=FastAPI(); app.include_router(protected_api.protected_router(factory,b'x'*32))
    with TestClient(app,base_url='https://testserver',raise_server_exceptions=False) as client:
        path=f'/api/v1/secure/investigations/{cid}/notes'; h={'Authorization':'Bearer '+viewer}; params={'author_id':str(actor)}
        assert client.get(path).status_code==401
        assert client.get(path,headers=h,params={'author_id':'not-a-uuid'}).status_code==422
        assert client.get(path,headers=h,params={'author_id':str(other_actor)}).json()['items']==[]
        assert client.get(path,headers=h,params={**params,'after':str(mid)}).status_code==404
        assert client.get(path,headers=h,params={**params,'after':str(oid)}).status_code==404
        def fail(*args,**kwargs): raise RuntimeError('audit unavailable')
        with monkeypatch.context() as patch:
            patch.setattr(protected_api,'record_event',fail)
            assert client.get(path,headers=h,params=params).status_code==500
        first=client.get(path,headers=h,params=params).json()
        second=client.get(path,headers=h,params={**params,'after':first['next_cursor']}).json()
        rows=first['items']+second['items']
        assert len(rows)==101 and len({r['id'] for r in rows})==101 and second['next_cursor'] is None
        assert all(r['author_id']==str(actor) and r['status']=='analyst_entered_unverified' for r in rows)
    with factory() as db:
        events=list(db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type=='investigation_read',SecurityAuditEvent.target_investigation_id==cid)))
        assert len(events)==3


def test_relationship_detail_tenant_parent_scope_and_audit(migration_db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import accounts, protected_api
    from app.bootstrap import create_tenant_with_admin
    from app.models import SecurityAuditEvent
    from app.security import Role
    from app.sessions import issue_session
    engine,_=migration_db; factory=sessionmaker(engine,expire_on_commit=False)
    tenant,actor=create_tenant_with_admin(factory,tenant_name='a',username='admin',password='a safe long password')
    other,other_actor=create_tenant_with_admin(factory,tenant_name='b',username='admin',password='a safe long password')
    with factory.begin() as db:
        admin=issue_session(db,tenant,'admin','a safe long password')
        foreign=issue_session(db,other,'admin','a safe long password')
    accounts.create_user(factory,admin_token=admin,username='viewer',password='a safe long password',role=Role.VIEWER)
    with factory.begin() as db:
        viewer=issue_session(db,tenant,'viewer','a safe long password')
        x=Entity(tenant_id=tenant,created_by=actor,kind='indicator',title='x',source='fixture')
        y=Entity(tenant_id=tenant,created_by=actor,kind='indicator',title='y',source='fixture')
        z=Entity(tenant_id=tenant,created_by=actor,kind='indicator',title='z',source='fixture')
        f=Entity(tenant_id=other,created_by=other_actor,kind='indicator',title='foreign',source='fixture')
        db.add_all([x,y,z,f]); db.flush()
        relation=Relationship(tenant_id=tenant,subject_id=x.id,object_id=y.id,kind='RELATED_TO',source='fixture',created_by=actor,provenance={'status':'analyst_assertion_unverified'})
        db.add(relation); db.flush(); xid,yid,zid,fid,rid=x.id,y.id,z.id,f.id,relation.id
    app=FastAPI(); app.include_router(protected_api.protected_router(factory,b'x'*32))
    h=lambda t:{'Authorization':'Bearer '+t}
    with TestClient(app,base_url='https://testserver',raise_server_exceptions=False) as client:
        path=f'/api/v1/secure/entities/{xid}/relationships/{rid}'
        assert client.get(path).status_code==401
        assert client.get(path,headers=h(foreign)).status_code==404
        assert client.get(f'/api/v1/secure/entities/{zid}/relationships/{rid}',headers=h(viewer)).status_code==404
        assert client.get(f'/api/v1/secure/entities/{fid}/relationships/{rid}',headers=h(viewer)).status_code==404
        def fail(*args,**kwargs): raise RuntimeError('audit unavailable')
        with monkeypatch.context() as patch:
            patch.setattr(protected_api,'record_event',fail)
            assert client.get(path,headers=h(viewer)).status_code==500
        response=client.get(path,headers=h(viewer))
        assert response.status_code==200 and response.headers['cache-control']=='no-store'
        assert response.json()['id']==str(rid) and 'not independently verified' in response.json()['notice']
        assert client.get(f'/api/v1/secure/entities/{yid}/relationships/{rid}',headers=h(viewer)).status_code==200
    with factory() as db:
        events=list(db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.event_type=='relationship_read')))
        assert len(events)==2 and {e.target_entity_id for e in events}=={xid,yid}
