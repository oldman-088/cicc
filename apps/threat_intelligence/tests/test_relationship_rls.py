"""Opt-in tests against disposable local PostgreSQL, never a shared database."""
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, select, text
from sqlalchemy.exc import DBAPIError

from apps.threat_intelligence.api import app
from apps.threat_intelligence.relationship_api import Principal, get_principal
from apps.threat_intelligence.relationship_storage import PostgresRelationshipStore, audit_event, relationship
from test_relationship_http import BASE, payload, request

@pytest.fixture(scope='module')
def rls_db(tmp_path_factory):
    if os.getenv('CICC_TEST_PG_EMBEDDED') != '1':
        pytest.skip('set CICC_TEST_PG_EMBEDDED=1 to run isolated PostgreSQL tests')
    pgserver = pytest.importorskip('pgserver')
    pytest.importorskip('psycopg')
    server = pgserver.get_server(tmp_path_factory.mktemp('ti-rls'), cleanup_mode='stop')
    admin = create_engine(server.get_uri().replace('postgresql://', 'postgresql+psycopg://', 1))
    schema_dir = Path(__file__).parents[1] / 'schema'
    with admin.connect() as conn:
        for filename in ('p2_01_postgres_proposal.sql', 'p2_01_rls_proposal.sql'):
            sql = (schema_dir / filename).read_text()
            sql = '\n'.join(line for line in sql.splitlines() if not line.startswith('--'))
            for statement in sql.split(';'):
                if statement.strip():
                    conn.exec_driver_sql(statement)
        conn.exec_driver_sql('CREATE ROLE ti_fixture_rls LOGIN NOSUPERUSER NOBYPASSRLS')
        conn.exec_driver_sql('GRANT SELECT, INSERT ON ti_relationship_entity, ti_relationship_record, ti_relationship_idempotency, ti_relationship_audit TO ti_fixture_rls')
        conn.exec_driver_sql('GRANT USAGE, SELECT ON SEQUENCE ti_relationship_record_sequence_seq TO ti_fixture_rls')
        conn.commit()
    runtime = create_engine(admin.url.set(username='ti_fixture_rls'), pool_size=4, max_overflow=4)
    yield admin, runtime
    runtime.dispose()
    admin.dispose()
    server.cleanup()

@pytest.fixture
def env(rls_db):
    admin, db = rls_db
    tenant_a, tenant_b = 'a-' + uuid4().hex, 'b-' + uuid4().hex
    app.state.relationship_store = PostgresRelationshipStore(db, enforce_rls=True)
    app.state.relationship_audit = lambda event: None
    def identity(tenant=tenant_a):
        app.dependency_overrides[get_principal] = lambda: Principal(subject='fixture-user', tenant_id=tenant, permissions=frozenset({'threat:read','threat:write'}))
    identity()
    yield tenant_a, tenant_b, identity, admin, db
    app.dependency_overrides.clear()
    del app.state.relationship_store
    del app.state.relationship_audit


def create(data, key, headers=None):
    return request('POST', BASE + '/relationships', data, {'Idempotency-Key': key, **(headers or {})})


def test_rls_cross_tenant_http_and_immutable_request_identity(env):
    tenant_a, tenant_b, identity, _, _ = env
    original = create(payload(), 'key')[1]
    identity(tenant_b)
    assert request('GET', BASE + '/relationships/' + original['relationship_id'])[0] == 404
    assert request('GET', BASE + '/relationships')[1]['total'] == 0
    assert request('POST', BASE + '/relationship-analysis/traverse', {'entity_id':'a', 'entity_type':'Actor'})[0] == 404
    forged = payload(); forged['tenant_id'] = tenant_a
    assert create(forged, 'forged')[0] == 422
    created = create(payload('b','c'), 'other', {'X-Tenant-ID': tenant_a})
    assert created[0] == 201
    identity(tenant_a)
    assert request('GET', BASE + '/relationships/' + created[1]['relationship_id'])[0] == 404


def test_rls_direct_access_and_pool_reset(env):
    tenant_a, tenant_b, identity, _, db = env
    a = create(payload(), 'a')[1]['relationship_id']
    identity(tenant_b)
    b = create(payload('c','d'), 'b')[1]['relationship_id']
    with db.begin() as conn:
        # No identity set: default deny, even though the SQL role has SELECT.
        assert conn.execute(select(relationship.c.relationship_id)).scalars().all() == []
        conn.execute(text("SELECT set_config('cicc.tenant_id', :v, true)"), {'v': tenant_a})
        assert [str(x) for x in conn.execute(select(relationship.c.relationship_id)).scalars()] == [a]
        assert set(conn.execute(select(audit_event.c.tenant_id)).scalars()) == {tenant_a}
        with pytest.raises(DBAPIError):
            conn.execute(audit_event.insert().values(event_id=uuid4(), tenant_id=tenant_b, actor='fixture',
                operation='test', outcome='test', correlation_id=uuid4(), occurred_at='2026-01-01T00:00:00Z'))
    # Rollback/commit clears transaction-local setting, including reused connections.
    with db.begin() as conn:
        assert conn.execute(select(relationship.c.relationship_id)).scalars().all() == []
        conn.execute(text("SELECT set_config('cicc.tenant_id', :v, true)"), {'v': tenant_b})
        assert [str(x) for x in conn.execute(select(relationship.c.relationship_id)).scalars()] == [b]
        assert set(conn.execute(select(audit_event.c.tenant_id)).scalars()) == {tenant_b}


def test_rls_fail_closed_for_bypass_role(env):
    _, _, _, admin, _ = env
    app.state.relationship_store = PostgresRelationshipStore(admin, enforce_rls=True)
    code, body = request('GET', BASE + '/relationships')
    assert code == 500 and body['detail'] == 'Internal server error'


def test_rls_transactional_audit_failure_rolls_back(env):
    _, _, _, _, db = env
    def fail(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith('INSERT INTO TI_RELATIONSHIP_AUDIT'):
            raise RuntimeError('sensitive fixture error')
    event.listen(db, 'before_cursor_execute', fail)
    try:
        code, body = create(payload(), 'failure')
        assert code == 500 and 'sensitive fixture error' not in str(body)
    finally:
        event.remove(db, 'before_cursor_execute', fail)
    assert request('GET', BASE + '/relationships')[1]['total'] == 0
    assert create(payload(), 'failure')[0] == 201


def test_rls_concurrent_tenant_repository_calls(env):
    from apps.threat_intelligence.relationship_storage import AuditContext
    tenant_a, tenant_b, _, _, db = env
    a_id = create(payload(), 'a')[1]['relationship_id']
    # No per-thread global FastAPI overrides: concurrent calls have distinct trusted contexts.
    identity = AuditContext(tenant_a, 'a-fixture', uuid4())
    other = AuditContext(tenant_b, 'b-fixture', uuid4())
    store = PostgresRelationshipStore(db, enforce_rls=True)
    from uuid import UUID
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda context: store.get(context, UUID(a_id)), [identity, other] * 12))
    assert all((result is not None) == (i % 2 == 0) for i, result in enumerate(results))


def test_rls_blocks_cross_tenant_entity_relationship_and_idempotency_writes(env):
    from sqlalchemy.exc import DBAPIError
    from apps.threat_intelligence.relationship_storage import entity, idempotency
    tenant_a, tenant_b, identity, admin, db = env
    identity(tenant_b)
    original = create(payload('source', 'target'), 'foreign')[1]
    with admin.connect() as conn:
        row = dict(conn.execute(select(relationship).where(relationship.c.tenant_id == tenant_b)).mappings().one())
        key_row = dict(conn.execute(select(idempotency).where(idempotency.c.tenant_id == tenant_b)).mappings().one())
    del row['sequence']
    row['relationship_id'] = uuid4()
    row['fingerprint'] = 'f' * 64
    key_row['key'] = 'forged'
    attempts = [entity.insert().values(tenant_id=tenant_b, entity_type='X', entity_id='unauthorized'),
                relationship.insert().values(**row), idempotency.insert().values(**key_row)]
    for stmt in attempts:
        with pytest.raises(DBAPIError):
            with db.begin() as conn:
                conn.execute(text("SELECT set_config('cicc.tenant_id', :v, true)"), {'v': tenant_a})
                conn.execute(stmt)
    with admin.connect() as conn:
        assert conn.execute(select(relationship.c.relationship_id).where(relationship.c.tenant_id == tenant_b)).scalars().all()[0] == __import__('uuid').UUID(original['relationship_id'])


def test_missing_forced_rls_is_rejected(env):
    _, _, _, admin, _ = env
    with admin.begin() as conn:
        conn.exec_driver_sql('ALTER TABLE ti_relationship_audit NO FORCE ROW LEVEL SECURITY')
    try:
        assert request('GET', BASE + '/relationships')[0] == 500
    finally:
        with admin.begin() as conn:
            conn.exec_driver_sql('ALTER TABLE ti_relationship_audit FORCE ROW LEVEL SECURITY')


def test_rls_rollback_proposal_and_reapply_on_isolated_db(env):
    _, _, _, admin, _ = env
    schema_dir = Path(__file__).parents[1] / 'schema'
    def apply(name):
        content = (schema_dir / name).read_text()
        content = '\n'.join(line for line in content.splitlines() if not line.startswith('--'))
        with admin.connect() as conn:
            for stmt in content.split(';'):
                if stmt.strip():
                    conn.exec_driver_sql(stmt)
    apply('p2_01_rls_rollback_proposal.sql')
    try:
        # Store detects absent FORCE RLS and refuses operation after rollback.
        assert request('GET', BASE + '/relationships')[0] == 500
    finally:
        apply('p2_01_rls_proposal.sql')
    assert request('GET', BASE + '/relationships')[0] == 200


def test_custom_tenant_guc_is_not_an_authentication_boundary(env):
    # Explicitly demonstrate the limitation: direct arbitrary SQL on the same
    # application role can assert another tenant. Host must prohibit that access.
    tenant_a, tenant_b, identity, _, db = env
    identity(tenant_b)
    target = create(payload('target-a', 'target-b'), 'victim')[1]['relationship_id']
    identity(tenant_a)
    assert request('GET', BASE + '/relationships/' + target)[0] == 404
    with db.begin() as conn:
        conn.execute(text("SELECT set_config('cicc.tenant_id', :v, true)"), {'v': tenant_b})
        assert target in [str(r) for r in conn.execute(select(relationship.c.relationship_id)).scalars()]
