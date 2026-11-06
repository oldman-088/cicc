"""Opt-in adversarial SQL tests of proposed session-user RLS, isolated PG only."""
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import DBAPIError

from apps.threat_intelligence.api import app
from apps.threat_intelligence.relationship_api import Principal, get_principal
from apps.threat_intelligence.relationship_storage import AuditContext, PostgresRelationshipStore, audit_event, entity, relationship
from test_relationship_http import BASE, payload, request

@pytest.fixture(scope='module')
def role_db(tmp_path_factory):
    if os.getenv('CICC_TEST_PG_EMBEDDED') != '1':
        pytest.skip('set CICC_TEST_PG_EMBEDDED=1 to run isolated PostgreSQL tests')
    pgserver = pytest.importorskip('pgserver')
    pytest.importorskip('psycopg')
    server = pgserver.get_server(tmp_path_factory.mktemp('ti-role-bound'), cleanup_mode='stop')
    admin = create_engine(server.get_uri().replace('postgresql://', 'postgresql+psycopg://', 1))
    folder = Path(__file__).parents[1] / 'schema'
    with admin.connect() as conn:
        for name in ['p2_01_postgres_proposal.sql', 'p2_01_rls_proposal.sql', 'p2_01_role_bound_rls_proposal.sql']:
            conn.exec_driver_sql((folder / name).read_text())
        conn.exec_driver_sql('CREATE ROLE ti_role_a LOGIN NOSUPERUSER NOBYPASSRLS')
        conn.exec_driver_sql('CREATE ROLE ti_role_b LOGIN NOSUPERUSER NOBYPASSRLS')
        conn.exec_driver_sql('CREATE ROLE ti_role_unmapped LOGIN NOSUPERUSER NOBYPASSRLS')
        conn.exec_driver_sql('CREATE ROLE ti_role_common NOLOGIN NOSUPERUSER NOBYPASSRLS')
        conn.exec_driver_sql('GRANT ti_role_common TO ti_role_a, ti_role_b, ti_role_unmapped')
        conn.exec_driver_sql("INSERT INTO ti_security.tenant_role_map VALUES ('ti_role_a','tenant-A'), ('ti_role_b','tenant-B')")
        conn.exec_driver_sql('GRANT USAGE ON SCHEMA ti_security TO ti_role_common')
        conn.exec_driver_sql('GRANT EXECUTE ON FUNCTION ti_security.authenticated_tenant() TO ti_role_common')
        conn.exec_driver_sql('GRANT SELECT, INSERT ON ti_relationship_entity, ti_relationship_record, ti_relationship_idempotency, ti_relationship_audit TO ti_role_common')
        conn.exec_driver_sql('GRANT USAGE, SELECT ON SEQUENCE ti_relationship_record_sequence_seq TO ti_role_common')
        conn.commit()
    pools = [create_engine(admin.url.set(username=role), pool_size=2, max_overflow=2) for role in ['ti_role_a','ti_role_b','ti_role_unmapped']]
    yield admin, *pools
    for pool in pools: pool.dispose()
    admin.dispose()
    server.cleanup()

@pytest.fixture
def env(role_db):
    admin, a, b, unmapped = role_db
    app.state.relationship_audit = lambda event: None
    def identity(tenant='tenant-A', db=a):
        app.state.relationship_store = PostgresRelationshipStore(db, tenant_binding='session_role')
        app.dependency_overrides[get_principal] = lambda: Principal(subject='fixture-actor', tenant_id=tenant, permissions=frozenset({'threat:read','threat:write'}))
    identity()
    yield admin, a, b, unmapped, identity
    app.dependency_overrides.clear()
    del app.state.relationship_store
    del app.state.relationship_audit


def create():
    suffix = uuid4().hex
    return request('POST', BASE + '/relationships', payload('a-'+suffix, 'b-'+suffix), {'Idempotency-Key': suffix})


def test_role_bound_end_to_end_and_context_mismatch(env):
    _, a, b, _, identity = env
    code, record = create()
    assert code == 201
    rid = record['relationship_id']
    identity('tenant-B', b)
    assert request('GET', BASE + '/relationships/' + rid)[0] == 404
    assert request('POST', BASE + '/relationship-analysis/traverse', {'entity_type':'Actor', 'entity_id':record['source_entity']['entity_id']})[0] == 404
    identity('tenant-B', a)  # Application principal cannot select a different DB login tenant.
    assert request('GET', BASE + '/relationships/' + rid)[0] == 500
    identity('tenant-A', a)
    assert request('GET', BASE + '/relationships/' + rid)[0] == 200


def test_arbitrary_guc_cannot_cross_read_or_insert(env):
    _, a, b, _, identity = env
    identity('tenant-B', b); victim = create()[1]
    with a.begin() as conn:
        conn.execute(text("SELECT set_config('cicc.tenant_id', 'tenant-B', true)"))
        assert conn.execute(select(relationship.c.relationship_id).where(relationship.c.relationship_id == UUID(victim['relationship_id']))).first() is None
        assert 'tenant-B' not in conn.execute(select(audit_event.c.tenant_id)).scalars().all()
    with pytest.raises(DBAPIError):
        with a.begin() as conn:
            conn.execute(text("SELECT set_config('cicc.tenant_id', 'tenant-B', true)"))
            conn.execute(entity.insert().values(tenant_id='tenant-B', entity_type='Actor', entity_id='forged'))


def test_unmapped_or_bypass_roles_fail_closed(env):
    admin, _, _, unmapped, identity = env
    identity('tenant-A', unmapped)
    assert request('GET', BASE + '/relationships')[0] == 500
    identity('tenant-A', admin)
    assert request('GET', BASE + '/relationships')[0] == 500
    with unmapped.begin() as conn:
        assert conn.execute(select(relationship.c.relationship_id)).scalars().all() == []


def test_runtime_role_cannot_modify_mapping_switch_roles_or_change_policy(env):
    _, a, _, _, _ = env
    for statement in ["UPDATE ti_security.tenant_role_map SET tenant_id='tenant-B' WHERE login_role='ti_role_a'",
                      'SELECT * FROM ti_security.tenant_role_map', 'SET ROLE ti_role_b',
                      'SET SESSION AUTHORIZATION ti_role_b',
                      'ALTER TABLE ti_relationship_record DISABLE ROW LEVEL SECURITY',
                      'CREATE TABLE ti_security.fake (x int)',
                      'DELETE FROM ti_relationship_audit',
                      'UPDATE ti_relationship_record SET relationship_type=\'RELATED_TO\'']:
        with pytest.raises(DBAPIError):
            with a.begin() as conn:
                conn.exec_driver_sql(statement)


def test_pool_reuse_rollback_and_parallel_tenants(env):
    _, a, b, _, identity = env
    identity('tenant-A', a); record = create()[1]
    rid = UUID(record['relationship_id'])
    # Application mismatches roll back and cannot leak to next pooled transaction.
    store_a = PostgresRelationshipStore(a, tenant_binding='session_role')
    store_b = PostgresRelationshipStore(b, tenant_binding='session_role')
    with pytest.raises(RuntimeError):
        store_a.get(AuditContext('tenant-B', 'fixture', uuid4()), rid)
    assert store_a.get(AuditContext('tenant-A', 'fixture', uuid4()), rid) is not None
    def lookup(i):
        store, tenant = (store_a, 'tenant-A') if i % 2 == 0 else (store_b, 'tenant-B')
        return store.get(AuditContext(tenant, 'fixture', uuid4()), rid)
    with ThreadPoolExecutor(max_workers=6) as pool:
        values = list(pool.map(lookup, range(16)))
    assert all((value is not None) == (i % 2 == 0) for i, value in enumerate(values))


def test_role_rls_denies_update_delete_even_with_table_privilege(env):
    admin, a, b, _, identity = env
    identity('tenant-B', b); victim = create()[1]
    with admin.begin() as conn:
        conn.exec_driver_sql('GRANT UPDATE, DELETE ON ti_relationship_record, ti_relationship_audit TO ti_role_common')
    try:
        with a.begin() as conn:
            conn.execute(text("SELECT set_config('cicc.tenant_id', 'tenant-B', true)"))
            assert conn.execute(relationship.update().where(relationship.c.relationship_id == UUID(victim['relationship_id'])).values(relationship_type='RELATED_TO')).rowcount == 0
            assert conn.execute(relationship.delete().where(relationship.c.relationship_id == UUID(victim['relationship_id']))).rowcount == 0
            assert conn.execute(audit_event.delete().where(audit_event.c.tenant_id == 'tenant-B')).rowcount == 0
        identity('tenant-B', b)
        assert request('GET', BASE + '/relationships/' + victim['relationship_id'])[0] == 200
    finally:
        with admin.begin() as conn:
            conn.exec_driver_sql('REVOKE UPDATE, DELETE ON ti_relationship_record, ti_relationship_audit FROM ti_role_common')


def test_extra_permissive_policy_is_detected(env):
    admin, _, _, _, _ = env
    with admin.begin() as conn:
        conn.exec_driver_sql('CREATE POLICY ti_unsafe_extra ON ti_relationship_record USING (true)')
    try:
        assert request('GET', BASE + '/relationships')[0] == 500
    finally:
        with admin.begin() as conn:
            conn.exec_driver_sql('DROP POLICY ti_unsafe_extra ON ti_relationship_record')
    assert request('GET', BASE + '/relationships')[0] == 200


def test_role_rls_rollback_is_rejected_by_role_bound_store(env):
    admin, _, _, _, _ = env
    folder = Path(__file__).parents[1] / 'schema'
    forward = (folder / 'p2_01_role_bound_rls_proposal.sql').read_text()
    policies = 'BEGIN;\n' + forward[forward.index('DROP POLICY'):]
    with admin.connect() as conn:
        conn.exec_driver_sql((folder / 'p2_01_role_bound_rls_rollback_proposal.sql').read_text())
    try:
        assert request('GET', BASE + '/relationships')[0] == 500
    finally:
        with admin.connect() as conn:
            conn.exec_driver_sql(policies)
    assert request('GET', BASE + '/relationships')[0] == 200


def test_role_audit_failure_rolls_back_idempotency_and_relationship(env):
    from sqlalchemy import event
    _, a, _, _, _ = env
    def fail(conn, cursor, statement, params, context, executemany):
        if statement.lstrip().upper().startswith('INSERT INTO TI_RELATIONSHIP_AUDIT'):
            raise RuntimeError('fixture audit failure')
    key = uuid4().hex
    body = payload('unique-'+key, 'unique2-'+key)
    event.listen(a, 'before_cursor_execute', fail)
    try:
        assert request('POST', BASE + '/relationships', body, {'Idempotency-Key': key})[0] == 500
    finally:
        event.remove(a, 'before_cursor_execute', fail)
    assert request('POST', BASE + '/relationships', body, {'Idempotency-Key': key})[0] == 201


def test_set_common_role_does_not_switch_authenticated_tenant(env):
    _, a, b, _, identity = env
    identity('tenant-B', b); victim = create()[1]
    with a.begin() as conn:
        conn.exec_driver_sql('SET LOCAL ROLE ti_role_common')
        assert conn.execute(text('SELECT ti_security.authenticated_tenant()')).scalar_one() == 'tenant-A'
        conn.execute(text("SELECT set_config('cicc.tenant_id', 'tenant-B', true)"))
        assert conn.execute(select(relationship.c.relationship_id).where(relationship.c.relationship_id == UUID(victim['relationship_id']))).first() is None


def test_audit_rls_denies_cross_tenant_but_own_audit_can_be_forged_by_role(env):
    from datetime import datetime, timezone
    _, a, _, _, _ = env
    values = dict(event_id=uuid4(), tenant_id='tenant-B', actor='forged', operation='test',
                  outcome='forged', correlation_id=uuid4(), occurred_at=datetime.now(timezone.utc))
    with pytest.raises(DBAPIError):
        with a.begin() as conn:
            conn.execute(audit_event.insert().values(**values))
    # SQL injection with the application's INSERT grant can forge an audit event
    # for its own tenant; independent trustworthy audit needs stronger privileges.
    values.update(tenant_id='tenant-A', event_id=uuid4())
    with a.begin() as conn:
        conn.execute(audit_event.insert().values(**values))
        assert conn.execute(select(audit_event.c.actor).where(audit_event.c.event_id == values['event_id'])).scalar_one() == 'forged'
