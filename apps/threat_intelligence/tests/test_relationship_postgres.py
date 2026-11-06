"""Opt-in isolated real PostgreSQL integration tests; never target shared DBs."""
import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, func, select

from apps.threat_intelligence.api import app
from apps.threat_intelligence.relationship_api import Principal, get_principal
from apps.threat_intelligence.relationship_storage import PostgresRelationshipStore, metadata, relationship, audit_event
from test_relationship_http import request, payload, BASE


@pytest.fixture(scope='module')
def pg_engine(tmp_path_factory):
    if os.getenv('CICC_TEST_PG_EMBEDDED') != '1':
        pytest.skip('set CICC_TEST_PG_EMBEDDED=1 to run isolated PostgreSQL tests')
    pgserver = pytest.importorskip('pgserver')
    pytest.importorskip('psycopg')
    server = pgserver.get_server(tmp_path_factory.mktemp('ti-postgres'), cleanup_mode='stop')
    url = server.get_uri().replace('postgresql://', 'postgresql+psycopg://', 1)
    engine = create_engine(url, pool_size=12, max_overflow=4)
    # Exercise the exact standalone migration proposal on this isolated instance.
    from pathlib import Path
    sql = (Path(__file__).parents[1] / "schema" / "p2_01_postgres_proposal.sql").read_text()
    sql = "\n".join(line for line in sql.splitlines() if not line.startswith("--"))
    with engine.connect() as conn:
        for statement in sql.split(";"):
            if statement.strip():
                conn.exec_driver_sql(statement)
    yield engine
    engine.dispose()
    server.cleanup()

@pytest.fixture
def env(pg_engine):
    tenant = 'fixture-' + uuid4().hex
    app.state.relationship_store = PostgresRelationshipStore(pg_engine, enforce_rls=False)
    app.state.relationship_audit = lambda event: None
    def identity(tenant_id=tenant, permissions=('threat:read', 'threat:write')):
        app.dependency_overrides[get_principal] = lambda: Principal(subject='fixture-actor', tenant_id=tenant_id, permissions=frozenset(permissions))
    identity()
    yield tenant, identity
    app.dependency_overrides.clear()
    del app.state.relationship_store
    del app.state.relationship_audit


def create(data, key):
    return request('POST', BASE + '/relationships', data, {'Idempotency-Key': key})


def test_persistence_restart_and_tenant_isolation(env, pg_engine):
    tenant, identity = env
    code, first = create(payload(), 'persist')
    assert code == 201
    # New store and new connection pool emulate an application process restart.
    new_engine = create_engine(pg_engine.url)
    try:
        app.state.relationship_store = PostgresRelationshipStore(new_engine, enforce_rls=False)
        assert request('GET', BASE + '/relationships/' + first['relationship_id']) == (200, first)
        assert create(payload(), 'persist') == (200, first)
        identity(tenant + '-other')
        assert request('GET', BASE + '/relationships/' + first['relationship_id'])[0] == 404
        assert request('GET', BASE + '/relationships')[1]['total'] == 0
        assert create(payload(), 'persist')[1]['relationship_id'] != first['relationship_id']
    finally:
        new_engine.dispose()


def test_concurrent_idempotency_and_observations(env, pg_engine):
    tenant, _ = env
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: create(payload(), 'same'), range(12)))
    assert sorted(code for code, _ in results) == [200] * 11 + [201]
    assert len({record['relationship_id'] for _, record in results}) == 1
    assert create(payload('x', 'y'), 'same')[0] == 409
    changed = payload(); changed['provenance'] = 'different observation'
    assert create(changed, 'other')[0] == 201
    with pg_engine.connect() as conn:
        assert conn.execute(select(func.count()).select_from(relationship).where(relationship.c.tenant_id == tenant)).scalar_one() == 2
        outcomes = conn.execute(select(audit_event.c.outcome).where(audit_event.c.tenant_id == tenant)).scalars().all()
        assert outcomes.count('created') == 2 and outcomes.count('replayed') == 11 and 'conflict' in outcomes


def test_graph_filter_cycles_and_paginate(env):
    for i, item in enumerate([payload('a','b'), payload('b','c','TARGETS'), payload('c','a')]):
        assert create(item, str(i))[0] == 201
    args = {'entity_id':'a', 'entity_type':'Actor', 'max_depth':2, 'limit':2}
    code, page = request('POST', BASE + '/relationship-analysis/traverse', args)
    assert code == 200 and page['total'] == 3 and page['visited_entities'] == 3 and page['has_more']
    args['offset'] = 2
    other = request('POST', BASE + '/relationship-analysis/traverse', args)[1]
    assert len(other['items']) == 1 and not other['has_more']
    args['offset'] = 0; args['relationship_types'] = ['USES']
    assert request('POST', BASE + '/relationship-analysis/traverse', args)[1]['total'] == 2
    assert request('GET', BASE + '/relationships', query={'entity_type':'Actor','entity_id':'b', 'relationship_type':'TARGETS'})[1]['total'] == 1
    assert request('POST', BASE + '/relationship-analysis/traverse', {'entity_type':'Actor','entity_id':'missing'})[0] == 404


def test_audit_failure_rolls_back_write(env, pg_engine):
    tenant, _ = env
    def fail_audit(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith('INSERT INTO TI_RELATIONSHIP_AUDIT'):
            raise RuntimeError('secret test error')
    event.listen(pg_engine, 'before_cursor_execute', fail_audit)
    try:
        code, body = create(payload(), 'fail')
        assert code == 500 and 'secret test error' not in str(body)
    finally:
        event.remove(pg_engine, 'before_cursor_execute', fail_audit)
    with pg_engine.connect() as conn:
        assert conn.execute(select(func.count()).select_from(relationship).where(relationship.c.tenant_id == tenant)).scalar_one() == 0
    assert create(payload(), 'fail')[0] == 201


def test_durable_audit_fields_and_denial(env, pg_engine):
    tenant, identity = env
    rid = create(payload(), 'event')[1]['relationship_id']
    assert request('GET', BASE + '/relationships/' + rid)[0] == 200
    with pg_engine.connect() as conn:
        rows = conn.execute(select(audit_event).where(audit_event.c.tenant_id == tenant).order_by(audit_event.c.occurred_at)).mappings().all()
    assert [(x['operation'], x['outcome']) for x in rows] == [('relationship.create','created'), ('relationship.read','success')]
    assert all(x['actor'] == 'fixture-actor' and str(x['resource_id']) == rid and x['correlation_id'] and x['occurred_at'].tzinfo for x in rows)
    assert 'test evidence' not in str(rows) and 'fixture source' not in str(rows)
    identity(tenant, ())
    assert request('GET', BASE + '/relationships')[0] == 403


def test_another_process_reads_committed_data(env, pg_engine):
    import subprocess
    import sys
    tenant, _ = env
    rid = create(payload(), 'process-restart')[1]['relationship_id']
    script = '''
import os
from uuid import UUID, uuid4
from sqlalchemy import create_engine
from apps.threat_intelligence.relationship_storage import PostgresRelationshipStore, AuditContext
store = PostgresRelationshipStore(create_engine(os.environ['CICC_LOCAL_TEST_URL']), enforce_rls=False)
r = store.get(AuditContext(os.environ['CICC_LOCAL_TENANT'], 'restart-fixture', uuid4()), UUID(os.environ['CICC_LOCAL_RECORD']))
assert r is not None and str(r.relationship_id) == os.environ['CICC_LOCAL_RECORD']
'''
    environ = dict(os.environ, CICC_LOCAL_TEST_URL=pg_engine.url.render_as_string(hide_password=False), CICC_LOCAL_TENANT=tenant, CICC_LOCAL_RECORD=rid)
    result = subprocess.run([sys.executable, '-c', script], env=environ, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, 'child process could not read the committed record'


def test_correlation_header_matches_durable_audit(env, pg_engine):
    from uuid import UUID
    tenant, _ = env
    code, body, headers = request('POST', BASE + '/relationships', payload(), {'Idempotency-Key': 'correlation'}, include_headers=True)
    assert code == 201
    correlation = UUID(headers[b'x-correlation-id'].decode())
    with pg_engine.connect() as conn:
        row = conn.execute(select(audit_event).where(audit_event.c.tenant_id == tenant)).mappings().one()
    assert row['correlation_id'] == correlation and str(row['resource_id']) == body['relationship_id']


def test_cross_tenant_and_fingerprint_foreign_keys(env, pg_engine):
    from sqlalchemy.exc import IntegrityError
    from apps.threat_intelligence.relationship_storage import idempotency
    tenant, _ = env
    rid = create(payload(), 'original')[1]['relationship_id']
    for bogus_tenant, fingerprint in [(tenant + '-other', 'x' * 64), (tenant, 'x' * 64)]:
        with pytest.raises(IntegrityError):
            with pg_engine.begin() as conn:
                conn.execute(idempotency.insert().values(tenant_id=bogus_tenant, key='invalid', fingerprint=fingerprint, relationship_id=rid))


def test_concurrent_duplicate_distinct_keys(env):
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda n: create(payload(), 'unique-' + str(n)), range(8)))
    assert sorted(code for code, _ in results) == [200] * 7 + [201]
    assert len({record['relationship_id'] for _, record in results}) == 1


def test_graph_limit_fails_without_partial_result(env, pg_engine):
    app.state.relationship_store = PostgresRelationshipStore(pg_engine, max_traversal_edges=1, enforce_rls=False)
    assert create(payload('a','b'), '1')[0] == 201
    assert create(payload('a','c'), '2')[0] == 201
    code, body = request('POST', BASE + '/relationship-analysis/traverse', {'entity_type':'Actor','entity_id':'a'})
    assert code == 422 and body['detail'] == 'Traversal exceeds configured graph limit'


def test_database_server_restart_preserves_records(tmp_path_factory):
    if os.getenv('CICC_TEST_PG_EMBEDDED') != '1':
        pytest.skip('set CICC_TEST_PG_EMBEDDED=1 to run isolated PostgreSQL tests')
    pgserver = pytest.importorskip('pgserver')
    pytest.importorskip('psycopg')
    pgdata = tmp_path_factory.mktemp('ti-postgres-restart')
    server = pgserver.get_server(pgdata, cleanup_mode='stop')
    engine = create_engine(server.get_uri().replace('postgresql://', 'postgresql+psycopg://', 1))
    tenant = 'restart-' + uuid4().hex
    try:
        metadata.create_all(engine)
        app.state.relationship_store = PostgresRelationshipStore(engine, enforce_rls=False)
        app.state.relationship_audit = lambda event: None
        app.dependency_overrides[get_principal] = lambda: Principal(subject='restart-fixture', tenant_id=tenant, permissions=frozenset({'threat:read','threat:write'}))
        rid = create(payload(), 'restart')[1]['relationship_id']
        old_pid = server.get_pid()
        engine.dispose()
        server.cleanup()  # Stop only the disposable server owned by this test.
        server = pgserver.get_server(pgdata, cleanup_mode='stop')
        assert server.get_pid() != old_pid
        engine = create_engine(server.get_uri().replace('postgresql://', 'postgresql+psycopg://', 1))
        app.state.relationship_store = PostgresRelationshipStore(engine, enforce_rls=False)
        assert request('GET', BASE + '/relationships/' + rid)[0] == 200
        assert create(payload(), 'restart')[0] == 200
    finally:
        app.dependency_overrides.clear()
        del app.state.relationship_store
        del app.state.relationship_audit
        engine.dispose()
        server.cleanup()
