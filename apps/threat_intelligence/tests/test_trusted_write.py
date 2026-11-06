"""Isolated PostgreSQL tests for the proposed controlled create/audit path."""
import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, event, select, text
from sqlalchemy.exc import DBAPIError

from apps.threat_intelligence.api import app
from apps.threat_intelligence.relationship_api import Principal, get_principal
from apps.threat_intelligence.relationship_storage import TrustedWritePostgresRelationshipStore, audit_event, relationship
from test_relationship_http import BASE, payload, request

@pytest.fixture(scope='module')
def databases(tmp_path_factory):
    if os.getenv('CICC_TEST_PG_EMBEDDED') != '1':
        pytest.skip('set CICC_TEST_PG_EMBEDDED=1 to run isolated PostgreSQL tests')
    pgserver = pytest.importorskip('pgserver'); pytest.importorskip('psycopg')
    server = pgserver.get_server(tmp_path_factory.mktemp('ti-trusted-write'), cleanup_mode='stop')
    admin = create_engine(server.get_uri().replace('postgresql://', 'postgresql+psycopg://', 1))
    folder = Path(__file__).parents[1] / 'schema'
    with admin.connect() as c:
        for name in ('p2_01_postgres_proposal.sql','p2_01_rls_proposal.sql','p2_01_role_bound_rls_proposal.sql','p2_01_trusted_write_proposal.sql','p2_01_trusted_get_proposal.sql','p2_01_trusted_query_proposal.sql'):
            c.exec_driver_sql((folder / name).read_text())
        c.exec_driver_sql('CREATE ROLE ti_trusted_a LOGIN NOSUPERUSER NOBYPASSRLS')
        c.exec_driver_sql('CREATE ROLE ti_trusted_b LOGIN NOSUPERUSER NOBYPASSRLS')
        c.exec_driver_sql("INSERT INTO ti_security.tenant_role_map VALUES ('ti_trusted_a','tenant-A'),('ti_trusted_b','tenant-B')")
        c.exec_driver_sql("INSERT INTO ti_security.login_actor_map VALUES ('ti_trusted_a','actor-A'),('ti_trusted_b','actor-B')")
        c.exec_driver_sql('GRANT USAGE ON SCHEMA ti_security TO ti_trusted_a, ti_trusted_b')
        c.exec_driver_sql('GRANT EXECUTE ON FUNCTION ti_security.authenticated_tenant(), ti_security.authenticated_actor(), ti_security.trusted_create_relationship(text,jsonb), ti_security.trusted_get_relationship(uuid), ti_security.trusted_list_relationships(text,text,text,integer,integer), ti_security.trusted_traverse_relationships(text,text,integer,text[],integer,integer) TO ti_trusted_a, ti_trusted_b')
        c.commit()
    a, b = [create_engine(admin.url.set(username=name), pool_size=8, max_overflow=4) for name in ('ti_trusted_a','ti_trusted_b')]
    yield admin, a, b
    a.dispose(); b.dispose(); admin.dispose(); server.cleanup()

@pytest.fixture
def env(databases):
    admin, a, b = databases
    app.state.relationship_audit = lambda event: None
    def identity(tenant='tenant-A', actor='actor-A', db=a):
        app.state.relationship_store = TrustedWritePostgresRelationshipStore(db)
        app.dependency_overrides[get_principal] = lambda: Principal(subject=actor, tenant_id=tenant, permissions=frozenset({'threat:read','threat:write'}))
    identity()
    yield admin, a, b, identity
    app.dependency_overrides.clear()
    del app.state.relationship_store
    del app.state.relationship_audit


def create(data, key, include_headers=False):
    return request('POST', BASE + '/relationships', data, {'Idempotency-Key': key}, include_headers=include_headers)


def test_actual_asgi_create_has_database_derived_audit_identity_and_time(env):
    admin, _, _, _ = env
    key = uuid4().hex; data = payload('a-'+key, 'b-'+key)
    before = datetime.now(timezone.utc)
    code, record, headers = create(data, key, include_headers=True)
    after = datetime.now(timezone.utc)
    assert code == 201
    corr = UUID(headers[b'x-correlation-id'].decode())
    with admin.connect() as conn:
        row = conn.execute(select(audit_event).where(audit_event.c.correlation_id == corr)).mappings().one()
    assert (row['actor'],row['tenant_id'],row['operation'],row['outcome']) == ('actor-A','tenant-A','relationship.create','created')
    assert str(row['resource_id']) == record['relationship_id'] and before <= row['occurred_at'] <= after
    assert request('GET', BASE + '/relationships/' + record['relationship_id'])[0] == 200
    assert request('GET', BASE + '/relationships')[0] == 200


def test_replay_conflict_and_concurrency_audited(env):
    admin, _, _, _ = env
    key = uuid4().hex; data = payload('a-'+key, 'b-'+key)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: create(data, key), range(8)))
    assert sorted(x[0] for x in results) == [200] * 7 + [201]
    assert len({x[1]['relationship_id'] for x in results}) == 1
    assert create(payload('other-'+key, 'different-'+key), key)[0] == 409
    with admin.connect() as conn:
        outcomes = conn.execute(select(audit_event.c.outcome).where(audit_event.c.resource_id == UUID(results[0][1]['relationship_id']))).scalars().all()
    assert outcomes.count('created') == 1 and outcomes.count('replayed') == 7


def test_runtime_cannot_forge_audit_modify_or_claim_other_actor(env):
    _, a, _, identity = env
    for sql in ["INSERT INTO public.ti_relationship_audit(event_id,tenant_id,actor,operation,outcome,correlation_id,occurred_at) VALUES (gen_random_uuid(),'tenant-A','forged','fake','created',gen_random_uuid(), now())",
                'UPDATE public.ti_relationship_audit SET actor=\'forged\'', 'DELETE FROM public.ti_relationship_audit',
                "UPDATE ti_security.login_actor_map SET actor='forged'", 'SET ROLE ti_trusted_b',
                'ALTER FUNCTION ti_security.trusted_create_relationship(text,jsonb) RENAME TO forged']:
        with pytest.raises(DBAPIError):
            with a.begin() as conn: conn.exec_driver_sql(sql)
    identity('tenant-A','actor-B',a)
    assert create(payload(), uuid4().hex)[0] == 500
    identity('tenant-B','actor-A',a)
    assert create(payload(), uuid4().hex)[0] == 500


def test_direct_sql_cannot_supply_audit_fields_or_call_other_tenant(env):
    _, a, b, identity = env
    identity('tenant-B','actor-B',b); key = uuid4().hex
    victim = create(payload('x-'+key,'y-'+key), key)[1]
    with a.begin() as conn:
        conn.execute(text("SELECT set_config('cicc.tenant_id', 'tenant-B', true)"))
        result = conn.execute(text('SELECT ti_security.trusted_get_relationship(:id)'), {'id': UUID(victim['relationship_id'])}).scalar_one()
        assert result['record'] is None and result['tenant'] == 'tenant-A'
    with pytest.raises(DBAPIError):
        with a.begin() as conn:
            conn.execute(select(audit_event.c.tenant_id)).all()
    # No actor, event type, timestamp or tenant parameter exists; forged fields
    # inside the record are rejected, not interpreted as trusted audit data.
    forged = dict(victim, actor='actor-B', occurred_at='2000-01-01T00:00:00Z')
    with pytest.raises(DBAPIError):
        with a.begin() as conn:
            conn.execute(text('SELECT ti_security.trusted_create_relationship(:key, CAST(:record AS jsonb))'), {'key':uuid4().hex,'record':json.dumps(forged)})


def test_failed_audit_rolls_back_everything_and_retry_succeeds(env):
    admin, _, _, _ = env
    key = uuid4().hex; data = payload('a-'+key, 'b-'+key)
    # Isolated fault injection into the database audit trigger; removed afterwards.
    with admin.begin() as conn:
        conn.exec_driver_sql("CREATE FUNCTION public.ti_test_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit failure'; END $$")
        conn.exec_driver_sql('CREATE TRIGGER ti_test_fail_audit BEFORE INSERT ON public.ti_relationship_audit FOR EACH ROW EXECUTE FUNCTION public.ti_test_fail_audit()')
    try:
        assert create(data, key)[0] == 500
    finally:
        with admin.begin() as conn:
            conn.exec_driver_sql('DROP TRIGGER ti_test_fail_audit ON public.ti_relationship_audit')
            conn.exec_driver_sql('DROP FUNCTION public.ti_test_fail_audit()')
    assert create(data, key)[0] == 201



def test_actor_mapping_change_during_write_rolls_back(env):
    admin, a, _, _ = env
    key = uuid4().hex
    switched = []
    def rotate(conn, cursor, statement, params, context, executemany):
        if 'trusted_create_relationship' in statement and not switched:
            with admin.begin() as owner:
                owner.execute(text("UPDATE ti_security.login_actor_map SET actor='actor-new' WHERE login_role='ti_trusted_a'"))
            switched.append(True)
    event.listen(a, 'before_cursor_execute', rotate)
    try:
        assert create(payload('rotation-'+key, 'other-'+key), key)[0] == 500
    finally:
        event.remove(a, 'before_cursor_execute', rotate)
        with admin.begin() as owner:
            owner.execute(text("UPDATE ti_security.login_actor_map SET actor='actor-A' WHERE login_role='ti_trusted_a'"))
    assert switched
    with admin.connect() as owner:
        assert owner.execute(select(relationship.c.relationship_id).where(relationship.c.source_id == 'rotation-'+key)).first() is None
    assert create(payload('rotation-'+key, 'other-'+key), key)[0] == 201


def test_rollback_removes_trusted_write_and_reapply_restores_it(env):
    admin, _, _, _ = env
    folder = Path(__file__).parents[1] / 'schema'
    forward = (folder / 'p2_01_trusted_write_proposal.sql').read_text()
    function_sql = 'BEGIN;\n' + forward[forward.index('CREATE FUNCTION ti_security.trusted_create_relationship'):]
    key = uuid4().hex
    data = payload('rollback-'+key, 'rollback-target-'+key)
    with admin.connect() as conn:
        conn.exec_driver_sql((folder / 'p2_01_trusted_write_rollback_proposal.sql').read_text())
    try:
        assert create(data, key)[0] == 500
    finally:
        with admin.connect() as conn:
            conn.exec_driver_sql(function_sql)
            conn.exec_driver_sql('GRANT EXECUTE ON FUNCTION ti_security.trusted_create_relationship(text,jsonb) TO ti_trusted_a, ti_trusted_b')
            conn.commit()
    assert create(data, key)[0] == 201


def test_controlled_read_audit_and_cross_tenant_denial(env):
    admin, a, b, identity = env
    key = uuid4().hex
    created = create(payload('read-'+key, 'read-target-'+key), key)[1]
    rid = created['relationship_id']
    code, body, headers = request('GET', BASE + '/relationships/' + rid, include_headers=True)
    assert code == 200 and body['relationship_id'] == rid
    corr = UUID(headers[b'x-correlation-id'].decode())
    with admin.connect() as conn:
        audit = conn.execute(select(audit_event).where(audit_event.c.correlation_id == corr)).mappings().one()
    assert (audit['tenant_id'], audit['actor'], audit['operation'], audit['outcome']) == ('tenant-A','actor-A','relationship.read','success')
    identity('tenant-B', 'actor-B', b)
    code, body, headers = request('GET', BASE + '/relationships/' + rid, include_headers=True)
    assert code == 404
    with admin.connect() as conn:
        missing = conn.execute(select(audit_event).where(audit_event.c.correlation_id == UUID(headers[b'x-correlation-id'].decode()))).mappings().one()
    assert (missing['tenant_id'], missing['actor'], missing['outcome']) == ('tenant-B','actor-B','not_found')
    # Direct reads are denied even for the same tenant: controlled reads must
    # execute and write audit together.
    with pytest.raises(DBAPIError):
        with a.begin() as conn: conn.execute(select(relationship.c.relationship_id)).all()


def test_controlled_read_fails_closed_when_audit_fails(env):
    admin, _, _, _ = env
    key = uuid4().hex
    rid = create(payload('failread-'+key, 'failread-target-'+key), key)[1]['relationship_id']
    with admin.begin() as conn:
        conn.exec_driver_sql("CREATE FUNCTION public.ti_test_read_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture failure'; END $$")
        conn.exec_driver_sql('CREATE TRIGGER ti_test_read_audit_failure BEFORE INSERT ON public.ti_relationship_audit FOR EACH ROW EXECUTE FUNCTION public.ti_test_read_audit_failure()')
    try:
        assert request('GET', BASE + '/relationships/' + rid)[0] == 500
    finally:
        with admin.begin() as conn:
            conn.exec_driver_sql('DROP TRIGGER ti_test_read_audit_failure ON public.ti_relationship_audit')
            conn.exec_driver_sql('DROP FUNCTION public.ti_test_read_audit_failure()')
    assert request('GET', BASE + '/relationships/' + rid)[0] == 200


def test_controlled_read_mapping_change_aborts_without_audit(env):
    admin, a, _, _ = env
    key = uuid4().hex
    rid = create(payload('mapread-'+key, 'mapread-target-'+key), key)[1]['relationship_id']
    switched = []
    def rotate(conn, cursor, statement, params, context, executemany):
        if 'trusted_get_relationship' in statement and not switched:
            with admin.begin() as owner:
                owner.execute(text("UPDATE ti_security.login_actor_map SET actor='actor-new' WHERE login_role='ti_trusted_a'"))
            switched.append(True)
    event.listen(a, 'before_cursor_execute', rotate)
    try:
        assert request('GET', BASE + '/relationships/' + rid)[0] == 500
    finally:
        event.remove(a, 'before_cursor_execute', rotate)
        with admin.begin() as owner:
            owner.execute(text("UPDATE ti_security.login_actor_map SET actor='actor-A' WHERE login_role='ti_trusted_a'"))
    assert switched
    with admin.connect() as owner:
        assert owner.execute(select(audit_event.c.event_id).where(audit_event.c.resource_id == UUID(rid), audit_event.c.actor == 'actor-new')).first() is None
    assert request('GET', BASE + '/relationships/' + rid)[0] == 200


def test_controlled_get_rollback_fails_closed_and_reapply_restores(env):
    admin, _, _, _ = env
    folder = Path(__file__).parents[1] / 'schema'
    key = uuid4().hex
    rid = create(payload('getrollback-'+key, 'getrollback-target-'+key), key)[1]['relationship_id']
    with admin.connect() as conn:
        conn.exec_driver_sql((folder / 'p2_01_trusted_get_rollback_proposal.sql').read_text())
    try:
        assert request('GET', BASE + '/relationships/' + rid)[0] == 500
    finally:
        with admin.connect() as conn:
            conn.exec_driver_sql((folder / 'p2_01_trusted_get_proposal.sql').read_text())
            conn.exec_driver_sql('GRANT EXECUTE ON FUNCTION ti_security.trusted_get_relationship(uuid) TO ti_trusted_a, ti_trusted_b')
            conn.commit()
    assert request('GET', BASE + '/relationships/' + rid)[0] == 200


def test_controlled_list_and_traverse_isolated_audited_and_ordered(env):
    admin, a, b, identity = env
    token = uuid4().hex; nodes = ['n'+str(i)+token for i in range(4)]
    created = [create(payload(nodes[i], nodes[i+1], 'USES' if i < 2 else 'TARGETS'), uuid4().hex)[1] for i in range(3)]
    params = {'entity_id':nodes[1], 'entity_type':'Actor', 'limit':1, 'offset':0}
    code, page, headers = request('GET', BASE+'/relationships', query=params, include_headers=True)
    assert code == 200 and page['total'] == 2 and page['has_more'] and page['items'][0]['relationship_id'] == created[0]['relationship_id']
    params['offset']=1
    assert request('GET',BASE+'/relationships',query=params)[1]['items'][0]['relationship_id'] == created[1]['relationship_id']
    params['relationship_type']='TARGETS'
    assert request('GET',BASE+'/relationships',query=params)[1]['total'] == 0
    with admin.connect() as conn:
        event_row=conn.execute(select(audit_event).where(audit_event.c.correlation_id == UUID(headers[b'x-correlation-id'].decode()))).mappings().one()
    assert (event_row['actor'],event_row['tenant_id'],event_row['operation']) == ('actor-A','tenant-A','relationship.list')
    data={'entity_id':nodes[0], 'entity_type':'Actor','max_depth':3,'limit':1,'offset':1}
    status, page, headers=request('POST',BASE+'/relationship-analysis/traverse',data, include_headers=True)
    assert status == 200 and page['total']==3 and page['visited_entities']==4
    assert page['items'][0]['depth']==2 and page['items'][0]['relationship']['relationship_id']==created[1]['relationship_id']
    with admin.connect() as conn:
        event_row=conn.execute(select(audit_event).where(audit_event.c.correlation_id == UUID(headers[b'x-correlation-id'].decode()))).mappings().one()
    assert (event_row['actor'],event_row['tenant_id'],event_row['operation'],event_row['outcome']) == ('actor-A','tenant-A','relationship.traverse','success')
    data['relationship_types']=['USES']; data['offset']=0
    assert request('POST',BASE+'/relationship-analysis/traverse',data)[1]['total']==2
    data['relationship_types']=[]
    assert request('POST',BASE+'/relationship-analysis/traverse',data)[1]['total']==0
    identity('tenant-B','actor-B',b)
    victim = create(payload('private-'+token, 'private-target-'+token), uuid4().hex)[1]['relationship_id']
    assert request('GET',BASE+'/relationships',query={'entity_id':nodes[1], 'entity_type':'Actor'})[1]['total']==0
    status, _, headers=request('POST',BASE+'/relationship-analysis/traverse',data,include_headers=True)
    assert status==404
    with admin.connect() as conn:
        event_row=conn.execute(select(audit_event).where(audit_event.c.correlation_id == UUID(headers[b'x-correlation-id'].decode()))).mappings().one()
    assert (event_row['tenant_id'],event_row['outcome'])==('tenant-B','not_found')
    # Malicious GUC cannot change a login's bound tenant, including in a reused connection.
    with a.begin() as conn:
        conn.execute(text("SELECT set_config('cicc.tenant_id','tenant-B',true)"))
        result=conn.execute(text("SELECT ti_security.trusted_list_relationships(NULL,NULL,NULL,500,0)")).scalar_one()
        assert result['tenant']=='tenant-A' and all(item['relationship_id'] != victim for item in result['items'])
    identity()
    assert request('POST',BASE+'/relationship-analysis/traverse',{'entity_id':nodes[0],'entity_type':'Actor','max_depth':0})[1]['visited_entities']==1


def test_controlled_query_direct_sql_validation_and_missing_privileges(env):
    _, a, _, _ = env
    for sql in ["SELECT ti_security.trusted_list_relationships(NULL,NULL,NULL,501,0)",
                "SELECT ti_security.trusted_list_relationships('x',NULL,NULL,1,0)",
                "SELECT ti_security.trusted_traverse_relationships('x','Actor',9,NULL,1,0)",
                "SELECT ti_security.trusted_traverse_relationships('x','Actor',1,ARRAY[NULL]::text[],1,0)",
                'SELECT * FROM public.ti_relationship_entity', 'SELECT * FROM public.ti_relationship_record']:
        with pytest.raises(DBAPIError):
            with a.begin() as conn: conn.exec_driver_sql(sql)


def test_controlled_queries_fail_closed_on_audit_failure(env):
    admin, _, _, _ = env
    key=uuid4().hex; node='audit-list-'+key
    assert create(payload(node,'target-'+key),key)[0]==201
    with admin.begin() as conn:
        conn.exec_driver_sql("CREATE FUNCTION public.ti_test_queries_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture failure'; END $$")
        conn.exec_driver_sql('CREATE TRIGGER ti_test_queries_fail_audit BEFORE INSERT ON public.ti_relationship_audit FOR EACH ROW EXECUTE FUNCTION public.ti_test_queries_fail_audit()')
    try:
        assert request('GET',BASE+'/relationships')[0]==500
        assert request('POST',BASE+'/relationship-analysis/traverse',{'entity_id':node,'entity_type':'Actor'})[0]==500
    finally:
        with admin.begin() as conn:
            conn.exec_driver_sql('DROP TRIGGER ti_test_queries_fail_audit ON public.ti_relationship_audit')
            conn.exec_driver_sql('DROP FUNCTION public.ti_test_queries_fail_audit()')
    assert request('GET',BASE+'/relationships')[0]==200


def test_controlled_query_rollback_and_reapply(env):
    admin, _, _, _ = env
    folder=Path(__file__).parents[1]/'schema'
    with admin.connect() as conn:
        conn.exec_driver_sql((folder/'p2_01_trusted_query_rollback_proposal.sql').read_text())
    try:
        assert request('GET',BASE+'/relationships')[0]==500
        assert request('POST',BASE+'/relationship-analysis/traverse',{'entity_id':'fixture','entity_type':'Actor'})[0]==500
    finally:
        with admin.connect() as conn:
            conn.exec_driver_sql((folder/'p2_01_trusted_query_proposal.sql').read_text())
            conn.exec_driver_sql('GRANT EXECUTE ON FUNCTION ti_security.trusted_list_relationships(text,text,text,integer,integer), ti_security.trusted_traverse_relationships(text,text,integer,text[],integer,integer) TO ti_trusted_a, ti_trusted_b')
            conn.commit()
    assert request('GET',BASE+'/relationships')[0]==200


def test_traversal_limit_is_audited_without_partial_results(env):
    admin, _, _, _ = env
    key=uuid4().hex; node='cap-'+key
    created=create(payload(node,'first-'+key),key)[1]
    with admin.begin() as conn:
        conn.execute(text("INSERT INTO public.ti_relationship_entity(tenant_id,entity_type,entity_id) SELECT 'tenant-A','Actor',:prefix || i FROM generate_series(1,1000) i"), {'prefix':'cap-target-'+key+'-'})
        conn.execute(text("""INSERT INTO public.ti_relationship_record(tenant_id,relationship_id,source_type,source_id,target_type,target_id,relationship_type,fingerprint,record)
            SELECT 'tenant-A',gen_random_uuid(),'Actor',:source,'Actor',:prefix || i,'USES',md5(:prefix || i),base.record
            FROM generate_series(1,1000) i CROSS JOIN (SELECT record FROM public.ti_relationship_record WHERE relationship_id=:rid) base"""),
            {'source':node,'prefix':'cap-target-'+key+'-','rid':UUID(created['relationship_id'])})
    code, body, headers=request('POST',BASE+'/relationship-analysis/traverse',{'entity_id':node,'entity_type':'Actor'},include_headers=True)
    assert code==422 and 'items' not in body
    with admin.connect() as conn:
        row=conn.execute(select(audit_event).where(audit_event.c.correlation_id==UUID(headers[b'x-correlation-id'].decode()))).mappings().one()
    assert row['operation']=='relationship.traverse' and row['outcome']=='limit_exceeded'


def test_operation_specific_database_grants(env):
    admin, _, _, _ = env
    with admin.begin() as conn:
        conn.exec_driver_sql('CREATE ROLE ti_read_only LOGIN NOSUPERUSER NOBYPASSRLS')
        conn.exec_driver_sql("INSERT INTO ti_security.tenant_role_map VALUES ('ti_read_only','tenant-A')")
        conn.exec_driver_sql("INSERT INTO ti_security.login_actor_map VALUES ('ti_read_only','reader')")
        conn.exec_driver_sql('GRANT USAGE ON SCHEMA ti_security TO ti_read_only')
        conn.exec_driver_sql('GRANT EXECUTE ON FUNCTION ti_security.authenticated_tenant(),ti_security.authenticated_actor(),ti_security.trusted_list_relationships(text,text,text,integer,integer) TO ti_read_only')
    db=create_engine(admin.url.set(username='ti_read_only'))
    try:
        with db.begin() as conn:
            assert conn.execute(text('SELECT ti_security.trusted_list_relationships(NULL,NULL,NULL,1,0)')).scalar_one()['actor']=='reader'
        with pytest.raises(DBAPIError):
            with db.begin() as conn:
                conn.execute(text("SELECT ti_security.trusted_create_relationship('fixture', '{}'::jsonb)"))
        with pytest.raises(DBAPIError):
            with db.begin() as conn:
                conn.execute(text("SELECT ti_security.trusted_traverse_relationships('x','Actor',1,NULL,1,0)"))
    finally:
        db.dispose()


def test_malformed_stored_record_aborts_query_audit_transaction(env):
    admin, _, _, _ = env
    key=uuid4().hex; node='badrow-'+key
    created=create(payload(node,'target-'+key),key)[1]
    with admin.begin() as conn:
        conn.execute(text("UPDATE public.ti_relationship_record SET record=record-'source_entity' WHERE relationship_id=:rid"),{'rid':UUID(created['relationship_id'])})
    with admin.connect() as conn:
        before=conn.execute(select(audit_event.c.event_id).where(audit_event.c.operation.in_(['relationship.list','relationship.traverse']))).all()
    assert request('GET',BASE+'/relationships',query={'entity_id':node,'entity_type':'Actor'})[0]==500
    assert request('POST',BASE+'/relationship-analysis/traverse',{'entity_id':node,'entity_type':'Actor'})[0]==500
    with admin.connect() as conn:
        after=conn.execute(select(audit_event.c.event_id).where(audit_event.c.operation.in_(['relationship.list','relationship.traverse']))).all()
    assert before==after


def test_role_bound_pool_reuses_backend_without_tenant_guc_leak(env):
    admin, _, b, identity = env
    token=uuid4().hex
    identity('tenant-B','actor-B',b)
    victim=create(payload('pool-secret-'+token,'pool-target-'+token),token)[1]['relationship_id']
    pool=create_engine(admin.url.set(username='ti_trusted_a'),pool_size=1,max_overflow=0)
    try:
        with pool.begin() as conn:
            pid=conn.execute(text('SELECT pg_backend_pid()')).scalar_one()
            conn.execute(text("SELECT set_config('cicc.tenant_id','tenant-B',false)"))
        with pool.connect() as conn:
            assert conn.execute(text('SELECT pg_backend_pid()')).scalar_one()==pid
            assert conn.execute(text("SELECT current_setting('cicc.tenant_id')")).scalar_one()=='tenant-B'
        identity('tenant-A','actor-A',pool)
        code, data=request('GET',BASE+'/relationships',query={'entity_id':'pool-secret-'+token,'entity_type':'Actor'})
        assert code==200 and data['total']==0 and all(r['relationship_id']!=victim for r in data['items'])
        assert request('GET',BASE+'/relationships/'+victim)[0]==404
    finally:
        pool.dispose()
