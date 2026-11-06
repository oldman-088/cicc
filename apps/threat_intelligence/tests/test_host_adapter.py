"""Independent mounted host adapter + real disposable PG; not Agent 1 host.

All test identities/headers/data are EXPERIMENTAL_DEMO_DATA_ONLY fixtures.
"""
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from sqlalchemy import select
from apps.threat_intelligence.host_adapter import create_host_application
from apps.threat_intelligence.relationship_api import Principal
from apps.threat_intelligence.relationship_storage import audit_event, idempotency
from test_relationship_http import request, payload, BASE
from test_trusted_write import databases  # isolated PG schema/role fixture


@pytest.fixture
def host(databases):
    admin, a, b = databases
    links, events = [], []
    def resolve(req):
        identities = {'fixture-A': Principal(subject='actor-A',tenant_id='tenant-A',permissions=frozenset({'threat:read','threat:write'})),
                      'fixture-B': Principal(subject='actor-B',tenant_id='tenant-B',permissions=frozenset({'threat:read','threat:write'})),
                      'fixture-read': Principal(subject='actor-A',tenant_id='tenant-A',permissions=frozenset({'threat:read'})),
                      'fixture-write': Principal(subject='actor-A',tenant_id='tenant-A',permissions=frozenset({'threat:write'}))}
        return identities.get(req.headers.get('Authorization'))
    def pools(principal): return {'tenant-A':a, 'tenant-B':b}[principal.tenant_id]
    domain=create_host_application(resolve_principal=resolve,engine_for_principal=pools,security_audit=events.append,link_trace=links.append)
    app=FastAPI(); app.mount('/approved-host-prefix',domain)
    return app, admin, links, events


def call(host, method, path, body=None, identity='fixture-A', extra=None, query=None):
    headers={'Authorization':identity, **(extra or {})}
    return request(method,'/approved-host-prefix'+BASE+path,body,headers,query,application=host,include_headers=True)


def test_mounted_adapter_auth_postgres_audit_and_trace(host):
    app, admin, links, events = host
    token=uuid4().hex
    status, data, hdr=call(app,'POST','/relationships',payload('mounted-'+token,'target-'+token),extra={'Idempotency-Key':token})
    assert status==201 and UUID(hdr[b'x-correlation-id'].decode())==links[-1]
    with admin.connect() as conn:
        row=conn.execute(select(audit_event).where(audit_event.c.correlation_id==links[-1])).mappings().one()
    assert (row['tenant_id'],row['actor'],row['operation'])==('tenant-A','actor-A','relationship.create')
    assert events[-1]=={'subject':'actor-A','tenant_id':'tenant-A','action':'relationship.create.attempt'}
    rid=data['relationship_id']
    assert call(app,'GET','/relationships/'+rid)[0]==200
    assert call(app,'GET','/relationships/'+rid,identity='fixture-B')[0]==404
    assert call(app,'GET','/relationships',query={'entity_id':'mounted-'+token,'entity_type':'Actor'})[1]['total']==1
    assert call(app,'POST','/relationship-analysis/traverse',{'entity_id':'mounted-'+token,'entity_type':'Actor'})[1]['total']==1
    assert call(app,'GET','/relationships',identity='invalid')[0]==401
    assert call(app,'POST','/relationships',payload(),identity='fixture-read',extra={'Idempotency-Key':'fixture'})[0]==403


def test_forged_input_and_error_redaction(host):
    app, _, _, _ = host
    body=payload();body['tenant_id']='tenant-B';body['sensitive_fixture']='SECRET_FIXTURE'
    code, data, _=call(app,'POST','/relationships',body,extra={'Idempotency-Key':uuid4().hex})
    assert code==422 and data=={'detail':'Invalid request'} and 'SECRET_FIXTURE' not in str(data)
    code, data, _=call(app,'GET','/relationships/not-a-uuid')
    assert code==422 and data=={'detail':'Invalid request'}


def test_per_request_pool_selection_concurrent(host):
    app, _, _, _=host; token=uuid4().hex
    def write(identity):
        return call(app,'POST','/relationships',payload('race-'+token,'race-target-'+token),identity=identity,extra={'Idempotency-Key':'key-'+token})
    with ThreadPoolExecutor(max_workers=2) as executor:
        first,second=list(executor.map(write, ['fixture-A','fixture-B']))
    assert first[0]==second[0]==201 and first[1]['relationship_id']!=second[1]['relationship_id']
    assert call(app,'GET','/relationships/'+first[1]['relationship_id'],identity='fixture-B')[0]==404
    assert call(app,'GET','/relationships/'+second[1]['relationship_id'],identity='fixture-A')[0]==404


def test_trace_failure_reports_unavailable_after_commit(databases):
    admin, a, _=databases
    def resolve(req): return Principal(subject='actor-A',tenant_id='tenant-A',permissions=frozenset({'threat:write'}))
    def broken(_): raise RuntimeError('SECRET_FIXTURE')
    app=FastAPI(); app.mount('/approved-host-prefix',create_host_application(resolve_principal=resolve,engine_for_principal=lambda _:a,security_audit=lambda _:None,link_trace=broken))
    key=uuid4().hex
    code, body, headers=call(app,'POST','/relationships',payload('trace-'+key,'target-'+key),extra={'Idempotency-Key':key})
    assert code==503 and 'SECRET_FIXTURE' not in str(body)
    corr=UUID(headers[b'x-correlation-id'].decode())
    with admin.connect() as conn:
        rid=conn.execute(select(idempotency.c.relationship_id).where(idempotency.c.tenant_id=='tenant-A',idempotency.c.key==key)).scalar_one()
        row=conn.execute(select(audit_event).where(audit_event.c.correlation_id==corr)).mappings().one()
        assert row['resource_id']==rid and row['outcome']=='created'
    recovered=FastAPI()
    recovered.mount('/approved-host-prefix',create_host_application(resolve_principal=resolve,engine_for_principal=lambda _:a,security_audit=lambda _:None,link_trace=lambda _:None))
    retry, body, _=call(recovered,'POST','/relationships',payload('trace-'+key,'target-'+key),extra={'Idempotency-Key':key})
    assert retry==200 and UUID(body['relationship_id'])==rid


def test_timeout_and_bad_callbacks_fail_closed(databases):
    import asyncio
    _, a, _=databases
    async def slow(_): await asyncio.sleep(1)
    domain=create_host_application(
        resolve_principal=lambda _:Principal(subject='actor-A',tenant_id='tenant-A',permissions=frozenset({'threat:read'})),
        engine_for_principal=lambda _:a,security_audit=lambda _:None,link_trace=slow,trace_timeout_seconds=0.01)
    app=FastAPI(); app.mount('/approved-host-prefix',domain)
    code, data, headers=call(app,'GET','/relationships')
    assert code==503 and data=={'detail':'Trace integration unavailable'} and UUID(headers[b'x-correlation-id'].decode())
    with pytest.raises(TypeError):
        create_host_application(resolve_principal=lambda _:None,engine_for_principal=lambda _:a,security_audit=lambda _:None,link_trace=None)
    with pytest.raises(ValueError):
        create_host_application(resolve_principal=lambda _:None,engine_for_principal=lambda _:a,security_audit=lambda _:None,link_trace=lambda _:None,trace_timeout_seconds=float('nan'))


def test_awaitable_security_audit_cannot_silently_skip(host, databases):
    _, a, _=databases
    class BadAudit:
        async def __call__(self, event): pass
    domain=create_host_application(resolve_principal=lambda _:Principal(subject='actor-A',tenant_id='tenant-A',permissions=frozenset({'threat:read'})),
        engine_for_principal=lambda _:a,security_audit=BadAudit(),link_trace=lambda _:None)
    app=FastAPI(); app.mount('/approved-host-prefix',domain)
    assert call(app,'GET','/relationships')[0]==503


def test_security_events_for_rejections_are_metadata_only(host):
    app, _, _, events=host
    assert call(app,'GET','/relationships',identity='invalid')[0]==401
    assert events[-1]=={'action':'host.security.response','status':401}
    assert call(app,'POST','/relationships',payload(),identity='fixture-read',extra={'Idempotency-Key':uuid4().hex})[0]==403
    assert events[-1]=={'action':'host.security.response','status':403,'subject':'actor-A','tenant_id':'tenant-A'}
    bad=payload(); bad['tenant_id']='SENSITIVE_FIXTURE_BODY'
    assert call(app,'POST','/relationships',bad,extra={'Idempotency-Key':uuid4().hex})[0]==422
    assert events[-1]['action']=='host.security.response' and events[-1]['status']==422
    assert 'SENSITIVE_FIXTURE_BODY' not in str(events[-1])


def test_security_event_failure_never_reports_success(databases):
    _, a, _=databases
    def audit(_): raise RuntimeError('SECRET_FIXTURE')
    domain=create_host_application(resolve_principal=lambda _:None,engine_for_principal=lambda _:a,security_audit=audit,link_trace=lambda _:None)
    app=FastAPI();app.mount('/approved-host-prefix',domain)
    status, body, _=call(app,'GET','/relationships')
    assert status==503 and body=={'detail':'Security audit unavailable'} and 'SECRET_FIXTURE' not in str(body)


def test_database_identity_failure_emits_sanitized_security_event(databases):
    _, a, _=databases; events=[]
    domain=create_host_application(resolve_principal=lambda _:Principal(subject='wrong-actor',tenant_id='tenant-A',permissions=frozenset({'threat:read'})),
        engine_for_principal=lambda _:a,security_audit=events.append,link_trace=lambda _:None)
    app=FastAPI();app.mount('/approved-host-prefix',domain)
    status, body, _=call(app,'GET','/relationships')
    assert status==500 and body=={'detail':'Internal server error'}
    assert events[-1]=={'action':'host.security.response','status':500,'subject':'wrong-actor','tenant_id':'tenant-A'}


def test_trace_and_failure_audit_outage_preserves_committed_correlation(databases):
    admin, a, _=databases
    def audit(event):
        if event['action']=='host.security.response': raise RuntimeError('fixture sink down')
    def trace(_): raise RuntimeError('fixture trace down')
    domain=create_host_application(resolve_principal=lambda _:Principal(subject='actor-A',tenant_id='tenant-A',permissions=frozenset({'threat:write'})),
        engine_for_principal=lambda _:a,security_audit=audit,link_trace=trace)
    app=FastAPI();app.mount('/approved-host-prefix',domain)
    token=uuid4().hex
    code, body, headers=call(app,'POST','/relationships',payload('trace-audit-'+token,'trace-target-'+token),extra={'Idempotency-Key':token})
    assert code==503 and body=={'detail':'Security audit unavailable'}
    corr=UUID(headers[b'x-correlation-id'].decode())
    with admin.connect() as conn:
        assert conn.execute(select(audit_event.c.event_id).where(audit_event.c.correlation_id==corr,audit_event.c.outcome=='created')).one()


def test_caller_supplied_correlation_cannot_impersonate_trace(host):
    app, admin, links, _=host
    key=uuid4().hex; forged=uuid4()
    status, body, headers=call(app,'POST','/relationships',payload('forged-'+key,'target-'+key),
        extra={'Idempotency-Key':key, 'X-Correlation-ID':str(forged)})
    assert status==201
    actual=UUID(headers[b'x-correlation-id'].decode())
    assert actual != forged and links[-1]==actual
    with admin.connect() as conn:
        assert conn.execute(select(audit_event.c.event_id).where(audit_event.c.correlation_id==actual)).one()


def test_host_resolver_and_pool_timeouts_fail_closed(databases):
    import asyncio
    _, a, _=databases
    async def slow(_): await asyncio.sleep(1)
    events=[]
    kwargs=dict(security_audit=events.append,link_trace=lambda _:None,dependency_timeout_seconds=0.01)
    app=FastAPI();app.mount('/approved-host-prefix',create_host_application(resolve_principal=slow,engine_for_principal=lambda _:a,**kwargs))
    status, body, _=call(app,'GET','/relationships')
    assert status==503 and body=={'detail':'Authentication unavailable'}
    assert events[-1]=={'action':'host.security.response','status':503}
    app=FastAPI();app.mount('/approved-host-prefix',create_host_application(resolve_principal=lambda _:Principal(subject='actor-A',tenant_id='tenant-A',permissions=frozenset({'threat:read'})),engine_for_principal=slow,**kwargs))
    status, body, _=call(app,'GET','/relationships')
    assert status==503 and body=={'detail':'Relationship storage unavailable'}
    assert events[-1]['subject']=='actor-A' and events[-1]['status']==503


def test_host_failure_audit_timeout_fails_closed(databases):
    import time
    _, a, _=databases
    def slow(_): time.sleep(0.1)
    domain=create_host_application(resolve_principal=lambda _:None,engine_for_principal=lambda _:a,security_audit=slow,link_trace=lambda _:None,dependency_timeout_seconds=0.01)
    app=FastAPI();app.mount('/approved-host-prefix',domain)
    code, body, _=call(app,'GET','/relationships')
    assert code==503 and body=={'detail':'Security audit unavailable'}


def test_read_denied_for_write_only_and_forged_tenant_headers(host):
    app, _, _, events=host
    token=uuid4().hex; node='tenant-forgery-'+token
    created=call(app,'POST','/relationships',payload(node,'target-'+token),extra={'Idempotency-Key':token})[1]
    assert call(app,'GET','/relationships',identity='fixture-write')[0]==403
    assert call(app,'POST','/relationship-analysis/traverse',{'entity_id':node,'entity_type':'Actor'},identity='fixture-write')[0]==403
    assert events[-1]['status']==403 and events[-1]['tenant_id']=='tenant-A'
    status, page, _=call(app,'GET','/relationships',query={'entity_id':node,'entity_type':'Actor','tenant_id':'tenant-B'},
                         extra={'X-Tenant-ID':'tenant-B','X-Actor-ID':'actor-B'})
    assert status==200 and page['total']==1 and page['items'][0]['relationship_id']==created['relationship_id']


def test_mounted_adapter_database_audit_failure_rolls_back(host):
    app, admin, _, _=host
    key=uuid4().hex; data=payload('host-audit-rollback-'+key,'target-'+key)
    with admin.begin() as conn:
        conn.exec_driver_sql("CREATE FUNCTION public.ti_host_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture failure'; END $$")
        conn.exec_driver_sql('CREATE TRIGGER ti_host_audit_failure BEFORE INSERT ON public.ti_relationship_audit FOR EACH ROW EXECUTE FUNCTION public.ti_host_audit_failure()')
    try:
        status, body, _=call(app,'POST','/relationships',data,extra={'Idempotency-Key':key})
        assert status==500 and body=={'detail':'Internal server error'}
    finally:
        with admin.begin() as conn:
            conn.exec_driver_sql('DROP TRIGGER ti_host_audit_failure ON public.ti_relationship_audit')
            conn.exec_driver_sql('DROP FUNCTION public.ti_host_audit_failure()')
    with admin.connect() as conn:
        assert conn.execute(select(idempotency.c.key).where(idempotency.c.tenant_id=='tenant-A',idempotency.c.key==key)).first() is None
    assert call(app,'POST','/relationships',data,extra={'Idempotency-Key':key})[0]==201


def test_disposable_db_owner_can_modify_audit_so_not_admin_resistant(host):
    app, admin, _, _=host; key=uuid4().hex
    status, _, headers=call(app,'POST','/relationships',payload('admin-boundary-'+key,'target-'+key),extra={'Idempotency-Key':key})
    assert status==201
    correlation=UUID(headers[b'x-correlation-id'].decode())
    # Intentional privileged tamper against only this disposable test DB row.
    with admin.begin() as conn:
        updated=conn.execute(audit_event.update().where(audit_event.c.correlation_id==correlation).values(actor='EXPERIMENTAL_DEMO_DATA_ONLY_admin_fixture'))
        assert updated.rowcount==1
    with admin.connect() as conn:
        assert conn.execute(select(audit_event.c.actor).where(audit_event.c.correlation_id==correlation)).scalar_one()=='EXPERIMENTAL_DEMO_DATA_ONLY_admin_fixture'


def test_quality_library_does_not_publish_unapproved_routes_or_change_adapter(host):
    from datetime import timedelta
    from apps.threat_intelligence.vulnerability_quality import quality_json_for_version
    from test_vulnerability_quality import inventory, obs, CVE, NOW
    app, _, _, _=host
    data=quality_json_for_version('cicc.vulnerability-quality/1',inventory(),[obs(1,'NVD',CVE)],[],as_of=NOW,max_observation_age=timedelta(days=1))
    assert 'cicc.vulnerability-quality/1' in data
    assert call(app,'GET','/vulnerability-quality')[0]==404
    assert call(app,'GET','/kev-conflicts/1')[0]==404
    # Existing mounted relationship adapter still enforces its authentication.
    assert call(app,'GET','/relationships',identity='invalid')[0]==401
