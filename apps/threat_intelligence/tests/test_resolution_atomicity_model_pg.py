"""Test-only transactional model in disposable PG, not a production resolution API.

Actor, audit and permissions here are synthetic, not trusted host identities.
"""
from concurrent.futures import ThreadPoolExecutor
import pytest
from sqlalchemy import text
from apps.threat_intelligence.cisa_kev_persistence import persist_catalog
from apps.threat_intelligence.cisa_kev_snapshot import inspect_conflict
from apps.threat_intelligence.cisa_github_collector import verify_source_bytes
from test_cisa_kev_persistence import db,collected
from test_cisa_github_collector import sample

@pytest.fixture
def model(db):
    original=collected(sample());persist_catalog(db,original)
    item=sample();item['vulnerabilities'][0]['product']='EXPERIMENTAL_DEMO_DATA_ONLY conflicting fixture'
    result=persist_catalog(db,collected(item))
    with db.begin() as c:
        c.exec_driver_sql('CREATE TABLE ti_kev.test_head (id bigint PRIMARY KEY, version integer NOT NULL)')
        c.exec_driver_sql('CREATE TABLE ti_kev.test_event (conflict_id bigint, version integer, rationale text)')
        c.exec_driver_sql('CREATE TABLE ti_kev.test_audit (conflict_id bigint, version integer, actor text)')
        c.execute(text('INSERT INTO ti_kev.test_head VALUES (:id, 0)'),{'id':result.conflict_id})
    inspection=inspect_conflict(db,origin=original.origin,conflict_id=result.conflict_id)
    return db,inspection


def transact(engine, conflict_id, expected, fail_audit=False):
    with engine.begin() as c:
        version=c.execute(text('UPDATE ti_kev.test_head SET version=version+1 WHERE id=:id AND version=:expected RETURNING version'),
                          {'id':conflict_id,'expected':expected}).scalar_one_or_none()
        if version is None: return False
        c.execute(text("INSERT INTO ti_kev.test_event VALUES (:id,:v,'EXPERIMENTAL_DEMO_DATA_ONLY rationale')"),{'id':conflict_id,'v':version})
        if fail_audit: raise RuntimeError('EXPERIMENTAL_DEMO_DATA_ONLY injected audit failure')
        c.execute(text("INSERT INTO ti_kev.test_audit VALUES (:id,:v,'EXPERIMENTAL_DEMO_DATA_ONLY actor')"),{'id':conflict_id,'v':version})
        return True


def counts(engine):
    with engine.connect() as c:
        return c.execute(text('SELECT (SELECT version FROM ti_kev.test_head), (SELECT count(*) FROM ti_kev.test_event), (SELECT count(*) FROM ti_kev.test_audit)')).one()


def test_audit_failure_rolls_back_head_and_event_and_preserves_original_bytes(model):
    engine,i=model; old=verify_source_bytes(i['previous']);new=verify_source_bytes(i['candidate'])
    with pytest.raises(RuntimeError): transact(engine,i['conflict_id'],0,fail_audit=True)
    assert counts(engine)==(0,0,0)
    after=inspect_conflict(engine,origin=i['origin'],conflict_id=i['conflict_id'])
    assert verify_source_bytes(after['previous'])==old and verify_source_bytes(after['candidate'])==new
    assert transact(engine,i['conflict_id'],0) and counts(engine)==(1,1,1)


def test_atomic_head_compare_serializes_conflicting_parallel_drafts(model):
    engine,i=model
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes=list(pool.map(lambda _:transact(engine,i['conflict_id'],0),range(2)))
    assert sorted(outcomes)==[False,True]
    assert counts(engine)==(1,1,1)
