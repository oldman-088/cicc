"""Disposable PostgreSQL persistence; all synthetic content is EXPERIMENTAL_DEMO_DATA_ONLY."""
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pytest
from sqlalchemy import create_engine, text
from apps.threat_intelligence.cisa_github_collector import CollectionError, fetch_catalog
from apps.threat_intelligence.cisa_kev_persistence import persist_catalog, run_once, StaleCatalogError
from test_cisa_github_collector import sample, fixture_transport

@pytest.fixture
def db(tmp_path_factory):
    if os.getenv('CICC_TEST_PG_EMBEDDED') != '1':
        pytest.skip('set CICC_TEST_PG_EMBEDDED=1 for isolated PostgreSQL tests')
    pgserver=pytest.importorskip('pgserver'); pytest.importorskip('psycopg')
    server=pgserver.get_server(tmp_path_factory.mktemp('ti-kev'),cleanup_mode='stop')
    engine=create_engine(server.get_uri().replace('postgresql://','postgresql+psycopg://',1),pool_size=8)
    path=Path(__file__).parents[1]/'schema'/'p2_02_kev_storage_proposal.sql'
    with engine.connect() as conn: conn.exec_driver_sql(path.read_text())
    yield engine
    engine.dispose(); server.cleanup()


def collected(data):
    transport,_=fixture_transport(data)
    return fetch_catalog(transport=transport, sleep=lambda _:None, min_interval=0)


def counts(db):
    with db.connect() as conn:
        return tuple(conn.execute(text('SELECT (SELECT count(*) FROM ti_kev.snapshot),(SELECT count(*) FROM ti_kev.revision),(SELECT count(*) FROM ti_kev.snapshot_entry)')).one())


def test_snapshot_and_incremental_history(db):
    data=sample(); first=collected(data)
    assert first.origin=='EXPERIMENTAL_DEMO_DATA_ONLY'
    before=counts(db); result=persist_catalog(db,first)
    assert (result.outcome,result.added,result.changed,result.removed)==('created',1,0,0)
    assert tuple(x-y for x,y in zip(counts(db),before))==(1,1,1)
    assert persist_catalog(db,first).outcome=='unchanged'
    assert tuple(x-y for x,y in zip(counts(db),before))==(1,1,1)
    data['dateReleased']='2026-01-02T00:00:00Z'
    data['vulnerabilities'][0]['product']='updated fixture'
    other=dict(data['vulnerabilities'][0]);other['cveID']='CVE-2099-0002';data['vulnerabilities'].append(other);data['count']=2
    update=persist_catalog(db,collected(data))
    assert (update.outcome,update.added,update.changed,update.removed)==('created',1,1,0)
    data['dateReleased']='2026-01-03T00:00:00Z'; data['vulnerabilities'].pop(0);data['count']=1
    removal=persist_catalog(db,collected(data))
    assert (removal.added,removal.changed,removal.removed)==(0,0,1)
    with db.connect() as conn:
        row=conn.execute(text('SELECT origin,entry_count,source_url,collected_at,released_at FROM ti_kev.snapshot WHERE id=:id'),{'id':removal.snapshot_id}).mappings().one()
        assert row['origin']=='EXPERIMENTAL_DEMO_DATA_ONLY' and row['entry_count']==1 and row['collected_at'].tzinfo and row['released_at'].tzinfo
        assert conn.execute(text('SELECT count(*) FROM ti_kev.snapshot_entry WHERE snapshot_id=:id'),{'id':result.snapshot_id}).scalar_one()==1


def test_stale_and_invalid_collection_never_replace_last_snapshot(db):
    newer=sample(); newer['dateReleased']='2026-01-03T00:00:00Z'
    persist_catalog(db,collected(newer))
    before=counts(db)
    with pytest.raises(StaleCatalogError): persist_catalog(db,collected(sample()))
    bad=sample();bad['count']=2
    with pytest.raises(CollectionError): collected(bad)
    dup=sample();dup['vulnerabilities'].append(dup['vulnerabilities'][0]);dup['count']=2
    with pytest.raises(CollectionError): collected(dup)
    assert counts(db)==before


def test_atomic_rollback_and_recovery(db):
    data=sample();data['dateReleased']='2026-01-04T00:00:00Z';data['vulnerabilities'][0]['product']='rollback fixture'
    item=collected(data); before=counts(db)
    with db.begin() as conn:
        conn.exec_driver_sql("CREATE FUNCTION ti_kev.test_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$")
        conn.exec_driver_sql('CREATE TRIGGER test_fail BEFORE INSERT ON ti_kev.snapshot_entry FOR EACH ROW EXECUTE FUNCTION ti_kev.test_fail()')
    try:
        with pytest.raises(Exception): persist_catalog(db,item)
    finally:
        with db.begin() as conn:
            conn.exec_driver_sql('DROP TRIGGER test_fail ON ti_kev.snapshot_entry');conn.exec_driver_sql('DROP FUNCTION ti_kev.test_fail()')
    assert counts(db)==before
    assert persist_catalog(db,item).outcome=='created'


def test_concurrent_idempotence(db):
    data=sample();data['dateReleased']='2026-01-05T00:00:00Z'; item=collected(data);before=counts(db)
    with ThreadPoolExecutor(max_workers=6) as pool: results=list(pool.map(lambda _:persist_catalog(db,item),range(6)))
    assert [r.outcome for r in results].count('created')==1
    assert [r.outcome for r in results].count('unchanged')==5
    assert len({r.snapshot_id for r in results})==1
    assert counts(db)[0]==before[0]+1


def test_failure_before_persist_does_not_change_db(db,monkeypatch):
    import apps.threat_intelligence.cisa_github_collector as collector
    before=counts(db)
    def fail(): raise CollectionError('network unavailable')
    monkeypatch.setattr(collector,'fetch_catalog',fail)
    with pytest.raises(CollectionError): run_once(db)
    assert counts(db)==before


def test_live_collection_persistence(db):
    if os.getenv('CICC_TEST_LIVE_CISA_GITHUB') != '1':
        pytest.skip('live source test not enabled')
    result=run_once(db)
    with db.connect() as conn:
        row=conn.execute(text('SELECT origin,entry_count FROM ti_kev.snapshot WHERE id=:id'),{'id':result.snapshot_id}).mappings().one()
        count=conn.execute(text('SELECT count(*) FROM ti_kev.snapshot_entry WHERE snapshot_id=:id'),{'id':result.snapshot_id}).scalar_one()
    assert row['origin']=='FETCHED_FROM_GITHUB_CISA_REPO' and row['entry_count']==count>0


def test_least_privilege_worker_cannot_rewrite_or_delete_history(db):
    with db.begin() as conn:
        conn.exec_driver_sql('CREATE ROLE ti_kev_worker LOGIN NOSUPERUSER NOBYPASSRLS')
        conn.exec_driver_sql('GRANT USAGE ON SCHEMA ti_kev TO ti_kev_worker')
        conn.exec_driver_sql('GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA ti_kev TO ti_kev_worker')
        conn.exec_driver_sql('GRANT UPDATE (checked_at) ON ti_kev.snapshot TO ti_kev_worker')
        conn.exec_driver_sql('GRANT USAGE ON ALL SEQUENCES IN SCHEMA ti_kev TO ti_kev_worker')
    worker=create_engine(db.url.set(username='ti_kev_worker'))
    try:
        data=sample();data['dateReleased']='2026-01-06T00:00:00Z';data['vulnerabilities'][0]['product']='worker fixture'
        item=collected(data)
        assert persist_catalog(worker,item).outcome=='created'
        assert persist_catalog(worker,item).outcome=='unchanged'
        for sql in ['DELETE FROM ti_kev.snapshot', "UPDATE ti_kev.revision SET record='{}'::jsonb", 'UPDATE ti_kev.snapshot SET origin=\'FETCHED_FROM_GITHUB_CISA_REPO\'']:
            with pytest.raises(Exception):
                with worker.begin() as conn: conn.exec_driver_sql(sql)
    finally:
        worker.dispose()


def test_isolated_schema_rollback_and_reapply(db):
    # Destructive rollback is exercised only in a fresh disposable server.
    folder=Path(__file__).parents[1]/'schema'
    assert persist_catalog(db,collected(sample())).outcome=='created'
    with db.connect() as conn:
        conn.exec_driver_sql((folder/'p2_02_kev_storage_rollback_proposal.sql').read_text())
        conn.exec_driver_sql((folder/'p2_02_kev_storage_proposal.sql').read_text())
    assert counts(db)==(0,0,0)
    assert persist_catalog(db,collected(sample())).outcome=='created'
