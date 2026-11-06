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
    with engine.connect() as conn:
        conn.exec_driver_sql(path.read_text())
        conn.exec_driver_sql((path.parent/'p2_03_kev_metadata_proposal.sql').read_text())
        conn.exec_driver_sql((path.parent/'p2_04_kev_blob_proposal.sql').read_text())
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
    from apps.threat_intelligence.cisa_kev_snapshot import load_snapshot
    loaded=load_snapshot(db,origin='FETCHED_FROM_GITHUB_CISA_REPO',snapshot_id=result.snapshot_id)
    assert loaded.catalog.count==count and loaded.origin=='FETCHED_FROM_GITHUB_CISA_REPO'


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
        for sql in ['DELETE FROM ti_kev.snapshot', "UPDATE ti_kev.revision SET record='{}'::jsonb", "UPDATE ti_kev.source_blob SET source_bytes=decode('00','hex')", 'DELETE FROM ti_kev.source_blob', 'UPDATE ti_kev.snapshot SET origin=\'FETCHED_FROM_GITHUB_CISA_REPO\'']:
            with pytest.raises(Exception):
                with worker.begin() as conn: conn.exec_driver_sql(sql)
    finally:
        worker.dispose()


def test_isolated_schema_rollback_and_reapply(db):
    # Destructive rollback is exercised only in a fresh disposable server.
    folder=Path(__file__).parents[1]/'schema'
    assert persist_catalog(db,collected(sample())).outcome=='created'
    with db.connect() as conn:
        conn.exec_driver_sql((folder/'p2_04_kev_blob_rollback_proposal.sql').read_text())
        conn.exec_driver_sql((folder/'p2_03_kev_metadata_rollback_proposal.sql').read_text())
        conn.exec_driver_sql((folder/'p2_02_kev_storage_rollback_proposal.sql').read_text())
        conn.exec_driver_sql((folder/'p2_02_kev_storage_proposal.sql').read_text())
        conn.exec_driver_sql((folder/'p2_03_kev_metadata_proposal.sql').read_text())
        conn.exec_driver_sql((folder/'p2_04_kev_blob_proposal.sql').read_text())
    assert counts(db)==(0,0,0)
    assert persist_catalog(db,collected(sample())).outcome=='created'


def test_health_distinguishes_never_overdue_and_future(db):
    from datetime import timedelta, datetime, timezone
    from apps.threat_intelligence.cisa_kev_health import check_health
    origin='EXPERIMENTAL_DEMO_DATA_ONLY'; item=collected(sample())
    assert check_health(db,origin=origin,as_of=item.collected_at,max_check_age=timedelta(hours=1)).status=='never_collected'
    result=persist_catalog(db,item)
    state=check_health(db,origin=origin,as_of=item.collected_at+timedelta(hours=1),max_check_age=timedelta(hours=1))
    assert state.status=='within_check_window' and state.snapshot_id==result.snapshot_id and state.entry_count==1
    assert check_health(db,origin=origin,as_of=item.collected_at+timedelta(hours=1,seconds=1),max_check_age=timedelta(hours=1)).status=='check_overdue'
    assert check_health(db,origin=origin,as_of=item.collected_at-timedelta(seconds=1),max_check_age=timedelta(hours=1)).status=='future_check_time'
    earlier=datetime(2025,1,1,tzinfo=timezone.utc)
    assert check_health(db,origin=origin,as_of=earlier,max_check_age=timedelta(hours=1)).source_release_in_future is True
    assert check_health(db,origin='FETCHED_FROM_GITHUB_CISA_REPO',as_of=item.collected_at,max_check_age=timedelta(hours=1)).status=='never_collected'
    with pytest.raises(ValueError): check_health(db,origin=origin,as_of=datetime(2026,1,1),max_check_age=timedelta(hours=1))
    with pytest.raises(ValueError): check_health(db,origin=origin,as_of=item.collected_at,max_check_age=timedelta(0))
    with pytest.raises(ValueError): check_health(db,origin='invalid',as_of=item.collected_at,max_check_age=timedelta(hours=1))


def test_snapshot_roundtrip_feeds_offline_correlation(db):
    from apps.threat_intelligence.cisa_kev_snapshot import load_snapshot
    from apps.threat_intelligence.kev_correlation import correlate_kev
    from apps.threat_intelligence.relationship_analysis import EntityReference
    from test_intelligence_assessment import record
    from datetime import timedelta
    data=sample();data['newCatalogField']='preserved top-level field'
    original=collected(data); saved=persist_catalog(db,original)
    loaded=load_snapshot(db,origin='EXPERIMENTAL_DEMO_DATA_ONLY',snapshot_id=saved.snapshot_id)
    assert loaded.catalog.model_extra['newCatalogField']=='preserved top-level field'
    assert loaded.catalog.vulnerabilities[0].model_extra['futureField']=='preserved'
    assert loaded.github_blob_sha==original.github_blob_sha and loaded.content_sha256==original.content_sha256
    rel=record(101);rel.target_entity=EntityReference(entity_type='CVE',entity_id='CVE-2099-0001')
    result=correlate_kev([rel],loaded,as_of=loaded.collected_at,evidence_max_age=timedelta(days=1),catalog_max_age=timedelta(days=1),cve_entity_types={'CVE'})
    assert len(result.matches)==1 and result.origin=='EXPERIMENTAL_DEMO_DATA_ONLY'
    assert result.matches[0].kev_entry.cveID=='CVE-2099-0001'


def test_snapshot_missing_metadata_or_wrong_origin_fails_closed(db):
    from apps.threat_intelligence.cisa_kev_snapshot import load_snapshot, SnapshotUnavailable
    item=collected(sample()); result=persist_catalog(db,item)
    with pytest.raises(SnapshotUnavailable): load_snapshot(db,origin='FETCHED_FROM_GITHUB_CISA_REPO',snapshot_id=result.snapshot_id)
    with db.begin() as conn: conn.execute(text('DELETE FROM ti_kev.catalog_metadata WHERE snapshot_id=:id'),{'id':result.snapshot_id})
    with pytest.raises(SnapshotUnavailable): load_snapshot(db,origin=item.origin,snapshot_id=result.snapshot_id)
    # An identical complete, integrity-checked synthetic fixture fetch backfills legacy metadata.
    assert persist_catalog(db,item).outcome=='unchanged'
    assert load_snapshot(db,origin=item.origin).catalog.count==1


def test_snapshot_detects_corrupted_revision(db):
    from apps.threat_intelligence.cisa_kev_snapshot import load_snapshot, SnapshotUnavailable
    item=collected(sample()); persist_catalog(db,item)
    # Only isolated privileged fault injection; restricted worker cannot UPDATE.
    with db.begin() as conn:
        conn.execute(text("UPDATE ti_kev.revision SET record=jsonb_set(record,'{product}',to_jsonb('altered fixture'::text))"))
    with pytest.raises(SnapshotUnavailable,match='integrity'):
        load_snapshot(db,origin=item.origin)


def test_source_blob_is_exact_and_forged_catalog_is_rejected(db):
    from apps.threat_intelligence.cisa_github_collector import CollectionError, CollectedCatalog
    from apps.threat_intelligence.cisa_kev_snapshot import load_snapshot
    item=collected(sample()); before=counts(db)
    # A JSON/model reconstruction lacks original bytes; it cannot masquerade as
    # a validated source fetch. Both fixture origin and fake data remain labeled.
    detached=CollectedCatalog.model_validate(item.model_dump())
    with pytest.raises(CollectionError,match='bytes unavailable'):
        persist_catalog(db,detached)
    assert counts(db)==before
    altered_catalog=item.catalog.model_copy(update={'title':'different fixture'})
    forged=item.model_copy(update={'catalog':altered_catalog})
    with pytest.raises(CollectionError,match='metadata does not match'):
        persist_catalog(db,forged)
    result=persist_catalog(db,item)
    loaded=load_snapshot(db,origin=item.origin,snapshot_id=result.snapshot_id)
    assert loaded._source_bytes==item._source_bytes
    assert '_source_bytes' not in loaded.model_dump() and '_source_bytes' not in loaded.model_dump_json()


def test_blob_corruption_detected_and_missing_blob_backfilled(db):
    from apps.threat_intelligence.cisa_kev_snapshot import load_snapshot, SnapshotUnavailable
    item=collected(sample()); result=persist_catalog(db,item)
    with db.begin() as conn:
        conn.execute(text("UPDATE ti_kev.source_blob SET source_bytes=decode('00','hex') WHERE origin=:origin"),{'origin':item.origin})
    with pytest.raises(SnapshotUnavailable,match='blob integrity'): load_snapshot(db,origin=item.origin)
    with pytest.raises(ValueError,match='stored source blob'): persist_catalog(db,item)
    # Deletion is test-only: production restricted worker has no DELETE grant.
    with db.begin() as conn: conn.execute(text('DELETE FROM ti_kev.source_blob WHERE origin=:origin'),{'origin':item.origin})
    with pytest.raises(SnapshotUnavailable,match='unavailable'): load_snapshot(db,origin=item.origin)
    assert persist_catalog(db,item).outcome=='unchanged'
    assert load_snapshot(db,origin=item.origin,snapshot_id=result.snapshot_id)._source_bytes==item._source_bytes


def test_blob_rolls_back_with_snapshot_on_failure(db):
    item=collected(sample())
    with db.begin() as conn:
        conn.exec_driver_sql("CREATE FUNCTION ti_kev.test_blob_rollback() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$")
        conn.exec_driver_sql('CREATE TRIGGER test_blob_rollback BEFORE INSERT ON ti_kev.snapshot FOR EACH ROW EXECUTE FUNCTION ti_kev.test_blob_rollback()')
    try:
        with pytest.raises(Exception): persist_catalog(db,item)
    finally:
        with db.begin() as conn:
            conn.exec_driver_sql('DROP TRIGGER test_blob_rollback ON ti_kev.snapshot')
            conn.exec_driver_sql('DROP FUNCTION ti_kev.test_blob_rollback()')
    with db.connect() as conn:
        assert conn.execute(text('SELECT count(*) FROM ti_kev.source_blob')).scalar_one()==0
    assert persist_catalog(db,item).outcome=='created'


def test_rehashed_normalized_tampering_still_disagrees_with_original_blob(db):
    import hashlib, json
    from apps.threat_intelligence.cisa_kev_snapshot import load_snapshot, SnapshotUnavailable
    item=collected(sample()); result=persist_catalog(db,item)
    with db.begin() as conn:
        row=conn.execute(text('SELECT origin,cve_id,record FROM ti_kev.revision')).mappings().one()
        changed=dict(row['record'], product='EXPERIMENTAL_DEMO_DATA_ONLY tampered fixture')
        encoded=json.dumps(changed,sort_keys=True,ensure_ascii=False,separators=(',',':'))
        digest=hashlib.sha256(encoded.encode()).hexdigest()
        conn.execute(text('INSERT INTO ti_kev.revision(origin,cve_id,content_sha256,record) VALUES (:origin,:cve,:digest,CAST(:record AS jsonb))'),
                     {'origin':row['origin'],'cve':row['cve_id'],'digest':digest,'record':encoded})
        conn.execute(text('UPDATE ti_kev.snapshot_entry SET content_sha256=:digest WHERE snapshot_id=:id'),{'digest':digest,'id':result.snapshot_id})
    with pytest.raises(SnapshotUnavailable,match='blob integrity'):
        load_snapshot(db,origin=item.origin)


def test_unchanged_fetch_detects_corruption_before_advancing_health(db):
    from datetime import timedelta
    from apps.threat_intelligence.cisa_kev_persistence import SnapshotIntegrityError
    from apps.threat_intelligence.cisa_kev_health import check_health
    item=collected(sample()); result=persist_catalog(db,item)
    with db.begin() as conn:
        conn.execute(text("UPDATE ti_kev.revision SET record=jsonb_set(record,'{product}',to_jsonb('broken fixture'::text))"))
    later=item.model_copy(update={'collected_at':item.collected_at+timedelta(hours=2)})
    with pytest.raises(SnapshotIntegrityError): persist_catalog(db,later)
    health=check_health(db,origin=item.origin,as_of=later.collected_at,max_check_age=timedelta(hours=1))
    assert health.status=='check_overdue' and health.snapshot_id==result.snapshot_id
    assert health.checked_at==item.collected_at


def test_unchanged_fetch_detects_missing_membership_and_bad_metadata(db):
    from apps.threat_intelligence.cisa_kev_persistence import SnapshotIntegrityError
    item=collected(sample()); result=persist_catalog(db,item)
    with db.begin() as conn:
        conn.execute(text('DELETE FROM ti_kev.snapshot_entry WHERE snapshot_id=:id'),{'id':result.snapshot_id})
    with pytest.raises(SnapshotIntegrityError,match='membership'): persist_catalog(db,item)
    # Restore only the isolated test fixture, then inject independently corrupt metadata.
    with db.begin() as conn:
        conn.execute(text('''INSERT INTO ti_kev.snapshot_entry(snapshot_id,origin,cve_id,content_sha256)
            SELECT :id,origin,cve_id,content_sha256 FROM ti_kev.revision'''),{'id':result.snapshot_id})
        conn.execute(text("UPDATE ti_kev.catalog_metadata SET catalog=jsonb_set(catalog,'{title}',to_jsonb('altered fixture'::text)) WHERE snapshot_id=:id"),{'id':result.snapshot_id})
    with pytest.raises(SnapshotIntegrityError,match='metadata'): persist_catalog(db,item)
