"""Load complete persisted public-feed snapshots for trusted internal analysis.

Not a tenant API. Read-only database credentials and schema access are supplied
by the host; persisted source provenance is not cryptographic attestation.
"""
import hashlib
import json
import re
from sqlalchemy import text
from sqlalchemy.engine import Engine
from .cisa_github_collector import CollectedCatalog, CollectionError, METADATA_URL, parse_catalog, verify_source_bytes

class SnapshotUnavailable(Exception):
    """Snapshot is absent, predates metadata migration, or is incomplete."""


def load_snapshot(engine: Engine, *, origin: str, snapshot_id: int | None = None) -> CollectedCatalog:
    if engine.dialect.name != 'postgresql':
        raise ValueError('PostgreSQL is required')
    if origin not in ('FETCHED_FROM_GITHUB_CISA_REPO','EXPERIMENTAL_DEMO_DATA_ONLY'):
        raise ValueError('invalid origin')
    if snapshot_id is not None and (type(snapshot_id) is not int or snapshot_id <= 0):
        raise ValueError('invalid snapshot identifier')
    with engine.begin() as conn:
        conn.execute(text('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY'))
        return _load_snapshot_conn(conn, origin=origin, snapshot_id=snapshot_id)


def _load_snapshot_conn(conn, *, origin: str, snapshot_id: int | None = None) -> CollectedCatalog:
    """Validate in an existing transaction, including original bytes and membership."""
    row=conn.execute(text('''SELECT s.id,s.origin,s.source_url,s.blob_sha,s.content_sha256,s.collected_at,s.released_at,s.catalog_version,s.entry_count,m.catalog
        FROM ti_kev.snapshot s LEFT JOIN ti_kev.catalog_metadata m ON m.snapshot_id=s.id
        WHERE s.origin=:origin AND (CAST(:id AS bigint) IS NULL OR s.id=CAST(:id AS bigint)) ORDER BY s.id DESC LIMIT 1'''), {'origin':origin,'id':snapshot_id}).mappings().first()
    if row is None or row['catalog'] is None:
        raise SnapshotUnavailable('snapshot or catalog metadata unavailable')
    revision_rows=conn.execute(text('''SELECT e.cve_id,e.content_sha256,r.record FROM ti_kev.snapshot_entry e JOIN ti_kev.revision r
        ON (e.origin,e.cve_id,e.content_sha256)=(r.origin,r.cve_id,r.content_sha256)
        WHERE e.snapshot_id=:id AND e.origin=:origin ORDER BY e.cve_id'''), {'id':row['id'],'origin':origin}).mappings().all()
    entries=[]
    for revision in revision_rows:
        record=revision['record']
        encoded=json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        if not isinstance(record,dict) or record.get('cveID') != revision['cve_id'] or hashlib.sha256(encoded).hexdigest() != revision['content_sha256']:
            raise SnapshotUnavailable('stored revision integrity check failed')
        entries.append(record)
    meta=dict(row['catalog'])
    if 'vulnerabilities' in meta:
        raise SnapshotUnavailable('stored catalog metadata is inconsistent')
    meta['vulnerabilities']=entries
    if (row['source_url'] != METADATA_URL or not re.fullmatch(r'[0-9a-f]{40}', row['blob_sha'])
        or not re.fullmatch(r'[0-9a-f]{64}', row['content_sha256']) or len(entries) != row['entry_count']):
        raise SnapshotUnavailable('stored snapshot metadata is inconsistent')
    try:
        catalog=parse_catalog(json.dumps(meta, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))
    except CollectionError:
        raise SnapshotUnavailable('stored catalog validation failed') from None
    if catalog.dateReleased != row['released_at'] or catalog.catalogVersion != row['catalog_version']:
        raise SnapshotUnavailable('stored catalog metadata is inconsistent')
    blob=conn.execute(text('SELECT blob_sha,source_bytes FROM ti_kev.source_blob WHERE origin=:origin AND content_sha256=:digest'),
        {'origin':origin,'digest':row['content_sha256']}).mappings().first()
    if blob is None or blob['blob_sha'] != row['blob_sha']:
        raise SnapshotUnavailable('original source blob unavailable')
    result=CollectedCatalog(catalog=catalog,source_url=row['source_url'],github_blob_sha=row['blob_sha'],
        content_sha256=row['content_sha256'],collected_at=row['collected_at'],origin=row['origin'])
    result._source_bytes=bytes(blob['source_bytes'])
    try:
        verify_source_bytes(result)
    except CollectionError:
        raise SnapshotUnavailable('original source blob integrity check failed') from None
    return result


def load_conflict_candidate(engine: Engine, *, origin: str, conflict_id: int) -> CollectedCatalog:
    """Load quarantined original bytes, checking both digests; not a resolution."""
    if engine.dialect.name != 'postgresql' or origin not in ('FETCHED_FROM_GITHUB_CISA_REPO','EXPERIMENTAL_DEMO_DATA_ONLY'):
        raise ValueError('invalid database or origin')
    if type(conflict_id) is not int or conflict_id <= 0:
        raise ValueError('invalid conflict identifier')
    with engine.begin() as conn:
        conn.execute(text('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY'))
        return _load_conflict_candidate_conn(conn,origin=origin,conflict_id=conflict_id)


def _load_conflict_candidate_conn(conn, *, origin: str, conflict_id: int) -> CollectedCatalog:
    row=conn.execute(text('''SELECT c.observed_at,c.candidate_content_sha256,b.blob_sha,b.source_bytes
        FROM ti_kev.source_conflict c JOIN ti_kev.source_blob b ON (b.origin,b.content_sha256)=(c.origin,c.candidate_content_sha256)
        WHERE c.origin=:origin AND c.id=:id'''), {'origin':origin,'id':conflict_id}).mappings().first()
    if row is None:
        raise SnapshotUnavailable('conflict candidate unavailable')
    try:
        raw=bytes(row['source_bytes'])
        result=CollectedCatalog(catalog=parse_catalog(raw), source_url=METADATA_URL,
            github_blob_sha=row['blob_sha'], content_sha256=row['candidate_content_sha256'],
            collected_at=row['observed_at'],origin=origin)
        result._source_bytes=raw
        verify_source_bytes(result)
    except (CollectionError, ValueError, TypeError):
        raise SnapshotUnavailable('conflict candidate integrity check failed') from None
    return result


def inspect_conflict(engine: Engine, *, origin: str, conflict_id: int):
    """Return verified original streams, metadata and deterministic delta, read-only.

    The result is for trusted operators; it makes no resolution or source-truth
    decision. All reads share one repeatable-read transaction.
    """
    if engine.dialect.name != 'postgresql' or origin not in ('FETCHED_FROM_GITHUB_CISA_REPO','EXPERIMENTAL_DEMO_DATA_ONLY'):
        raise ValueError('invalid database or origin')
    if type(conflict_id) is not int or conflict_id <= 0:
        raise ValueError('invalid conflict identifier')
    with engine.begin() as conn:
        conn.execute(text('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY'))
        row=conn.execute(text('''SELECT previous_snapshot_id,observed_at FROM ti_kev.source_conflict
            WHERE origin=:origin AND id=:id'''),{'origin':origin,'id':conflict_id}).mappings().first()
        if row is None: raise SnapshotUnavailable('conflict unavailable')
        previous=_load_snapshot_conn(conn,origin=origin,snapshot_id=row['previous_snapshot_id'])
        candidate=_load_conflict_candidate_conn(conn,origin=origin,conflict_id=conflict_id)
        old=previous.catalog; new=candidate.catalog
        if old.dateReleased != new.dateReleased:
            raise SnapshotUnavailable('conflict release metadata inconsistent')
        before={r.cveID:r.model_dump(mode='json') for r in old.vulnerabilities}
        after={r.cveID:r.model_dump(mode='json') for r in new.vulnerabilities}
        old_meta=old.model_dump(mode='json',exclude={'vulnerabilities'})
        new_meta=new.model_dump(mode='json',exclude={'vulnerabilities'})
        metadata_fields=sorted(k for k in old_meta.keys()|new_meta.keys() if old_meta.get(k)!=new_meta.get(k) or (k in old_meta)!=(k in new_meta))
        added=sorted(after.keys()-before.keys()); removed=sorted(before.keys()-after.keys())
        changed=sorted(k for k in before.keys() & after.keys() if before[k]!=after[k])
        if not (metadata_fields or added or removed or changed):
            raise SnapshotUnavailable('conflict has no normalized disagreement')
        return {'schema_version':'cicc.kev-conflict-inspection/1','conflict_id':conflict_id,'origin':origin,
                'previous_snapshot_id':row['previous_snapshot_id'],'observed_at':row['observed_at'],
                'release_at':old.dateReleased,'previous_collected_at':previous.collected_at,
                'candidate_collected_at':candidate.collected_at,
                'previous_sha256':previous.content_sha256,'candidate_sha256':candidate.content_sha256,
                'previous_blob_sha':previous.github_blob_sha,'candidate_blob_sha':candidate.github_blob_sha,
                'metadata_fields_changed':metadata_fields,'added_cves':added,'removed_cves':removed,'changed_cves':changed,
                'previous':previous,'candidate':candidate}
