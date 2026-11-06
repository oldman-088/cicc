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
