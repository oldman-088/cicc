"""Transactional full-snapshot CISA KEV persistence for a trusted worker.

No migration or connection is executed at import. The caller provisions the
isolated schema and grants; source data is public, not tenant-owned. Do not
accept a CollectedCatalog from an API caller as proof of source authenticity.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from sqlalchemy import text
from sqlalchemy.engine import Engine
from .cisa_github_collector import CollectedCatalog, METADATA_URL

@dataclass(frozen=True)
class PersistenceResult:
    snapshot_id: int
    outcome: str
    added: int
    changed: int
    removed: int

class StaleCatalogError(Exception):
    """An older catalog cannot silently replace a newer active snapshot."""


def persist_catalog(engine: Engine, collected: CollectedCatalog) -> PersistenceResult:
    if engine.dialect.name != 'postgresql':
        raise ValueError('PostgreSQL is required')
    if (collected.source_url != METADATA_URL or collected.collected_at.tzinfo is None or collected.collected_at.utcoffset() is None
        or not re.fullmatch(r'[0-9a-f]{40}', collected.github_blob_sha)
        or not re.fullmatch(r'[0-9a-f]{64}', collected.content_sha256)):
        raise ValueError('invalid collection provenance')
    catalog = collected.catalog
    if catalog.count != len(catalog.vulnerabilities) or len({r.cveID for r in catalog.vulnerabilities}) != catalog.count:
        raise ValueError('incomplete or duplicate catalog')
    # One immutable content revision per normalized entry, with source fields
    # preserved. Hash is deduplication, not verification or a confidence score.
    rows = []
    for entry in catalog.vulnerabilities:
        record = json.dumps(entry.model_dump(mode='json'), sort_keys=True, ensure_ascii=False, separators=(',', ':'))
        rows.append({'origin':collected.origin, 'cve':entry.cveID, 'digest':hashlib.sha256(record.encode('utf-8')).hexdigest(), 'record':record})
    incoming = {r['cve']:r['digest'] for r in rows}
    catalog_metadata = json.dumps(catalog.model_dump(mode='json', exclude={'vulnerabilities'}), ensure_ascii=False, separators=(',', ':'))
    with engine.begin() as conn:
        conn.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"), {'key':'ti_kev_snapshot:'+collected.origin})
        previous = conn.execute(text("SELECT id, blob_sha, content_sha256, released_at FROM ti_kev.snapshot WHERE origin=:origin ORDER BY id DESC LIMIT 1"), {'origin':collected.origin}).mappings().first()
        if previous and catalog.dateReleased < previous['released_at']:
            raise StaleCatalogError('source catalog is older than current snapshot')
        if previous and previous['blob_sha'] == collected.github_blob_sha:
            if previous['content_sha256'] != collected.content_sha256:
                raise ValueError('inconsistent blob digest')
            conn.execute(text('INSERT INTO ti_kev.catalog_metadata(snapshot_id,catalog) VALUES (:id, CAST(:catalog AS jsonb)) ON CONFLICT DO NOTHING'), {'id':previous['id'],'catalog':catalog_metadata})
            conn.execute(text('UPDATE ti_kev.snapshot SET checked_at=GREATEST(checked_at, :checked) WHERE id=:id'), {'checked':collected.collected_at, 'id':previous['id']})
            return PersistenceResult(previous['id'],'unchanged',0,0,0)
        previous_entries = dict(conn.execute(text('SELECT cve_id,content_sha256 FROM ti_kev.snapshot_entry WHERE snapshot_id=:id'), {'id':previous['id']}).all()) if previous else {}
        added = len(incoming.keys()-previous_entries.keys())
        removed = len(previous_entries.keys()-incoming.keys())
        changed = sum(incoming[key] != previous_entries[key] for key in incoming.keys() & previous_entries.keys())
        snapshot_id = conn.execute(text('''INSERT INTO ti_kev.snapshot(origin,source_url,blob_sha,content_sha256,released_at,collected_at,checked_at,catalog_version,entry_count)
          VALUES (:origin,:url,:blob,:digest,:released,:collected,:collected,:version,:count) RETURNING id'''),
          {'origin':collected.origin,'url':collected.source_url,'blob':collected.github_blob_sha,'digest':collected.content_sha256,
           'released':catalog.dateReleased,'collected':collected.collected_at,'version':catalog.catalogVersion,'count':catalog.count}).scalar_one()
        conn.execute(text('INSERT INTO ti_kev.catalog_metadata(snapshot_id,catalog) VALUES (:id, CAST(:catalog AS jsonb))'), {'id':snapshot_id,'catalog':catalog_metadata})
        if rows:
            conn.execute(text('''INSERT INTO ti_kev.revision(origin,cve_id,content_sha256,record)
              VALUES (:origin,:cve,:digest,CAST(:record AS jsonb)) ON CONFLICT DO NOTHING'''), rows)
            conn.execute(text('''INSERT INTO ti_kev.snapshot_entry(snapshot_id,origin,cve_id,content_sha256)
              VALUES (:snapshot,:origin,:cve,:digest)'''), [dict(r, snapshot=snapshot_id) for r in rows])
        return PersistenceResult(snapshot_id,'created',added,changed,removed)


def run_once(engine: Engine):
    """Fetch first; an unavailable or incomplete feed never changes persistence."""
    from .cisa_github_collector import fetch_catalog
    return persist_catalog(engine, fetch_catalog())


def main():
    # Intended for a host scheduler with a dedicated least-privilege worker.
    # Connection URL is accepted only from environment, not command-line args.
    import os
    import sys
    from sqlalchemy import create_engine
    url = os.environ.get('CICC_TI_KEV_DATABASE_URL')
    if not url:
        print('KEV collection not configured', file=sys.stderr)
        return 2
    engine = None
    try:
        engine = create_engine(url, pool_pre_ping=True)
        result = run_once(engine)
        print(f'KEV collection {result.outcome}; snapshot={result.snapshot_id}; added={result.added}; changed={result.changed}; removed={result.removed}')
        return 0
    except Exception:
        # Do not print provider payloads, connection URLs, exceptions or secrets.
        print('KEV collection failed', file=sys.stderr)
        return 1
    finally:
        if engine is not None:
            try:
                engine.dispose()
            except Exception:
                pass  # Do not disclose connection details on shutdown failure.

if __name__ == '__main__':
    raise SystemExit(main())
