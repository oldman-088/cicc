"""Offline evidence tracing across explicit asset, inventory, link and provider claims.

Caller-scoped only: no tenant authorization, provider authentication, matching
by package name/version, applicability, exposure or remediation assessment.
"""
from collections import defaultdict
import json
from .vi_asset_correlation import correlate_declared_asset_evidence
from .vi_evidence_ingestion import EvidenceError, evidence_batch_report, verify_evidence_bytes

MAX_RAW_BYTES = 8_000_000
MAX_RAW_VERIFICATION_BYTES = 16_000_000
MAX_TRACE_MATCHES = 10_000
MAX_TRACE_BYTES = 4_194_304


def build_evidence_trace(inventories, bindings, source_evidence, *, as_of,
                         max_collection_age, raw_by_sha256=None):
    """Trace declared CVE links to source records naming the same CVE and origin.

    Optional raw bytes are keyed by digest and checked against every associated
    normalized source observation. A missing raw object means not checked, never
    verified. Digest consistency does not authenticate the publisher. This API is
    an unmounted local transformation, not an authorization or transport contract.
    """
    base = correlate_declared_asset_evidence(inventories, bindings, as_of=as_of,
                                             max_age=max_collection_age)
    batch = evidence_batch_report(source_evidence, as_of=as_of,
                                  max_collection_age=max_collection_age)
    if raw_by_sha256 is None:
        raw_by_sha256 = {}
    if not isinstance(raw_by_sha256, dict) or len(raw_by_sha256) > 5000:
        raise EvidenceError('invalid raw evidence map')
    if any(not isinstance(k, str) or not isinstance(v, bytes) for k, v in raw_by_sha256.items()):
        raise EvidenceError('invalid raw evidence map')
    if sum(len(v) for v in raw_by_sha256.values()) > MAX_RAW_BYTES:
        raise EvidenceError('raw evidence map size exceeded')
    known = {e.source_sha256 for e in source_evidence}
    if set(raw_by_sha256) - known:
        raise EvidenceError('unreferenced raw evidence')
    verification_bytes = sum(len(raw_by_sha256[e.source_sha256]) for e in source_evidence
                             if e.source_sha256 in raw_by_sha256)
    if verification_bytes > MAX_RAW_VERIFICATION_BYTES:
        raise EvidenceError('raw evidence verification work limit exceeded')
    for item in source_evidence:
        if item.source_sha256 in raw_by_sha256:
            verify_evidence_bytes(item, raw_by_sha256[item.source_sha256])

    # Use revalidated, deterministically ordered observations from the batch.
    index = defaultdict(list)
    for row in batch['observations']:
        item = row['evidence']
        for cve in item['cve_ids']:
            index[(item['origin'], cve)].append(row)
    docs = {i.document_id: i for i in inventories}
    results = []
    matches = 0
    output_bytes = 0
    def account(value):
        nonlocal output_bytes
        output_bytes += len(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                       separators=(',', ':')).encode('utf-8')) + 32
        if output_bytes > MAX_TRACE_BYTES:
            raise EvidenceError('expanded evidence payload limit exceeded')

    for entry in base['results']:
        inv = docs[entry['binding']['document_id']]
        if entry['binding']['origin'] != inv.origin:
            raise EvidenceError('binding and inventory origin mismatch')
        components = {c.bom_ref: c.model_dump(mode='json') for c in inv.components}
        links = []
        for timed_link in entry['links']:
            link = timed_link['link']
            if link['origin'] != inv.origin:
                raise EvidenceError('vulnerability link and inventory origin mismatch')
            candidates = index.get((link['origin'], link['cve_id']), [])
            matches += len(candidates)
            if matches > MAX_TRACE_MATCHES:
                raise EvidenceError('expanded source match limit exceeded')
            observations = []
            for row in candidates:
                item = row['evidence']
                observation = {**row, 'byte_consistency':
                    'consistent_with_supplied_bytes' if item['source_sha256'] in raw_by_sha256 else 'not_checked'}
                account(observation)
                observations.append(observation)
            linked = {'declared_link': link, 'link_age_seconds': timed_link['age_seconds'],
                      'link_age_status': timed_link['age_status'],
                      'component': components[link['bom_ref']], 'source_observations': observations,
                      'source_observation_state': 'observed' if observations else 'unknown'}
            account({key: val for key, val in linked.items() if key != 'source_observations'})
            links.append(linked)
        result = {key: val for key, val in entry.items() if key != 'links'}
        account(result)
        result['links'] = links
        results.append(result)
    return {'schema_version': 'cicc.vi.asset-source-trace/1', 'as_of': batch['as_of'],
            'max_collection_age_seconds': batch['max_collection_age_seconds'], 'results': results,
            'interpretation': ('Explicit asset/inventory/component/CVE declarations and same-CVE source claims only; '
                               'no publisher authentication, source independence, applicability, exposure or remediation inference.')}
