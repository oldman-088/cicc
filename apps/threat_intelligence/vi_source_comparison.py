"""Bounded cross-provenance comparison of directly comparable supplied claims.

Provenance is a caller-supplied locator, not an authenticated publisher, nor
proof of independence. Differences are evidence, never a source selection.
"""
from collections import defaultdict
from decimal import Decimal
import json
from .vi_evidence_ingestion import EvidenceError, evidence_batch_report

MAX_CLAIMS = 20_000
MAX_OUTPUT_BYTES = 4_194_304


def compare_same_revision_across_provenance(evidence, *, as_of, max_collection_age):
    """Compare same-origin, same provider/record/revision/issuer/field only.

    NVD vectors are compared as literal strings, not semantically interpreted.
    No comparison is made for missing revision, issuer or noncomparable sources.
    Collection time does not establish when an upstream claim became true.
    """
    batch = evidence_batch_report(evidence, as_of=as_of, max_collection_age=max_collection_age)
    groups = defaultdict(list)
    count = 0
    claim_bytes = 0
    for row in batch['observations']:
        e = row['evidence']
        def record(revision, metric, issuer, field, value):
            nonlocal count, claim_bytes
            count += 1
            if count > MAX_CLAIMS:
                raise EvidenceError('comparison claim limit exceeded')
            key=(e['origin'],e['source'],e['source_record_id'],revision,metric,issuer,field)
            claim={'value':value,'provenance':e['provenance'],
                   'source_sha256':e['source_sha256'],'collected_at':e['collected_at']}
            claim_bytes += len(json.dumps(claim,ensure_ascii=False,separators=(',',':')).encode('utf-8')) + 32
            if claim_bytes > MAX_OUTPUT_BYTES:
                raise EvidenceError('comparison output limit exceeded')
            groups[key].append(claim)
        if e['source']=='NVD' and e['source_modified_at'] is not None:
            for metric in e['cvss_observations']:
                if 'source' not in metric:
                    continue
                for field in ('vector','base_score'):
                    if field in metric:
                        value=str(Decimal(metric[field]).normalize()) if field=='base_score' else metric[field]
                        record(e['source_modified_at'],metric['kind'],metric['source'],field,value)
        elif e['source']=='EPSS' and e['epss_score_date'] is not None:
            record(e['epss_score_date'],'epss','provider-declared','score',str(Decimal(e['epss_score']).normalize()))
    differences=[]; used=0
    for key, claims in sorted(groups.items()):
        by_provenance=defaultdict(set)
        for claim in claims:
            by_provenance[claim['provenance']].add(claim['value'])
        if len(by_provenance)<2 or len({c['value'] for c in claims})<2:
            continue
        # At least one differently-valued pair must have distinct provenance.
        first=next(iter(by_provenance.values()))
        if all(values == first and len(values)==1 for values in by_provenance.values()):
            continue
        claims.sort(key=lambda x:(x['provenance'],x['value'],x['source_sha256'],x['collected_at']))
        item={'origin':key[0],'source':key[1],'source_record_id':key[2], 'revision':key[3],
              'metric':key[4],'issuer':key[5],'field':key[6],'claims':claims}
        used += len(json.dumps(item,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode('utf-8')) + 32
        if used>MAX_OUTPUT_BYTES:
            raise EvidenceError('comparison output limit exceeded')
        differences.append(item)
    return {'schema_version':'cicc.vi.cross-provenance-comparison/1','as_of':batch['as_of'],
            'differences':differences,'interpretation':('Same-revision supplied values only; provenance is not authenticated '
                'or independent, literal vectors may be semantically equivalent, and no winner or applicability is inferred.')}
