"""Synthetic cross-provenance evidence comparisons; not independent verification."""
from datetime import timedelta
import pytest
from apps.threat_intelligence.vi_source_comparison import compare_same_revision_across_provenance
from apps.threat_intelligence.vi_evidence_ingestion import EvidenceError
from test_vi_evidence_ingestion import load,NOW,CVE


def report(items):
    return compare_same_revision_across_provenance(items,as_of=NOW,max_collection_age=timedelta(days=1))

def epss(score,provenance,day='2026-01-02'):
    return load('EPSS',{'cve':CVE,'epss':score,'date':day}).model_copy(update={'provenance':provenance})

def test_identical_revision_differs_across_provenance_no_winner():
    a,b=epss('0.10','fixture A'),epss('0.2','fixture B')
    out=report([b,a]);d=out['differences'][0]
    assert d['revision']=='2026-01-02' and d['field']=='score'
    assert [(x['provenance'],x['value']) for x in d['claims']]==[('fixture A','0.1'),('fixture B','0.2')]
    assert len(d['claims'][0]['source_sha256'])==64 and out==report([a,b])
    assert 'no winner' in out['interpretation']

def test_no_conflation_of_versions_provenances_or_origins():
    a=epss('0.1','A')
    assert report([a,epss('0.10','B')])['differences']==[]
    assert report([a,epss('0.2','A')])['differences']==[]
    assert report([a,epss('0.2','B','2026-01-01')])['differences']==[]
    assert report([a,epss('0.2','B').model_copy(update={'origin':'CALLER_SUPPLIED_UNVERIFIED'})])['differences']==[]

def test_nvd_requires_same_revision_metric_issuer_and_distinct_provenance():
    def nvd(score,issuer,revision='2026-01-02T00:00:00Z'):
        row={'cvssData':{'baseScore':score}}
        if issuer: row['source']=issuer
        return load('NVD',{'id':CVE,'lastModified':revision,'metrics':{'cvssMetricV31':[row]}})
    a=nvd(1,'issuer').model_copy(update={'provenance':'A'})
    b=nvd(9,'issuer').model_copy(update={'provenance':'B'})
    assert report([a,b])['differences'][0]['field']=='base_score'
    assert report([a,nvd(9,'different').model_copy(update={'provenance':'B'})])['differences']==[]
    assert report([nvd(1,None),nvd(9,None).model_copy(update={'provenance':'B'})])['differences']==[]

def test_comparison_limits_are_enforced(monkeypatch):
    import apps.threat_intelligence.vi_source_comparison as comp
    monkeypatch.setattr(comp,'MAX_CLAIMS',1)
    with pytest.raises(EvidenceError,match='claim limit'): report([epss('0.1','A'),epss('0.2','B')])
    monkeypatch.setattr(comp,'MAX_CLAIMS',20)
    monkeypatch.setattr(comp,'MAX_OUTPUT_BYTES',1)
    with pytest.raises(EvidenceError,match='output limit'): report([epss('0.1','A'),epss('0.2','B')])
