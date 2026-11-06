"""Synthetic provider records only, EXPERIMENTAL_DEMO_DATA_ONLY."""
import json
from datetime import datetime,timedelta,timezone
import pytest
from apps.threat_intelligence.vi_evidence_ingestion import parse_source_evidence,quality_observation,EvidenceError
from apps.threat_intelligence.vulnerability_quality import quality_document
from test_vulnerability_quality import inventory

NOW=datetime(2026,1,3,tzinfo=timezone.utc); CVE='CVE-2099-1234'; LABEL='EXPERIMENTAL_DEMO_DATA_ONLY'
def raw(d): return json.dumps(d,sort_keys=True).encode()
def load(source,data): return parse_source_evidence(raw(data),source=source,collected_at=NOW,provenance='fixture:'+source,origin=LABEL)

@pytest.mark.parametrize('source,doc',[
 ('NVD',{'cve':{'id':CVE,'lastModified':'2026-01-02T00:00:00Z','metrics':{'cvssMetricV31':[{'source':'fixture','cvssData':{'vectorString':'CVSS:3.1/fixture','baseScore':9.1}}]}}}),
 ('OSV',{'id':'OSV-fixture','aliases':[CVE,'GHSA-fixture'],'modified':'2026-01-02T00:00:00Z'}),
 ('GHSA',{'ghsa_id':'GHSA-fixture','cve_id':CVE,'updated_at':'2026-01-02T00:00:00Z','identifiers':[{'type':'CVE','value':CVE}]}),
])
def test_provider_subset_preserves_evidence_and_joins_only_explicit_cves(source,doc):
    result=load(source,doc);again=load(source,doc)
    assert result==again and result.cve_ids==[CVE] and result.origin==LABEL and len(result.source_sha256)==64
    assert result.source_modified_at is not None and result.collected_at==NOW
    obs=quality_observation(result)
    assert result.source_sha256 in obs.provenance and obs.cve_ids==[CVE] and obs.claims==[]
    report=quality_document(inventory(),[obs],[],as_of=NOW+timedelta(days=2),max_observation_age=timedelta(days=1))
    assessment=next(x for x in report['evidence']['assessments'] if x['cve_id']==CVE)
    assert assessment['observations'][0]['age_status']=='outside_window' and assessment['linked_components']==[]
    if source=='NVD': assert result.cvss_observations[0]['base_score']=='9.1'


def test_epss_preserves_published_score_and_date_without_inventing_a_decision():
    result=load('EPSS',{'cve':CVE,'epss':'0.04200','date':'2026-01-02'})
    assert result.epss_score=='0.04200' and str(result.epss_score_date)=='2026-01-02'
    assert result.source_modified_at is None and result.cvss_observations==[]
    with pytest.raises(EvidenceError): quality_observation(result)


def test_unlinked_source_and_missing_cvss_remain_unknown():
    e=load('OSV',{'id':'OSV-fixture','aliases':['GHSA-fixture']})
    assert e.cve_ids==[] and e.source_modified_at is None
    assert quality_observation(e).cve_ids==[]
    nvd=load('NVD',{'id':CVE})
    assert nvd.cvss_observations==[] and nvd.source_modified_at is None


@pytest.mark.parametrize('source,doc',[
 ('EPSS',{'cve':CVE,'epss':'1.1','date':'2026-01-02'}),
 ('EPSS',{'cve':CVE,'epss':'0.1','date':'2026-13-02'}),
 ('GHSA',{'ghsa_id':'GHSA-fixture','cve_id':'CVE-invalid'}),
 ('OSV',{'id':'OSV-fixture','aliases':['CVE-invalid']}),
 ('NVD',{'id':CVE,'lastModified':'2026-01-01T00:00:00'}),
 ('NVD',{'id':CVE,'metrics':{'cvssMetricV31':[{'cvssData':{'baseScore':11}}]}}),
])
def test_invalid_evidence_fails_closed(source,doc):
    with pytest.raises(EvidenceError): load(source,doc)


def test_malformed_duplicate_and_oversized_never_turn_into_empty_evidence():
    for data in [b'{"id":"a","id":"b"}',b'\xff',b'x'*1_000_001,b'{}']:
        with pytest.raises(EvidenceError): parse_source_evidence(data,source='OSV',collected_at=NOW,provenance='fixture',origin=LABEL)
    with pytest.raises(EvidenceError): parse_source_evidence(raw({'id':'fixture'}),source='OSV',collected_at=0,provenance='fixture',origin=LABEL)


def test_missing_provenance_and_forged_numeric_timestamp_are_rejected():
    for provenance in ('','   '):
        with pytest.raises(EvidenceError): parse_source_evidence(raw({'id':'fixture'}),source='OSV',collected_at=NOW,provenance=provenance,origin=LABEL)
    result=load('OSV',{'id':'fixture'})
    from apps.threat_intelligence.vi_evidence_ingestion import SourceEvidence
    malformed=result.model_dump();malformed['collected_at']=0
    with pytest.raises(ValueError): SourceEvidence.model_validate(malformed)
    forged=result.model_copy(update={'cve_ids':['CVE-invalid']})
    with pytest.raises(ValueError): quality_observation(forged)


def test_exact_raw_verification_rejects_tampering_and_preserves_source_identity():
    from apps.threat_intelligence.vi_evidence_ingestion import verify_evidence_bytes
    doc={'id':'OSV-fixture','aliases':[CVE]};e=load('OSV',doc)
    assert verify_evidence_bytes(e,raw(doc)) is None
    with pytest.raises(EvidenceError): verify_evidence_bytes(e,raw(doc|{'id':'other'}))
    forged=e.model_copy(update={'cve_ids':['CVE-2099-9999']})
    with pytest.raises(EvidenceError): verify_evidence_bytes(forged,raw(doc))


def test_batch_duplicate_content_age_and_comparable_conflicts_without_winner():
    from apps.threat_intelligence.vi_evidence_ingestion import evidence_batch_report
    a=load('EPSS',{'cve':CVE,'epss':'0.1','date':'2026-01-02'})
    b=load('EPSS',{'cve':CVE,'epss':'0.100','date':'2026-01-02'})
    c=load('EPSS',{'cve':CVE,'epss':'0.2','date':'2026-01-02'})
    result=evidence_batch_report([c,a,b,a],as_of=NOW+timedelta(days=2),max_collection_age=timedelta(days=1))
    assert result==evidence_batch_report([a,b,a,c],as_of=NOW+timedelta(days=2),max_collection_age=timedelta(days=1))
    assert result['duplicate_content'][0]['observation_count']==2
    assert len(result['same_revision_conflicts'])==1 and result['same_revision_conflicts'][0]['differing_fields']['score']==['0.1','0.2']
    assert all(x['collection_age_status']=='stale' for x in result['observations'])
    assert all(x['source_modified_status']=='unknown' for x in result['observations'])
    assert 'no source winner' in result['interpretation']


def test_same_revision_cvss_conflict_requires_explicit_matching_issuer():
    from apps.threat_intelligence.vi_evidence_ingestion import evidence_batch_report
    def nvd(score,source=None):
        row={'cvssData':{'baseScore':score}}
        if source is not None: row['source']=source
        return load('NVD',{'id':CVE,'lastModified':'2026-01-02T00:00:00Z','metrics':{'cvssMetricV31':[row]}})
    kw=dict(as_of=NOW,max_collection_age=timedelta(days=1))
    assert not evidence_batch_report([nvd(1),nvd(9)],**kw)['same_revision_conflicts']
    assert not evidence_batch_report([nvd(1,'source-a'),nvd(9,'source-b')],**kw)['same_revision_conflicts']
    assert evidence_batch_report([nvd(1,'source-a'),nvd(9,'source-a')],**kw)['same_revision_conflicts']


def test_numeric_cvss_formatting_does_not_create_false_disagreement():
    from apps.threat_intelligence.vi_evidence_ingestion import evidence_batch_report
    def nvd(score):
        text='{"id":"'+CVE+'","lastModified":"2026-01-02T00:00:00Z","metrics":{"cvssMetricV31":[{"source":"fixture","cvssData":{"baseScore":'+score+'}}]}}'
        return parse_source_evidence(text.encode(),source='NVD',collected_at=NOW,provenance='fixture',origin=LABEL)
    result=evidence_batch_report([nvd('9.1'),nvd('9.10')],as_of=NOW,max_collection_age=timedelta(days=1))
    assert result['same_revision_conflicts']==[]
    assert {item['evidence']['cvss_observations'][0]['base_score'] for item in result['observations']}=={'9.1','9.10'}


def test_batch_revalidates_mutated_nested_evidence():
    from apps.threat_intelligence.vi_evidence_ingestion import evidence_batch_report
    e=load('NVD',{'id':CVE,'lastModified':'2026-01-02T00:00:00Z','metrics':{'cvssMetricV31':[{'source':'fixture','cvssData':{'baseScore':9.1}}]}})
    e.cvss_observations[0]['base_score']='NaN'
    with pytest.raises(EvidenceError): evidence_batch_report([e],as_of=NOW,max_collection_age=timedelta(days=1))


def test_score_dates_and_future_collection_are_separate_from_source_freshness():
    from apps.threat_intelligence.vi_evidence_ingestion import evidence_batch_report
    e=load('EPSS',{'cve':CVE,'epss':'0.1','date':'2026-01-04'})
    row=evidence_batch_report([e],as_of=NOW-timedelta(days=1),max_collection_age=timedelta(days=1))['observations'][0]
    assert row['score_date_age_days']==-2 and row['score_date_status']=='future'
    assert row['collection_age_status']=='future' and row['source_modified_status']=='unknown'


def test_fixture_and_unverified_origins_are_never_conflated():
    from apps.threat_intelligence.vi_evidence_ingestion import evidence_batch_report
    demo=load('EPSS',{'cve':CVE,'epss':'0.1','date':'2026-01-02'})
    different=load('EPSS',{'cve':CVE,'epss':'0.2','date':'2026-01-02'}).model_copy(update={'origin':'CALLER_SUPPLIED_UNVERIFIED'})
    same=demo.model_copy(update={'origin':'CALLER_SUPPLIED_UNVERIFIED'})
    report=evidence_batch_report([demo,different,same],as_of=NOW,max_collection_age=timedelta(days=1))
    assert report['duplicate_content']==[]
    assert len(report['same_revision_conflicts'])==1 and report['same_revision_conflicts'][0]['origin']=='CALLER_SUPPLIED_UNVERIFIED'
