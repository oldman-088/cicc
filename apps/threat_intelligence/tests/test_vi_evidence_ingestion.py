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
