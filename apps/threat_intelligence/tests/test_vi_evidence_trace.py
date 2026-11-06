"""End-to-end offline evidence joins; every intelligence value is synthetic."""
from datetime import timedelta
import json
import pytest
from apps.threat_intelligence.sbom_ingestion import import_sbom
from apps.threat_intelligence.vi_evidence_trace import build_evidence_trace
from apps.threat_intelligence.vi_evidence_ingestion import parse_source_evidence, EvidenceError
from apps.threat_intelligence.vulnerability_quality import VulnerabilityLink, Inventory
from test_vi_asset_correlation import binding
from test_vi_evidence_ingestion import CVE, LABEL, NOW, raw, load
from uuid import UUID


def fixture_inventory():
    sbom = raw({'bomFormat':'CycloneDX','specVersion':'1.5','components':[{'bom-ref':'fixture-component',
                'name':'EXPERIMENTAL_DEMO_DATA_ONLY package','version':'1'}]})
    imported = import_sbom(sbom,document_id='EXPERIMENTAL_DEMO_DATA_ONLY sbom',
        provenance='EXPERIMENTAL_DEMO_DATA_ONLY sbom source',collected_at=NOW,origin=LABEL)
    data=imported.inventory.model_dump()
    data['vulnerability_links']=[VulnerabilityLink(link_id=UUID(int=1),bom_ref='fixture-component',cve_id=CVE,
        basis='analyst_declared',provenance='EXPERIMENTAL_DEMO_DATA_ONLY analyst claim',collected_at=NOW,
        origin=LABEL).model_dump()]
    return Inventory.model_validate(data)


def run(inv, sources, **kw):
    return build_evidence_trace([inv],[binding()],sources,as_of=NOW+timedelta(days=2),
                                max_collection_age=timedelta(days=1),**kw)


def test_raw_sbom_declared_link_and_multiple_provider_claims_trace_without_conclusion():
    inv=fixture_inventory(); osv_doc={'id':'OSV-EXPERIMENTAL_DEMO_DATA_ONLY','aliases':[CVE]}
    e=load('OSV',osv_doc); epss=load('EPSS',{'cve':CVE,'epss':'0.1','date':'2026-01-02'})
    report=run(inv,[epss,e],raw_by_sha256={e.source_sha256:raw(osv_doc)})
    link=report['results'][0]['links'][0]
    assert link['component']['bom_ref']=='fixture-component' and link['declared_link']['basis']=='analyst_declared'
    assert report['results'][0]['inventory_completeness']=='unknown'
    assert report['results'][0]['applicability']==report['results'][0]['exposure']=='unknown'
    assert {x['evidence']['source'] for x in link['source_observations']}=={'OSV','EPSS'}
    statuses={x['evidence']['source']:x['byte_consistency'] for x in link['source_observations']}
    assert statuses=={'OSV':'consistent_with_supplied_bytes','EPSS':'not_checked'}
    assert all(x['collection_age_status']=='stale' for x in link['source_observations'])
    assert report==run(inv,[e,epss],raw_by_sha256={e.source_sha256:raw(osv_doc)})
    assert 'no publisher authentication' in report['interpretation']


def test_missing_record_or_other_origin_is_unknown_not_absence_or_verified():
    inv=fixture_inventory();e=load('OSV',{'id':'OSV-demo','aliases':[CVE]})
    other=e.model_copy(update={'origin':'CALLER_SUPPLIED_UNVERIFIED'})
    link=run(inv,[other])['results'][0]['links'][0]
    assert link['source_observations']==[] and link['source_observation_state']=='unknown'
    assert run(inv,[])['results'][0]['links'][0]['source_observation_state']=='unknown'


def test_rejects_mixed_declared_origins_and_forged_or_unreferenced_bytes():
    inv=fixture_inventory(); e=load('OSV',{'id':'OSV-demo','aliases':[CVE]})
    with pytest.raises(EvidenceError): run(inv,[e],raw_by_sha256={e.source_sha256:b'{}'})
    with pytest.raises(EvidenceError): run(inv,[e],raw_by_sha256={'0'*64:b'{}'})
    data=inv.model_dump(); data['vulnerability_links'][0]['origin']='CALLER_SUPPLIED_UNVERIFIED'
    with pytest.raises(EvidenceError): run(Inventory.model_validate(data),[e])
    bad_binding=binding().model_copy(update={'origin':'CALLER_SUPPLIED_UNVERIFIED'})
    with pytest.raises(EvidenceError): build_evidence_trace([inv],[bad_binding],[e],as_of=NOW,max_collection_age=timedelta(days=1))


def test_expansion_limit_and_mutated_inputs_fail_closed(monkeypatch):
    import apps.threat_intelligence.vi_evidence_trace as trace
    inv=fixture_inventory(); e=load('OSV',{'id':'OSV-demo','aliases':[CVE]})
    monkeypatch.setattr(trace,'MAX_TRACE_MATCHES',1)
    with pytest.raises(EvidenceError): run(inv,[e,e])
    inv.vulnerability_links.clear()
    inv.components.clear()
    # No link remains: empty inventory is not a claim of complete coverage.
    assert run(inv,[e])['results'][0]['inventory_completeness']=='unknown'
    e.cve_ids.append('CVE-invalid')
    with pytest.raises(EvidenceError): run(inv,[e])


def test_expanded_byte_budget_fails_before_oversized_output(monkeypatch):
    import apps.threat_intelligence.vi_evidence_trace as trace
    inv=fixture_inventory();e=load('OSV',{'id':'OSV-demo','aliases':[CVE]})
    monkeypatch.setattr(trace,'MAX_TRACE_BYTES',100)
    with pytest.raises(EvidenceError,match='payload limit'): run(inv,[e])


def test_repeated_raw_verification_work_is_bounded(monkeypatch):
    import apps.threat_intelligence.vi_evidence_trace as trace
    doc={'id':'OSV-demo','aliases':[CVE]}; e=load('OSV',doc)
    monkeypatch.setattr(trace,'MAX_RAW_VERIFICATION_BYTES',len(raw(doc)))
    with pytest.raises(EvidenceError,match='verification work limit'):
        run(fixture_inventory(),[e,e],raw_by_sha256={e.source_sha256:raw(doc)})
