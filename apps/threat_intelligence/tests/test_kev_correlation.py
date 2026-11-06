"""All inputs here are synthetic EXPERIMENTAL_DEMO_DATA_ONLY fixtures."""
from datetime import datetime, timedelta, timezone
from uuid import UUID
import pytest
from apps.threat_intelligence.cisa_github_collector import fetch_catalog
from apps.threat_intelligence.kev_correlation import correlate_kev
from apps.threat_intelligence.relationship_analysis import EntityReference
from test_cisa_github_collector import sample, fixture_transport
from test_intelligence_assessment import record, ev


def catalog():
    transport,_=fixture_transport(sample())
    return fetch_catalog(transport=transport,sleep=lambda _:None,min_interval=0)


def run(records,c=None,**kwargs):
    c=c or catalog()
    return correlate_kev(records,c,as_of=kwargs.get('as_of',c.collected_at),
       evidence_max_age=kwargs.get('evidence_max_age',timedelta(days=2)),
       catalog_max_age=kwargs.get('catalog_max_age',timedelta(days=1)),
       cve_entity_types=kwargs.get('cve_entity_types',{'CVE'}))


def test_exact_join_preserves_provenance_freshness_and_unresolved_conflict():
    c=catalog(); r=record(1,evidence=[ev(1,'fixture-source',c.collected_at-timedelta(days=3))],conflicts=[{'claim':'fixture conflict'}])
    r.target_entity=EntityReference(entity_type='CVE',entity_id='CVE-2099-0001')
    out=run([r],c)
    assert out.origin=='EXPERIMENTAL_DEMO_DATA_ONLY' and out.catalog_collection_status=='within_window'
    assert len(out.matches)==1 and out.matches[0].matched_roles==['target']
    match=out.matches[0]
    assert match.kev_entry.cveID=='CVE-2099-0001' and match.evidence_collection_ages[0].status=='outside_window'
    assert match.evidence_collection_ages[0].observation.provenance=='fixture feed'
    assert match.conflict_status=='unresolved' and match.explicit_conflicts[0]['conflict']['claim']=='fixture conflict'
    assert 'does not establish' in out.explanation
    match.explicit_conflicts[0]['conflict']['claim']='changed'
    assert r.conflicting_intelligence[0]['claim']=='fixture conflict'


def test_no_inference_type_filter_and_duplicate_side_join():
    c=catalog(); r=record(1)
    r.source_entity=EntityReference(entity_type='CVE',entity_id='CVE-2099-0001')
    r.target_entity=EntityReference(entity_type='CVE',entity_id='CVE-2099-0001')
    assert run([r],c).matches[0].matched_roles==['source','target']
    report=run([r],c,cve_entity_types={'Vulnerability'})
    assert not report.matches and report.unmatched_relationship_ids==[UUID(int=1)]
    r.target_entity.entity_id='cve-2099-0001';r.source_entity.entity_id='cve-2099-0001'
    assert not run([r],c).matches


def test_explicit_time_horizons_future_and_validation():
    c=catalog(); r=record(1);r.target_entity=EntityReference(entity_type='CVE',entity_id='CVE-2099-0001')
    assert run([r],c,as_of=c.collected_at-timedelta(seconds=1)).catalog_collection_status=='future_collection_time'
    assert run([r],c,as_of=c.collected_at+timedelta(days=1)).catalog_collection_status=='within_window'
    assert run([r],c,as_of=c.collected_at+timedelta(days=1,seconds=1)).catalog_collection_status=='outside_window'
    with pytest.raises(ValueError): run([r,r],c)
    with pytest.raises(ValueError): run([r],c,cve_entity_types=set())
    with pytest.raises(ValueError): run([r],c,evidence_max_age=timedelta(0))
    with pytest.raises(ValueError): run([r],c,as_of=datetime(2026,1,1))
    assert run([],c).matches==[]
