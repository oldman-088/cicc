"""Candidate schema and fixture handoff tests, not browser or actual-host integration."""
import json
from datetime import timedelta
from pathlib import Path
import pytest
from apps.threat_intelligence.frontend_vi_candidates import (QualityCandidate,SbomCandidate,ConflictCandidate,
    ResolutionAvailabilityCandidate,SourceEvidenceBatchCandidate,sbom_summary,resolution_availability)
from apps.threat_intelligence.vulnerability_quality import quality_document, Inventory, QualityReport
from test_vulnerability_quality import inventory,obs,CVE,NOW
from test_sbom_ingestion import load,cyclone

ROOT=Path(__file__).parents[3]/'docs'/'vi_candidate_contracts'

def test_fixture_schemas_and_candidate_versions():
    mapping={'quality':QualityCandidate,'sbom':SbomCandidate,'conflict':ConflictCandidate,'resolution_availability':ResolutionAvailabilityCandidate,'source_evidence':SourceEvidenceBatchCandidate}
    for name,model in mapping.items():
        schema=json.loads((ROOT/(name+'.schema.json')).read_text())
        example=json.loads((ROOT/(name+'.example.json')).read_text())
        assert schema==model.model_json_schema()
        model.model_validate(example)
        assert 'EXPERIMENTAL_DEMO_DATA_ONLY' in json.dumps(example) or name=='resolution_availability'
    assert json.loads((ROOT/'inventory.schema.json').read_text())==Inventory.model_json_schema()
    assert json.loads((ROOT/'quality_evidence_core.schema.json').read_text())==QualityReport.model_json_schema()
    assert not resolution_availability(schema_version='cicc.vi.resolution-availability/1')['persistent_history_available']
    with pytest.raises(ValueError): resolution_availability(schema_version='cicc.vi.resolution-availability/2')
    with pytest.raises(ValueError): sbom_summary(load(cyclone()),schema_version='cicc.vi.sbom-summary/2')


def test_actual_local_implementations_match_candidate_shapes():
    report=quality_document(inventory(),[obs(1,'NVD',CVE)],[],as_of=NOW,max_observation_age=timedelta(days=1))
    QualityCandidate.model_validate(report)
    out=sbom_summary(load(cyclone()),schema_version='cicc.vi.sbom-summary/1')
    SbomCandidate.model_validate(out)
    assert out['inventory']['component_completeness']=='unknown'
    assert out['inventory']['vulnerability_links']==[]
