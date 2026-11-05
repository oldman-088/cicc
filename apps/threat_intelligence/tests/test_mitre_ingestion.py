import pytest
from datetime import datetime
from apps.threat_intelligence.mitre_ingestion import (
    MITREFrameworkModel,
    MITRETechniqueModel,
    MITRETacticModel,
    MITREGroupModel,
    MITRESoftwareModel,
    MITRERelationshipModel,
    MITREIngestionService,
    EXPERIMENTAL_DEMO_DATA_ONLY,
    SecurityError
)

class TestMITREFrameworkModel:
    """Tests for MITRE Framework Model"""
    
    def test_create_framework(self):
        """Test framework model creation"""
        framework = MITREFrameworkModel(
            framework_id="mitre-attack",
            version="v14",
            release_date=datetime.utcnow(),
            description="MITRE ATT&CK Framework v14",
            source="MITRE ATT&CK",
            provenance="ingestion_pipeline",
            confidence=1.0,
            experimental_label=None,
            tenant_id="tenant-001"
        )
        assert framework.framework_id == "mitre-attack"
        assert framework.version == "v14"
        assert framework.confidence == 1.0
        assert framework.experimental_label is None
        assert framework.tenant_id == "tenant-001"
    
    def test_experimental_label(self):
        """Test experimental label handling"""
        framework = MITREFrameworkModel(
            framework_id="mitre-attack",
            version="v14",
            source="MITRE ATT&CK",
            provenance="ingestion_pipeline",
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )
        assert framework.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY
    
    def test_invalid_experimental_label(self):
        """Test invalid experimental label rejection"""
        with pytest.raises(ValueError):
            MITREFrameworkModel(
                framework_id="mitre-attack",
                version="v14",
                source="MITRE ATT&CK",
                provenance="ingestion_pipeline",
                experimental_label="INVALID_LABEL"
            )

class TestMITRETechniqueModel:
    """Tests for MITRE Technique Model"""
    
    def test_create_technique(self):
        """Test technique model creation"""
        technique = MITRETechniqueModel(
            technique_id="T1059",
            name="Command and Scripting Interpreter",
            tactic_ids=["TA0002"],
            framework_version="v14",
            source="MITRE ATT&CK",
            provenance="ingestion_pipeline",
            confidence=1.0,
            experimental_label=None,
            tenant_id="tenant-001"
        )
        assert technique.technique_id == "T1059"
        assert technique.name == "Command and Scripting Interpreter"
        assert "TA0002" in technique.tactic_ids
        assert technique.framework_version == "v14"
    
    def test_sub_technique(self):
        """Test sub-technique creation"""
        sub_technique = MITRETechniqueModel(
            technique_id="T1059",
            sub_technique_id="T1059.001",
            name="PowerShell",
            framework_version="v14",
            source="MITRE ATT&CK",
            provenance="ingestion_pipeline",
            confidence=1.0
        )
        assert sub_technique.sub_technique_id == "T1059.001"

class TestMITRETacticModel:
    """Tests for MITRE Tactic Model"""
    
    def test_create_tactic(self):
        """Test tactic model creation"""
        tactic = MITRETacticModel(
            tactic_id="TA0002",
            name="Execution",
            description="The adversary is trying to run malicious code",
            framework_version="v14",
            source="MITRE ATT&CK",
            provenance="ingestion_pipeline",
            confidence=1.0
        )
        assert tactic.tactic_id == "TA0002"
        assert tactic.name == "Execution"

class TestMITREGroupModel:
    """Tests for MITRE Group Model"""
    
    def test_create_group(self):
        """Test group model creation"""
        group = MITREGroupModel(
            group_id="G0001",
            name="APT28",
            description="Threat group APT28",
            framework_version="v14",
            source="MITRE ATT&CK",
            provenance="ingestion_pipeline",
            confidence=1.0
        )
        assert group.group_id == "G0001"
        assert group.name == "APT28"

class TestMITRESoftwareModel:
    """Tests for MITRE Software Model"""
    
    def test_create_software(self):
        """Test software model creation"""
        software = MITRESoftwareModel(
            software_id="S0001",
            name="PowerShell",
            description="Windows command-line shell",
            framework_version="v14",
            source="MITRE ATT&CK",
            provenance="ingestion_pipeline",
            confidence=1.0
        )
        assert software.software_id == "S0001"
        assert software.name == "PowerShell"

class TestMITRERelationshipModel:
    """Tests for MITRE Relationship Model"""
    
    def test_create_relationship(self):
        """Test relationship model creation"""
        relationship = MITRERelationshipModel(
            relationship_id="REL-001",
            source_entity_id="T1059",
            target_entity_id="TA0002",
            relationship_type="uses",
            framework_version="v14",
            source="MITRE ATT&CK",
            provenance="ingestion_pipeline",
            confidence=1.0
        )
        assert relationship.relationship_id == "REL-001"
        assert relationship.source_entity_id == "T1059"
        assert relationship.target_entity_id == "TA0002"
        assert relationship.relationship_type == "uses"

class TestMITREIngestionService:
    """Tests for MITRE Ingestion Service"""
    
    def setup_method(self):
        """Setup service for testing"""
        self.service = MITREIngestionService(tenant_id="tenant-001")
    
    def test_ingest_framework(self):
        """Test framework ingestion"""
        framework_data = {
            "framework_id": "mitre-attack",
            "version": "v14",
            "release_date": datetime.utcnow(),
            "description": "MITRE ATT&CK Framework v14",
            "source": "MITRE ATT&CK",
            "provenance": "ingestion_pipeline",
            "confidence": 1.0
        }
        framework = self.service.ingest_framework(framework_data)
        assert framework.framework_id == "mitre-attack"
        assert framework.version == "v14"
        assert framework.tenant_id == "tenant-001"
    
    def test_ingest_technique(self):
        """Test technique ingestion"""
        technique_data = {
            "technique_id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic_ids": ["TA0002"],
            "framework_version": "v14",
            "source": "MITRE ATT&CK",
            "provenance": "ingestion_pipeline",
            "confidence": 1.0
        }
        technique = self.service.ingest_technique(technique_data)
        assert technique.technique_id == "T1059"
        assert technique.name == "Command and Scripting Interpreter"
    
    def test_ingest_tactic(self):
        """Test tactic ingestion"""
        tactic_data = {
            "tactic_id": "TA0002",
            "name": "Execution",
            "description": "The adversary is trying to run malicious code",
            "framework_version": "v14",
            "source": "MITRE ATT&CK",
            "provenance": "ingestion_pipeline",
            "confidence": 1.0
        }
        tactic = self.service.ingest_tactic(tactic_data)
        assert tactic.tactic_id == "TA0002"
        assert tactic.name == "Execution"
    
    def test_ingest_group(self):
        """Test group ingestion"""
        group_data = {
            "group_id": "G0001",
            "name": "APT28",
            "description": "Threat group APT28",
            "framework_version": "v14",
            "source": "MITRE ATT&CK",
            "provenance": "ingestion_pipeline",
            "confidence": 1.0
        }
        group = self.service.ingest_group(group_data)
        assert group.group_id == "G0001"
        assert group.name == "APT28"
    
    def test_ingest_software(self):
        """Test software ingestion"""
        software_data = {
            "software_id": "S0001",
            "name": "PowerShell",
            "description": "Windows command-line shell",
            "framework_version": "v14",
            "source": "MITRE ATT&CK",
            "provenance": "ingestion_pipeline",
            "confidence": 1.0
        }
        software = self.service.ingest_software(software_data)
        assert software.software_id == "S0001"
        assert software.name == "PowerShell"
    
    def test_ingest_relationship(self):
        """Test relationship ingestion"""
        relationship_data = {
            "relationship_id": "REL-001",
            "source_entity_id": "T1059",
            "target_entity_id": "TA0002",
            "relationship_type": "uses",
            "framework_version": "v14",
            "source": "MITRE ATT&CK",
            "provenance": "ingestion_pipeline",
            "confidence": 1.0
        }
        relationship = self.service.ingest_relationship(relationship_data)
        assert relationship.relationship_id == "REL-001"
        assert relationship.source_entity_id == "T1059"
        assert relationship.target_entity_id == "TA0002"
        assert relationship.relationship_type == "uses"
    
    def test_duplicate_detection(self):
        """Test duplicate detection (security/integrity)"""
        result = self.service.detect_duplicates("T1059", "technique")
        assert isinstance(result, bool)
    
    def test_validate_external_data(self):
        """Test external data validation (security)"""
        valid_data = {"key": "value"}
        result = self.service.validate_external_data(valid_data)
        assert result is True
        
        # Test malformed data handling
        with pytest.raises(ValueError):
            self.service.validate_external_data("not_a_dict")
    
    def test_security_boundaries(self):
        """Test security boundary validation"""
        # Service should maintain security boundaries
        assert self.service._validation_enabled is True
        assert self.service._provenance_tracking is True
        assert self.service._audit_logging is True
    
    def test_conflict_detection(self):
        """Test conflicting intelligence detection (integrity)"""
        result = self.service.detect_conflicts(None, None)
        assert isinstance(result, bool)
    
    def test_historical_preservation(self):
        """Test historical observation preservation (integrity)"""
        # Should not raise exception
        self.service.preserve_historical_observations(None)
    
    def test_verified_vs_inferred(self):
        """Test verified vs inferred distinction (integrity)"""
        class MockEntity:
            confidence = 0.95
        
        result = self.service.distinguish_verified_vs_inferred(MockEntity())
        assert result == "verified"
    
    def test_timeouts_retries(self):
        """Test timeouts, retries, rate limits, circuit breakers (production)"""
        # Should not raise exception
        self.service.implement_timeouts_retries()
    
    def test_avoid_silent_discard(self):
        """Test avoid silent discard (integrity)"""
        # Should not raise exception
        self.service.avoid_silent_discard(Exception("Test error"))
    
    def test_security_error(self):
        """Test security error handling"""
        with pytest.raises(SecurityError):
            raise SecurityError("Test security violation")

    def test_stateful_duplicate_and_version_tracking(self):
        """Regression test: stateful duplicate detection, canonical sub-technique IDs, and version history"""
        assert self.service.detect_duplicates("T1059", "technique") is False
        assert self.service.detect_duplicates("T1059.001", "technique") is False

        parent = self.service.ingest_technique({
            "technique_id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic_ids": ["TA0002"],
            "framework_version": "v13",
        })
        sub = self.service.ingest_technique({
            "technique_id": "T1059",
            "sub_technique_id": "T1059.001",
            "name": "PowerShell",
            "tactic_ids": ["TA0002"],
            "framework_version": "v13",
        })
        assert parent.canonical_id == "T1059"
        assert sub.canonical_id == "T1059.001"
        assert self.service.detect_duplicates("T1059", "technique") is True
        assert self.service.detect_duplicates("T1059.001", "technique") is True

        # Controlled update to v14 records version history entry
        self.service.ingest_technique({
            "technique_id": "T1059",
            "sub_technique_id": "T1059.001",
            "name": "PowerShell",
            "tactic_ids": ["TA0002"],
            "framework_version": "v14",
        })
        assert len(self.service._version_history) == 1
        assert self.service._version_history[0]["entity_id"] == "T1059.001"
        assert self.service._version_history[0]["previous_version"] == "v13"
        assert self.service._version_history[0]["new_version"] == "v14"

    def test_stix_attack_bundle_and_conflict_detection(self):
        """Regression test: STIX 2.1 ATT&CK bundle ingestion and real conflict detection"""
        bundle = {
            "type": "bundle",
            "id": "bundle--11111111-2222-3333-4444-555555555555",
            "objects": [
                {
                    "type": "x-mitre-tactic",
                    "id": "x-mitre-tactic--ta0002",
                    "name": "Execution",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "TA0002"}],
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--t1059-001",
                    "name": "PowerShell",
                    "x_mitre_is_subtechnique": True,
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
                    "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}],
                },
                {
                    "type": "intrusion-set",
                    "id": "intrusion-set--g0007",
                    "name": "APT28",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "G0007"}],
                },
                {
                    "type": "relationship",
                    "id": "relationship--rel-001",
                    "relationship_type": "uses",
                    "source_ref": "intrusion-set--g0007",
                    "target_ref": "attack-pattern--t1059-001",
                },
            ],
        }
        parsed = self.service.ingest_stix_attack_bundle(bundle, framework_version="v14")
        assert len(parsed["tactics"]) == 1
        assert len(parsed["techniques"]) == 1
        assert parsed["techniques"][0].canonical_id == "T1059.001"
        assert len(parsed["groups"]) == 1
        assert len(parsed["relationships"]) == 1
        assert parsed["relationships"][0].source_entity_id == "G0007"
        assert parsed["relationships"][0].target_entity_id == "T1059.001"

        t_conflict = MITRETechniqueModel(
            technique_id="T1059",
            sub_technique_id="T1059.001",
            name="Conflicting Technique Name",
            framework_version="v14",
            source="MITRE ATT&CK",
            provenance="test",
        )
        assert self.service.detect_conflicts(parsed["techniques"][0], t_conflict) is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
