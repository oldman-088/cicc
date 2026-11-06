"""
Unit Tests for OSINT Intelligence Sources Integration Foundation (P1-04)

Tests cover:
- OSINTSourceModel validation and creation
- OSINTRecordModel normalization and STIX 2.1 compatibility
- OSINTHistoryModel tracking and provenance
- OSINTIngestionService pipeline (registration, ingestion, deduplication, conflict handling)
- Security boundaries and authorization simulation
- Timeouts, retries, rate limits, circuit breakers simulation
- Coordination interfaces (Agent 1, Agent 3, Agent 4)
- Experimental labeling (EXPERIMENTAL_DEMO_DATA_ONLY)
- STIX 2.1/TAXII 2.1 compatibility simulation
- Offline fixtures and deterministic tests (no live verification)
"""

import pytest
from datetime import datetime, timezone
from apps.threat_intelligence.osint_sources import (
    OSINTSourceModel,
    OSINTRecordModel,
    OSINTHistoryModel,
    OSINTIngestionService,
    EXPERIMENTAL_DEMO_DATA_ONLY
)

class TestOSINTSourceModel:
    
    def test_create_source(self):
        """Test OSINT source creation with STIX/TAXII compatibility"""
        source = OSINTSourceModel(
            source_name="MITRE ATT&CK TAXII Feed",
            source_type="stix_taxii",
            source_url="https://cti-taxii.mitre.org/stix/collections/",
            collection_id="enterprise-attack",
            confidence_score=0.9,
            provenance="community",
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )
        
        assert source.source_id is not None
        assert source.source_name == "MITRE ATT&CK TAXII Feed"
        assert source.source_type == "stix_taxii"
        assert source.confidence_score == 0.9
        assert source.provenance == "community"
        assert source.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY
        assert source.is_active is True
    
    def test_experimental_label(self):
        """Test experimental labeling constraint"""
        source = OSINTSourceModel(
            source_name="Test Source",
            source_type="threat_actor",
            provenance="vendor",
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )
        assert source.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY
    
    def test_invalid_experimental_label(self):
        """Test validation failure for invalid experimental label"""
        with pytest.raises(ValueError, match="Experimental label must be"):
            OSINTSourceModel(
                source_name="Test Source",
                source_type="threat_actor",
                provenance="vendor",
                experimental_label="INVALID_LABEL"
            )

class TestOSINTRecordModel:
    
    def test_create_record(self):
        """Test OSINT record creation with STIX 2.1 objects"""
        record = OSINTRecordModel(
            source_id="source-123",
            stix_id="indicator--12345678-1234-1234-1234-123456789012",
            object_type="indicator",
            pattern="[file:hashes.'SHA-256' = 'abc123']",
            pattern_type="stix",
            name="Malicious File Hash",
            description="Malicious file hash indicator",
            confidence=0.85,
            provenance="community",
            verified_vs_inferred="inferred",
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY,
            related_to=["threat-actor--12345678-1234-1234-1234-123456789013"]
        )
        
        assert record.record_id is not None
        assert record.source_id == "source-123"
        assert record.stix_id == "indicator--12345678-1234-1234-1234-123456789012"
        assert record.object_type == "indicator"
        assert record.pattern == "[file:hashes.'SHA-256' = 'abc123']"
        assert record.pattern_type == "stix"
        assert record.confidence == 0.85
        assert record.provenance == "community"
        assert record.verified_vs_inferred == "inferred"
        assert record.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY
        assert len(record.related_to) == 1

class TestOSINTHistoryModel:
    
    def test_create_history(self):
        """Test historical tracking creation"""
        history = OSINTHistoryModel(
            source_id="source-123",
            record_id="record-456",
            action="ingest",
            previous_state=None,
            new_state={"object_type": "indicator", "confidence": 0.85},
            provenance="community",
            confidence=0.85,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )
        
        assert history.history_id is not None
        assert history.source_id == "source-123"
        assert history.record_id == "record-456"
        assert history.action == "ingest"
        assert history.provenance == "community"
        assert history.confidence == 0.85
        assert history.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY

class TestOSINTIngestionService:
    
    def setup_method(self):
        """Setup service before each test"""
        self.service = OSINTIngestionService()
    
    def test_register_source(self):
        """Test source registration and security boundaries"""
        source = OSINTSourceModel(
            source_name="CISA KEV OSINT Feed",
            source_type="stix_taxii",
            source_url="https://cisa.gov/stix/collections/",
            collection_id="kev",
            confidence_score=0.95,
            provenance="government",
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )
        
        registered = self.service.register_source(source)
        assert registered.source_id == source.source_id
        assert source.source_id in self.service.sources
        assert len(self.service.history) == 1
    
    def test_ingest_stix_bundle(self):
        """Test STIX 2.1 bundle ingestion and normalization"""
        source = OSINTSourceModel(
            source_name="Test OSINT Feed",
            source_type="stix_taxii",
            provenance="community",
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )
        self.service.register_source(source)
        
        # STIX 2.1 bundle simulation (offline fixtures)
        stix_objects = [
            {
                "id": "indicator--12345678-1234-1234-1234-123456789012",
                "type": "indicator",
                "pattern": "[file:hashes.'SHA-256' = 'abc123']",
                "pattern_type": "stix",
                "name": "Malicious File Hash",
                "description": "Malicious file hash indicator",
                "object_refs": []
            },
            {
                "id": "threat-actor--12345678-1234-1234-1234-123456789013",
                "type": "threat-actor",
                "name": "APT Group X",
                "description": "Advanced persistent threat group",
                "object_refs": []
            }
        ]
        
        records = self.service.ingest_stix_bundle(source.source_id, stix_objects)
        
        assert len(records) == 2
        assert records[0].object_type == "indicator"
        assert records[1].object_type == "threat-actor"
        assert records[0].stix_id == "indicator--12345678-1234-1234-1234-123456789012"
        assert records[1].stix_id == "threat-actor--12345678-1234-1234-1234-123456789013"
        assert len(self.service.history) == 3  # 1 registration + 2 ingestions
    
    def test_duplicate_detection(self):
        """Test duplicate detection and conflict handling"""
        source = OSINTSourceModel(
            source_name="Test OSINT Feed",
            source_type="stix_taxii",
            provenance="community",
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )
        self.service.register_source(source)
        
        stix_object = {
            "id": "indicator--12345678-1234-1234-1234-123456789012",
            "type": "indicator",
            "pattern": "[file:hashes.'SHA-256' = 'abc123']",
            "pattern_type": "stix",
            "name": "Malicious File Hash",
            "description": "Malicious file hash indicator"
        }
        
        # First ingestion
        records1 = self.service.ingest_stix_bundle(source.source_id, [stix_object])
        assert len(records1) == 1
        
        # Second ingestion (duplicate) - should detect conflict and NOT create new record
        records2 = self.service.ingest_stix_bundle(source.source_id, [stix_object])
        
        # The service should detect the duplicate and handle conflict (not add new record)
        # The test expects 0 new records returned (conflict handled)
        assert len(records2) == 0  # Duplicate detected and handled
        
        # History should show conflict
        conflict_histories = [h for h in self.service.history if h.action == "conflict"]
        assert len(conflict_histories) == 1
    
    def test_security_boundaries(self):
        """Test security boundaries and authorization simulation"""
        self.service = OSINTIngestionService()
        
        # Attempt ingestion without registration should raise PermissionError
        stix_object = {
            "id": "indicator--12345678-1234-1234-1234-123456789012",
            "type": "indicator"
        }
        
        # The _validate_security_boundaries method raises PermissionError for unregistered sources
        with pytest.raises(PermissionError, match="Source source-unknown not found or unauthorized for ingest"):
            self.service.ingest_stix_bundle("source-unknown", [stix_object])
    
    def test_malformed_data_handling(self):
        """Test safe handling of malformed or malicious feed data"""
        source = OSINTSourceModel(
            source_name="Test OSINT Feed",
            source_type="stix_taxii",
            provenance="community",
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )
        self.service.register_source(source)
        
        # Malformed objects (should be safely skipped)
        malformed_objects = [
            None,
            "not_a_dict",
            {"type": "indicator"},  # Missing ID
            {"id": "indicator--123"},  # Missing type
            {"id": "indicator--123", "type": "indicator", "pattern": "[file:hashes.'SHA-256' = 'abc123']"}  # Valid
        ]
        
        records = self.service.ingest_stix_bundle(source.source_id, malformed_objects)
        
        # Only the valid object should be ingested
        assert len(records) == 1
        assert records[0].object_type == "indicator"
        assert records[0].stix_id == "indicator--123"
    
    def test_get_records_by_type(self):
        """Test retrieval by STIX object type"""
        source = OSINTSourceModel(
            source_name="Test OSINT Feed",
            source_type="stix_taxii",
            provenance="community",
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )
        self.service.register_source(source)
        
        stix_objects = [
            {"id": "indicator--1", "type": "indicator", "pattern": "[file:hashes.'SHA-256' = 'abc123']"},
            {"id": "threat-actor--1", "type": "threat-actor", "name": "APT Group X"},
            {"id": "campaign--1", "type": "campaign", "name": "Operation X"}
        ]
        
        self.service.ingest_stix_bundle(source.source_id, stix_objects)
        
        indicators = self.service.get_records_by_type("indicator")
        threat_actors = self.service.get_records_by_type("threat-actor")
        campaigns = self.service.get_records_by_type("campaign")
        
        assert len(indicators) == 1
        assert len(threat_actors) == 1
        assert len(campaigns) == 1
    
    def test_source_statistics(self):
        """Test source statistics calculation"""
        source = OSINTSourceModel(
            source_name="Test OSINT Feed",
            source_type="stix_taxii",
            provenance="community",
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )
        self.service.register_source(source)
        
        stix_objects = [
            {"id": "indicator--1", "type": "indicator", "pattern": "[file:hashes.'SHA-256' = 'abc123']"},
            {"id": "threat-actor--1", "type": "threat-actor", "name": "APT Group X"}
        ]
        
        self.service.ingest_stix_bundle(source.source_id, stix_objects)
        
        stats = self.service.get_source_statistics(source.source_id)
        
        assert stats["source_id"] == source.source_id
        assert stats["total_records"] == 2
        assert "indicator" in stats["object_types"]
        assert "threat-actor" in stats["object_types"]
        assert stats["confidence_avg"] == 0.5  # Default confidence
    
    def test_coordination_interfaces(self):
        """Test coordination with Agent 1, Agent 3, Agent 4"""
        # Agent 1 coordination
        result1 = self.service.coordinate_with_agent_1({"task": "ingest_stix"})
        assert result1["status"] == "coordinated"
        assert result1["agent"] == "Agent 1"
        assert "timestamp" in result1
        
        # Agent 3 coordination
        result3 = self.service.coordinate_with_agent_3([
            {"cve": "CVE-2023-1234", "ioc": "indicator--123"}
        ])
        assert result3["status"] == "coordinated"
        assert result3["agent"] == "Agent 3"
        assert result3["ioc_count"] == 1
        assert "CVE-2023-1234" in result3["cve_references"]
        
        # Agent 4 coordination
        result4 = self.service.coordinate_with_agent_4({"frontend_data": "ready"})
        assert result4["status"] == "coordinated"
        assert result4["agent"] == "Agent 4"
        assert result4["frontend_ready"] is True
    
    def test_timeouts_retries_simulation(self):
        """Test timeout/retry/rate limit/circuit breaker simulation"""
        # These are simulation methods (always succeed in offline fixtures)
        assert self.service._simulate_timeout_retry("ingest") is True
        assert self.service._simulate_rate_limit("source-123") is True
        assert self.service._simulate_circuit_breaker("source-123") is True
    
    def test_experimental_label_consistency(self):
        """Test experimental labeling across all components"""
        source = OSINTSourceModel(
            source_name="Test",
            source_type="stix_taxii",
            provenance="community",
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )
        
        record = OSINTRecordModel(
            source_id="source-123",
            stix_id="indicator--123",
            object_type="indicator",
            provenance="community",
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )
        
        history = OSINTHistoryModel(
            source_id="source-123",
            record_id="record-456",
            action="ingest",
            provenance="community",
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )
        
        assert source.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY
        assert record.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY
        assert history.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY
