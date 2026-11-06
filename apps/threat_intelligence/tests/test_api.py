import pytest
from datetime import datetime, timedelta
from pydantic import ValidationError
from apps.threat_intelligence.api import (
    ThreatIntelligenceAPI,
    ThreatIntelligenceRequest,
    ThreatIntelligenceResponse,
    Agent1CoordinationContract,
    Agent4FrontendContract,
    SecurityError,
    EXPERIMENTAL_DEMO_DATA_ONLY,
    app  # Import FastAPI app for test client
)

from apps.threat_intelligence.relationship_analysis import (
    RelationshipAnalysisEngine,
    RelationshipType,
    RelationshipConfidence,
    RelationshipEvidence,
    EntityReference,
    RelationshipRecord
)

from apps.threat_intelligence.source_adapters import SourceAdapterConfig, ThreatIntelligenceSourceAdapter

class TestThreatIntelligenceAPI:
    """Unit tests for Threat Intelligence API Implementation & Mounting (P1-05 + P2-01)"""

    @pytest.fixture
    def api_request(self):
        """Fixture for API request schema"""
        return ThreatIntelligenceRequest(
            tenant_id="tenant-123",
            query="test",
            limit=10,
            offset=0,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

    @pytest.fixture
    def relationship_engine(self):
        """Fixture for Relationship Analysis Engine (P2-01)"""
        return RelationshipAnalysisEngine()

    @pytest.fixture
    def sample_entities(self):
        """Fixture for sample entities (EXPERIMENTAL_DEMO_DATA_ONLY)"""
        return {
            "threat_actor": EntityReference(
                entity_id="TA-001",
                entity_type="ThreatActor",
                name="APT-29",
                experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
            ),
            "malware": EntityReference(
                entity_id="MW-001",
                entity_type="Malware",
                name="SolarWinds-Sunburst",
                experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
            ),
            "campaign": EntityReference(
                entity_id="CMP-001",
                entity_type="Campaign",
                name="SolarWinds-Campaign-2020",
                experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
            )
        }

    @pytest.fixture
    def sample_evidence(self):
        """Fixture for sample relationship evidence (EXPERIMENTAL_DEMO_DATA_ONLY)"""
        return [
            RelationshipEvidence(
                source="CISA-KEV-2020-001",
                description="Attribution evidence from CISA KEV report",
                confidence=RelationshipConfidence.CONFIRMED,
                provenance="CISA-KEV-Integration-Connector",
                experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
            )
        ]

    # --- P1-05 FOUNDATION TESTS (PRESERVED - 10 TESTS) ---

    def test_api_initialization(self):
        """Test API initialization and security boundaries"""
        api = ThreatIntelligenceAPI(tenant_id="tenant-123", experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY)
        assert api.tenant_id == "tenant-123"
        assert api.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY
        assert api._validation_enabled is True
        assert api._provenance_tracking is True
        assert api._audit_logging is True

    def test_request_schema_validation(self):
        """Test ThreatIntelligenceRequest schema validation"""
        # Valid request
        req = ThreatIntelligenceRequest(tenant_id="tenant-123", query="test", limit=50, offset=0, experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY)
        assert req.tenant_id == "tenant-123"
        assert req.limit == 50

        # Invalid experimental label
        with pytest.raises(ValidationError):
            ThreatIntelligenceRequest(experimental_label="INVALID_LABEL")

    def test_response_schema_validation(self):
        """Test ThreatIntelligenceResponse schema validation"""
        resp = ThreatIntelligenceResponse(
            status="success",
            data=[{"id": "1"}],
            total_count=1,
            has_more=False,
            provenance="test_provenance",
            confidence=1.0,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY,
            timestamp=datetime.utcnow()
        )
        assert resp.status == "success"
        assert resp.total_count == 1
        assert resp.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_endpoint_mounting(self):
        """Test API endpoint mounting (Agent 1/4 coordination)"""
        api = ThreatIntelligenceAPI()

        def dummy_handler(req):
            return {"data": [], "total_count": 0, "has_more": False}

        success = api.mount_endpoint("/api/v1/test", dummy_handler)
        assert success is True
        assert "/api/v1/test" in api._mounted_endpoints

    def test_endpoint_invocation(self):
        """Test endpoint invocation through intended CICC integration path"""
        api = ThreatIntelligenceAPI(tenant_id="tenant-123", experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY)
        request = ThreatIntelligenceRequest(tenant_id="tenant-123", query="actor", limit=10, offset=0, experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY)

        # Invoke actors endpoint (P1-05 mounting)
        response = api.invoke_endpoint("/api/v1/threat-intelligence/actors", request)

        assert response["status"] == "success"
        assert response["provenance"].startswith("threat_intelligence_api_v1::/api/v1/threat-intelligence/actors")
        assert response["experimental_label"] == EXPERIMENTAL_DEMO_DATA_ONLY
        assert len(response["data"]) > 0
        assert response["data"][0]["label"] == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_security_boundaries_validation(self):
        """Test security boundaries validation (Agent 1/4 requirement)"""
        api = ThreatIntelligenceAPI()
        api._validation_enabled = False

        request = ThreatIntelligenceRequest(experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY)
        with pytest.raises(SecurityError, match="Input validation disabled"):
            api._validate_security_boundaries()

    def test_malformed_request_handling(self):
        """Test malformed request handling (security measure)"""
        api = ThreatIntelligenceAPI()
        error = ValueError("Test error")
        response = api.handle_malformed_request(error)

        assert response["status"] == "error"
        assert response["provenance"] == "threat_intelligence_api_v1"
        assert response["experimental_label"] == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_agent1_coordination_contract(self):
        """Test contract compatibility with Agent 1 (Coordination)"""
        api = ThreatIntelligenceAPI(tenant_id="tenant-1", experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY)

        # Register domain gateway
        registered = Agent1CoordinationContract.register_domain_gateway(api)
        assert registered is True

        # Invoke through gateway
        request = ThreatIntelligenceRequest(tenant_id="tenant-1", query="test", experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY)
        response = Agent1CoordinationContract.invoke_through_gateway("/api/v1/threat-intelligence/actors", request)

        assert response["status"] == "success"
        assert response["provenance"].startswith("threat_intelligence_api_v1")

    def test_agent4_frontend_contract(self):
        """Test contract compatibility with Agent 4 (Frontend Integration)"""
        api = ThreatIntelligenceAPI(experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY)
        request = ThreatIntelligenceRequest(experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY)
        response = api.invoke_endpoint("/api/v1/threat-intelligence/actors", request)

        # Validate frontend response format
        valid = Agent4FrontendContract.validate_frontend_response(response)
        assert valid is True

    def test_idempotency_and_provenance(self):
        """Test idempotency, provenance preservation, and confidence tracking"""
        api = ThreatIntelligenceAPI(experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY)
        request = ThreatIntelligenceRequest(experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY)

        response1 = api.invoke_endpoint("/api/v1/threat-intelligence/actors", request)
        response2 = api.invoke_endpoint("/api/v1/threat-intelligence/actors", request)

        # Provenance should include path and timestamp should differ
        assert response1["provenance"] == response2["provenance"]
        assert response1["confidence"] == response2["confidence"] == 1.0
        assert response1["experimental_label"] == response2["experimental_label"] == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_integration_with_existing_modules(self):
        """Test integration with P1-01, P1-02, P1-03, P1-04 modules"""
        api = ThreatIntelligenceAPI(experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY)
        request = ThreatIntelligenceRequest(experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY)

        # Test MITRE Ingestion (P1-01)
        resp_mitre = api.invoke_endpoint("/api/v1/threat-intelligence/mitre-ingestion", request)
        assert resp_mitre["status"] == "success"
        assert "MITRE-001" in str(resp_mitre["data"])

        # Test CISA KEV (P1-02)
        resp_kev = api.invoke_endpoint("/api/v1/threat-intelligence/cisa-kev", request)
        assert resp_kev["status"] == "success"
        assert "KEV-001" in str(resp_kev["data"])

        # Test Vendor Advisories (P1-03)
        resp_vendor = api.invoke_endpoint("/api/v1/threat-intelligence/vendor-advisories", request)
        assert resp_vendor["status"] == "success"
        assert "VEND-001" in str(resp_vendor["data"])

        # Test OSINT Sources (P1-04)
        resp_osint = api.invoke_endpoint("/api/v1/threat-intelligence/osint-sources", request)
        assert resp_osint["status"] == "success"
        assert "OSINT-001" in str(resp_osint["data"])

    def test_source_adapter_mounting(self):
        """Test source adapter foundation mounting and invocation (P1-05 Advancement)"""
        api = ThreatIntelligenceAPI()

        # Verify source adapter endpoint is mounted
        assert "/api/v1/threat-intelligence/source-adapters" in api._mounted_endpoints

        request = ThreatIntelligenceRequest(experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY)
        response = api.invoke_endpoint("/api/v1/threat-intelligence/source-adapters", request)

        assert response["status"] == "success"
        assert response["experimental_label"] == EXPERIMENTAL_DEMO_DATA_ONLY
        assert "provenance" in response

    def test_source_adapter_security_error(self):
        """Test source adapter security error handling"""
        api = ThreatIntelligenceAPI()

        # Test security boundary validation
        api._validation_enabled = False
        with pytest.raises(SecurityError, match="Input validation disabled"):
            api._validate_security_boundaries()

        # Restore validation
        api._validation_enabled = True

    def test_source_adapter_timeout_simulation(self):
        """Test source adapter timeout/retry/rate limit simulation (P1-05 Advancement)"""
        # Create adapter configuration
        config = SourceAdapterConfig(
            adapter_id="ADAPT-001",
            configuration={"timeout": 30, "retries": 3, "rate_limit": 100},
            provenance="SourceAdapter-Foundation",
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        # Test configuration validation
        assert config.adapter_id == "ADAPT-001"
        assert config.configuration["timeout"] == 30
        assert config.configuration["retries"] == 3
        assert config.configuration["rate_limit"] == 100
        assert config.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_source_adapter_circuit_breaker(self):
        """Test source adapter circuit breaker simulation (P1-05 Advancement)"""
        # Create adapter configuration with circuit breaker settings
        config = SourceAdapterConfig(
            adapter_id="ADAPT-002",
            configuration={"circuit_breaker": True, "failure_threshold": 5},
            provenance="SourceAdapter-Foundation",
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        # Test circuit breaker configuration
        assert config.configuration["circuit_breaker"] is True
        assert config.configuration["failure_threshold"] == 5
        assert config.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_source_adapter_integration(self):
        """Test source adapter integration with API mounting (P1-05 Advancement)"""
        api = ThreatIntelligenceAPI()

        # Test integration path simulation
        config = SourceAdapterConfig(
            adapter_id="ADAPT-003",
            configuration={"integration": "test"},
            provenance="SourceAdapter-Foundation",
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        # Verify mounting and invocation
        assert "/api/v1/threat-intelligence/source-adapters" in api._mounted_endpoints

        request = ThreatIntelligenceRequest(experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY)
        response = api.invoke_endpoint("/api/v1/threat-intelligence/source-adapters", request)

        assert response["status"] == "success"
        assert response["experimental_label"] == EXPERIMENTAL_DEMO_DATA_ONLY
        assert "provenance" in response

    # --- P2-01 RELATIONSHIP ANALYSIS ENGINE TESTS (NEW - 10 TESTS) ---

    def test_relationship_engine_initialization(self, relationship_engine):
        """Test P2-01 Relationship Analysis Engine initialization"""
        assert relationship_engine is not None
        assert relationship_engine.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY
        assert len(relationship_engine.relationships) == 0
        assert len(relationship_engine.entity_index) == 0

    def test_relationship_creation_and_preservation(self, relationship_engine, sample_entities, sample_evidence):
        """Test relationship creation with provenance preservation and conflict handling (P2-01)"""
        record = relationship_engine.create_relationship(
            source_entity=sample_entities["threat_actor"],
            target_entity=sample_entities["malware"],
            relationship_type=RelationshipType.USES,
            confidence=RelationshipConfidence.CONFIRMED,
            evidence=sample_evidence,
            provenance="CISA-KEV-Integration-Connector",
            confirmed=True,
            conflicting_intelligence=[
                {
                    "source": "Vendor-Advisory-2020-001",
                    "conflict_description": "Vendor advisory suggests different attribution",
                    "confidence": RelationshipConfidence.LOW.value,
                    "experimental_label": EXPERIMENTAL_DEMO_DATA_ONLY
                }
            ],
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        assert record is not None
        assert record.relationship_id is not None
        assert record.source_entity.entity_id == "TA-001"
        assert record.target_entity.entity_id == "MW-001"
        assert record.relationship_type == RelationshipType.USES
        assert record.confidence == RelationshipConfidence.CONFIRMED
        assert record.confirmed is True
        assert record.provenance == "CISA-KEV-Integration-Connector"
        assert record.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY
        assert len(record.evidence) == 1
        assert record.conflicting_intelligence is not None
        assert len(record.conflicting_intelligence) == 1

        # Verify storage and indexing
        assert record.relationship_id in relationship_engine.relationships
        assert len(relationship_engine.entity_index) == 2

    def test_relationship_traversal_analysis(self, relationship_engine, sample_entities, sample_evidence):
        """Test explainable relationship traversal (P2-01)"""
        # Create relationship chain
        relationship_engine.create_relationship(
            source_entity=sample_entities["threat_actor"],
            target_entity=sample_entities["malware"],
            relationship_type=RelationshipType.USES,
            confidence=RelationshipConfidence.CONFIRMED,
            evidence=sample_evidence,
            provenance="CISA-KEV-Integration-Connector",
            confirmed=True,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        relationship_engine.create_relationship(
            source_entity=sample_entities["malware"],
            target_entity=sample_entities["campaign"],
            relationship_type=RelationshipType.ASSOCIATED_WITH,
            confidence=RelationshipConfidence.HIGH,
            evidence=[],
            provenance="OSINT-Integration-Foundation",
            confirmed=False,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        # Traverse relationships
        traversal = relationship_engine.traverse_relationships(
            start_entity_id="TA-001",
            start_entity_type="ThreatActor",
            max_depth=3
        )

        assert traversal["start_entity"]["id"] == "TA-001"
        assert traversal["start_entity"]["type"] == "ThreatActor"
        assert traversal["max_depth"] == 3
        assert traversal["relationships_found"] == 2
        assert traversal["visited_entities"] == 3
        assert traversal["experimental_label"] == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_campaign_correlation_analysis(self, relationship_engine, sample_entities):
        """Test campaign correlation analysis (P2-01)"""
        # Create campaign relationships
        relationship_engine.create_relationship(
            source_entity=sample_entities["campaign"],
            target_entity=sample_entities["threat_actor"],
            relationship_type=RelationshipType.ATTRIBUTED_TO,
            confidence=RelationshipConfidence.HIGH,
            evidence=[],
            provenance="OSINT-Integration-Foundation",
            confirmed=False,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        # Create second campaign
        campaign_2 = EntityReference(
            entity_id="CMP-002",
            entity_type="Campaign",
            name="SolarWinds-Campaign-2021",
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        relationship_engine.create_relationship(
            source_entity=campaign_2,
            target_entity=sample_entities["threat_actor"],
            relationship_type=RelationshipType.ATTRIBUTED_TO,
            confidence=RelationshipConfidence.HIGH,
            evidence=[],
            provenance="OSINT-Integration-Foundation",
            confirmed=False,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        # Correlate campaigns
        correlation = relationship_engine.correlate_campaigns(["CMP-001", "CMP-002"])

        assert correlation["campaigns_analyzed"] == 2
        assert "CMP-001" in correlation["correlation_results"]
        assert "CMP-002" in correlation["correlation_results"]
        assert correlation["experimental_label"] == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_intelligence_graph_preparation(self, relationship_engine, sample_entities):
        """Test intelligence graph preparation for investigation-ready records (P2-01)"""
        # Create relationships
        relationship_engine.create_relationship(
            source_entity=sample_entities["threat_actor"],
            target_entity=sample_entities["malware"],
            relationship_type=RelationshipType.USES,
            confidence=RelationshipConfidence.CONFIRMED,
            evidence=[],
            provenance="CISA-KEV-Integration-Connector",
            confirmed=True,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        # Prepare graph
        graph = relationship_engine.prepare_intelligence_graph(
            entity_ids=["TA-001", "MW-001"],
            entity_types=["ThreatActor", "Malware"]
        )

        assert graph["total_nodes"] == 2
        assert graph["total_edges"] == 1
        assert graph["experimental_label"] == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_conflict_resolution_and_timeline(self, relationship_engine, sample_entities):
        """Test conflicting intelligence resolution and threat activity timeline (P2-01)"""
        # Create relationship with conflicting intelligence
        record = relationship_engine.create_relationship(
            source_entity=sample_entities["threat_actor"],
            target_entity=sample_entities["campaign"],
            relationship_type=RelationshipType.ATTRIBUTED_TO,
            confidence=RelationshipConfidence.HIGH,
            evidence=[],
            provenance="OSINT-Integration-Foundation",
            confirmed=False,
            conflicting_intelligence=[
                {
                    "source": "Vendor-Advisory-2020-001",
                    "conflict_description": "Vendor advisory suggests different attribution",
                    "confidence": RelationshipConfidence.LOW.value,
                    "experimental_label": EXPERIMENTAL_DEMO_DATA_ONLY
                }
            ],
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        # Test conflict resolution (preserves original, doesn't discard)
        resolution = relationship_engine.resolve_conflicting_intelligence(record.relationship_id)
        assert "error" not in resolution
        assert resolution["relationship_id"] == str(record.relationship_id)
        assert resolution["original_record"]["type"] == RelationshipType.ATTRIBUTED_TO.value
        assert resolution["conflicting_intelligence"] is not None
        assert len(resolution["conflicting_intelligence"]) == 1
        assert resolution["resolution_strategy"] == "PRESERVE_ORIGINAL_WITH_CONFLICT_TRACKING"
        assert resolution["experimental_label"] == EXPERIMENTAL_DEMO_DATA_ONLY

        # Test threat activity timeline
        now = datetime.utcnow()
        relationship_engine.create_relationship(
            source_entity=sample_entities["threat_actor"],
            target_entity=sample_entities["malware"],
            relationship_type=RelationshipType.USES,
            confidence=RelationshipConfidence.CONFIRMED,
            evidence=[],
            provenance="CISA-KEV-Integration-Connector",
            confirmed=True,
            temporal_context={
                "start_time": now - timedelta(days=30),
                "end_time": now - timedelta(days=15),
                "description": "Initial compromise phase"
            },
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        timeline = relationship_engine.generate_threat_activity_timeline(
            entity_id="TA-001",
            entity_type="ThreatActor"
        )

        assert timeline["entity_id"] == "TA-001"
        assert timeline["entity_type"] == "ThreatActor"
        assert timeline["total_events"] == 1
        assert timeline["experimental_label"] == EXPERIMENTAL_DEMO_DATA_ONLY

# Export test class
__all__ = [
    "TestThreatIntelligenceAPI"
]
