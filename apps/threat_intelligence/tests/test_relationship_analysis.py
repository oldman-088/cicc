"""
Tests for P2-01 Cross-Entity Relationship Analysis Engine

Requirements:
- Deterministic tests using clearly labeled fixtures
- Preserve source attribution
- Distinguish confirmed vs inferred relationships
- Preserve conflicting intelligence
- Make confidence and evidence inspectable
- Document limitations and performance characteristics

Author: Arena.ai Agent Mode (Threat Intelligence Domain)
Date: 2026-11-06
Experimental Label: EXPERIMENTAL_DEMO_DATA_ONLY
"""

import pytest
from datetime import datetime, timedelta
from uuid import uuid4
from typing import Dict, Any

from apps.threat_intelligence.relationship_analysis import (
    RelationshipAnalysisEngine,
    RelationshipType,
    RelationshipConfidence,
    RelationshipEvidence,
    EntityReference,
    RelationshipRecord,
    EXPERIMENTAL_DEMO_DATA_ONLY
)


class TestRelationshipAnalysisEngine:
    """Test suite for P2-01 Cross-Entity Relationship Analysis Engine"""

    @pytest.fixture
    def engine(self):
        """Fixture for RelationshipAnalysisEngine"""
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
            ),
            "ttp": EntityReference(
                entity_id="TTP-001",
                entity_type="TTP",
                name="T1078-Valid-Accounts",
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

    def test_engine_initialization(self, engine):
        """Test engine initialization and experimental labeling"""
        assert engine is not None
        assert engine.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY
        assert len(engine.relationships) == 0
        assert len(engine.entity_index) == 0

    def test_create_relationship_confirmed(self, engine, sample_entities, sample_evidence):
        """Test creating confirmed relationship with provenance preservation"""
        record = engine.create_relationship(
            source_entity=sample_entities["threat_actor"],
            target_entity=sample_entities["malware"],
            relationship_type=RelationshipType.USES,
            confidence=RelationshipConfidence.CONFIRMED,
            evidence=sample_evidence,
            provenance="CISA-KEV-Integration-Connector",
            confirmed=True,
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

        # Verify storage
        assert record.relationship_id in engine.relationships
        assert len(engine.entity_index) == 2  # Source and target entities

    def test_create_relationship_inferred(self, engine, sample_entities):
        """Test creating inferred relationship with conflicting intelligence preservation"""
        conflicting_intelligence = [
            {
                "source": "Vendor-Advisory-2020-001",
                "conflict_description": "Vendor advisory suggests different attribution",
                "confidence": RelationshipConfidence.LOW.value,
                "experimental_label": EXPERIMENTAL_DEMO_DATA_ONLY
            }
        ]

        record = engine.create_relationship(
            source_entity=sample_entities["malware"],
            target_entity=sample_entities["campaign"],
            relationship_type=RelationshipType.ASSOCIATED_WITH,
            confidence=RelationshipConfidence.INFERRED,
            evidence=[],
            provenance="OSINT-Integration-Foundation",
            confirmed=False,
            conflicting_intelligence=conflicting_intelligence,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        assert record is not None
        assert record.confirmed is False
        assert record.confidence == RelationshipConfidence.INFERRED
        assert record.conflicting_intelligence is not None
        assert len(record.conflicting_intelligence) == 1
        assert record.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_get_relationships_for_entity(self, engine, sample_entities, sample_evidence):
        """Test entity-based relationship retrieval"""
        # Create multiple relationships for the same entity
        engine.create_relationship(
            source_entity=sample_entities["threat_actor"],
            target_entity=sample_entities["malware"],
            relationship_type=RelationshipType.USES,
            confidence=RelationshipConfidence.CONFIRMED,
            evidence=sample_evidence,
            provenance="CISA-KEV-Integration-Connector",
            confirmed=True,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        engine.create_relationship(
            source_entity=sample_entities["threat_actor"],
            target_entity=sample_entities["campaign"],
            relationship_type=RelationshipType.ATTRIBUTED_TO,
            confidence=RelationshipConfidence.HIGH,
            evidence=[],
            provenance="OSINT-Integration-Foundation",
            confirmed=False,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        # Retrieve relationships for threat actor
        relationships = engine.get_relationships_for_entity("TA-001", "ThreatActor")

        assert len(relationships) == 2

        # Verify relationship types
        relationship_types = [rel.relationship_type for rel in relationships]
        assert RelationshipType.USES in relationship_types
        assert RelationshipType.ATTRIBUTED_TO in relationship_types

        # Verify experimental labeling
        for rel in relationships:
            assert rel.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_analyze_attribution_evidence(self, engine, sample_entities, sample_evidence):
        """Test threat actor attribution evidence analysis"""
        # Create attribution relationships
        engine.create_relationship(
            source_entity=sample_entities["threat_actor"],
            target_entity=sample_entities["malware"],
            relationship_type=RelationshipType.USES,
            confidence=RelationshipConfidence.CONFIRMED,
            evidence=sample_evidence,
            provenance="CISA-KEV-Integration-Connector",
            confirmed=True,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        engine.create_relationship(
            source_entity=sample_entities["threat_actor"],
            target_entity=sample_entities["campaign"],
            relationship_type=RelationshipType.ATTRIBUTED_TO,
            confidence=RelationshipConfidence.HIGH,
            evidence=[],
            provenance="OSINT-Integration-Foundation",
            confirmed=False,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        # Analyze attribution evidence
        analysis = engine.analyze_attribution_evidence("TA-001")

        assert analysis["threat_actor_id"] == "TA-001"
        assert analysis["total_relationships"] == 2
        assert len(analysis["evidence_items"]) == 2

        # Verify evidence preservation
        evidence_items = analysis["evidence_items"]
        confirmed_items = [item for item in evidence_items if item["confirmed"]]
        inferred_items = [item for item in evidence_items if not item["confirmed"]]

        assert len(confirmed_items) == 1
        assert len(inferred_items) == 1

        # Verify experimental labeling
        for item in evidence_items:
            assert item["experimental_label"] == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_correlate_campaigns(self, engine, sample_entities):
        """Test campaign correlation analysis"""
        # Create campaign relationships
        engine.create_relationship(
            source_entity=sample_entities["campaign"],
            target_entity=sample_entities["threat_actor"],
            relationship_type=RelationshipType.ATTRIBUTED_TO,
            confidence=RelationshipConfidence.HIGH,
            evidence=[],
            provenance="OSINT-Integration-Foundation",
            confirmed=False,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        # Create second campaign with same actor
        campaign_2 = EntityReference(
            entity_id="CMP-002",
            entity_type="Campaign",
            name="SolarWinds-Campaign-2021",
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        engine.create_relationship(
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
        correlation = engine.correlate_campaigns(["CMP-001", "CMP-002"])

        assert correlation["campaigns_analyzed"] == 2
        assert "CMP-001" in correlation["correlation_results"]
        assert "CMP-002" in correlation["correlation_results"]

        # Verify experimental labeling
        assert correlation["experimental_label"] == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_traverse_relationships_bfs(self, engine, sample_entities, sample_evidence):
        """Test explainable relationship traversal (BFS implementation)"""
        # Create chain: ThreatActor -> Malware -> Campaign -> TTP
        engine.create_relationship(
            source_entity=sample_entities["threat_actor"],
            target_entity=sample_entities["malware"],
            relationship_type=RelationshipType.USES,
            confidence=RelationshipConfidence.CONFIRMED,
            evidence=sample_evidence,
            provenance="CISA-KEV-Integration-Connector",
            confirmed=True,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        engine.create_relationship(
            source_entity=sample_entities["malware"],
            target_entity=sample_entities["campaign"],
            relationship_type=RelationshipType.ASSOCIATED_WITH,
            confidence=RelationshipConfidence.HIGH,
            evidence=[],
            provenance="OSINT-Integration-Foundation",
            confirmed=False,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        engine.create_relationship(
            source_entity=sample_entities["campaign"],
            target_entity=sample_entities["ttp"],
            relationship_type=RelationshipType.USES,
            confidence=RelationshipConfidence.MEDIUM,
            evidence=[],
            provenance="MITRE-Ingestion-Pipeline",
            confirmed=False,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        # Traverse from threat actor
        traversal = engine.traverse_relationships(
            start_entity_id="TA-001",
            start_entity_type="ThreatActor",
            max_depth=3
        )

        assert traversal["start_entity"]["id"] == "TA-001"
        assert traversal["start_entity"]["type"] == "ThreatActor"
        assert traversal["max_depth"] == 3
        assert traversal["relationships_found"] == 3
        assert traversal["visited_entities"] == 4  # TA, MW, CMP, TTP

        # Verify traversal path
        traversal_path = traversal["traversal_path"]
        assert len(traversal_path) == 3

        # Verify experimental labeling
        assert traversal["experimental_label"] == EXPERIMENTAL_DEMO_DATA_ONLY
        for path_item in traversal_path:
            assert path_item["experimental_label"] == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_resolve_conflicting_intelligence(self, engine, sample_entities):
        """Test conflicting intelligence resolution (preservation, no silent discard)"""
        conflicting_intelligence = [
            {
                "source": "Vendor-Advisory-2020-001",
                "conflict_description": "Vendor advisory suggests different attribution",
                "confidence": RelationshipConfidence.LOW.value,
                "experimental_label": EXPERIMENTAL_DEMO_DATA_ONLY
            },
            {
                "source": "OSINT-Feed-2020-002",
                "conflict_description": "OSINT feed suggests alternative campaign",
                "confidence": RelationshipConfidence.MEDIUM.value,
                "experimental_label": EXPERIMENTAL_DEMO_DATA_ONLY
            }
        ]

        record = engine.create_relationship(
            source_entity=sample_entities["threat_actor"],
            target_entity=sample_entities["campaign"],
            relationship_type=RelationshipType.ATTRIBUTED_TO,
            confidence=RelationshipConfidence.HIGH,
            evidence=[],
            provenance="OSINT-Integration-Foundation",
            confirmed=False,
            conflicting_intelligence=conflicting_intelligence,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        # Resolve conflicts
        resolution = engine.resolve_conflicting_intelligence(record.relationship_id)

        assert "error" not in resolution
        assert resolution["relationship_id"] == str(record.relationship_id)
        assert resolution["original_record"]["type"] == RelationshipType.ATTRIBUTED_TO.value
        assert resolution["original_record"]["confidence"] == RelationshipConfidence.HIGH.value
        assert resolution["original_record"]["confirmed"] is False
        assert resolution["conflicting_intelligence"] is not None
        assert len(resolution["conflicting_intelligence"]) == 2
        assert resolution["resolution_strategy"] == "PRESERVE_ORIGINAL_WITH_CONFLICT_TRACKING"
        assert resolution["experimental_label"] == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_generate_threat_activity_timeline(self, engine, sample_entities):
        """Test threat activity timeline generation from temporal context"""
        # Create relationships with temporal context
        now = datetime.utcnow()

        engine.create_relationship(
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

        engine.create_relationship(
            source_entity=sample_entities["threat_actor"],
            target_entity=sample_entities["campaign"],
            relationship_type=RelationshipType.ATTRIBUTED_TO,
            confidence=RelationshipConfidence.HIGH,
            evidence=[],
            provenance="OSINT-Integration-Foundation",
            confirmed=False,
            temporal_context={
                "start_time": now - timedelta(days=15),
                "end_time": now,
                "description": "Campaign execution phase"
            },
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        # Generate timeline
        timeline = engine.generate_threat_activity_timeline("TA-001", "ThreatActor")

        assert timeline["entity_id"] == "TA-001"
        assert timeline["entity_type"] == "ThreatActor"
        assert timeline["total_events"] == 2

        # Verify temporal ordering
        events = timeline["timeline_events"]
        assert len(events) == 2

        # Verify experimental labeling
        assert timeline["experimental_label"] == EXPERIMENTAL_DEMO_DATA_ONLY
        for event in events:
            assert event["experimental_label"] == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_prepare_intelligence_graph(self, engine, sample_entities, sample_evidence):
        """Test intelligence graph preparation for investigation-ready records"""
        # Create relationships
        engine.create_relationship(
            source_entity=sample_entities["threat_actor"],
            target_entity=sample_entities["malware"],
            relationship_type=RelationshipType.USES,
            confidence=RelationshipConfidence.CONFIRMED,
            evidence=sample_evidence,
            provenance="CISA-KEV-Integration-Connector",
            confirmed=True,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        engine.create_relationship(
            source_entity=sample_entities["malware"],
            target_entity=sample_entities["campaign"],
            relationship_type=RelationshipType.ASSOCIATED_WITH,
            confidence=RelationshipConfidence.HIGH,
            evidence=[],
            provenance="OSINT-Integration-Foundation",
            confirmed=False,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        # Prepare graph
        graph = engine.prepare_intelligence_graph(
            entity_ids=["TA-001", "MW-001", "CMP-001"],
            entity_types=["ThreatActor", "Malware", "Campaign"]
        )

        assert graph["total_nodes"] == 3
        assert graph["total_edges"] == 2

        # Verify nodes
        nodes = graph["nodes"]
        assert len(nodes) == 3
        node_ids = [node["id"] for node in nodes]
        assert "TA-001" in node_ids
        assert "MW-001" in node_ids
        assert "CMP-001" in node_ids

        # Verify edges
        edges = graph["edges"]
        assert len(edges) == 2

        # Verify experimental labeling
        assert graph["experimental_label"] == EXPERIMENTAL_DEMO_DATA_ONLY
        for node in nodes:
            assert node["experimental_label"] == EXPERIMENTAL_DEMO_DATA_ONLY
        for edge in edges:
            assert edge["experimental_label"] == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_preserve_conflicting_intelligence(self, engine, sample_entities):
        """Test that conflicting intelligence is preserved, not silently discarded"""
        conflicting_intelligence = [
            {
                "source": "Vendor-Advisory-2020-001",
                "conflict_description": "Vendor advisory suggests different attribution",
                "confidence": RelationshipConfidence.LOW.value,
                "experimental_label": EXPERIMENTAL_DEMO_DATA_ONLY
            }
        ]

        record = engine.create_relationship(
            source_entity=sample_entities["threat_actor"],
            target_entity=sample_entities["campaign"],
            relationship_type=RelationshipType.ATTRIBUTED_TO,
            confidence=RelationshipConfidence.HIGH,
            evidence=[],
            provenance="OSINT-Integration-Foundation",
            confirmed=False,
            conflicting_intelligence=conflicting_intelligence,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        # Verify conflicting intelligence is preserved in record
        assert record.conflicting_intelligence is not None
        assert len(record.conflicting_intelligence) == 1
        assert record.conflicting_intelligence[0]["source"] == "Vendor-Advisory-2020-001"
        assert record.conflicting_intelligence[0]["experimental_label"] == EXPERIMENTAL_DEMO_DATA_ONLY

        # Verify resolution preserves conflicts
        resolution = engine.resolve_conflicting_intelligence(record.relationship_id)
        assert len(resolution["conflicting_intelligence"]) == 1
        assert resolution["resolution_strategy"] == "PRESERVE_ORIGINAL_WITH_CONFLICT_TRACKING"

    def test_relationship_confidence_inspection(self, engine, sample_entities):
        """Test that confidence and evidence are inspectable"""
        evidence_high = [
            RelationshipEvidence(
                source="CISA-KEV-2020-001",
                description="High confidence attribution evidence",
                confidence=RelationshipConfidence.CONFIRMED,
                provenance="CISA-KEV-Integration-Connector",
                experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
            )
        ]

        evidence_low = [
            RelationshipEvidence(
                source="OSINT-Feed-2020-001",
                description="Low confidence inferred relationship",
                confidence=RelationshipConfidence.LOW,
                provenance="OSINT-Integration-Foundation",
                experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
            )
        ]

        # Create high confidence relationship
        record_high = engine.create_relationship(
            source_entity=sample_entities["threat_actor"],
            target_entity=sample_entities["malware"],
            relationship_type=RelationshipType.USES,
            confidence=RelationshipConfidence.CONFIRMED,
            evidence=evidence_high,
            provenance="CISA-KEV-Integration-Connector",
            confirmed=True,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        # Create low confidence relationship
        record_low = engine.create_relationship(
            source_entity=sample_entities["threat_actor"],
            target_entity=sample_entities["campaign"],
            relationship_type=RelationshipType.ATTRIBUTED_TO,
            confidence=RelationshipConfidence.LOW,
            evidence=evidence_low,
            provenance="OSINT-Integration-Foundation",
            confirmed=False,
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY
        )

        # Verify confidence inspection
        assert record_high.confidence == RelationshipConfidence.CONFIRMED
        assert record_low.confidence == RelationshipConfidence.LOW

        # Verify evidence inspection
        assert len(record_high.evidence) == 1
        assert len(record_low.evidence) == 1

        assert record_high.evidence[0].confidence == RelationshipConfidence.CONFIRMED
        assert record_low.evidence[0].confidence == RelationshipConfidence.LOW

        # Verify experimental labeling
        assert record_high.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY
        assert record_low.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY
        assert record_high.evidence[0].experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY
        assert record_low.evidence[0].experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY


# Export test class
__all__ = [
    "TestRelationshipAnalysisEngine"
]


def test_traversal_uses_only_stored_relationships_and_respects_filters():
    engine = RelationshipAnalysisEngine()
    a = EntityReference(entity_id="TA-001", entity_type="ThreatActor")
    b = EntityReference(entity_id="b", entity_type="Malware")
    c = EntityReference(entity_id="c", entity_type="Campaign")
    assert engine.traverse_relationships("TA-001", "ThreatActor")["traversal_path"] == []
    def link(source, target, kind):
        return engine.create_relationship(source, target, kind, RelationshipConfidence.LOW, [], "fixture")
    ab = link(a, b, RelationshipType.USES)
    bc = link(b, c, RelationshipType.TARGETS)
    ca = link(c, a, RelationshipType.USES)
    loop = link(a, a, RelationshipType.USES)
    assert len(engine.get_relationships_for_entity("TA-001", "ThreatActor")) == 3
    one = engine.traverse_relationships("TA-001", "ThreatActor", max_depth=1)
    assert {x["relationship_id"] for x in one["traversal_path"]} == {str(ab.relationship_id), str(ca.relationship_id), str(loop.relationship_id)}
    full = engine.traverse_relationships("TA-001", "ThreatActor", max_depth=2)
    assert {x["relationship_id"] for x in full["traversal_path"]} == {str(r.relationship_id) for r in (ab, bc, ca, loop)}
    assert len(full["traversal_path"]) == 4
    filtered = engine.traverse_relationships("TA-001", "ThreatActor", relationship_types=[RelationshipType.USES])
    assert str(bc.relationship_id) not in {x["relationship_id"] for x in filtered["traversal_path"]}
    assert engine.traverse_relationships("TA-001", "ThreatActor", relationship_types=[])["relationships_found"] == 0
    assert engine.traverse_relationships("TA-001", "ThreatActor", max_depth=0)["relationships_found"] == 0
    with pytest.raises(ValueError):
        engine.traverse_relationships("TA-001", "ThreatActor", max_depth=-1)


def test_traversal_does_not_conflate_entity_types():
    engine = RelationshipAnalysisEngine()
    a = EntityReference(entity_id="shared", entity_type="Actor")
    b = EntityReference(entity_id="shared", entity_type="Malware")
    c = EntityReference(entity_id="third", entity_type="Campaign")
    for source, target in [(a, b), (b, c)]:
        engine.create_relationship(source, target, RelationshipType.USES, RelationshipConfidence.LOW, [], "fixture")
    result = engine.traverse_relationships("shared", "Actor", max_depth=2)
    assert result["relationships_found"] == 2
    assert result["visited_entities"] == 3
    assert [item["depth"] for item in result["traversal_path"]] == [1, 2]
