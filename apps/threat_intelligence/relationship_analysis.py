"""
Cross-Entity Relationship Analysis Engine (P2-01)

Implementation of advanced relationship traversal, attribution evidence,
campaign correlation, malware family relationships, TTP mapping,
IOC correlation, confidence scoring, evidence-based enrichment,
temporal intelligence analysis, conflicting intelligence resolution,
threat activity timelines, intelligence graph preparation, and
investigation-ready records.

Requirements:
- Preserve source attribution
- Distinguish confirmed vs inferred relationships
- Preserve conflicting intelligence
- Make confidence and evidence inspectable
- Add deterministic tests with EXPLICITLY LABELED fixtures
- Document limitations and performance characteristics

Author: Arena.ai Agent Mode (Threat Intelligence Domain)
Date: 2026-11-06
Version: 1.0
Experimental Label: EXPERIMENTAL_DEMO_DATA_ONLY
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List, Dict, Any, Union, Tuple
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict

# Experimental demonstration data labeling
EXPERIMENTAL_DEMO_DATA_ONLY = "EXPERIMENTAL_DEMO_DATA_ONLY"


class RelationshipType(str, Enum):
    """Core relationship types from Master Prompt Section 6"""
    ATTRIBUTED_TO = "ATTRIBUTED_TO"
    USES = "USES"
    TARGETS = "TARGETS"
    INDICATES = "INDICATES"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    EXPLOITS = "EXPLOITS"
    AFFECTS = "AFFECTS"
    OBSERVED_IN = "OBSERVED_IN"
    DERIVED_FROM = "DERIVED_FROM"
    CORROBORATES = "CORROBORATES"
    CONTRADICTS = "CONTRADICTS"
    CONTAINS = "CONTAINS"
    DEPENDS_ON = "DEPENDS_ON"
    BELONGS_TO = "BELONGS_TO"
    RELATED_TO = "RELATED_TO"


class RelationshipConfidence(str, Enum):
    """Confidence levels for relationship analysis"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"
    INFERRED = "INFERRED"


class RelationshipEvidence(BaseModel):
    """Evidence supporting a relationship"""
    model_config = ConfigDict(extra="forbid")

    evidence_id: UUID = Field(default_factory=uuid4, description="Unique evidence identifier")
    source: str = Field(..., description="Source attribution")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Collection time")
    description: str = Field(..., description="Evidence description")
    confidence: RelationshipConfidence = Field(..., description="Confidence level")
    provenance: str = Field(..., description="Provenance tracking")
    experimental_label: str = Field(
        default=EXPERIMENTAL_DEMO_DATA_ONLY,
        description="Experimental data labeling"
    )


class EntityReference(BaseModel):
    """Reference to an entity in the unified intelligence graph"""
    model_config = ConfigDict(extra="forbid")

    entity_id: str = Field(..., description="Unique entity identifier")
    entity_type: str = Field(..., description="Entity type (ThreatActor, Malware, Campaign, etc.)")
    name: Optional[str] = Field(None, description="Entity name")
    experimental_label: str = Field(
        default=EXPERIMENTAL_DEMO_DATA_ONLY,
        description="Experimental data labeling"
    )


class RelationshipRecord(BaseModel):
    """Provenance-aware relationship record"""
    model_config = ConfigDict(extra="forbid")

    relationship_id: UUID = Field(default_factory=uuid4, description="Unique relationship identifier")
    source_entity: EntityReference = Field(..., description="Source entity reference")
    target_entity: EntityReference = Field(..., description="Target entity reference")
    relationship_type: RelationshipType = Field(..., description="Relationship type")
    confidence: RelationshipConfidence = Field(..., description="Confidence level")
    evidence: List[RelationshipEvidence] = Field(default_factory=list, description="Supporting evidence")
    provenance: str = Field(..., description="Provenance tracking")
    temporal_context: Optional[Dict[str, Any]] = Field(None, description="Temporal context")
    confirmed: bool = Field(default=False, description="Confirmed vs inferred")
    conflicting_intelligence: Optional[List[Dict[str, Any]]] = Field(
        None, description="Preserved conflicting intelligence"
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Creation time")
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Update time")
    experimental_label: str = Field(
        default=EXPERIMENTAL_DEMO_DATA_ONLY,
        description="Experimental data labeling"
    )


class RelationshipAnalysisEngine:
    """
    P2-01 Cross-Entity Relationship Analysis Engine

    Supports:
    - Threat actor relationships
    - Malware relationships
    - Campaign correlation
    - TTP relationships
    - Infrastructure and indicator relationships
    - Attribution evidence and confidence
    - Provenance-aware relationship records
    - Temporal context
    - Explainable relationship traversal
    """

    def __init__(self):
        """Initialize the relationship analysis engine"""
        self.relationships: Dict[UUID, RelationshipRecord] = {}
        self.entity_index: Dict[Tuple[str, str], List[UUID]] = {}  # (type, id) -> relationship_ids
        self.experimental_label = EXPERIMENTAL_DEMO_DATA_ONLY

    def create_relationship(
        self,
        source_entity: EntityReference,
        target_entity: EntityReference,
        relationship_type: RelationshipType,
        confidence: RelationshipConfidence,
        evidence: List[RelationshipEvidence],
        provenance: str,
        temporal_context: Optional[Dict[str, Any]] = None,
        confirmed: bool = False,
        conflicting_intelligence: Optional[List[Dict[str, Any]]] = None,
        experimental_label: Optional[str] = EXPERIMENTAL_DEMO_DATA_ONLY
    ) -> RelationshipRecord:
        """
        Create a provenance-aware relationship record

        Preserves source attribution, distinguishes confirmed vs inferred,
        preserves conflicting intelligence, makes confidence inspectable.
        """
        record = RelationshipRecord(
            source_entity=source_entity,
            target_entity=target_entity,
            relationship_type=relationship_type,
            confidence=confidence,
            evidence=evidence,
            provenance=provenance,
            temporal_context=temporal_context,
            confirmed=confirmed,
            conflicting_intelligence=conflicting_intelligence,
            experimental_label=experimental_label if experimental_label is not None else self.experimental_label
        )

        # Store relationship
        self.relationships[record.relationship_id] = record

        # Index by entities for traversal
        self._index_relationship(record)

        return record

    def _index_relationship(self, record: RelationshipRecord) -> None:
        """Index relationship for entity-based traversal"""
        source_key = (record.source_entity.entity_type, record.source_entity.entity_id)
        target_key = (record.target_entity.entity_type, record.target_entity.entity_id)

        if source_key not in self.entity_index:
            self.entity_index[source_key] = []
        if target_key not in self.entity_index:
            self.entity_index[target_key] = []

        self.entity_index[source_key].append(record.relationship_id)
        if target_key != source_key:
            self.entity_index[target_key].append(record.relationship_id)

    def get_relationships_for_entity(self, entity_id: str, entity_type: str) -> List[RelationshipRecord]:
        """Retrieve all relationships for a specific entity"""
        key = (entity_type, entity_id)
        relationship_ids = self.entity_index.get(key, [])
        return [self.relationships[rid] for rid in relationship_ids if rid in self.relationships]

    def analyze_attribution_evidence(
        self,
        threat_actor_id: str,
        malware_id: Optional[str] = None,
        campaign_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze threat actor attribution evidence

        Preserves source attribution and confidence
        """
        relationships = self.get_relationships_for_entity(threat_actor_id, "ThreatActor")

        attribution_evidence = []
        for rel in relationships:
            if rel.relationship_type in [
                RelationshipType.ATTRIBUTED_TO,
                RelationshipType.USES,
                RelationshipType.TARGETS
            ]:
                attribution_evidence.append({
                    "relationship_id": str(rel.relationship_id),
                    "type": rel.relationship_type.value,
                    "target": {
                        "id": rel.target_entity.entity_id,
                        "type": rel.target_entity.entity_type,
                        "name": rel.target_entity.name
                    },
                    "confidence": rel.confidence.value,
                    "confirmed": rel.confirmed,
                    "evidence_count": len(rel.evidence),
                    "provenance": rel.provenance,
                    "temporal_context": rel.temporal_context,
                    "conflicting_intelligence": rel.conflicting_intelligence,
                    "experimental_label": rel.experimental_label
                })

        return {
            "threat_actor_id": threat_actor_id,
            "total_relationships": len(attribution_evidence),
            "evidence_items": attribution_evidence,
            "experimental_label": self.experimental_label
        }

    def correlate_campaigns(
        self,
        campaign_ids: List[str],
        temporal_window: Optional[Dict[str, datetime]] = None
    ) -> Dict[str, Any]:
        """
        Campaign correlation analysis

        Identifies relationships between campaigns across temporal context
        """
        campaign_relationships = {}

        for campaign_id in campaign_ids:
            relationships = self.get_relationships_for_entity(campaign_id, "Campaign")
            campaign_relationships[campaign_id] = {
                "relationships": [
                    {
                        "id": str(rel.relationship_id),
                        "type": rel.relationship_type.value,
                        "target": {
                            "id": rel.target_entity.entity_id,
                            "type": rel.target_entity.entity_type,
                            "name": rel.target_entity.name
                        },
                        "confidence": rel.confidence.value,
                        "confirmed": rel.confirmed,
                        "evidence_count": len(rel.evidence),
                        "provenance": rel.provenance,
                        "temporal_context": rel.temporal_context,
                        "conflicting_intelligence": rel.conflicting_intelligence,
                        "experimental_label": rel.experimental_label
                    }
                    for rel in relationships
                ],
                "total_count": len(relationships)
            }

        return {
            "campaigns_analyzed": len(campaign_ids),
            "correlation_results": campaign_relationships,
            "experimental_label": self.experimental_label
        }

    def traverse_relationships(
        self,
        start_entity_id: str,
        start_entity_type: str,
        max_depth: int = 3,
        relationship_types: Optional[List[RelationshipType]] = None
    ) -> Dict[str, Any]:
        """
        Explainable relationship traversal (BFS implementation)

        Supports temporal context and evidence inspection
        """
        if max_depth < 0:
            raise ValueError("max_depth must be non-negative")
        from collections import deque

        start = (start_entity_type, start_entity_id)
        queue = deque([(start, 0)])
        visited = {start}
        seen_relationships = set()
        traversal_results = []
        allowed = None if relationship_types is None else set(relationship_types)

        # Depth is the number of edges from the starting entity. Edges that
        # would extend beyond max_depth are not returned.
        while queue:
            (current_type, current_id), depth = queue.popleft()
            if depth >= max_depth:
                continue
            for rel in self.get_relationships_for_entity(current_id, current_type):
                if allowed is not None and rel.relationship_type not in allowed:
                    continue
                if rel.relationship_id not in seen_relationships:
                    seen_relationships.add(rel.relationship_id)
                    traversal_results.append({
                        "relationship_id": str(rel.relationship_id),
                        "source": {"id": rel.source_entity.entity_id, "type": rel.source_entity.entity_type, "name": rel.source_entity.name},
                        "target": {"id": rel.target_entity.entity_id, "type": rel.target_entity.entity_type, "name": rel.target_entity.name},
                        "type": rel.relationship_type.value,
                        "confidence": rel.confidence.value,
                        "confirmed": rel.confirmed,
                        "evidence_count": len(rel.evidence),
                        "provenance": rel.provenance,
                        "temporal_context": rel.temporal_context,
                        "conflicting_intelligence": rel.conflicting_intelligence,
                        "depth": depth + 1,
                        "experimental_label": rel.experimental_label,
                    })
                source = (rel.source_entity.entity_type, rel.source_entity.entity_id)
                target = (rel.target_entity.entity_type, rel.target_entity.entity_id)
                neighbor = target if source == (current_type, current_id) else source
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, depth + 1))

        return {
            "start_entity": {
                "id": start_entity_id,
                "type": start_entity_type
            },
            "max_depth": max_depth,
            "relationships_found": len(traversal_results),
            "traversal_path": traversal_results,
            "visited_entities": len(visited),
            "experimental_label": self.experimental_label
        }

    def resolve_conflicting_intelligence(
        self,
        relationship_id: UUID
    ) -> Dict[str, Any]:
        """
        Resolve conflicting intelligence while preserving original records

        Does not silently discard conflicting information
        """
        if relationship_id not in self.relationships:
            return {
                "error": "Relationship not found",
                "experimental_label": self.experimental_label
            }

        record = self.relationships[relationship_id]

        resolution = {
            "relationship_id": str(relationship_id),
            "original_record": {
                "type": record.relationship_type.value,
                "confidence": record.confidence.value,
                "confirmed": record.confirmed,
                "provenance": record.provenance,
                "evidence_count": len(record.evidence)
            },
            "conflicting_intelligence": record.conflicting_intelligence or [],
            "resolution_strategy": "PRESERVE_ORIGINAL_WITH_CONFLICT_TRACKING",
            "experimental_label": self.experimental_label
        }

        return resolution

    def generate_threat_activity_timeline(
        self,
        entity_id: str,
        entity_type: str
    ) -> Dict[str, Any]:
        """
        Generate threat activity timeline from relationship temporal context
        """
        relationships = self.get_relationships_for_entity(entity_id, entity_type)

        timeline_events = []
        for rel in relationships:
            if rel.temporal_context:
                timeline_events.append({
                    "relationship_id": str(rel.relationship_id),
                    "type": rel.relationship_type.value,
                    "temporal_context": rel.temporal_context,
                    "confidence": rel.confidence.value,
                    "provenance": rel.provenance,
                    "experimental_label": rel.experimental_label
                })

        # Sort by temporal context if available
        timeline_events.sort(
            key=lambda x: x["temporal_context"].get("start_time", datetime.min)
            if x["temporal_context"] else datetime.min
        )

        return {
            "entity_id": entity_id,
            "entity_type": entity_type,
            "timeline_events": timeline_events,
            "total_events": len(timeline_events),
            "experimental_label": self.experimental_label
        }

    def prepare_intelligence_graph(
        self,
        entity_ids: List[str],
        entity_types: List[str]
    ) -> Dict[str, Any]:
        """
        Prepare intelligence graph for investigation-ready records
        """
        graph_nodes = []
        graph_edges = []

        # Add entities as nodes
        for entity_id, entity_type in zip(entity_ids, entity_types):
            graph_nodes.append({
                "id": entity_id,
                "type": entity_type,
                "experimental_label": self.experimental_label
            })

        # Add relationships as edges
        for entity_id, entity_type in zip(entity_ids, entity_types):
            relationships = self.get_relationships_for_entity(entity_id, entity_type)
            for rel in relationships:
                edge = {
                    "source": rel.source_entity.entity_id,
                    "target": rel.target_entity.entity_id,
                    "type": rel.relationship_type.value,
                    "confidence": rel.confidence.value,
                    "confirmed": rel.confirmed,
                    "evidence_count": len(rel.evidence),
                    "provenance": rel.provenance,
                    "experimental_label": rel.experimental_label
                }
                # Avoid duplicate edges
                if edge not in graph_edges:
                    graph_edges.append(edge)

        return {
            "nodes": graph_nodes,
            "edges": graph_edges,
            "total_nodes": len(graph_nodes),
            "total_edges": len(graph_edges),
            "experimental_label": self.experimental_label
        }


# Export constants and classes
__all__ = [
    "RelationshipType",
    "RelationshipConfidence",
    "RelationshipEvidence",
    "EntityReference",
    "RelationshipRecord",
    "RelationshipAnalysisEngine",
    "EXPERIMENTAL_DEMO_DATA_ONLY"
]
