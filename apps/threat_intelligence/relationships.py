"""
Threat Intelligence Relationship Layer for CICC.
Branch: arena/93315d2c-cicc
Constraint: Independent file, no modification to models.py/main.py/migrations
"""

from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
import uuid

# Experimental data labeling: CLEARLY MARKED
EXPERIMENTAL_DEMO_DATA_ONLY = "EXPERIMENTAL_DEMO_DATA_ONLY"

# Relationship Types (explicit semantics)
RELATIONSHIP_TYPES = {
    "ATTRIBUTED_TO": "Threat actor attributed to campaign/malware",
    "USES": "Threat actor/malware uses TTP/technique",
    "TARGETS": "Campaign/malware targets asset/organization",
    "INDICATES": "Indicator indicates threat actor/malware/campaign",
    "ASSOCIATED_WITH": "Entities associated without specific attribution",
    "EXPLOITS": "Malware exploits vulnerability",
    "AFFECTS": "Vulnerability affects asset/software",
    "OBSERVED_IN": "Indicator observed in incident/campaign",
    "DERIVED_FROM": "Intelligence derived from source/evidence",
    "CORROBORATES": "Evidence corroborates intelligence",
    "CONTRADICTS": "Evidence contradicts intelligence",
    "CONTAINS": "Container/campaign contains entities",
    "DEPENDS_ON": "Entity depends on another",
    "BELONGS_TO": "Entity belongs to group/campaign",
    "RELATED_TO": "General relationship without specific type"
}

class RelationshipModel(BaseModel):
    """Independent Threat Intelligence Relationship data model"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_entity_id: str = Field(..., description="Source entity ID")
    source_entity_type: str = Field(..., description="Source entity type (ThreatActor, Malware, Campaign, TTP, MITRE, etc.)")
    target_entity_id: str = Field(..., description="Target entity ID")
    target_entity_type: str = Field(..., description="Target entity type (ThreatActor, Malware, Campaign, TTP, MITRE, etc.)")
    relationship_type: str = Field(..., description="Relationship type (ATTRIBUTED_TO, USES, TARGETS, etc.)")
    description: Optional[str] = Field(None, description="Relationship description")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence score (0-1)")
    source: Optional[str] = Field(None, description="Intelligence source")
    provenance: Optional[str] = Field(None, description="Provenance information")
    evidence: Optional[str] = Field(None, description="Supporting evidence")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    experimental_label: Optional[str] = Field(default=None, description="Experimental data label")
    valid_until: Optional[datetime] = Field(None, description="Validity expiration")
    
    model_config = ConfigDict(extra="ignore")
        
    def __init__(self, **data):
        super().__init__(**data)
        # Set experimental label if no source provided
        if self.source is None and self.experimental_label is None:
            self.experimental_label = EXPERIMENTAL_DEMO_DATA_ONLY
            
        # Validate relationship type
        if self.relationship_type not in RELATIONSHIP_TYPES:
            raise ValueError(f"Invalid relationship_type: {self.relationship_type}. Must be one of {list(RELATIONSHIP_TYPES.keys())}")

    def __post_init__(self):
        # Ensure experimental label is set in __init__ (Pydantic V2 compatibility)
        pass

class RelationshipService:
    """Independent Threat Intelligence Relationship service functions"""
    
    def __init__(self):
        self._relationships: Dict[str, RelationshipModel] = {}
        # Cross-module references for efficient traversal
        self._source_index: Dict[str, List[str]] = {}  # source_entity_id -> [relationship_ids]
        self._target_index: Dict[str, List[str]] = {}  # target_entity_id -> [relationship_ids]
        self._type_index: Dict[str, List[str]] = {}    # relationship_type -> [relationship_ids]
    
    def create_relationship(self, relationship_data: Dict[str, Any]) -> RelationshipModel:
        """Create independent threat intelligence relationship"""
        # Ensure experimental label is set in data before model creation
        if relationship_data.get("source") is None and "experimental_label" not in relationship_data:
            relationship_data["experimental_label"] = EXPERIMENTAL_DEMO_DATA_ONLY
            
        relationship = RelationshipModel(**relationship_data)
        self._relationships[relationship.id] = relationship
        
        # Update indexes for efficient traversal
        self._update_indexes(relationship)
        
        return relationship
    
    def _update_indexes(self, relationship: RelationshipModel):
        """Update internal indexes for relationship traversal"""
        # Source index
        if relationship.source_entity_id not in self._source_index:
            self._source_index[relationship.source_entity_id] = []
        self._source_index[relationship.source_entity_id].append(relationship.id)
        
        # Target index
        if relationship.target_entity_id not in self._target_index:
            self._target_index[relationship.target_entity_id] = []
        self._target_index[relationship.target_entity_id].append(relationship.id)
        
        # Type index
        if relationship.relationship_type not in self._type_index:
            self._type_index[relationship.relationship_type] = []
        self._type_index[relationship.relationship_type].append(relationship.id)
    
    def get_relationship(self, relationship_id: str) -> Optional[RelationshipModel]:
        """Get relationship by ID"""
        return self._relationships.get(relationship_id)
    
    def list_relationships(self) -> List[RelationshipModel]:
        """List all relationships"""
        return list(self._relationships.values())
    
    def find_by_source(self, source_entity_id: str) -> List[RelationshipModel]:
        """Find relationships where entity is source"""
        relationship_ids = self._source_index.get(source_entity_id, [])
        return [self._relationships[rid] for rid in relationship_ids if rid in self._relationships]
    
    def find_by_target(self, target_entity_id: str) -> List[RelationshipModel]:
        """Find relationships where entity is target"""
        relationship_ids = self._target_index.get(target_entity_id, [])
        return [self._relationships[rid] for rid in relationship_ids if rid in self._relationships]
    
    def find_by_type(self, relationship_type: str) -> List[RelationshipModel]:
        """Find relationships by type"""
        relationship_ids = self._type_index.get(relationship_type, [])
        return [self._relationships[rid] for rid in relationship_ids if rid in self._relationships]
    
    def find_actor_campaign_relationships(self, actor_id: str) -> List[RelationshipModel]:
        """Find Threat Actor ↔ Campaign relationships (ATTRIBUTED_TO)"""
        relationships = self.find_by_source(actor_id) + self.find_by_target(actor_id)
        return [r for r in relationships if r.relationship_type == "ATTRIBUTED_TO"]
    
    def find_malware_actor_relationships(self, malware_id: str) -> List[RelationshipModel]:
        """Find Malware ↔ Threat Actor relationships (USES/ATTRIBUTED_TO)"""
        relationships = self.find_by_source(malware_id) + self.find_by_target(malware_id)
        return [r for r in relationships if r.relationship_type in ["USES", "ATTRIBUTED_TO"]]
    
    def find_malware_ttp_relationships(self, malware_id: str) -> List[RelationshipModel]:
        """Find Malware ↔ TTP relationships (USES)"""
        relationships = self.find_by_source(malware_id) + self.find_by_target(malware_id)
        return [r for r in relationships if r.relationship_type == "USES"]
    
    def find_campaign_targets(self, campaign_id: str) -> List[RelationshipModel]:
        """Find Campaign ↔ Targets relationships (TARGETS)"""
        relationships = self.find_by_source(campaign_id) + self.find_by_target(campaign_id)
        return [r for r in relationships if r.relationship_type == "TARGETS"]
    
    def find_ttp_mitre_relationships(self, ttp_id: str) -> List[RelationshipModel]:
        """Find TTP ↔ MITRE ATT&CK relationships (USES/RELATED_TO)"""
        relationships = self.find_by_source(ttp_id) + self.find_by_target(ttp_id)
        return [r for r in relationships if r.relationship_type in ["USES", "RELATED_TO"]]
    
    def update_relationship(self, relationship_id: str, update_data: Dict[str, Any]) -> Optional[RelationshipModel]:
        """Update existing relationship"""
        if relationship_id not in self._relationships:
            return None
        
        relationship = self._relationships[relationship_id]
        
        # Handle experimental label in update data
        if "source" in update_data and update_data["source"] is None and "experimental_label" not in update_data:
            update_data["experimental_label"] = EXPERIMENTAL_DEMO_DATA_ONLY
            
        # Remove from old indexes if type or entities change
        old_source = relationship.source_entity_id
        old_target = relationship.target_entity_id
        old_type = relationship.relationship_type
        
        for key, value in update_data.items():
            if hasattr(relationship, key):
                setattr(relationship, key, value)
        
        # Update indexes if entities or type changed
        if (relationship.source_entity_id != old_source or 
            relationship.target_entity_id != old_target or 
            relationship.relationship_type != old_type):
            # Remove from old indexes
            if old_source in self._source_index and relationship_id in self._source_index[old_source]:
                self._source_index[old_source].remove(relationship_id)
            if old_target in self._target_index and relationship_id in self._target_index[old_target]:
                self._target_index[old_target].remove(relationship_id)
            if old_type in self._type_index and relationship_id in self._type_index[old_type]:
                self._type_index[old_type].remove(relationship_id)
            # Add to new indexes
            self._update_indexes(relationship)
        
        relationship.updated_at = datetime.utcnow()
        return relationship
    
    def delete_relationship(self, relationship_id: str) -> bool:
        """Delete relationship"""
        if relationship_id in self._relationships:
            relationship = self._relationships[relationship_id]
            
            # Remove from indexes
            if relationship.source_entity_id in self._source_index:
                if relationship_id in self._source_index[relationship.source_entity_id]:
                    self._source_index[relationship.source_entity_id].remove(relationship_id)
            
            if relationship.target_entity_id in self._target_index:
                if relationship_id in self._target_index[relationship.target_entity_id]:
                    self._target_index[relationship.target_entity_id].remove(relationship_id)
            
            if relationship.relationship_type in self._type_index:
                if relationship_id in self._type_index[relationship.relationship_type]:
                    self._type_index[relationship.relationship_type].remove(relationship_id)
            
            del self._relationships[relationship_id]
            return True
        return False
    
    def traverse_relationships(self, entity_id: str, max_depth: int = 3) -> Dict[str, Any]:
        """Traverse relationships from entity (breadth-first search)"""
        visited = {entity_id}
        queue = [(entity_id, 0)]
        result = {
            "entity_id": entity_id,
            "depth_0": [],
            "depth_1": [],
            "depth_2": [],
            "depth_3": [],
            "total_relationships": 0
        }
        
        while queue:
            current_id, depth = queue.pop(0)
            
            if depth >= max_depth:
                continue
                
            # Find relationships from current entity
            relationships = self.find_by_source(current_id) + self.find_by_target(current_id)
            
            for rel in relationships:
                result[f"depth_{depth+1}"].append({
                    "relationship_id": rel.id,
                    "relationship_type": rel.relationship_type,
                    "source": rel.source_entity_id,
                    "target": rel.target_entity_id,
                    "confidence": rel.confidence,
                    "source_info": rel.source,
                    "provenance": rel.provenance
                })
                result["total_relationships"] += 1
                
                # Add connected entities to queue
                next_entities = []
                if rel.source_entity_id != current_id and rel.source_entity_id not in visited:
                    next_entities.append(rel.source_entity_id)
                    visited.add(rel.source_entity_id)
                if rel.target_entity_id != current_id and rel.target_entity_id not in visited:
                    next_entities.append(rel.target_entity_id)
                    visited.add(rel.target_entity_id)
                
                for next_id in next_entities:
                    queue.append((next_id, depth + 1))
        
        return result

# Independent module - no imports from models.py or main.py
# Relationship layer connects all Threat Intelligence modules
