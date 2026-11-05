"""
Independent Threat Actor module for CICC Threat Intelligence.
Branch: arena/93315d2c-cicc
Constraint: Independent file, no modification to models.py/main.py/migrations
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
import uuid

# Experimental data labeling: CLEARLY MARKED
EXPERIMENTAL_DEMO_DATA_ONLY = "EXPERIMENTAL_DEMO_DATA_ONLY"

class ThreatActorModel(BaseModel):
    """Independent Threat Actor data model"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., description="Threat actor name")
    alias: Optional[List[str]] = Field(default_factory=list, description="Known aliases")
    description: Optional[str] = Field(None, description="Actor description")
    mitre_attack_ids: Optional[List[str]] = Field(default_factory=list, description="MITRE ATT&CK identifiers")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence score (0-1)")
    source: Optional[str] = Field(None, description="Intelligence source")
    provenance: Optional[str] = Field(None, description="Provenance information")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    experimental_label: Optional[str] = Field(default=None, description="Experimental data label")
    
    model_config = ConfigDict(extra="ignore")
        
    def __init__(self, **data):
        super().__init__(**data)
        # Set experimental label if no source provided
        if self.source is None and self.experimental_label is None:
            self.experimental_label = EXPERIMENTAL_DEMO_DATA_ONLY

    def __post_init__(self):
        # Ensure experimental label is set in __init__ (Pydantic V2 compatibility)
        pass

class ThreatActorService:
    """Independent Threat Actor service functions"""
    
    def __init__(self):
        self._actors: Dict[str, ThreatActorModel] = {}
    
    def create_actor(self, actor_data: Dict[str, Any]) -> ThreatActorModel:
        """Create independent threat actor"""
        # Ensure experimental label is set in data before model creation
        if actor_data.get("source") is None and "experimental_label" not in actor_data:
            actor_data["experimental_label"] = EXPERIMENTAL_DEMO_DATA_ONLY
            
        actor = ThreatActorModel(**actor_data)
        self._actors[actor.id] = actor
        return actor
    
    def get_actor(self, actor_id: str) -> Optional[ThreatActorModel]:
        """Get threat actor by ID"""
        return self._actors.get(actor_id)
    
    def list_actors(self) -> List[ThreatActorModel]:
        """List all threat actors"""
        return list(self._actors.values())
    
    def find_by_mitre_id(self, mitre_id: str) -> List[ThreatActorModel]:
        """Find actors associated with MITRE ATT&CK ID"""
        return [
            actor for actor in self._actors.values()
            if mitre_id in actor.mitre_attack_ids
        ]
    
    def update_actor(self, actor_id: str, update_data: Dict[str, Any]) -> Optional[ThreatActorModel]:
        """Update existing threat actor"""
        if actor_id not in self._actors:
            return None
        
        actor = self._actors[actor_id]
        # Handle experimental label in update data
        if "source" in update_data and update_data["source"] is None and "experimental_label" not in update_data:
            update_data["experimental_label"] = EXPERIMENTAL_DEMO_DATA_ONLY
            
        for key, value in update_data.items():
            if hasattr(actor, key):
                setattr(actor, key, value)
        
        actor.updated_at = datetime.utcnow()
        return actor
    
    def delete_actor(self, actor_id: str) -> bool:
        """Delete threat actor"""
        if actor_id in self._actors:
            del self._actors[actor_id]
            return True
        return False

# Independent module - no imports from models.py or main.py
