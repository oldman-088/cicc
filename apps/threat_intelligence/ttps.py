"""
Independent TTP module for CICC Threat Intelligence.
Branch: arena/93315d2c-cicc
Constraint: Independent file, no modification to models.py/main.py/migrations
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
import uuid

# Experimental data labeling: CLEARLY MARKED
EXPERIMENTAL_DEMO_DATA_ONLY = "EXPERIMENTAL_DEMO_DATA_ONLY"

class TTPModel(BaseModel):
    """Independent TTP data model"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., description="TTP name")
    description: Optional[str] = Field(None, description="TTP description")
    mitre_attack_id: Optional[str] = Field(None, description="MITRE ATT&CK technique/tactic ID")
    category: Optional[str] = Field(None, description="TTP category (technique, tactic, etc.)")
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

class TTPService:
    """Independent TTP service functions"""
    
    def __init__(self):
        self._ttps: Dict[str, TTPModel] = {}
    
    def create_ttp(self, ttp_data: Dict[str, Any]) -> TTPModel:
        """Create independent TTP"""
        # Ensure experimental label is set in data before model creation
        if ttp_data.get("source") is None and "experimental_label" not in ttp_data:
            ttp_data["experimental_label"] = EXPERIMENTAL_DEMO_DATA_ONLY
            
        ttp = TTPModel(**ttp_data)
        self._ttps[ttp.id] = ttp
        return ttp
    
    def get_ttp(self, ttp_id: str) -> Optional[TTPModel]:
        """Get TTP by ID"""
        return self._ttps.get(ttp_id)
    
    def list_ttps(self) -> List[TTPModel]:
        """List all TTPs"""
        return list(self._ttps.values())
    
    def find_by_mitre_id(self, mitre_id: str) -> List[TTPModel]:
        """Find TTPs matching MITRE ATT&CK ID"""
        return [
            ttp for ttp in self._ttps.values()
            if ttp.mitre_attack_id == mitre_id
        ]
    
    def update_ttp(self, ttp_id: str, update_data: Dict[str, Any]) -> Optional[TTPModel]:
        """Update existing TTP"""
        if ttp_id not in self._ttps:
            return None
        
        ttp = self._ttps[ttp_id]
        # Handle experimental label in update data
        if "source" in update_data and update_data["source"] is None and "experimental_label" not in update_data:
            update_data["experimental_label"] = EXPERIMENTAL_DEMO_DATA_ONLY
            
        for key, value in update_data.items():
            if hasattr(ttp, key):
                setattr(ttp, key, value)
        
        ttp.updated_at = datetime.utcnow()
        return ttp
    
    def delete_ttp(self, ttp_id: str) -> bool:
        """Delete TTP"""
        if ttp_id in self._ttps:
            del self._ttps[ttp_id]
            return True
        return False

# Independent module - no imports from models.py or main.py
