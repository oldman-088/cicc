"""
Common MITRE ATT&CK identifier service for CICC Threat Intelligence.
Branch: arena/93315d2c-cicc
Constraint: Independent file, no modification to models.py/main.py/migrations
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
import uuid

# Experimental data labeling: CLEARLY MARKED
EXPERIMENTAL_DEMO_DATA_ONLY = "EXPERIMENTAL_DEMO_DATA_ONLY"

class MITREMappingModel(BaseModel):
    """Independent MITRE ATT&CK mapping data model"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    mitre_id: str = Field(..., description="MITRE ATT&CK technique/tactic ID")
    name: str = Field(..., description="MITRE technique/tactic name")
    description: Optional[str] = Field(None, description="MITRE description")
    category: Optional[str] = Field(None, description="Category (technique, tactic, etc.)")
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

class MITREMappingService:
    """Independent MITRE ATT&CK mapping service functions"""
    
    def __init__(self):
        self._mappings: Dict[str, MITREMappingModel] = {}
    
    def create_mapping(self, mapping_data: Dict[str, Any]) -> MITREMappingModel:
        """Create independent MITRE mapping"""
        # Ensure experimental label is set in data before model creation
        if mapping_data.get("source") is None and "experimental_label" not in mapping_data:
            mapping_data["experimental_label"] = EXPERIMENTAL_DEMO_DATA_ONLY
            
        mapping = MITREMappingModel(**mapping_data)
        self._mappings[mapping.id] = mapping
        return mapping
    
    def create_experimental_mapping(self, mapping_data: Dict[str, Any]) -> MITREMappingModel:
        """Create experimental MITRE mapping (explicitly marked)"""
        mapping_data["experimental_label"] = EXPERIMENTAL_DEMO_DATA_ONLY
        mapping = MITREMappingModel(**mapping_data)
        self._mappings[mapping.id] = mapping
        return mapping
    
    def get_mapping(self, mapping_id: str) -> Optional[MITREMappingModel]:
        """Get MITRE mapping by ID"""
        return self._mappings.get(mapping_id)
    
    def get_by_mitre_id(self, mitre_id: str) -> Optional[MITREMappingModel]:
        """Get MITRE mapping by MITRE ID"""
        for mapping in self._mappings.values():
            if mapping.mitre_id == mitre_id:
                return mapping
        return None
    
    def list_mappings(self) -> List[MITREMappingModel]:
        """List all MITRE mappings"""
        return list(self._mappings.values())
    
    def update_mapping(self, mapping_id: str, update_data: Dict[str, Any]) -> Optional[MITREMappingModel]:
        """Update existing MITRE mapping"""
        if mapping_id not in self._mappings:
            return None
        
        mapping = self._mappings[mapping_id]
        # Handle experimental label in update data
        if "source" in update_data and update_data["source"] is None and "experimental_label" not in update_data:
            update_data["experimental_label"] = EXPERIMENTAL_DEMO_DATA_ONLY
            
        for key, value in update_data.items():
            if hasattr(mapping, key):
                setattr(mapping, key, value)
        
        mapping.updated_at = datetime.utcnow()
        return mapping
    
    def delete_mapping(self, mapping_id: str) -> bool:
        """Delete MITRE mapping"""
        if mapping_id in self._mappings:
            del self._mappings[mapping_id]
            return True
        return False

# Independent module - no imports from models.py or main.py
