"""
Intelligence Enrichment and Provenance Layer for CICC.
Branch: arena/93315d2c-cicc
Constraint: Independent file, no modification to models.py/main.py/migrations
"""

from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
import uuid

# Experimental data labeling: CLEARLY MARKED
EXPERIMENTAL_DEMO_DATA_ONLY = "EXPERIMENTAL_DEMO_DATA_ONLY"

# Intelligence Source Types
SOURCE_TYPES = {
    "MITRE_ATTACK": "Official MITRE ATT&CK framework",
    "CISA_KEV": "CISA Known Exploited Vulnerabilities",
    "CISA_ALERTS": "CISA security alerts",
    "VENDOR_ADVISORY": "Official vendor security advisory",
    "OPEN_SOURCE": "Reputable open intelligence source",
    "INTERNAL": "Internal CICC intelligence",
    "EXPERIMENTAL": "Experimental demonstration data"
}

class IntelligenceSourceModel(BaseModel):
    """Independent Intelligence Source data model"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., description="Source name")
    type: str = Field(..., description="Source type (MITRE_ATTACK, CISA_KEV, etc.)")
    url: Optional[str] = Field(None, description="Source URL")
    description: Optional[str] = Field(None, description="Source description")
    reliability_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Source reliability (0-1)")
    last_sync: Optional[datetime] = Field(None, description="Last synchronization time")
    status: str = Field(default="active", description="Source status (active, inactive, error)")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence in source (0-1)")
    source: Optional[str] = Field(None, description="Intelligence source")
    provenance: Optional[str] = Field(None, description="Provenance information")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    experimental_label: Optional[str] = Field(default=None, description="Experimental data label")
    
    model_config = ConfigDict(extra="ignore")
        
    def __init__(self, **data):
        super().__init__(**data)
        # Set experimental label if no source provided
        if getattr(self, 'source', None) is None and self.experimental_label is None:
            self.experimental_label = EXPERIMENTAL_DEMO_DATA_ONLY
            
        # Validate source type
        if self.type not in SOURCE_TYPES:
            raise ValueError(f"Invalid source_type: {self.type}. Must be one of {list(SOURCE_TYPES.keys())}")

    def __post_init__(self):
        # Ensure experimental label is set in __init__ (Pydantic V2 compatibility)
        pass

class IntelligenceEnrichmentModel(BaseModel):
    """Independent Intelligence Enrichment data model"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str = Field(..., description="Entity being enriched (ThreatActor, Malware, etc.)")
    entity_type: str = Field(..., description="Entity type")
    enrichment_type: str = Field(..., description="Enrichment type (attribution, correlation, context, etc.)")
    enriched_data: Dict[str, Any] = Field(default_factory=dict, description="Enriched intelligence data")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence score (0-1)")
    source_id: Optional[str] = Field(None, description="Intelligence source ID")
    provenance: Optional[str] = Field(None, description="Provenance information")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    experimental_label: Optional[str] = Field(default=None, description="Experimental data label")
    
    # Explicit source field for __init__ compatibility
    source: Optional[str] = Field(None, description="Intelligence source (for __init__ compatibility)")
    
    model_config = ConfigDict(extra="ignore")
        
    def __init__(self, **data):
        super().__init__(**data)
        # Set experimental label if no source provided
        if getattr(self, 'source', None) is None and self.experimental_label is None:
            self.experimental_label = EXPERIMENTAL_DEMO_DATA_ONLY

    def __post_init__(self):
        # Ensure experimental label is set in __init__ (Pydantic V2 compatibility)
        pass

class IntelligenceEnrichmentService:
    """Independent Intelligence Enrichment and Provenance service functions"""
    
    def __init__(self):
        self._sources: Dict[str, IntelligenceSourceModel] = {}
        self._enrichments: Dict[str, IntelligenceEnrichmentModel] = {}
    
    # Source Management
    def create_source(self, source_data: Dict[str, Any]) -> IntelligenceSourceModel:
        """Create independent intelligence source"""
        # Ensure experimental label is set in data before model creation
        if source_data.get("source") is None and "experimental_label" not in source_data:
            source_data["experimental_label"] = EXPERIMENTAL_DEMO_DATA_ONLY
            
        source = IntelligenceSourceModel(**source_data)
        self._sources[source.id] = source
        return source
    
    def get_source(self, source_id: str) -> Optional[IntelligenceSourceModel]:
        """Get intelligence source by ID"""
        return self._sources.get(source_id)
    
    def list_sources(self) -> List[IntelligenceSourceModel]:
        """List all intelligence sources"""
        return list(self._sources.values())
    
    def find_by_type(self, source_type: str) -> List[IntelligenceSourceModel]:
        """Find sources by type"""
        return [s for s in self._sources.values() if s.type == source_type]
    
    def update_source(self, source_id: str, update_data: Dict[str, Any]) -> Optional[IntelligenceSourceModel]:
        """Update existing intelligence source"""
        if source_id not in self._sources:
            return None
        
        source = self._sources[source_id]
        # Handle experimental label in update data
        if "source" in update_data and update_data["source"] is None and "experimental_label" not in update_data:
            update_data["experimental_label"] = EXPERIMENTAL_DEMO_DATA_ONLY
            
        for key, value in update_data.items():
            if hasattr(source, key):
                setattr(source, key, value)
        
        source.updated_at = datetime.utcnow()
        return source
    
    def delete_source(self, source_id: str) -> bool:
        """Delete intelligence source"""
        if source_id in self._sources:
            del self._sources[source_id]
            return True
        return False
    
    # Enrichment Management
    def create_enrichment(self, enrichment_data: Dict[str, Any]) -> IntelligenceEnrichmentModel:
        """Create independent intelligence enrichment"""
        # Ensure experimental label is set in data before model creation
        if enrichment_data.get("source") is None and "experimental_label" not in enrichment_data:
            enrichment_data["experimental_label"] = EXPERIMENTAL_DEMO_DATA_ONLY
            
        enrichment = IntelligenceEnrichmentModel(**enrichment_data)
        self._enrichments[enrichment.id] = enrichment
        return enrichment
    
    def get_enrichment(self, enrichment_id: str) -> Optional[IntelligenceEnrichmentModel]:
        """Get intelligence enrichment by ID"""
        return self._enrichments.get(enrichment_id)
    
    def list_enrichments(self) -> List[IntelligenceEnrichmentModel]:
        """List all intelligence enrichments"""
        return list(self._enrichments.values())
    
    def find_by_entity(self, entity_id: str) -> List[IntelligenceEnrichmentModel]:
        """Find enrichments for specific entity"""
        return [e for e in self._enrichments.values() if e.entity_id == entity_id]
    
    def find_by_source(self, source_id: str) -> List[IntelligenceEnrichmentModel]:
        """Find enrichments from specific source"""
        return [e for e in self._enrichments.values() if e.source_id == source_id]
    
    def update_enrichment(self, enrichment_id: str, update_data: Dict[str, Any]) -> Optional[IntelligenceEnrichmentModel]:
        """Update existing intelligence enrichment"""
        if enrichment_id not in self._enrichments:
            return None
        
        enrichment = self._enrichments[enrichment_id]
        # Handle experimental label in update data
        if "source" in update_data and update_data["source"] is None and "experimental_label" not in update_data:
            update_data["experimental_label"] = EXPERIMENTAL_DEMO_DATA_ONLY
            
        for key, value in update_data.items():
            if hasattr(enrichment, key):
                setattr(enrichment, key, value)
        
        enrichment.updated_at = datetime.utcnow()
        return enrichment
    
    def delete_enrichment(self, enrichment_id: str) -> bool:
        """Delete intelligence enrichment"""
        if enrichment_id in self._enrichments:
            del self._enrichments[enrichment_id]
            return True
        return False
    
    def enrich_entity(self, entity_id: str, entity_type: str, enrichment_type: str, 
                     enriched_data: Dict[str, Any], source_id: Optional[str] = None,
                     confidence: float = 1.0) -> IntelligenceEnrichmentModel:
        """Convenience method to enrich an entity"""
        data = {
            "entity_id": entity_id,
            "entity_type": entity_type,
            "enrichment_type": enrichment_type,
            "enriched_data": enriched_data,
            "confidence": confidence,
            "source_id": source_id
        }
        return self.create_enrichment(data)

# Independent module - no imports from models.py or main.py
# Enrichment layer enhances all Threat Intelligence modules
