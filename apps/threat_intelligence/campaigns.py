"""
Independent Campaign module for CICC Threat Intelligence.
Branch: arena/93315d2c-cicc
Constraint: Independent file, no modification to models.py/main.py/migrations
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
import uuid

# Experimental data labeling: CLEARLY MARKED
EXPERIMENTAL_DEMO_DATA_ONLY = "EXPERIMENTAL_DEMO_DATA_ONLY"

class CampaignModel(BaseModel):
    """Independent Campaign data model"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., description="Campaign name")
    description: Optional[str] = Field(None, description="Campaign description")
    threat_actor_ids: Optional[List[str]] = Field(default_factory=list, description="Associated threat actor IDs")
    malware_ids: Optional[List[str]] = Field(default_factory=list, description="Associated malware IDs")
    ttp_ids: Optional[List[str]] = Field(default_factory=list, description="Associated TTP IDs")
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

class CampaignService:
    """Independent Campaign service functions"""
    
    def __init__(self):
        self._campaigns: Dict[str, CampaignModel] = {}
    
    def create_campaign(self, campaign_data: Dict[str, Any]) -> CampaignModel:
        """Create independent campaign"""
        # Ensure experimental label is set in data before model creation
        if campaign_data.get("source") is None and "experimental_label" not in campaign_data:
            campaign_data["experimental_label"] = EXPERIMENTAL_DEMO_DATA_ONLY
            
        campaign = CampaignModel(**campaign_data)
        self._campaigns[campaign.id] = campaign
        return campaign
    
    def get_campaign(self, campaign_id: str) -> Optional[CampaignModel]:
        """Get campaign by ID"""
        return self._campaigns.get(campaign_id)
    
    def list_campaigns(self) -> List[CampaignModel]:
        """List all campaigns"""
        return list(self._campaigns.values())
    
    def find_by_mitre_id(self, mitre_id: str) -> List[CampaignModel]:
        """Find campaigns associated with MITRE ATT&CK ID"""
        return [
            campaign for campaign in self._campaigns.values()
            if mitre_id in campaign.mitre_attack_ids
        ]
    
    def update_campaign(self, campaign_id: str, update_data: Dict[str, Any]) -> Optional[CampaignModel]:
        """Update existing campaign"""
        if campaign_id not in self._campaigns:
            return None
        
        campaign = self._campaigns[campaign_id]
        # Handle experimental label in update data
        if "source" in update_data and update_data["source"] is None and "experimental_label" not in update_data:
            update_data["experimental_label"] = EXPERIMENTAL_DEMO_DATA_ONLY
            
        for key, value in update_data.items():
            if hasattr(campaign, key):
                setattr(campaign, key, value)
        
        campaign.updated_at = datetime.utcnow()
        return campaign
    
    def delete_campaign(self, campaign_id: str) -> bool:
        """Delete campaign"""
        if campaign_id in self._campaigns:
            del self._campaigns[campaign_id]
            return True
        return False

# Independent module - no imports from models.py or main.py
