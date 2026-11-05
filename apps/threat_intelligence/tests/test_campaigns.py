"""
Unit tests for Campaign module.
Branch: arena/93315d2c-cicc
Constraint: Independent file, tests only
"""

import pytest
from datetime import datetime
from apps.threat_intelligence.campaigns import CampaignModel, CampaignService

class TestCampaignModel:
    """Test Campaign data model"""
    
    def test_create_campaign(self):
        """Test creating campaign model"""
        data = {
            "name": "Test Campaign",
            "description": "Test description",
            "threat_actor_ids": ["actor-1", "actor-2"],
            "malware_ids": ["malware-1"],
            "ttp_ids": ["ttp-1"],
            "mitre_attack_ids": ["T1059", "TA0002"],
            "confidence": 0.95,
            "source": "Test Source",
            "provenance": "Test Provenance"
        }
        campaign = CampaignModel(**data)
        
        assert campaign.name == "Test Campaign"
        assert len(campaign.threat_actor_ids) == 2
        assert len(campaign.malware_ids) == 1
        assert len(campaign.ttp_ids) == 1
        assert campaign.confidence == 0.95
        assert campaign.source == "Test Source"
        assert campaign.experimental_label is None
        assert isinstance(campaign.created_at, datetime)
    
    def test_experimental_label(self):
        """Test experimental data labeling"""
        data = {
            "name": "Experimental Campaign",
            "description": "No source provided"
        }
        campaign = CampaignModel(**data)
        
        assert campaign.experimental_label == "EXPERIMENTAL_DEMO_DATA_ONLY"

class TestCampaignService:
    """Test Campaign service functions"""
    
    def setup_method(self):
        """Setup test service"""
        self.service = CampaignService()
    
    def test_create_campaign(self):
        """Test creating campaign"""
        data = {
            "name": "Test Campaign",
            "description": "Test description",
            "mitre_attack_ids": ["T1059"]
        }
        campaign = self.service.create_campaign(data)
        
        assert campaign.id is not None
        assert campaign.name == "Test Campaign"
        assert campaign.experimental_label == "EXPERIMENTAL_DEMO_DATA_ONLY"
        assert len(self.service.list_campaigns()) == 1
    
    def test_get_campaign(self):
        """Test getting campaign"""
        data = {"name": "Test Campaign"}
        campaign = self.service.create_campaign(data)
        
        retrieved = self.service.get_campaign(campaign.id)
        assert retrieved is not None
        assert retrieved.name == "Test Campaign"
    
    def test_list_campaigns(self):
        """Test listing campaigns"""
        self.service.create_campaign({"name": "Campaign 1"})
        self.service.create_campaign({"name": "Campaign 2"})
        
        campaigns = self.service.list_campaigns()
        assert len(campaigns) == 2
    
    def test_find_by_mitre_id(self):
        """Test finding campaigns by MITRE ID"""
        self.service.create_campaign({
            "name": "Campaign 1",
            "mitre_attack_ids": ["T1059", "TA0002"]
        })
        self.service.create_campaign({
            "name": "Campaign 2",
            "mitre_attack_ids": ["T1059"]
        })
        self.service.create_campaign({
            "name": "Campaign 3",
            "mitre_attack_ids": ["T1060"]
        })
        
        results = self.service.find_by_mitre_id("T1059")
        assert len(results) == 2
        
        results = self.service.find_by_mitre_id("T1060")
        assert len(results) == 1
    
    def test_update_campaign(self):
        """Test updating campaign"""
        data = {"name": "Original Name", "description": "Original"}
        campaign = self.service.create_campaign(data)
        
        update_data = {"name": "Updated Name", "description": "Updated"}
        updated = self.service.update_campaign(campaign.id, update_data)
        
        assert updated is not None
        assert updated.name == "Updated Name"
        assert updated.description == "Updated"
        assert updated.updated_at > updated.created_at
    
    def test_delete_campaign(self):
        """Test deleting campaign"""
        data = {"name": "Campaign to Delete"}
        campaign = self.service.create_campaign(data)
        
        success = self.service.delete_campaign(campaign.id)
        assert success is True
        
        retrieved = self.service.get_campaign(campaign.id)
        assert retrieved is None
        
        # Test deleting non-existent campaign
        success = self.service.delete_campaign("non-existent")
        assert success is False

if __name__ == "__main__":
    pytest.main([__file__])
