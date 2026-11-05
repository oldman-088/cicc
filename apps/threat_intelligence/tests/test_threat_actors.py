"""
Unit tests for Threat Actor module.
Branch: arena/93315d2c-cicc
Constraint: Independent file, tests only
"""

import pytest
from datetime import datetime
from apps.threat_intelligence.threat_actors import ThreatActorModel, ThreatActorService

class TestThreatActorModel:
    """Test Threat Actor data model"""
    
    def test_create_threat_actor(self):
        """Test creating threat actor model"""
        data = {
            "name": "Test Threat Actor",
            "alias": ["Alias1", "Alias2"],
            "description": "Test description",
            "mitre_attack_ids": ["T1059", "TA0002"],
            "confidence": 0.85,
            "source": "Test Source",
            "provenance": "Test Provenance"
        }
        actor = ThreatActorModel(**data)
        
        assert actor.name == "Test Threat Actor"
        assert len(actor.alias) == 2
        assert actor.confidence == 0.85
        assert actor.source == "Test Source"
        assert actor.experimental_label is None
        assert isinstance(actor.created_at, datetime)
    
    def test_experimental_label(self):
        """Test experimental data labeling"""
        data = {
            "name": "Experimental Actor",
            "description": "No source provided"
        }
        actor = ThreatActorModel(**data)
        
        assert actor.experimental_label == "EXPERIMENTAL_DEMO_DATA_ONLY"

class TestThreatActorService:
    """Test Threat Actor service functions"""
    
    def setup_method(self):
        """Setup test service"""
        self.service = ThreatActorService()
    
    def test_create_actor(self):
        """Test creating threat actor"""
        data = {
            "name": "Test Actor",
            "description": "Test description",
            "mitre_attack_ids": ["T1059"]
        }
        actor = self.service.create_actor(data)
        
        assert actor.id is not None
        assert actor.name == "Test Actor"
        assert actor.experimental_label == "EXPERIMENTAL_DEMO_DATA_ONLY"
        assert len(self.service.list_actors()) == 1
    
    def test_get_actor(self):
        """Test getting threat actor"""
        data = {"name": "Test Actor"}
        actor = self.service.create_actor(data)
        
        retrieved = self.service.get_actor(actor.id)
        assert retrieved is not None
        assert retrieved.name == "Test Actor"
    
    def test_list_actors(self):
        """Test listing threat actors"""
        self.service.create_actor({"name": "Actor 1"})
        self.service.create_actor({"name": "Actor 2"})
        
        actors = self.service.list_actors()
        assert len(actors) == 2
    
    def test_find_by_mitre_id(self):
        """Test finding actors by MITRE ID"""
        self.service.create_actor({
            "name": "Actor 1",
            "mitre_attack_ids": ["T1059", "TA0002"]
        })
        self.service.create_actor({
            "name": "Actor 2",
            "mitre_attack_ids": ["T1059"]
        })
        self.service.create_actor({
            "name": "Actor 3",
            "mitre_attack_ids": ["T1060"]
        })
        
        results = self.service.find_by_mitre_id("T1059")
        assert len(results) == 2
        
        results = self.service.find_by_mitre_id("T1060")
        assert len(results) == 1
    
    def test_update_actor(self):
        """Test updating threat actor"""
        data = {"name": "Original Name", "description": "Original"}
        actor = self.service.create_actor(data)
        
        update_data = {"name": "Updated Name", "description": "Updated"}
        updated = self.service.update_actor(actor.id, update_data)
        
        assert updated is not None
        assert updated.name == "Updated Name"
        assert updated.description == "Updated"
        assert updated.updated_at > updated.created_at
    
    def test_delete_actor(self):
        """Test deleting threat actor"""
        data = {"name": "Actor to Delete"}
        actor = self.service.create_actor(data)
        
        success = self.service.delete_actor(actor.id)
        assert success is True
        
        retrieved = self.service.get_actor(actor.id)
        assert retrieved is None
        
        # Test deleting non-existent actor
        success = self.service.delete_actor("non-existent")
        assert success is False

if __name__ == "__main__":
    pytest.main([__file__])
