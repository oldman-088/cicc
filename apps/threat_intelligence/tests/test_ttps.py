"""
Unit tests for TTP module.
Branch: arena/93315d2c-cicc
Constraint: Independent file, tests only
"""

import pytest
from datetime import datetime
from apps.threat_intelligence.ttps import TTPModel, TTPService

class TestTTPModel:
    """Test TTP data model"""
    
    def test_create_ttp(self):
        """Test creating TTP model"""
        data = {
            "name": "Test TTP",
            "description": "Test description",
            "mitre_attack_id": "T1059",
            "category": "Technique",
            "confidence": 0.88,
            "source": "Test Source",
            "provenance": "Test Provenance"
        }
        ttp = TTPModel(**data)
        
        assert ttp.name == "Test TTP"
        assert ttp.mitre_attack_id == "T1059"
        assert ttp.category == "Technique"
        assert ttp.confidence == 0.88
        assert ttp.source == "Test Source"
        assert ttp.experimental_label is None
        assert isinstance(ttp.created_at, datetime)
    
    def test_experimental_label(self):
        """Test experimental data labeling"""
        data = {
            "name": "Experimental TTP",
            "category": "Technique"
        }
        ttp = TTPModel(**data)
        
        assert ttp.experimental_label == "EXPERIMENTAL_DEMO_DATA_ONLY"

class TestTTPService:
    """Test TTP service functions"""
    
    def setup_method(self):
        """Setup test service"""
        self.service = TTPService()
    
    def test_create_ttp(self):
        """Test creating TTP"""
        data = {
            "name": "Test TTP",
            "category": "Technique",
            "mitre_attack_id": "T1059"
        }
        ttp = self.service.create_ttp(data)
        
        assert ttp.id is not None
        assert ttp.name == "Test TTP"
        assert ttp.experimental_label == "EXPERIMENTAL_DEMO_DATA_ONLY"
        assert len(self.service.list_ttps()) == 1
    
    def test_get_ttp(self):
        """Test getting TTP"""
        data = {"name": "Test TTP"}
        ttp = self.service.create_ttp(data)
        
        retrieved = self.service.get_ttp(ttp.id)
        assert retrieved is not None
        assert retrieved.name == "Test TTP"
    
    def test_list_ttps(self):
        """Test listing TTPs"""
        self.service.create_ttp({"name": "TTP 1"})
        self.service.create_ttp({"name": "TTP 2"})
        
        ttps = self.service.list_ttps()
        assert len(ttps) == 2
    
    def test_find_by_mitre_id(self):
        """Test finding TTPs by MITRE ID"""
        self.service.create_ttp({
            "name": "TTP 1",
            "mitre_attack_id": "T1059"
        })
        self.service.create_ttp({
            "name": "TTP 2",
            "mitre_attack_id": "T1059"
        })
        self.service.create_ttp({
            "name": "TTP 3",
            "mitre_attack_id": "T1060"
        })
        
        results = self.service.find_by_mitre_id("T1059")
        assert len(results) == 2
        
        results = self.service.find_by_mitre_id("T1060")
        assert len(results) == 1
    
    def test_update_ttp(self):
        """Test updating TTP"""
        data = {"name": "Original Name", "category": "Technique"}
        ttp = self.service.create_ttp(data)
        
        update_data = {"name": "Updated Name", "category": "Tactic"}
        updated = self.service.update_ttp(ttp.id, update_data)
        
        assert updated is not None
        assert updated.name == "Updated Name"
        assert updated.category == "Tactic"
        assert updated.updated_at > updated.created_at
    
    def test_delete_ttp(self):
        """Test deleting TTP"""
        data = {"name": "TTP to Delete"}
        ttp = self.service.create_ttp(data)
        
        success = self.service.delete_ttp(ttp.id)
        assert success is True
        
        retrieved = self.service.get_ttp(ttp.id)
        assert retrieved is None
        
        # Test deleting non-existent TTP
        success = self.service.delete_ttp("non-existent")
        assert success is False

if __name__ == "__main__":
    pytest.main([__file__])
