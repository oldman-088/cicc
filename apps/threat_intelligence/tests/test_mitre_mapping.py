"""
Unit tests for MITRE ATT&CK mapping service.
Branch: arena/93315d2c-cicc
Constraint: Independent file, tests only
"""

import pytest
from datetime import datetime
from apps.threat_intelligence.mitre_mapping import MITREMappingModel, MITREMappingService

class TestMITREMappingModel:
    """Test MITRE mapping data model"""
    
    def test_create_mapping(self):
        """Test creating MITRE mapping model"""
        data = {
            "mitre_id": "T1059",
            "name": "Command and Scripting Interpreter",
            "category": "Technique",
            "description": "Adversaries may use command and scripting interpreters",
            "confidence": 1.0,
            "source": "MITRE ATT&CK",
            "provenance": "MITRE Official"
        }
        mapping = MITREMappingModel(**data)
        
        assert mapping.mitre_id == "T1059"
        assert mapping.name == "Command and Scripting Interpreter"
        assert mapping.category == "Technique"
        assert mapping.confidence == 1.0
        assert mapping.source == "MITRE ATT&CK"
        assert mapping.experimental_label is None
        assert isinstance(mapping.created_at, datetime)
    
    def test_experimental_label(self):
        """Test experimental data labeling for non-MITRE source"""
        data = {
            "mitre_id": "T9999",
            "name": "Experimental Technique",
            "category": "Technique"
        }
        mapping = MITREMappingModel(**data)
        
        assert mapping.experimental_label == "EXPERIMENTAL_DEMO_DATA_ONLY"

class TestMITREMappingService:
    """Test MITRE mapping service functions"""
    
    def setup_method(self):
        """Setup test service"""
        self.service = MITREMappingService()
    
    def test_create_mapping(self):
        """Test creating MITRE mapping"""
        data = {
            "mitre_id": "T1059",
            "name": "Command and Scripting Interpreter",
            "category": "Technique",
            "source": "MITRE ATT&CK"
        }
        mapping = self.service.create_mapping(data)
        
        assert mapping.id is not None
        assert mapping.mitre_id == "T1059"
        assert mapping.experimental_label is None  # MITRE source
        assert len(self.service.list_mappings()) == 1
    
    def test_create_experimental_mapping(self):
        """Test creating experimental MITRE mapping"""
        data = {
            "mitre_id": "T9999",
            "name": "Experimental Technique",
            "category": "Technique"
        }
        mapping = self.service.create_mapping(data)
        
        assert mapping.experimental_label == "EXPERIMENTAL_DEMO_DATA_ONLY"
    
    def test_get_mapping(self):
        """Test getting MITRE mapping"""
        data = {"mitre_id": "T1059", "name": "Test Technique", "category": "Technique"}
        mapping = self.service.create_mapping(data)
        
        retrieved = self.service.get_mapping(mapping.id)
        assert retrieved is not None
        assert retrieved.mitre_id == "T1059"
    
    def test_get_by_mitre_id(self):
        """Test getting mapping by MITRE ID"""
        self.service.create_mapping({
            "mitre_id": "T1059",
            "name": "Technique 1",
            "category": "Technique"
        })
        self.service.create_mapping({
            "mitre_id": "TA0002",
            "name": "Tactic 1",
            "category": "Tactic"
        })
        
        mapping1 = self.service.get_by_mitre_id("T1059")
        assert mapping1 is not None
        assert mapping1.name == "Technique 1"
        
        mapping2 = self.service.get_by_mitre_id("TA0002")
        assert mapping2 is not None
        assert mapping2.name == "Tactic 1"
        
        mapping3 = self.service.get_by_mitre_id("T9999")
        assert mapping3 is None
    
    def test_list_mappings(self):
        """Test listing MITRE mappings"""
        self.service.create_mapping({"mitre_id": "T1059", "name": "Technique 1", "category": "Technique"})
        self.service.create_mapping({"mitre_id": "TA0002", "name": "Tactic 1", "category": "Tactic"})
        
        mappings = self.service.list_mappings()
        assert len(mappings) == 2
    
    def test_update_mapping(self):
        """Test updating MITRE mapping"""
        data = {"mitre_id": "T1059", "name": "Original Name", "category": "Technique"}
        mapping = self.service.create_mapping(data)
        
        update_data = {"name": "Updated Name", "category": "Tactic"}
        updated = self.service.update_mapping(mapping.id, update_data)
        
        assert updated is not None
        assert updated.name == "Updated Name"
        assert updated.category == "Tactic"
        assert updated.updated_at > updated.created_at
    
    def test_delete_mapping(self):
        """Test deleting MITRE mapping"""
        data = {"mitre_id": "T1059", "name": "Technique to Delete", "category": "Technique"}
        mapping = self.service.create_mapping(data)
        
        success = self.service.delete_mapping(mapping.id)
        assert success is True
        
        retrieved = self.service.get_mapping(mapping.id)
        assert retrieved is None
        
        # Test deleting non-existent mapping
        success = self.service.delete_mapping("non-existent")
        assert success is False

if __name__ == "__main__":
    pytest.main([__file__])
