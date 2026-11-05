"""
Unit tests for Intelligence Collection and Normalization Layer.
Branch: arena/93315d2c-cicc
Constraint: Independent file, tests only
"""

import pytest
from datetime import datetime
from apps.threat_intelligence.collection import CollectionTaskModel, NormalizationRecordModel, CollectionService, COLLECTION_STATUS, NORMALIZATION_STATUS

class TestCollectionTaskModel:
    """Test Collection Task data model"""
    
    def test_create_collection_task(self):
        """Test creating collection task model"""
        data = {
            "source_id": "source-1",
            "query": "threat_actor:APT29",
            "target_entities": ["ThreatActor", "Campaign"],
            "status": "COMPLETED",
            "collected_count": 15,
            "confidence": 0.95,
            "source": "MITRE ATT&CK",
            "provenance": "Official MITRE distribution"
        }
        task = CollectionTaskModel(**data)
        
        assert task.source_id == "source-1"
        assert task.query == "threat_actor:APT29"
        assert task.status == "COMPLETED"
        assert task.collected_count == 15
        assert task.confidence == 0.95
        assert task.source == "MITRE ATT&CK"
        assert task.experimental_label is None
        assert isinstance(task.created_at, datetime)
    
    def test_experimental_label(self):
        """Test experimental data labeling"""
        data = {
            "source_id": "source-1",
            "query": "test query",
            "target_entities": ["ThreatActor"]
        }
        task = CollectionTaskModel(**data)
        
        assert task.experimental_label == "EXPERIMENTAL_DEMO_DATA_ONLY"
    
    def test_invalid_status(self):
        """Test invalid collection status validation"""
        data = {
            "source_id": "source-1",
            "query": "test query",
            "target_entities": ["ThreatActor"],
            "status": "INVALID_STATUS"
        }
        
        with pytest.raises(ValueError, match="Invalid status"):
            CollectionTaskModel(**data)

class TestNormalizationRecordModel:
    """Test Normalization Record data model"""
    
    def test_create_normalization_record(self):
        """Test creating normalization record model"""
        data = {
            "collection_task_id": "task-1",
            "raw_data": {"entities": ["actor-1"]},
            "normalized_data": {"normalized_entities": ["actor-1"]},
            "status": "COMPLETED",
            "confidence": 0.98,
            "source": "MITRE ATT&CK",
            "provenance": "Official MITRE distribution"
        }
        record = NormalizationRecordModel(**data)
        
        assert record.collection_task_id == "task-1"
        assert record.status == "COMPLETED"
        assert record.confidence == 0.98
        assert record.source == "MITRE ATT&CK"
        assert record.experimental_label is None
        assert isinstance(record.created_at, datetime)
    
    def test_experimental_label(self):
        """Test experimental data labeling"""
        data = {
            "collection_task_id": "task-1",
            "raw_data": {"entities": ["actor-1"]},
            "normalized_data": {"normalized_entities": ["actor-1"]}
        }
        record = NormalizationRecordModel(**data)
        
        assert record.experimental_label == "EXPERIMENTAL_DEMO_DATA_ONLY"
    
    def test_invalid_status(self):
        """Test invalid normalization status validation"""
        data = {
            "collection_task_id": "task-1",
            "raw_data": {"entities": ["actor-1"]},
            "normalized_data": {"normalized_entities": ["actor-1"]},
            "status": "INVALID_STATUS"
        }
        
        with pytest.raises(ValueError, match="Invalid status"):
            NormalizationRecordModel(**data)

class TestCollectionService:
    """Test Collection service functions"""
    
    def setup_method(self):
        """Setup test service"""
        self.service = CollectionService()
    
    # Collection Task Management Tests
    def test_create_collection_task(self):
        """Test creating collection task"""
        data = {
            "source_id": "source-1",
            "query": "threat_actor:APT29",
            "target_entities": ["ThreatActor", "Campaign"],
            "status": "COMPLETED"
        }
        task = self.service.create_collection_task(data)
        
        assert task.id is not None
        assert task.source_id == "source-1"
        assert task.query == "threat_actor:APT29"
        assert task.status == "COMPLETED"
        assert task.experimental_label == "EXPERIMENTAL_DEMO_DATA_ONLY"
        assert len(self.service.list_collection_tasks()) == 1
    
    def test_get_collection_task(self):
        """Test getting collection task"""
        data = {
            "source_id": "source-1",
            "query": "threat_actor:APT29",
            "target_entities": ["ThreatActor"]
        }
        task = self.service.create_collection_task(data)
        
        retrieved = self.service.get_collection_task(task.id)
        assert retrieved is not None
        assert retrieved.source_id == "source-1"
    
    def test_list_collection_tasks(self):
        """Test listing collection tasks"""
        self.service.create_collection_task({
            "source_id": "source-1",
            "query": "threat_actor:APT29",
            "target_entities": ["ThreatActor"]
        })
        self.service.create_collection_task({
            "source_id": "source-2",
            "query": "malware:Emotet",
            "target_entities": ["Malware"]
        })
        
        tasks = self.service.list_collection_tasks()
        assert len(tasks) == 2
    
    def test_find_by_source(self):
        """Test finding collection tasks by source"""
        self.service.create_collection_task({
            "source_id": "source-1",
            "query": "threat_actor:APT29",
            "target_entities": ["ThreatActor"]
        })
        self.service.create_collection_task({
            "source_id": "source-1",
            "query": "malware:Emotet",
            "target_entities": ["Malware"]
        })
        self.service.create_collection_task({
            "source_id": "source-2",
            "query": "campaign:FIN7",
            "target_entities": ["Campaign"]
        })
        
        source1_tasks = self.service.find_by_source("source-1")
        assert len(source1_tasks) == 2
    
    def test_find_by_status(self):
        """Test finding collection tasks by status"""
        self.service.create_collection_task({
            "source_id": "source-1",
            "query": "threat_actor:APT29",
            "target_entities": ["ThreatActor"],
            "status": "COMPLETED"
        })
        self.service.create_collection_task({
            "source_id": "source-2",
            "query": "malware:Emotet",
            "target_entities": ["Malware"],
            "status": "FAILED"
        })
        
        completed_tasks = self.service.find_by_status("COMPLETED")
        assert len(completed_tasks) == 1
        
        failed_tasks = self.service.find_by_status("FAILED")
        assert len(failed_tasks) == 1
    
    def test_update_collection_task(self):
        """Test updating collection task"""
        data = {
            "source_id": "source-1",
            "query": "threat_actor:APT29",
            "target_entities": ["ThreatActor"],
            "status": "PENDING"
        }
        task = self.service.create_collection_task(data)
        
        update_data = {
            "status": "COMPLETED",
            "collected_count": 15,
            "confidence": 0.98
        }
        updated = self.service.update_collection_task(task.id, update_data)
        
        assert updated is not None
        assert updated.status == "COMPLETED"
        assert updated.collected_count == 15
        assert updated.confidence == 0.98
        assert updated.updated_at > updated.created_at
    
    def test_delete_collection_task(self):
        """Test deleting collection task"""
        data = {
            "source_id": "source-1",
            "query": "threat_actor:APT29",
            "target_entities": ["ThreatActor"]
        }
        task = self.service.create_collection_task(data)
        
        success = self.service.delete_collection_task(task.id)
        assert success is True
        
        retrieved = self.service.get_collection_task(task.id)
        assert retrieved is None
    
    # Normalization Record Management Tests
    def test_create_normalization_record(self):
        """Test creating normalization record"""
        data = {
            "collection_task_id": "task-1",
            "raw_data": {"entities": ["actor-1"]},
            "normalized_data": {"normalized_entities": ["actor-1"]},
            "status": "COMPLETED"
        }
        record = self.service.create_normalization_record(data)
        
        assert record.id is not None
        assert record.collection_task_id == "task-1"
        assert record.status == "COMPLETED"
        assert record.experimental_label == "EXPERIMENTAL_DEMO_DATA_ONLY"
        assert len(self.service.list_normalization_records()) == 1
    
    def test_get_normalization_record(self):
        """Test getting normalization record"""
        data = {
            "collection_task_id": "task-1",
            "raw_data": {"entities": ["actor-1"]},
            "normalized_data": {"normalized_entities": ["actor-1"]}
        }
        record = self.service.create_normalization_record(data)
        
        retrieved = self.service.get_normalization_record(record.id)
        assert retrieved is not None
        assert retrieved.collection_task_id == "task-1"
    
    def test_list_normalization_records(self):
        """Test listing normalization records"""
        self.service.create_normalization_record({
            "collection_task_id": "task-1",
            "raw_data": {"entities": ["actor-1"]},
            "normalized_data": {"normalized_entities": ["actor-1"]}
        })
        self.service.create_normalization_record({
            "collection_task_id": "task-2",
            "raw_data": {"entities": ["malware-1"]},
            "normalized_data": {"normalized_entities": ["malware-1"]}
        })
        
        records = self.service.list_normalization_records()
        assert len(records) == 2
    
    def test_find_by_collection_task(self):
        """Test finding normalization records by collection task"""
        self.service.create_normalization_record({
            "collection_task_id": "task-1",
            "raw_data": {"entities": ["actor-1"]},
            "normalized_data": {"normalized_entities": ["actor-1"]}
        })
        self.service.create_normalization_record({
            "collection_task_id": "task-1",
            "raw_data": {"entities": ["campaign-1"]},
            "normalized_data": {"normalized_entities": ["campaign-1"]}
        })
        self.service.create_normalization_record({
            "collection_task_id": "task-2",
            "raw_data": {"entities": ["malware-1"]},
            "normalized_data": {"normalized_entities": ["malware-1"]}
        })
        
        task1_records = self.service.find_by_collection_task("task-1")
        assert len(task1_records) == 2
    
    def test_find_by_status(self):
        """Test finding normalization records by status"""
        self.service.create_normalization_record({
            "collection_task_id": "task-1",
            "raw_data": {"entities": ["actor-1"]},
            "normalized_data": {"normalized_entities": ["actor-1"]},
            "status": "COMPLETED"
        })
        self.service.create_normalization_record({
            "collection_task_id": "task-2",
            "raw_data": {"entities": ["malware-1"]},
            "normalized_data": {"normalized_entities": ["malware-1"]},
            "status": "FAILED"
        })
        
        completed_records = self.service.find_by_status("COMPLETED")
        assert len(completed_records) == 1
        
        failed_records = self.service.find_by_status("FAILED")
        assert len(failed_records) == 1
    
    def test_update_normalization_record(self):
        """Test updating normalization record"""
        data = {
            "collection_task_id": "task-1",
            "raw_data": {"entities": ["actor-1"]},
            "normalized_data": {"normalized_entities": ["actor-1"]},
            "status": "PENDING"
        }
        record = self.service.create_normalization_record(data)
        
        update_data = {
            "status": "COMPLETED",
            "normalized_data": {"normalized_entities": ["actor-1", "campaign-1"]},
            "confidence": 0.98
        }
        updated = self.service.update_normalization_record(record.id, update_data)
        
        assert updated is not None
        assert updated.status == "COMPLETED"
        assert len(updated.normalized_data["normalized_entities"]) == 2
        assert updated.confidence == 0.98
        assert updated.updated_at > updated.created_at
    
    def test_delete_normalization_record(self):
        """Test deleting normalization record"""
        data = {
            "collection_task_id": "task-1",
            "raw_data": {"entities": ["actor-1"]},
            "normalized_data": {"normalized_entities": ["actor-1"]}
        }
        record = self.service.create_normalization_record(data)
        
        success = self.service.delete_normalization_record(record.id)
        assert success is True
        
        retrieved = self.service.get_normalization_record(record.id)
        assert retrieved is None
    
    # Execution Tests
    def test_execute_collection(self):
        """Test collection execution simulation"""
        task = self.service.execute_collection(
            source_id="source-1",
            query="threat_actor:APT29",
            target_entities=["ThreatActor", "Campaign"]
        )
        
        assert task.source_id == "source-1"
        assert task.query == "threat_actor:APT29"
        assert task.status == "COMPLETED"
        assert task.collected_count == 10
        assert task.experimental_label == "EXPERIMENTAL_DEMO_DATA_ONLY"
    
    def test_normalize_collection(self):
        """Test normalization execution simulation"""
        raw_data = {
            "entities": ["actor-1", "campaign-1"],
            "relationships": [["actor-1", "campaign-1", "ATTRIBUTED_TO"]],
            "confidence": 0.9
        }
        
        record = self.service.normalize_collection(
            collection_task_id="task-1",
            raw_data=raw_data
        )
        
        assert record.collection_task_id == "task-1"
        assert record.status == "COMPLETED"
        assert record.normalized_data["confidence_score"] == 0.9
        assert record.experimental_label == "EXPERIMENTAL_DEMO_DATA_ONLY"

if __name__ == "__main__":
    pytest.main([__file__])
