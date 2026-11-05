"""
Intelligence Collection and Normalization Layer for CICC.
Branch: arena/93315d2c-cicc
Constraint: Independent file, no modification to models.py/main.py/migrations
"""

from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
import uuid

# Experimental data labeling: CLEARLY MARKED
EXPERIMENTAL_DEMO_DATA_ONLY = "EXPERIMENTAL_DEMO_DATA_ONLY"

# Collection Status Types
COLLECTION_STATUS = {
    "PENDING": "Collection pending",
    "IN_PROGRESS": "Collection in progress",
    "COMPLETED": "Collection completed",
    "FAILED": "Collection failed",
    "CANCELLED": "Collection cancelled"
}

# Normalization Status Types
NORMALIZATION_STATUS = {
    "PENDING": "Normalization pending",
    "IN_PROGRESS": "Normalization in progress",
    "COMPLETED": "Normalization completed",
    "FAILED": "Normalization failed",
    "SKIPPED": "Normalization skipped"
}

class CollectionTaskModel(BaseModel):
    """Independent Intelligence Collection Task data model"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_id: Optional[str] = Field(None, description="Intelligence source ID")
    query: Optional[str] = Field(None, description="Collection query/parameters")
    target_entities: List[str] = Field(default_factory=list, description="Target entity types")
    status: str = Field(default="PENDING", description="Collection status")
    started_at: Optional[datetime] = Field(None, description="Collection start time")
    completed_at: Optional[datetime] = Field(default_factory=datetime.utcnow, description="Collection completion time")
    collected_count: int = Field(default=0, description="Number of items collected")
    failed_count: int = Field(default=0, description="Number of failed items")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence in collection (0-1)")
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
            
        # Validate collection status
        if self.status not in COLLECTION_STATUS:
            raise ValueError(f"Invalid status: {self.status}. Must be one of {list(COLLECTION_STATUS.keys())}")

    def __post_init__(self):
        # Ensure experimental label is set in __init__ (Pydantic V2 compatibility)
        pass

class NormalizationRecordModel(BaseModel):
    """Independent Intelligence Normalization Record data model"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    collection_task_id: Optional[str] = Field(None, description="Collection task ID")
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="Raw collected data")
    normalized_data: Dict[str, Any] = Field(default_factory=dict, description="Normalized intelligence data")
    status: str = Field(default="PENDING", description="Normalization status")
    processed_at: Optional[datetime] = Field(default_factory=datetime.utcnow, description="Processing time")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence in normalization (0-1)")
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
            
        # Validate normalization status
        if self.status not in NORMALIZATION_STATUS:
            raise ValueError(f"Invalid status: {self.status}. Must be one of {list(NORMALIZATION_STATUS.keys())}")

    def __post_init__(self):
        # Ensure experimental label is set in __init__ (Pydantic V2 compatibility)
        pass

class CollectionService:
    """Independent Intelligence Collection and Normalization service functions"""
    
    def __init__(self):
        self._collection_tasks: Dict[str, CollectionTaskModel] = {}
        self._normalization_records: Dict[str, NormalizationRecordModel] = {}
    
    # Collection Task Management
    def create_collection_task(self, task_data: Dict[str, Any]) -> CollectionTaskModel:
        """Create independent collection task"""
        # Ensure experimental label is set in data before model creation
        if task_data.get("source") is None and "experimental_label" not in task_data:
            task_data["experimental_label"] = EXPERIMENTAL_DEMO_DATA_ONLY
            
        task = CollectionTaskModel(**task_data)
        self._collection_tasks[task.id] = task
        return task
    
    def get_collection_task(self, task_id: str) -> Optional[CollectionTaskModel]:
        """Get collection task by ID"""
        return self._collection_tasks.get(task_id)
    
    def list_collection_tasks(self) -> List[CollectionTaskModel]:
        """List all collection tasks"""
        return list(self._collection_tasks.values())
    
    def find_by_source(self, source_id: str) -> List[CollectionTaskModel]:
        """Find collection tasks by source"""
        return [t for t in self._collection_tasks.values() if t.source_id == source_id]
    
    def find_by_status(self, status: str) -> List[CollectionTaskModel]:
        """Find collection tasks by status"""
        return [t for t in self._collection_tasks.values() if t.status == status]
    
    def update_collection_task(self, task_id: str, update_data: Dict[str, Any]) -> Optional[CollectionTaskModel]:
        """Update existing collection task"""
        if task_id not in self._collection_tasks:
            return None
        
        task = self._collection_tasks[task_id]
        # Handle experimental label in update data
        if "source" in update_data and update_data["source"] is None and "experimental_label" not in update_data:
            update_data["experimental_label"] = EXPERIMENTAL_DEMO_DATA_ONLY
            
        for key, value in update_data.items():
            if hasattr(task, key):
                setattr(task, key, value)
        
        task.updated_at = datetime.utcnow()
        return task
    
    def delete_collection_task(self, task_id: str) -> bool:
        """Delete collection task"""
        if task_id in self._collection_tasks:
            del self._collection_tasks[task_id]
            return True
        return False
    
    # Normalization Record Management
    def create_normalization_record(self, record_data: Dict[str, Any]) -> NormalizationRecordModel:
        """Create independent normalization record"""
        # Ensure experimental label is set in data before model creation
        if record_data.get("source") is None and "experimental_label" not in record_data:
            record_data["experimental_label"] = EXPERIMENTAL_DEMO_DATA_ONLY
            
        record = NormalizationRecordModel(**record_data)
        self._normalization_records[record.id] = record
        return record
    
    def get_normalization_record(self, record_id: str) -> Optional[NormalizationRecordModel]:
        """Get normalization record by ID"""
        return self._normalization_records.get(record_id)
    
    def list_normalization_records(self) -> List[NormalizationRecordModel]:
        """List all normalization records"""
        return list(self._normalization_records.values())
    
    def find_by_collection_task(self, collection_task_id: str) -> List[NormalizationRecordModel]:
        """Find normalization records by collection task"""
        return [r for r in self._normalization_records.values() if r.collection_task_id == collection_task_id]
    
    def find_by_status(self, status: str) -> List[NormalizationRecordModel]:
        """Find normalization records by status"""
        return [r for r in self._normalization_records.values() if r.status == status]
    
    def update_normalization_record(self, record_id: str, update_data: Dict[str, Any]) -> Optional[NormalizationRecordModel]:
        """Update existing normalization record"""
        if record_id not in self._normalization_records:
            return None
        
        record = self._normalization_records[record_id]
        # Handle experimental label in update data
        if "source" in update_data and update_data["source"] is None and "experimental_label" not in update_data:
            update_data["experimental_label"] = EXPERIMENTAL_DEMO_DATA_ONLY
            
        for key, value in update_data.items():
            if hasattr(record, key):
                setattr(record, key, value)
        
        record.updated_at = datetime.utcnow()
        return record
    
    def delete_normalization_record(self, record_id: str) -> bool:
        """Delete normalization record"""
        if record_id in self._normalization_records:
            del self._normalization_records[record_id]
            return True
        return False
    
    # Collection Execution (simulated for independent module)
    def execute_collection(self, source_id: str, query: str, target_entities: List[str]) -> CollectionTaskModel:
        """Execute intelligence collection (simulated)"""
        task_data = {
            "source_id": source_id,
            "query": query,
            "target_entities": target_entities,
            "status": "COMPLETED",
            "collected_count": 10,  # Simulated count
            "failed_count": 0,
            "confidence": 0.95
        }
        return self.create_collection_task(task_data)
    
    # Normalization Execution (simulated for independent module)
    def normalize_collection(self, collection_task_id: str, raw_data: Dict[str, Any]) -> NormalizationRecordModel:
        """Normalize collected intelligence data (simulated)"""
        # Simulated normalization logic
        normalized_data = {
            "normalized_entities": raw_data.get("entities", []),
            "normalized_relationships": raw_data.get("relationships", []),
            "confidence_score": raw_data.get("confidence", 0.8),
            "processing_time": datetime.utcnow().isoformat()
        }
        
        record_data = {
            "collection_task_id": collection_task_id,
            "raw_data": raw_data,
            "normalized_data": normalized_data,
            "status": "COMPLETED",
            "confidence": 0.95
        }
        return self.create_normalization_record(record_data)

# Independent module - no imports from models.py or main.py
# Collection and Normalization layer supports all Threat Intelligence modules
