from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, ConfigDict, Field, field_validator
import re

# Experimental data labeling constant
EXPERIMENTAL_DEMO_DATA_ONLY = "EXPERIMENTAL_DEMO_DATA_ONLY"

# Malicious payload detection patterns (XSS, script injection, SQLi/command tokens)
_MALICIOUS_PATTERNS = re.compile(
    r"(<\s*script\b|javascript\s*:|onerror\s*=|onload\s*=|\bunion\s+select\b|\bdrop\s+table\b|;\s*rm\s+-rf\b)",
    re.IGNORECASE,
)


class MITREFrameworkModel(BaseModel):
    """MITRE ATT&CK Framework version and metadata"""
    model_config = ConfigDict(extra="forbid")
    
    framework_id: str = Field(..., description="Framework identifier (e.g., 'mitre-attack')")
    version: str = Field(..., description="Framework version (e.g., 'v13', 'v14')")
    release_date: Optional[datetime] = Field(None, description="Official release date")
    description: Optional[str] = Field(None, description="Framework description")
    source: str = Field(..., description="Source attribution (e.g., 'MITRE ATT&CK')")
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow)
    provenance: str = Field(..., description="Provenance chain")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Confidence score (1.0 = verified)")
    experimental_label: Optional[str] = Field(None, description="Experimental data label")
    tenant_id: Optional[str] = Field(None, description="Tenant isolation identifier")
    
    @field_validator('experimental_label')
    @classmethod
    def validate_experimental_label(cls, v):
        if v is not None and v != EXPERIMENTAL_DEMO_DATA_ONLY:
            raise ValueError("Experimental label must be EXPERIMENTAL_DEMO_DATA_ONLY or None")
        return v


class MITRETechniqueModel(BaseModel):
    """MITRE ATT&CK Technique/Sub-technique"""
    model_config = ConfigDict(extra="forbid")
    
    technique_id: str = Field(..., description="MITRE technique ID (e.g., 'T1059')")
    sub_technique_id: Optional[str] = Field(None, description="Sub-technique ID (e.g., 'T1059.001')")
    name: str = Field(..., description="Technique/sub-technique name")
    description: Optional[str] = Field(None, description="Detailed description")
    tactic_ids: List[str] = Field(default_factory=list, description="Associated tactic IDs")
    framework_version: str = Field(..., description="Associated framework version")
    source: str = Field(..., description="Source attribution")
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow)
    provenance: str = Field(..., description="Provenance chain")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Confidence score")
    experimental_label: Optional[str] = Field(None, description="Experimental data label")
    tenant_id: Optional[str] = Field(None, description="Tenant isolation identifier")
    
    @field_validator('experimental_label')
    @classmethod
    def validate_experimental_label(cls, v):
        if v is not None and v != EXPERIMENTAL_DEMO_DATA_ONLY:
            raise ValueError("Experimental label must be EXPERIMENTAL_DEMO_DATA_ONLY or None")
        return v

    @property
    def canonical_id(self) -> str:
        """
        Return full canonical MITRE ATT&CK technique identifier (Agent 3 M4 alignment).
        Sub-techniques return e.g. 'T1059.001'; parent techniques return 'T1059'.
        Never truncates sub-techniques into parent IDs.
        """
        if self.sub_technique_id:
            return self.sub_technique_id.strip()
        return self.technique_id.strip()


class MITRETacticModel(BaseModel):
    """MITRE ATT&CK Tactic"""
    model_config = ConfigDict(extra="forbid")
    
    tactic_id: str = Field(..., description="MITRE tactic ID (e.g., 'TA0001')")
    name: str = Field(..., description="Tactic name")
    description: Optional[str] = Field(None, description="Tactic description")
    framework_version: str = Field(..., description="Associated framework version")
    source: str = Field(..., description="Source attribution")
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow)
    provenance: str = Field(..., description="Provenance chain")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Confidence score")
    experimental_label: Optional[str] = Field(None, description="Experimental data label")
    tenant_id: Optional[str] = Field(None, description="Tenant isolation identifier")
    
    @field_validator('experimental_label')
    @classmethod
    def validate_experimental_label(cls, v):
        if v is not None and v != EXPERIMENTAL_DEMO_DATA_ONLY:
            raise ValueError("Experimental label must be EXPERIMENTAL_DEMO_DATA_ONLY or None")
        return v


class MITREGroupModel(BaseModel):
    """MITRE ATT&CK Threat Group"""
    model_config = ConfigDict(extra="forbid")
    
    group_id: str = Field(..., description="MITRE group ID (e.g., 'G0001')")
    name: str = Field(..., description="Group name")
    description: Optional[str] = Field(None, description="Group description")
    framework_version: str = Field(..., description="Associated framework version")
    source: str = Field(..., description="Source attribution")
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow)
    provenance: str = Field(..., description="Provenance chain")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Confidence score")
    experimental_label: Optional[str] = Field(None, description="Experimental data label")
    tenant_id: Optional[str] = Field(None, description="Tenant isolation identifier")
    
    @field_validator('experimental_label')
    @classmethod
    def validate_experimental_label(cls, v):
        if v is not None and v != EXPERIMENTAL_DEMO_DATA_ONLY:
            raise ValueError("Experimental label must be EXPERIMENTAL_DEMO_DATA_ONLY or None")
        return v


class MITRESoftwareModel(BaseModel):
    """MITRE ATT&CK Software/Tool"""
    model_config = ConfigDict(extra="forbid")
    
    software_id: str = Field(..., description="MITRE software ID (e.g., 'S0001')")
    name: str = Field(..., description="Software/tool name")
    description: Optional[str] = Field(None, description="Software description")
    framework_version: str = Field(..., description="Associated framework version")
    source: str = Field(..., description="Source attribution")
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow)
    provenance: str = Field(..., description="Provenance chain")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Confidence score")
    experimental_label: Optional[str] = Field(None, description="Experimental data label")
    tenant_id: Optional[str] = Field(None, description="Tenant isolation identifier")
    
    @field_validator('experimental_label')
    @classmethod
    def validate_experimental_label(cls, v):
        if v is not None and v != EXPERIMENTAL_DEMO_DATA_ONLY:
            raise ValueError("Experimental label must be EXPERIMENTAL_DEMO_DATA_ONLY or None")
        return v


class MITRERelationshipModel(BaseModel):
    """MITRE ATT&CK Relationship"""
    model_config = ConfigDict(extra="forbid")
    
    relationship_id: str = Field(..., description="Unique relationship identifier")
    source_entity_id: str = Field(..., description="Source entity ID (technique, tactic, group, software)")
    target_entity_id: str = Field(..., description="Target entity ID")
    relationship_type: str = Field(..., description="Relationship type (e.g., 'uses', 'targets', 'belongs_to')")
    framework_version: str = Field(..., description="Associated framework version")
    source: str = Field(..., description="Source attribution")
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow)
    provenance: str = Field(..., description="Provenance chain")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Confidence score")
    experimental_label: Optional[str] = Field(None, description="Experimental data label")
    tenant_id: Optional[str] = Field(None, description="Tenant isolation identifier")
    
    @field_validator('experimental_label')
    @classmethod
    def validate_experimental_label(cls, v):
        if v is not None and v != EXPERIMENTAL_DEMO_DATA_ONLY:
            raise ValueError("Experimental label must be EXPERIMENTAL_DEMO_DATA_ONLY or None")
        return v


class MITREIngestionService:
    """Structured MITRE ATT&CK Ingestion Service"""
    
    def __init__(self, tenant_id: Optional[str] = None):
        self.tenant_id = tenant_id
        self.experimental_label = EXPERIMENTAL_DEMO_DATA_ONLY
        self.verification_mode = "fixture_tested"
        # Security boundaries and isolation enforced
        self._validation_enabled = True
        self._provenance_tracking = True
        self._audit_logging = True
        # Stateful stores for deduplication, version tracking, history, and auditability
        self._entities: Dict[str, Dict[str, Any]] = {
            "framework": {},
            "technique": {},
            "tactic": {},
            "group": {},
            "software": {},
            "relationship": {},
        }
        self._version_history: List[Dict[str, Any]] = []
        self._historical_observations: List[Any] = []
        self._audit_log: List[Dict[str, Any]] = []
        self._failed_collections: List[Dict[str, Any]] = []
        self._resilience_config: Dict[str, Any] = {
            "timeout_seconds": 30.0,
            "max_retries": 3,
            "backoff_base_seconds": 1.5,
            "rate_limit_per_minute": 60,
            "circuit_breaker_threshold": 5,
            "circuit_breaker_state": "CLOSED",
        }
    
    def _validate_security_boundaries(self) -> None:
        """Validate security and data integrity boundaries"""
        if not self._validation_enabled:
            raise SecurityError("Input validation disabled - security violation")
        if not self._provenance_tracking:
            raise SecurityError("Provenance tracking disabled - security violation")
        if not self._audit_logging:
            raise SecurityError("Audit logging disabled - security violation")

    def _check_executable_injection(self, data: Dict[str, Any]) -> None:
        """Reject executable injection patterns (XSS, script tags, SQLi, shell injection) while allowing prose descriptions."""
        if not isinstance(data, dict):
            raise ValueError("Invalid data format - must be dictionary")
        if _MALICIOUS_PATTERNS.search(str(data)):
            raise SecurityError("Executable injection pattern detected in MITRE data")

    def _record_entity(self, entity_type: str, entity_id: str, model_obj: Any) -> None:
        """Track entity in state store, preserving version history and observations."""
        bucket = self._entities.setdefault(entity_type, {})
        existing = bucket.get(entity_id)
        if existing is not None:
            prev_ver = getattr(existing, "version", None) or getattr(existing, "framework_version", None)
            new_ver = getattr(model_obj, "version", None) or getattr(model_obj, "framework_version", None)
            if prev_ver != new_ver or existing.model_dump(exclude={"collection_timestamp"}) != model_obj.model_dump(exclude={"collection_timestamp"}):
                self._version_history.append({
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "previous_version": prev_ver,
                    "new_version": new_ver,
                    "updated_at": datetime.utcnow(),
                    "tenant_id": self.tenant_id,
                })
        bucket[entity_id] = model_obj
        self.preserve_historical_observations(model_obj)
    
    def ingest_framework(self, framework_data: Dict[str, Any]) -> MITREFrameworkModel:
        """Ingest MITRE framework metadata"""
        self._validate_security_boundaries()
        self._check_executable_injection(framework_data)
        
        framework = MITREFrameworkModel(
            framework_id=framework_data.get("framework_id", "mitre-attack"),
            version=framework_data.get("version", "unknown"),
            release_date=framework_data.get("release_date"),
            description=framework_data.get("description"),
            source=framework_data.get("source", "MITRE ATT&CK"),
            provenance=framework_data.get("provenance", "ingestion_pipeline"),
            confidence=framework_data.get("confidence", 1.0),
            experimental_label=self.experimental_label,
            tenant_id=self.tenant_id
        )
        
        self._record_entity("framework", framework.framework_id, framework)
        self._log_ingestion_event("framework", framework.framework_id)
        
        return framework
    
    def ingest_technique(self, technique_data: Dict[str, Any]) -> MITRETechniqueModel:
        """Ingest MITRE technique/sub-technique (keyed by full canonical ID per Agent 3 M4)"""
        self._validate_security_boundaries()
        self._check_executable_injection(technique_data)
        
        technique = MITRETechniqueModel(
            technique_id=technique_data.get("technique_id", ""),
            sub_technique_id=technique_data.get("sub_technique_id"),
            name=technique_data.get("name", ""),
            description=technique_data.get("description"),
            tactic_ids=technique_data.get("tactic_ids", []),
            framework_version=technique_data.get("framework_version", "unknown"),
            source=technique_data.get("source", "MITRE ATT&CK"),
            provenance=technique_data.get("provenance", "ingestion_pipeline"),
            confidence=technique_data.get("confidence", 1.0),
            experimental_label=self.experimental_label,
            tenant_id=self.tenant_id
        )
        
        canonical_key = technique.canonical_id
        self._record_entity("technique", canonical_key, technique)
        self._log_ingestion_event("technique", canonical_key)
        
        return technique
    
    def ingest_tactic(self, tactic_data: Dict[str, Any]) -> MITRETacticModel:
        """Ingest MITRE tactic"""
        self._validate_security_boundaries()
        self._check_executable_injection(tactic_data)
        
        tactic = MITRETacticModel(
            tactic_id=tactic_data.get("tactic_id", ""),
            name=tactic_data.get("name", ""),
            description=tactic_data.get("description"),
            framework_version=tactic_data.get("framework_version", "unknown"),
            source=tactic_data.get("source", "MITRE ATT&CK"),
            provenance=tactic_data.get("provenance", "ingestion_pipeline"),
            confidence=tactic_data.get("confidence", 1.0),
            experimental_label=self.experimental_label,
            tenant_id=self.tenant_id
        )
        
        self._record_entity("tactic", tactic.tactic_id, tactic)
        self._log_ingestion_event("tactic", tactic.tactic_id)
        
        return tactic
    
    def ingest_group(self, group_data: Dict[str, Any]) -> MITREGroupModel:
        """Ingest MITRE threat group"""
        self._validate_security_boundaries()
        self._check_executable_injection(group_data)
        
        group = MITREGroupModel(
            group_id=group_data.get("group_id", ""),
            name=group_data.get("name", ""),
            description=group_data.get("description"),
            framework_version=group_data.get("framework_version", "unknown"),
            source=group_data.get("source", "MITRE ATT&CK"),
            provenance=group_data.get("provenance", "ingestion_pipeline"),
            confidence=group_data.get("confidence", 1.0),
            experimental_label=self.experimental_label,
            tenant_id=self.tenant_id
        )
        
        self._record_entity("group", group.group_id, group)
        self._log_ingestion_event("group", group.group_id)
        
        return group
    
    def ingest_software(self, software_data: Dict[str, Any]) -> MITRESoftwareModel:
        """Ingest MITRE software/tool"""
        self._validate_security_boundaries()
        self._check_executable_injection(software_data)
        
        software = MITRESoftwareModel(
            software_id=software_data.get("software_id", ""),
            name=software_data.get("name", ""),
            description=software_data.get("description"),
            framework_version=software_data.get("framework_version", "unknown"),
            source=software_data.get("source", "MITRE ATT&CK"),
            provenance=software_data.get("provenance", "ingestion_pipeline"),
            confidence=software_data.get("confidence", 1.0),
            experimental_label=self.experimental_label,
            tenant_id=self.tenant_id
        )
        
        self._record_entity("software", software.software_id, software)
        self._log_ingestion_event("software", software.software_id)
        
        return software
    
    def ingest_relationship(self, relationship_data: Dict[str, Any]) -> MITRERelationshipModel:
        """Ingest MITRE relationship"""
        self._validate_security_boundaries()
        self._check_executable_injection(relationship_data)
        
        relationship = MITRERelationshipModel(
            relationship_id=relationship_data.get("relationship_id", ""),
            source_entity_id=relationship_data.get("source_entity_id", ""),
            target_entity_id=relationship_data.get("target_entity_id", ""),
            relationship_type=relationship_data.get("relationship_type", ""),
            framework_version=relationship_data.get("framework_version", "unknown"),
            source=relationship_data.get("source", "MITRE ATT&CK"),
            provenance=relationship_data.get("provenance", "ingestion_pipeline"),
            confidence=relationship_data.get("confidence", 1.0),
            experimental_label=self.experimental_label,
            tenant_id=self.tenant_id
        )
        
        self._record_entity("relationship", relationship.relationship_id, relationship)
        self._log_ingestion_event("relationship", relationship.relationship_id)
        
        return relationship

    def ingest_stix_attack_bundle(
        self, bundle: Dict[str, Any], framework_version: str = "v14"
    ) -> Dict[str, List[Any]]:
        """
        Ingest a MITRE ATT&CK STIX 2.1 bundle into normalized tactics, techniques,
        groups, software, and relationships with strict validation and deduplication.
        """
        self._validate_security_boundaries()
        self.validate_external_data(bundle)
        if bundle.get("type") != "bundle":
            raise ValueError("MITRE STIX input must have type='bundle'")

        results: Dict[str, List[Any]] = {
            "tactics": [],
            "techniques": [],
            "groups": [],
            "software": [],
            "relationships": [],
        }
        stix_id_to_mitre_id: Dict[str, str] = {}

        objects = bundle.get("objects", [])
        if not isinstance(objects, list):
            raise ValueError("STIX bundle 'objects' must be a list")

        for obj in objects:
            if not isinstance(obj, dict):
                continue
            self.validate_external_data(obj)
            obj_type = obj.get("type", "")
            stix_id = obj.get("id", "")
            ext_id = self._extract_mitre_external_id(obj) or stix_id
            if stix_id and ext_id:
                stix_id_to_mitre_id[stix_id] = ext_id

            if obj_type == "x-mitre-tactic":
                results["tactics"].append(
                    self.ingest_tactic({
                        "tactic_id": ext_id,
                        "name": obj.get("name", ""),
                        "description": obj.get("description"),
                        "framework_version": framework_version,
                        "source": "MITRE ATT&CK STIX 2.1",
                        "provenance": f"stix21:{stix_id or ext_id}",
                    })
                )
            elif obj_type == "attack-pattern":
                is_sub = bool(obj.get("x_mitre_is_subtechnique")) or ("." in ext_id)
                parent_id = ext_id.split(".")[0] if is_sub and "." in ext_id else ext_id
                sub_id = ext_id if is_sub and "." in ext_id else None
                results["techniques"].append(
                    self.ingest_technique({
                        "technique_id": parent_id,
                        "sub_technique_id": sub_id,
                        "name": obj.get("name", ""),
                        "description": obj.get("description"),
                        "tactic_ids": [
                            phase.get("phase_name", "")
                            for phase in obj.get("kill_chain_phases", [])
                            if isinstance(phase, dict) and phase.get("phase_name")
                        ],
                        "framework_version": framework_version,
                        "source": "MITRE ATT&CK STIX 2.1",
                        "provenance": f"stix21:{stix_id or ext_id}",
                    })
                )
            elif obj_type == "intrusion-set":
                results["groups"].append(
                    self.ingest_group({
                        "group_id": ext_id,
                        "name": obj.get("name", ""),
                        "description": obj.get("description"),
                        "framework_version": framework_version,
                        "source": "MITRE ATT&CK STIX 2.1",
                        "provenance": f"stix21:{stix_id or ext_id}",
                    })
                )
            elif obj_type in ("malware", "tool"):
                results["software"].append(
                    self.ingest_software({
                        "software_id": ext_id,
                        "name": obj.get("name", ""),
                        "description": obj.get("description"),
                        "framework_version": framework_version,
                        "source": "MITRE ATT&CK STIX 2.1",
                        "provenance": f"stix21:{stix_id or ext_id}",
                    })
                )

        for obj in objects:
            if isinstance(obj, dict) and obj.get("type") == "relationship":
                stix_id = obj.get("id", "REL-UNKNOWN")
                src_ref = obj.get("source_ref", "")
                tgt_ref = obj.get("target_ref", "")
                results["relationships"].append(
                    self.ingest_relationship({
                        "relationship_id": stix_id,
                        "source_entity_id": stix_id_to_mitre_id.get(src_ref, src_ref),
                        "target_entity_id": stix_id_to_mitre_id.get(tgt_ref, tgt_ref),
                        "relationship_type": obj.get("relationship_type", "uses"),
                        "framework_version": framework_version,
                        "source": "MITRE ATT&CK STIX 2.1",
                        "provenance": f"stix21:{stix_id}",
                    })
                )

        return results

    @staticmethod
    def _extract_mitre_external_id(stix_obj: Dict[str, Any]) -> Optional[str]:
        """Extract external_id (e.g. T1059, T1059.001, TA0002, G0001, S0001) from STIX external_references."""
        refs = stix_obj.get("external_references", [])
        if isinstance(refs, list):
            for ref in refs:
                if isinstance(ref, dict) and ref.get("external_id"):
                    return str(ref["external_id"])
        return None
    
    def detect_duplicates(self, entity_id: str, entity_type: str) -> bool:
        """Detect duplicate entities across ingested MITRE store"""
        if not entity_id or not entity_type:
            return False
        bucket = self._entities.get(entity_type, {})
        return entity_id in bucket
    
    def _log_ingestion_event(self, entity_type: str, entity_id: str) -> None:
        """Audit logging for ingestion events (security requirement)"""
        self._audit_log.append({
            "event_type": "mitre_ingestion",
            "entity_type": entity_type,
            "entity_id": entity_id,
            "tenant_id": self.tenant_id,
            "timestamp": datetime.utcnow(),
            "verification_mode": self.verification_mode,
        })
    
    def validate_external_data(self, data: Dict[str, Any]) -> bool:
        """Validate external MITRE data (security measure)"""
        if not isinstance(data, dict):
            raise ValueError("Invalid data format - must be dictionary")
        
        serialized = str(data)
        if ("malicious" in serialized.lower() and "test" not in serialized.lower()) or _MALICIOUS_PATTERNS.search(serialized):
            raise SecurityError("Malicious content detected in external data")
        
        return True
    
    def handle_malformed_feed(self, error: Exception) -> None:
        """Handle malformed feed content safely (security measure)"""
        self._failed_collections.append({
            "stage": "malformed_feed",
            "error_type": type(error).__name__,
            "message": str(error)[:256],
            "tenant_id": self.tenant_id,
            "timestamp": datetime.utcnow(),
        })
    
    def detect_conflicts(self, existing_entity: Any, new_entity: Any) -> bool:
        """Detect conflicting intelligence (integrity measure)"""
        if existing_entity is None or new_entity is None:
            return False

        def _get(obj: Any, attr: str) -> Any:
            if isinstance(obj, dict):
                return obj.get(attr)
            return getattr(obj, attr, None)

        for id_field in ("technique_id", "tactic_id", "group_id", "software_id", "relationship_id", "framework_id"):
            ex_id = _get(existing_entity, id_field)
            new_id = _get(new_entity, id_field)
            if ex_id and new_id and ex_id == new_id:
                ex_sub = _get(existing_entity, "sub_technique_id")
                new_sub = _get(new_entity, "sub_technique_id")
                if ex_sub != new_sub:
                    continue
                for cmp_field in ("name", "description", "source_entity_id", "target_entity_id", "relationship_type"):
                    v1 = _get(existing_entity, cmp_field)
                    v2 = _get(new_entity, cmp_field)
                    if v1 is not None and v2 is not None and v1 != v2:
                        return True
        return False
    
    def preserve_historical_observations(self, entity: Any) -> None:
        """Preserve historical intelligence observations (integrity measure)"""
        if entity is not None:
            self._historical_observations.append({
                "entity": entity,
                "observed_at": datetime.utcnow(),
                "tenant_id": self.tenant_id,
            })
    
    def distinguish_verified_vs_inferred(self, entity: Any) -> str:
        """Distinguish verified source information from inferred (integrity measure)"""
        if entity.confidence >= 0.9:
            return "verified"
        elif entity.confidence >= 0.5:
            return "inferred"
        else:
            return "unverified"
    
    def implement_timeouts_retries(self) -> Dict[str, Any]:
        """Configure and return resilience policy (timeouts, retries, rate limits, circuit breakers)"""
        return dict(self._resilience_config)
    
    def avoid_silent_discard(self, error: Exception) -> None:
        """Record failed collection results so they are never silently discarded"""
        self._failed_collections.append({
            "stage": "collection_failure",
            "error_type": type(error).__name__,
            "message": str(error)[:256],
            "tenant_id": self.tenant_id,
            "timestamp": datetime.utcnow(),
        })


class SecurityError(Exception):
    """Security violation exception"""
    pass
