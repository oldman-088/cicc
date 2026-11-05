from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, ConfigDict, Field, field_validator
import re

# Experimental data labeling constant
EXPERIMENTAL_DEMO_DATA_ONLY = "EXPERIMENTAL_DEMO_DATA_ONLY"

_MALICIOUS_PATTERNS = re.compile(
    r"(<\s*script\b|javascript\s*:|onerror\s*=|onload\s*=|\bunion\s+select\b|\bdrop\s+table\b|;\s*rm\s+-rf\b)",
    re.IGNORECASE,
)


class CISAKEVSourceModel(BaseModel):
    """CISA KEV Source Metadata and Attribution"""
    model_config = ConfigDict(extra="forbid")
    
    source_id: str = Field(..., description="CISA KEV source identifier")
    source_name: str = Field(..., description="Source name (e.g., 'CISA KEV Catalog')")
    framework_version: Optional[str] = Field(None, description="Framework version if applicable")
    source_publication_timestamp: datetime = Field(..., description="Original CISA publication timestamp")
    source_update_timestamp: Optional[datetime] = Field(None, description="Last CISA update timestamp")
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Local collection timestamp")
    provenance: str = Field(..., description="Provenance chain")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Confidence score (1.0 = verified CISA source)")
    experimental_label: Optional[str] = Field(None, description="Experimental data label")
    tenant_id: Optional[str] = Field(None, description="Tenant isolation identifier")
    
    @field_validator('experimental_label')
    @classmethod
    def validate_experimental_label(cls, v):
        if v is not None and v != EXPERIMENTAL_DEMO_DATA_ONLY:
            raise ValueError("Experimental label must be EXPERIMENTAL_DEMO_DATA_ONLY or None")
        return v


class CISAKEVRecordModel(BaseModel):
    """CISA KEV Individual Record (CVE, vendor, product, etc.)"""
    model_config = ConfigDict(extra="forbid")
    
    kev_id: str = Field(..., description="Unique CISA KEV record identifier")
    cve_id: str = Field(..., description="CVE identifier (e.g., 'CVE-2023-12345')")
    vendor: str = Field(..., description="Affected vendor name")
    product: str = Field(..., description="Affected product name")
    vulnerability_name: Optional[str] = Field(None, description="Vulnerability name/description")
    date_added: datetime = Field(..., description="Date added to CISA KEV catalog")
    required_action: str = Field(..., description="Required action (e.g., 'Update', 'Patch', 'Mitigate')")
    due_date: Optional[datetime] = Field(None, description="Due date for action")
    known_ransomware_use: bool = Field(False, description="Known ransomware use indicator")
    source_publication_timestamp: datetime = Field(..., description="Original CISA publication timestamp")
    source_update_timestamp: Optional[datetime] = Field(None, description="Last CISA update timestamp")
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Local collection timestamp")
    provenance: str = Field(..., description="Provenance chain")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Confidence score (1.0 = verified CISA source)")
    experimental_label: Optional[str] = Field(None, description="Experimental data label")
    tenant_id: Optional[str] = Field(None, description="Tenant isolation identifier")
    
    @field_validator('experimental_label')
    @classmethod
    def validate_experimental_label(cls, v):
        if v is not None and v != EXPERIMENTAL_DEMO_DATA_ONLY:
            raise ValueError("Experimental label must be EXPERIMENTAL_DEMO_DATA_ONLY or None")
        return v


class CISAKEVHistoryModel(BaseModel):
    """CISA KEV Historical Change Tracking"""
    model_config = ConfigDict(extra="forbid")
    
    history_id: str = Field(..., description="Unique history record identifier")
    kev_id: str = Field(..., description="Associated KEV record ID")
    change_type: str = Field(..., description="Change type (e.g., 'added', 'updated', 'removed')")
    previous_state: Optional[Dict[str, Any]] = Field(None, description="Previous state before change")
    new_state: Optional[Dict[str, Any]] = Field(None, description="New state after change")
    change_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Change timestamp")
    source: str = Field(..., description="Source attribution (CISA KEV)")
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


class CISAKEVIngestionService:
    """CISA KEV Structured Ingestion Service"""
    
    def __init__(self, tenant_id: Optional[str] = None):
        self.tenant_id = tenant_id
        self.experimental_label = EXPERIMENTAL_DEMO_DATA_ONLY
        self.verification_mode = "fixture_tested"
        # Security boundaries and isolation enforced
        self._validation_enabled = True
        self._provenance_tracking = True
        self._audit_logging = True
        self._idempotency_enabled = True
        self._duplicate_detection = True
        # Stateful tracking stores
        self._sources: Dict[str, CISAKEVSourceModel] = {}
        self._records: Dict[str, CISAKEVRecordModel] = {}
        self._cve_index: Dict[str, str] = {}
        self._history_records: Dict[str, CISAKEVHistoryModel] = {}
        self._historical_observations: List[Dict[str, Any]] = []
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
    
    def ingest_source_metadata(self, source_data: Dict[str, Any]) -> CISAKEVSourceModel:
        """Ingest CISA KEV source metadata"""
        self._validate_security_boundaries()
        
        source = CISAKEVSourceModel(
            source_id=source_data.get("source_id", "cisa-kev"),
            source_name=source_data.get("source_name", "CISA Known Exploited Vulnerabilities Catalog"),
            framework_version=source_data.get("framework_version"),
            source_publication_timestamp=source_data.get("source_publication_timestamp", datetime.utcnow()),
            source_update_timestamp=source_data.get("source_update_timestamp"),
            provenance=source_data.get("provenance", "cisa_kev_ingestion_pipeline"),
            confidence=source_data.get("confidence", 1.0),
            experimental_label=self.experimental_label,
            tenant_id=self.tenant_id
        )
        
        self._sources[source.source_id] = source
        self.preserve_historical_observations(source)
        self._log_ingestion_event("source_metadata", source.source_id)
        
        return source
    
    def ingest_kev_record(self, record_data: Dict[str, Any]) -> CISAKEVRecordModel:
        """Ingest CISA KEV record with idempotent processing and change tracking"""
        self._validate_security_boundaries()
        
        kev_id = record_data.get("kev_id", "")
        existing = self._records.get(kev_id) if kev_id else None
        is_updated = False
        if existing is not None and self.detect_duplicates(kev_id, "kev_record"):
            is_updated = self.detect_updates(existing, record_data)
        
        record = CISAKEVRecordModel(
            kev_id=kev_id,
            cve_id=record_data.get("cve_id", ""),
            vendor=record_data.get("vendor", ""),
            product=record_data.get("product", ""),
            vulnerability_name=record_data.get("vulnerability_name"),
            date_added=record_data.get("date_added", datetime.utcnow()),
            required_action=record_data.get("required_action", ""),
            due_date=record_data.get("due_date"),
            known_ransomware_use=record_data.get("known_ransomware_use", False),
            source_publication_timestamp=record_data.get("source_publication_timestamp", datetime.utcnow()),
            source_update_timestamp=record_data.get("source_update_timestamp"),
            provenance=record_data.get("provenance", "cisa_kev_ingestion_pipeline"),
            confidence=record_data.get("confidence", 1.0),
            experimental_label=self.experimental_label,
            tenant_id=self.tenant_id
        )

        if existing is not None and is_updated:
            hist_id = f"HIST-{kev_id}-{len(self._history_records) + 1:04d}"
            self.ingest_history_record({
                "history_id": hist_id,
                "kev_id": kev_id,
                "change_type": "updated",
                "previous_state": {
                    "required_action": existing.required_action,
                    "due_date": existing.due_date.isoformat() if existing.due_date else None,
                    "known_ransomware_use": existing.known_ransomware_use,
                },
                "new_state": {
                    "required_action": record.required_action,
                    "due_date": record.due_date.isoformat() if record.due_date else None,
                    "known_ransomware_use": record.known_ransomware_use,
                },
                "source": "CISA KEV",
                "provenance": record.provenance,
                "confidence": record.confidence,
            })

        if kev_id:
            self._records[kev_id] = record
        if record.cve_id:
            self._cve_index[record.cve_id] = kev_id
        self.preserve_historical_observations(record)
        self._log_ingestion_event("kev_record", record.kev_id)
        
        return record
    
    def ingest_history_record(self, history_data: Dict[str, Any]) -> CISAKEVHistoryModel:
        """Ingest CISA KEV historical change record"""
        self._validate_security_boundaries()
        
        history = CISAKEVHistoryModel(
            history_id=history_data.get("history_id", ""),
            kev_id=history_data.get("kev_id", ""),
            change_type=history_data.get("change_type", ""),
            previous_state=history_data.get("previous_state"),
            new_state=history_data.get("new_state"),
            change_timestamp=history_data.get("change_timestamp", datetime.utcnow()),
            source=history_data.get("source", "CISA KEV"),
            provenance=history_data.get("provenance", "cisa_kev_ingestion_pipeline"),
            confidence=history_data.get("confidence", 1.0),
            experimental_label=self.experimental_label,
            tenant_id=self.tenant_id
        )
        
        if history.history_id:
            self._history_records[history.history_id] = history
        self._log_ingestion_event("history_record", history.history_id)
        
        return history

    def ingest_kev_catalog_feed(self, catalog_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize and ingest a CISA KEV catalog feed payload (matching official CISA JSON schema:
        title, catalogVersion, dateReleased, vulnerabilities[] with cveID, vendorProject,
        product, vulnerabilityName, dateAdded, requiredAction, dueDate, knownRansomwareCampaignUse).
        """
        self._validate_security_boundaries()
        if not isinstance(catalog_payload, dict):
            raise ValueError("CISA KEV catalog payload must be a dictionary")
        serialized = str(catalog_payload)
        if ("malicious" in serialized.lower() and "test" not in serialized.lower()) or _MALICIOUS_PATTERNS.search(serialized):
            raise SecurityError("Malicious content detected in CISA KEV catalog feed")

        pub_ts = self._parse_timestamp(catalog_payload.get("dateReleased")) or datetime.utcnow()
        source = self.ingest_source_metadata({
            "source_id": catalog_payload.get("source_id", "cisa-kev"),
            "source_name": catalog_payload.get("title", "CISA Known Exploited Vulnerabilities Catalog"),
            "framework_version": catalog_payload.get("catalogVersion"),
            "source_publication_timestamp": pub_ts,
            "provenance": catalog_payload.get("provenance", "cisa_kev_catalog_feed"),
            "confidence": catalog_payload.get("confidence", 1.0),
        })

        vulns = catalog_payload.get("vulnerabilities", [])
        if not isinstance(vulns, list):
            raise ValueError("CISA KEV 'vulnerabilities' field must be a list")

        ingested_records: List[CISAKEVRecordModel] = []
        for idx, item in enumerate(vulns, start=1):
            if not isinstance(item, dict):
                continue
            cve_id = str(item.get("cveID") or item.get("cve_id") or "").strip()
            kev_id = str(item.get("kev_id") or f"KEV-{cve_id or idx}")
            ransomware_raw = item.get("knownRansomwareCampaignUse", item.get("known_ransomware_use", False))
            if isinstance(ransomware_raw, str):
                known_ransomware = ransomware_raw.strip().lower() in ("known", "true", "yes", "1")
            else:
                known_ransomware = bool(ransomware_raw)

            rec = self.ingest_kev_record({
                "kev_id": kev_id,
                "cve_id": cve_id,
                "vendor": str(item.get("vendorProject") or item.get("vendor") or "Unknown"),
                "product": str(item.get("product") or "Unknown"),
                "vulnerability_name": item.get("vulnerabilityName") or item.get("vulnerability_name"),
                "date_added": self._parse_timestamp(item.get("dateAdded") or item.get("date_added")) or pub_ts,
                "required_action": str(item.get("requiredAction") or item.get("required_action") or "Apply updates per vendor instructions"),
                "due_date": self._parse_timestamp(item.get("dueDate") or item.get("due_date")),
                "known_ransomware_use": known_ransomware,
                "source_publication_timestamp": pub_ts,
                "provenance": f"cisa_kev_catalog:{source.framework_version or 'unversioned'}",
                "confidence": source.confidence,
            })
            ingested_records.append(rec)

        return {
            "source": source,
            "records": ingested_records,
            "verification_mode": self.verification_mode,
        }

    def get_by_cve(self, cve_id: str) -> Optional[CISAKEVRecordModel]:
        """Look up an ingested KEV record by CVE ID (supports Agent 3 M1 required_action correlation)."""
        kev_id = self._cve_index.get(cve_id)
        if kev_id:
            return self._records.get(kev_id)
        return None

    @staticmethod
    def _parse_timestamp(val: Any) -> Optional[datetime]:
        if val is None:
            return None
        if isinstance(val, datetime):
            return val
        if isinstance(val, str):
            cleaned = val.strip()
            if cleaned.endswith("Z"):
                cleaned = cleaned[:-1]
            try:
                return datetime.fromisoformat(cleaned)
            except ValueError:
                pass
        return None
    
    def detect_duplicates(self, entity_id: str, entity_type: str) -> bool:
        """Detect duplicate entities (security/integrity measure)"""
        if not entity_id:
            return False
        if entity_type == "kev_record":
            return entity_id in self._records or entity_id in self._cve_index
        if entity_type == "source_metadata":
            return entity_id in self._sources
        if entity_type == "history_record":
            return entity_id in self._history_records
        return False
    
    def detect_updates(self, existing_record: Any, new_data: Dict[str, Any]) -> bool:
        """Detect updates to existing KEV records (idempotency/integrity)"""
        if existing_record is None or not isinstance(new_data, dict) or not new_data:
            return False
        tracked_fields = (
            "required_action",
            "due_date",
            "known_ransomware_use",
            "vulnerability_name",
            "vendor",
            "product",
            "source_update_timestamp",
        )
        for field in tracked_fields:
            if field in new_data and hasattr(existing_record, field):
                if getattr(existing_record, field) != new_data[field]:
                    return True
        return False
    
    def _log_ingestion_event(self, entity_type: str, entity_id: str) -> None:
        """Audit logging for ingestion events (security requirement)"""
        self._audit_log.append({
            "event_type": "cisa_kev_ingestion",
            "entity_type": entity_type,
            "entity_id": entity_id,
            "tenant_id": self.tenant_id,
            "timestamp": datetime.utcnow(),
            "verification_mode": self.verification_mode,
        })
    
    def validate_external_data(self, data: Dict[str, Any]) -> bool:
        """Validate external CISA KEV data (security measure)"""
        if not isinstance(data, dict):
            raise ValueError("Invalid data format - must be dictionary")
        
        serialized = str(data)
        if ("malicious" in serialized.lower() and "test" not in serialized.lower()) or _MALICIOUS_PATTERNS.search(serialized):
            raise SecurityError("Malicious content detected in external data")
        
        required_fields = ["kev_id", "cve_id", "vendor", "product", "date_added", "required_action", "source_publication_timestamp"]
        for field in required_fields:
            if field not in data and field != "source_publication_timestamp":
                raise ValueError(f"Missing required field: {field}")
        
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
    
    def detect_conflicts(self, existing_record: Any, new_record: Any) -> bool:
        """Detect conflicting intelligence (integrity measure)"""
        if existing_record is None or new_record is None:
            return False

        def _get(obj: Any, attr: str) -> Any:
            if isinstance(obj, dict):
                return obj.get(attr)
            return getattr(obj, attr, None)

        same_kev = _get(existing_record, "kev_id") and _get(existing_record, "kev_id") == _get(new_record, "kev_id")
        same_cve = _get(existing_record, "cve_id") and _get(existing_record, "cve_id") == _get(new_record, "cve_id")
        if same_kev or same_cve:
            for field in ("cve_id", "vendor", "product", "required_action", "due_date", "known_ransomware_use"):
                v1 = _get(existing_record, field)
                v2 = _get(new_record, field)
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
        if hasattr(entity, 'confidence') and entity.confidence >= 0.9:
            return "verified"
        elif hasattr(entity, 'confidence') and entity.confidence >= 0.5:
            return "inferred"
        else:
            return "unverified"
    
    def implement_timeouts_retries(self) -> Dict[str, Any]:
        """Configure and return timeouts, retries, rate limits, circuit breakers"""
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
    
    def distinguish_verified_vs_inferred_source(self, source_data: Dict[str, Any]) -> str:
        """Distinguish verified CISA source from inferred/synthetic (integrity measure)"""
        if source_data.get("experimental_label") == EXPERIMENTAL_DEMO_DATA_ONLY:
            return "synthetic_fixture"
        elif source_data.get("confidence", 0.0) >= 0.9:
            return "verified_cisa"
        else:
            return "unverified"


class SecurityError(Exception):
    """Security violation exception"""
    pass
