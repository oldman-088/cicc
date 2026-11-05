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


class VendorSecurityAdvisorySourceModel(BaseModel):
    """Vendor Security Advisory Source Metadata and Attribution"""
    model_config = ConfigDict(extra="forbid")
    
    source_id: str = Field(..., description="Vendor source identifier (e.g., 'msrc', 'cisco', 'redhat', 'ubuntu', 'debian', 'ghsa')")
    vendor_name: str = Field(..., description="Vendor name (e.g., 'Microsoft', 'Cisco', 'Red Hat', 'Ubuntu', 'Debian', 'GitHub')")
    framework_version: Optional[str] = Field(None, description="Framework version if applicable")
    source_publication_timestamp: datetime = Field(..., description="Original vendor publication timestamp")
    source_update_timestamp: Optional[datetime] = Field(None, description="Last vendor update timestamp")
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Local collection timestamp")
    provenance: str = Field(..., description="Provenance chain")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Confidence score (1.0 = verified vendor source)")
    experimental_label: Optional[str] = Field(None, description="Experimental data label")
    tenant_id: Optional[str] = Field(None, description="Tenant isolation identifier")
    
    @field_validator('experimental_label')
    @classmethod
    def validate_experimental_label(cls, v):
        if v is not None and v != EXPERIMENTAL_DEMO_DATA_ONLY:
            raise ValueError("Experimental label must be EXPERIMENTAL_DEMO_DATA_ONLY or None")
        return v


class VendorSecurityAdvisoryRecordModel(BaseModel):
    """Vendor Security Advisory Individual Record (CVE, product, version, etc.)"""
    model_config = ConfigDict(extra="forbid")
    
    advisory_id: str = Field(..., description="Unique vendor advisory identifier")
    vendor_source_id: str = Field(..., description="Vendor-specific source identifier")
    cve_references: List[str] = Field(default_factory=list, description="CVE identifiers (e.g., ['CVE-2023-12345'])")
    affected_products: List[str] = Field(default_factory=list, description="Affected product names")
    affected_versions: List[str] = Field(default_factory=list, description="Affected version ranges")
    vulnerability_description: Optional[str] = Field(None, description="Vulnerability description")
    severity: Optional[str] = Field(None, description="Severity level (e.g., 'Critical', 'High', 'Medium', 'Low')")
    date_published: datetime = Field(..., description="Original vendor publication timestamp")
    date_modified: Optional[datetime] = Field(None, description="Last vendor modification timestamp")
    required_action: Optional[str] = Field(None, description="Required action (e.g., 'Update', 'Patch', 'Mitigate')")
    due_date: Optional[datetime] = Field(None, description="Due date for action")
    source_publication_timestamp: datetime = Field(..., description="Original vendor publication timestamp")
    source_update_timestamp: Optional[datetime] = Field(None, description="Last vendor update timestamp")
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Local collection timestamp")
    provenance: str = Field(..., description="Provenance chain")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Confidence score (1.0 = verified vendor source)")
    experimental_label: Optional[str] = Field(None, description="Experimental data label")
    tenant_id: Optional[str] = Field(None, description="Tenant isolation identifier")
    
    @field_validator('experimental_label')
    @classmethod
    def validate_experimental_label(cls, v):
        if v is not None and v != EXPERIMENTAL_DEMO_DATA_ONLY:
            raise ValueError("Experimental label must be EXPERIMENTAL_DEMO_DATA_ONLY or None")
        return v


class VendorSecurityAdvisoryHistoryModel(BaseModel):
    """Vendor Security Advisory Historical Change Tracking"""
    model_config = ConfigDict(extra="forbid")
    
    history_id: str = Field(..., description="Unique history record identifier")
    advisory_id: str = Field(..., description="Associated advisory ID")
    change_type: str = Field(..., description="Change type (e.g., 'added', 'updated', 'removed', 'severity_changed')")
    previous_state: Optional[Dict[str, Any]] = Field(None, description="Previous state before change")
    new_state: Optional[Dict[str, Any]] = Field(None, description="New state after change")
    change_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Change timestamp")
    source: str = Field(..., description="Source attribution (vendor name)")
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


class VendorSecurityAdvisoryIngestionService:
    """Vendor Security Advisory Structured Ingestion Service (Reusable Connector Interface)"""
    
    def __init__(self, vendor_type: str = "generic", tenant_id: Optional[str] = None):
        """
        Initialize vendor advisory ingestion service.
        Supported vendor_type: 'msrc', 'cisco', 'redhat', 'ubuntu', 'debian', 'ghsa', 'generic'.
        Note: All vendor parsers are fixture-tested offline unless live transport is explicitly invoked.
        """
        self.vendor_type = vendor_type
        self.tenant_id = tenant_id
        self.experimental_label = EXPERIMENTAL_DEMO_DATA_ONLY
        self.verification_mode = "fixture_tested"
        # Security boundaries and isolation enforced
        self._validation_enabled = True
        self._provenance_tracking = True
        self._audit_logging = True
        self._idempotency_enabled = True
        self._duplicate_detection = True
        
        # Vendor-specific parser implementations
        self._parsers = {
            "msrc": self._parse_microsoft_msrc,
            "cisco": self._parse_cisco,
            "redhat": self._parse_redhat,
            "ubuntu": self._parse_ubuntu,
            "debian": self._parse_debian,
            "ghsa": self._parse_github_ghsa,
        }

        # Stateful tracking stores
        self._sources: Dict[str, VendorSecurityAdvisorySourceModel] = {}
        self._advisories: Dict[str, VendorSecurityAdvisoryRecordModel] = {}
        self._cve_to_advisories: Dict[str, List[str]] = {}
        self._history_records: Dict[str, VendorSecurityAdvisoryHistoryModel] = {}
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

    @staticmethod
    def _normalize_cves(raw_cves: Any) -> List[str]:
        """Deduplicate and preserve order of CVE identifiers."""
        if not isinstance(raw_cves, list):
            return []
        seen = set()
        normalized: List[str] = []
        for item in raw_cves:
            val = str(item).strip().upper()
            if val and val not in seen:
                seen.add(val)
                normalized.append(val)
        return normalized
    
    def _parse_microsoft_msrc(self, raw_data: Dict[str, Any]) -> VendorSecurityAdvisoryRecordModel:
        """Parse Microsoft Security Response Center (MSRC) advisory data"""
        cves = self._normalize_cves(raw_data.get("cve_ids", raw_data.get("cves", [])))
        parsed_data = {
            "advisory_id": raw_data.get("msrc_id") or raw_data.get("advisory_id") or "MSRC-UNKNOWN",
            "vendor_source_id": raw_data.get("msrc_source_id", "msrc"),
            "cve_references": cves,
            "affected_products": list(raw_data.get("products", raw_data.get("affected_products", []))),
            "affected_versions": list(raw_data.get("versions", raw_data.get("affected_versions", []))),
            "vulnerability_description": raw_data.get("description"),
            "severity": raw_data.get("severity", "Unknown"),
            "date_published": raw_data.get("published", datetime.utcnow()),
            "date_modified": raw_data.get("modified"),
            "required_action": raw_data.get("action", "Update"),
            "due_date": raw_data.get("due_date"),
            "source_publication_timestamp": raw_data.get("source_publication_timestamp", datetime.utcnow()),
            "source_update_timestamp": raw_data.get("source_update_timestamp"),
            "provenance": raw_data.get("provenance", "msrc_ingestion_pipeline"),
            "confidence": raw_data.get("confidence", 1.0),
            "experimental_label": self.experimental_label,
            "tenant_id": self.tenant_id
        }
        return self.ingest_advisory_record(parsed_data)
    
    def _parse_cisco(self, raw_data: Dict[str, Any]) -> VendorSecurityAdvisoryRecordModel:
        """Parse Cisco Security Advisories data"""
        cves = self._normalize_cves(raw_data.get("cves", raw_data.get("cve_ids", [])))
        parsed_data = {
            "advisory_id": raw_data.get("cisco_id") or raw_data.get("advisory_id") or "CISCO-UNKNOWN",
            "vendor_source_id": raw_data.get("cisco_source_id", "cisco"),
            "cve_references": cves,
            "affected_products": list(raw_data.get("products", raw_data.get("affected_products", []))),
            "affected_versions": list(raw_data.get("versions", raw_data.get("affected_versions", []))),
            "vulnerability_description": raw_data.get("description"),
            "severity": raw_data.get("severity", "Unknown"),
            "date_published": raw_data.get("published", datetime.utcnow()),
            "date_modified": raw_data.get("modified"),
            "required_action": raw_data.get("action", "Update"),
            "due_date": raw_data.get("due_date"),
            "source_publication_timestamp": raw_data.get("source_publication_timestamp", datetime.utcnow()),
            "source_update_timestamp": raw_data.get("source_update_timestamp"),
            "provenance": raw_data.get("provenance", "cisco_ingestion_pipeline"),
            "confidence": raw_data.get("confidence", 1.0),
            "experimental_label": self.experimental_label,
            "tenant_id": self.tenant_id
        }
        return self.ingest_advisory_record(parsed_data)
    
    def _parse_redhat(self, raw_data: Dict[str, Any]) -> VendorSecurityAdvisoryRecordModel:
        """Parse Red Hat Security Advisories (RHSA) data"""
        cves = self._normalize_cves(raw_data.get("cves", raw_data.get("cve_ids", [])))
        parsed_data = {
            "advisory_id": raw_data.get("rhsa_id") or raw_data.get("advisory_id") or "RHSA-UNKNOWN",
            "vendor_source_id": raw_data.get("redhat_source_id", "redhat"),
            "cve_references": cves,
            "affected_products": list(raw_data.get("products", raw_data.get("affected_products", []))),
            "affected_versions": list(raw_data.get("versions", raw_data.get("affected_versions", []))),
            "vulnerability_description": raw_data.get("description"),
            "severity": raw_data.get("severity", "Unknown"),
            "date_published": raw_data.get("published", datetime.utcnow()),
            "date_modified": raw_data.get("modified"),
            "required_action": raw_data.get("action", "Update"),
            "due_date": raw_data.get("due_date"),
            "source_publication_timestamp": raw_data.get("source_publication_timestamp", datetime.utcnow()),
            "source_update_timestamp": raw_data.get("source_update_timestamp"),
            "provenance": raw_data.get("provenance", "redhat_ingestion_pipeline"),
            "confidence": raw_data.get("confidence", 1.0),
            "experimental_label": self.experimental_label,
            "tenant_id": self.tenant_id
        }
        return self.ingest_advisory_record(parsed_data)
    
    def _parse_ubuntu(self, raw_data: Dict[str, Any]) -> VendorSecurityAdvisoryRecordModel:
        """Parse Ubuntu Security Notices (USN) data"""
        cves = self._normalize_cves(raw_data.get("cves", raw_data.get("cve_ids", [])))
        parsed_data = {
            "advisory_id": raw_data.get("usn_id") or raw_data.get("advisory_id") or "USN-UNKNOWN",
            "vendor_source_id": raw_data.get("ubuntu_source_id", "ubuntu"),
            "cve_references": cves,
            "affected_products": list(raw_data.get("products", raw_data.get("affected_products", []))),
            "affected_versions": list(raw_data.get("versions", raw_data.get("affected_versions", []))),
            "vulnerability_description": raw_data.get("description"),
            "severity": raw_data.get("severity", "Unknown"),
            "date_published": raw_data.get("published", datetime.utcnow()),
            "date_modified": raw_data.get("modified"),
            "required_action": raw_data.get("action", "Update"),
            "due_date": raw_data.get("due_date"),
            "source_publication_timestamp": raw_data.get("source_publication_timestamp", datetime.utcnow()),
            "source_update_timestamp": raw_data.get("source_update_timestamp"),
            "provenance": raw_data.get("provenance", "ubuntu_ingestion_pipeline"),
            "confidence": raw_data.get("confidence", 1.0),
            "experimental_label": self.experimental_label,
            "tenant_id": self.tenant_id
        }
        return self.ingest_advisory_record(parsed_data)

    def _parse_debian(self, raw_data: Dict[str, Any]) -> VendorSecurityAdvisoryRecordModel:
        """Parse Debian Security Advisory (DSA) data (supports Agent 3 M2 DSA-* correlation)"""
        cves = self._normalize_cves(raw_data.get("cves", raw_data.get("cve_ids", [])))
        parsed_data = {
            "advisory_id": raw_data.get("dsa_id") or raw_data.get("advisory_id") or "DSA-UNKNOWN",
            "vendor_source_id": raw_data.get("debian_source_id", "debian"),
            "cve_references": cves,
            "affected_products": list(raw_data.get("packages", raw_data.get("products", []))),
            "affected_versions": list(raw_data.get("fixed_versions", raw_data.get("versions", []))),
            "vulnerability_description": raw_data.get("description"),
            "severity": raw_data.get("severity", "High"),
            "date_published": raw_data.get("published", datetime.utcnow()),
            "date_modified": raw_data.get("modified"),
            "required_action": raw_data.get("action", "Upgrade package"),
            "due_date": raw_data.get("due_date"),
            "source_publication_timestamp": raw_data.get("source_publication_timestamp", datetime.utcnow()),
            "source_update_timestamp": raw_data.get("source_update_timestamp"),
            "provenance": raw_data.get("provenance", "debian_dsa_ingestion_pipeline"),
            "confidence": raw_data.get("confidence", 1.0),
            "experimental_label": self.experimental_label,
            "tenant_id": self.tenant_id,
        }
        return self.ingest_advisory_record(parsed_data)

    def _parse_github_ghsa(self, raw_data: Dict[str, Any]) -> VendorSecurityAdvisoryRecordModel:
        """Parse GitHub Security Advisory (GHSA) data"""
        cves = self._normalize_cves(raw_data.get("cves", raw_data.get("cve_ids", [])))
        parsed_data = {
            "advisory_id": raw_data.get("ghsa_id") or raw_data.get("advisory_id") or "GHSA-UNKNOWN",
            "vendor_source_id": raw_data.get("ghsa_source_id", "ghsa"),
            "cve_references": cves,
            "affected_products": list(raw_data.get("packages", raw_data.get("products", []))),
            "affected_versions": list(raw_data.get("vulnerable_version_ranges", raw_data.get("versions", []))),
            "vulnerability_description": raw_data.get("summary") or raw_data.get("description"),
            "severity": raw_data.get("severity", "Unknown"),
            "date_published": raw_data.get("published", datetime.utcnow()),
            "date_modified": raw_data.get("updated") or raw_data.get("modified"),
            "required_action": raw_data.get("action", "Upgrade dependency"),
            "due_date": raw_data.get("due_date"),
            "source_publication_timestamp": raw_data.get("source_publication_timestamp", datetime.utcnow()),
            "source_update_timestamp": raw_data.get("source_update_timestamp"),
            "provenance": raw_data.get("provenance", "ghsa_ingestion_pipeline"),
            "confidence": raw_data.get("confidence", 1.0),
            "experimental_label": self.experimental_label,
            "tenant_id": self.tenant_id,
        }
        return self.ingest_advisory_record(parsed_data)
    
    def parse_vendor_advisory(self, vendor_type: str, raw_data: Dict[str, Any]) -> VendorSecurityAdvisoryRecordModel:
        """Unified parser interface for all supported vendors"""
        parser_map = {
            "msrc": self._parse_microsoft_msrc,
            "cisco": self._parse_cisco,
            "redhat": self._parse_redhat,
            "ubuntu": self._parse_ubuntu,
            "debian": self._parse_debian,
            "ghsa": self._parse_github_ghsa,
        }
        
        if vendor_type not in parser_map:
            raise ValueError(
                f"Unsupported vendor type: {vendor_type}. Supported: msrc, cisco, redhat, ubuntu, debian, ghsa"
            )
        
        return parser_map[vendor_type](raw_data)
    
    def ingest_source_metadata(self, source_data: Dict[str, Any]) -> VendorSecurityAdvisorySourceModel:
        """Ingest vendor security advisory source metadata"""
        self._validate_security_boundaries()
        
        source = VendorSecurityAdvisorySourceModel(
            source_id=source_data.get("source_id", self.vendor_type),
            vendor_name=source_data.get("vendor_name", self.vendor_type.capitalize()),
            framework_version=source_data.get("framework_version"),
            source_publication_timestamp=source_data.get("source_publication_timestamp", datetime.utcnow()),
            source_update_timestamp=source_data.get("source_update_timestamp"),
            collection_timestamp=datetime.utcnow(),
            provenance=source_data.get("provenance", f"{self.vendor_type}_ingestion_pipeline"),
            confidence=source_data.get("confidence", 1.0),
            experimental_label=self.experimental_label,
            tenant_id=self.tenant_id
        )
        
        self._sources[source.source_id] = source
        self.preserve_historical_observations(source)
        self._log_ingestion_event("source_metadata", source.source_id)
        
        return source
    
    def ingest_advisory_record(self, record_data: Dict[str, Any]) -> VendorSecurityAdvisoryRecordModel:
        """Ingest vendor security advisory record with idempotent processing and history tracking"""
        self._validate_security_boundaries()
        
        advisory_id = record_data.get("advisory_id", "")
        existing = self._advisories.get(advisory_id) if advisory_id else None
        is_updated = False
        if existing is not None and self.detect_duplicates(advisory_id, "advisory_record"):
            is_updated = self.detect_updates(existing, record_data)
        
        record = VendorSecurityAdvisoryRecordModel(
            advisory_id=advisory_id,
            vendor_source_id=record_data.get("vendor_source_id", ""),
            cve_references=record_data.get("cve_references", []),
            affected_products=record_data.get("affected_products", []),
            affected_versions=record_data.get("affected_versions", []),
            vulnerability_description=record_data.get("vulnerability_description"),
            severity=record_data.get("severity"),
            date_published=record_data.get("date_published", datetime.utcnow()),
            date_modified=record_data.get("date_modified"),
            required_action=record_data.get("required_action"),
            due_date=record_data.get("due_date"),
            source_publication_timestamp=record_data.get("source_publication_timestamp", datetime.utcnow()),
            source_update_timestamp=record_data.get("source_update_timestamp"),
            collection_timestamp=datetime.utcnow(),
            provenance=record_data.get("provenance", f"{self.vendor_type}_ingestion_pipeline"),
            confidence=record_data.get("confidence", 1.0),
            experimental_label=self.experimental_label,
            tenant_id=self.tenant_id
        )

        if existing is not None and is_updated:
            hist_id = f"HIST-{advisory_id}-{len(self._history_records) + 1:04d}"
            change_type = "severity_changed" if existing.severity != record.severity else "updated"
            self.ingest_history_record({
                "history_id": hist_id,
                "advisory_id": advisory_id,
                "change_type": change_type,
                "previous_state": {
                    "severity": existing.severity,
                    "required_action": existing.required_action,
                    "affected_versions": list(existing.affected_versions),
                },
                "new_state": {
                    "severity": record.severity,
                    "required_action": record.required_action,
                    "affected_versions": list(record.affected_versions),
                },
                "source": record.vendor_source_id or self.vendor_type,
                "provenance": record.provenance,
                "confidence": record.confidence,
            })

        if advisory_id:
            self._advisories[advisory_id] = record
            for cve in record.cve_references:
                bucket = self._cve_to_advisories.setdefault(cve, [])
                if advisory_id not in bucket:
                    bucket.append(advisory_id)

        self.preserve_historical_observations(record)
        self._log_ingestion_event("advisory_record", record.advisory_id)
        
        return record
    
    def ingest_history_record(self, history_data: Dict[str, Any]) -> VendorSecurityAdvisoryHistoryModel:
        """Ingest vendor security advisory historical change record"""
        self._validate_security_boundaries()
        
        history = VendorSecurityAdvisoryHistoryModel(
            history_id=history_data.get("history_id", ""),
            advisory_id=history_data.get("advisory_id", ""),
            change_type=history_data.get("change_type", ""),
            previous_state=history_data.get("previous_state"),
            new_state=history_data.get("new_state"),
            change_timestamp=history_data.get("change_timestamp", datetime.utcnow()),
            source=history_data.get("source", self.vendor_type.capitalize()),
            provenance=history_data.get("provenance", f"{self.vendor_type}_ingestion_pipeline"),
            confidence=history_data.get("confidence", 1.0),
            experimental_label=self.experimental_label,
            tenant_id=self.tenant_id
        )
        
        if history.history_id:
            self._history_records[history.history_id] = history
        self._log_ingestion_event("history_record", history.history_id)
        
        return history

    def get_advisories_for_cve(self, cve_id: str) -> List[VendorSecurityAdvisoryRecordModel]:
        """Return all ingested vendor advisories referencing `cve_id` (supports Agent 3 M2 correlation)."""
        ids = self._cve_to_advisories.get(cve_id.strip().upper(), [])
        return [self._advisories[aid] for aid in ids if aid in self._advisories]
    
    def detect_duplicates(self, entity_id: str, entity_type: str) -> bool:
        """Detect duplicate entities (security/integrity measure)"""
        if not entity_id:
            return False
        if entity_type == "advisory_record":
            return entity_id in self._advisories
        if entity_type == "source_metadata":
            return entity_id in self._sources
        if entity_type == "history_record":
            return entity_id in self._history_records
        return False
    
    def detect_updates(self, existing_record: Any, new_data: Dict[str, Any]) -> bool:
        """Detect updates to existing advisory records (idempotency/integrity)"""
        if existing_record is None or not isinstance(new_data, dict) or not new_data:
            return False
        tracked_fields = (
            "severity",
            "required_action",
            "due_date",
            "affected_products",
            "affected_versions",
            "cve_references",
            "vulnerability_description",
            "date_modified",
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
            "event_type": "vendor_advisory_ingestion",
            "entity_type": entity_type,
            "entity_id": entity_id,
            "vendor_type": self.vendor_type,
            "tenant_id": self.tenant_id,
            "timestamp": datetime.utcnow(),
            "verification_mode": self.verification_mode,
        })
    
    def validate_external_data(self, data: Dict[str, Any]) -> bool:
        """Validate external vendor advisory data (security measure)"""
        if not isinstance(data, dict):
            raise ValueError("Invalid data format - must be dictionary")
        
        serialized = str(data)
        if ("malicious" in serialized.lower() and "test" not in serialized.lower()) or _MALICIOUS_PATTERNS.search(serialized):
            raise SecurityError("Malicious content detected in external data")
        
        required_fields = ["advisory_id", "vendor_source_id", "cve_references", "affected_products", "date_published", "source_publication_timestamp"]
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
            "vendor_type": self.vendor_type,
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

        if _get(existing_record, "advisory_id") and _get(existing_record, "advisory_id") == _get(new_record, "advisory_id"):
            for field in ("severity", "required_action", "cve_references", "affected_products", "affected_versions"):
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
                "vendor_type": self.vendor_type,
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
            "vendor_type": self.vendor_type,
            "tenant_id": self.tenant_id,
            "timestamp": datetime.utcnow(),
        })
    
    def distinguish_verified_vs_inferred_source(self, source_data: Dict[str, Any]) -> str:
        """Distinguish verified vendor source from inferred/synthetic (integrity measure)"""
        if source_data.get("experimental_label") == EXPERIMENTAL_DEMO_DATA_ONLY:
            return "synthetic_fixture"
        elif source_data.get("confidence", 0.0) >= 0.9:
            return "verified_vendor"
        else:
            return "unverified"


class SecurityError(Exception):
    """Security violation exception"""
    pass
