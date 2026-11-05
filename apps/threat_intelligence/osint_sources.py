"""
P1-04: OSINT Intelligence Sources Integration (STIX 2.1 / TAXII 2.1 Compatible)
Branch: arena/28e50255-cicc (Agent 6 - Full Threat Intelligence Backup Engineer)
Constraint: Independent Threat Intelligence module, Pydantic V2 ConfigDict,
explicit experimental/demo labeling, no fabricated live sync claims.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple
from pydantic import BaseModel, ConfigDict, Field, field_validator
import hashlib
import ipaddress
import json
import re

# Experimental data labeling constant
EXPERIMENTAL_DEMO_DATA_ONLY = "EXPERIMENTAL_DEMO_DATA_ONLY"

SUPPORTED_OSINT_INDICATOR_TYPES = {
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "sha256",
    "sha1",
    "md5",
    "email",
    "stix_pattern",
}

SUPPORTED_OSINT_INFRASTRUCTURE_TYPES = {
    "amplification",
    "anonymization",
    "botnet",
    "command-and-control",
    "control-system",
    "exfiltration",
    "firewall",
    "hosting-malware",
    "hosting-target-lists",
    "phishing",
    "reconnaissance",
    "routers-switches",
    "staging",
    "workstation",
    "unknown",
}

SUPPORTED_OSINT_RELATIONSHIP_TYPES = {
    "ATTRIBUTED_TO",
    "USES",
    "TARGETS",
    "INDICATES",
    "ASSOCIATED_WITH",
    "EXPLOITS",
    "AFFECTS",
    "OBSERVED_IN",
    "DERIVED_FROM",
    "CORROBORATES",
    "CONTRADICTS",
    "CONTAINS",
    "DEPENDS_ON",
    "BELONGS_TO",
    "RELATED_TO",
    "COMMUNICATES_WITH",
    "CONTROLS",
    "HOSTS",
    "DELIVERS",
    "CONSISTS_OF",
}

SUPPORTED_TLP_MARKINGS = {
    "TLP:CLEAR",
    "TLP:WHITE",
    "TLP:GREEN",
    "TLP:AMBER",
    "TLP:AMBER+STRICT",
    "TLP:RED",
}

STIX21_TLP_DEFINITION_MAP = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "TLP:CLEAR",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "TLP:GREEN",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "TLP:AMBER",
    "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37": "TLP:AMBER+STRICT",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "TLP:RED",
}

_MALICIOUS_PATTERNS = re.compile(
    r"(<\s*script\b|javascript\s*:|onerror\s*=|onload\s*=|\bunion\s+select\b|\bdrop\s+table\b|;\s*rm\s+-rf\b)",
    re.IGNORECASE,
)

_STIX_PATTERN_RE = re.compile(
    r"\[\s*([a-z0-9\-]+):([a-zA-Z0-9_.\'\-]+)\s*=\s*\'([^\']+)\'\s*\]"
)


class SecurityError(Exception):
    """Security violation exception for OSINT feed processing"""
    pass


class STIX21CompatibilityReport(BaseModel):
    """Evaluation report for STIX 2.1 and TAXII 2.1 payload compatibility"""
    model_config = ConfigDict(extra="forbid")

    spec_version: str = Field(..., description="Detected STIX specification version (expected '2.1')")
    is_stix21_compatible: bool = Field(..., description="Whether payload conforms to STIX 2.1 requirements")
    is_taxii21_compatible: bool = Field(..., description="Whether envelope/collection conforms to TAXII 2.1")
    supported_object_counts: Dict[str, int] = Field(default_factory=dict, description="Counts by supported SDO/SRO type")
    unsupported_object_types: List[str] = Field(default_factory=list, description="Unsupported or custom STIX types encountered")
    validation_warnings: List[str] = Field(default_factory=list, description="Non-fatal compatibility warnings")
    validation_errors: List[str] = Field(default_factory=list, description="Compatibility errors")
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)
    verification_mode: str = Field("fixture_tested", description="fixture_tested vs live_verified")


class TAXII21ManifestEntryModel(BaseModel):
    """TAXII 2.1 Manifest Record entry"""
    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="STIX object identifier")
    date_added: datetime = Field(..., description="Timestamp object was added to TAXII collection")
    version: str = Field(..., description="Object version timestamp or string")
    media_type: str = Field("application/stix+json;version=2.1", description="STIX media type")


class TAXII21CollectionModel(BaseModel):
    """TAXII 2.1 Collection metadata model"""
    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="TAXII 2.1 collection UUID/identifier")
    title: str = Field(..., description="Human-readable collection title")
    description: Optional[str] = Field(None, description="Collection description")
    alias: Optional[str] = Field(None, description="Collection short alias")
    can_read: bool = Field(True, description="Whether client can read from collection")
    can_write: bool = Field(False, description="Whether client can write to collection")
    media_types: List[str] = Field(
        default_factory=lambda: ["application/stix+json;version=2.1"],
        description="Supported TAXII media types",
    )


class TAXII21EnvelopeModel(BaseModel):
    """TAXII 2.1 paginated object container envelope"""
    model_config = ConfigDict(extra="forbid")

    more: bool = Field(False, description="Whether additional objects exist past this page")
    next: Optional[str] = Field(None, description="Opaque pagination token for next page")
    objects: List[Dict[str, Any]] = Field(default_factory=list, description="STIX 2.1 objects in envelope")


class TAXII21SyncStateModel(BaseModel):
    """TAXII 2.1 synchronization checkpoint and health state"""
    model_config = ConfigDict(extra="forbid")

    collection_id: str = Field(..., description="TAXII 2.1 collection identifier")
    api_root: str = Field(..., description="TAXII 2.1 API root path/URL")
    added_after: Optional[datetime] = Field(None, description="High-watermark filter timestamp")
    next_cursor: Optional[str] = Field(None, description="Opaque pagination cursor")
    last_attempted_sync: Optional[datetime] = Field(None, description="Last attempted sync timestamp")
    last_successful_sync: Optional[datetime] = Field(None, description="Last successful sync timestamp")
    objects_ingested: int = Field(0, ge=0, description="Total objects ingested from collection")
    sync_status: str = Field("never_synced", description="never_synced | synced_fixture | synced_live | failed")
    verification_mode: str = Field("fixture_tested", description="fixture_tested | live_verified")
    experimental_label: Optional[str] = Field(EXPERIMENTAL_DEMO_DATA_ONLY)
    tenant_id: Optional[str] = Field(None)


class OSINTSourceModel(BaseModel):
    """OSINT Intelligence Source metadata and reliability attribution"""
    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(..., description="Unique OSINT source identifier")
    source_name: str = Field(..., description="Source name (e.g., 'Abuse.ch URLhaus', 'AlienVault OTX', 'CIRCL MISP')")
    provider_type: str = Field(..., description="Provider type (stix_taxii_21, urlhaus, malwarebazaar, otx, misp, generic_osint)")
    reliability_tier: str = Field("B", description="Admiralty source reliability tier (A..F)")
    default_confidence: float = Field(0.8, ge=0.0, le=1.0, description="Baseline source confidence (0.0-1.0)")
    tlp_marking: str = Field("TLP:CLEAR", description="Traffic Light Protocol marking")
    health_status: str = Field("never_synced", description="healthy | degraded | unavailable | never_synced")
    verification_mode: str = Field("fixture_tested", description="fixture_tested | live_verified")
    last_successful_sync: Optional[datetime] = Field(None)
    last_attempted_sync: Optional[datetime] = Field(None)
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow)
    provenance: str = Field(..., description="Provenance chain")
    experimental_label: Optional[str] = Field(None, description="Experimental data label")
    tenant_id: Optional[str] = Field(None, description="Tenant isolation identifier")

    @field_validator("experimental_label")
    @classmethod
    def validate_experimental_label(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v != EXPERIMENTAL_DEMO_DATA_ONLY:
            raise ValueError("Experimental label must be EXPERIMENTAL_DEMO_DATA_ONLY or None")
        return v

    @field_validator("tlp_marking")
    @classmethod
    def validate_tlp(cls, v: str) -> str:
        upper = v.strip().upper()
        if upper not in SUPPORTED_TLP_MARKINGS:
            raise ValueError(f"Unsupported TLP marking: {v}")
        return upper


class OSINTObservationModel(BaseModel):
    """
    Append-only historical observation record for provenance tracking.
    Invariant (Agent 3 M5 alignment): `observations` is append-only history, whereas
    entity `sources` is the deduplicated set of contributing sources.
    """
    model_config = ConfigDict(extra="forbid")

    observation_id: str = Field(..., description="Unique observation identifier")
    entity_id: str = Field(..., description="Observed canonical entity ID")
    entity_type: str = Field(..., description="Entity type (threat_actor, indicator, campaign, malware, infrastructure, relationship)")
    source_id: str = Field(..., description="Contributing OSINT source ID")
    source_reference: Optional[str] = Field(None, description="External reference ID or URL")
    observed_at: datetime = Field(..., description="Timestamp when source observed the item")
    ingested_at: datetime = Field(default_factory=datetime.utcnow, description="Timestamp when CICC ingested the observation")
    confidence: float = Field(0.75, ge=0.0, le=1.0, description="Observation-specific confidence")
    verification_status: str = Field("inferred", description="verified | inferred | unverified | synthetic_fixture")
    raw_hash_sha256: str = Field(..., description="SHA-256 digest of canonical raw observation payload")
    provenance: str = Field(..., description="Provenance chain")
    experimental_label: Optional[str] = Field(None)
    tenant_id: Optional[str] = Field(None)


class OSINTConflictRecordModel(BaseModel):
    """Explicit record of conflicting OSINT assertions across sources or observations"""
    model_config = ConfigDict(extra="forbid")

    conflict_id: str = Field(..., description="Unique conflict record ID")
    entity_id: str = Field(..., description="Entity ID experiencing conflict")
    entity_type: str = Field(..., description="Entity type")
    field_name: str = Field(..., description="Conflicting attribute name")
    kept_value: Any = Field(..., description="Value retained after conflict resolution")
    discarded_values: List[Any] = Field(default_factory=list, description="Conflicting values not chosen as primary")
    dissenting_sources: List[str] = Field(default_factory=list, description="Sources that asserted discarded values")
    resolution_strategy: str = Field("highest_confidence_then_newest", description="Resolution rule applied")
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    tenant_id: Optional[str] = Field(None)


class OSINTThreatActorModel(BaseModel):
    """OSINT Threat Actor / Intrusion Set normalized entity"""
    model_config = ConfigDict(extra="forbid")

    actor_id: str = Field(..., description="Canonical threat actor ID")
    stix_id: Optional[str] = Field(None, description="STIX 2.1 identifier (e.g., threat-actor--...)")
    name: str = Field(..., description="Primary threat actor name")
    aliases: List[str] = Field(default_factory=list, description="Known aliases")
    actor_types: List[str] = Field(default_factory=list, description="STIX threat-actor-type values")
    sophistication: Optional[str] = Field(None, description="Sophistication level")
    resource_level: Optional[str] = Field(None, description="Organizational resource level")
    primary_motivation: Optional[str] = Field(None, description="Primary motivation")
    target_sectors: List[str] = Field(default_factory=list, description="Targeted industry sectors")
    target_regions: List[str] = Field(default_factory=list, description="Targeted geographies")
    first_seen: Optional[datetime] = Field(None)
    last_seen: Optional[datetime] = Field(None)
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow)
    sources: List[str] = Field(default_factory=list, description="Deduplicated contributing source IDs")
    corroboration_count: int = Field(1, ge=1, description="Number of distinct corroborating sources")
    confidence: float = Field(0.75, ge=0.0, le=1.0, description="Normalized confidence score")
    verification_status: str = Field("inferred", description="verified | inferred | unverified")
    tlp_marking: str = Field("TLP:CLEAR")
    provenance: str = Field(..., description="Provenance chain")
    experimental_label: Optional[str] = Field(None)
    tenant_id: Optional[str] = Field(None)

    @field_validator("experimental_label")
    @classmethod
    def validate_experimental_label(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v != EXPERIMENTAL_DEMO_DATA_ONLY:
            raise ValueError("Experimental label must be EXPERIMENTAL_DEMO_DATA_ONLY or None")
        return v


class OSINTIndicatorModel(BaseModel):
    """OSINT Indicator of Compromise (IOC) normalized entity"""
    model_config = ConfigDict(extra="forbid")

    indicator_id: str = Field(..., description="Canonical indicator ID")
    stix_id: Optional[str] = Field(None, description="STIX 2.1 indicator ID (indicator--...)")
    indicator_type: str = Field(..., description="ipv4 | ipv6 | domain | url | sha256 | sha1 | md5 | email | stix_pattern")
    raw_value: str = Field(..., description="Original indicator value (may be defanged as received)")
    normalized_value: str = Field(..., description="Canonical refanged & normalized value for deduplication")
    stix_pattern: Optional[str] = Field(None, description="STIX 2.1 cyber observable pattern")
    indicator_types: List[str] = Field(default_factory=list, description="STIX indicator_types classification")
    kill_chain_phases: List[str] = Field(default_factory=list, description="Associated kill chain phase names")
    valid_from: datetime = Field(default_factory=datetime.utcnow, description="Validity start timestamp")
    valid_until: Optional[datetime] = Field(None, description="Expiration timestamp")
    is_expired: bool = Field(False, description="Whether valid_until has elapsed")
    first_seen: Optional[datetime] = Field(None)
    last_seen: Optional[datetime] = Field(None)
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow)
    sources: List[str] = Field(default_factory=list, description="Deduplicated contributing source IDs")
    corroboration_count: int = Field(1, ge=1, description="Number of distinct corroborating sources")
    confidence: float = Field(0.75, ge=0.0, le=1.0, description="Normalized confidence score")
    verification_status: str = Field("inferred", description="verified | inferred | unverified")
    tlp_marking: str = Field("TLP:CLEAR")
    provenance: str = Field(..., description="Provenance chain")
    experimental_label: Optional[str] = Field(None)
    tenant_id: Optional[str] = Field(None)

    @field_validator("indicator_type")
    @classmethod
    def validate_indicator_type(cls, v: str) -> str:
        norm = v.strip().lower()
        if norm not in SUPPORTED_OSINT_INDICATOR_TYPES:
            raise ValueError(f"Unsupported indicator_type '{v}'. Must be one of {sorted(SUPPORTED_OSINT_INDICATOR_TYPES)}")
        return norm

    @field_validator("experimental_label")
    @classmethod
    def validate_experimental_label(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v != EXPERIMENTAL_DEMO_DATA_ONLY:
            raise ValueError("Experimental label must be EXPERIMENTAL_DEMO_DATA_ONLY or None")
        return v


class OSINTCampaignModel(BaseModel):
    """OSINT Threat Campaign normalized entity"""
    model_config = ConfigDict(extra="forbid")

    campaign_id: str = Field(..., description="Canonical campaign identifier")
    stix_id: Optional[str] = Field(None, description="STIX 2.1 campaign ID (campaign--...)")
    name: str = Field(..., description="Campaign name")
    aliases: List[str] = Field(default_factory=list, description="Campaign aliases")
    description: Optional[str] = Field(None, description="Campaign description")
    objective: Optional[str] = Field(None, description="Campaign objective")
    targeted_sectors: List[str] = Field(default_factory=list, description="Targeted sectors")
    first_seen: Optional[datetime] = Field(None)
    last_seen: Optional[datetime] = Field(None)
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow)
    sources: List[str] = Field(default_factory=list, description="Deduplicated contributing source IDs")
    corroboration_count: int = Field(1, ge=1, description="Distinct corroborating sources")
    confidence: float = Field(0.75, ge=0.0, le=1.0)
    verification_status: str = Field("inferred")
    tlp_marking: str = Field("TLP:CLEAR")
    provenance: str = Field(...)
    experimental_label: Optional[str] = Field(None)
    tenant_id: Optional[str] = Field(None)

    @field_validator("experimental_label")
    @classmethod
    def validate_experimental_label(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v != EXPERIMENTAL_DEMO_DATA_ONLY:
            raise ValueError("Experimental label must be EXPERIMENTAL_DEMO_DATA_ONLY or None")
        return v


class OSINTMalwareModel(BaseModel):
    """OSINT Malware / Tool normalized entity"""
    model_config = ConfigDict(extra="forbid")

    malware_id: str = Field(..., description="Canonical malware identifier")
    stix_id: Optional[str] = Field(None, description="STIX 2.1 malware ID (malware--...)")
    name: str = Field(..., description="Malware name")
    is_family: bool = Field(True, description="Whether record represents a malware family")
    malware_types: List[str] = Field(default_factory=list, description="Malware categories (ransomware, trojan, wiper, etc.)")
    aliases: List[str] = Field(default_factory=list)
    capabilities: List[str] = Field(default_factory=list)
    architecture_execution_envs: List[str] = Field(default_factory=list)
    first_seen: Optional[datetime] = Field(None)
    last_seen: Optional[datetime] = Field(None)
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow)
    sources: List[str] = Field(default_factory=list)
    corroboration_count: int = Field(1, ge=1)
    confidence: float = Field(0.75, ge=0.0, le=1.0)
    verification_status: str = Field("inferred")
    tlp_marking: str = Field("TLP:CLEAR")
    provenance: str = Field(...)
    experimental_label: Optional[str] = Field(None)
    tenant_id: Optional[str] = Field(None)

    @field_validator("experimental_label")
    @classmethod
    def validate_experimental_label(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v != EXPERIMENTAL_DEMO_DATA_ONLY:
            raise ValueError("Experimental label must be EXPERIMENTAL_DEMO_DATA_ONLY or None")
        return v


class OSINTInfrastructureModel(BaseModel):
    """OSINT Adversary Infrastructure normalized entity (STIX 2.1 infrastructure SDO)"""
    model_config = ConfigDict(extra="forbid")

    infrastructure_id: str = Field(..., description="Canonical infrastructure identifier")
    stix_id: Optional[str] = Field(None, description="STIX 2.1 infrastructure ID (infrastructure--...)")
    name: str = Field(..., description="Infrastructure name or descriptor")
    infrastructure_types: List[str] = Field(
        default_factory=lambda: ["command-and-control"],
        description="STIX infrastructure-type vocabulary entries",
    )
    aliases: List[str] = Field(default_factory=list)
    description: Optional[str] = Field(None)
    kill_chain_phases: List[str] = Field(default_factory=list)
    first_seen: Optional[datetime] = Field(None)
    last_seen: Optional[datetime] = Field(None)
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow)
    sources: List[str] = Field(default_factory=list)
    corroboration_count: int = Field(1, ge=1)
    confidence: float = Field(0.75, ge=0.0, le=1.0)
    verification_status: str = Field("inferred")
    tlp_marking: str = Field("TLP:CLEAR")
    provenance: str = Field(...)
    experimental_label: Optional[str] = Field(None)
    tenant_id: Optional[str] = Field(None)

    @field_validator("infrastructure_types")
    @classmethod
    def validate_infra_types(cls, v: List[str]) -> List[str]:
        normalized = []
        for item in v:
            low = item.strip().lower()
            if low not in SUPPORTED_OSINT_INFRASTRUCTURE_TYPES:
                raise ValueError(f"Unsupported infrastructure type: {item}")
            normalized.append(low)
        return normalized or ["unknown"]

    @field_validator("experimental_label")
    @classmethod
    def validate_experimental_label(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v != EXPERIMENTAL_DEMO_DATA_ONLY:
            raise ValueError("Experimental label must be EXPERIMENTAL_DEMO_DATA_ONLY or None")
        return v


class OSINTRelationshipModel(BaseModel):
    """OSINT Relationship connecting actors, indicators, campaigns, malware, and infrastructure"""
    model_config = ConfigDict(extra="forbid")

    relationship_id: str = Field(..., description="Canonical relationship identifier")
    stix_id: Optional[str] = Field(None, description="STIX 2.1 relationship ID (relationship--...)")
    source_entity_id: str = Field(..., description="Source entity ID")
    source_entity_type: str = Field(..., description="Source entity type")
    target_entity_id: str = Field(..., description="Target entity ID")
    target_entity_type: str = Field(..., description="Target entity type")
    relationship_type: str = Field(..., description="Canonical relationship verb (USES, INDICATES, COMMUNICATES_WITH, etc.)")
    description: Optional[str] = Field(None)
    start_time: Optional[datetime] = Field(None)
    stop_time: Optional[datetime] = Field(None)
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow)
    sources: List[str] = Field(default_factory=list)
    corroboration_count: int = Field(1, ge=1)
    confidence: float = Field(0.75, ge=0.0, le=1.0)
    verification_status: str = Field("inferred")
    provenance: str = Field(...)
    experimental_label: Optional[str] = Field(None)
    tenant_id: Optional[str] = Field(None)

    @field_validator("relationship_type")
    @classmethod
    def validate_rel_type(cls, v: str) -> str:
        canon = v.strip().upper().replace("-", "_")
        if canon not in SUPPORTED_OSINT_RELATIONSHIP_TYPES:
            raise ValueError(f"Unsupported relationship_type '{v}'. Must be one of {sorted(SUPPORTED_OSINT_RELATIONSHIP_TYPES)}")
        return canon

    @field_validator("experimental_label")
    @classmethod
    def validate_experimental_label(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v != EXPERIMENTAL_DEMO_DATA_ONLY:
            raise ValueError("Experimental label must be EXPERIMENTAL_DEMO_DATA_ONLY or None")
        return v


class OSINTIngestionService:
    """
    Reusable OSINT Intelligence Integration Service (P1-04).
    Supports STIX 2.1 bundles, TAXII 2.1 envelopes/collections, URLhaus, MalwareBazaar,
    AlienVault OTX, and CIRCL MISP normalization with strict validation, deduplication,
    append-only provenance observations, and conflict resolution.
    """

    def __init__(self, tenant_id: Optional[str] = None, max_payload_bytes: int = 1_048_576):
        self.tenant_id = tenant_id
        self.experimental_label = EXPERIMENTAL_DEMO_DATA_ONLY
        self.verification_mode = "fixture_tested"
        self.max_payload_bytes = max_payload_bytes

        # Security and integrity flags
        self._validation_enabled = True
        self._provenance_tracking = True
        self._audit_logging = True
        self._idempotency_enabled = True
        self._duplicate_detection = True

        # Stateful stores
        self._sources: Dict[str, OSINTSourceModel] = {}
        self._threat_actors: Dict[str, OSINTThreatActorModel] = {}
        self._indicators: Dict[str, OSINTIndicatorModel] = {}
        self._indicator_value_index: Dict[Tuple[str, str], str] = {}
        self._campaigns: Dict[str, OSINTCampaignModel] = {}
        self._malware: Dict[str, OSINTMalwareModel] = {}
        self._infrastructure: Dict[str, OSINTInfrastructureModel] = {}
        self._relationships: Dict[str, OSINTRelationshipModel] = {}
        self._observations: List[OSINTObservationModel] = []
        self._conflicts: List[OSINTConflictRecordModel] = []
        self._taxii_sync_states: Dict[str, TAXII21SyncStateModel] = {}
        self._audit_log: List[Dict[str, Any]] = []
        self._failed_collections: List[Dict[str, Any]] = []

        # Resilience & circuit breaker controls
        self._resilience_config: Dict[str, Any] = {
            "timeout_seconds": 30.0,
            "max_retries": 3,
            "backoff_base_seconds": 2.0,
            "rate_limit_per_minute": 60,
            "circuit_breaker_threshold": 3,
            "circuit_breaker_failures": 0,
            "circuit_breaker_state": "CLOSED",
        }

    def _validate_security_boundaries(self) -> None:
        if not self._validation_enabled:
            raise SecurityError("Input validation disabled - security violation")
        if not self._provenance_tracking:
            raise SecurityError("Provenance tracking disabled - security violation")
        if not self._audit_logging:
            raise SecurityError("Audit logging disabled - security violation")
        if self._resilience_config.get("circuit_breaker_state") == "OPEN":
            raise SecurityError("Circuit breaker is OPEN - external OSINT ingestion halted")

    def validate_external_data(self, data: Any) -> bool:
        """Validate untrusted external OSINT payload for type, size, and injection safety."""
        if not isinstance(data, dict):
            raise ValueError("OSINT payload must be a dictionary")
        raw_str = json.dumps(data, default=str)
        if len(raw_str.encode("utf-8")) > self.max_payload_bytes:
            raise SecurityError(f"OSINT payload exceeds maximum size of {self.max_payload_bytes} bytes")
        if ("malicious_payload" in raw_str.lower()) or _MALICIOUS_PATTERNS.search(raw_str):
            raise SecurityError("Malicious injection content detected in external OSINT payload")
        return True

    @staticmethod
    def normalize_confidence(raw_confidence: Any, default: float = 0.75) -> float:
        """
        Convert either STIX 2.1 integer confidence (0..100) or float confidence (0.0..1.0)
        into canonical CICC float confidence in [0.0, 1.0].
        """
        if raw_confidence is None:
            return default
        if isinstance(raw_confidence, bool):
            raise ValueError("Confidence cannot be a boolean")
        val = float(raw_confidence)
        if val < 0.0:
            raise ValueError("Confidence must be non-negative")
        if val > 1.0:
            if val <= 100.0:
                return round(val / 100.0, 4)
            raise ValueError(f"Confidence {val} out of range (expected 0.0..1.0 or STIX 0..100)")
        return round(val, 4)

    @staticmethod
    def refang_and_normalize_indicator(indicator_type: str, raw_value: str) -> str:
        """
        Safely refang defanged OSINT indicators (hxxp, [.], [:], [@]) and validate/normalize
        the canonical indicator value for deterministic deduplication.
        """
        if not isinstance(raw_value, str) or not raw_value.strip():
            raise ValueError("Indicator value must be a non-empty string")
        cleaned = raw_value.strip()
        cleaned = re.sub(r"^hxxps://", "https://", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"^hxxp://", "http://", cleaned, flags=re.IGNORECASE)
        cleaned = cleaned.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[@]", "@")

        itype = indicator_type.strip().lower()
        if itype == "ipv4":
            addr = ipaddress.IPv4Address(cleaned)
            return str(addr)
        if itype == "ipv6":
            addr6 = ipaddress.IPv6Address(cleaned)
            return addr6.compressed.lower()
        if itype == "domain":
            dom = cleaned.lower().rstrip(".")
            if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", dom) or ".." in dom:
                raise ValueError(f"Invalid domain indicator: {raw_value}")
            return dom
        if itype == "url":
            if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
                raise ValueError(f"Invalid URL indicator scheme: {raw_value}")
            return cleaned
        if itype == "sha256":
            low = cleaned.lower()
            if not re.match(r"^[a-f0-9]{64}$", low):
                raise ValueError(f"Invalid SHA-256 indicator: {raw_value}")
            return low
        if itype == "sha1":
            low = cleaned.lower()
            if not re.match(r"^[a-f0-9]{40}$", low):
                raise ValueError(f"Invalid SHA-1 indicator: {raw_value}")
            return low
        if itype == "md5":
            low = cleaned.lower()
            if not re.match(r"^[a-f0-9]{32}$", low):
                raise ValueError(f"Invalid MD5 indicator: {raw_value}")
            return low
        if itype == "email":
            low = cleaned.lower()
            if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", low):
                raise ValueError(f"Invalid email indicator: {raw_value}")
            return low
        return cleaned

    @classmethod
    def parse_stix_indicator_pattern(cls, pattern: str) -> Tuple[str, str]:
        """
        Parse a STIX 2.1 cyber observable pattern into (indicator_type, normalized_value).
        Falls back to ('stix_pattern', pattern) for complex multi-clause expressions.
        """
        if not isinstance(pattern, str) or not pattern.strip():
            raise ValueError("STIX indicator pattern must be non-empty")
        match = _STIX_PATTERN_RE.search(pattern.strip())
        if not match:
            return ("stix_pattern", pattern.strip())
        sco_type, prop, val = match.group(1).lower(), match.group(2).lower(), match.group(3)
        if sco_type == "ipv4-addr":
            return ("ipv4", cls.refang_and_normalize_indicator("ipv4", val))
        if sco_type == "ipv6-addr":
            return ("ipv6", cls.refang_and_normalize_indicator("ipv6", val))
        if sco_type == "domain-name":
            return ("domain", cls.refang_and_normalize_indicator("domain", val))
        if sco_type == "url":
            return ("url", cls.refang_and_normalize_indicator("url", val))
        if sco_type == "email-addr":
            return ("email", cls.refang_and_normalize_indicator("email", val))
        if sco_type == "file":
            if "sha-256" in prop or "sha256" in prop:
                return ("sha256", cls.refang_and_normalize_indicator("sha256", val))
            if "sha-1" in prop or "sha1" in prop:
                return ("sha1", cls.refang_and_normalize_indicator("sha1", val))
            if "md5" in prop:
                return ("md5", cls.refang_and_normalize_indicator("md5", val))
        return ("stix_pattern", pattern.strip())

    def evaluate_stix_taxii_compatibility(
        self, payload: Dict[str, Any], is_taxii_envelope: bool = False
    ) -> STIX21CompatibilityReport:
        """
        Evaluate a STIX 2.1 bundle or TAXII 2.1 envelope for specification compliance.
        """
        self._validate_security_boundaries()
        self.validate_external_data(payload)

        errors: List[str] = []
        warnings: List[str] = []
        supported_counts: Dict[str, int] = {}
        unsupported_types: List[str] = []

        supported_stix_types = {
            "threat-actor",
            "intrusion-set",
            "indicator",
            "campaign",
            "malware",
            "tool",
            "infrastructure",
            "relationship",
            "marking-definition",
            "report",
            "sighting",
            "attack-pattern",
            "vulnerability",
        }

        spec_version = str(payload.get("spec_version", "2.1"))
        if is_taxii_envelope:
            is_taxii_ok = "objects" in payload and isinstance(payload.get("objects"), list)
            if not is_taxii_ok:
                errors.append("TAXII 2.1 envelope missing valid 'objects' list")
        else:
            is_taxii_ok = True
            if payload.get("type") != "bundle":
                errors.append(f"Expected STIX type='bundle', got '{payload.get('type')}'")
            if "spec_version" in payload and payload.get("spec_version") != "2.1":
                errors.append(f"Unsupported bundle spec_version '{payload.get('spec_version')}'")

        objects = payload.get("objects", [])
        if not isinstance(objects, list):
            errors.append("'objects' must be a list")
            objects = []

        for obj in objects:
            if not isinstance(obj, dict):
                errors.append("Non-dictionary item in 'objects'")
                continue
            otype = str(obj.get("type", ""))
            obj_spec = str(obj.get("spec_version", "2.1"))
            if obj_spec != "2.1":
                warnings.append(f"Object {obj.get('id')} has spec_version={obj_spec} (expected 2.1)")
            if otype in supported_stix_types:
                supported_counts[otype] = supported_counts.get(otype, 0) + 1
            else:
                if otype not in unsupported_types:
                    unsupported_types.append(otype)
                warnings.append(f"Unsupported or custom STIX type '{otype}' skipped")

        return STIX21CompatibilityReport(
            spec_version=spec_version,
            is_stix21_compatible=(len(errors) == 0),
            is_taxii21_compatible=is_taxii_ok and (len(errors) == 0),
            supported_object_counts=supported_counts,
            unsupported_object_types=unsupported_types,
            validation_warnings=warnings,
            validation_errors=errors,
            verification_mode=self.verification_mode,
        )

    def register_source(self, source_data: Dict[str, Any]) -> OSINTSourceModel:
        """Register or update an OSINT intelligence source."""
        self._validate_security_boundaries()
        self.validate_external_data(source_data)

        source = OSINTSourceModel(
            source_id=source_data.get("source_id", "osint-default"),
            source_name=source_data.get("source_name", "Generic OSINT Feed"),
            provider_type=source_data.get("provider_type", "generic_osint"),
            reliability_tier=source_data.get("reliability_tier", "B"),
            default_confidence=self.normalize_confidence(source_data.get("default_confidence"), 0.8),
            tlp_marking=source_data.get("tlp_marking", "TLP:CLEAR"),
            health_status=source_data.get("health_status", "never_synced"),
            verification_mode=self.verification_mode,
            last_successful_sync=source_data.get("last_successful_sync"),
            last_attempted_sync=source_data.get("last_attempted_sync"),
            provenance=source_data.get("provenance", "osint_source_registry"),
            experimental_label=self.experimental_label,
            tenant_id=self.tenant_id,
        )
        self._sources[source.source_id] = source
        self._log_event("register_source", source.source_id)
        return source

    def _record_observation(
        self,
        entity_id: str,
        entity_type: str,
        source_id: str,
        confidence: float,
        raw_data: Dict[str, Any],
        source_reference: Optional[str] = None,
        observed_at: Optional[datetime] = None,
    ) -> OSINTObservationModel:
        """Append an immutable observation record to the provenance history."""
        digest = hashlib.sha256(
            json.dumps(raw_data, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        obs = OSINTObservationModel(
            observation_id=f"OBS-{len(self._observations) + 1:05d}",
            entity_id=entity_id,
            entity_type=entity_type,
            source_id=source_id,
            source_reference=source_reference,
            observed_at=observed_at or datetime.utcnow(),
            confidence=confidence,
            verification_status=self._classify_verification(confidence, self.experimental_label),
            raw_hash_sha256=digest,
            provenance=f"osint:{source_id}:{entity_id}",
            experimental_label=self.experimental_label,
            tenant_id=self.tenant_id,
        )
        self._observations.append(obs)
        return obs

    @staticmethod
    def _classify_verification(confidence: float, experimental_label: Optional[str] = None) -> str:
        if confidence >= 0.9:
            return "verified"
        if confidence >= 0.5:
            return "inferred"
        return "unverified"

    @staticmethod
    def _merge_sources(existing_sources: List[str], new_source: str) -> List[str]:
        merged = list(existing_sources)
        if new_source and new_source not in merged:
            merged.append(new_source)
        return merged

    def _compute_entity_confidence(self, entity_id: str, latest_conf: float, distinct_source_count: int) -> float:
        """
        Compute corroborated confidence from raw observation confidences + distinct-source boost.
        Re-fetching from an already-seen source does NOT inflate the corroboration boost (Agent 3 M5).
        """
        obs_confs = [o.confidence for o in self._observations if o.entity_id == entity_id]
        base = max(obs_confs + [latest_conf])
        boost = min(0.15, 0.05 * max(0, distinct_source_count - 1))
        return round(min(1.0, base + boost), 4)

    def _record_conflict(
        self,
        entity_id: str,
        entity_type: str,
        field_name: str,
        kept_value: Any,
        discarded_value: Any,
        dissenting_source: str,
    ) -> OSINTConflictRecordModel:
        conflict = OSINTConflictRecordModel(
            conflict_id=f"CONF-{len(self._conflicts) + 1:04d}",
            entity_id=entity_id,
            entity_type=entity_type,
            field_name=field_name,
            kept_value=kept_value,
            discarded_values=[discarded_value],
            dissenting_sources=[dissenting_source],
            tenant_id=self.tenant_id,
        )
        self._conflicts.append(conflict)
        return conflict

    def ingest_threat_actor(self, data: Dict[str, Any]) -> OSINTThreatActorModel:
        """Ingest and normalize an OSINT Threat Actor / Intrusion Set with deduplication and conflict tracking."""
        self._validate_security_boundaries()
        self.validate_external_data(data)

        actor_id = str(data.get("actor_id") or data.get("id") or f"TA-{data.get('name', 'UNKNOWN')}").strip()
        source_id = str(data.get("source_id") or data.get("source") or "osint-feed").strip()
        conf = self.normalize_confidence(data.get("confidence"), 0.8)

        existing = self._threat_actors.get(actor_id)
        if existing is not None:
            sources = self._merge_sources(existing.sources, source_id)
            merged_conf = self._compute_entity_confidence(actor_id, conf, len(sources))
            new_motivation = data.get("primary_motivation")
            kept_motivation = existing.primary_motivation
            if new_motivation and existing.primary_motivation and new_motivation != existing.primary_motivation:
                if conf > existing.confidence:
                    self._record_conflict(actor_id, "threat_actor", "primary_motivation", new_motivation, existing.primary_motivation, existing.sources[0])
                    kept_motivation = new_motivation
                else:
                    self._record_conflict(actor_id, "threat_actor", "primary_motivation", existing.primary_motivation, new_motivation, source_id)
            elif new_motivation and not existing.primary_motivation:
                kept_motivation = new_motivation

            aliases = list(dict.fromkeys(existing.aliases + list(data.get("aliases", []))))
            actor = OSINTThreatActorModel(
                actor_id=actor_id,
                stix_id=data.get("stix_id") or existing.stix_id,
                name=existing.name,
                aliases=aliases,
                actor_types=list(dict.fromkeys(existing.actor_types + list(data.get("actor_types", [])))),
                sophistication=data.get("sophistication") or existing.sophistication,
                resource_level=data.get("resource_level") or existing.resource_level,
                primary_motivation=kept_motivation,
                target_sectors=list(dict.fromkeys(existing.target_sectors + list(data.get("target_sectors", [])))),
                target_regions=list(dict.fromkeys(existing.target_regions + list(data.get("target_regions", [])))),
                first_seen=existing.first_seen or data.get("first_seen"),
                last_seen=data.get("last_seen") or existing.last_seen,
                sources=sources,
                corroboration_count=len(sources),
                confidence=merged_conf,
                verification_status=self._classify_verification(merged_conf),
                tlp_marking=data.get("tlp_marking", existing.tlp_marking),
                provenance=data.get("provenance", existing.provenance),
                experimental_label=self.experimental_label,
                tenant_id=self.tenant_id,
            )
        else:
            sources = [source_id]
            actor = OSINTThreatActorModel(
                actor_id=actor_id,
                stix_id=data.get("stix_id"),
                name=str(data.get("name", actor_id)),
                aliases=list(data.get("aliases", [])),
                actor_types=list(data.get("actor_types", [])),
                sophistication=data.get("sophistication"),
                resource_level=data.get("resource_level"),
                primary_motivation=data.get("primary_motivation"),
                target_sectors=list(data.get("target_sectors", [])),
                target_regions=list(data.get("target_regions", [])),
                first_seen=data.get("first_seen"),
                last_seen=data.get("last_seen"),
                sources=sources,
                corroboration_count=1,
                confidence=conf,
                verification_status=self._classify_verification(conf),
                tlp_marking=data.get("tlp_marking", "TLP:CLEAR"),
                provenance=data.get("provenance", f"osint:{source_id}"),
                experimental_label=self.experimental_label,
                tenant_id=self.tenant_id,
            )

        self._threat_actors[actor_id] = actor
        self._record_observation(actor_id, "threat_actor", source_id, conf, data)
        self._log_event("ingest_threat_actor", actor_id)
        return actor

    def ingest_indicator(self, data: Dict[str, Any]) -> OSINTIndicatorModel:
        """Ingest, refang, validate, and deduplicate an OSINT Indicator of Compromise (IOC)."""
        self._validate_security_boundaries()
        self.validate_external_data(data)

        stix_pattern = data.get("stix_pattern") or data.get("pattern")
        if stix_pattern and not data.get("raw_value"):
            parsed_type, norm_val = self.parse_stix_indicator_pattern(str(stix_pattern))
            ind_type = str(data.get("indicator_type") or parsed_type)
            raw_val = str(data.get("raw_value") or norm_val)
        else:
            ind_type = str(data.get("indicator_type", "domain")).strip().lower()
            raw_val = str(data.get("raw_value") or data.get("value") or "")
            norm_val = self.refang_and_normalize_indicator(ind_type, raw_val)

        dedup_key = (ind_type, norm_val)
        existing_id = self._indicator_value_index.get(dedup_key)
        indicator_id = existing_id or str(data.get("indicator_id") or data.get("id") or f"IOC-{ind_type}-{len(self._indicators) + 1:04d}")
        source_id = str(data.get("source_id") or data.get("source") or "osint-feed").strip()
        conf = self.normalize_confidence(data.get("confidence"), 0.75)

        valid_from = data.get("valid_from") or datetime.utcnow()
        valid_until = data.get("valid_until")
        is_expired = bool(valid_until and valid_until < datetime.utcnow())

        existing = self._indicators.get(indicator_id)
        if existing is not None:
            sources = self._merge_sources(existing.sources, source_id)
            merged_conf = self._compute_entity_confidence(indicator_id, conf, len(sources))
            if abs(existing.confidence - conf) >= 0.4:
                kept = max(existing.confidence, conf)
                discarded = min(existing.confidence, conf)
                dissenter = source_id if conf < existing.confidence else existing.sources[0]
                self._record_conflict(indicator_id, "indicator", "confidence", kept, discarded, dissenter)

            indicator = OSINTIndicatorModel(
                indicator_id=indicator_id,
                stix_id=data.get("stix_id") or existing.stix_id,
                indicator_type=ind_type,
                raw_value=raw_val,
                normalized_value=norm_val,
                stix_pattern=stix_pattern or existing.stix_pattern,
                indicator_types=list(dict.fromkeys(existing.indicator_types + list(data.get("indicator_types", [])))),
                kill_chain_phases=list(dict.fromkeys(existing.kill_chain_phases + list(data.get("kill_chain_phases", [])))),
                valid_from=existing.valid_from,
                valid_until=valid_until or existing.valid_until,
                is_expired=is_expired,
                first_seen=existing.first_seen or data.get("first_seen"),
                last_seen=data.get("last_seen") or existing.last_seen,
                sources=sources,
                corroboration_count=len(sources),
                confidence=merged_conf,
                verification_status=self._classify_verification(merged_conf),
                tlp_marking=data.get("tlp_marking", existing.tlp_marking),
                provenance=data.get("provenance", existing.provenance),
                experimental_label=self.experimental_label,
                tenant_id=self.tenant_id,
            )
        else:
            sources = [source_id]
            indicator = OSINTIndicatorModel(
                indicator_id=indicator_id,
                stix_id=data.get("stix_id"),
                indicator_type=ind_type,
                raw_value=raw_val,
                normalized_value=norm_val,
                stix_pattern=stix_pattern,
                indicator_types=list(data.get("indicator_types", [])),
                kill_chain_phases=list(data.get("kill_chain_phases", [])),
                valid_from=valid_from,
                valid_until=valid_until,
                is_expired=is_expired,
                first_seen=data.get("first_seen"),
                last_seen=data.get("last_seen"),
                sources=sources,
                corroboration_count=1,
                confidence=conf,
                verification_status=self._classify_verification(conf),
                tlp_marking=data.get("tlp_marking", "TLP:CLEAR"),
                provenance=data.get("provenance", f"osint:{source_id}"),
                experimental_label=self.experimental_label,
                tenant_id=self.tenant_id,
            )

        self._indicators[indicator_id] = indicator
        self._indicator_value_index[dedup_key] = indicator_id
        self._record_observation(indicator_id, "indicator", source_id, conf, data)
        self._log_event("ingest_indicator", indicator_id)
        return indicator

    def ingest_campaign(self, data: Dict[str, Any]) -> OSINTCampaignModel:
        """Ingest and normalize an OSINT Campaign."""
        self._validate_security_boundaries()
        self.validate_external_data(data)

        campaign_id = str(data.get("campaign_id") or data.get("id") or f"CAMP-{len(self._campaigns) + 1:04d}").strip()
        source_id = str(data.get("source_id") or data.get("source") or "osint-feed").strip()
        conf = self.normalize_confidence(data.get("confidence"), 0.8)

        existing = self._campaigns.get(campaign_id)
        if existing is not None:
            sources = self._merge_sources(existing.sources, source_id)
            merged_conf = self._compute_entity_confidence(campaign_id, conf, len(sources))
            campaign = OSINTCampaignModel(
                campaign_id=campaign_id,
                stix_id=data.get("stix_id") or existing.stix_id,
                name=existing.name,
                aliases=list(dict.fromkeys(existing.aliases + list(data.get("aliases", [])))),
                description=data.get("description") or existing.description,
                objective=data.get("objective") or existing.objective,
                targeted_sectors=list(dict.fromkeys(existing.targeted_sectors + list(data.get("targeted_sectors", [])))),
                first_seen=existing.first_seen or data.get("first_seen"),
                last_seen=data.get("last_seen") or existing.last_seen,
                sources=sources,
                corroboration_count=len(sources),
                confidence=merged_conf,
                verification_status=self._classify_verification(merged_conf),
                tlp_marking=data.get("tlp_marking", existing.tlp_marking),
                provenance=data.get("provenance", existing.provenance),
                experimental_label=self.experimental_label,
                tenant_id=self.tenant_id,
            )
        else:
            sources = [source_id]
            campaign = OSINTCampaignModel(
                campaign_id=campaign_id,
                stix_id=data.get("stix_id"),
                name=str(data.get("name", campaign_id)),
                aliases=list(data.get("aliases", [])),
                description=data.get("description"),
                objective=data.get("objective"),
                targeted_sectors=list(data.get("targeted_sectors", [])),
                first_seen=data.get("first_seen"),
                last_seen=data.get("last_seen"),
                sources=sources,
                corroboration_count=1,
                confidence=conf,
                verification_status=self._classify_verification(conf),
                tlp_marking=data.get("tlp_marking", "TLP:CLEAR"),
                provenance=data.get("provenance", f"osint:{source_id}"),
                experimental_label=self.experimental_label,
                tenant_id=self.tenant_id,
            )

        self._campaigns[campaign_id] = campaign
        self._record_observation(campaign_id, "campaign", source_id, conf, data)
        self._log_event("ingest_campaign", campaign_id)
        return campaign

    def ingest_malware(self, data: Dict[str, Any]) -> OSINTMalwareModel:
        """Ingest and normalize an OSINT Malware / Tool entity."""
        self._validate_security_boundaries()
        self.validate_external_data(data)

        malware_id = str(data.get("malware_id") or data.get("id") or f"MAL-{len(self._malware) + 1:04d}").strip()
        source_id = str(data.get("source_id") or data.get("source") or "osint-feed").strip()
        conf = self.normalize_confidence(data.get("confidence"), 0.85)

        existing = self._malware.get(malware_id)
        if existing is not None:
            sources = self._merge_sources(existing.sources, source_id)
            merged_conf = self._compute_entity_confidence(malware_id, conf, len(sources))
            malware = OSINTMalwareModel(
                malware_id=malware_id,
                stix_id=data.get("stix_id") or existing.stix_id,
                name=existing.name,
                is_family=bool(data.get("is_family", existing.is_family)),
                malware_types=list(dict.fromkeys(existing.malware_types + list(data.get("malware_types", [])))),
                aliases=list(dict.fromkeys(existing.aliases + list(data.get("aliases", [])))),
                capabilities=list(dict.fromkeys(existing.capabilities + list(data.get("capabilities", [])))),
                architecture_execution_envs=list(dict.fromkeys(existing.architecture_execution_envs + list(data.get("architecture_execution_envs", [])))),
                first_seen=existing.first_seen or data.get("first_seen"),
                last_seen=data.get("last_seen") or existing.last_seen,
                sources=sources,
                corroboration_count=len(sources),
                confidence=merged_conf,
                verification_status=self._classify_verification(merged_conf),
                tlp_marking=data.get("tlp_marking", existing.tlp_marking),
                provenance=data.get("provenance", existing.provenance),
                experimental_label=self.experimental_label,
                tenant_id=self.tenant_id,
            )
        else:
            sources = [source_id]
            malware = OSINTMalwareModel(
                malware_id=malware_id,
                stix_id=data.get("stix_id"),
                name=str(data.get("name", malware_id)),
                is_family=bool(data.get("is_family", True)),
                malware_types=list(data.get("malware_types", [])),
                aliases=list(data.get("aliases", [])),
                capabilities=list(data.get("capabilities", [])),
                architecture_execution_envs=list(data.get("architecture_execution_envs", [])),
                first_seen=data.get("first_seen"),
                last_seen=data.get("last_seen"),
                sources=sources,
                corroboration_count=1,
                confidence=conf,
                verification_status=self._classify_verification(conf),
                tlp_marking=data.get("tlp_marking", "TLP:CLEAR"),
                provenance=data.get("provenance", f"osint:{source_id}"),
                experimental_label=self.experimental_label,
                tenant_id=self.tenant_id,
            )

        self._malware[malware_id] = malware
        self._record_observation(malware_id, "malware", source_id, conf, data)
        self._log_event("ingest_malware", malware_id)
        return malware

    def ingest_infrastructure(self, data: Dict[str, Any]) -> OSINTInfrastructureModel:
        """Ingest and normalize an OSINT Adversary Infrastructure entity."""
        self._validate_security_boundaries()
        self.validate_external_data(data)

        infra_id = str(data.get("infrastructure_id") or data.get("id") or f"INFRA-{len(self._infrastructure) + 1:04d}").strip()
        source_id = str(data.get("source_id") or data.get("source") or "osint-feed").strip()
        conf = self.normalize_confidence(data.get("confidence"), 0.8)

        existing = self._infrastructure.get(infra_id)
        if existing is not None:
            sources = self._merge_sources(existing.sources, source_id)
            merged_conf = self._compute_entity_confidence(infra_id, conf, len(sources))
            infra = OSINTInfrastructureModel(
                infrastructure_id=infra_id,
                stix_id=data.get("stix_id") or existing.stix_id,
                name=existing.name,
                infrastructure_types=list(dict.fromkeys(existing.infrastructure_types + list(data.get("infrastructure_types", [])))),
                aliases=list(dict.fromkeys(existing.aliases + list(data.get("aliases", [])))),
                description=data.get("description") or existing.description,
                kill_chain_phases=list(dict.fromkeys(existing.kill_chain_phases + list(data.get("kill_chain_phases", [])))),
                first_seen=existing.first_seen or data.get("first_seen"),
                last_seen=data.get("last_seen") or existing.last_seen,
                sources=sources,
                corroboration_count=len(sources),
                confidence=merged_conf,
                verification_status=self._classify_verification(merged_conf),
                tlp_marking=data.get("tlp_marking", existing.tlp_marking),
                provenance=data.get("provenance", existing.provenance),
                experimental_label=self.experimental_label,
                tenant_id=self.tenant_id,
            )
        else:
            sources = [source_id]
            infra = OSINTInfrastructureModel(
                infrastructure_id=infra_id,
                stix_id=data.get("stix_id"),
                name=str(data.get("name", infra_id)),
                infrastructure_types=list(data.get("infrastructure_types", ["command-and-control"])),
                aliases=list(data.get("aliases", [])),
                description=data.get("description"),
                kill_chain_phases=list(data.get("kill_chain_phases", [])),
                first_seen=data.get("first_seen"),
                last_seen=data.get("last_seen"),
                sources=sources,
                corroboration_count=1,
                confidence=conf,
                verification_status=self._classify_verification(conf),
                tlp_marking=data.get("tlp_marking", "TLP:CLEAR"),
                provenance=data.get("provenance", f"osint:{source_id}"),
                experimental_label=self.experimental_label,
                tenant_id=self.tenant_id,
            )

        self._infrastructure[infra_id] = infra
        self._record_observation(infra_id, "infrastructure", source_id, conf, data)
        self._log_event("ingest_infrastructure", infra_id)
        return infra

    def ingest_relationship(self, data: Dict[str, Any]) -> OSINTRelationshipModel:
        """Ingest and normalize an OSINT Relationship between threat entities."""
        self._validate_security_boundaries()
        self.validate_external_data(data)

        rel_id = str(data.get("relationship_id") or data.get("id") or f"REL-{len(self._relationships) + 1:04d}").strip()
        source_id = str(data.get("source_id") or data.get("source") or "osint-feed").strip()
        conf = self.normalize_confidence(data.get("confidence"), 0.8)

        existing = self._relationships.get(rel_id)
        if existing is not None:
            sources = self._merge_sources(existing.sources, source_id)
            merged_conf = self._compute_entity_confidence(rel_id, conf, len(sources))
            rel = OSINTRelationshipModel(
                relationship_id=rel_id,
                stix_id=data.get("stix_id") or existing.stix_id,
                source_entity_id=existing.source_entity_id,
                source_entity_type=existing.source_entity_type,
                target_entity_id=existing.target_entity_id,
                target_entity_type=existing.target_entity_type,
                relationship_type=existing.relationship_type,
                description=data.get("description") or existing.description,
                start_time=existing.start_time or data.get("start_time"),
                stop_time=data.get("stop_time") or existing.stop_time,
                sources=sources,
                corroboration_count=len(sources),
                confidence=merged_conf,
                verification_status=self._classify_verification(merged_conf),
                provenance=data.get("provenance", existing.provenance),
                experimental_label=self.experimental_label,
                tenant_id=self.tenant_id,
            )
        else:
            sources = [source_id]
            rel = OSINTRelationshipModel(
                relationship_id=rel_id,
                stix_id=data.get("stix_id"),
                source_entity_id=str(data.get("source_entity_id", "")),
                source_entity_type=str(data.get("source_entity_type", "unknown")),
                target_entity_id=str(data.get("target_entity_id", "")),
                target_entity_type=str(data.get("target_entity_type", "unknown")),
                relationship_type=str(data.get("relationship_type", "RELATED_TO")),
                description=data.get("description"),
                start_time=data.get("start_time"),
                stop_time=data.get("stop_time"),
                sources=sources,
                corroboration_count=1,
                confidence=conf,
                verification_status=self._classify_verification(conf),
                provenance=data.get("provenance", f"osint:{source_id}"),
                experimental_label=self.experimental_label,
                tenant_id=self.tenant_id,
            )

        self._relationships[rel_id] = rel
        self._record_observation(rel_id, "relationship", source_id, conf, data)
        self._log_event("ingest_relationship", rel_id)
        return rel

    def ingest_stix21_bundle(
        self, bundle: Dict[str, Any], source_id: str = "stix21-osint-feed"
    ) -> Dict[str, Any]:
        """
        Ingest a complete STIX 2.1 bundle containing threat-actors, intrusion-sets,
        indicators, campaigns, malware, infrastructure, and relationships.
        """
        compat = self.evaluate_stix_taxii_compatibility(bundle, is_taxii_envelope=False)
        if not compat.is_stix21_compatible:
            raise ValueError(f"Incompatible STIX 2.1 bundle: {compat.validation_errors}")

        return self._ingest_stix_objects(bundle.get("objects", []), source_id=source_id, compatibility=compat)

    def ingest_taxii21_envelope(
        self,
        collection: TAXII21CollectionModel,
        envelope_data: Dict[str, Any],
        api_root: str = "/taxii2/api1/",
        source_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Ingest a TAXII 2.1 paginated envelope for a collection and update checkpoint sync state.
        """
        if not collection.can_read:
            raise SecurityError(f"TAXII 2.1 collection '{collection.id}' does not permit read access")

        compat = self.evaluate_stix_taxii_compatibility(envelope_data, is_taxii_envelope=True)
        if not compat.is_taxii21_compatible:
            raise ValueError(f"Incompatible TAXII 2.1 envelope: {compat.validation_errors}")

        envelope = TAXII21EnvelopeModel(
            more=bool(envelope_data.get("more", False)),
            next=envelope_data.get("next"),
            objects=list(envelope_data.get("objects", [])),
        )
        effective_source = source_id or f"taxii21:{collection.id}"
        ingested = self._ingest_stix_objects(envelope.objects, source_id=effective_source, compatibility=compat)

        now = datetime.utcnow()
        prev_state = self._taxii_sync_states.get(collection.id)
        total_count = (prev_state.objects_ingested if prev_state else 0) + len(envelope.objects)
        sync_state = TAXII21SyncStateModel(
            collection_id=collection.id,
            api_root=api_root,
            next_cursor=envelope.next,
            last_attempted_sync=now,
            last_successful_sync=now,
            objects_ingested=total_count,
            sync_status="synced_fixture",
            verification_mode=self.verification_mode,
            experimental_label=self.experimental_label,
            tenant_id=self.tenant_id,
        )
        self._taxii_sync_states[collection.id] = sync_state
        ingested["taxii_sync_state"] = sync_state
        return ingested

    def _ingest_stix_objects(
        self,
        objects: List[Dict[str, Any]],
        source_id: str,
        compatibility: STIX21CompatibilityReport,
    ) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "threat_actors": [],
            "indicators": [],
            "campaigns": [],
            "malware": [],
            "infrastructure": [],
            "relationships": [],
            "compatibility": compatibility,
            "verification_mode": self.verification_mode,
        }
        stix_type_map: Dict[str, str] = {}

        for obj in objects:
            if not isinstance(obj, dict):
                continue
            otype = obj.get("type", "")
            sid = obj.get("id", "")
            tlp = self._resolve_stix_tlp(obj.get("object_marking_refs", []))
            conf = self.normalize_confidence(obj.get("confidence"), 0.8)

            if otype in ("threat-actor", "intrusion-set"):
                stix_type_map[sid] = "ThreatActor"
                results["threat_actors"].append(
                    self.ingest_threat_actor({
                        "actor_id": sid,
                        "stix_id": sid,
                        "name": obj.get("name", sid),
                        "aliases": obj.get("aliases", []),
                        "actor_types": obj.get("threat_actor_types", []),
                        "sophistication": obj.get("sophistication"),
                        "resource_level": obj.get("resource_level"),
                        "primary_motivation": obj.get("primary_motivation"),
                        "first_seen": self._parse_dt(obj.get("first_seen")),
                        "last_seen": self._parse_dt(obj.get("last_seen")),
                        "source_id": source_id,
                        "confidence": conf,
                        "tlp_marking": tlp,
                        "provenance": f"stix21:{source_id}:{sid}",
                    })
                )
            elif otype == "indicator":
                stix_type_map[sid] = "Indicator"
                results["indicators"].append(
                    self.ingest_indicator({
                        "indicator_id": sid,
                        "stix_id": sid,
                        "stix_pattern": obj.get("pattern", ""),
                        "indicator_types": obj.get("indicator_types", []),
                        "kill_chain_phases": [
                            p.get("phase_name", "")
                            for p in obj.get("kill_chain_phases", [])
                            if isinstance(p, dict) and p.get("phase_name")
                        ],
                        "valid_from": self._parse_dt(obj.get("valid_from")) or datetime.utcnow(),
                        "valid_until": self._parse_dt(obj.get("valid_until")),
                        "source_id": source_id,
                        "confidence": conf,
                        "tlp_marking": tlp,
                        "provenance": f"stix21:{source_id}:{sid}",
                    })
                )
            elif otype == "campaign":
                stix_type_map[sid] = "Campaign"
                results["campaigns"].append(
                    self.ingest_campaign({
                        "campaign_id": sid,
                        "stix_id": sid,
                        "name": obj.get("name", sid),
                        "aliases": obj.get("aliases", []),
                        "description": obj.get("description"),
                        "objective": obj.get("objective"),
                        "first_seen": self._parse_dt(obj.get("first_seen")),
                        "last_seen": self._parse_dt(obj.get("last_seen")),
                        "source_id": source_id,
                        "confidence": conf,
                        "tlp_marking": tlp,
                        "provenance": f"stix21:{source_id}:{sid}",
                    })
                )
            elif otype in ("malware", "tool"):
                stix_type_map[sid] = "Malware"
                results["malware"].append(
                    self.ingest_malware({
                        "malware_id": sid,
                        "stix_id": sid,
                        "name": obj.get("name", sid),
                        "is_family": obj.get("is_family", True),
                        "malware_types": obj.get("malware_types", []),
                        "aliases": obj.get("aliases", []),
                        "capabilities": obj.get("capabilities", []),
                        "source_id": source_id,
                        "confidence": conf,
                        "tlp_marking": tlp,
                        "provenance": f"stix21:{source_id}:{sid}",
                    })
                )
            elif otype == "infrastructure":
                stix_type_map[sid] = "Infrastructure"
                results["infrastructure"].append(
                    self.ingest_infrastructure({
                        "infrastructure_id": sid,
                        "stix_id": sid,
                        "name": obj.get("name", sid),
                        "infrastructure_types": obj.get("infrastructure_types", ["command-and-control"]),
                        "aliases": obj.get("aliases", []),
                        "description": obj.get("description"),
                        "first_seen": self._parse_dt(obj.get("first_seen")),
                        "last_seen": self._parse_dt(obj.get("last_seen")),
                        "source_id": source_id,
                        "confidence": conf,
                        "tlp_marking": tlp,
                        "provenance": f"stix21:{source_id}:{sid}",
                    })
                )

        for obj in objects:
            if isinstance(obj, dict) and obj.get("type") == "relationship":
                sid = obj.get("id", f"relationship--{len(self._relationships) + 1}")
                sref = str(obj.get("source_ref", ""))
                tref = str(obj.get("target_ref", ""))
                conf = self.normalize_confidence(obj.get("confidence"), 0.8)
                results["relationships"].append(
                    self.ingest_relationship({
                        "relationship_id": sid,
                        "stix_id": sid,
                        "source_entity_id": sref,
                        "source_entity_type": stix_type_map.get(sref, sref.split("--")[0] if "--" in sref else "unknown"),
                        "target_entity_id": tref,
                        "target_entity_type": stix_type_map.get(tref, tref.split("--")[0] if "--" in tref else "unknown"),
                        "relationship_type": obj.get("relationship_type", "RELATED_TO"),
                        "description": obj.get("description"),
                        "start_time": self._parse_dt(obj.get("start_time")),
                        "stop_time": self._parse_dt(obj.get("stop_time")),
                        "source_id": source_id,
                        "confidence": conf,
                        "provenance": f"stix21:{source_id}:{sid}",
                    })
                )

        return results

    def parse_urlhaus_entry(self, entry: Dict[str, Any]) -> OSINTIndicatorModel:
        """Normalize an Abuse.ch URLhaus feed entry into an OSINTIndicatorModel."""
        self._validate_security_boundaries()
        self.validate_external_data(entry)
        return self.ingest_indicator({
            "indicator_id": f"URLHAUS-{entry.get('id', 'UNKNOWN')}",
            "indicator_type": "url",
            "raw_value": entry.get("url", ""),
            "indicator_types": ["malicious-activity"] + list(entry.get("tags", [])),
            "first_seen": self._parse_dt(entry.get("dateadded")),
            "source_id": "abuse_ch_urlhaus",
            "confidence": entry.get("confidence", 0.9),
            "tlp_marking": "TLP:CLEAR",
            "provenance": f"urlhaus:{entry.get('id', 'unknown')}",
        })

    def parse_malwarebazaar_entry(self, entry: Dict[str, Any]) -> Tuple[OSINTIndicatorModel, Optional[OSINTMalwareModel]]:
        """Normalize an Abuse.ch MalwareBazaar sample entry into hash indicator + optional malware family."""
        self._validate_security_boundaries()
        self.validate_external_data(entry)
        sha256_val = str(entry.get("sha256_hash", "")).strip()
        ind = self.ingest_indicator({
            "indicator_id": f"MB-{sha256_val[:16]}",
            "indicator_type": "sha256",
            "raw_value": sha256_val,
            "indicator_types": ["malicious-activity"],
            "first_seen": self._parse_dt(entry.get("first_seen")),
            "source_id": "abuse_ch_malwarebazaar",
            "confidence": entry.get("confidence", 0.95),
            "tlp_marking": "TLP:CLEAR",
            "provenance": f"malwarebazaar:{sha256_val}",
        })
        signature = entry.get("signature")
        mal = None
        if signature:
            mal = self.ingest_malware({
                "malware_id": f"MAL-{str(signature).upper()}",
                "name": str(signature),
                "is_family": True,
                "malware_types": list(entry.get("tags", ["trojan"])),
                "source_id": "abuse_ch_malwarebazaar",
                "confidence": 0.9,
                "provenance": f"malwarebazaar:{sha256_val}",
            })
        return ind, mal

    @staticmethod
    def _resolve_stix_tlp(marking_refs: Any) -> str:
        if isinstance(marking_refs, list):
            for ref in marking_refs:
                if ref in STIX21_TLP_DEFINITION_MAP:
                    return STIX21_TLP_DEFINITION_MAP[ref]
        return "TLP:CLEAR"

    @staticmethod
    def _parse_dt(val: Any) -> Optional[datetime]:
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
                return None
        return None

    def get_observations_for_entity(self, entity_id: str) -> List[OSINTObservationModel]:
        """Return append-only provenance observations for a specific entity."""
        return [o for o in self._observations if o.entity_id == entity_id]

    def get_conflicts_for_entity(self, entity_id: str) -> List[OSINTConflictRecordModel]:
        """Return recorded conflicts for a specific entity."""
        return [c for c in self._conflicts if c.entity_id == entity_id]

    def detect_duplicates(self, entity_id: str, entity_type: str) -> bool:
        """Check whether an entity ID is already present in the OSINT store."""
        store_map = {
            "threat_actor": self._threat_actors,
            "indicator": self._indicators,
            "campaign": self._campaigns,
            "malware": self._malware,
            "infrastructure": self._infrastructure,
            "relationship": self._relationships,
            "source": self._sources,
        }
        bucket = store_map.get(entity_type, {})
        return entity_id in bucket

    def record_collection_failure(self, source_id: str, error: Exception) -> None:
        """
        Record failed OSINT collection attempts without silent discard, and update
        circuit breaker state when consecutive failures reach threshold.
        """
        failures = int(self._resilience_config.get("circuit_breaker_failures", 0)) + 1
        self._resilience_config["circuit_breaker_failures"] = failures
        if failures >= int(self._resilience_config.get("circuit_breaker_threshold", 3)):
            self._resilience_config["circuit_breaker_state"] = "OPEN"
        if source_id in self._sources:
            src = self._sources[source_id]
            self._sources[source_id] = src.model_copy(update={
                "health_status": "unavailable",
                "last_attempted_sync": datetime.utcnow(),
            })
        self._failed_collections.append({
            "source_id": source_id,
            "error_type": type(error).__name__,
            "message": str(error)[:256],
            "circuit_breaker_state": self._resilience_config["circuit_breaker_state"],
            "tenant_id": self.tenant_id,
            "timestamp": datetime.utcnow(),
        })

    def reset_circuit_breaker(self) -> None:
        """Reset circuit breaker state to CLOSED after recovery verification."""
        self._resilience_config["circuit_breaker_failures"] = 0
        self._resilience_config["circuit_breaker_state"] = "CLOSED"

    def _log_event(self, action: str, entity_id: str) -> None:
        self._audit_log.append({
            "event_type": "osint_ingestion",
            "action": action,
            "entity_id": entity_id,
            "tenant_id": self.tenant_id,
            "verification_mode": self.verification_mode,
            "timestamp": datetime.utcnow(),
        })
