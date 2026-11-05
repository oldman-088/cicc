"""
Threat Intelligence Cross-Agent Integration Contracts & Interoperability Layer
Branch: arena/28e50255-cicc (Agent 6 - Full Threat Intelligence Backup Engineer)

Implements:
- Agent 1 Coordination Contract v1.0 & Issue #5 Worker Heartbeat payloads
- Agent 3 Vulnerability Intelligence correlation & M1-M6 mismatch resolutions
- Agent 4 Frontend typed DTO envelopes (list, detail, error, freshness, provenance)

Important Contract Rule:
No proposed cross-branch host mounting or shared schema migration is assumed accepted.
All adapters operate as pure, tested contract boundaries within `apps/threat_intelligence/`.
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
import re

from apps.threat_intelligence.cisa_kev import CISAKEVIngestionService, EXPERIMENTAL_DEMO_DATA_ONLY
from apps.threat_intelligence.vendor_advisories import VendorSecurityAdvisoryIngestionService

_TASK_KIND_RE = re.compile(r"^[a-z0-9_]+$")
_TASK_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

VALID_MAPPING_TYPES = {
    "exploitation_technique",
    "primary_impact",
    "secondary_impact",
    "mitigation",
}

VALID_CONSULTED_STATES = {
    "consulted_mapped",
    "consulted_unmapped",
    "not_consulted",
}


# ============================================================================
# 1. Agent 1 (Central Coordination & System Health) Contract v1.0 Models
# ============================================================================

class Agent1RegistrationPayload(BaseModel):
    """Conforms to Agent 1 POST /api/v1/coordination/agents/register (Contract v1.0 #1)"""
    model_config = ConfigDict(extra="forbid")

    agent: str = Field("agent-2-threat-intel", description="Canonical domain agent identifier")
    capabilities: List[str] = Field(
        default_factory=lambda: [
            "threat_intel_ingestion",
            "mitre_attack",
            "cisa_kev",
            "vendor_advisories",
            "osint_stix_taxii",
        ]
    )
    meta: Dict[str, Any] = Field(
        default_factory=lambda: {
            "acting_agent": "agent-6-backup",
            "primary_owner": "agent-2",
            "contract_version": "1.0",
            "verification_mode": "fixture_tested",
        }
    )


class Agent1HeartbeatPayload(BaseModel):
    """Conforms to Agent 1 POST /api/v1/coordination/agents/{agent}/heartbeat (Contract v1.0 #2)"""
    model_config = ConfigDict(extra="forbid")

    status: str = Field("online", description="online | busy | draining | offline")
    active_tasks: int = Field(0, ge=0)
    meta: Dict[str, Any] = Field(default_factory=dict)


class Agent1OpsWorkerHeartbeatPayload(BaseModel):
    """Conforms to Issue #5 POST /api/v1/ops/workers/heartbeat"""
    model_config = ConfigDict(extra="forbid")

    worker: str = Field(..., min_length=1, description="Deterministic worker identity (e.g., 'ti-worker-01')")
    queue: Optional[str] = Field("threat_intel", description="Worker queue name")
    details: Optional[str] = Field(None, description="Human-readable status detail (no secrets)")
    interval_seconds: int = Field(30, ge=10, le=60, description="Heartbeat cadence (>=30s per Issue #5)")
    stall_threshold_seconds: int = Field(120, ge=60, description="Stall threshold (default 120s = 4 missed beats)")


class Agent1TaskEnqueuePayload(BaseModel):
    """Conforms to Agent 1 POST /api/v1/coordination/tasks (Contract v1.0 #5)"""
    model_config = ConfigDict(extra="forbid")

    task_id: Optional[str] = Field(None, description="Path-safe task ID ([A-Za-z0-9_.:-], no slashes)")
    kind: str = Field(..., description="Task kind ([a-z0-9_]+)")
    title: str = Field(..., min_length=1)
    payload: Dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(5, ge=1, le=10)
    idempotency_key: Optional[str] = Field(None)
    repo: str = Field("oldman-088/cicc")
    branch_ref: str = Field("arena/28e50255-cicc")
    depends_on: List[str] = Field(default_factory=list)
    timeout_s: int = Field(3600, ge=1)
    ttl_s: int = Field(86400, ge=1)
    requires_approval: bool = Field(False)

    @field_validator("kind")
    @classmethod
    def validate_kind(cls, v: str) -> str:
        if not _TASK_KIND_RE.match(v):
            raise ValueError(f"Invalid kind '{v}': must match ^[a-z0-9_]+$")
        return v

    @field_validator("task_id")
    @classmethod
    def validate_task_id(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _TASK_ID_RE.match(v):
            raise ValueError(f"Invalid task_id '{v}': must be path-safe [A-Za-z0-9_.:-] without slashes")
        return v


# ============================================================================
# 2. Agent 3 (Vulnerability Intelligence) M1-M6 Correlation Models
# ============================================================================

class VendorAdvisoryLinkDTO(BaseModel):
    """
    Agent 3 M2 Resolution: Separate structured vendor advisory reference (never stuffed into CVE aliases).
    """
    model_config = ConfigDict(extra="forbid")

    advisory_id: str = Field(..., description="Vendor advisory ID (e.g., DSA-5678-1, RHSA-2024-0001, USN-2024-0001, MS-2024-0001)")
    vendor_source_id: str = Field(..., description="Vendor identifier (msrc, cisco, redhat, ubuntu, debian, ghsa)")
    affected_products: List[str] = Field(default_factory=list)
    affected_versions: List[str] = Field(default_factory=list)
    required_action: Optional[str] = Field(None)
    severity: Optional[str] = Field(None)
    date_published: datetime = Field(...)
    provenance: str = Field(...)
    experimental_label: Optional[str] = Field(EXPERIMENTAL_DEMO_DATA_ONLY)


class KEVVulnerabilityCorrelationDTO(BaseModel):
    """
    Agent 3 M1 & M2 Resolution:
    - Tri-state `kev`: None (not consulted), False (consulted & absent), True (consulted & present)
    - `kev_required_action`: verbatim CISA requiredAction string when present
    - `vendor_advisories`: separate tuple/list of vendor advisories referencing this CVE
    """
    model_config = ConfigDict(extra="forbid")

    cve_id: str = Field(..., description="Canonical CVE identifier (CVE-YYYY-NNNN+)")
    kev: Optional[bool] = Field(None, description="None = not consulted, False = absent, True = in CISA KEV")
    kev_date_added: Optional[datetime] = Field(None)
    kev_due_date: Optional[datetime] = Field(None)
    kev_required_action: Optional[str] = Field(None, description="Verbatim CISA requiredAction (M1 resolution)")
    known_ransomware_use: Optional[bool] = Field(None)
    vendor_advisories: List[VendorAdvisoryLinkDTO] = Field(
        default_factory=list,
        description="Separate vendor advisory records (M2 resolution: not CVE aliases)",
    )
    experimental_label: Optional[str] = Field(EXPERIMENTAL_DEMO_DATA_ONLY)


class AttackTechniqueMappingEntryDTO(BaseModel):
    """
    Agent 3 M3 & M4 Resolution:
    - Full canonical technique ID including sub-technique suffix (e.g., T1059.001)
    - Explicit CTID mapping_type (exploitation_technique, primary_impact, secondary_impact, mitigation)
    """
    model_config = ConfigDict(extra="forbid")

    technique_id: str = Field(..., description="Full canonical ATT&CK ID (^T\\d{4}(\\.\\d{3})?$)")
    name: str = Field(..., description="Technique or sub-technique name")
    mapping_type: str = Field("exploitation_technique", description="CTID mapping_type")
    comment: Optional[str] = Field(None)

    @field_validator("technique_id")
    @classmethod
    def validate_full_technique_id(cls, v: str) -> str:
        cleaned = v.strip().upper()
        if not _TECHNIQUE_ID_RE.match(cleaned):
            raise ValueError(f"Invalid ATT&CK technique_id '{v}': must match ^T\\d{4}(\\.\\d{3})?$")
        return cleaned

    @field_validator("mapping_type")
    @classmethod
    def validate_mapping_type(cls, v: str) -> str:
        low = v.strip().lower()
        if low not in VALID_MAPPING_TYPES:
            raise ValueError(f"Invalid mapping_type '{v}': must be one of {sorted(VALID_MAPPING_TYPES)}")
        return low


class CVETechniqueCorrelationDTO(BaseModel):
    """
    Agent 3 M6 Resolution:
    Always carries three-valued `consulted` ('consulted_mapped' | 'consulted_unmapped' | 'not_consulted')
    beside `techniques` so 'never looked' is never misreported as '0 techniques'.
    """
    model_config = ConfigDict(extra="forbid")

    cve_id: str = Field(...)
    consulted: str = Field(..., description="consulted_mapped | consulted_unmapped | not_consulted")
    techniques: List[AttackTechniqueMappingEntryDTO] = Field(default_factory=list)
    source: Optional[str] = Field(None)

    @field_validator("consulted")
    @classmethod
    def validate_consulted(cls, v: str) -> str:
        if v not in VALID_CONSULTED_STATES:
            raise ValueError(f"Invalid consulted state '{v}': must be one of {sorted(VALID_CONSULTED_STATES)}")
        return v


class TechniqueRollupDTO(BaseModel):
    """
    Agent 3 M3, M4, M6 Resolution:
    - `techniques`: filtered to `exploitation_technique` by default so impact/mitigation do not inflate exposure counts
    - `techniques_by_mapping_type`: additive split counts across all 4 CTID mapping types
    - `consulted`: three-valued status surfaced alongside counts
    """
    model_config = ConfigDict(extra="forbid")

    consulted: str = Field(..., description="consulted_mapped | consulted_unmapped | not_consulted")
    total_cves: int = Field(0, ge=0)
    techniques: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Exploitation techniques only (keyed by full canonical technique_id)",
    )
    techniques_by_mapping_type: Dict[str, int] = Field(
        default_factory=lambda: {
            "exploitation_technique": 0,
            "primary_impact": 0,
            "secondary_impact": 0,
            "mitigation": 0,
        }
    )


class ProvenanceSummaryDTO(BaseModel):
    """
    Agent 3 M5 Resolution:
    `sources` is the deduplicated set of source names; `observations_count` is the append-only
    observation count (`observations_count >= len(sources)`); `corroboration_count == len(sources)`.
    """
    model_config = ConfigDict(extra="forbid")

    entity_id: str = Field(...)
    sources: List[str] = Field(default_factory=list, description="Deduplicated contributing source names")
    observations_count: int = Field(0, ge=0, description="Total append-only observation records")
    corroboration_count: int = Field(0, ge=0, description="Count of distinct corroborating sources")


class DataOrigin(str, Enum):
    """Where the data came from (amendment 6: enum, not free string)."""

    EXPERIMENTAL_DEMO = EXPERIMENTAL_DEMO_DATA_ONLY
    LIVE_SOURCE = "live_source"


class VerificationMode(str, Enum):
    """Evidence level behind the data (amendment 6: enum, not free string)."""

    FIXTURE_TESTED = "fixture_tested"
    ORACLE_VERIFIED = "oracle_verified"
    LIVE_VERIFIED = "live_verified"


class HostMountStatus(str, Enum):
    """
    Whether a host has actually mounted these routes (amendment 6: enum, not free string).

    The only honest default is NOT_MOUNTED_PENDING_OWNER_APPROVAL. Nothing in this package may set
    MOUNTED_BY_HOST; that is a host-side fact a host must assert for itself.
    """

    NOT_MOUNTED_PENDING_OWNER_APPROVAL = "not_mounted_pending_owner_approval"
    MOUNTED_BY_HOST = "mounted_by_host"


class ThreatIntelEntityType(str, Enum):
    """Entity discriminator (amendment 1: `type` is a closed enum, not a free string)."""

    THREAT_ACTOR = "threat_actor"
    CAMPAIGN = "campaign"
    MALWARE = "malware"
    SOFTWARE = "software"
    INDICATOR = "indicator"
    TTP = "ttp"
    VULNERABILITY = "vulnerability"
    ADVISORY = "advisory"
    RELATIONSHIP = "relationship"
    REPORT = "report"


class FreshnessMetaDTO(BaseModel):
    """
    Explicit freshness, verification and experimental labelling metadata for UI display.

    Amendment 2: `collected_at` has NO default. A freshness field that silently defaults to "now"
    would let a caller present unsourced data as freshly collected, so the caller must supply an
    explicit timezone-aware value.
    Amendment 6: enums instead of free strings, plus `age_seconds` / `stale_after_seconds` so the
    UI can explain *why* something is stale rather than trusting a bare boolean.
    """

    model_config = ConfigDict(extra="forbid")

    origin: DataOrigin = DataOrigin.EXPERIMENTAL_DEMO
    verification_mode: VerificationMode = VerificationMode.FIXTURE_TESTED
    host_mount_status: HostMountStatus = HostMountStatus.NOT_MOUNTED_PENDING_OWNER_APPROVAL
    collected_at: datetime = Field(
        ..., description="Explicit timezone-aware collection time; never defaulted"
    )
    last_successful_sync: Optional[datetime] = Field(None)
    age_seconds: Optional[int] = Field(
        None, ge=0, description="Data age at response time; None when unknown"
    )
    stale_after_seconds: Optional[int] = Field(None, ge=1, description="Declared staleness horizon")
    is_stale: bool = Field(False)

    @field_validator("collected_at", "last_successful_sync")
    @classmethod
    def _require_tz(cls, v: Optional[datetime]) -> Optional[datetime]:
        """Amendment 2: reject naive timestamps rather than guessing their zone."""
        if v is not None and v.tzinfo is None:
            raise ValueError(
                "timestamps must be timezone-aware ISO-8601; a naive datetime would be "
                "interpreted against an unknown host zone"
            )
        return v

    @model_validator(mode="after")
    def _staleness_must_be_declared(self) -> "FreshnessMetaDTO":
        """`is_stale` may only be True when a horizon was actually declared."""
        if self.is_stale and self.stale_after_seconds is None:
            raise ValueError("is_stale=True requires stale_after_seconds to be declared")
        if (
            self.is_stale
            and self.stale_after_seconds is not None
            and self.age_seconds is not None
            and self.age_seconds <= self.stale_after_seconds
        ):
            raise ValueError("is_stale=True contradicts age_seconds <= stale_after_seconds")
        return self


class PaginationMetaDTO(BaseModel):
    """
    Opaque cursor pagination metadata.

    Amendment 5: `total_count` is nullable because totals are frequently unknown under cursoring.
    `next_cursor is not None` is the single source of truth for "there is more"; `has_more` is a
    derived convenience that can never contradict it.
    """

    model_config = ConfigDict(extra="forbid")

    limit: int = Field(50, ge=1, le=500)
    total_count: Optional[int] = Field(
        None, ge=0, description="None when the total is unknown under cursoring"
    )
    next_cursor: Optional[str] = Field(
        None, description="Non-null is the authoritative has_more signal"
    )

    @property
    def has_more(self) -> bool:
        return self.next_cursor is not None


class ProvenanceRefDTO(BaseModel):
    """Per-record provenance pointer (amendment 7: provenance on list items, not only on detail)."""

    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(..., min_length=1, max_length=256)
    observation_count: int = Field(1, ge=0)
    source_reference: Optional[str] = Field(None, max_length=512)
    retrieved_at: Optional[datetime] = None


class ConfidenceDTO(BaseModel):
    """
    Confidence kept separate from verification (amendment 1).

    `score` is analytical confidence in the value. `verification_mode` is evidence about where the
    data came from. Conflating them lets a low-evidence record masquerade as trustworthy.
    """

    model_config = ConfigDict(extra="forbid")

    score: float = Field(0.0, ge=0.0, le=1.0)
    verification_mode: VerificationMode = VerificationMode.FIXTURE_TESTED
    corroborating_source_count: int = Field(0, ge=0)
    conflict_open: bool = Field(
        False, description="True when sources disagree and the disagreement is unresolved"
    )


class ThreatIntelEntityDTO(BaseModel):
    """
    Base typed entity DTO (amendment 1).

    Every list and detail payload carries these fields instead of an opaque `Dict[str, Any]`, so
    the frontend has a real schema to runtime-validate against.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, max_length=512)
    type: ThreatIntelEntityType
    name: Optional[str] = Field(
        None, max_length=512, description="None when the entity has no display name"
    )
    confidence: ConfidenceDTO = Field(default_factory=ConfidenceDTO)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    provenance: List[ProvenanceRefDTO] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(
        default_factory=dict,
        description="Type-specific fields; the typed base above is always present",
    )

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _require_tz(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is not None and v.tzinfo is None:
            raise ValueError("first_seen/last_seen must be timezone-aware ISO-8601")
        return v


class ThreatIntelListEnvelope(BaseModel):
    """
    Typed list response envelope.

    Amendment 1: `data` is a list of typed entity DTOs, not `List[Dict[str, Any]]`.
    Amendment 3: `tenant_id` is deliberately absent. The frontend must never supply or trust
    tenant identity, so it is not offered in a frontend-facing envelope at all.
    """

    model_config = ConfigDict(extra="forbid")

    data: List[ThreatIntelEntityDTO] = Field(default_factory=list)
    page: PaginationMetaDTO = Field(default_factory=PaginationMetaDTO)
    freshness: FreshnessMetaDTO = Field(...)
    contract_version: str = Field("1.1.0-proposed", description="Bumped by the amendment set")


class ThreatIntelDetailEnvelope(BaseModel):
    """
    Typed detail response envelope.

    Amendment 3: no `tenant_id`.
    Amendment 7: `provenance_summary` is nullable - an entity with no recorded provenance reports
    None rather than being forced to fabricate one.
    """

    model_config = ConfigDict(extra="forbid")

    data: ThreatIntelEntityDTO = Field(...)
    provenance_summary: Optional[ProvenanceSummaryDTO] = Field(
        None, description="None when no provenance is recorded; never fabricated"
    )
    freshness: FreshnessMetaDTO = Field(...)
    contract_version: str = Field("1.1.0-proposed")


class ThreatIntelErrorBody(BaseModel):
    """The nested `error` object, matching the CICC BFF `{error: {code}}` shape (amendment 4)."""

    model_config = ConfigDict(extra="forbid")

    code: str = Field(..., min_length=1, max_length=128, description="Stable machine-readable code")
    message: str = Field(
        ..., min_length=1, max_length=1000, description="Safe for display; no internal details"
    )
    correlation_id: Optional[str] = Field(
        None, max_length=128, description="Ties a client report to server logs"
    )
    details: Optional[Dict[str, Any]] = Field(
        None, description="Structured, safe-for-display field errors only"
    )
    retry_after_seconds: Optional[int] = Field(None, ge=0, description="Populated for 429 and 503")


class ThreatIntelErrorEnvelope(BaseModel):
    """
    Typed error envelope aligned with the CICC BFF error model (amendment 4).

    Serialises as `{"error": {"code": ..., "message": ...}}` so one frontend error model works
    across domains. Internal exception text must never reach `message`.
    """

    model_config = ConfigDict(extra="forbid")

    status: int = Field(..., ge=400, le=599)
    error: ThreatIntelErrorBody = Field(...)

    @model_validator(mode="after")
    def _retry_after_consistency(self) -> "ThreatIntelErrorEnvelope":
        """429/503 must tell the client how long to wait; other statuses must not imply it."""
        if self.status in (429, 503) and self.error.retry_after_seconds is None:
            raise ValueError(f"status {self.status} requires error.retry_after_seconds")
        if self.status not in (429, 503) and self.error.retry_after_seconds is not None:
            raise ValueError(f"retry_after_seconds is not meaningful for status {self.status}")
        return self

    def to_response_body(self) -> Dict[str, Any]:
        """The exact JSON body a host should return."""
        return {"error": self.error.model_dump(exclude_none=True)}
# ============================================================================
# 4. Cross-Domain Integration Bridge Service
# ============================================================================

class ThreatIntelligenceIntegrationBridge:
    """
    Coordinates Threat Intelligence data across:
    - Agent 1 (Central Coordination & System Health)
    - Agent 3 (Vulnerability Intelligence M1-M6 contracts)
    - Agent 4 (Frontend typed DTO envelopes)
    """

    def __init__(
        self,
        kev_service: Optional[CISAKEVIngestionService] = None,
        advisory_service: Optional[VendorSecurityAdvisoryIngestionService] = None,
        tenant_id: Optional[str] = None,
    ):
        self.kev_service = kev_service
        self.advisory_service = advisory_service
        self.tenant_id = tenant_id

    def build_agent1_registration(self) -> Agent1RegistrationPayload:
        return Agent1RegistrationPayload()

    def build_agent1_ops_heartbeat(
        self, worker_id: str = "threat-intel-worker-01", details: str = "fixture_tested_ready"
    ) -> Agent1OpsWorkerHeartbeatPayload:
        return Agent1OpsWorkerHeartbeatPayload(
            worker=worker_id,
            queue="threat_intel",
            details=details,
        )

    def correlate_cve_kev_and_advisories(
        self, cve_id: str, kev_consulted: bool = True
    ) -> KEVVulnerabilityCorrelationDTO:
        """
        Produce an M1 + M2 compliant correlation record for a CVE.
        If `kev_consulted` is False or `kev_service` is None, `kev` is `None` (not consulted),
        never falsely reporting `False` when KEV was not checked.
        """
        norm_cve = cve_id.strip().upper()
        advisories: List[VendorAdvisoryLinkDTO] = []
        if self.advisory_service is not None:
            for adv in self.advisory_service.get_advisories_for_cve(norm_cve):
                advisories.append(
                    VendorAdvisoryLinkDTO(
                        advisory_id=adv.advisory_id,
                        vendor_source_id=adv.vendor_source_id,
                        affected_products=list(adv.affected_products),
                        affected_versions=list(adv.affected_versions),
                        required_action=adv.required_action,
                        severity=adv.severity,
                        date_published=adv.date_published,
                        provenance=adv.provenance,
                        experimental_label=adv.experimental_label,
                    )
                )

        if not kev_consulted or self.kev_service is None:
            return KEVVulnerabilityCorrelationDTO(
                cve_id=norm_cve,
                kev=None,
                vendor_advisories=advisories,
            )

        kev_rec = self.kev_service.get_by_cve(norm_cve)
        if kev_rec is None:
            return KEVVulnerabilityCorrelationDTO(
                cve_id=norm_cve,
                kev=False,
                vendor_advisories=advisories,
            )

        return KEVVulnerabilityCorrelationDTO(
            cve_id=norm_cve,
            kev=True,
            kev_date_added=kev_rec.date_added,
            kev_due_date=kev_rec.due_date,
            kev_required_action=kev_rec.required_action,
            known_ransomware_use=kev_rec.known_ransomware_use,
            vendor_advisories=advisories,
            experimental_label=kev_rec.experimental_label,
        )

    @staticmethod
    def build_technique_rollup(
        correlations: List[CVETechniqueCorrelationDTO], mapping_loaded: bool = True
    ) -> TechniqueRollupDTO:
        """
        Compute M3, M4, M6 compliant ATT&CK technique rollup:
        - Keys on full canonical technique_id (never truncating T1059.001 into T1059)
        - Filters default `techniques` list to `exploitation_technique`
        - Populates `techniques_by_mapping_type` across all 4 CTID mapping types
        - Surfaces three-valued `consulted` status
        """
        split_counts: Dict[str, int] = {
            "exploitation_technique": 0,
            "primary_impact": 0,
            "secondary_impact": 0,
            "mitigation": 0,
        }
        if not mapping_loaded or not correlations or all(c.consulted == "not_consulted" for c in correlations):
            return TechniqueRollupDTO(
                consulted="not_consulted",
                total_cves=len(correlations),
                techniques=[],
                techniques_by_mapping_type=split_counts,
            )

        exploitation_by_id: Dict[str, Dict[str, Any]] = {}
        any_mapped = False

        for corr in correlations:
            for tech in corr.techniques:
                any_mapped = True
                split_counts[tech.mapping_type] = split_counts.get(tech.mapping_type, 0) + 1
                if tech.mapping_type == "exploitation_technique":
                    entry = exploitation_by_id.setdefault(
                        tech.technique_id,
                        {
                            "technique_id": tech.technique_id,
                            "name": tech.name,
                            "mapping_type": "exploitation_technique",
                            "cve_count": 0,
                            "cves": [],
                        },
                    )
                    if corr.cve_id not in entry["cves"]:
                        entry["cves"].append(corr.cve_id)
                        entry["cve_count"] += 1

        consulted_state = "consulted_mapped" if any_mapped else "consulted_unmapped"
        return TechniqueRollupDTO(
            consulted=consulted_state,
            total_cves=len(correlations),
            techniques=list(exploitation_by_id.values()),
            techniques_by_mapping_type=split_counts,
        )

    @staticmethod
    def summarize_provenance(entity_id: str, observation_sources: List[str]) -> ProvenanceSummaryDTO:
        """
        Compute M5 compliant provenance summary from an ordered list of observation source IDs.
        `sources` is deduplicated; `observations_count == len(observation_sources)`;
        `corroboration_count == len(sources)`.
        """
        dedup_sources = list(dict.fromkeys(s for s in observation_sources if s))
        return ProvenanceSummaryDTO(
            entity_id=entity_id,
            sources=dedup_sources,
            observations_count=len(observation_sources),
            corroboration_count=len(dedup_sources),
        )
