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
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, ConfigDict, Field, field_validator
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


# ============================================================================
# 3. Agent 4 (Frontend) Typed Response & Error Envelopes (PR #3 Coordination)
# ============================================================================

class FreshnessMetaDTO(BaseModel):
    """Explicit freshness, verification, and experimental labeling metadata for UI display"""
    model_config = ConfigDict(extra="forbid")

    origin: str = Field(EXPERIMENTAL_DEMO_DATA_ONLY, description="EXPERIMENTAL_DEMO_DATA_ONLY | live_source")
    verification_mode: str = Field("fixture_tested", description="fixture_tested | oracle_verified | live_verified")
    host_mount_status: str = Field(
        "not_mounted_pending_owner_approval",
        description="Explicitly informs frontend that Threat Intel HTTP routes are package-level until mounted",
    )
    collected_at: datetime = Field(default_factory=datetime.utcnow)
    last_successful_sync: Optional[datetime] = Field(None)
    is_stale: bool = Field(False)


class PaginationMetaDTO(BaseModel):
    """Opaque cursor pagination metadata"""
    model_config = ConfigDict(extra="forbid")

    limit: int = Field(50, ge=1, le=500)
    total_count: int = Field(0, ge=0)
    next_cursor: Optional[str] = Field(None)


class ThreatIntelListEnvelope(BaseModel):
    """Typed list response envelope for Threat Intelligence entities"""
    model_config = ConfigDict(extra="forbid")

    data: List[Dict[str, Any]] = Field(default_factory=list)
    page: PaginationMetaDTO = Field(default_factory=PaginationMetaDTO)
    freshness: FreshnessMetaDTO = Field(default_factory=FreshnessMetaDTO)
    tenant_id: Optional[str] = Field(None)


class ThreatIntelDetailEnvelope(BaseModel):
    """Typed detail response envelope for a single Threat Intelligence entity"""
    model_config = ConfigDict(extra="forbid")

    data: Dict[str, Any] = Field(...)
    provenance_summary: ProvenanceSummaryDTO = Field(...)
    freshness: FreshnessMetaDTO = Field(default_factory=FreshnessMetaDTO)
    tenant_id: Optional[str] = Field(None)


class ThreatIntelErrorEnvelope(BaseModel):
    """Typed error envelope for Threat Intelligence API responses"""
    model_config = ConfigDict(extra="forbid")

    status: int = Field(..., ge=400, le=599)
    error_code: str = Field(...)
    message: str = Field(...)
    details: Optional[Dict[str, Any]] = Field(None)


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
