"""
CICC Threat Intelligence Domain (P1-01 ... P1-04 + cross-agent integration contracts).

This package is the Threat Intelligence implementation surface for
`oldman-088/cicc`. It is deliberately framework-free: every module exposes
Pydantic v2 models plus a service class that performs in-memory, auditable,
provenance-preserving ingestion. Persistence (PostgreSQL/SQLAlchemy), HTTP
routing (FastAPI), and background workers are *integration contracts only* and
are NOT mounted by this package.

Experimental labeling:
    All ingested records are tagged ``EXPERIMENTAL_DEMO_DATA_ONLY`` unless a
    live, externally verified source is explicitly wired by the platform owner.
    No module in this package performs outbound network requests; every
    verification result is reported as ``fixture_tested`` unless a live source
    is actually contacted by the caller.

Branch provenance:
    Recovered and extended from Agent 2 commits ``933b29f``, ``805cd2b`` and
    ``1a46f70`` (PR #3, branch ``arena/93315d2c-cicc``) and continued by
    Agent 6 on ``arena/28e50255-cicc``.
"""

from apps.threat_intelligence.campaigns import (
    EXPERIMENTAL_DEMO_DATA_ONLY,
    CampaignModel,
    CampaignService,
)
from apps.threat_intelligence.cisa_kev import (
    CISAKEVHistoryModel,
    CISAKEVIngestionService,
    CISAKEVRecordModel,
    CISAKEVSourceModel,
)
from apps.threat_intelligence.collection import (
    CollectionService,
    CollectionTaskModel,
    NormalizationRecordModel,
)
from apps.threat_intelligence.enrichment import (
    IntelligenceEnrichmentModel,
    IntelligenceEnrichmentService,
    IntelligenceSourceModel,
)
from apps.threat_intelligence.integration_contracts import (
    VALID_CONSULTED_STATES,
    VALID_MAPPING_TYPES,
    Agent1HeartbeatPayload,
    Agent1OpsWorkerHeartbeatPayload,
    Agent1RegistrationPayload,
    Agent1TaskEnqueuePayload,
    AttackTechniqueMappingEntryDTO,
    CVETechniqueCorrelationDTO,
    FreshnessMetaDTO,
    KEVVulnerabilityCorrelationDTO,
    PaginationMetaDTO,
    ProvenanceSummaryDTO,
    TechniqueRollupDTO,
    ThreatIntelligenceIntegrationBridge,
    ThreatIntelDetailEnvelope,
    ThreatIntelErrorEnvelope,
    ThreatIntelListEnvelope,
    VendorAdvisoryLinkDTO,
)
from apps.threat_intelligence.malware import (
    MalwareModel,
    MalwareService,
)
from apps.threat_intelligence.mitre_ingestion import (
    MITREFrameworkModel,
    MITREGroupModel,
    MITREIngestionService,
    MITRERelationshipModel,
    MITRESoftwareModel,
    MITRETacticModel,
    MITRETechniqueModel,
)
from apps.threat_intelligence.mitre_ingestion import SecurityError as MITREIngestionSecurityError
from apps.threat_intelligence.mitre_mapping import (
    MITREMappingModel,
    MITREMappingService,
)
from apps.threat_intelligence.osint_sources import (
    OSINTCampaignModel,
    OSINTConflictRecordModel,
    OSINTIndicatorModel,
    OSINTIngestionService,
    OSINTInfrastructureModel,
    OSINTMalwareModel,
    OSINTObservationModel,
    OSINTRelationshipModel,
    OSINTSourceModel,
    OSINTThreatActorModel,
    STIX21CompatibilityReport,
    TAXII21CollectionModel,
    TAXII21EnvelopeModel,
    TAXII21ManifestEntryModel,
    TAXII21SyncStateModel,
)
from apps.threat_intelligence.osint_sources import SecurityError
from apps.threat_intelligence.persistence import (
    APPEND_ONLY_TABLES,
    SCHEMA_SQL,
    AppendOnlyViolationError,
    AuditRecord,
    ConflictRecord,
    EntityHistoryRecord,
    EntityPage,
    PersistenceError,
    SQLiteThreatIntelRepository,
    StoredEntityRecord,
    StoredObservation,
    TenantIsolationError,
    ThreatIntelRepository,
    repository_from_url,
)
from apps.threat_intelligence.relationships import (
    RelationshipModel,
    RelationshipService,
)
from apps.threat_intelligence.collection_workers import (
    TERMINAL_STATES,
    CircuitBreakerConfig,
    CollectionJob,
    CollectionWorker,
    CollectionWorkerError,
    JobEvent,
    JobNotLeasableError,
    JobState,
    LeaseConflictError,
    RetryPolicy,
    SourceCircuitBreaker,
    UnknownJobError,
    WorkerMetrics,
    derive_idempotency_key,
)
from apps.threat_intelligence.api_surface import (
    API_CONTRACT_VERSION,
    API_PREFIX,
    ROUTES,
    ApiNotFoundError,
    ApiResponse,
    ApiSurfaceNotMountedError,
    ApiUnauthorizedError,
    ApiValidationError,
    HttpMethod,
    RequestContext,
    RouteSpec,
    ThreatIntelApiSurface,
    build_fastapi_router,
)
from apps.threat_intelligence.source_reliability import (
    VERIFICATION_RANK,
    FreshnessPolicy,
    FreshnessState,
    ReliabilityTier,
    SourceAvailability,
    SourceOutcome,
    SourceReliabilityError,
    SourceReliabilityRecord,
    SourceReliabilityService,
    VerificationEvidence,
    VerificationPromotionError,
)
from apps.threat_intelligence.contract_registry import (
    ContractDependency,
    ContractNotAcceptedError,
    ContractRegistry,
    ContractRegistryError,
    ContractStatus,
    OwnerAcceptanceError,
    default_registry,
)
from apps.threat_intelligence.reports import (
    DuplicateReportError,
    ReportAppendOnlyViolationError,
    ReportClassification,
    ReportEntityReference,
    ReportEvidenceRef,
    ReportHistoryEntry,
    ReportKind,
    ReportOrigin,
    ReportRelationshipRef,
    ReportSourceAttribution,
    ReportStatus,
    ReportValidationError,
    ReportVerificationMode,
    ThreatIntelReport,
    ThreatIntelReportService,
)
from apps.threat_intelligence.relationship_analysis import (
    AssertionOrigin,
    AssertionStatus,
    ContradictionRecord,
    ContradictionSummary,
    Direction,
    DuplicateGroup,
    EvidenceItem,
    PathResult,
    RelationshipAnalysisService,
    RelationshipAssertion,
    RelationshipError,
    RelationshipSemantics,
    TraversalResult,
    build_default_semantics,
)
from apps.threat_intelligence.conflict_resolution import (
    ClaimOrigin,
    ConflictError,
    ConflictResolutionRecord,
    ConflictResolutionService,
    ConflictState,
    ResolvedValue,
    ResolutionStrategy,
    SourceClaim,
)
from apps.threat_intelligence.observability import (
    DomainHealthSnapshot,
    DomainObservabilityEvent,
    ObservabilityError,
    SourceHealth,
    SourceHealthView,
    ThreatIntelObservabilityService,
)
from apps.threat_intelligence.live_source_readiness import (
    LIVE_OPT_IN_ENV,
    FetchedPayload,
    FetchPlan,
    LiveAccessRefusedError,
    LiveSourceError,
    LiveSourceGate,
    LiveSourcePolicy,
    LiveSourceReadinessService,
    PayloadStatus,
    ProvenanceStampedRecord,
    SourceSchema,
)
from apps.threat_intelligence.threat_actors import (
    ThreatActorModel,
    ThreatActorService,
)
from apps.threat_intelligence.ttps import (
    TTPModel,
    TTPService,
)
from apps.threat_intelligence.vendor_advisories import (
    VendorSecurityAdvisoryHistoryModel,
    VendorSecurityAdvisoryIngestionService,
    VendorSecurityAdvisoryRecordModel,
    VendorSecurityAdvisorySourceModel,
)

__version__ = "1.3.0"

__all__ = [
    # P1-00 core entity modules
    "EXPERIMENTAL_DEMO_DATA_ONLY",
    "ThreatActorModel",
    "ThreatActorService",
    "MalwareModel",
    "MalwareService",
    "CampaignModel",
    "CampaignService",
    "TTPModel",
    "TTPService",
    "MITREMappingModel",
    "MITREMappingService",
    # Extended layers (relationships / enrichment / collection)
    "RelationshipModel",
    "RelationshipService",
    "IntelligenceSourceModel",
    "IntelligenceEnrichmentModel",
    "IntelligenceEnrichmentService",
    "CollectionTaskModel",
    "NormalizationRecordModel",
    "CollectionService",
    # P1-01 MITRE ATT&CK ingestion
    "MITREIngestionService",
    "MITREFrameworkModel",
    "MITRETacticModel",
    "MITRETechniqueModel",
    "MITREGroupModel",
    "MITRESoftwareModel",
    "MITRERelationshipModel",
    "MITREIngestionSecurityError",
    # P1-02 CISA KEV
    "CISAKEVIngestionService",
    "CISAKEVRecordModel",
    "CISAKEVSourceModel",
    "CISAKEVHistoryModel",
    # P1-03 vendor security advisories
    "VendorSecurityAdvisoryIngestionService",
    "VendorSecurityAdvisoryRecordModel",
    "VendorSecurityAdvisorySourceModel",
    "VendorSecurityAdvisoryHistoryModel",
    # P1-04 OSINT / STIX 2.1 / TAXII 2.1
    "OSINTIngestionService",
    "OSINTSourceModel",
    "OSINTThreatActorModel",
    "OSINTIndicatorModel",
    "OSINTCampaignModel",
    "OSINTMalwareModel",
    "OSINTInfrastructureModel",
    "OSINTRelationshipModel",
    "OSINTObservationModel",
    "OSINTConflictRecordModel",
    "STIX21CompatibilityReport",
    "TAXII21CollectionModel",
    "TAXII21EnvelopeModel",
    "TAXII21ManifestEntryModel",
    "TAXII21SyncStateModel",
    "SecurityError",
    # Cross-agent integration contracts
    "ThreatIntelligenceIntegrationBridge",
    "Agent1RegistrationPayload",
    "Agent1HeartbeatPayload",
    "Agent1OpsWorkerHeartbeatPayload",
    "Agent1TaskEnqueuePayload",
    "KEVVulnerabilityCorrelationDTO",
    "VendorAdvisoryLinkDTO",
    "AttackTechniqueMappingEntryDTO",
    "CVETechniqueCorrelationDTO",
    "TechniqueRollupDTO",
    "ProvenanceSummaryDTO",
    "ThreatIntelListEnvelope",
    "ThreatIntelDetailEnvelope",
    "ThreatIntelErrorEnvelope",
    "FreshnessMetaDTO",
    "PaginationMetaDTO",
    "VALID_MAPPING_TYPES",
    "VALID_CONSULTED_STATES",
    # P3-01 persistence (SQLite, append-only history, tenant isolation)
    "ThreatIntelRepository",
    "SQLiteThreatIntelRepository",
    "repository_from_url",
    "StoredEntityRecord",
    "StoredObservation",
    "EntityHistoryRecord",
    "ConflictRecord",
    "AuditRecord",
    "EntityPage",
    "PersistenceError",
    "AppendOnlyViolationError",
    "TenantIsolationError",
    "SCHEMA_SQL",
    "APPEND_ONLY_TABLES",
    # P3-02 API integration surface (contract-only, NOT mounted)
    "ThreatIntelApiSurface",
    "RouteSpec",
    "ROUTES",
    "API_PREFIX",
    "API_CONTRACT_VERSION",
    "RequestContext",
    "ApiResponse",
    "HttpMethod",
    "ApiValidationError",
    "ApiNotFoundError",
    "ApiUnauthorizedError",
    "ApiSurfaceNotMountedError",
    "build_fastapi_router",
    # P3-03 background collection architecture (no worker process runs)
    "CollectionWorker",
    "CollectionJob",
    "JobState",
    "JobEvent",
    "WorkerMetrics",
    "RetryPolicy",
    "CircuitBreakerConfig",
    "SourceCircuitBreaker",
    "TERMINAL_STATES",
    "CollectionWorkerError",
    "UnknownJobError",
    "JobNotLeasableError",
    "LeaseConflictError",
    "derive_idempotency_key",
    # Source reliability, freshness & evidence-gated verification
    "SourceReliabilityService",
    "SourceReliabilityRecord",
    "SourceOutcome",
    "FreshnessPolicy",
    "FreshnessState",
    "SourceAvailability",
    "ReliabilityTier",
    "VerificationEvidence",
    "VerificationPromotionError",
    "SourceReliabilityError",
    "VERIFICATION_RANK",
    # Cross-agent contract registry (proposed vs owner-accepted, pinned provenance)
    "ContractRegistry",
    "ContractDependency",
    "ContractStatus",
    "ContractRegistryError",
    "ContractNotAcceptedError",
    "OwnerAcceptanceError",
    "default_registry",
    # P0-A Domain B item 24: Threat Intelligence Reports
    "ThreatIntelReport",
    "ThreatIntelReportService",
    "ReportHistoryEntry",
    "ReportEntityReference",
    "ReportRelationshipRef",
    "ReportEvidenceRef",
    "ReportSourceAttribution",
    "ReportKind",
    "ReportStatus",
    "ReportClassification",
    "ReportOrigin",
    "ReportVerificationMode",
    "ReportValidationError",
    "DuplicateReportError",
    "ReportAppendOnlyViolationError",
    # P0-B Relationship analysis (typed semantics, provenance, contradictions, traversal)
    "RelationshipAnalysisService",
    "RelationshipAssertion",
    "RelationshipSemantics",
    "ContradictionRecord",
    "ContradictionSummary",
    "DuplicateGroup",
    "EvidenceItem",
    "TraversalResult",
    "PathResult",
    "AssertionOrigin",
    "AssertionStatus",
    "Direction",
    "RelationshipError",
    "build_default_semantics",
    # P0-C Deterministic conflict resolution (claims vs conclusions)
    "ConflictResolutionService",
    "SourceClaim",
    "ResolvedValue",
    "ConflictResolutionRecord",
    "ClaimOrigin",
    "ResolutionStrategy",
    "ConflictState",
    "ConflictError",
    # P0-D Domain observability
    "ThreatIntelObservabilityService",
    "SourceHealthView",
    "SourceHealth",
    "DomainHealthSnapshot",
    "DomainObservabilityEvent",
    "ObservabilityError",
    # P2 Live-source readiness (opt-in gated; no network client in this package)
    "LiveSourceReadinessService",
    "LiveSourceGate",
    "LiveSourcePolicy",
    "SourceSchema",
    "FetchPlan",
    "FetchedPayload",
    "ProvenanceStampedRecord",
    "PayloadStatus",
    "LiveSourceError",
    "LiveAccessRefusedError",
    "LIVE_OPT_IN_ENV",
]
