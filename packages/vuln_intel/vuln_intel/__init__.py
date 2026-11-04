"""CICC Vulnerability Intelligence.

A self-contained package: connectors (NVD, OSV), an EPSS integration interface,
unified CVE normalization and transparent prioritization.

Integration contract (important for the wider platform):

* this package imports **nothing** from ``sources.py``, ``main.py`` or
  ``models.py``, and never mutates them;
* it has no FastAPI/SQLAlchemy dependency, so it can be adopted by the API layer
  incrementally;
* it performs no network I/O unless a caller injects a
  :class:`~vuln_intel.transport.Transport`;
* live collection is **not verified** in the environment where this code was
  written (see ``docs/vulnerability-intelligence.md``).

Typical use::

    from vuln_intel import NvdConnector, OsvConnector, HttpxTransport
    from vuln_intel.normalization import normalize_sources
    from vuln_intel.priorities import rank_vulnerabilities

    nvd = NvdConnector(transport=HttpxTransport())
    record = nvd.get_cve("CVE-2021-44228")
    ranking = rank_vulnerabilities([record])
"""

from .affected import AffectedAssessment, Verdict, assess_affected
from .assessment import AssessmentReport, AssessmentWorkflow, workflow_for
from .circuit import BreakerState, CircuitBreaker, CircuitOpen
from .config import Secret, Settings
from .connectors import (
    EPSS_API,
    LIVE_PROVIDER_AVAILABLE,
    NVD_API,
    OSV_API,
    AdvisoryOnly,
    EpssCache,
    EpssProvider,
    EpssScore,
    FixtureEpssProvider,
    InMemoryEpssCache,
    NvdConnector,
    OsvConnector,
    OsvResult,
    UnavailableEpssProvider,
    parse_epss_response,
)
from .correlation import ClusterIndex, CorrelationCluster, correlate, resolve_identity
from .cvss import cvss_from_source, parse_vector, score_vector
from .errors import (
    MixedOriginError,
    SourceError,
    SourceNotFound,
    SourceRateLimited,
    SourceResponseError,
    SourceTimeout,
    SourceUnavailable,
    UnsupportedVector,
    ValidationError,
)
from .health import ComponentHealth, HealthReport, Metrics, Readiness, build_health_report
from .integration.observations import (
    ImmutableObservationLog,
    Observation,
    digest_payload,
    to_observations,
)
from .kev import KEV_URL, CachedKevCatalog, KevCatalog, KevConnector, KevEntry
from .normalization import (
    KevSignal,
    attach_epss,
    attach_kev,
    corroboration_report,
    index_kev,
    normalize_sources,
)
from .pipeline import EnrichmentPipeline, PipelineReport, SourceOutcome
from .priorities import (
    WEIGHTS,
    PriorityContext,
    PriorityResult,
    rank_vulnerabilities,
    score_vulnerability,
)
from .ratelimit import RateGate, quota_for_nvd, quota_for_osv
from .remediation import (
    RecommendedAction,
    Remediation,
    plan_remediation,
    summarize_remediation,
)
from .retry import RetryPolicy, call_with_retry
from .schema import (
    AffectedPackage,
    CollectionResult,
    CollectionStatus,
    CveId,
    CvssScore,
    Freshness,
    NormalizedVulnerability,
    Origin,
    ProvenanceRecord,
    Reference,
    Severity,
    SourceKind,
    SourceState,
    compute_freshness,
    merge_records,
    severity_from_score,
)
from .transport import HttpxTransport, Transport, TransportKind, TransportResponse, transport_kind

__version__ = "0.1.0"

__all__ = [
    "EPSS_API",
    "KEV_URL",
    "LIVE_PROVIDER_AVAILABLE",
    "NVD_API",
    "OSV_API",
    "WEIGHTS",
    "AdvisoryOnly",
    "AffectedAssessment",
    "AffectedPackage",
    "AssessmentReport",
    "AssessmentWorkflow",
    "BreakerState",
    "CachedKevCatalog",
    "CircuitBreaker",
    "CircuitOpen",
    "ClusterIndex",
    "CollectionResult",
    "CollectionStatus",
    "ComponentHealth",
    "CorrelationCluster",
    "CveId",
    "CvssScore",
    "EnrichmentPipeline",
    "EpssCache",
    "EpssProvider",
    "EpssScore",
    "FixtureEpssProvider",
    "Freshness",
    "HealthReport",
    "HttpxTransport",
    "ImmutableObservationLog",
    "InMemoryEpssCache",
    "KevCatalog",
    "KevConnector",
    "KevEntry",
    "KevSignal",
    "Metrics",
    "MixedOriginError",
    "NormalizedVulnerability",
    "NvdConnector",
    "Observation",
    "Origin",
    "OsvConnector",
    "OsvResult",
    "PipelineReport",
    "PriorityContext",
    "PriorityResult",
    "ProvenanceRecord",
    "RateGate",
    "Readiness",
    "RecommendedAction",
    "Reference",
    "Remediation",
    "RetryPolicy",
    "Secret",
    "Settings",
    "Severity",
    "SourceError",
    "SourceKind",
    "SourceNotFound",
    "SourceOutcome",
    "SourceRateLimited",
    "SourceResponseError",
    "SourceState",
    "SourceTimeout",
    "SourceUnavailable",
    "Transport",
    "TransportKind",
    "TransportResponse",
    "UnavailableEpssProvider",
    "UnsupportedVector",
    "ValidationError",
    "Verdict",
    "__version__",
    "assess_affected",
    "attach_epss",
    "attach_kev",
    "build_health_report",
    "call_with_retry",
    "compute_freshness",
    "correlate",
    "corroboration_report",
    "cvss_from_source",
    "digest_payload",
    "index_kev",
    "merge_records",
    "normalize_sources",
    "parse_epss_response",
    "parse_vector",
    "plan_remediation",
    "quota_for_nvd",
    "quota_for_osv",
    "rank_vulnerabilities",
    "resolve_identity",
    "score_vector",
    "score_vulnerability",
    "severity_from_score",
    "summarize_remediation",
    "to_observations",
    "transport_kind",
    "workflow_for",
]
