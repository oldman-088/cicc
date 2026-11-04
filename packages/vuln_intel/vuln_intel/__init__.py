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
from .normalization import (
    KevSignal,
    attach_epss,
    attach_kev,
    corroboration_report,
    index_kev,
    normalize_sources,
)
from .priorities import (
    WEIGHTS,
    PriorityContext,
    PriorityResult,
    rank_vulnerabilities,
    score_vulnerability,
)
from .ratelimit import RateGate, quota_for_nvd, quota_for_osv
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
from .transport import HttpxTransport, Transport, TransportResponse

__version__ = "0.1.0"

__all__ = [
    "EPSS_API",
    "LIVE_PROVIDER_AVAILABLE",
    "NVD_API",
    "OSV_API",
    "WEIGHTS",
    "AdvisoryOnly",
    "AffectedPackage",
    "CollectionResult",
    "CollectionStatus",
    "CveId",
    "CvssScore",
    "EpssCache",
    "EpssProvider",
    "EpssScore",
    "FixtureEpssProvider",
    "Freshness",
    "HttpxTransport",
    "InMemoryEpssCache",
    "KevSignal",
    "MixedOriginError",
    "NormalizedVulnerability",
    "NvdConnector",
    "Origin",
    "OsvConnector",
    "OsvResult",
    "PriorityContext",
    "PriorityResult",
    "ProvenanceRecord",
    "RateGate",
    "Reference",
    "RetryPolicy",
    "Severity",
    "SourceError",
    "SourceKind",
    "SourceNotFound",
    "SourceRateLimited",
    "SourceResponseError",
    "SourceState",
    "SourceTimeout",
    "SourceUnavailable",
    "Transport",
    "TransportResponse",
    "UnavailableEpssProvider",
    "UnsupportedVector",
    "ValidationError",
    "__version__",
    "attach_epss",
    "attach_kev",
    "call_with_retry",
    "compute_freshness",
    "corroboration_report",
    "cvss_from_source",
    "index_kev",
    "merge_records",
    "normalize_sources",
    "parse_epss_response",
    "parse_vector",
    "quota_for_nvd",
    "quota_for_osv",
    "rank_vulnerabilities",
    "score_vector",
    "score_vulnerability",
    "severity_from_score",
]
