"""Source connectors. Each module is self-contained and fails closed.

Nothing here performs I/O on import, and no connector instantiates a network
transport by default — callers must opt in explicitly.
"""

from .epss import (
    EPSS_API,
    LIVE_PROVIDER_AVAILABLE,
    EpssCache,
    EpssProvider,
    EpssScore,
    FixtureEpssProvider,
    InMemoryEpssCache,
    UnavailableEpssProvider,
    parse_epss_response,
)
from .nvd import LAST_VERIFIED_LIVE as NVD_LAST_VERIFIED_LIVE
from .nvd import NVD_API, NvdConnector
from .osv import LAST_VERIFIED_LIVE as OSV_LAST_VERIFIED_LIVE
from .osv import OSV_API, AdvisoryOnly, OsvConnector, OsvResult

__all__ = [
    "EPSS_API",
    "LIVE_PROVIDER_AVAILABLE",
    "NVD_API",
    "NVD_LAST_VERIFIED_LIVE",
    "OSV_API",
    "OSV_LAST_VERIFIED_LIVE",
    "AdvisoryOnly",
    "EpssCache",
    "EpssProvider",
    "EpssScore",
    "FixtureEpssProvider",
    "InMemoryEpssCache",
    "NvdConnector",
    "OsvConnector",
    "OsvResult",
    "UnavailableEpssProvider",
    "parse_epss_response",
]
