"""Source connectors. Each module is self-contained and fails closed.

Nothing here performs I/O on import, and no connector instantiates a network
transport by default — callers must opt in explicitly.
"""

from .debian import (
    DEBIAN_TRACKER_URL,
    DebianTrackerConnector,
    DebianTrackerSnapshot,
)
from .debian import (
    LAST_VERIFIED_LIVE as DEBIAN_LAST_VERIFIED_LIVE,
)
from .debian import (
    to_vulnerability_records as debian_to_vulnerability_records,
)
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
from .ghsa import (
    GHSA_API,
    GhsaConnector,
    GhsaSnapshot,
)
from .ghsa import (
    LAST_VERIFIED_LIVE as GHSA_LAST_VERIFIED_LIVE,
)
from .nvd import LAST_VERIFIED_LIVE as NVD_LAST_VERIFIED_LIVE
from .nvd import NVD_API, NvdConnector
from .osv import LAST_VERIFIED_LIVE as OSV_LAST_VERIFIED_LIVE
from .osv import OSV_API, AdvisoryOnly, OsvConnector, OsvResult
from .ubuntu import (
    LAST_VERIFIED_LIVE as UBUNTU_LAST_VERIFIED_LIVE,
)
from .ubuntu import (
    USN_DB_URL,
    UbuntuSnapshot,
    UbuntuUsnConnector,
)

__all__ = [
    "DEBIAN_LAST_VERIFIED_LIVE",
    "DEBIAN_TRACKER_URL",
    "EPSS_API",
    "GHSA_API",
    "GHSA_LAST_VERIFIED_LIVE",
    "LIVE_PROVIDER_AVAILABLE",
    "NVD_API",
    "NVD_LAST_VERIFIED_LIVE",
    "OSV_API",
    "OSV_LAST_VERIFIED_LIVE",
    "UBUNTU_LAST_VERIFIED_LIVE",
    "USN_DB_URL",
    "AdvisoryOnly",
    "DebianTrackerConnector",
    "DebianTrackerSnapshot",
    "EpssCache",
    "EpssProvider",
    "EpssScore",
    "FixtureEpssProvider",
    "GhsaConnector",
    "GhsaSnapshot",
    "InMemoryEpssCache",
    "NvdConnector",
    "OsvConnector",
    "OsvResult",
    "UbuntuSnapshot",
    "UbuntuUsnConnector",
    "UnavailableEpssProvider",
    "debian_to_vulnerability_records",
    "parse_epss_response",
]
