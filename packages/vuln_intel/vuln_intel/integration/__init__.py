"""Integration layer: normalized records → CICC storage contract.

Kept inside this package so the host's core files stay untouched. The host
implements :class:`VulnerabilityStore` / :class:`AuditPort`; nothing here imports
``app.*``, SQLAlchemy or FastAPI (enforced by ``tests/test_isolation.py``).
"""

from .asgi import VulnerabilityAsgiApp, build_app
from .contracts import (
    AuditPort,
    ImportReport,
    RecordOutcome,
    UpsertOutcome,
    UpsertResult,
    VulnerabilityStore,
)
from .host_adapter import (
    HOST_PERMISSION_READ,
    HostPrincipalResolver,
    MountDescriptor,
    mountable,
    principal_resolver,
)
from .mapping import (
    ENRICHMENT_KEY,
    ENTITY_KIND,
    assert_persistable,
    to_enrichment,
    to_entity_payload,
    to_provenance,
    to_source_details,
    to_store_payload,
)
from .service import IngestionPolicy, IngestionService
from .sqlite_store import SCHEMA_VERSION, SQLiteVulnerabilityStore
from .store import InMemoryVulnerabilityStore, RecordingAudit, RefusingStore

__all__ = [
    "ENRICHMENT_KEY",
    "ENTITY_KIND",
    "HOST_PERMISSION_READ",
    "SCHEMA_VERSION",
    "AuditPort",
    "HostPrincipalResolver",
    "ImportReport",
    "InMemoryVulnerabilityStore",
    "IngestionPolicy",
    "IngestionService",
    "MountDescriptor",
    "RecordOutcome",
    "RecordingAudit",
    "RefusingStore",
    "SQLiteVulnerabilityStore",
    "UpsertOutcome",
    "UpsertResult",
    "VulnerabilityAsgiApp",
    "VulnerabilityStore",
    "assert_persistable",
    "build_app",
    "mountable",
    "principal_resolver",
    "to_enrichment",
    "to_entity_payload",
    "to_provenance",
    "to_source_details",
    "to_store_payload",
]
