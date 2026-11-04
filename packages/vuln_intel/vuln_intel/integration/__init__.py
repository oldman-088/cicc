"""Integration layer: normalized records → CICC storage contract.

Kept inside this package so the host's core files stay untouched. The host
implements :class:`VulnerabilityStore` / :class:`AuditPort`; nothing here imports
``app.*``, SQLAlchemy or FastAPI (enforced by ``tests/test_isolation.py``).
"""

from .contracts import (
    AuditPort,
    ImportReport,
    RecordOutcome,
    UpsertOutcome,
    UpsertResult,
    VulnerabilityStore,
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
from .store import InMemoryVulnerabilityStore, RecordingAudit, RefusingStore

__all__ = [
    "ENRICHMENT_KEY",
    "ENTITY_KIND",
    "AuditPort",
    "ImportReport",
    "InMemoryVulnerabilityStore",
    "IngestionPolicy",
    "IngestionService",
    "RecordOutcome",
    "RecordingAudit",
    "RefusingStore",
    "UpsertOutcome",
    "UpsertResult",
    "VulnerabilityStore",
    "assert_persistable",
    "to_enrichment",
    "to_entity_payload",
    "to_provenance",
    "to_source_details",
    "to_store_payload",
]
