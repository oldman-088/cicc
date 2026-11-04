"""Ports the host application implements.

The integration layer never imports ``app.*``.  Instead the host supplies small
adapters that satisfy these protocols, which keeps `vuln_intel` importable in
isolation (enforced by ``tests/test_isolation.py``) and keeps the database,
session and permission model in the host where it belongs.

Reference implementation: :class:`vuln_intel.integration.store.InMemoryVulnerabilityStore`
used by tests and by the dry-run preview.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, Protocol, Sequence

__all__ = [
    "AuditPort",
    "ImportReport",
    "RecordOutcome",
    "UpsertOutcome",
    "UpsertResult",
    "VulnerabilityStore",
]


class UpsertOutcome(str):
    """Outcome vocabulary shared with the host's audit types."""

    CREATED = "created"
    UPDATED = "updated"
    UNCHANGED = "unchanged"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class UpsertResult:
    """What the store did with one record."""

    outcome: str
    entity_id: str | None = None
    provenance_id: str | None = None
    #: Set when the store refused the write; the service surfaces it verbatim.
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "entity_id": self.entity_id,
            "provenance_id": self.provenance_id,
            "reason": self.reason,
        }


class VulnerabilityStore(Protocol):
    """Persistence port.

    Implementations MUST be tenant-scoped and MUST enforce these rules, because
    the service cannot enforce them from outside a transaction:

    1. ``(tenant_id, cve)`` is unique;
    2. an older ``collected_at`` never overwrites a newer one;
    3. a write and its provenance event commit atomically;
    4. the caller's authorization was already checked by the host.
    """

    def find(self, *, tenant_id: str, cve: str) -> Mapping[str, Any] | None:  # pragma: no cover
        """Return the stored row for this tenant/CVE, or ``None``."""

    def list(  # pragma: no cover
        self,
        *,
        tenant_id: str,
        limit: int,
        cursor: str | None = None,
        severity: str | None = None,
        kev_only: bool = False,
        order: str = "cve",
    ) -> tuple[Sequence[Mapping[str, Any]], str | None]:
        """Return ``(rows, next_cursor)`` for one tenant.

        ``limit`` is the *page size*, not a cap on how many rows exist. The store
        decides how rows are filtered efficiently (in SQL, not in Python), and
        returns an opaque cursor for the next page. ``cursor`` is opaque by design:
        callers must not construct one, so the store can change its ordering
        strategy without breaking clients.
        """

    def upsert(  # pragma: no cover
        self,
        *,
        tenant_id: str,
        cve: str,
        entity: Mapping[str, Any],
        details: Mapping[str, Any],
        enrichment: Mapping[str, Any] | None,
        provenance: Mapping[str, Any],
        collected_at: datetime,
        dry_run: bool,
    ) -> UpsertResult:
        """Persist one observation atomically with its provenance event."""


class AuditPort(Protocol):
    """Audit sink. Kept separate from the store so audit failures are visible."""

    def record(  # pragma: no cover
        self,
        *,
        tenant_id: str,
        action: str,
        actor_id: str | None,
        target_entity_id: str | None,
        target_provenance_id: str | None,
        details: Mapping[str, Any],
    ) -> None:
        """Append one audit event. Never silently swallow failures."""


@dataclass(frozen=True)
class RecordOutcome:
    cve: str
    outcome: str
    reason: str | None = None
    entity_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "outcome": self.outcome,
            "reason": self.reason,
            "entity_id": self.entity_id,
        }


@dataclass
class ImportReport:
    """Machine-readable result of one import run."""

    tenant_id: str
    dry_run: bool
    origin: str
    outcomes: list[RecordOutcome] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    payloads: list[dict[str, Any]] = field(default_factory=list)

    @property
    def created(self) -> int:
        return sum(1 for o in self.outcomes if o.outcome == UpsertOutcome.CREATED)

    @property
    def updated(self) -> int:
        return sum(1 for o in self.outcomes if o.outcome == UpsertOutcome.UPDATED)

    @property
    def unchanged(self) -> int:
        return sum(1 for o in self.outcomes if o.outcome == UpsertOutcome.UNCHANGED)

    @property
    def failed(self) -> int:
        return sum(1 for o in self.outcomes if o.outcome == UpsertOutcome.SKIPPED) + len(
            self.rejected
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "dry_run": self.dry_run,
            "origin": self.origin,
            "created": self.created,
            "updated": self.updated,
            "unchanged": self.unchanged,
            "failed": self.failed,
            "outcomes": [o.as_dict() for o in self.outcomes],
            "rejected": list(self.rejected),
            "payloads": list(self.payloads),
        }
