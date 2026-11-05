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
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

__all__ = [
    "AuditPort",
    "ImportReport",
    "RecordOutcome",
    "UpsertOutcome",
    "UpsertResult",
    "VulnerabilityStore",
    "verify_port",
]


class UpsertOutcome(str):
    """Outcome vocabulary shared with the host's audit types."""

    CREATED = "created"
    UPDATED = "updated"
    UNCHANGED = "unchanged"
    SKIPPED = "skipped"
    #: A dry run described what it *would* do. The service used this string as a
    #: literal for a while, which meant a dry-run report counted it in none of its
    #: totals: created+updated+unchanged+failed summed to zero for N records.
    PREVIEWED = "previewed"


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


@runtime_checkable
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


@runtime_checkable
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


def verify_port(candidate: object, port: type = VulnerabilityStore) -> tuple[str, ...]:
    """Return the names of the methods ``candidate`` is missing to satisfy ``port``.

    ``isinstance(candidate, VulnerabilityStore)`` works now that the protocol is
    ``runtime_checkable``, but it raises ``TypeError`` on a port that is not, and it
    answers with a bare boolean. A host wiring a SQL adapter gets far more from
    "your adapter is missing: upsert" than from "False", so the boolean is available
    *and* the diagnosis is.

    Deliberately shallow: ``runtime_checkable`` checks that a method of that name
    exists, not that its signature matches. Signature conformance is mypy's job, and
    pretending otherwise here would imply a guarantee this cannot make.
    """
    if not isinstance(port, type) or not getattr(port, "_is_protocol", False):
        # `issubclass(int, Protocol)` is True, so that is not a usable guard. A
        # protocol is marked by `_is_protocol`, and anything else would produce a
        # list of stdlib method names presented as "your adapter is missing these".
        raise TypeError("port must be a Protocol subclass")
    missing = [
        name
        for name in getattr(port, "__protocol_attrs__", dir(port))
        if not name.startswith("_") and not hasattr(candidate, name)
    ]
    return tuple(sorted(missing))


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
    def previewed(self) -> int:
        return sum(1 for o in self.outcomes if o.outcome == UpsertOutcome.PREVIEWED)

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
            "previewed": self.previewed,
            "failed": self.failed,
            "outcomes": [o.as_dict() for o in self.outcomes],
            "rejected": list(self.rejected),
            "payloads": list(self.payloads),
        }
