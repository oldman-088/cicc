"""Ports the host application implements.

The integration layer never imports ``app.*``.  Instead the host supplies small
adapters that satisfy these protocols, which keeps `vuln_intel` importable in
isolation (enforced by ``tests/test_isolation.py``) and keeps the database,
session and permission model in the host where it belongs.

Reference implementation: :class:`vuln_intel.integration.store.InMemoryVulnerabilityStore`
used by tests and by the dry-run preview.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

__all__ = [
    "CONFLICT_REASON",
    "AuditPort",
    "ConflictDetail",
    "ImportReport",
    "RecordOutcome",
    "UpsertOutcome",
    "UpsertResult",
    "VulnerabilityStore",
    "conflict_detail",
    "verify_port",
]


#: One wording for one rule, in one place.
#:
#: This string was copied into all three stores. Three copies of a rule is how the
#: three stores drifted apart in the first place (the SQLite adapter kept applying
#: equal-instant disagreements as updates for a whole milestone after the other two
#: refused them), so the wording lives here now and the stores import it.
CONFLICT_REASON = (
    "conflicting observation for the same instant: refusing to let one source "
    "overwrite another at equal timestamps"
)


def _digest(body: Mapping[str, Any]) -> str:
    """Stable hash of an observation body, for comparison across stores."""
    canonical = json.dumps(body, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _flatten(body: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    """Nested mappings to dotted paths, so a difference names a field, not a blob."""
    flat: dict[str, Any] = {}
    for key, value in body.items():
        path = f"{prefix}{key}"
        if isinstance(value, Mapping):
            flat.update(_flatten(value, prefix=f"{path}."))
        else:
            flat[path] = value
    return flat


def conflict_detail(
    *,
    existing_details: Mapping[str, Any],
    incoming_details: Mapping[str, Any],
    instant: str,
    existing_source: str | None = None,
    incoming_source: str | None = None,
) -> ConflictDetail:
    """Describe a same-instant disagreement without resolving it.

    Never picks a winner: this only records what differed. The caller has already
    decided the incoming body loses; this explains why it was refused.
    """
    left, right = _flatten(existing_details), _flatten(incoming_details)
    differing = tuple(
        sorted(
            path
            for path in set(left) | set(right)
            if left.get(path, _MISSING) != right.get(path, _MISSING)
        )
    )
    return ConflictDetail(
        instant=instant,
        existing_source=existing_source,
        incoming_source=incoming_source,
        differing_fields=differing,
        existing_digest=_digest(existing_details),
        incoming_digest=_digest(incoming_details),
    )


_MISSING = object()


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
    #: Two observations claim the same instant but disagree about the content.
    #:
    #: This used to be silently applied as an update. The host importer
    #: (``apps/api/app/connectors/nvd_import.py``) refuses exactly this case with
    #: "Older or conflicting observation cannot overwrite a newer observation", so the
    #: two writers disagreed about what a same-timestamp conflict means — and the
    #: disagreeing write won. It is now refused here too, but as its own outcome
    #: rather than an exception: a batch importer must be able to carry on with the
    #: other records and report this one, which a raised exception prevents.
    CONFLICTED = "conflicted"


@dataclass(frozen=True)
class ConflictDetail:
    """What a refused write was carrying, kept because the refusal is evidence.

    A conflict is a fact about two sources disagreeing, and the disagreement is the
    only reason the record was refused. Reporting it as a prose string threw away
    exactly the information needed to resolve it: which source contradicted which,
    when each claimed to have observed it, and which fields differed.

    The fields are deliberately plain JSON-compatible values so a host can store this
    block without a schema change and an operator can read it without code.
    """

    #: Instant both observations claim. Neither is newer, which is the whole problem.
    instant: str
    #: Source of the observation that was accepted and is still stored, if known.
    existing_source: str | None
    #: Source of the observation that was refused.
    incoming_source: str | None
    #: Field names whose values differ, sorted. Empty (with a hash mismatch) means the
    #: difference is somewhere the field walk cannot see.
    differing_fields: tuple[str, ...]
    #: Hash of each body, so a reviewer can tell "same fields, different value" from
    #: "the shapes differ and the walk missed it".
    existing_digest: str
    incoming_digest: str
    message: str = CONFLICT_REASON

    def as_dict(self) -> dict[str, Any]:
        return {
            "instant": self.instant,
            "existing_source": self.existing_source,
            "incoming_source": self.incoming_source,
            "differing_fields": list(self.differing_fields),
            "existing_digest": self.existing_digest,
            "incoming_digest": self.incoming_digest,
            "message": self.message,
        }


@dataclass(frozen=True)
class UpsertResult:
    """What the store did with one record."""

    outcome: str
    entity_id: str | None = None
    provenance_id: str | None = None
    #: Set when the store refused the write; the service surfaces it verbatim.
    reason: str | None = None
    #: Populated only for :attr:`UpsertOutcome.CONFLICTED`: what the refused
    #: observation was carrying, and how it differed from the body that was kept.
    #: ``None`` for every other outcome, so a caller can rely on it being present
    #: exactly when the write was refused as a contradiction.
    conflict: ConflictDetail | None = None

    @property
    def conflicted(self) -> bool:
        return self.outcome == UpsertOutcome.CONFLICTED

    def as_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "entity_id": self.entity_id,
            "provenance_id": self.provenance_id,
            "reason": self.reason,
            "conflict": self.conflict.as_dict() if self.conflict else None,
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
    #: Present only when ``outcome`` is ``CONFLICTED``; the report carries the
    #: disagreement rather than just counting it.
    conflict: ConflictDetail | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "outcome": self.outcome,
            "reason": self.reason,
            "entity_id": self.entity_id,
            "conflict": self.conflict.as_dict() if self.conflict else None,
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
    def conflicted(self) -> int:
        """Observations refused because they contradicted a same-instant record."""
        return sum(1 for o in self.outcomes if o.outcome == UpsertOutcome.CONFLICTED)

    @property
    def conflicts(self) -> list[RecordOutcome]:
        """The refused observations themselves, not only how many there were."""
        return [o for o in self.outcomes if o.outcome == UpsertOutcome.CONFLICTED]

    @property
    def failed(self) -> int:
        # A conflict is not a failure of the run; it is a disagreement that was
        # detected and refused. Counting it as failed would make a source that
        # contradicts itself look like an outage.
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
            # Counted apart from `failed`: a disagreement is not an outage.
            "conflicted": self.conflicted,
            "conflicts": [o.as_dict() for o in self.conflicts],
            "failed": self.failed,
            "outcomes": [o.as_dict() for o in self.outcomes],
            "rejected": list(self.rejected),
            "payloads": list(self.payloads),
        }
