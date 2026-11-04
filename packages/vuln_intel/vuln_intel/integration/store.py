"""Reference implementations of the storage and audit ports.

Two stores are provided:

* :class:`InMemoryVulnerabilityStore` — dict-backed, for tests and dry-run
  previews.  It enforces the same *rules* the real adapter must enforce (tenant
  scoping, CVE uniqueness, no overwrite by older observations, provenance
  emitted on change), so integration tests exercise the real control flow.
* :class:`RefusingStore` — used when no approval exists.  It refuses every write
  with an explicit reason, which is preferable to a silent no-op.

A real SQLAlchemy adapter is **not** shipped: it would need an approved
migration and must live in the host.  ``SQLALCHEMY_ADAPTER_RECIPE`` documents the
exact mapping for whoever writes it (see docs/INTEGRATION.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from .contracts import UpsertOutcome, UpsertResult
from .mapping import ENRICHMENT_KEY, assert_persistable, event_types

__all__ = ["InMemoryVulnerabilityStore", "RecordingAudit", "RefusingStore"]


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


@dataclass
class _Row:
    entity_id: str
    details: dict[str, Any]
    collected_at: datetime
    origin: str
    provenance: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class InMemoryVulnerabilityStore:
    """Tenant-scoped in-memory store honouring the persistence invariants."""

    allow_fixture: bool = False
    rows: dict[tuple[str, str], _Row] = field(default_factory=dict, repr=False)
    provenance_events: list[dict[str, Any]] = field(default_factory=list, repr=False)
    writes: int = 0

    # -- read port -------------------------------------------------------
    def find(self, *, tenant_id: str, cve: str) -> Mapping[str, Any] | None:
        row = self.rows.get((tenant_id, cve))
        if row is None:
            return None
        # `cve` is part of the read contract: a caller that fetched by identifier
        # must not have to remember which identifier it asked for, and an API
        # shaper that omits it emits a record with a null primary key.
        return {
            "cve": cve,
            "entity_id": row.entity_id,
            "details": row.details,
            "collected_at": row.collected_at,
            "origin": row.origin,
        }

    def list(
        self,
        *,
        tenant_id: str,
        limit: int,
        cursor: str | None = None,
        severity: str | None = None,
        kev_only: bool = False,
        order: str = "cve",
    ) -> tuple[Sequence[Mapping[str, Any]], str | None]:
        """Page one tenant's rows.

        Filtering happens here rather than in the caller for the same reason the
        SQL adapter must do it in SQL: paging after filtering is correct, paging
        before filtering silently drops matching rows.
        """
        if limit < 1:
            raise ValueError("limit must be >= 1")
        if order not in ("cve", "-cve", "severity", "-severity"):
            raise ValueError("unsupported order")
        rows = [
            (cve, row)
            for (tenant, cve), row in self.rows.items()
            if tenant == tenant_id
        ]
        if severity is not None:
            wanted = severity.strip().lower()
            rows = [
                (cve, row)
                for cve, row in rows
                if str((row.details.get(ENRICHMENT_KEY) or {}).get("severity", "")).lower()
                == wanted
            ]
        if kev_only:
            rows = [
                (cve, row)
                for cve, row in rows
                if bool((row.details.get(ENRICHMENT_KEY) or {}).get("kev"))
            ]

        def severity_key(row: _Row) -> str:
            return str((row.details.get(ENRICHMENT_KEY) or {}).get("severity", ""))

        reverse = order.startswith("-")
        rows.sort(
            key=(lambda item: item[0]) if order.endswith("cve") else (lambda item: severity_key(item[1])),
            reverse=reverse,
        )
        # The cursor is the last key emitted, not an offset: an offset shifts when
        # rows are inserted mid-listing, which would skip or repeat records.
        if cursor:
            keys = [item[0] if order.endswith("cve") else severity_key(item[1]) for item in rows]
            try:
                start = keys.index(cursor) + 1
            except ValueError:
                start = 0
            rows = rows[start:]

        page = rows[:limit]
        next_cursor = None
        if len(rows) > limit and page:
            last = page[-1]
            next_cursor = last[0] if order.endswith("cve") else severity_key(last[1])
        out: list[Mapping[str, Any]] = []
        for cve, row in page:
            out.append(
                {
                    "cve": cve,
                    "entity_id": row.entity_id,
                    "details": row.details,
                    "collected_at": row.collected_at,
                    "origin": row.origin,
                }
            )
        return out, next_cursor

    # -- write port ------------------------------------------------------
    def upsert(
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
        payload = {"origin": (enrichment or {}).get("origin", "live"), "cve": cve}
        assert_persistable(payload, allow_fixture=self.allow_fixture)

        key = (tenant_id, cve)
        incoming = _aware(collected_at)
        existing = self.rows.get(key)

        merged_details = dict(details)
        if enrichment is not None:
            merged_details[ENRICHMENT_KEY] = dict(enrichment)
        else:
            merged_details.setdefault(ENRICHMENT_KEY, {})

        if existing is None:
            entity_id = f"entity-{tenant_id[:8]}-{cve}"
            self.rows[key] = _Row(
                entity_id=entity_id,
                details=merged_details,
                collected_at=incoming,
                origin=str(payload["origin"]),
                provenance=[dict(provenance)],
            )
            event_type, _ = event_types(created=True)
            self.provenance_events.append(
                {**dict(provenance), "event_type": event_type, "tenant_id": tenant_id, "cve": cve}
            )
            self.writes += 1
            return UpsertResult(UpsertOutcome.CREATED, entity_id=entity_id, provenance_id=event_type)

        if incoming < existing.collected_at:
            # Mirrors the host importer: an older observation never wins.
            return UpsertResult(
                UpsertOutcome.SKIPPED,
                entity_id=existing.entity_id,
                reason="older observation cannot overwrite a newer one",
            )

        changed = existing.details != merged_details
        if changed:
            existing.details = merged_details
            existing.collected_at = incoming
            existing.provenance.append(dict(provenance))
            self.provenance_events.append(
                {
                    **dict(provenance),
                    "event_type": event_types(created=False)[0],
                    "tenant_id": tenant_id,
                    "cve": cve,
                }
            )
            self.writes += 1
            return UpsertResult(
                UpsertOutcome.UPDATED, entity_id=existing.entity_id, provenance_id="source_record_updated"
            )
        # Same timestamp and same body: refresh the stamp only, no new evidence.
        existing.collected_at = incoming
        return UpsertResult(UpsertOutcome.UNCHANGED, entity_id=existing.entity_id)


@dataclass
class RefusingStore:
    """Deny-by-default store used when no integration approval exists."""

    reason: str = (
        "integration not approved: no store adapter installed; "
        "writes are refused rather than silently discarded"
    )

    def find(self, *, tenant_id: str, cve: str) -> Mapping[str, Any] | None:
        return None

    def upsert(self, **kwargs: Any) -> UpsertResult:
        return UpsertResult(UpsertOutcome.SKIPPED, reason=self.reason)


@dataclass
class RecordingAudit:
    """Audit port that records calls and can be told to fail."""

    events: list[dict[str, Any]] = field(default_factory=list)
    fail: bool = False

    def record(
        self,
        *,
        tenant_id: str,
        action: str,
        actor_id: str | None,
        target_entity_id: str | None,
        target_provenance_id: str | None,
        details: Mapping[str, Any],
    ) -> None:
        if self.fail:
            raise RuntimeError("audit sink unavailable")
        self.events.append(
            {
                "tenant_id": tenant_id,
                "action": action,
                "actor_id": actor_id,
                "target_entity_id": target_entity_id,
                "target_provenance_id": target_provenance_id,
                "details": dict(details),
            }
        )
