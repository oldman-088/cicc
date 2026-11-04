"""Ingestion service: normalized records → host storage, safely.

The service is the only place that decides *whether* a record may be written.
It is deliberately paranoid:

1. **Origin gate.** A non-live record is refused unless the caller passes
   ``allow_fixture=True`` (dry-run preview / explicitly labelled demo tenant).
2. **Dry run.** ``dry_run=True`` produces the exact payloads without writing, so
   a reviewer can inspect the integration before it is approved.
3. **Age gate.** A record that is not newer than what is stored is reported as
   ``unchanged``/``skipped`` and never overwrites newer data.
4. **Atomicity is delegated but not assumed.** The store contract requires
   write+provenance in one transaction; failures come back as per-record
   outcomes instead of aborting the whole import.
5. **Audit is explicit.** If the audit port is supplied it is called for every
   write; a failing audit port surfaces as an error rather than being ignored.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Mapping, Sequence

from ..errors import MixedOriginError
from ..schema import NormalizedVulnerability, Origin, utcnow
from .contracts import (
    AuditPort,
    ImportReport,
    RecordOutcome,
    UpsertOutcome,
    UpsertResult,
    VulnerabilityStore,
)
from .mapping import assert_persistable, to_store_payload

__all__ = ["IngestionPolicy", "IngestionService"]


class IngestionPolicy:
    """Explicit, inspectable switches (no environment magic)."""

    __slots__ = ("allow_fixture", "dry_run", "stop_on_audit_failure")

    def __init__(
        self,
        *,
        allow_fixture: bool = False,
        dry_run: bool = True,
        stop_on_audit_failure: bool = True,
    ) -> None:
        self.allow_fixture = allow_fixture
        # Safe default: an unapproved integration must not write anything.
        self.dry_run = dry_run
        self.stop_on_audit_failure = stop_on_audit_failure

    def as_dict(self) -> dict[str, object]:
        return {
            "allow_fixture": self.allow_fixture,
            "dry_run": self.dry_run,
            "stop_on_audit_failure": self.stop_on_audit_failure,
        }


class IngestionService:
    """Apply normalized records to a tenant through a :class:`VulnerabilityStore`."""

    def __init__(
        self,
        *,
        store: VulnerabilityStore | None = None,
        audit: AuditPort | None = None,
        policy: IngestionPolicy | None = None,
    ) -> None:
        self.store = store
        self.audit = audit
        self.policy = policy or IngestionPolicy()

    # -- public ----------------------------------------------------------
    def import_records(
        self,
        records: Sequence[NormalizedVulnerability],
        *,
        tenant_id: str,
        actor_id: str | None = None,
        collected_at: datetime | None = None,
    ) -> ImportReport:
        """Import a batch, reporting one outcome per record."""
        if not tenant_id or not isinstance(tenant_id, str):
            raise ValueError("tenant_id is required")
        origins = {record.origin for record in records}
        if len(origins) > 1:
            raise MixedOriginError(
                "refusing to import a mixed-origin batch: "
                + ", ".join(sorted(o.value for o in origins))
            )
        origin = next(iter(origins)).value if origins else Origin.LIVE.value
        moment = collected_at or utcnow()
        if moment.tzinfo is None:
            raise ValueError("collected_at must be timezone-aware")

        report = ImportReport(
            tenant_id=tenant_id, dry_run=self.policy.dry_run, origin=origin
        )

        for record in records:
            payload = to_store_payload(record, tenant_id=tenant_id, collected_at=moment)
            try:
                assert_persistable(payload, allow_fixture=self.policy.allow_fixture)
            except PermissionError as exc:
                report.outcomes.append(
                    RecordOutcome(
                        cve=str(record.cve),
                        outcome=UpsertOutcome.SKIPPED,
                        reason=str(exc),
                    )
                )
                continue

            if self.policy.dry_run:
                preview = _jsonable(payload)
                assert isinstance(preview, dict)  # payload is always a mapping
                report.payloads.append(preview)
                report.outcomes.append(
                    RecordOutcome(cve=str(record.cve), outcome="previewed")
                )
                continue

            if self.store is None:
                report.outcomes.append(
                    RecordOutcome(
                        cve=str(record.cve),
                        outcome=UpsertOutcome.SKIPPED,
                        reason="no store configured; refusing to report a write that did not happen",
                    )
                )
                continue

            report.outcomes.append(
                self._write(record, payload, tenant_id=tenant_id, actor_id=actor_id, report=report)
            )
        return report

    # -- internals -------------------------------------------------------
    def _write(
        self,
        record: NormalizedVulnerability,
        payload: Mapping[str, object],
        *,
        tenant_id: str,
        actor_id: str | None,
        report: ImportReport,
    ) -> RecordOutcome:
        assert self.store is not None
        try:
            result: UpsertResult = self.store.upsert(
                tenant_id=tenant_id,
                cve=str(record.cve),
                entity=payload["entity"],  # type: ignore[arg-type]
                details=payload["details"],  # type: ignore[arg-type]
                enrichment=payload["enrichment"],  # type: ignore[arg-type]
                provenance=payload["provenance"],  # type: ignore[arg-type]
                collected_at=payload["collected_at"],  # type: ignore[arg-type]
                dry_run=False,
            )
        except Exception as exc:
            return RecordOutcome(
                cve=str(record.cve),
                outcome=UpsertOutcome.SKIPPED,
                reason=f"store rejected the write: {type(exc).__name__}",
            )

        if self.audit is not None and result.outcome in (
            UpsertOutcome.CREATED,
            UpsertOutcome.UPDATED,
        ):
            try:
                self.audit.record(
                    tenant_id=tenant_id,
                    action="nvd_record_imported",
                    actor_id=actor_id,
                    target_entity_id=result.entity_id,
                    target_provenance_id=result.provenance_id,
                    details={
                        "cve": str(record.cve),
                        "origin": record.origin.value,
                        "outcome": result.outcome,
                        "sources": list(record.sources),
                    },
                )
            except Exception as exc:
                if self.policy.stop_on_audit_failure:
                    return RecordOutcome(
                        cve=str(record.cve),
                        outcome=UpsertOutcome.SKIPPED,
                        reason=(
                            "write succeeded but audit failed: "
                            f"{type(exc).__name__}; treat the record as unverified"
                        ),
                        entity_id=result.entity_id,
                    )
                report.rejected.append(
                    {"cve": str(record.cve), "reason": "audit failure (non-fatal policy)"}
                )
        return RecordOutcome(
            cve=str(record.cve),
            outcome=result.outcome,
            reason=result.reason,
            entity_id=result.entity_id,
        )


def _jsonable(value: object) -> object:
    """Render a payload for the preview artifact (datetimes → ISO strings)."""
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
        return [_jsonable(v) for v in value]
    return value
