"""Source-specific observations: the audit-grade layer under the merged view.

Why this exists
---------------
A merged :class:`~vuln_intel.schema.NormalizedVulnerability` is a *convenience*
view.  It deliberately loses information: which source said what, when, and with
which identifier.  For intelligence work that is not enough — an analyst must be
able to prove *"NVD said 9.8 at 10:00, OSV said 7.5 at 11:00"*, and an auditor
must be able to show that a later revision did not quietly rewrite history.

So ingestion is two-layered:

1. **Observation** (append-only, one row per source record) — immutable evidence.
2. **Merged entity view** — derived from observations, may change as sources do.

Invariants enforced by :class:`ImmutableObservationLog`:

* an observation is **never** rewritten; a changed source record appends a new one;
* **idempotent**: the same (tenant, source, source_ref, digest) is stored once;
* identity is preserved: source name, source reference, collection time, origin
  and a SHA-256 digest of the canonical payload;
* ordering is defined by ``collected_at`` then ``(source, digest)`` so a replay is
  deterministic;
* fixture/demo observations are refused unless the log explicitly allows them,
  and are tagged so they can never be mistaken for live evidence.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Protocol, Sequence

from ..schema import NormalizedVulnerability, Origin, ProvenanceRecord
from .mapping import to_source_details

__all__ = [
    "MERGED_VIEW_NOTICE",
    "AppendResult",
    "ImmutableObservationLog",
    "Observation",
    "ObservationLog",
    "digest_payload",
    "to_observations",
]

#: Every merged record produced from observations carries this statement.
MERGED_VIEW_NOTICE = (
    "derived view built from append-only source observations; "
    "the observations, not this view, are the evidence"
)


def digest_payload(payload: Mapping[str, Any]) -> str:
    """Stable SHA-256 over canonical JSON (sorted keys, no whitespace).

    Used for idempotency *and* tamper-evidence: a replayed observation with the
    same content collapses to one row; any byte change produces a new row.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _aware(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        raise ValueError("collected_at must be timezone-aware")
    return moment.astimezone(timezone.utc)


@dataclass(frozen=True)
class Observation:
    """One immutable source record for one CVE."""

    tenant_id: str
    cve: str
    source: str
    source_ref: str | None
    origin: Origin
    collected_at: datetime
    payload: Mapping[str, Any]
    digest: str
    observed_at: datetime | None = None

    def __post_init__(self) -> None:
        _aware(self.collected_at)
        if not self.source:
            raise ValueError("observation needs a source name")
        if not self.digest:
            raise ValueError("observation needs a digest")

    @property
    def identity(self) -> tuple[str, str, str, str]:
        """Deduplication key."""
        return (self.tenant_id, self.source, str(self.cve), self.digest)

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "cve": self.cve,
            "source": self.source,
            "source_ref": self.source_ref,
            "origin": self.origin.value,
            "collected_at": self.collected_at.isoformat(),
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "digest": self.digest,
            "payload": dict(self.payload),
        }


@dataclass(frozen=True)
class AppendResult:
    outcome: str  # appended | duplicate | refused
    digest: str
    reason: str | None = None


class ObservationLog(Protocol):
    """Append-only storage port. Implementations must never update in place."""

    def append(self, observation: Observation) -> AppendResult:  # pragma: no cover
        ...

    def list_for(self, *, tenant_id: str, cve: str) -> Sequence[Observation]:  # pragma: no cover
        ...


@dataclass
class ImmutableObservationLog:
    """Reference append-only log (in-memory). Enforces every invariant we rely on."""

    allow_fixture: bool = False
    _rows: dict[tuple[str, str], list[Observation]] = field(default_factory=dict, repr=False)
    _seen: set[tuple[str, str, str, str]] = field(default_factory=set, repr=False)
    refused: list[dict[str, str]] = field(default_factory=list, repr=False)

    def append(self, observation: Observation) -> AppendResult:
        if observation.origin is not Origin.LIVE and not self.allow_fixture:
            self.refused.append(
                {
                    "cve": str(observation.cve),
                    "source": observation.source,
                    "reason": f"origin={observation.origin.value} not accepted by a live log",
                }
            )
            return AppendResult(
                "refused",
                observation.digest,
                reason="fixture/demo observations are not accepted by a live log",
            )
        if observation.identity in self._seen:
            return AppendResult("duplicate", observation.digest)
        self._seen.add(observation.identity)
        key = (observation.tenant_id, str(observation.cve))
        self._rows.setdefault(key, []).append(observation)
        return AppendResult("appended", observation.digest)

    def list_for(self, *, tenant_id: str, cve: str) -> Sequence[Observation]:
        rows = list(self._rows.get((tenant_id, str(cve)), []))
        # Deterministic replay order, independent of insertion order.
        rows.sort(key=lambda o: (o.collected_at, o.source, o.digest))
        return rows

    @property
    def size(self) -> int:
        return sum(len(rows) for rows in self._rows.values())


def to_observations(
    record: NormalizedVulnerability, *, tenant_id: str, collected_at: datetime
) -> list[Observation]:
    """Split a normalized record into one observation per contributing source.

    A record merged from NVD + OSV yields **two** observations.  Each keeps the
    source-specific part of the payload so the two claims stay separable, which is
    exactly what a merged record cannot express.
    """
    moment = _aware(collected_at)
    details = to_source_details(record)
    observations: list[Observation] = []

    provenance_by_source: dict[str, ProvenanceRecord] = {}
    for provenance_entry in record.provenance:
        provenance_by_source.setdefault(str(provenance_entry.source), provenance_entry)

    sources = list(record.sources) or ["unknown"]
    for source in sources:
        entry: ProvenanceRecord | None = provenance_by_source.get(source)
        # Source-scoped payload: only the fields that source can vouch for.
        payload: dict[str, Any] = {
            "cve_id": str(record.cve),
            "origin": record.origin.value,
            "source": source,
            "source_reference": entry.source_ref if entry else None,
            "url": entry.url if entry else None,
            "transport": entry.transport if entry else "unknown",
            "published": details["published"],
            "last_modified": details["last_modified"],
            "severity": details["severity"],
            "cvss": details["cvss"] if "nvd" in source or "osv" in source else [],
            "cwe": details["cwe"] if source == "nvd" else [],
            "references": details["references"],
            "affected": details["affected"] if source == "osv" else [],
            "kev": record.kev if source == "cisa-kev" else None,
            "epss": details["epss"] if source == "epss" else None,
            "aliases": list(record.aliases) if source == "osv" else [],
        }
        observations.append(
            Observation(
                tenant_id=tenant_id,
                cve=str(record.cve),
                source=source,
                source_ref=entry.source_ref if entry else None,
                origin=record.origin,
                collected_at=moment,
                payload=payload,
                digest=digest_payload(payload),
                observed_at=record.modified or record.published,
            )
        )
    return observations


def observations_to_json(observations: Iterable[Observation]) -> list[dict[str, Any]]:
    """Export helper for reports and drift investigation."""
    return [observation.as_dict() for observation in observations]
