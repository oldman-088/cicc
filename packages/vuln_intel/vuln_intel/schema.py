"""Vendor-neutral vulnerability schema.

This is the *normalization target*: NVD, OSV and (later) EPSS all map onto these
types, so the platform never has to reason about source-specific shapes.

Two invariants are enforced structurally rather than by convention:

1. **Origin is never ambiguous.**  Every record carries ``Origin.LIVE``,
   ``Origin.FIXTURE`` or ``Origin.DEMO``.  :func:`merge_records` refuses to
   combine differing origins, so a demo record can never be silently averaged
   into live intelligence.
2. **Absence is explicit.**  A missing CVSS score is ``None`` — not ``0.0`` —
   and an unparseable vector yields ``CvssScore.assessed=False`` instead of an
   invented number.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from functools import cached_property
from typing import Any, Iterable, Mapping, Sequence

from .errors import MixedOriginError, ValidationError

__all__ = [
    "CVE_PATTERN",
    "AffectedPackage",
    "CollectionResult",
    "CollectionStatus",
    "CveId",
    "CvssScore",
    "NormalizedVulnerability",
    "Origin",
    "ProvenanceRecord",
    "Reference",
    "Severity",
    "SourceKind",
    "SourceState",
    "compute_freshness",
    "merge_records",
    "severity_from_score",
    "utcnow",
]

CVE_PATTERN = re.compile(r"^CVE-(\d{4})-(\d{4,7})$")

#: Earliest year CVE IDs were assigned.
_MIN_CVE_YEAR = 1999


class Origin(str, Enum):
    """Where a record came from. Sorting/merged records must share one origin."""

    LIVE = "live"
    FIXTURE = "fixture"
    DEMO = "demo"

    @property
    def is_real(self) -> bool:
        return self is Origin.LIVE


class CollectionStatus(str, Enum):
    """Outcome of one collection attempt.

    ``FAILED`` must never be rendered as "no vulnerabilities": the two are
    different facts and the UI/report layer is expected to branch on this.
    """

    OK = "ok"
    PARTIAL = "partial"
    FAILED = "failed"
    NOT_CONFIGURED = "not_configured"


class SourceKind(str, Enum):
    NVD = "nvd"
    OSV = "osv"
    EPSS = "epss"
    #: Vendor tracker / advisory sources added by the takeover continuation.
    DEBIAN_TRACKER = "debian-security-tracker"
    UBUNTU_USN = "ubuntu-usn"
    GHSA = "github-advisories"


class RecordStatus(str, Enum):
    """How much standing an advisory has as a *claim*.

    Deliberately separate from severity: a ``DISPUTED`` critical and a ``PUBLISHED``
    critical have the same severity and a different standing, and a remediation queue
    that cannot tell them apart will spend real effort on a contested claim.

    ``None`` (not a member) means the provider said nothing.  It is not modelled as an
    ``UNKNOWN`` member so that "we never asked" and "the source declared nothing" stay
    distinguishable through the nullable field.
    """

    #: Asserted normally; the default for a well-formed record.
    PUBLISHED = "published"
    #: A stakeholder contests the claim (NVD ``cveTags: disputed``).
    DISPUTED = "disputed"
    #: NVD has not finished enrichment; fields may still change.
    UNDERGOING_ANALYSIS = "undergoing_analysis"
    #: Withdrawn or rejected.  The advisory is not a live claim.
    REJECTED = "rejected"


#: Ordering used when sources disagree about standing: the **most cautious**
#: description wins.  A record one source has withdrawn is not presented as
#: confidently published just because another source has not caught up — acting on a
#: rejected CVE wastes effort, whereas hesitating over a live one is recoverable.
_STATUS_PRECEDENCE: tuple[RecordStatus, ...] = (
    RecordStatus.REJECTED,
    RecordStatus.DISPUTED,
    RecordStatus.UNDERGOING_ANALYSIS,
    RecordStatus.PUBLISHED,
)


def strictest_status(values: Iterable[RecordStatus | None]) -> RecordStatus | None:
    """The most cautious non-``None`` status, or ``None`` if all are ``None``."""
    present = [v for v in values if v is not None]
    if not present:
        return None
    return min(present, key=lambda s: _STATUS_PRECEDENCE.index(s))


class Severity(str, Enum):
    """CVSS v3 qualitative rating. ``UNKNOWN`` means "not stated by the source"."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


def utcnow() -> datetime:
    """Timezone-aware UTC now (never naive)."""
    return datetime.now(timezone.utc)


def _ensure_aware(value: datetime | None, *, field_name: str) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        raise ValidationError("timestamps must be timezone-aware", field=field_name)
    return value.astimezone(timezone.utc)


def _parse_moment(value: object, field_name: str) -> datetime | None:
    """Parse an ISO 8601 string (or accept a datetime) into an aware UTC datetime.

    Deserialisation needs this: everything on the wire is a string, and silently
    returning ``None`` for an unparseable timestamp would turn "we do not know when
    this last succeeded" into "it never has" — a distinguishable fact turned into a
    wrong one. So a malformed value raises instead of being swallowed.
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return _ensure_aware(value, field_name=field_name)
    if not isinstance(value, str):
        raise ValidationError(
            f"{field_name} must be an ISO 8601 string or a datetime", field=field_name
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(
            f"{field_name} is not a valid ISO 8601 timestamp: {value!r}", field=field_name
        ) from exc
    return _ensure_aware(parsed, field_name=field_name)


@dataclass(frozen=True, order=True)
class CveId:
    """A validated CVE identifier.

    Only ``CVE-YYYY-NNNN`` with a plausible year is accepted.  Anything else is
    a :class:`ValidationError` — the platform never invents or repairs an ID.
    """

    year: int
    number: int

    @classmethod
    def parse(cls, value: object) -> CveId:
        if not isinstance(value, str):
            raise ValidationError("CVE id must be a string", field="cve")
        text = value.strip().upper()
        match = CVE_PATTERN.match(text)
        if match is None:
            raise ValidationError(f"malformed CVE id: {text!r}", field="cve")
        year, number = int(match.group(1)), int(match.group(2))
        if not _MIN_CVE_YEAR <= year <= utcnow().year + 1:
            raise ValidationError(f"implausible CVE year: {year}", field="cve")
        return cls(year=year, number=number)

    def __str__(self) -> str:
        return f"CVE-{self.year:04d}-{self.number:04d}"


@dataclass(frozen=True)
class CvssScore:
    """A CVSS v3 base score with its vector.

    ``assessed`` is ``False`` when the vector exists but this package cannot
    score it; consumers must then treat the value as unavailable.
    """

    version: str
    base_score: float
    severity: Severity
    vector: str | None = None
    assessed: bool = True
    source: str | None = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.base_score <= 10.0:
            raise ValidationError("CVSS base score must be within 0.0-10.0", field="base_score")
        if self.assessed and self.severity is Severity.UNKNOWN:
            raise ValidationError("an assessed score needs a severity", field="severity")

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "base_score": self.base_score,
            "severity": self.severity.value,
            "vector": self.vector,
            "assessed": self.assessed,
            "source": self.source,
        }


def severity_from_score(score: float) -> Severity:
    """CVSS v3 qualitative rating (specification section 5)."""
    if score == 0.0:
        return Severity.NONE
    if score < 4.0:
        return Severity.LOW
    if score < 7.0:
        return Severity.MEDIUM
    if score < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL


@dataclass(frozen=True)
class Reference:
    url: str
    kind: str = "other"
    source: str | None = None


@dataclass(frozen=True)
class AffectedPackage:
    """Vendor-neutral affected range.

    ``introduced``/``fixed`` follow OSV semantics and are kept as opaque version
    strings: this package deliberately performs **no** version comparison, since
    that requires ecosystem-specific ordering.  ``purl`` is populated when the
    source supplies it.
    """

    ecosystem: str
    name: str
    introduced: str | None = None
    fixed: str | None = None
    versions: tuple[str, ...] = ()
    purl: str | None = None
    #: ``SEMVER`` / ``ECOSYSTEM`` / ``GIT``.  Kept because a GIT range holds commit
    #: SHAs, and treating one as a version silently produces wrong answers.
    range_type: str | None = None
    #: Inclusive upper bound, mutually exclusive with ``fixed`` in OSV.
    last_affected: str | None = None
    #: Every event of every range for this package, as
    #: ``(range_index, event_kind, value)``.  A single (introduced, fixed) pair
    #: cannot represent an advisory that was fixed twice; this can.
    events: tuple[tuple[int, str, str], ...] = ()

    @property
    def is_comparable_range(self) -> bool:
        return (self.range_type or "").upper() in ("SEMVER", "ECOSYSTEM")


@dataclass(frozen=True)
class ProvenanceRecord:
    """Minimal, honest lineage for one contribution to a record."""

    source: SourceKind | str
    source_ref: str | None
    fetched_at: datetime
    transport: str = "fixture"
    url: str | None = None
    digest: str | None = None

    def __post_init__(self) -> None:
        _ensure_aware(self.fetched_at, field_name="fetched_at")


@dataclass(frozen=True)
class FieldConflict:
    """A structured record of one disagreement between sources.

    ``conflict_notes`` already described disagreements, but only in English, so no
    consumer could *count* them: "how many records have a disputed severity?" required
    parsing prose, and a UI could not filter by field. Both forms are now produced from
    the same decision, so they cannot drift apart.

    ``discarded`` is the part that matters most. ``pick()`` keeps the earliest value
    and previously retained the losing values nowhere retrievable, which made the
    merge lossy in a way nobody could audit: the record said the sources disagreed but
    could not say what either said.
    """

    #: Name of the field on :class:`NormalizedVulnerability`.
    field: str
    #: The value retained in the merged record, rendered for display.
    kept: str
    #: Every other value a source asserted, in the order encountered.
    discarded: tuple[str, ...]
    #: Sources asserting a value that was *not* kept. Empty when unknown.
    dissenters: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.field:
            raise ValidationError("a field conflict must name the field", field="field")
        if not self.discarded:
            raise ValidationError(
                "a field conflict must record what was discarded, "
                "otherwise it describes unanimity",
                field="field",
            )

    def as_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "kept": self.kept,
            "discarded": list(self.discarded),
            "dissenters": list(self.dissenters),
        }


@dataclass(frozen=True)
class NormalizedVulnerability:
    """One vulnerability, normalized across sources.

    Fields that no contributing source supplied stay ``None``; they are never
    filled with zeroes or placeholders.
    """

    cve: CveId
    origin: Origin
    aliases: tuple[str, ...] = ()
    summary: str | None = None
    details: str | None = None
    published: datetime | None = None
    modified: datetime | None = None
    cvss: tuple[CvssScore, ...] = ()
    severity: Severity = Severity.UNKNOWN
    cwe: tuple[str, ...] = ()
    references: tuple[Reference, ...] = ()
    affected: tuple[AffectedPackage, ...] = ()
    kev: bool | None = None
    kev_date_added: datetime | None = None
    #: CISA's binding remediation deadline.  Stored because it is the single most
    #: actionable field in the catalogue: it turns "patch this" into "patch this
    #: by the 21st".  Kept as ``date`` — the feed publishes a calendar day, and
    #: rendering it as a midnight UTC timestamp implies a precision it lacks.
    kev_due_date: date | None = None
    known_exploited: bool | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    epss_model_date: str | None = None
    #: CISA's published SSVC inputs, when a provider supplied them (NVD carries
    #: ``cve.ssvc.ssvcV203[].ssvcData``).  Stored as the three provider-supplied
    #: decision points only: the fourth (mission & well-being) is
    #: stakeholder-specific and cannot come from a feed, so it is never invented
    #: here.  ``None`` means the provider said nothing, never "no exploitation".
    ssvc: tuple[tuple[str, str], ...] = ()
    #: How much standing the advisory has.  ``None`` = the provider declared nothing.
    record_status: RecordStatus | None = None
    #: When a source withdrew the record (OSV ``withdrawn``).  Kept because "withdrawn
    #: in 2021" and "withdrawn yesterday" are different operational situations.
    withdrawn: datetime | None = None
    provenance: tuple[ProvenanceRecord, ...] = ()
    sources: tuple[str, ...] = ()
    #: Human-readable disagreements, kept for logs and report prose.
    conflict_notes: tuple[str, ...] = ()
    #: The same disagreements, structured, so they can be counted and filtered.
    #: A record with an empty ``conflicts`` and non-empty ``conflict_notes`` would be
    #: a rendering that escaped the structured path; a test asserts they agree.
    conflicts: tuple[FieldConflict, ...] = ()
    verification: str = "unverified"

    def __post_init__(self) -> None:
        if not isinstance(self.cve, CveId):
            raise ValidationError("record must carry a validated CveId", field="cve")
        if not isinstance(self.origin, Origin):
            raise ValidationError("record must declare an explicit origin", field="origin")
        _ensure_aware(self.published, field_name="published")
        _ensure_aware(self.modified, field_name="modified")
        _ensure_aware(self.kev_date_added, field_name="kev_date_added")
        _ensure_aware(self.withdrawn, field_name="withdrawn")
        if self.record_status is not None and not isinstance(
            self.record_status, RecordStatus
        ):
            raise ValidationError(
                "record_status must be a RecordStatus or None", field="record_status"
            )
        if self.epss_score is not None and not 0.0 <= self.epss_score <= 1.0:
            raise ValidationError("EPSS score must be within 0.0-1.0", field="epss_score")
        if self.epss_percentile is not None and not 0.0 <= self.epss_percentile <= 1.0:
            raise ValidationError(
                "EPSS percentile must be within 0.0-1.0", field="epss_percentile"
            )

    @property
    def is_actionable_claim(self) -> bool | None:
        """Whether the record can be treated as a live claim.

        ``False`` for a rejected/withdrawn advisory: remediating one is wasted work.
        ``None`` when the provider declared nothing — which must not be read as
        ``True``, because that would promote silence to a guarantee.
        """
        if self.record_status is None:
            return None
        return self.record_status is not RecordStatus.REJECTED

    # -- convenience ------------------------------------------------------
    # `cached_property` is safe here because the dataclass is frozen: the `cvss`
    # tuple cannot change, so the result cannot go stale. Without it, ranking a
    # 5,000-record batch rescanned the same tuple 15,000 times — 36 ms of a 194 ms
    # profile purely recomputing an answer that could not have changed.
    @cached_property
    def best_cvss(self) -> CvssScore | None:
        """Highest assessed CVSS score, preferring the newest specification.

        v4.0 is preferred over v3.x because it is the current standard and its
        scores are not comparable to v3's (the same flaw scores differently).
        Within one version the highest wins, which matches how a security team
        reads "the score" for a record carrying several ratings.

        This previously considered only ``3.x`` vectors, so a record that NVD
        published with ``cvssMetricV40`` alone reported no score at all — the
        score was computed correctly and then discarded.
        """
        for prefix in ("4", "3"):
            scored = [c for c in self.cvss if c.assessed and c.version.startswith(prefix)]
            if scored:
                return max(scored, key=lambda c: c.base_score)
        return None

    @cached_property
    def effective_severity(self) -> Severity:
        """Source-stated severity, else derived from the best assessed vector."""
        if self.severity is not Severity.UNKNOWN:
            return self.severity
        best = self.best_cvss
        return best.severity if best else Severity.UNKNOWN

    def with_provenance(self, record: ProvenanceRecord) -> NormalizedVulnerability:
        return replace(self, provenance=self.provenance + (record,))

    def as_summary(self) -> dict[str, Any]:
        """Compact, JSON-safe projection for API responses and reports."""
        best = self.best_cvss
        return {
            "cve": str(self.cve),
            "origin": self.origin.value,
            "severity": self.effective_severity.value,
            "cvss_base_score": best.base_score if best else None,
            "cvss_version": best.version if best else None,
            "published": self.published.isoformat() if self.published else None,
            "modified": self.modified.isoformat() if self.modified else None,
            "kev": self.kev,
            "epss_score": self.epss_score,
            "epss_percentile": self.epss_percentile,
            "sources": list(self.sources),
            "verification": self.verification,
            "conflicts": list(self.conflict_notes),
        }


@dataclass(frozen=True)
class SourceState:
    """Observed health of one source. ``last_success`` is evidence, not a claim."""

    kind: SourceKind
    status: CollectionStatus
    checked_at: datetime
    last_success: datetime | None = None
    error: str | None = None
    retry_after: float | None = None
    records: int = 0
    #: When the source was last *attempted*, success or failure. Added as a separate
    #: field because Master Prompt §7 lists "last successful synchronization" and
    #: "last attempted synchronization" as two requirements, and the gap between them
    #: is the outage signal: attempted a minute ago but last succeeded a week ago is a
    #: source in trouble, whereas no attempt at all is a scheduler that has stopped.
    #:
    #: It also has to survive *serialisation*. A value preserved in the collector and
    #: dropped by ``as_dict`` is exactly the failure this milestone exists to close:
    #: the lower layer keeps it, the upper layer discards it, and the operator sees a
    #: healthy source.
    last_attempt: datetime | None = None

    def __post_init__(self) -> None:
        if self.last_attempt is not None:
            _ensure_aware(self.last_attempt, field_name="last_attempt")

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "status": self.status.value,
            "checked_at": self.checked_at.isoformat(),
            "last_success": self.last_success.isoformat() if self.last_success else None,
            "last_attempt": self.last_attempt.isoformat() if self.last_attempt else None,
            "error": self.error,
            "retry_after": self.retry_after,
            "records": self.records,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> SourceState:
        """Restore a serialised state.

        ``last_attempt`` absent means the payload predates the field, in which case it
        falls back to ``checked_at`` — which *is* the attempt time for any state that
        was ever serialised. It never falls back to ``last_success``, because that
        would invent an attempt that did not happen.
        """
        checked = _parse_moment(payload.get("checked_at"), "checked_at")
        if checked is None:
            raise ValidationError("source state needs checked_at", field="checked_at")
        attempt_raw = payload.get("last_attempt")
        return cls(
            kind=SourceKind(str(payload.get("kind") or SourceKind.NVD.value)),
            status=CollectionStatus(str(payload.get("status") or CollectionStatus.FAILED.value)),
            checked_at=checked,
            last_success=_parse_moment(payload.get("last_success"), "last_success"),
            error=(str(payload["error"]) if payload.get("error") else None),
            retry_after=(
                float(payload["retry_after"])
                if isinstance(payload.get("retry_after"), (int, float))
                else None
            ),
            records=int(payload.get("records") or 0),
            last_attempt=(
                _parse_moment(attempt_raw, "last_attempt")
                if attempt_raw
                else checked
            ),
        )


@dataclass(frozen=True)
class CollectionResult:
    """Result of a collection call: records **and** the state that produced them."""

    state: SourceState
    records: tuple[NormalizedVulnerability, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.state.status in (CollectionStatus.OK, CollectionStatus.PARTIAL)

    @classmethod
    def failed(
        cls,
        kind: SourceKind,
        error: str,
        *,
        retry_after: float | None = None,
        last_success: datetime | None = None,
        warnings: Sequence[str] = (),
    ) -> CollectionResult:
        return cls(
            state=SourceState(
                kind=kind,
                status=CollectionStatus.FAILED,
                checked_at=utcnow(),
                last_success=last_success,
                error=error,
                retry_after=retry_after,
            ),
            warnings=tuple(warnings),
        )


@dataclass(frozen=True)
class Freshness:
    """How stale a record is. ``unknown`` when no timestamp exists."""

    age: timedelta | None
    bucket: str  # unknown | fresh | recent | stale | expired

    @property
    def is_stale(self) -> bool:
        return self.bucket in ("stale", "expired")


def compute_freshness(
    observed: datetime | None,
    *,
    now: datetime | None = None,
    fresh_within: timedelta = timedelta(hours=24),
    stale_after: timedelta = timedelta(days=7),
) -> Freshness:
    """Classify age. Missing timestamps are reported as ``unknown``, never "fresh"."""
    if observed is None:
        return Freshness(age=None, bucket="unknown")
    now = now or utcnow()
    observed_utc = _ensure_aware(observed, field_name="observed")
    if observed_utc is None:  # unreachable (observed is not None) but explicit
        return Freshness(age=None, bucket="unknown")
    age = now - observed_utc
    if age < fresh_within:
        return Freshness(age=age, bucket="fresh")
    if age < stale_after:
        return Freshness(age=age, bucket="recent")
    if age < stale_after * 4:
        return Freshness(age=age, bucket="stale")
    return Freshness(age=age, bucket="expired")


def _merge_cvss(
    *collections: Sequence[CvssScore],
) -> tuple[tuple[CvssScore, ...], list[str], list[tuple[str, float, list[float]]]]:
    """Union by (version, vector, source); flag divergent scores for one version.

    Variadic on purpose. It used to take exactly ``left, right`` while
    ``merge_records`` called ``_merge_cvss(*(i.cvss for i in items))``, so merging
    **three or more** records raised ``TypeError`` — and every test merged exactly
    two, so nothing failed. Corroboration by three sources is the normal case for a
    widely-reported CVE, which makes this the worst possible place for that bug.

    Returns the merged scores, human-readable notes, and the conflicts as
    ``(version, kept_score, discarded_scores)``. The structured form is returned
    rather than re-parsed from the notes: an earlier version recovered scores with a
    regex that also matched the *specification version*, so "CVSS 3.1 ... 7.1, 9.8"
    yielded a kept score of 9.8 with 3.1 among the discarded values.
    """
    merged: list[CvssScore] = []
    notes: list[str] = []
    disagreed: list[tuple[str, float, list[float]]] = []
    # Keyed on the score too: two records asserting the *same* version, vector and
    # source but different scores were previously collapsed as duplicates, so the
    # higher score vanished with no note at all — the record quietly under-reported
    # its own severity.
    seen: set[tuple[str, str | None, str | None, float | None]] = set()
    for score in [score for collection in collections for score in collection]:
        key = (score.version, score.vector, score.source, score.base_score)
        if key in seen:
            continue
        seen.add(key)
        merged.append(score)
    by_version: dict[str, set[float]] = {}
    for score in merged:
        if score.assessed:
            by_version.setdefault(score.version, set()).add(score.base_score)
    for version, values in sorted(by_version.items()):
        if len(values) > 1:
            highest = max(values)
            notes.append(
                f"CVSS {version} disagreement across sources: "
                + ", ".join(f"{v:.1f}" for v in sorted(values))
                + f" (highest kept: {highest:.1f})"
            )
            disagreed.append((version, highest, sorted(v for v in values if v != highest)))
    return tuple(merged), notes, disagreed


def merge_records(records: Iterable[NormalizedVulnerability]) -> NormalizedVulnerability:
    """Merge records for the **same** CVE into one corroborated record.

    Guarantees:

    * every input must share one :class:`Origin` (else :class:`MixedOriginError`);
    * every input must describe the same CVE (else :class:`ValidationError`);
    * conflicting scalar values keep the earliest observation and are recorded
      in ``conflict_notes`` — nothing is silently overwritten.

    This is corroboration, not verification: the result remains
    ``verification="unverified"`` unless a source explicitly asserted otherwise.
    """
    items = list(records)
    if not items:
        raise ValidationError("cannot merge an empty record set")
    origins = {item.origin for item in items}
    if len(origins) > 1:
        raise MixedOriginError(
            "refusing to merge records from different origins: "
            + ", ".join(sorted(o.value for o in origins))
        )
    cves = {item.cve for item in items}
    if len(cves) > 1:
        raise ValidationError("refusing to merge records for different CVEs", field="cve")

    base = items[0]
    notes: list[str] = []
    conflicts: list[FieldConflict] = []

    def record_conflict(
        field_name: str, kept: object, discarded: Iterable[object], *,
        dissenters: Iterable[str] = (), note: str | None = None,
    ) -> None:
        """Record one disagreement as data **and** prose, from one decision.

        Generating the note from the conflict (rather than writing both by hand)
        is what keeps the two views from drifting: a future field cannot be given a
        prose note without also producing a structured one.
        """
        rendered = tuple(str(v) for v in discarded)
        if not rendered:
            return
        conflicts.append(
            FieldConflict(
                field=field_name,
                kept=str(kept),
                discarded=rendered,
                dissenters=tuple(sorted(set(dissenters))),
            )
        )
        notes.append(
            note
            or f"{field_name} disagreement across sources: "
            + ", ".join(sorted({*rendered, str(kept)}))
            + f" (kept: {kept})"
        )

    def sources_saying(attr: str, value: object) -> tuple[str, ...]:
        return tuple(
            s for i in items if getattr(i, attr) == value for s in i.sources
        )

    severity_values = {i.effective_severity for i in items if i.effective_severity is not Severity.UNKNOWN}
    severity = base.effective_severity
    if len(severity_values) > 1:
        ranked = sorted(severity_values, key=lambda s: list(Severity).index(s))
        severity = ranked[-1]
        losers = [v for v in severity_values if v is not severity]
        record_conflict(
            "severity", severity.value, [v.value for v in losers],
            dissenters=[src for v in losers for src in sources_saying("effective_severity", v)],
            note="severity disagreement across sources: "
            + ", ".join(sorted(s.value for s in severity_values))
            + f" (highest kept: {severity.value})",
        )

    cvss, cvss_notes, cvss_conflicts = _merge_cvss(*(i.cvss for i in items))
    notes.extend(cvss_notes)
    for version, kept_score, discarded_scores in cvss_conflicts:
        conflicts.append(
            FieldConflict(
                field=f"cvss.{version}",
                kept=f"{kept_score:.1f}",
                discarded=tuple(f"{v:.1f}" for v in discarded_scores),
            )
        )

    def pick(attr: str):
        values = [getattr(i, attr) for i in items if getattr(i, attr) is not None]
        if not values:
            return None
        kept = values[0]
        # Previously this noted "earliest kept" and threw the rest away, so the
        # merged record could say sources disagreed but not what any of them said.
        losers = [v for v in values[1:] if str(v) != str(kept)]
        record_conflict(
            attr, kept, losers,
            dissenters=[s for v in losers for s in sources_saying(attr, v)],
            note=f"{attr} disagreement across sources; earliest kept",
        )
        return kept

    def union(attr: str) -> tuple:
        out: list = []
        seen: set[str] = set()
        for item in items:
            for value in getattr(item, attr):
                key = str(value)
                if key not in seen:
                    seen.add(key)
                    out.append(value)
        return tuple(out)

    epss_scores = {i.epss_score for i in items if i.epss_score is not None}
    if len(epss_scores) > 1:
        top = max(epss_scores)
        record_conflict(
            "epss_score", f"{top:.4f}", [f"{v:.4f}" for v in epss_scores if v != top],
            dissenters=[s for i in items if i.epss_score is not None
                        and i.epss_score != top for s in i.sources],
            note="epss_score disagreement across sources; highest kept",
        )

    kev_values = {i.kev for i in items if i.kev is not None}
    kev = None
    if kev_values:
        kev = True in kev_values
        if len(kev_values) > 1:
            record_conflict(
                "kev", kev, [not kev],
                dissenters=[s for i in items if i.kev is not None
                            and i.kev is not kev for s in i.sources],
                note="kev disagreement across sources: CISA KEV membership asserted by some, denied by others (presence kept)",
            )

    verification = next(
        (i.verification for i in items if i.verification == "verified"), "unverified"
    )

    # Standing is merged by taking the *most cautious* description, not the first
    # or the loudest. If one source has withdrawn a record and another has not yet
    # caught up, presenting it as confidently published would be the wrong way to
    # resolve the disagreement: acting on a rejected CVE wastes effort, while
    # hesitating over a live one is recoverable.
    statuses = [i.record_status for i in items if i.record_status is not None]
    record_status = strictest_status(statuses)
    if len(set(statuses)) > 1:
        kept_status = record_status.value if record_status else "none"
        record_conflict(
            "record_status", kept_status,
            sorted({s.value for s in set(statuses)} - {kept_status}),
            dissenters=[s for i in items if i.record_status is not None
                        and i.record_status is not record_status for s in i.sources],
            note="sources disagree on record standing: "
            + ", ".join(sorted(s.value for s in set(statuses)))
            + f" (most cautious kept: {kept_status})",
        )
    withdrawn = min(
        (i.withdrawn for i in items if i.withdrawn is not None), default=None
    )

    # SSVC inputs are provider assertions; the union is a merge, but a *conflicting*
    # value for the same key is a real disagreement and must be reported rather than
    # silently resolved by whichever record happened to come first.
    ssvc_values: dict[str, set[str]] = {}
    for item in items:
        for key, value in item.ssvc:
            ssvc_values.setdefault(key, set()).add(value)
    for key, values in sorted(ssvc_values.items()):
        if len(values) > 1:
            record_conflict(
                f"ssvc.{key}", "dropped", sorted(values),
                dissenters=[s for i in items for k, v in i.ssvc
                            if k == key and v in values for s in i.sources],
                note=f"SSVC input '{key}' disagrees across sources: "
                + ", ".join(sorted(values))
                + " (input dropped rather than guessed)",
            )
    ssvc = tuple(
        (key, next(iter(values)))
        for key, values in sorted(ssvc_values.items())
        if len(values) == 1
    )

    return replace(
        base,
        severity=severity,
        cvss=cvss,
        summary=pick("summary"),
        details=pick("details"),
        published=pick("published"),
        modified=pick("modified"),
        aliases=union("aliases"),
        cwe=union("cwe"),
        references=union("references"),
        affected=union("affected"),
        provenance=union("provenance"),
        sources=tuple(sorted({*[s for i in items for s in i.sources]})),
        kev=kev,
        kev_date_added=pick("kev_date_added"),
        kev_due_date=pick("kev_due_date"),
        known_exploited=pick("known_exploited"),
        epss_score=max(epss_scores) if epss_scores else None,
        epss_percentile=max(
            (i.epss_percentile for i in items if i.epss_percentile is not None), default=None
        ),
        epss_model_date=pick("epss_model_date"),
        # Previously omitted from the merged record: a merged record silently lost
        # every SSVC input, so CISA's assessment vanished as soon as two sources
        # corroborated the same CVE. Found by reading the merge against the field
        # list rather than by a failing test.
        ssvc=ssvc,
        record_status=record_status,
        withdrawn=withdrawn,
        conflicts=tuple(
            dict.fromkeys([*base.conflicts, *conflicts])
        ),
        conflict_notes=tuple(dict.fromkeys([*base.conflict_notes, *notes])),
        verification=verification,
    )


def coerce_text(value: object, *, field_name: str, limit: int = 20000) -> str | None:
    """Trimmed string or ``None``; oversized/ill-typed input is a validation error."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError("expected a string", field=field_name)
    text = value.strip()
    if not text:
        return None
    if len(text) > limit:
        raise ValidationError(f"text exceeds {limit} characters", field=field_name)
    return text


def parse_timestamp(value: object, *, field_name: str) -> datetime | None:
    """Parse ISO-8601 into an aware UTC datetime, or ``None`` when absent.

    Handles the trailing ``Z`` used by OSV and the space-separated form used by
    NVD's ``published``/``lastModified`` fields.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError("timestamp must be a string", field=field_name)
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValidationError(f"unparseable timestamp: {value!r}", field=field_name) from exc
    if parsed.tzinfo is None:
        # NVD historically emits naive UTC; interpreting as UTC is documented
        # behaviour for that source only (see connectors.nvd).
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def mapping_list(value: object, *, field_name: str) -> list[Mapping[str, Any]]:
    """Strict list-of-objects accessor used by the connectors."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValidationError("expected a list", field=field_name)
    out: list[Mapping[str, Any]] = []
    for entry in value:
        if not isinstance(entry, Mapping):
            raise ValidationError("expected list of objects", field=field_name)
        out.append(entry)
    return out
