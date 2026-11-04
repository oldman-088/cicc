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
    provenance: tuple[ProvenanceRecord, ...] = ()
    sources: tuple[str, ...] = ()
    conflict_notes: tuple[str, ...] = ()
    verification: str = "unverified"

    def __post_init__(self) -> None:
        if not isinstance(self.cve, CveId):
            raise ValidationError("record must carry a validated CveId", field="cve")
        if not isinstance(self.origin, Origin):
            raise ValidationError("record must declare an explicit origin", field="origin")
        _ensure_aware(self.published, field_name="published")
        _ensure_aware(self.modified, field_name="modified")
        _ensure_aware(self.kev_date_added, field_name="kev_date_added")
        if self.epss_score is not None and not 0.0 <= self.epss_score <= 1.0:
            raise ValidationError("EPSS score must be within 0.0-1.0", field="epss_score")
        if self.epss_percentile is not None and not 0.0 <= self.epss_percentile <= 1.0:
            raise ValidationError(
                "EPSS percentile must be within 0.0-1.0", field="epss_percentile"
            )

    # -- convenience ------------------------------------------------------
    @property
    def best_cvss(self) -> CvssScore | None:
        """Highest assessed CVSS v3 score, or ``None`` when nothing is scored."""
        scored = [c for c in self.cvss if c.assessed and c.version.startswith("3")]
        return max(scored, key=lambda c: c.base_score, default=None)

    @property
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

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "status": self.status.value,
            "checked_at": self.checked_at.isoformat(),
            "last_success": self.last_success.isoformat() if self.last_success else None,
            "error": self.error,
            "retry_after": self.retry_after,
            "records": self.records,
        }


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
    left: Sequence[CvssScore], right: Sequence[CvssScore]
) -> tuple[tuple[CvssScore, ...], list[str]]:
    """Union by (version, vector, source); flag divergent scores for one version."""
    merged: list[CvssScore] = []
    notes: list[str] = []
    seen: set[tuple[str, str | None, str | None]] = set()
    for score in list(left) + list(right):
        key = (score.version, score.vector, score.source)
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
            notes.append(
                f"CVSS {version} disagreement across sources: "
                + ", ".join(f"{v:.1f}" for v in sorted(values))
            )
    return tuple(merged), notes


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
    severity_values = {i.effective_severity for i in items if i.effective_severity is not Severity.UNKNOWN}
    severity = base.effective_severity
    if len(severity_values) > 1:
        ranked = sorted(severity_values, key=lambda s: list(Severity).index(s))
        severity = ranked[-1]
        notes.append(
            "severity disagreement across sources: "
            + ", ".join(sorted(s.value for s in severity_values))
            + f" (highest kept: {severity.value})"
        )

    cvss, cvss_notes = _merge_cvss(*(i.cvss for i in items))
    notes.extend(cvss_notes)

    def pick(attr: str):
        values = [getattr(i, attr) for i in items if getattr(i, attr) is not None]
        if not values:
            return None
        unique = {str(v) for v in values}
        if len(unique) > 1:
            notes.append(f"{attr} disagreement across sources; earliest kept")
        return values[0]

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
        notes.append("EPSS disagreement across sources; highest kept")

    kev_values = {i.kev for i in items if i.kev is not None}
    kev = None
    if kev_values:
        kev = True in kev_values
        if len(kev_values) > 1:
            notes.append("sources disagree on CISA KEV membership; presence kept")

    verification = next(
        (i.verification for i in items if i.verification == "verified"), "unverified"
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
