"""Read-only comparison of host-side and package-side vulnerability records.

Why this exists
---------------
Two ingestion paths write the same facts into two schemas
(:doc:`docs/vulnerability-intelligence/SOURCE_DIVERGENCE.md`). Before either path can
be consolidated, someone has to know *how far apart they already are* — and today
nothing can answer that. This module answers it without touching either side.

How "read-only" is enforced
---------------------------
Not by convention, and not by a flag someone can set to ``False``. The API takes
sequences of mappings. It has no connection, no session, no store, no port, and imports
nothing that can write. A caller handed the rows from whatever it likes; this module
returns a report and mutates nothing — including not normalising the input rows in
place. That makes "never updates, deletes or reconciles" a property of the type
signature rather than a promise in a docstring.

What it deliberately refuses to do
----------------------------------
It does not pick a winner, merge a record, or propose a fix. When the two sides
disagree, the report says what disagreed and stops there. Choosing which side is right
is the owner decision this module exists to inform, not to make.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

__all__ = [
    "SHARED_FIELDS",
    "ComparisonReport",
    "FieldVerdict",
    "RecordComparison",
    "compare_records",
]

#: The fields both schemas actually write. Everything else is one-sided and comparing
#: it would produce a difference for every record that says nothing.
SHARED_FIELDS = ("cve_id", "published", "last_modified", "descriptions")

#: Verdicts for a single field, ordered from "no difference" to "real difference".
IDENTICAL = "identical"
#: Same instant, different spelling (``2026-01-01T00:00:00Z`` vs ``...+00:00``).
TIMESTAMP_FORMAT = "timestamp_format"
#: Same set of items, different order. Not a contradiction, but not byte-identical.
ORDERING = "ordering"
#: Genuinely different content. This is the only verdict that is a real disagreement.
SEMANTIC = "semantic"
#: The field exists on one side only.
ABSENT = "absent"

#: Record-level statuses.
RECORD_IDENTICAL = "identical"
#: Every difference is a representation difference (format or ordering).
RECORD_REPRESENTATION = "representation_only"
#: At least one field genuinely disagrees.
RECORD_CONFLICTING = "conflicting"
#: Present on both sides but one observation is older than the other.
RECORD_STALE = "stale"
#: Present on one side only.
RECORD_HOST_ONLY = "host_only"
RECORD_PACKAGE_ONLY = "package_only"


@dataclass(frozen=True)
class FieldVerdict:
    """What comparing one field found, with the evidence for the conclusion."""

    name: str
    verdict: str
    host_value: Any = None
    package_value: Any = None
    note: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "field": self.name,
            "verdict": self.verdict,
            "host_value": _jsonable(self.host_value),
            "package_value": _jsonable(self.package_value),
            "note": self.note,
        }


@dataclass(frozen=True)
class RecordComparison:
    """One CVE, seen from both sides."""

    cve: str
    status: str
    fields: tuple[FieldVerdict, ...] = ()
    #: Host provenance, preserved verbatim so the report can be audited later.
    host_first_collected_at: str | None = None
    host_last_collected_at: str | None = None
    #: Package provenance.
    package_collected_at: str | None = None
    package_origin: str | None = None
    #: Which side is behind, when status is ``stale``.
    stale_side: str | None = None
    note: str | None = None

    @property
    def differing_fields(self) -> tuple[str, ...]:
        return tuple(f.name for f in self.fields if f.verdict not in (IDENTICAL, ABSENT))

    @property
    def semantic_fields(self) -> tuple[str, ...]:
        return tuple(f.name for f in self.fields if f.verdict == SEMANTIC)

    def as_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "status": self.status,
            "differing_fields": list(self.differing_fields),
            "semantic_fields": list(self.semantic_fields),
            "fields": [f.as_dict() for f in self.fields],
            "provenance": {
                "host_first_collected_at": self.host_first_collected_at,
                "host_last_collected_at": self.host_last_collected_at,
                "package_collected_at": self.package_collected_at,
                "package_origin": self.package_origin,
            },
            "stale_side": self.stale_side,
            "note": self.note,
        }


@dataclass
class ComparisonReport:
    """Machine-readable result of one comparison. Shaped like ``ImportReport``."""

    records: list[RecordComparison] = field(default_factory=list)
    #: The fields that were compared, so a reader knows what was *not* examined.
    compared_fields: tuple[str, ...] = SHARED_FIELDS
    #: Rows that could not be compared at all, with the reason.
    unusable: list[dict[str, Any]] = field(default_factory=list)

    def _count(self, status: str) -> int:
        return sum(1 for r in self.records if r.status == status)

    @property
    def identical(self) -> int:
        return self._count(RECORD_IDENTICAL)

    @property
    def representation_only(self) -> int:
        return self._count(RECORD_REPRESENTATION)

    @property
    def conflicting(self) -> int:
        return self._count(RECORD_CONFLICTING)

    @property
    def stale(self) -> int:
        return self._count(RECORD_STALE)

    @property
    def host_only(self) -> int:
        return self._count(RECORD_HOST_ONLY)

    @property
    def package_only(self) -> int:
        return self._count(RECORD_PACKAGE_ONLY)

    @property
    def compared(self) -> int:
        return len(self.records)

    @property
    def null_fields(self) -> list[dict[str, Any]]:
        """Every compared field where one side records no value, with both sides shown.

        Called out separately because "the package has no published date for this CVE"
        is a different question from "the two sides disagree about it", and an operator
        asked to fix the first should not have to scan per-field verdicts to find it.
        """
        out: list[dict[str, Any]] = []
        for record in self.records:
            # `verdict`, not `field`: the module imports `field` from dataclasses and
            # a loop variable of the same name silently shadows it.
            for verdict in record.fields:
                if verdict.verdict != SEMANTIC:
                    continue
                if verdict.host_value is not None and verdict.package_value is not None:
                    continue
                out.append(
                    {
                        "cve": record.cve,
                        "field": verdict.name,
                        "missing_side": (
                            "host" if verdict.host_value is None else "package"
                        ),
                        "host_value": _jsonable(verdict.host_value),
                        "package_value": _jsonable(verdict.package_value),
                        "note": verdict.note,
                    }
                )
        return out

    def as_dict(self) -> dict[str, Any]:
        return {
            "compared_fields": list(self.compared_fields),
            "totals": {
                "compared": self.compared,
                "identical": self.identical,
                "representation_only": self.representation_only,
                "conflicting": self.conflicting,
                "stale": self.stale,
                "host_only": self.host_only,
                "package_only": self.package_only,
                "unusable": len(self.unusable),
                "null_fields": len(self.null_fields),
            },
            "records": [r.as_dict() for r in self.records],
            # Explicit, so a `published: None` discrepancy is a named output rather
            # than something a reader has to discover inside a field verdict.
            "null_fields": self.null_fields,
            "unusable": list(self.unusable),
        }


# -- value canonicalisation -------------------------------------------------


def _as_instant(value: Any) -> datetime | None:
    """Parse a timestamp the way each side actually writes it, or None.

    Returns None rather than raising: an unparseable timestamp is a reportable fact,
    not a reason to abandon the whole comparison.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    # NVD writes 'Z', this package writes '+00:00'; both are the same instant.
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _canonical_descriptions(value: Any) -> Any:
    """Descriptions as a language→text mapping, so ordering is not a difference."""
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return value
    out: dict[str, str] = {}
    for item in value:
        if isinstance(item, Mapping):
            language = str(item.get("language") or "")
            out[language] = str(item.get("text") or "").strip()
        else:
            out[str(item)] = ""
    return out


def _compare_field(name: str, host: Any, package: Any) -> FieldVerdict:
    """Classify one field difference as format, ordering, or genuine."""
    # Checked first: the package emits every key with an explicit null, so one side
    # holding no value is the commonest real difference and must not be mistaken for
    # an unparseable timestamp further down.
    if host is None or package is None:
        missing = "host" if host is None else "package"
        return FieldVerdict(
            name,
            SEMANTIC,
            host,
            package,
            f"{missing} records no value; the other side does",
        )

    if name in ("published", "last_modified"):
        left, right = _as_instant(host), _as_instant(package)
        if left is None or right is None:
            note = "one side is not a parseable timestamp; compared as text"
            verdict = IDENTICAL if host == package else SEMANTIC
            return FieldVerdict(name, verdict, host, package, note)
        if left == right and str(host) == str(package):
            return FieldVerdict(name, IDENTICAL, host, package)
        if left == right:
            # Same instant, different spelling: a representation difference, not a
            # disagreement. Reporting it as a conflict would drown the real ones.
            return FieldVerdict(
                name,
                TIMESTAMP_FORMAT,
                host,
                package,
                "same instant, different representation",
            )
        return FieldVerdict(
            name,
            SEMANTIC,
            host,
            package,
            f"different instants: {left.isoformat()} vs {right.isoformat()}",
        )

    if name == "descriptions":
        left, right = _canonical_descriptions(host), _canonical_descriptions(package)
        if left == right:
            if (
                isinstance(host, Sequence)
                and isinstance(package, Sequence)
                and list(host) != list(package)
            ):
                return FieldVerdict(
                    name,
                    ORDERING,
                    host,
                    package,
                    "same descriptions in a different order",
                )
            return FieldVerdict(name, IDENTICAL, host, package)
        return FieldVerdict(name, SEMANTIC, host, package, "description content differs")

    # Anything else is compared as a plain value, case-insensitively for identifiers.
    if (
        name == "cve_id"
        and isinstance(host, str)
        and isinstance(package, str)
        and host.strip().upper() == package.strip().upper()
    ):
        return FieldVerdict(
            name,
            IDENTICAL if host == package else ORDERING,
            host,
            package,
            None if host == package else "same CVE in different case",
        )
    return FieldVerdict(name, IDENTICAL if host == package else SEMANTIC, host, package)


def _describe_difference(verdicts: Iterable[FieldVerdict]) -> str:
    """Record-level status, from the strongest difference found."""
    seen = {v.verdict for v in verdicts}
    if SEMANTIC in seen:
        return RECORD_CONFLICTING
    if seen & {TIMESTAMP_FORMAT, ORDERING}:
        return RECORD_REPRESENTATION
    if seen == {ABSENT} or not seen:
        return RECORD_REPRESENTATION
    return RECORD_IDENTICAL


# -- entry point ------------------------------------------------------------


def _key(row: Mapping[str, Any], *, cve_field: str) -> str | None:
    value = row.get(cve_field) or (row.get("details") or {}).get("cve_id")
    if not value:
        return None
    return str(value).strip().upper()


def compare_records(
    *,
    host_rows: Iterable[Mapping[str, Any]],
    package_rows: Iterable[Mapping[str, Any]],
    host_cve_field: str = "cve_id",
    package_cve_field: str = "cve",
    stale_threshold_seconds: int = 0,
) -> ComparisonReport:
    """Compare two sets of rows, keyed by CVE. Never writes to either side.

    ``stale_threshold_seconds`` is explicit rather than a magic constant: two imports
    minutes apart are normal, so "stale" is a judgement the caller must make and state.
    """
    report = ComparisonReport()

    host: dict[str, Mapping[str, Any]] = {}
    for row in host_rows:
        key = _key(row, cve_field=host_cve_field)
        if key is None:
            report.unusable.append(
                {"side": "host", "reason": "no CVE identifier", "row_keys": sorted(row)}
            )
            continue
        if key in host:
            report.unusable.append(
                {"side": "host", "reason": "duplicate CVE in host input", "cve": key}
            )
            continue
        host[key] = row

    package: dict[str, Mapping[str, Any]] = {}
    for row in package_rows:
        key = _key(row, cve_field=package_cve_field)
        if key is None:
            report.unusable.append(
                {"side": "package", "reason": "no CVE identifier", "row_keys": sorted(row)}
            )
            continue
        if key in package:
            report.unusable.append(
                {"side": "package", "reason": "duplicate CVE in package input", "cve": key}
            )
            continue
        package[key] = row

    for key in sorted(set(host) | set(package)):
        host_row, package_row = host.get(key), package.get(key)
        host_details = dict(host_row.get("details") or {}) if host_row else {}
        package_details = dict(package_row.get("details") or {}) if package_row else {}

        if host_row is None:
            report.records.append(
                RecordComparison(
                    cve=key,
                    status=RECORD_PACKAGE_ONLY,
                    host_first_collected_at=None,
                    host_last_collected_at=None,
                    package_collected_at=_text(_stamp(package_row, "collected_at")),
                    package_origin=_origin_of(package_row),
                )
            )
            continue
        if package_row is None:
            report.records.append(
                RecordComparison(
                    cve=key,
                    status=RECORD_HOST_ONLY,
                    host_first_collected_at=_text(_stamp(host_row, "first_collected_at")),
                    host_last_collected_at=_text(_stamp(host_row, "last_collected_at")),
                    package_collected_at=None,
                    package_origin=None,
                )
            )
            continue

        verdicts: list[FieldVerdict] = []
        for name in SHARED_FIELDS:
            in_host, in_package = name in host_details, name in package_details
            if not in_host and not in_package:
                continue
            if in_host != in_package:
                verdicts.append(
                    FieldVerdict(
                        name,
                        ABSENT,
                        host_details.get(name),
                        package_details.get(name),
                        f"written by {'host' if in_host else 'package'} only",
                    )
                )
                continue
            verdicts.append(
                _compare_field(name, host_details.get(name), package_details.get(name))
            )

        status = _describe_difference(verdicts)
        stale_side = None
        if status != RECORD_CONFLICTING:
            stale_side = _staleness(host_row, package_row, stale_threshold_seconds)
            if stale_side:
                status = RECORD_STALE

        report.records.append(
            RecordComparison(
                cve=key,
                status=status,
                fields=tuple(verdicts),
                host_first_collected_at=_text(_stamp(host_row, "first_collected_at")),
                host_last_collected_at=_text(_stamp(host_row, "last_collected_at")),
                package_collected_at=_text(_stamp(package_row, "collected_at")),
                package_origin=_origin_of(package_row),
                stale_side=stale_side,
            )
        )
    return report


def _stamp(row: Mapping[str, Any] | None, *names: str) -> Any:
    if row is None:
        return None
    for name in names:
        if row.get(name) is not None:
            return row[name]
    return None


def _origin_of(row: Mapping[str, Any] | None) -> str | None:
    """The package's own origin marker, preserved so a fixture row is visible."""
    if row is None:
        return None
    origin = row.get("origin")
    return str(origin) if origin else None


def _text(value: Any) -> str | None:
    """Timestamps as ISO text, so the report is JSON without a custom encoder."""
    if value is None:
        return None
    instant = _as_instant(value)
    return instant.isoformat() if instant else str(value)


def _staleness(
    host_row: Mapping[str, Any], package_row: Mapping[str, Any], threshold: int
) -> str | None:
    """Which side is behind, if either is beyond the caller's threshold.

    A threshold of 0 (or less) disables the judgement entirely rather than declaring
    any difference stale: the two sides are collected by different jobs at different
    times, so *some* gap is always present and calling it stale would be noise.
    """
    if threshold <= 0:
        return None
    host = _as_instant(_stamp(host_row, "last_collected_at", "first_collected_at"))
    package = _as_instant(_stamp(package_row, "collected_at"))
    if host is None or package is None:
        return None
    delta = (package - host).total_seconds()
    if delta > threshold:
        return "host"  # the host is behind the package
    if delta < -threshold:
        return "package"
    return None


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value
