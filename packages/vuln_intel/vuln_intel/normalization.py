"""Unified CVE normalization across NVD, OSV, CISA KEV and EPSS.

The connectors each produce :class:`~vuln_intel.schema.NormalizedVulnerability`.
This module combines them into a single per-CVE view and enforces the
separation rules that keep demo data out of real intelligence.

Conflict policy (deliberate and conservative):

* nothing is silently overwritten — disagreements land in ``conflict_notes`` and
  the *highest* severity wins (a downgrade must be a human decision);
* a CVE only counts as corroborated when two or more sources contributed;
* merging never upgrades ``verification`` above what a source asserted.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import date, datetime
from typing import Iterable, Mapping, Sequence

from .errors import MixedOriginError, ValidationError
from .schema import (
    CveId,
    Freshness,
    NormalizedVulnerability,
    Origin,
    ProvenanceRecord,
    SourceKind,
    compute_freshness,
    merge_records,
    utcnow,
)

__all__ = [
    "KevSignal",
    "attach_epss",
    "attach_kev",
    "corroboration_report",
    "index_kev",
    "normalize_sources",
]

_ORIGIN_TO_SOURCE_ORIGIN = {
    "live": "live",
    "fixture": "fixture",
    "demo": "demo",
    "cached": "cached",
}


class KevSignal:
    """CISA KEV membership for a CVE.

    ``checked`` matters: ``listed=False`` is only meaningful when the catalog was
    actually consulted.  Without that flag, absence of KEV data would look like
    "not exploited", which is exactly the kind of false reassurance the project
    forbids.
    """

    __slots__ = ("catalog_version", "checked", "cve", "date_added", "due_date", "listed")

    def __init__(
        self,
        cve: CveId,
        *,
        listed: bool,
        date_added: datetime | None = None,
        due_date: date | None = None,
        checked: bool = True,
        catalog_version: str | None = None,
    ) -> None:
        self.cve = cve
        self.listed = listed
        self.date_added = date_added
        self.due_date = due_date
        self.checked = checked
        self.catalog_version = catalog_version

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"KevSignal({self.cve!s}, listed={self.listed}, checked={self.checked})"
        )


def index_kev(payload: Mapping[str, object]) -> dict[str, KevSignal]:
    """Index a CISA KEV catalog payload by CVE string.

    Accepts the documented catalog shape::

        {"catalogVersion": "...", "dateReleased": "...",
         "vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", ...}]}

    Unparseable entries raise rather than being skipped: a partially indexed KEV
    catalog would produce false "not listed" answers.
    """
    entries = payload.get("vulnerabilities")
    if not isinstance(entries, list):
        raise ValidationError("KEV payload has no 'vulnerabilities' list", field="vulnerabilities")
    version = payload.get("catalogVersion")
    catalog_version = version if isinstance(version, str) else None
    index: dict[str, KevSignal] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise ValidationError("KEV entry is not an object", field="vulnerabilities")
        raw = entry.get("cveID")
        cve = CveId.parse(raw)
        added_raw = entry.get("dateAdded")
        added: datetime | None = None
        if isinstance(added_raw, str) and added_raw.strip():
            try:
                added = datetime.fromisoformat(added_raw.strip()).replace(
                    tzinfo=utcnow().tzinfo
                )
            except ValueError as exc:
                raise ValidationError(
                    f"unparseable KEV dateAdded: {added_raw!r}", field="dateAdded"
                ) from exc
        due_raw = entry.get("dueDate")
        due: date | None = None
        if isinstance(due_raw, str) and due_raw.strip():
            try:
                # CISA publishes a calendar day.  A malformed deadline is a data
                # error worth surfacing, but it must not discard the membership
                # fact, which is the part that changes prioritisation.
                due = date.fromisoformat(due_raw.strip())
            except ValueError as exc:
                raise ValidationError(
                    f"unparseable KEV dueDate: {due_raw!r}", field="dueDate"
                ) from exc
        index[str(cve)] = KevSignal(
            cve,
            listed=True,
            date_added=added,
            due_date=due,
            checked=True,
            catalog_version=catalog_version,
        )
    return index


def normalize_sources(
    contributions: Iterable[NormalizedVulnerability],
    *,
    now: datetime | None = None,
) -> dict[str, NormalizedVulnerability]:
    """Group contributions by CVE and merge each group.

    Raises :class:`MixedOriginError` if a single CVE received contributions from
    more than one origin, so a demo record can never be folded into live data.
    """
    grouped: dict[str, list[NormalizedVulnerability]] = {}
    for record in contributions:
        grouped.setdefault(str(record.cve), []).append(record)

    merged: dict[str, NormalizedVulnerability] = {}
    for cve, items in grouped.items():
        origins = {item.origin for item in items}
        if len(origins) > 1:
            raise MixedOriginError(
                f"{cve} has contributions from multiple origins: "
                + ", ".join(sorted(o.value for o in origins))
            )
        combined = merge_records(items) if len(items) > 1 else items[0]
        if len({str(i.cve) for i in items}) > 1:  # defensive; merge_records checks too
            raise ValidationError("grouped records disagree on CVE", field="cve")
        merged[cve] = combined
    return merged


def attach_kev(
    record: NormalizedVulnerability,
    signal: KevSignal | None,
    *,
    fetched_at: datetime | None = None,
) -> NormalizedVulnerability:
    """Attach CISA KEV membership.

    ``signal=None`` means the catalog was **not** consulted: ``kev`` stays
    ``None`` (unknown) instead of ``False``.
    """
    if signal is not None and signal.cve != record.cve:
        raise ValidationError("KEV signal is for a different CVE", field="cve")
    if signal is None:
        return replace(
            record,
            conflict_notes=record.conflict_notes
            + ("CISA KEV not consulted: exploitation status unknown",),
        )
    notes = list(record.conflict_notes)
    if record.kev is not None and record.kev != signal.listed:
        notes.append("CISA KEV membership changed or disagreed with earlier data")
    provenance = record.provenance
    if signal.checked:
        provenance = provenance + (
            ProvenanceRecord(
                source="cisa-kev",
                source_ref=signal.catalog_version,
                fetched_at=fetched_at or utcnow(),
                transport="catalog",
                url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            ),
        )
    sources = tuple(sorted({*record.sources, "cisa-kev"})) if signal.checked else record.sources
    return replace(
        record,
        kev=signal.listed,
        kev_date_added=signal.date_added,
        kev_due_date=signal.due_date,
        known_exploited=signal.listed,
        provenance=provenance,
        sources=sources,
        conflict_notes=tuple(dict.fromkeys(notes)),
    )


def attach_epss(
    record: NormalizedVulnerability,
    score: object | None,
) -> NormalizedVulnerability:
    """Attach an EPSS observation.

    ``score`` is any object exposing ``score``/``percentile``/``model_date``/
    ``origin`` (i.e. :class:`~vuln_intel.connectors.epss.EpssScore`).  Passing
    ``None`` leaves the fields unset — EPSS stays *unavailable*, never zero.

    A fixture/demo EPSS value can never be attached to a live record.
    """
    if score is None:
        return record
    origin = getattr(score, "origin", None)
    if origin in ("fixture", "demo") and record.origin is Origin.LIVE:
        raise MixedOriginError(
            f"refusing to attach {origin} EPSS data to a live record ({record.cve})"
        )
    value = getattr(score, "score", None)
    percentile = getattr(score, "percentile", None)
    if value is None or percentile is None:
        raise ValidationError("EPSS score object is incomplete", field="epss")
    return replace(
        record,
        epss_score=float(value),
        epss_percentile=float(percentile),
        epss_model_date=getattr(score, "model_date", None),
        provenance=record.provenance
        + (
            ProvenanceRecord(
                source=SourceKind.EPSS,
                source_ref=getattr(score, "model_version", None),
                fetched_at=getattr(score, "observed_at", utcnow()),
                transport=origin or "unknown",
                url="https://api.first.org/data/v1/epss",
            ),
        ),
        sources=tuple(sorted({*record.sources, "epss"})),
    )


def corroboration_report(
    records: Sequence[NormalizedVulnerability],
    *,
    now: datetime | None = None,
) -> list[dict[str, object]]:
    """Per-record corroboration and freshness facts, for dashboards and audits."""
    now = now or utcnow()
    report: list[dict[str, object]] = []
    for record in records:
        freshness: Freshness = compute_freshness(record.modified or record.published, now=now)
        sources = sorted(set(record.sources))
        report.append(
            {
                "cve": str(record.cve),
                "origin": record.origin.value,
                "sources": sources,
                "source_count": len(sources),
                "corroborated": len(sources) >= 2,
                "verification": record.verification,
                "freshness": freshness.bucket,
                "age_hours": round(freshness.age.total_seconds() / 3600, 1)
                if freshness.age
                else None,
                "kev": record.kev,
                "epss": record.epss_score,
                "conflicts": list(record.conflict_notes),
            }
        )
    return report
