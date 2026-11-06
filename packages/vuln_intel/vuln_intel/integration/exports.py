"""Serve the interop exports from rows that are already in the store.

The gap this closes
-------------------
``interop/vex.py`` (CycloneDX VEX), ``interop/openvex.py`` (OpenVEX) and
``interop/sarif.py`` were complete and tested, and **nothing called them except the
golden-file generator**. A downstream team that wanted our VEX verdicts had no way to
get them from the running service; the adapters could only be reached from Python by
anyone who already had a live :class:`AssessmentReport` in hand.

That is the difference between a capability and a library function. This module is the
bridge: it reads a tenant's stored rows, rebuilds the model objects the adapters expect,
evaluates exposure against a supplied inventory, and returns a document.

What is rebuilt, and what is honestly not
-----------------------------------------
Stored rows carry two things: source ``details`` and the ``cicc_enrichment`` block. The
record type is rebuilt from both, so a record that goes in and comes out of the store
produces the same CVSS, KEV state, EPSS figures, conflicts and CVE identity. Fields that
were never persisted cannot be invented, and where a field is missing the rebuild leaves
it missing rather than guessing a default — a fabricated severity would be worse than a
null one.

The one thing this module refuses to do is *assess* without an inventory. ``to_vex``
needs an :class:`AssessmentReport`, whose ``exposure`` block comes from matching records
against installed packages. With no inventory there is no exposure, so the export is
empty-but-explicit: every CVE is reported in ``unassessed``. Returning a document that
claims everything is fine would be the worst possible answer, and it is the answer a
naive implementation gives.

Provenance
----------
Every document states the export time, the tool, and how many records it was built from,
and the result carries ``generated_at`` separately from the document so a caller can
record what it actually served. Two documents built from the same rows at the same
instant are byte-identical, because the adapters derive their identifiers from content.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Sequence

from ..assessment import workflow_for
from ..interop.openvex import OpenVexExport, to_openvex
from ..interop.sarif import to_sarif
from ..interop.vex import VexExport, to_vex
from ..schema import (
    AffectedPackage,
    CveId,
    CvssScore,
    NormalizedVulnerability,
    Origin,
    Severity,
)
from ..watchlist import Dependency, Inventory

__all__ = [
    "ExportUnavailable",
    "InteropExport",
    "build_inventory",
    "export_openvex",
    "export_sarif",
    "export_vex",
    "record_from_row",
]

#: Raised when an export cannot be produced truthfully (as opposed to producing an empty
#: but accurate document). Distinct from returning nothing.
class ExportUnavailable(RuntimeError):
    """The requested document cannot be produced from the available data."""


@dataclass(frozen=True)
class InteropExport:
    """A document, its time, and what it was built from."""

    document: Mapping[str, Any]
    generated_at: datetime
    record_count: int
    #: CVEs that carry no exposure assessment, so no verdict could be stated.
    unassessed: tuple[str, ...] = ()
    #: True when the tenant had no stored records at all.
    empty: bool = False


def _severity(value: object) -> Severity:
    if isinstance(value, str):
        try:
            return Severity(value.strip().lower())
        except ValueError:
            return Severity.UNKNOWN
    return Severity.UNKNOWN


def record_from_row(row: Mapping[str, Any]) -> NormalizedVulnerability:
    """Rebuild a :class:`NormalizedVulnerability` from a stored row.

    Reads ``details`` first and the enrichment block as fallback, matching
    :func:`..integration.api.shape_record`'s dual-read rule. A test asserts a record
    survives ``to_store_payload`` -> ``record_from_row`` with its CVSS, KEV and EPSS
    intact, because a rebuild that silently drops severity would produce a VEX document
    claiming everything is unknown — accurate-looking and useless.
    """
    details = dict(row.get("details") or {})
    enrichment = dict(details.get("cicc_enrichment") or {})

    def pick(*keys: str) -> Any:
        for key in keys:
            if key in details and details[key] is not None:
                return details[key]
            if key in enrichment and enrichment[key] is not None:
                return enrichment[key]
        return None

    cve_raw = row.get("cve") or details.get("cve_id") or enrichment.get("cve_id")
    if not cve_raw:
        raise ExportUnavailable("stored row has no CVE identifier; refusing to invent one")

    origin_raw = pick("origin")
    if not origin_raw:
        # Origin is not optional on the record type, and there is no "unknown" member,
        # so an absent origin is a store invariant violation rather than something to
        # paper over: guessing FIXTURE would be safe, guessing LIVE would be a lie.
        raise ExportUnavailable(
            f"stored row for {cve_raw} has no origin; refusing to guess whether this "
            "record is live or synthetic"
        )
    try:
        origin = Origin(str(origin_raw))
    except ValueError as exc:
        raise ExportUnavailable(f"stored row for {cve_raw} has unknown origin {origin_raw!r}") from exc

    cvss: list[CvssScore] = []
    for score in details.get("cvss") or []:
        if not isinstance(score, Mapping):
            continue
        try:
            cvss.append(
                CvssScore(
                    version=str(score.get("version") or ""),
                    base_score=float(score.get("base_score") or 0.0),
                    severity=_severity(score.get("severity")),
                    vector=str(score.get("vector") or ""),
                    source=score.get("source"),
                )
            )
        except (TypeError, ValueError):
            # A single unreadable score must not discard the record; the remaining
            # scores still describe it, and dropping them all would understate severity.
            continue

    affected: list[AffectedPackage] = []
    for entry in details.get("affected") or []:
        if not isinstance(entry, Mapping):
            continue
        try:
            affected.append(
                AffectedPackage(
                    ecosystem=str(entry.get("ecosystem") or ""),
                    name=str(entry.get("name") or ""),
                    introduced=entry.get("introduced"),
                    fixed=entry.get("fixed"),
                    versions=tuple(entry.get("versions") or ()),
                )
            )
        except (TypeError, ValueError):
            continue

    epss = enrichment.get("epss") or {}
    kev_value = enrichment.get("kev")
    return NormalizedVulnerability(
        cve=CveId.parse(str(cve_raw)),
        origin=origin,
        summary=details.get("summary"),
        details=details.get("details") or details.get("description"),
        affected=tuple(affected),
        cvss=tuple(cvss),
        cwe=tuple(str(item) for item in details.get("cwe") or ()),
        kev=bool(kev_value) if kev_value is not None else None,
        epss_score=epss.get("score"),
        epss_percentile=epss.get("percentile"),
        sources=tuple(str(item) for item in enrichment.get("contributing_sources") or ()),
    )


def build_inventory(
    dependencies: Sequence[Mapping[str, Any]] | None,
) -> Inventory | None:
    """Build an :class:`Inventory` from plain mappings, or ``None`` when not supplied.

    ``None`` and ``[]`` are different and are kept different: no inventory at all means
    exposure was never evaluated, while an empty inventory means "nothing is installed",
    which is a real answer that happens to produce no matches. Collapsing them would let
    a caller forget to pass inventory and receive a document implying a clean estate.
    """
    if dependencies is None:
        return None
    built: list[Dependency] = []
    for entry in dependencies:
        try:
            built.append(
                Dependency(
                    ecosystem=str(entry.get("ecosystem") or ""),
                    name=str(entry.get("name") or ""),
                    version=str(entry.get("version") or ""),
                    asset=entry.get("asset"),
                )
            )
        except (TypeError, ValueError) as exc:
            raise ExportUnavailable(f"invalid dependency entry: {exc}") from exc
    return Inventory(dependencies=tuple(built))


def _report(
    rows: Sequence[Mapping[str, Any]],
    *,
    dependencies: Sequence[Mapping[str, Any]] | None,
    now: datetime,
):
    records = [record_from_row(row) for row in rows]
    inventory = build_inventory(dependencies)
    # With no inventory the report still gets built: it carries ratings and references,
    # and every adapter lists the unassessed CVEs explicitly instead of omitting them.
    return workflow_for(records=records, inventory=inventory, now=lambda: now)


def export_vex(
    rows: Sequence[Mapping[str, Any]],
    *,
    now: datetime,
    dependencies: Sequence[Mapping[str, Any]] | None = None,
    tool: str = "cicc-vuln-intel",
    tool_version: str = "0.1.0",
) -> tuple[InteropExport, VexExport]:
    """CycloneDX VEX for a tenant's stored rows."""
    report = _report(rows, dependencies=dependencies, now=now)
    vex = to_vex(report, generated_at=now, tool=tool, tool_version=tool_version)
    return (
        InteropExport(
            document=vex.document,
            generated_at=now,
            record_count=len(rows),
            unassessed=vex.unassessed,
            empty=not rows,
        ),
        vex,
    )


def export_openvex(
    rows: Sequence[Mapping[str, Any]],
    *,
    now: datetime,
    dependencies: Sequence[Mapping[str, Any]] | None = None,
    tool: str = "cicc-vuln-intel",
    tool_version: str = "0.1.0",
) -> tuple[InteropExport, OpenVexExport]:
    """OpenVEX for a tenant's stored rows."""
    report = _report(rows, dependencies=dependencies, now=now)
    openvex = to_openvex(report, generated_at=now, tool=tool, tool_version=tool_version)
    return (
        InteropExport(
            document=openvex.document,
            generated_at=now,
            record_count=len(rows),
            unassessed=openvex.unassessed,
            empty=not rows,
        ),
        openvex,
    )


def export_sarif(
    rows: Sequence[Mapping[str, Any]],
    *,
    now: datetime,
    dependencies: Sequence[Mapping[str, Any]] | None = None,
    tool: str = "cicc-vuln-intel",
    tool_version: str | None = "0.1.0",
) -> InteropExport:
    """SARIF for a tenant's stored rows.

    SARIF is a *results* format, so it describes findings rather than assertions about
    them. The exposure report supplies the findings; with no inventory there are none,
    and the export is empty for the honest reason that nothing was evaluated.
    """
    report = _report(rows, dependencies=dependencies, now=now)
    document = to_sarif(report, tool=tool, tool_version=tool_version)
    return InteropExport(
        document=document,
        generated_at=now,
        record_count=len(rows),
        empty=not rows,
    )
