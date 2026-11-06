"""B-08 (pure part): cross-run exposure rollup — which assets carry unresolved risk.

The storage decision (strategy A/B) is still pending with the owner, so this
module implements **only the domain calculation**: a pure, fixture-testable
aggregation over one or more :class:`~vuln_intel.assessment.AssessmentReport`
runs.  The durable boundary is a documented :class:`ExposureRollupStore`
protocol — an adapter can be written the moment the owner picks a strategy;
nothing here invents persistence or chooses A/B on the owner's behalf.

Semantics:

* **dedup**: the same (cve, package, version) affected in several runs counts
  once; the verdict is taken from the *newest* run that evaluated it;
* **conflict**: if one run says AFFECTED and a newer run says NOT_AFFECTED for
  the same triple, the AFFECTED claim is kept and the pair is flagged
  ``conflicted`` — a disagreement is never silently resolved towards "safe";
* **freshness**: each input report carries its ``run_at``; the rollup reports
  the newest input and marks inputs older than ``max_age`` as ``stale``
  (stale inputs still contribute, labelled — they are not dropped);
* **confidence**: per-asset confidence is derived, never source-reported:
  ``high`` when every contributing input is fresh and no unverified matches
  exist, ``medium`` when fresh but some unverified, ``low`` when any input is
  stale. It is always labelled as calculated.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable, Protocol, Sequence

from .assessment import AssessmentReport
from .schema import utcnow
from .watchlist import PackageMatch

__all__ = [
    "AssetExposure",
    "ExposureRollup",
    "ExposureRollupStore",
    "rollup_exposures",
]


class ExposureRollupStore(Protocol):
    """Durable boundary for rollups. NOT implemented here — storage strategy is
    an owner decision. An adapter (SQL or otherwise) implements this once
    approved."""

    def save_rollup(self, *, tenant_id: str, rollup: ExposureRollup) -> None:  # pragma: no cover
        ...

    def load_rollup(self, *, tenant_id: str) -> ExposureRollup | None:  # pragma: no cover
        ...


@dataclass(frozen=True)
class AssetExposure:
    """One asset's aggregated exposure across runs."""

    asset: str
    affected: tuple[tuple[str, str, str], ...]  # (cve, package, version)
    conflicted: tuple[tuple[str, str, str], ...] = ()
    kev_affected: tuple[str, ...] = ()  # CVEs that are both affected and KEV-listed
    distinct_cves: int = 0
    confidence: str = "unknown"  # calculated, never source-reported

    def as_dict(self) -> dict[str, Any]:
        return {
            "asset": self.asset,
            "affected": [list(t) for t in self.affected],
            "conflicted": [list(t) for t in self.conflicted],
            "kev_affected": list(self.kev_affected),
            "distinct_cves": self.distinct_cves,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class ExposureRollup:
    """The aggregated result plus provenance about its inputs."""

    generated_at: datetime
    assets: tuple[AssetExposure, ...]
    inputs: tuple[datetime, ...]  # run_at of every contributing report
    stale_inputs: tuple[datetime, ...]
    max_age: timedelta

    @property
    def newest_input(self) -> datetime | None:
        return max(self.inputs) if self.inputs else None

    @property
    def assets_at_risk(self) -> tuple[str, ...]:
        return tuple(sorted(a.asset for a in self.assets if a.affected))

    def as_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(),
            "newest_input": self.newest_input.isoformat() if self.newest_input else None,
            "inputs": [i.isoformat() for i in self.inputs],
            "stale_inputs": [i.isoformat() for i in self.stale_inputs],
            "max_age_days": self.max_age.days,
            "assets_at_risk": list(self.assets_at_risk),
            "assets": [a.as_dict() for a in self.assets],
        }


def _kev_by_cve(report: AssessmentReport) -> dict[str, bool | None]:
    return {str(c.merged.cve): c.merged.kev for c in report.clusters}


def rollup_exposures(
    reports: Iterable[AssessmentReport],
    *,
    max_age: timedelta = timedelta(days=7),
    now: datetime | None = None,
) -> ExposureRollup:
    """Aggregate per-asset exposure across assessment runs.

    Newest-run-wins per (cve, package, version) triple, except that an AFFECTED
    verdict is never overwritten by a NOT_AFFECTED one — the pair is flagged
    conflicted instead.
    """
    moment = now or utcnow()
    items = sorted(reports, key=lambda r: r.run_at)  # oldest first: newest wins
    # triple -> (verdict, run_at, kev)
    latest: dict[tuple[str, str, str, str], tuple[str, datetime, bool | None]] = {}
    conflicted: set[tuple[str, str, str, str]] = set()
    kev_cves: dict[str, bool | None] = {}

    for report in items:
        kev = _kev_by_cve(report)
        kev_cves.update(kev)
        pool: Sequence[PackageMatch] = ()
        if report.exposure is not None:
            pool = (*report.exposure.matches, *report.exposure.unverified,
                    *report.exposure.not_affected)
        for match in pool:
            asset = match.dependency.asset or "unknown"
            triple = (match.cve, match.dependency.canonical_name,
                      match.dependency.version, asset)
            verdict = match.assessment.verdict.value
            prev = latest.get(triple)
            if prev is not None and prev[0] == "affected" and verdict != "affected":
                conflicted.add(triple)
                continue  # keep affected; flag conflict
            latest[triple] = (verdict, report.run_at, kev.get(match.cve))

    by_asset: dict[str, list[tuple[str, str, str]]] = {}
    by_asset_conflicted: dict[str, list[tuple[str, str, str]]] = {}
    for (cve, package, version, asset), (verdict, _run_at, _kev) in latest.items():
        if verdict == "affected":
            by_asset.setdefault(asset, []).append((cve, package, version))
    for (cve, package, version, asset) in conflicted:
        if (cve, package, version) in by_asset.get(asset, []):
            by_asset_conflicted.setdefault(asset, []).append((cve, package, version))

    inputs = tuple(r.run_at for r in items)
    stale = tuple(t for t in inputs if moment - t > max_age)
    any_unverified = any(
        r.exposure is not None and r.exposure.unverified for r in items
    )

    assets: list[AssetExposure] = []
    for asset in sorted(set(by_asset) | set(by_asset_conflicted)):
        affected = tuple(sorted(by_asset.get(asset, [])))
        kev_here = tuple(sorted({c for (c, _p, _v) in affected if kev_cves.get(c) is True}))
        if stale:
            confidence = "low"       # any stale input -> low
        elif any_unverified:
            confidence = "medium"
        else:
            confidence = "high"
        assets.append(
            AssetExposure(
                asset=asset,
                affected=affected,
                conflicted=tuple(sorted(by_asset_conflicted.get(asset, []))),
                kev_affected=kev_here,
                distinct_cves=len({c for (c, _p, _v) in affected}),
                confidence=confidence,
            )
        )
    return ExposureRollup(
        generated_at=moment,
        assets=tuple(assets),
        inputs=inputs,
        stale_inputs=stale,
        max_age=max_age,
    )

