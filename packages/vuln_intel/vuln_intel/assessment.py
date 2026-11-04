"""End-to-end assessment: from collected advisories to a decision-ready report.

The individual modules answer narrow questions.  This one runs the whole chain
and produces the artefact a security team actually consumes:

    collect -> correlate -> expose -> enrich -> rank -> remediate -> report

Design commitments, each of which exists because the naive version is harmful:

1. **One report, one origin.**  The whole run is refused if input mixes live and
   fixture data; a partially synthetic report is the exact failure the project
   forbids.
2. **Evidence before opinion.**  Sample citations are gathered from the records
   themselves, so the report can be audited against its sources.
3. **Unknown is a first-class outcome.**  Platforms that could not be evaluated,
   advisories with no affected data and sources that failed are all enumerated.
   A report never looks cleaner than its inputs.
4. **The report states what it is.**  ``live_verified`` is false unless a real,
   recorded fetch produced the data, and the notice travels with the payload.
5. **Nothing is dropped for being inconvenient.**  A record that cannot be
   correlated or scored still appears, with the reason.

The workflow is pure: it performs no I/O and calls no network.  Collection is
injected, which keeps it testable and keeps the "no accidental live request"
guarantee structural rather than a matter of discipline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Callable, Iterable, Mapping, Sequence

from .correlation import CorrelationCluster, correlate
from .errors import MixedOriginError
from .priorities import PriorityContext, PriorityResult, rank_vulnerabilities
from .remediation import Remediation, plan_remediation, summarize_remediation
from .schema import (
    CollectionStatus,
    NormalizedVulnerability,
    Origin,
    utcnow,
)
from .threat_intel import (
    CveTechniqueMap,
    TechniqueCorrelation,
    correlate_techniques,
    technique_rollup,
)
from .watchlist import ExposureReport, Inventory, analyse_exposure

__all__ = [
    "REPORT_NOTICE",
    "AssessmentReport",
    "AssessmentWorkflow",
    "verdict_of",
    "workflow_for",
]

#: Travelling with every report so a rendered artefact cannot be mistaken for a
#: verified production assessment.
REPORT_NOTICE = (
    "Assessment derived from the sources listed in this report. Ranking and "
    "remediation are computed, not approved policy; exploitation status is "
    "unknown wherever KEV was not consulted."
)


@dataclass(frozen=True)
class AssessmentReport:
    """A complete, auditable assessment."""

    run_at: datetime
    origin: Origin
    clusters: tuple[CorrelationCluster, ...] = ()
    exposure: ExposureReport | None = None
    ranking: tuple[PriorityResult, ...] = ()
    remediations: tuple[Remediation, ...] = ()
    source_errors: tuple[tuple[str, str], ...] = ()
    warnings: tuple[str, ...] = ()
    #: ``True`` only when the caller declares a recorded live fetch.
    live_verified: bool = False
    #: CVE -> ATT&CK correlation, when a threat-intelligence mapping was supplied.
    #: Empty means "not requested", never "nothing correlates" - the individual
    #: entries carry a ``consulted`` flag for that distinction.
    threat_intel: tuple[TechniqueCorrelation, ...] = ()

    # -- derived views ----------------------------------------------------
    @property
    def affected(self) -> tuple[Remediation, ...]:
        return tuple(r for r in self.remediations if r.action.is_actionable)

    @property
    def top_risks(self) -> tuple[Remediation, ...]:
        """Actionable items ordered by the ranking that produced them."""
        # Keyed by the string form: PriorityResult.cve is a CveId while
        # Remediation.cve is the canonical string.
        order = {str(r.cve): index for index, r in enumerate(self.ranking)}
        actionable = list(self.affected)
        actionable.sort(
            key=lambda r: (order.get(r.cve, len(order)), 0 if r.overdue else 1, r.cve)
        )
        return tuple(actionable)

    @property
    def incomplete(self) -> bool:
        return bool(self.source_errors) or bool(self.exposure and self.exposure.unverified)

    def as_dict(self) -> dict[str, object]:
        return {
            "run_at": self.run_at.isoformat(),
            "origin": self.origin.value,
            "live_verified": self.live_verified,
            "notice": REPORT_NOTICE,
            "summary": {
                "clusters": len(self.clusters),
                "ranked": len(self.ranking),
                "actionable": len(self.affected),
                "overdue": sum(1 for r in self.remediations if r.overdue),
                "assets_at_risk": list(self.exposure.assets_at_risk) if self.exposure else [],
                "incomplete": self.incomplete,
                "mitre_mapped": sum(1 for c in self.threat_intel if c.mapped),
                "mitre_consulted": bool(self.threat_intel and self.threat_intel[0].consulted),
            },
            "threat_intel": technique_rollup(self.threat_intel).as_dict()
            if self.threat_intel
            else {"consulted": False, "total_cves": 0, "techniques": []},
            "remediation_summary": summarize_remediation(list(self.remediations)),
            "exposure": self.exposure.as_dict() if self.exposure else None,
            "top_risks": [r.as_dict() for r in self.top_risks],
            "ranking": [r.as_dict() for r in self.ranking],
            "source_errors": [{"source": s, "error": e} for s, e in self.source_errors],
            "warnings": list(self.warnings),
        }

    def for_asset(self, asset: str) -> dict[str, object]:
        """Slice of the report belonging to one asset, for a team-level ticket."""
        if self.exposure is None:
            return {"asset": asset, "findings": []}
        findings = [m.as_dict() for m in self.exposure.for_asset(asset)]
        return {"asset": asset, "findings": findings, "count": len(findings)}


Collector = Callable[[], Sequence[NormalizedVulnerability]]


@dataclass
class AssessmentWorkflow:
    """Composes collection, correlation, exposure, ranking and remediation."""

    #: Advisory records, or collectors that produce them.
    collectors: Mapping[str, Collector] = field(default_factory=dict)
    #: Optional: which of our packages exist.  Without it, exposure is unknown.
    inventory: Inventory | None = None
    context: PriorityContext | Mapping[str, PriorityContext] | None = None
    now: Callable[[], datetime] = utcnow
    #: Set by the caller only after a real fetch has been recorded.
    live_verified: bool = False
    #: Optional threat-intelligence mapping (CVE -> MITRE ATT&CK).  Supplying it
    #: turns the report into something the threat-intelligence side can consume;
    #: leaving it out produces ``consulted=False`` rather than an empty claim.
    attack_mapping: CveTechniqueMap | None = None

    def run(self, *, today: date | None = None) -> AssessmentReport:
        run_at = self.now()
        warnings: list[str] = []
        errors: list[tuple[str, str]] = []
        collected: list[NormalizedVulnerability] = []

        for name, collector in self.collectors.items():
            try:
                produced = list(collector())
            except Exception as exc:  # a failing source must not sink the report
                errors.append((name, f"{type(exc).__name__}: {exc}"))
                continue
            if not produced:
                # An empty answer is a fact worth reporting, not a failure.
                warnings.append(f"{name} returned no records")
            collected.extend(produced)

        if not collected:
            return AssessmentReport(
                run_at=run_at,
                origin=Origin.LIVE,
                source_errors=tuple(errors),
                warnings=tuple([*warnings, "no records were collected"]),
                live_verified=self.live_verified,
                threat_intel=correlate_techniques((), self.attack_mapping),
            )

        origins = {record.origin for record in collected}
        if len(origins) > 1:
            raise MixedOriginError(
                "refusing to assess mixed origins: "
                + ", ".join(sorted(o.value for o in origins))
            )
        origin = next(iter(origins))
        if origin is not Origin.LIVE and self.live_verified:
            raise MixedOriginError(
                "live_verified cannot be set for non-live data"
            )

        clusters = correlate(collected)
        distinct = [cluster.merged for cluster in clusters]

        threat_intel = correlate_techniques(distinct, self.attack_mapping)
        if self.attack_mapping is not None:
            mapped = sum(1 for c in threat_intel if c.mapped)
            if mapped == 0:
                warnings.append(
                    "ATT&CK mapping supplied but no record matched it: the mapping "
                    "may be stale, or these CVEs may genuinely be unmapped"
                )
            else:
                warnings.append(
                    f"{mapped}/{len(threat_intel)} record(s) correlate to MITRE ATT&CK "
                    f"(mapping {self.attack_mapping.source} v{self.attack_mapping.version})"
                )

        exposure: ExposureReport | None = None
        if self.inventory is not None:
            exposure = analyse_exposure(self.inventory, distinct)
            if exposure.unexplorable:
                warnings.append(
                    f"{len(exposure.unexplorable)} advisory/advisories carry no affected "
                    "data and could not be matched to the inventory"
                )
            if exposure.unverified:
                warnings.append(
                    f"{len(exposure.unverified)} package/advisory pair(s) could not be "
                    "evaluated (unorderable version or GIT range) and are NOT safe"
                )
        else:
            warnings.append(
                "no dependency inventory supplied: exposure per asset was not evaluated"
            )

        ranking = rank_vulnerabilities(distinct, context=self.context, now=run_at)
        ranked_order = {str(r.cve): r.band for r in ranking}

        remediations = self._plan(
            distinct, exposure, ranked_order, today or run_at.date()
        )
        if origin is not Origin.LIVE:
            warnings.append(
                f"origin is '{origin.value}': this report is not production intelligence"
            )

        return AssessmentReport(
            run_at=run_at,
            origin=origin,
            clusters=clusters,
            exposure=exposure,
            ranking=tuple(ranking),
            remediations=tuple(remediations),
            source_errors=tuple(errors),
            warnings=tuple(dict.fromkeys(warnings)),
            live_verified=self.live_verified,
            threat_intel=threat_intel,
        )

    def _plan(
        self,
        records: Iterable[NormalizedVulnerability],
        exposure: ExposureReport | None,
        bands: Mapping[str, str],
        today: date,
    ) -> list[Remediation]:
        """Plan per (advisory, installed package) when an inventory exists."""
        plans: list[Remediation] = []
        if exposure is None:
            for lone in records:
                plans.append(
                    plan_remediation(
                        lone,
                        today=today,
                        priority_band=bands.get(str(lone.cve)),
                    )
                )
            return plans

        affected_by_cve: dict[str, set[tuple[str, str, str]]] = {}
        for match in exposure.affected:
            affected_by_cve.setdefault(match.cve, set()).add(
                (
                    match.dependency.canonical_ecosystem,
                    match.dependency.name,
                    match.dependency.version,
                )
            )
        by_cve: dict[str, NormalizedVulnerability] = {
            str(record.cve): record for record in records
        }
        for cve, installs in sorted(affected_by_cve.items()):
            advisory = by_cve.get(cve)
            if advisory is None:  # cluster primary CVE differs from the matched one
                continue
            for ecosystem, name, version in sorted(installs):
                plans.append(
                    plan_remediation(
                        advisory,
                        ecosystem=ecosystem,
                        name=name,
                        installed_version=version,
                        today=today,
                        priority_band=bands.get(cve),
                    )
                )
        return plans


def workflow_for(
    *,
    records: Sequence[NormalizedVulnerability],
    inventory: Inventory | None = None,
    context: PriorityContext | Mapping[str, PriorityContext] | None = None,
    now: Callable[[], datetime] = utcnow,
    live_verified: bool = False,
    attack_mapping: CveTechniqueMap | None = None,
) -> AssessmentReport:
    """Convenience wrapper for an in-memory record set."""
    return AssessmentWorkflow(
        collectors={"records": lambda: list(records)},
        inventory=inventory,
        context=context,
        now=now,
        live_verified=live_verified,
        attack_mapping=attack_mapping,
    ).run()


def verdict_of(report: AssessmentReport) -> CollectionStatus:
    """Project the report onto a collection status for upstream consumers."""
    if report.source_errors and not report.clusters:
        return CollectionStatus.FAILED
    if report.source_errors or report.incomplete:
        return CollectionStatus.PARTIAL
    return CollectionStatus.OK
