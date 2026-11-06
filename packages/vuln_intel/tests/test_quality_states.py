"""Inventory quality: keeping "checked and clean" apart from "never checked".

The failure this defends against is the most common one in vulnerability reporting: a
component that could not be matched, whose advisory had no ranges, or that was never
looked at, all rendered as "no known vulnerabilities". That converts ignorance into a
clean bill of health.

These tests build **real** `PackageMatch` / `ExposureReport` / `Dependency` objects from
the package rather than stand-ins. An earlier version of the adapter read
`match.advisory.cve`, which does not exist — the real field is `match.cve` — and a test
using a fake object with the shape I *assumed* would have passed while every real finding
was labelled "unspecified-advisory". Using the real dataclasses is the point.
"""

from __future__ import annotations

import pytest

from vuln_intel.affected import Verdict
from vuln_intel.quality_states import (
    CONCLUDED,
    UNKNOWN,
    ComponentQuality,
    QualityState,
    assess_inventory_quality,
)
from vuln_intel.watchlist import Dependency, ExposureReport, PackageMatch


class _Assessment:
    """Minimal stand-in for `AffectedAssessment`; only the verdict is read elsewhere.

    The verdict is the **real** `Verdict` enum, not the string "affected". Using a
    string here was this test file's own bug: the adapter classifies by enum value, so a
    string stand-in made every cleared match look inconclusive and two tests failed for
    the fixture's reason rather than the code's. Stub the shape, not the type.
    """

    def __init__(self, verdict: Verdict = Verdict.AFFECTED) -> None:
        self.verdict = verdict


def _match(cve: str, dependency: Dependency, verdict: Verdict = Verdict.AFFECTED) -> PackageMatch:
    return PackageMatch(
        cve=cve,
        dependency=dependency,
        assessment=_Assessment(verdict),  # type: ignore[arg-type]
        advisory_fixed=None,
        sources=("nvd",),
    )


def _dep(name: str = "lodash", version: str = "4.17.20", ecosystem: str = "npm") -> Dependency:
    return Dependency(
        ecosystem=ecosystem, name=name, version=version,
        purl=f"pkg:{ecosystem}/{name}@{version}",
    )


class TestNoAdvisoryDataMeansUncheckedNotClean:
    def test_a_missing_report_leaves_everything_unchecked(self):
        """The single most important behaviour: absence of data is not absence of risk."""
        report = assess_inventory_quality(
            dependencies=[_dep("a"), _dep("b")], exposure=None
        )
        assert report.total == 2
        assert report.concluded == 0
        assert all(c.state is QualityState.UNCHECKED for c in report.components)
        assert all(c.reason for c in report.components)
        assert report.is_conclusive is False
        assert report.coverage == 0.0

    def test_an_empty_inventory_has_no_coverage_rather_than_zero(self):
        """`None`, not 0% and not 100%. Both numbers would be a claim about nothing."""
        report = assess_inventory_quality(dependencies=[], exposure=None)
        assert report.total == 0
        assert report.coverage is None
        assert "not known" in report.summary_line()


class TestTheFiveStatesAreDistinguished:
    def _report(self) -> object:
        affected_dep = _dep("log4j-core", "2.14.1", "maven")
        cleared_dep = _dep("requests", "2.31.0", "pypi")
        unverified_dep = _dep("left-pad", "1.0.0")
        clean_dep = _dep("express", "4.18.2")
        return assess_inventory_quality(
            dependencies=[affected_dep, cleared_dep, unverified_dep, clean_dep],
            exposure=ExposureReport(
                matches=(_match("CVE-2021-44228", affected_dep),),
                not_affected=(
                    _match("CVE-2023-32681", cleared_dep, Verdict.NOT_AFFECTED),
                ),
                unverified=(
                    _match("CVE-2020-0001", unverified_dep, Verdict.UNKNOWN),
                ),
                unexplorable=("CVE-2019-9999",),
                advisories_considered=4,
            ),
            skipped=(
                {"name": "mystery", "reason": "no purl and no ecosystem"},
            ),
        )

    def test_each_component_gets_the_right_state(self):
        report = self._report()
        states = {c.component: c.state for c in report.components}
        assert states["maven:log4j-core"] is QualityState.AFFECTED
        assert states["pypi:requests"] is QualityState.NOT_AFFECTED
        assert states["npm:left-pad"] is QualityState.UNVERIFIABLE
        assert states["npm:express"] is QualityState.CLEAN
        assert states["unmatched:mystery"] is QualityState.UNCHECKED

    def test_real_advisory_identifiers_are_recorded(self):
        """Catches the `.advisory` vs `.cve` mistake: a wrong field yields 'unspecified'."""
        report = self._report()
        affected = report.affected[0]
        assert affected.advisories == ("CVE-2021-44228",)
        assert "unspecified" not in "".join(affected.advisories)

    def test_unknowns_are_counted_separately_from_conclusions(self):
        report = self._report()
        assert report.total == 5
        assert report.concluded == 3
        assert report.unknown == 2
        assert report.is_conclusive is False

    def test_unexplorable_advisories_are_carried_not_dropped(self):
        assert self._report().unexplorable == ("CVE-2019-9999",)

    def test_the_summary_never_calls_unknown_a_clean_result(self):
        line = self._report().summary_line()
        assert "unknown" in line
        assert "not a clean result" in line


class TestAffectedWinsOverCleared:
    def test_a_component_affected_by_one_advisory_and_cleared_by_another_is_afflicted(self):
        """Never optimistic: one live advisory is enough.

        A component can genuinely appear in both sets — cleared by a CVE that does not
        touch our version, affected by one that does. Reporting it as NOT_AFFECTED
        because a *different* advisory cleared it would be a wrong answer in the
        dangerous direction.
        """
        dependency = _dep("lib", "1.0")
        report = assess_inventory_quality(
            dependencies=[dependency],
            exposure=ExposureReport(
                matches=(_match("CVE-HIT", dependency),),
                not_affected=(_match("CVE-MISS", dependency),),
            ),
        )
        assert len(report.components) == 1
        assert report.components[0].state is QualityState.AFFECTED
        assert report.components[0].advisories == ("CVE-HIT",)


class TestItNeverInfersFromPresence:
    def test_a_component_with_no_advisories_is_clean_not_affected(self):
        report = assess_inventory_quality(
            dependencies=[_dep("safe-lib")],
            exposure=ExposureReport(),
        )
        assert report.affected == ()
        assert report.components[0].state is QualityState.CLEAN

    def test_presence_alone_never_produces_an_advisory(self):
        """There is no code path from a dependency to an advisory identifier."""
        report = assess_inventory_quality(
            dependencies=[_dep("a"), _dep("b")], exposure=ExposureReport()
        )
        assert all(c.advisories == () for c in report.components)


class TestTheStateGuards:
    def test_an_unknown_without_a_reason_is_refused(self):
        with pytest.raises(ValueError, match="states no reason"):
            ComponentQuality(component="x", state=QualityState.UNCHECKED)

    def test_an_unchecked_component_cannot_claim_evaluation(self):
        with pytest.raises(ValueError, match="cannot claim it was evaluated"):
            ComponentQuality(
                component="x", state=QualityState.UNCHECKED, reason="why", evaluated=True
            )

    def test_a_clean_component_cannot_cite_advisories(self):
        with pytest.raises(ValueError, match="cannot cite advisories"):
            ComponentQuality(
                component="x", state=QualityState.CLEAN, advisories=("CVE-1",)
            )

    def test_the_state_sets_are_disjoint_and_cover_everything(self):
        assert frozenset() == CONCLUDED & UNKNOWN
        assert frozenset(QualityState) == CONCLUDED | UNKNOWN


class TestDeterminismAndShape:
    def test_components_are_sorted_so_output_is_stable(self):
        report = assess_inventory_quality(
            dependencies=[_dep("z"), _dep("a"), _dep("m")], exposure=ExposureReport()
        )
        names = [c.component for c in report.components]
        assert names == sorted(names)

    def test_serialises_to_json_with_coverage_and_states(self):
        import json

        report = assess_inventory_quality(
            dependencies=[_dep("a")], exposure=ExposureReport()
        )
        body = json.loads(json.dumps(report.as_dict()))
        assert body["total"] == 1
        assert body["coverage"] == 1.0
        assert body["by_state"] == {"clean": 1}
        assert body["components"][0]["certain"] is True

    def test_duplicate_skipped_entries_are_collapsed(self):
        report = assess_inventory_quality(
            dependencies=[],
            exposure=ExposureReport(),
            skipped=(
                {"name": "x", "reason": "no purl"},
                {"name": "x", "reason": "no purl"},
            ),
        )
        assert report.total == 1
