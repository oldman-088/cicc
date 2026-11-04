"""End-to-end assessment workflow.

These tests guard the composite behaviour that no single module can: a report
must never look cleaner or more verified than its inputs, and a failure in one
source must not silently erase the findings from another.
"""

from __future__ import annotations

import json
from datetime import date, datetime, timezone

import pytest

from vuln_intel.assessment import (
    REPORT_NOTICE,
    AssessmentReport,
    AssessmentWorkflow,
    verdict_of,
    workflow_for,
)
from vuln_intel.errors import MixedOriginError
from vuln_intel.schema import (
    AffectedPackage,
    CollectionStatus,
    CveId,
    CvssScore,
    NormalizedVulnerability,
    Origin,
    Severity,
)
from vuln_intel.watchlist import Dependency, Inventory

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
TODAY = date(2026, 1, 1)
VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def log4j(*, origin: Origin = Origin.LIVE, kev: bool = True, due: date | None = date(2021, 12, 24)):
    return NormalizedVulnerability(
        cve=CveId.parse("CVE-2021-44228"),
        origin=origin,
        affected=(
            AffectedPackage(
                ecosystem="maven", name="log4j-core", introduced="2.0.0", fixed="2.15.0"
            ),
        ),
        kev=kev,
        kev_due_date=due,
        sources=("nvd", "cisa-kev") if kev else ("nvd",),
        cvss=(
            CvssScore(version="3.1", base_score=10.0, severity=Severity.CRITICAL, vector=VECTOR),
        ),
    )


def lodash(*, origin: Origin = Origin.LIVE):
    return NormalizedVulnerability(
        cve=CveId.parse("CVE-2019-10744"),
        origin=origin,
        affected=(
            AffectedPackage(ecosystem="npm", name="lodash", introduced="0", fixed="4.17.21"),
        ),
        sources=("osv",),
    )


def inventory():
    return Inventory(
        dependencies=(
            Dependency(ecosystem="maven", name="log4j-core", version="2.14.1", asset="payments"),
            Dependency(ecosystem="npm", name="lodash", version="4.17.21", asset="web"),
        )
    )


class TestHappyPath:
    def test_kev_vulnerability_becomes_an_emergency_patch_for_the_right_asset(self):
        report = AssessmentWorkflow(
            collectors={"nvd": lambda: [log4j()], "osv": lambda: [lodash()]},
            inventory=inventory(),
        ).run(today=TODAY)
        top = report.top_risks
        assert len(top) == 1
        assert top[0].cve == "CVE-2021-44228"
        assert top[0].action.value == "emergency_patch"
        assert top[0].overdue is True
        assert "log4j-core" in top[0].instruction

    def test_asset_slice_only_contains_that_asset(self):
        report = AssessmentWorkflow(
            collectors={"all": lambda: [log4j(), lodash()]}, inventory=inventory()
        ).run(today=TODAY)
        assert report.for_asset("payments")["count"] == 1
        assert report.for_asset("web")["count"] == 0  # lodash 4.17.21 is fixed

    def test_report_is_json_serialisable(self):
        report = AssessmentWorkflow(
            collectors={"all": lambda: [log4j()]}, inventory=inventory()
        ).run(today=TODAY)
        payload = json.loads(json.dumps(report.as_dict()))
        assert payload["summary"]["actionable"] == 1
        assert payload["notice"] == REPORT_NOTICE


class TestHonesty:
    def test_live_verified_is_false_by_default(self):
        report = workflow_for(records=[log4j()], inventory=inventory())
        assert report.live_verified is False
        assert report.as_dict()["live_verified"] is False

    def test_live_verified_cannot_be_claimed_for_fixture_data(self):
        with pytest.raises(MixedOriginError):
            AssessmentWorkflow(
                collectors={"x": lambda: [log4j(origin=Origin.FIXTURE)]},
                live_verified=True,
            ).run(today=TODAY)

    def test_fixture_report_says_it_is_not_production_intelligence(self):
        report = workflow_for(records=[log4j(origin=Origin.FIXTURE)], inventory=inventory())
        assert any("not production intelligence" in w for w in report.warnings)
        assert report.as_dict()["origin"] == "fixture"

    def test_mixed_origins_are_refused(self):
        with pytest.raises(MixedOriginError):
            AssessmentWorkflow(
                collectors={
                    "live": lambda: [log4j()],
                    "fixture": lambda: [lodash(origin=Origin.FIXTURE)],
                }
            ).run(today=TODAY)

    def test_unverified_pairs_make_the_report_incomplete(self):
        bad = Inventory(
            dependencies=(Dependency(ecosystem="npm", name="lodash", version="not-a-version"),)
        )
        report = AssessmentWorkflow(collectors={"osv": lambda: [lodash()]}, inventory=bad).run(
            today=TODAY
        )
        assert report.incomplete is True
        assert any("NOT safe" in w for w in report.warnings)
        assert verdict_of(report) is CollectionStatus.PARTIAL

    def test_no_inventory_is_stated_rather_than_assumed_clean(self):
        report = workflow_for(records=[log4j()])
        assert any("exposure per asset was not evaluated" in w for w in report.warnings)
        assert report.exposure is None


class TestFailureHandling:
    def test_one_failing_source_does_not_erase_the_others(self):
        def broken():
            raise RuntimeError("provider down")

        report = AssessmentWorkflow(
            collectors={"osv": lambda: [log4j()], "nvd": broken}, inventory=inventory()
        ).run(today=TODAY)
        assert len(report.top_risks) == 1
        assert report.source_errors
        assert report.source_errors[0][0] == "nvd"
        assert verdict_of(report) is CollectionStatus.PARTIAL

    def test_all_sources_failing_is_a_failed_report_not_an_empty_clean_one(self):
        def broken():
            raise RuntimeError("down")

        report = AssessmentWorkflow(collectors={"nvd": broken}).run(today=TODAY)
        assert report.clusters == ()
        assert verdict_of(report) is CollectionStatus.FAILED
        assert any("no records" in w for w in report.warnings)

    def test_empty_source_is_reported_as_empty_not_as_failure(self):
        report = AssessmentWorkflow(
            collectors={"nvd": list, "osv": lambda: [log4j()]}, inventory=inventory()
        ).run(today=TODAY)
        assert any("returned no records" in w for w in report.warnings)
        assert report.source_errors == ()

    def test_advisory_without_affected_data_is_called_out(self):
        bare = NormalizedVulnerability(
            cve=CveId.parse("CVE-2024-5000"), origin=Origin.LIVE, sources=("nvd",)
        )
        report = AssessmentWorkflow(
            collectors={"nvd": lambda: [bare]}, inventory=inventory()
        ).run(today=TODAY)
        assert any("no affected data" in w for w in report.warnings)


class TestReportShape:
    def test_top_risks_follow_ranking_order(self):
        report = AssessmentWorkflow(
            collectors={"all": lambda: [lodash(), log4j()]}, inventory=inventory()
        ).run(today=TODAY)
        order = [str(r.cve) for r in report.ranking]
        risks = [r.cve for r in report.top_risks]
        assert risks == [cve for cve in order if cve in risks]

    def test_summary_counts(self):
        report = AssessmentWorkflow(
            collectors={"all": lambda: [log4j(), lodash()]}, inventory=inventory()
        ).run(today=TODAY)
        summary = report.as_dict()["summary"]
        assert summary["clusters"] == 2
        assert summary["overdue"] == 1

    def test_verdict_of_clean_report(self):
        report = workflow_for(records=[log4j()], inventory=inventory())
        assert verdict_of(report) is CollectionStatus.OK

    def test_report_is_immutable(self):
        report = workflow_for(records=[log4j()], inventory=inventory())
        assert isinstance(report, AssessmentReport)
        with pytest.raises(Exception):
            report.run_at = NOW  # type: ignore[misc]
