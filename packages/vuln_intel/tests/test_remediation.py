"""Remediation planning.

A remediation plan is the artefact an operator acts on, so the tests here focus
on the ways such a plan can be *harmfully* wrong: telling someone to upgrade to a
version that does not exist, claiming a fix when none is published, or implying
applicability was checked when it was not.
"""

from __future__ import annotations

from datetime import date

import pytest

from vuln_intel.remediation import (
    RecommendedAction,
    UpgradeCost,
    assess_upgrade_cost,
    plan_remediation,
    summarize_remediation,
)
from vuln_intel.schema import (
    AffectedPackage,
    CveId,
    CvssScore,
    NormalizedVulnerability,
    Origin,
    Severity,
)

TODAY = date(2026, 1, 1)


def record(
    *,
    cve: str = "CVE-2021-44228",
    affected: tuple[AffectedPackage, ...] = (),
    kev: bool | None = None,
    due: date | None = None,
    severity: Severity = Severity.UNKNOWN,
    vector: str | None = None,
    sources: tuple[str, ...] = ("nvd",),
    conflicts: tuple[str, ...] = (),
) -> NormalizedVulnerability:
    if vector:
        # An assessed score must carry a severity; default to the one implied by
        # a 9.8 base score when the caller did not state one.
        cvss = (
            CvssScore(
                version="3.1",
                base_score=9.8,
                severity=severity if severity is not Severity.UNKNOWN else Severity.CRITICAL,
                vector=vector,
            ),
        )
    else:
        cvss = ()
    return NormalizedVulnerability(
        cve=CveId.parse(cve),
        origin=Origin.LIVE,
        affected=affected,
        kev=kev,
        kev_due_date=due,
        severity=severity,
        cvss=cvss,
        sources=sources,
        conflict_notes=conflicts,
    )


LOG4J = AffectedPackage(
    ecosystem="maven", name="log4j-core", introduced="2.0.0", fixed="2.15.0"
)


class TestUpgradeCost:
    @pytest.mark.parametrize(
        ("installed", "target", "eco", "expected"),
        [
            ("1.2.3", "1.2.4", "npm", UpgradeCost.PATCH),
            ("1.2.3", "1.3.0", "npm", UpgradeCost.MINOR),
            ("1.2.3", "2.0.0", "npm", UpgradeCost.MAJOR),
            ("1.2.3", "1.2.3", "npm", UpgradeCost.NONE),
            ("2.14.1", "2.15.0", "maven", UpgradeCost.MINOR),
            ("2.14.1", "3.0.0", "maven", UpgradeCost.MAJOR),
            ("v1.2.3", "v1.3.0", "go", UpgradeCost.MINOR),
            ("1.0", "1.0.1", "pypi", UpgradeCost.PATCH),
            # Debian versions have epochs and revisions: shape is not semver.
            ("1:1.0-1", "2.0-1", "debian", UpgradeCost.UNKNOWN),
            ("not-a-version", "1.0.0", "npm", UpgradeCost.UNKNOWN),
            (None, "1.0.0", "npm", UpgradeCost.UNKNOWN),
        ],
    )
    def test_cost_classification(self, installed, target, eco, expected):
        assert assess_upgrade_cost(installed, target, eco) is expected


class TestPlanRemediation:
    def test_affected_with_a_fix_is_a_patch(self):
        plan = plan_remediation(
            record(affected=(LOG4J,)),
            ecosystem="maven",
            name="log4j-core",
            installed_version="2.14.1",
            today=TODAY,
        )
        assert plan.action is RecommendedAction.PATCH
        assert plan.target_version == "2.15.0"
        assert plan.upgrade_cost is UpgradeCost.MINOR
        assert plan.instruction.startswith("upgrade log4j-core to 2.15.0")

    def test_fixed_version_installed_is_no_action(self):
        plan = plan_remediation(
            record(affected=(LOG4J,)),
            ecosystem="maven",
            name="log4j-core",
            installed_version="2.15.0",
            today=TODAY,
        )
        assert plan.action is RecommendedAction.NONE
        assert plan.instruction == "no action required"

    def test_kev_escalates_to_emergency(self):
        plan = plan_remediation(
            record(affected=(LOG4J,), kev=True),
            ecosystem="maven",
            name="log4j-core",
            installed_version="2.14.1",
            today=TODAY,
        )
        assert plan.action is RecommendedAction.EMERGENCY_PATCH

    def test_kev_without_a_fix_still_demands_action(self):
        """The dangerous case: exploited in the wild, nothing to upgrade to."""
        plan = plan_remediation(
            record(kev=True, cve="CVE-2021-44228", sources=("cisa-kev",)),
            today=TODAY,
        )
        assert plan.action is RecommendedAction.EMERGENCY_PATCH
        assert plan.target_version is None
        assert plan.mitigations

    def test_no_fix_and_not_kev_is_mitigate(self):
        plan = plan_remediation(
            record(affected=(AffectedPackage(ecosystem="npm", name="x", introduced="0"),)),
            ecosystem="npm",
            name="x",
            installed_version="1.0.0",
            today=TODAY,
        )
        assert plan.action is RecommendedAction.MITIGATE
        assert "no fixed release" in plan.instruction

    def test_overdue_kev_deadline_is_flagged(self):
        plan = plan_remediation(
            record(kev=True, due=date(2025, 12, 1)), today=TODAY
        )
        assert plan.overdue is True
        assert plan.days_remaining is not None and plan.days_remaining < 0
        assert any("passed" in reason for reason in plan.reasons)

    def test_imminent_deadline_is_flagged(self):
        plan = plan_remediation(record(kev=True, due=date(2026, 1, 5)), today=TODAY)
        assert plan.overdue is False
        assert any("due in" in reason for reason in plan.reasons)

    def test_distant_deadline_is_kept_but_not_called_urgent(self):
        plan = plan_remediation(record(kev=True, due=date(2026, 6, 1)), today=TODAY)
        assert plan.due_date == date(2026, 6, 1)
        assert not any("passed" in reason for reason in plan.reasons)

    def test_missing_installed_version_is_stated_not_hidden(self):
        plan = plan_remediation(record(affected=(LOG4J,)), ecosystem="maven", name="log4j-core")
        assert any("not evaluated" in warning for warning in plan.warnings)
        assert plan.action is RecommendedAction.PATCH

    def test_unknown_applicability_does_not_read_as_safe(self):
        plan = plan_remediation(
            record(affected=(AffectedPackage(ecosystem="go", name="x/y", range_type="GIT",
                                             introduced="0", fixed="abc123"),)),
            ecosystem="go",
            name="x/y",
            installed_version="v1.0.0",
            today=TODAY,
        )
        assert plan.action is RecommendedAction.MONITOR
        assert "unverified" in " ".join(plan.reasons)

    def test_mitigations_are_derived_from_the_cvss_vector(self):
        plan = plan_remediation(
            record(vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", kev=True),
            today=TODAY,
        )
        joined = " ".join(plan.mitigations)
        assert "AV:N" in joined
        assert "no privileges" in joined

    def test_record_without_provenance_is_questioned(self):
        plan = plan_remediation(record(sources=()), today=TODAY)
        assert any("no source provenance" in warning for warning in plan.warnings)

    def test_conflicts_surface_as_warnings(self):
        plan = plan_remediation(record(conflicts=("CVSS 3.1 disagreement",)), today=TODAY)
        assert any("disagreement" in warning for warning in plan.warnings)

    def test_lowest_fixed_version_is_preferred(self):
        """Advise the smallest bump that resolves the advisory."""
        affected = (
            AffectedPackage(ecosystem="npm", name="x", introduced="0", fixed="3.0.0"),
            AffectedPackage(ecosystem="npm", name="x", introduced="0", fixed="1.0.5"),
        )
        plan = plan_remediation(
            record(affected=affected), ecosystem="npm", name="x", installed_version="0.9.0"
        )
        assert plan.target_version == "1.0.5"

    def test_plan_is_json_safe(self):
        import json

        plan = plan_remediation(record(affected=(LOG4J,), kev=True), ecosystem="maven",
                                name="log4j-core", installed_version="2.14.1", today=TODAY)
        payload = json.loads(json.dumps(plan.as_dict()))
        assert payload["action"] == "emergency_patch"
        assert payload["instruction"]


class TestSummary:
    def test_aggregates_actions_and_costs(self):
        plans = [
            plan_remediation(record(cve="CVE-2021-44228", affected=(LOG4J,), kev=True),
                             ecosystem="maven", name="log4j-core",
                             installed_version="2.14.1", today=TODAY),
            plan_remediation(record(cve="CVE-2021-45046", affected=(LOG4J,)),
                             ecosystem="maven", name="log4j-core",
                             installed_version="2.15.0", today=TODAY),
        ]
        summary = summarize_remediation(plans)
        assert summary["total"] == 2
        assert summary["actionable"] == 1
        assert summary["emergency"] == 1
        assert summary["by_action"]["none"] == 1
