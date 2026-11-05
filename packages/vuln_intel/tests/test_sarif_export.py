"""Outbound SARIF export from an assessment report (e2e, fixture data)."""

from __future__ import annotations

from datetime import datetime, timezone

from vuln_intel.assessment import workflow_for
from vuln_intel.interop.sarif import to_sarif
from vuln_intel.schema import AffectedPackage, CveId, NormalizedVulnerability, Origin
from vuln_intel.watchlist import Dependency, Inventory

NOW = datetime(2026, 11, 5, 17, 0, tzinfo=timezone.utc)


def _report():
    affected = NormalizedVulnerability(
        cve=CveId.parse("CVE-2021-44228"), origin=Origin.FIXTURE, kev=True,
        affected=(AffectedPackage(ecosystem="maven", name="log4j-core",
                                  introduced="2.0.0", fixed="2.15.0"),),
        sources=("nvd", "cisa-kev"),
    )
    clean = NormalizedVulnerability(
        cve=CveId.parse("CVE-2026-0002"), origin=Origin.FIXTURE,
        affected=(AffectedPackage(ecosystem="npm", name="lodash",
                                  introduced="0", fixed="4.17.21"),),
        sources=("osv",),
    )
    unassessed = NormalizedVulnerability(cve=CveId.parse("CVE-2026-0003"),
                                         origin=Origin.FIXTURE, sources=("osv",))
    inv = Inventory(dependencies=(
        Dependency(ecosystem="maven", name="log4j-core", version="2.14.1", asset="payments"),
        Dependency(ecosystem="npm", name="lodash", version="4.17.21", asset="web"),
    ))
    return workflow_for(records=[affected, clean, unassessed], inventory=inv, now=lambda: NOW)


class TestSarifExport:
    def test_levels_per_exposure_state(self):
        doc = to_sarif(_report(), generated_at=NOW)
        assert doc["version"] == "2.1.0"
        run = doc["runs"][0]
        by_rule = {r["ruleId"]: r["level"] for r in run["results"]}
        assert by_rule["CVE-2021-44228"] == "error"      # affected
        assert by_rule["CVE-2026-0002"] == "none"         # not_affected
        props = run["properties"]
        assert props["cicc:origin"] == "fixture"
        assert props["cicc:live_verified"] == "false"
        assert "CVE-2026-0003" in props["cicc:unassessed"]  # never silently dropped

    def test_empty_report_valid(self):
        doc = to_sarif(workflow_for(records=[], inventory=Inventory(), now=lambda: NOW),
                       generated_at=NOW)
        assert doc["runs"][0]["results"] == []


SARIF_LEVELS = {"none", "note", "warning", "error"}


class TestSarifSpecShape:
    def test_structural_conformance_to_sarif_2_1_0(self):
        doc = to_sarif(_report(), generated_at=NOW)
        assert doc["version"] == "2.1.0"
        assert doc["$schema"].endswith("sarif-2.1.0.json")
        assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1
        run = doc["runs"][0]
        assert run["tool"]["driver"]["name"]
        for result in run["results"]:
            assert set(("ruleId", "level", "message")) <= set(result)
            assert result["level"] in SARIF_LEVELS
            assert isinstance(result["message"]["text"], str) and result["message"]["text"]
        props = run["properties"]
        for key in ("cicc:origin", "cicc:live_verified", "cicc:unassessed", "cicc:generated_at"):
            assert key in props

    def test_all_four_exposure_cases_present_and_distinct(self):
        doc = to_sarif(_report(), generated_at=NOW)
        levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
        assert levels == {"CVE-2021-44228": "error", "CVE-2026-0002": "none"}
        assert "CVE-2026-0003" in doc["runs"][0]["properties"]["cicc:unassessed"]

    def test_live_verified_never_true_for_fixture(self):
        doc = to_sarif(_report(), generated_at=NOW)
        assert doc["runs"][0]["properties"]["cicc:live_verified"] == "false"
        assert doc["runs"][0]["properties"]["cicc:origin"] == "fixture"
