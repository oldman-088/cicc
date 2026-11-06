"""VEX/SARIF export edge cases: empty, exposure-less, malformed-adjacent inputs."""

from __future__ import annotations

from datetime import datetime, timezone

from vuln_intel.assessment import workflow_for
from vuln_intel.interop.sarif import to_sarif
from vuln_intel.interop.vex import to_vex
from vuln_intel.schema import CveId, NormalizedVulnerability, Origin
from vuln_intel.watchlist import Inventory

NOW = datetime(2026, 11, 5, 18, 0, tzinfo=timezone.utc)


def _report(records):
    return workflow_for(records=records, inventory=Inventory(), now=lambda: NOW)


class TestVexEdges:
    def test_report_without_exposure_still_exports_every_cluster_unassessed(self):
        rec = NormalizedVulnerability(cve=CveId.parse("CVE-2026-0011"),
                                      origin=Origin.FIXTURE, sources=("osv",))
        export = to_vex(_report([rec]), generated_at=NOW)
        ids = [v["id"] for v in export.document["vulnerabilities"]]
        assert ids == ["CVE-2026-0011"]
        assert "CVE-2026-0011" in export.unassessed
        assert all("analysis" not in v for v in export.document["vulnerabilities"])

    def test_fixture_metadata_flags(self):
        rec = NormalizedVulnerability(cve=CveId.parse("CVE-2026-0013"),
                                      origin=Origin.FIXTURE, sources=("osv",))
        export = to_vex(_report([rec]), generated_at=NOW)
        props = {p["name"]: p["value"] for p in export.document["metadata"]["properties"]}
        assert props["cicc:live_verified"] == "false"
        assert props["cicc:origin"] == "fixture"


class TestSarifEdges:
    def test_report_without_exposure_has_empty_results_but_keeps_unassessed(self):
        rec = NormalizedVulnerability(cve=CveId.parse("CVE-2026-0012"),
                                      origin=Origin.FIXTURE, sources=("osv",))
        doc = to_sarif(_report([rec]), generated_at=NOW)
        run = doc["runs"][0]
        assert run["results"] == []
        assert "CVE-2026-0012" in run["properties"]["cicc:unassessed"]
        assert run["properties"]["cicc:live_verified"] == "false"
