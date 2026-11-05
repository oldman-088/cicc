"""VEX export edge cases: invalid / incomplete inputs must fail or degrade loudly, never silently."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from vuln_intel.assessment import workflow_for
from vuln_intel.errors import ValidationError
from vuln_intel.interop.vex import to_vex
from vuln_intel.schema import AffectedPackage, CveId, NormalizedVulnerability, Origin
from vuln_intel.watchlist import Dependency, Inventory

NOW = datetime(2026, 11, 5, 16, 0, tzinfo=timezone.utc)


def _report(records, inv=None):
    return workflow_for(records=records, inventory=inv or Inventory(), now=lambda: NOW)


class TestIncompleteInputs:
    def test_record_without_affected_packages_is_unassessed_not_invented(self):
        rec = NormalizedVulnerability(cve=CveId.parse("CVE-2026-0007"),
                                      origin=Origin.FIXTURE, sources=("osv",))
        export = to_vex(_report([rec]), generated_at=NOW)
        # no exposure evaluation -> carried in the document WITHOUT an analysis
        # block and reported via `unassessed`, never silently dropped
        entries = {v["id"]: v for v in export.document["vulnerabilities"]}
        assert "analysis" not in entries["CVE-2026-0007"]
        assert "CVE-2026-0007" in export.unassessed

    def test_empty_report_is_valid_empty_export(self):
        export = to_vex(_report([]), generated_at=NOW)
        assert export.document["vulnerabilities"] == []
        assert export.unassessed == () and export.under_investigation == ()

    def test_unknown_inventory_version_is_not_affected(self):
        rec = NormalizedVulnerability(
            cve=CveId.parse("CVE-2026-0008"), origin=Origin.FIXTURE,
            affected=(AffectedPackage(ecosystem="npm", name="leftpad",
                                      introduced="0", fixed="1.0.0"),),
            sources=("osv",),
        )
        inv = Inventory(dependencies=(Dependency(ecosystem="npm", name="leftpad",
                                                 version="2.0.0", asset="web"),))
        export = to_vex(_report([rec], inv), generated_at=NOW)
        states = {v["id"]: v["analysis"]["state"] for v in export.document["vulnerabilities"]}
        assert states["CVE-2026-0008"] == "not_affected"

    def test_invalid_cve_id_rejected_at_construction(self):
        with pytest.raises(ValidationError):
            NormalizedVulnerability(cve="not-a-cve", origin=Origin.FIXTURE)  # type: ignore[arg-type]

    def test_metadata_always_says_fixture_not_live(self):
        rec = NormalizedVulnerability(cve=CveId.parse("CVE-2026-0009"),
                                      origin=Origin.FIXTURE, kev=True, sources=("cisa-kev",))
        export = to_vex(_report([rec]), generated_at=NOW)
        props = {p["name"]: p["value"] for p in export.document["metadata"]["properties"]}
        assert props["cicc:live_verified"] == "false"
