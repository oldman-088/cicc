"""End-to-end: assessment report -> CycloneDX VEX export (ingestion to export loop)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from vuln_intel.assessment import workflow_for
from vuln_intel.interop.vex import to_vex
from vuln_intel.schema import (
    AffectedPackage,
    CveId,
    CvssScore,
    NormalizedVulnerability,
    Origin,
    Severity,
)
from vuln_intel.watchlist import Dependency, Inventory

NOW = datetime(2026, 11, 5, 15, 0, tzinfo=timezone.utc)
VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def _report():
    affected_rec = NormalizedVulnerability(
        cve=CveId.parse("CVE-2021-44228"), origin=Origin.FIXTURE, kev=True,
        summary="Log4Shell",
        affected=(AffectedPackage(ecosystem="maven", name="log4j-core",
                                  introduced="2.0.0", fixed="2.15.0"),),
        cvss=(CvssScore(version="3.1", base_score=10.0, severity=Severity.CRITICAL,
                        vector=VECTOR, source="nvd"),),
        sources=("nvd", "cisa-kev"),
    )
    clean_rec = NormalizedVulnerability(
        cve=CveId.parse("CVE-2026-0002"), origin=Origin.FIXTURE,
        summary="minor",
        affected=(AffectedPackage(ecosystem="npm", name="lodash",
                                  introduced="0", fixed="4.17.21"),),
        sources=("osv",),
    )
    inv = Inventory(dependencies=(
        Dependency(ecosystem="maven", name="log4j-core", version="2.14.1", asset="payments"),
        Dependency(ecosystem="npm", name="lodash", version="4.17.21", asset="web"),
    ))
    return workflow_for(records=[affected_rec, clean_rec], inventory=inv, now=lambda: NOW)


class TestAssessmentToVex:
    def test_full_loop_produces_valid_vex_with_correct_states(self):
        report = _report()
        export = to_vex(report, generated_at=NOW)
        doc = export.document
        assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.6"
        by_id = {}
        for v in doc["vulnerabilities"]:
            by_id.setdefault(v["id"], []).append(v)
        # affected + KEV -> exploitable
        assert by_id["CVE-2021-44228"][0]["analysis"]["state"] == "exploitable"
        # fixed install -> not_affected
        assert by_id["CVE-2026-0002"][0]["analysis"]["state"] == "not_affected"
        # metadata honesty flags
        props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
        assert props["cicc:live_verified"] == "false"
        assert props["cicc:origin"] == "fixture"
        # nothing under investigation, nothing unassessed
        assert export.under_investigation == ()
        assert export.unassessed == ()

    def test_vex_never_claims_live(self):
        export = to_vex(_report(), generated_at=NOW)
        assert "true" not in {p["value"] for p in export.document["metadata"]["properties"]
                              if p["name"] == "cicc:live_verified"}


class TestVexSerialDeterminism:
    def test_identical_inputs_identical_serial_across_different_clocks(self):
        """The serialNumber is content-derived, not clock-derived: two exports of
        the same logical report at different generation times share a serial."""
        later = NOW + timedelta(days=3)
        a = to_vex(_report(), generated_at=NOW).document["serialNumber"]
        b = to_vex(_report(), generated_at=later).document["serialNumber"]
        assert a == b and a.startswith("urn:uuid:")

    def test_identical_inputs_identical_full_document_at_same_clock(self):
        a = to_vex(_report(), generated_at=NOW).document
        b = to_vex(_report(), generated_at=NOW).document
        assert a == b

    def test_different_content_different_serial(self):
        other = to_vex(_report(), generated_at=NOW)
        rec2 = NormalizedVulnerability(
            cve=CveId.parse("CVE-2026-0099"), origin=Origin.FIXTURE,
            affected=(AffectedPackage(ecosystem="npm", name="x", introduced="0", fixed="1"),),
            sources=("osv",),
        )
        inv2 = Inventory(dependencies=(Dependency(ecosystem="npm", name="x", version="0.5", asset="a"),))
        rep2 = workflow_for(records=[rec2], inventory=inv2, now=lambda: NOW)
        c = to_vex(rep2, generated_at=NOW).document["serialNumber"]
        assert c != other.document["serialNumber"]
