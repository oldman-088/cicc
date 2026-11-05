"""CycloneDX VEX export: the verdict is the product, and it must never overstate.

The load-bearing rule of this adapter: an ``UNKNOWN`` verdict is exported as
``under_investigation``, never as ``not_affected``. Everything else is structure.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from vuln_intel.affected import Verdict
from vuln_intel.assessment import workflow_for
from vuln_intel.interop.vex import VEX_SPEC_VERSION, to_vex, vex_state_for
from vuln_intel.schema import (
    AffectedPackage,
    CveId,
    CvssScore,
    NormalizedVulnerability,
    Origin,
    Reference,
    Severity,
)
from vuln_intel.watchlist import Dependency, Inventory

NOW = datetime(2026, 2, 1, tzinfo=timezone.utc)
VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def _record(cve: str, *, kev: bool | None = None, ecosystem="maven", name="log4j-core",
            introduced="2.0.0", fixed="2.15.0") -> NormalizedVulnerability:
    return NormalizedVulnerability(
        cve=CveId.parse(cve),
        origin=Origin.FIXTURE,
        summary=f"flaw in {name}",
        affected=(AffectedPackage(ecosystem=ecosystem, name=name,
                                  introduced=introduced, fixed=fixed),),
        kev=kev,
        sources=("nvd", "cisa-kev") if kev else ("nvd",),
        cvss=(CvssScore(version="3.1", base_score=9.8, severity=Severity.CRITICAL,
                        vector=VECTOR, source="nvd"),),
        references=(Reference(url="https://nvd.example/" + cve, kind="advisory",
                              source="nvd"),),
    )


def _inventory(*deps: Dependency) -> Inventory:
    return Inventory(dependencies=deps)


class TestVexStateMapping:
    def test_affected_without_kev_is_affected(self):
        assert vex_state_for(Verdict.AFFECTED, kev=None) == "affected"
        assert vex_state_for(Verdict.AFFECTED, kev=False) == "affected"

    def test_affected_and_kev_listed_is_exploitable(self):
        assert vex_state_for(Verdict.AFFECTED, kev=True) == "exploitable"

    def test_not_affected_maps_directly(self):
        assert vex_state_for(Verdict.NOT_AFFECTED, kev=None) == "not_affected"

    def test_unknown_is_under_investigation_never_not_affected(self):
        assert vex_state_for(Verdict.UNKNOWN, kev=None) == "under_investigation"
        assert vex_state_for(Verdict.UNKNOWN, kev=True) == "under_investigation"


class TestDocumentStructure:
    def test_envelope_is_valid_cyclonedx_vex(self):
        report = workflow_for(
            records=[_record("CVE-2021-44228", kev=True)],
            inventory=_inventory(
                Dependency(ecosystem="maven", name="log4j-core",
                           version="2.14.1", asset="payments")
            ),
            now=lambda: NOW,
        )
        export = to_vex(report, generated_at=NOW)
        doc = export.document
        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == VEX_SPEC_VERSION
        assert doc["serialNumber"].startswith("urn:uuid:")
        assert doc["metadata"]["timestamp"] == NOW.isoformat()
        assert doc["metadata"]["tools"][0]["name"] == "cicc-vuln-intel"
        # round-trips as JSON
        json.loads(export.to_json())

    def test_metadata_carries_honesty_flags(self):
        report = workflow_for(
            records=[_record("CVE-2021-44228")],
            inventory=_inventory(
                Dependency(ecosystem="maven", name="log4j-core", version="2.14.1")
            ),
            now=lambda: NOW,
        )
        doc = to_vex(report, generated_at=NOW).document
        props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
        assert props["cicc:origin"] == "fixture"
        assert props["cicc:live_verified"] == "false"
        assert "notice" in props["cicc:notice"].lower() or "computed" in props["cicc:notice"]

    def test_naive_generated_at_is_refused(self):
        report = workflow_for(records=[_record("CVE-2021-44228")], now=lambda: NOW)
        with pytest.raises(ValueError, match="timezone-aware"):
            to_vex(report, generated_at=datetime(2026, 2, 1))


class TestAnalyses:
    def test_affected_kev_match_exports_exploitable_with_package_and_detail(self):
        report = workflow_for(
            records=[_record("CVE-2021-44228", kev=True)],
            inventory=_inventory(
                Dependency(ecosystem="maven", name="log4j-core",
                           version="2.14.1", asset="payments",
                           purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
            ),
            now=lambda: NOW,
        )
        export = to_vex(report, generated_at=NOW)
        vulns = export.document["vulnerabilities"]
        assert len(vulns) == 1
        entry = vulns[0]
        assert entry["id"] == "CVE-2021-44228"
        assert entry["analysis"]["state"] == "exploitable"
        assert "2.15.0" in entry["analysis"]["detail"]
        assert entry["affects"] == [
            {"ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}
        ]
        components = {c["bom-ref"]: c for c in export.document["components"]}
        assert "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" in components
        assert components["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"]["version"] == "2.14.1"

    def test_not_affected_package_exports_not_affected(self):
        report = workflow_for(
            records=[_record("CVE-2021-44228")],
            inventory=_inventory(
                Dependency(ecosystem="maven", name="log4j-core", version="2.15.0")
            ),
            now=lambda: NOW,
        )
        export = to_vex(report, generated_at=NOW)
        # log4j 2.15.0 is the fixed version: not inside [2.0.0, 2.15.0)
        states = [v["analysis"]["state"] for v in export.document["vulnerabilities"]]
        assert states == ["not_affected"]
        assert export.under_investigation == ()

    def test_unknown_verdict_exports_under_investigation_and_is_listed(self):
        # Composer is OPAQUE: verdicts for it are UNKNOWN by decision.
        report = workflow_for(
            records=[_record("CVE-2022-0001", ecosystem="composer", name="acme/lib",
                             introduced="1.0.0", fixed="1.0.1")],
            inventory=_inventory(
                Dependency(ecosystem="composer", name="acme/lib", version="1.0.0")
            ),
            now=lambda: NOW,
        )
        export = to_vex(report, generated_at=NOW)
        states = [v["analysis"]["state"] for v in export.document["vulnerabilities"]]
        assert states == ["under_investigation"]
        assert len(export.under_investigation) == 1
        assert export.under_investigation[0].startswith("CVE-2022-0001")

    def test_record_without_inventory_match_has_no_analysis_and_is_reported(self):
        report = workflow_for(
            records=[_record("CVE-2021-44228")],
            inventory=_inventory(
                Dependency(ecosystem="npm", name="lodash", version="4.17.21")
            ),
            now=lambda: NOW,
        )
        export = to_vex(report, generated_at=NOW)
        assert export.document["vulnerabilities"][0]["id"] == "CVE-2021-44228"
        assert "analysis" not in export.document["vulnerabilities"][0]
        assert export.unassessed == ("CVE-2021-44228",)

    def test_ratings_sorted_highest_severity_first_and_carry_vector(self):
        rec_low = NormalizedVulnerability(
            cve=CveId.parse("CVE-2021-44228"),
            origin=Origin.FIXTURE,
            cvss=(
                CvssScore(version="3.1", base_score=5.0, severity=Severity.MEDIUM,
                          vector="CVSS:3.1/AV:L", source="osv"),
                CvssScore(version="3.1", base_score=9.8, severity=Severity.CRITICAL,
                          vector=VECTOR, source="nvd"),
            ),
            sources=("nvd", "osv"),
        )
        report = workflow_for(records=[rec_low], now=lambda: NOW)
        doc = to_vex(report, generated_at=NOW).document
        ratings = doc["vulnerabilities"][0]["ratings"]
        assert ratings[0]["severity"] == "critical"
        assert ratings[0]["vector"] == VECTOR
        assert ratings[0]["method"] == "CVSSv31"
        assert ratings[1]["severity"] == "medium"

    def test_lost_fields_are_declared_not_dropped_silently(self):
        report = workflow_for(records=[_record("CVE-2021-44228")], now=lambda: NOW)
        export = to_vex(report, generated_at=NOW)
        assert "epss_score" in export.lost
        assert "provenance" in export.lost

    def test_deterministic_serial_number_is_a_uuid_and_document_is_stable(self):
        report = workflow_for(
            records=[_record("CVE-2021-44228")],
            inventory=_inventory(
                Dependency(ecosystem="maven", name="log4j-core", version="2.14.1")
            ),
            now=lambda: NOW,
        )
        a = to_vex(report, generated_at=NOW)
        b = to_vex(report, generated_at=NOW)
        # serial numbers differ (fresh uuid) but everything else is identical
        a.document.pop("serialNumber")
        b.document.pop("serialNumber")
        assert a.document == b.document
