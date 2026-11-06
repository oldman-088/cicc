"""CTIS adapter round-trip: record -> finding/report -> fields preserved."""

from __future__ import annotations

from datetime import datetime, timezone

from vuln_intel.interop.ctis import to_ctis_finding, to_ctis_report
from vuln_intel.schema import (
    AffectedPackage,
    CveId,
    CvssScore,
    NormalizedVulnerability,
    Origin,
    RecordStatus,
    Severity,
)

NOW = datetime(2026, 11, 5, tzinfo=timezone.utc)
VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def _record(**kw) -> NormalizedVulnerability:
    base = dict(
        cve=CveId.parse("CVE-2021-44228"), origin=Origin.FIXTURE, kev=True,
        summary="Log4Shell", record_status=RecordStatus.PUBLISHED,
        affected=(AffectedPackage(ecosystem="maven", name="log4j-core",
                                  introduced="2.0.0", fixed="2.15.0"),),
        cvss=(CvssScore(version="3.1", base_score=10.0, severity=Severity.CRITICAL,
                        vector=VECTOR, source="nvd"),),
        sources=("nvd", "cisa-kev"),
    )
    base.update(kw)
    return NormalizedVulnerability(**base)


class TestCtisRoundTrip:
    def test_finding_preserves_identity_severity_status(self):
        conv = to_ctis_finding(_record())
        f = conv.finding
        assert f["type"] == "vulnerability"
        assert f["title"].startswith("CVE-2021-44228")
        assert f["severity"] == "critical"
        assert f["status"] == "open"  # CTIS maps published/none -> open (documented)
        assert f["asset_ref"] == "advisory:CVE-2021-44228"  # honest synthetic ref
        assert conv.finding["vulnerability"]["ids"][0] == {"type": "cve", "id": "CVE-2021-44228"}

    def test_finding_keeps_cvss_and_affected(self):
        f = to_ctis_finding(_record()).finding
        assert f["scores"][0]["value"] == 10.0 and f["scores"][0]["system"] == "cvss"
        assert f["vulnerability"]["package_name"] == "log4j-core"
        assert f["vulnerability"]["fixed_versions"] == ["2.15.0"]

    def test_rejected_record_maps_to_rejected_status_not_dropped(self):
        f = to_ctis_finding(_record(record_status=RecordStatus.REJECTED)).finding
        assert f["status"] == "false_positive"  # rejected is never an open finding

    def test_record_without_severity_does_not_crash_and_warns(self):
        rec = _record(severity=None, cvss=())
        conv = to_ctis_finding(rec)
        assert conv.finding["severity"] in ("unknown", "none", "info")
        assert conv.warnings  # the gap is surfaced, not hidden

    def test_report_envelope_wraps_findings(self):
        rep = to_ctis_report([to_ctis_finding(_record())], generated_at=NOW)
        assert rep["version"] == "2.0"
        assert len(rep["findings"]) == 1
        assert rep["findings"][0]["vulnerability"]["ids"][0]["id"] == "CVE-2021-44228"

    def test_empty_report_is_valid(self):
        doc = to_ctis_report([], generated_at=NOW)
        assert doc["findings"] == []
