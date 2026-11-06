"""SARIF ingest: preserve scanner evidence, never upgrade a finding to a vuln."""

from __future__ import annotations

import pytest

from vuln_intel.errors import ValidationError
from vuln_intel.interop.sarif import (
    SARIF_VERSION,
    parse_sarif,
    to_vulnerability_candidates,
)


def _doc(*results, version=SARIF_VERSION, tool="bandit", tool_version="1.7.9"):
    return {
        "version": version,
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": tool, "version": tool_version}},
                "results": list(results),
            }
        ],
    }


def _result(rule_id=None, message="finding", uri="app/main.py", level="warning",
            fingerprints=None, properties=None):
    r = {"level": level, "message": {"text": message}}
    if rule_id:
        r["ruleId"] = rule_id
    if uri:
        r["locations"] = [
            {"physicalLocation": {"artifactLocation": {"uri": uri}}}
        ]
    if fingerprints:
        r["partialFingerprints"] = fingerprints
    if properties:
        r["properties"] = properties
    return r


class TestValidation:
    def test_valid_document_parses_with_tool_identity(self):
        doc = parse_sarif(_doc(_result(rule_id="CVE-2021-44228")))
        assert doc.version == SARIF_VERSION
        assert doc.tools == ("bandit",)
        (f,) = doc.findings
        assert f.tool == "bandit" and f.tool_version == "1.7.9"
        assert f.rule_id == "CVE-2021-44228"
        assert f.uri == "app/main.py"

    def test_wrong_version_is_refused_not_partially_read(self):
        with pytest.raises(ValidationError, match="unsupported SARIF version"):
            parse_sarif(_doc(_result(), version="2.0.0"))

    def test_non_object_is_refused(self):
        with pytest.raises(ValidationError, match="must be an object"):
            parse_sarif(["nope"])  # type: ignore[arg-type]

    def test_missing_runs_is_refused(self):
        with pytest.raises(ValidationError, match="runs"):
            parse_sarif({"version": SARIF_VERSION})

    def test_malformed_run_is_counted_not_fatal(self):
        doc = {"version": SARIF_VERSION, "runs": [{"nope": 1}, _doc()["runs"][0]]}
        parsed = parse_sarif(doc)
        assert parsed.skipped_runs == 1
        assert len(parsed.findings) == 0 or parsed.findings


class TestCandidates:
    def test_cve_in_rule_id_becomes_unconfirmed_candidate(self):
        doc = parse_sarif(_doc(_result(rule_id="CVE-2021-44228")))
        (c,) = to_vulnerability_candidates(doc.findings)
        assert c.cve == "CVE-2021-44228"
        assert c.cve_source == "ruleId"
        assert c.confirmed is False

    def test_cve_in_properties_is_accepted_with_source(self):
        doc = parse_sarif(
            _doc(_result(rule_id="B101", properties={"cve": "CVE-2026-4321"}))
        )
        (c,) = to_vulnerability_candidates(doc.findings)
        assert c.cve == "CVE-2026-4321"
        assert c.cve_source == "properties.cve"

    def test_finding_without_cve_is_not_a_candidate(self):
        doc = parse_sarif(_doc(_result(rule_id="B101", message="hardcoded password")))
        assert to_vulnerability_candidates(doc.findings) == ()

    def test_same_finding_twice_dedupes(self):
        fp = {"primaryLocationLineHash": "abc123"}
        doc = parse_sarif(
            _doc(_result(rule_id="CVE-2021-44228", fingerprints=fp),
                 _result(rule_id="CVE-2021-44228", fingerprints=fp))
        )
        assert len(to_vulnerability_candidates(doc.findings)) == 1

    def test_different_findings_same_cve_are_kept_separate(self):
        doc = parse_sarif(
            _doc(_result(rule_id="CVE-2021-44228", uri="a.py",
                         fingerprints={"h": "1"}),
                 _result(rule_id="CVE-2021-44228", uri="b.py",
                         fingerprints={"h": "2"}))
        )
        assert len(to_vulnerability_candidates(doc.findings)) == 2

    def test_scanner_level_is_preserved_but_not_a_severity(self):
        doc = parse_sarif(_doc(_result(rule_id="CVE-2026-0001", level="error")))
        (c,) = to_vulnerability_candidates(doc.findings)
        assert c.finding.level == "error"
        assert c.confirmed is False  # level never upgrades confirmation
