"""CTIS interoperability: the external schema is the specification.

These tests are unusual for this package in that the *authority* is outside the
repository. Elsewhere, a behaviour is correct because a test says so; here the
vendored OpenCTEM schema says so, and our opinion does not count.

That is the whole reason the adapter exists. Internal consistency proves our model
agrees with itself. Validation against CTIS proves it agrees with the world.
"""

from __future__ import annotations

import json
import pathlib
import re
from datetime import datetime, timezone

import pytest

from vuln_intel.interop.ctis import (
    _SOLUTION_TYPE,
    FINDING_TYPE,
    to_ctis_finding,
    to_ctis_report,
    uuid7,
)
from vuln_intel.remediation import RecommendedAction
from vuln_intel.schema import (
    CveId,
    CvssScore,
    FieldConflict,
    NormalizedVulnerability,
    Origin,
    RecordStatus,
    Severity,
)

SCHEMA_DIR = pathlib.Path(__file__).parent / "fixtures" / "ctis"
SCHEMA_BASE = "https://schemas.openctem.io/ctis/2.0/"

try:  # pragma: no cover - exercised by presence/absence of a test dependency
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource

    HAVE_VALIDATOR = True
except ImportError:  # pragma: no cover
    HAVE_VALIDATOR = False


def _record(**kwargs) -> NormalizedVulnerability:
    base = dict(
        cve=CveId.parse("CVE-2026-7000"),
        origin=Origin.FIXTURE,
        sources=("nvd", "osv"),
        summary="Heap buffer overflow in libfoo",
        cvss=(
            CvssScore(
                version="3.1", base_score=9.8, vector="AV:N/AC:L/PR:N/UI:N",
                severity=Severity.CRITICAL, source="nvd",
            ),
        ),
        epss_score=0.72,
        epss_percentile=0.98,
        kev=True,
        cwe=("CWE-120",),
        ssvc=(
            ("exploitation", "active"),
            ("automatable", "yes"),
            ("technical_impact", "total"),
        ),
    )
    base.update(kwargs)
    return NormalizedVulnerability(**base)


def _registry():
    schemas = {
        path.stem: json.loads(path.read_text())
        for path in sorted(SCHEMA_DIR.glob("*.json"))
    }
    registry = Registry()
    for name, schema in schemas.items():
        registry = registry.with_resource(
            f"{SCHEMA_BASE}{name}.json", Resource.from_contents(schema)
        )
    return schemas, registry


needs_validator = pytest.mark.skipif(
    not HAVE_VALIDATOR,
    reason="jsonschema is not installed; vendored-schema validation skipped",
)


@needs_validator
class TestValidatesAgainstTheRealSchema:
    """The claim in the adapter's docstring, tested rather than asserted in prose."""

    def test_a_full_finding_validates(self) -> None:
        schemas, registry = _registry()
        finding = to_ctis_finding(_record()).finding
        errors = list(Draft202012Validator(schemas["finding"], registry=registry).iter_errors(finding))
        assert errors == [], [f"{list(e.path)}: {e.message}" for e in errors]

    def test_a_report_envelope_validates(self) -> None:
        schemas, registry = _registry()
        report = to_ctis_report([to_ctis_finding(_record())])
        errors = list(Draft202012Validator(schemas["report"], registry=registry).iter_errors(report))
        assert errors == [], [f"{list(e.path)}: {e.message}" for e in errors]

    def test_a_minimal_record_still_validates(self) -> None:
        """No CVSS, no EPSS, no KEV, no SSVC, no summary — the required four only."""
        schemas, registry = _registry()
        finding = to_ctis_finding(
            _record(
                summary=None, cvss=(), epss_score=None, epss_percentile=None,
                kev=None, cwe=(), ssvc=(),
            )
        ).finding
        errors = list(Draft202012Validator(schemas["finding"], registry=registry).iter_errors(finding))
        assert errors == []

    def test_a_rejected_record_validates(self) -> None:
        schemas, registry = _registry()
        finding = to_ctis_finding(
            _record(record_status=RecordStatus.REJECTED)
        ).finding
        errors = list(Draft202012Validator(schemas["finding"], registry=registry).iter_errors(finding))
        assert errors == []

    def test_a_report_with_no_findings_validates(self) -> None:
        schemas, registry = _registry()
        report = to_ctis_report([])
        errors = list(Draft202012Validator(schemas["report"], registry=registry).iter_errors(report))
        assert errors == []


class TestSchemaFreeStructure:
    """Runs even without jsonschema, so the contract never goes unchecked in CI."""

    def test_required_fields_are_present(self) -> None:
        finding = to_ctis_finding(_record()).finding
        for name in ("type", "title", "severity", "asset_ref"):
            assert name in finding, name

    def test_type_is_always_vulnerability(self) -> None:
        assert to_ctis_finding(_record()).finding["type"] == FINDING_TYPE == "vulnerability"

    def test_severity_uses_the_closed_vocabulary(self) -> None:
        allowed = {"critical", "high", "medium", "low", "info", "unknown"}
        for severity in Severity:
            finding = to_ctis_finding(_record(severity=severity)).finding
            assert finding["severity"] in allowed, severity

    def test_status_uses_the_closed_vocabulary(self) -> None:
        allowed = {"open", "resolved", "suppressed", "false_positive",
                   "accepted_risk", "in_progress"}
        for status in (None, *RecordStatus):
            finding = to_ctis_finding(_record(record_status=status)).finding
            assert finding["status"] in allowed, status

    def test_technique_ids_match_the_schema_pattern(self) -> None:
        class _Mapping:
            by_cve = {
                "CVE-2026-7000": (
                    type("T", (), {"technique_id": "T1190"})(),
                    type("T", (), {"technique_id": "T1059.001"})(),
                )
            }

        finding = to_ctis_finding(_record(), attack_mapping=_Mapping()).finding
        pattern = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")
        for technique in finding["attack_technique_ids"]:
            assert pattern.match(technique), technique


class TestStandingMapping:
    """Where our vocabulary and CTIS's disagree, the decision is recorded."""

    def test_rejected_maps_to_false_positive_not_suppressed(self) -> None:
        """Suppressed means *we* silenced a real finding; rejected means it was never one."""
        finding = to_ctis_finding(_record(record_status=RecordStatus.REJECTED)).finding
        assert finding["status"] == "false_positive"

    def test_silence_maps_to_open(self) -> None:
        """The safe reading of 'the source said nothing' is to keep looking."""
        finding = to_ctis_finding(_record(record_status=None)).finding
        assert finding["status"] == "open"

    def test_disputed_is_flagged_as_a_compromise(self) -> None:
        conversion = to_ctis_finding(_record(record_status=RecordStatus.DISPUTED))
        assert conversion.finding["status"] == "in_progress"
        assert any("disputed" in warning for warning in conversion.warnings)

    def test_unknown_severity_does_not_become_info(self) -> None:
        """Mapping unknown to the lowest value would rank ignorance below safety.

        The record must carry no CVSS either: `effective_severity` correctly derives
        a severity from the best vector, so a record with a 9.8 score has a real
        severity even when its stated severity is UNKNOWN.
        """
        finding = to_ctis_finding(
            _record(severity=Severity.UNKNOWN, cvss=())
        ).finding
        assert finding["severity"] == "unknown"


class TestHonestLossReporting:
    """A silent lossy export is the failure mode this module exists to avoid."""

    def test_a_clean_record_reports_kev_as_lost(self) -> None:
        conversion = to_ctis_finding(_record())
        assert any("kev" in item for item in conversion.lost)
        assert not conversion.lossless

    def test_a_record_without_kev_loses_nothing_but_verification(self) -> None:
        conversion = to_ctis_finding(_record(kev=None, record_status=RecordStatus.PUBLISHED))
        assert conversion.lost == ()

    def test_conflicts_are_reported_as_unexportable(self) -> None:
        conversion = to_ctis_finding(
            _record(
                conflicts=(
                    FieldConflict(
                        field="severity", kept="critical", discarded=("high",)
                    ),
                )
            )
        )
        assert any("conflicts" in item for item in conversion.lost)

    def test_priority_is_named_as_a_nonstandard_extension(self) -> None:
        class _Priority:
            score = 77.7
            band = "urgent"
            policy = "provisional"
            policy_approved = False

        conversion = to_ctis_finding(_record(), priority=_Priority())
        assert conversion.finding["properties"]["cicc"]["priority_score"] == 77.7
        assert any("priority" in item for item in conversion.lost)

    def test_unverified_is_always_stated(self) -> None:
        """No live provider request has ever been recorded, and the export says so."""
        conversion = to_ctis_finding(_record())
        assert any("unverified" in warning for warning in conversion.warnings)


class TestRemediationMapping:
    def test_every_action_maps_to_a_schema_value(self) -> None:
        allowed = {"vendor_fix", "workaround", "mitigation", "no_fix_planned",
                   "none_available", "config_change", "upgrade"}
        assert set(_SOLUTION_TYPE) == set(RecommendedAction)
        assert set(_SOLUTION_TYPE.values()) <= allowed

    def test_no_fix_is_never_reported_as_no_fix_planned(self) -> None:
        """We learn what is *available*, never what a vendor *intends*."""
        assert "no_fix_planned" not in _SOLUTION_TYPE.values()


class TestReportIdempotencyKey:
    """`metadata.id` is the deduplication key; getting it wrong double-ingests."""

    def test_uuid7_shape(self) -> None:
        value = uuid7()
        assert re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            value,
        )

    def test_is_deterministic_for_the_same_inputs(self) -> None:
        moment = datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert uuid7(at=moment, random_bits=42) == uuid7(at=moment, random_bits=42)

    def test_differs_across_calls(self) -> None:
        assert uuid7() != uuid7()

    def test_encodes_the_millisecond_timestamp(self) -> None:
        moment = datetime(2026, 1, 1, tzinfo=timezone.utc)
        value = uuid7(at=moment, random_bits=0)
        millis = int(value.replace("-", "")[:12], 16)
        assert millis == int(moment.timestamp() * 1000)

    def test_a_retry_reuses_the_supplied_id(self) -> None:
        fixed = uuid7()
        first = to_ctis_report([], report_id=fixed)
        retry = to_ctis_report([], report_id=fixed)
        assert first["metadata"]["id"] == retry["metadata"]["id"] == fixed

    def test_report_requires_metadata_id_and_generated_at(self) -> None:
        metadata = to_ctis_report([])["metadata"]
        assert metadata["id"] and metadata["generated_at"]


class TestSsvcLabelHonesty:
    def test_an_undecidable_ssvc_is_a_range_not_a_guess(self) -> None:
        """mission_wellbeing is unknown to us, so a single decision would be invented."""
        scores = to_ctis_finding(_record()).finding["scores"]
        ssvc = next(s for s in scores if s["system"] == "ssvc")
        assert ".." in ssvc["label"]
        assert "value" not in ssvc

    def test_cvss_scores_keep_their_source(self) -> None:
        scores = to_ctis_finding(_record()).finding["scores"]
        cvss = next(s for s in scores if s["system"] == "cvss")
        assert cvss["source"] == "nvd"
        assert cvss["value"] == 9.8
