"""OpenVEX export: the justification field is a truth claim, so it is tested as one.

The load-bearing rules of this adapter, in order of what would hurt most if broken:

1. ``UNKNOWN`` never becomes ``not_affected``.
2. A version excluded because it *predates* the range is ``vulnerable_code_not_present``.
3. A version excluded because it *already has the fix* gets **no** justification — the
   vulnerable code is present, so claiming it is absent would be false, and calling a
   version bump an "inline mitigation" would be false in a different direction. The
   status note carries the reason instead.
4. Every emitted status and justification is inside the spec's enumeration.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from vuln_intel.affected import ExclusionSide, Verdict
from vuln_intel.assessment import workflow_for
from vuln_intel.interop.openvex import (
    ALLOWED_JUSTIFICATIONS,
    ALLOWED_STATUSES,
    OPENVEX_SPEC_VERSION,
    openvex_status_for,
    to_openvex,
)
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


def _record(cve: str, *, kev: bool | None = None, introduced="2.0.0", fixed="2.15.0"):
    return NormalizedVulnerability(
        cve=CveId.parse(cve),
        origin=Origin.FIXTURE,
        summary="flaw in log4j-core",
        affected=(
            AffectedPackage(
                ecosystem="maven", name="log4j-core", introduced=introduced, fixed=fixed
            ),
        ),
        kev=kev,
        sources=("nvd", "cisa-kev") if kev else ("nvd",),
        cvss=(
            CvssScore(
                version="3.1",
                base_score=9.8,
                severity=Severity.CRITICAL,
                vector=VECTOR,
                source="nvd",
            ),
        ),
        references=(Reference(url="https://nvd.example/" + cve, kind="advisory", source="nvd"),),
    )


def _report(version: str, *, cve="CVE-2021-44228", kev: bool | None = True):
    return workflow_for(
        records=[_record(cve, kev=kev)],
        inventory=Inventory(
            dependencies=(Dependency(ecosystem="maven", name="log4j-core",
                                     version=version, asset="payments"),)
        ),
        now=lambda: NOW,
    )


class TestStatusAndJustificationMapping:
    def test_affected_has_no_justification(self):
        status, justification = openvex_status_for(Verdict.AFFECTED)
        assert (status, justification) == ("affected", None)

    def test_unknown_is_under_investigation_never_not_affected(self):
        for kev in (None, False, True):
            status, _ = openvex_status_for(Verdict.UNKNOWN, kev=kev)
            assert status == "under_investigation"

    def test_predating_version_justifies_not_present(self):
        status, justification = openvex_status_for(
            Verdict.NOT_AFFECTED, excluded_by=ExclusionSide.BEFORE
        )
        assert status == "not_affected"
        assert justification == "vulnerable_code_not_present"

    def test_patched_version_gets_no_justification(self):
        """The vulnerable code *is* present; it is just already patched.

        Claiming ``vulnerable_code_not_present`` here would be a false statement in the
        document, which is worse than a missing optional field.
        """
        status, justification = openvex_status_for(
            Verdict.NOT_AFFECTED, excluded_by=ExclusionSide.AFTER
        )
        assert status == "not_affected"
        assert justification is None

    def test_unusable_range_gets_no_justification(self):
        for side in (None, ExclusionSide.UNKNOWN):
            _, justification = openvex_status_for(Verdict.NOT_AFFECTED, excluded_by=side)
            assert justification is None

    def test_every_justification_is_in_the_spec_enumeration(self):
        for side in (None, *ExclusionSide):
            _, justification = openvex_status_for(Verdict.NOT_AFFECTED, excluded_by=side)
            if justification is not None:
                assert justification in ALLOWED_JUSTIFICATIONS


class TestDocumentShape:
    def test_envelope_matches_the_openvex_context(self):
        export = to_openvex(_report("2.14.1"), generated_at=NOW)
        doc = export.document
        assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"
        assert doc["version"] == 1
        assert doc["timestamp"] == "2026-02-01T00:00:00Z"
        assert doc["tooling"].startswith("cicc-vuln-intel")
        assert OPENVEX_SPEC_VERSION == "0.2.0"
        json.loads(export.to_json())

    def test_every_status_is_legal(self):
        for version in ("1.0.0", "2.14.1", "2.15.0", "3.0.0"):
            for statement in to_openvex(_report(version), generated_at=NOW).statements:
                assert statement["status"] in ALLOWED_STATUSES

    def test_document_id_is_stable_for_the_same_input(self):
        first = to_openvex(_report("2.14.1"), generated_at=NOW).document["@id"]
        second = to_openvex(_report("2.14.1"), generated_at=NOW).document["@id"]
        assert first == second

    def test_products_carry_a_machine_readable_identity(self):
        export = to_openvex(_report("2.14.1"), generated_at=NOW)
        product = export.statements[0]["products"][0]
        assert product["@id"]
        assert product["identifiers"]["name"] == "log4j-core"
        assert product["identifiers"]["version"] == "2.14.1"


class TestTheHonestyProperties:
    def test_a_patched_version_says_the_fix_is_present(self):
        export = to_openvex(_report("2.15.0"), generated_at=NOW)
        statement = export.statements[0]
        assert statement["status"] == "not_affected"
        assert "justification" not in statement
        assert "already contains the fix" in statement["status_notes"]
        # and the omission is reported rather than hidden
        assert export.unjustified_not_affected

    def test_a_predating_version_says_the_code_is_absent(self):
        export = to_openvex(_report("1.9.0"), generated_at=NOW)
        statement = export.statements[0]
        assert statement["status"] == "not_affected"
        assert statement["justification"] == "vulnerable_code_not_present"
        assert "predates" in statement["status_notes"]
        assert not export.unjustified_not_affected

    def test_an_affected_version_records_kev_listing(self):
        export = to_openvex(_report("2.14.1"), generated_at=NOW)
        statement = export.statements[0]
        assert statement["status"] == "affected"
        assert "cisa_kev: listed" in statement["status_notes"]

    def test_records_without_exposure_data_are_counted_not_dropped(self):
        report = workflow_for(records=[_record("CVE-2021-44228")], inventory=None,
                              now=lambda: NOW)
        export = to_openvex(report, generated_at=NOW)
        assert export.statements == []
        assert "CVE-2021-44228" in export.unassessed

    def test_lost_fields_are_declared(self):
        export = to_openvex(_report("2.14.1"), generated_at=NOW)
        joined = " ".join(export.lost)
        assert "CVSS" in joined and "fixed version" in joined

    def test_timezone_naive_timestamp_is_refused(self):
        with pytest.raises(ValueError, match="timezone-aware"):
            to_openvex(_report("2.14.1"), generated_at=datetime(2026, 2, 1))
