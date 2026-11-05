"""B-04: Debian Security Tracker connector — offline fixtures only.

No live request is made or claimed; LAST_VERIFIED_LIVE stays None.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tests.conftest import FakeTransport, response
from vuln_intel.connectors.debian import (
    DEBIAN_TRACKER_URL,
    LAST_VERIFIED_LIVE,
    DebianTrackerConnector,
    snapshot_from_document,
    to_vulnerability_records,
)
from vuln_intel.errors import SourceResponseError
from vuln_intel.retry import RetryPolicy
from vuln_intel.schema import Origin

NOW = datetime(2026, 4, 1, 9, 0, tzinfo=timezone.utc)

TRACKER_DOC = {
    "log4j-core": {
        "CVE-2021-44228": {
            "description": "JNDI lookup remote code execution",
            "debianbug": 1000895,
            "releases": {
                "bookworm": {
                    "status": "resolved",
                    "fixed_version": "2.19.0-2+deb12u1",
                    "urgency": "high",
                },
                "bullseye": {"status": "open", "urgency": "high"},
                "sid": {"status": "not-affected", "nodsa": "Fixed before sid inclusion"},
            },
        }
    },
    "openssl": {
        "CVE-2026-1111": {
            "description": "fake overflow",
            "releases": {"bookworm": {"status": "resolved", "fixed_version": "3.0.11-1"}},
        },
        "TEMP-0001": {
            "description": "not yet a CVE",
            "releases": {"bookworm": {"status": "open"}},
        },
        "DSA-9999-1": {
            "description": "advisory-keyed entry",
            "releases": {"bookworm": {"status": "resolved", "fixed_version": "3.0.12-1"}},
        },
    },
    "broken-package": "not-a-mapping",  # malformed row
}


class TestParse:
    def test_snapshot_groups_and_counts_skipped_rows(self):
        snap = snapshot_from_document(
            TRACKER_DOC, fetched_at=NOW, origin=Origin.FIXTURE, transport="unaudited"
        )
        assert snap.packages == 3
        assert snap.skipped == 1  # the malformed package row
        by_cve = snap.by_cve()
        assert set(by_cve) == {"CVE-2021-44228", "CVE-2026-1111"}
        # TEMP-0001 and DSA-9999-1 stay in the snapshot as raw evidence
        ids = {i.issue_id for i in snap.issues}
        assert {"TEMP-0001", "DSA-9999-1"} <= ids

    def test_release_fixes_keep_status_urgency_and_notes(self):
        snap = snapshot_from_document(
            TRACKER_DOC, fetched_at=NOW, origin=Origin.FIXTURE, transport="unaudited"
        )
        issue = next(i for i in snap.issues if i.issue_id == "CVE-2021-44228")
        by_release = {r.release: r for r in issue.releases}
        assert by_release["bookworm"].is_resolved
        assert by_release["bookworm"].fixed_version == "2.19.0-2+deb12u1"
        assert by_release["bullseye"].is_vulnerable
        assert by_release["bullseye"].fixed_version is None
        assert not by_release["sid"].is_vulnerable
        assert by_release["sid"].note and "sid" in by_release["sid"].note

    def test_non_object_document_is_rejected(self):
        with pytest.raises(Exception):
            snapshot_from_document(
                ["not", "an", "object"],  # type: ignore[arg-type]
                fetched_at=NOW, origin=Origin.FIXTURE, transport="unaudited",
            )


class TestFetch:
    def test_fetch_uses_transport_and_tracks_attempt_and_success(self):
        connector = DebianTrackerConnector(
            transport=FakeTransport(script=[response(TRACKER_DOC)]),
            origin="fixture",
            sleep=lambda _: None,
        )
        snap = connector.fetch()
        assert snap.origin is Origin.FIXTURE
        assert connector.last_attempt is not None
        assert connector.last_success is not None
        assert connector.last_success >= connector.last_attempt
        assert connector.transport.calls[0]["url"] == DEBIAN_TRACKER_URL

    def test_failed_fetch_records_attempt_but_not_success(self):
        connector = DebianTrackerConnector(
            transport=FakeTransport(script=[response(b"nope", status=500)]),
            origin="fixture",
            retry=RetryPolicy(attempts=1),
            sleep=lambda _: None,
        )
        with pytest.raises(SourceResponseError):
            connector.fetch()
        assert connector.last_attempt is not None
        assert connector.last_success is None

    def test_no_transport_raises_instead_of_empty_snapshot(self):
        connector = DebianTrackerConnector(origin="fixture")
        with pytest.raises(SourceResponseError, match="no transport"):
            connector.fetch()

    def test_parse_does_not_touch_sync_timestamps(self):
        connector = DebianTrackerConnector(origin="fixture")
        connector.parse(TRACKER_DOC, fetched_at=NOW)
        assert connector.last_attempt is None and connector.last_success is None

    def test_live_claim_constant_is_none(self):
        assert LAST_VERIFIED_LIVE is None


class TestNormalization:
    def test_cve_records_carry_debian_affected_and_fixed_versions(self):
        snap = snapshot_from_document(
            TRACKER_DOC, fetched_at=NOW, origin=Origin.FIXTURE, transport="unaudited"
        )
        records = {str(r.cve): r for r in to_vulnerability_records(snap)}
        assert set(records) == {"CVE-2021-44228", "CVE-2026-1111"}
        log4j = records["CVE-2021-44228"]
        assert log4j.sources == ("debian-security-tracker",)
        affected = {a.name: a.fixed for a in log4j.affected}
        assert affected["log4j-core"] in (None, "2.19.0-2+deb12u1")
        fixed_versions = {a.fixed for a in log4j.affected if a.fixed}
        assert "2.19.0-2+deb12u1" in fixed_versions
        # not-affected release produced no affected entry
        assert all(a.ecosystem == "debian" for a in log4j.affected)
        # urgency preserved in details, not turned into a severity
        assert log4j.details and "urgency" in log4j.details
        assert log4j.severity.value == "unknown"
        assert log4j.verification == "unverified"
        assert log4j.origin is Origin.FIXTURE

    def test_non_cve_keys_produce_no_record(self):
        snap = snapshot_from_document(
            TRACKER_DOC, fetched_at=NOW, origin=Origin.FIXTURE, transport="unaudited"
        )
        records = to_vulnerability_records(snap)
        assert all(str(r.cve).startswith("CVE-") for r in records)

    def test_record_with_only_not_affected_releases_is_emitted_with_empty_ranges(self):
        doc = {
            "pkg": {
                "CVE-2026-2222": {
                    "description": "x",
                    "releases": {"bookworm": {"status": "not-affected"}},
                }
            }
        }
        snap = snapshot_from_document(
            doc, fetched_at=NOW, origin=Origin.FIXTURE, transport="unaudited"
        )
        (rec,) = to_vulnerability_records(snap)
        assert rec.affected == ()
        assert str(rec.cve) == "CVE-2026-2222"
