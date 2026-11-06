"""Ubuntu USN connector — offline fixtures only. No live claim."""

from __future__ import annotations

import bz2
import json
from datetime import datetime, timezone

import pytest

from tests.conftest import FakeTransport, response
from vuln_intel.connectors.ubuntu import (
    LAST_VERIFIED_LIVE,
    USN_DB_URL,
    UbuntuUsnConnector,
    snapshot_from_document,
    to_vulnerability_records,
)
from vuln_intel.errors import SourceResponseError
from vuln_intel.retry import RetryPolicy
from vuln_intel.schema import Origin, Severity

NOW = datetime(2026, 6, 1, 8, 0, tzinfo=timezone.utc)

USN_DOC = {
    "USN-7000-1": {
        "id": "USN-7000-1",
        "title": "OpenSSL vulnerability",
        "description": "Several issues in OpenSSL",
        "cves": ["CVE-2026-3333", "cve-2026-4444"],  # case normalized
        "severity": "high",
        "published": "2026-05-01T10:00:00Z",
        "updated": "2026-05-03T10:00:00Z",
        "releases": {
            "jammy": {
                "sources": {
                    "openssl": {"status": "released", "fixed_version": "3.0.2-0ubuntu1.20"},
                    "openssl3": {"status": "needed"},
                }
            },
            "focal": {"sources": {"openssl": {"status": "released", "fixed_version": "1.1.1f-1ubuntu2.24"}}},
        },
    },
    "USN-7001-1": {
        "id": "USN-7001-1",
        "title": "Notice with no CVEs",
        "cves": [],
        "severity": "low",
        "releases": {},
    },
    "USN-BROKEN": "not-a-mapping",
}


class TestParse:
    def test_notices_parsed_with_cves_severity_timestamps_and_fixes(self):
        snap = snapshot_from_document(
            USN_DOC, fetched_at=NOW, origin=Origin.FIXTURE, transport="unaudited"
        )
        assert snap.skipped == 1
        by_id = {n.usn_id: n for n in snap.notices}
        usn = by_id["USN-7000-1"]
        assert usn.cves == ("CVE-2026-3333", "CVE-2026-4444")
        assert usn.severity is Severity.HIGH
        assert usn.published == datetime(2026, 5, 1, 10, 0, tzinfo=timezone.utc)
        assert usn.updated is not None
        fixes = {(f.release, f.package): f for f in usn.fixes}
        assert fixes[("jammy", "openssl")].fixed_version == "3.0.2-0ubuntu1.20"
        assert fixes[("jammy", "openssl3")].status == "needed"
        assert fixes[("jammy", "openssl3")].fixed_version is None

    def test_malformed_cve_strings_are_skipped_not_fatal(self):
        doc = {"USN-1-1": {"cves": ["CVE-2026-1111", "not-a-cve"], "releases": {}}}
        snap = snapshot_from_document(
            doc, fetched_at=NOW, origin=Origin.FIXTURE, transport="unaudited"
        )
        assert snap.notices[0].cves == ("CVE-2026-1111",)


class TestFetch:
    def test_fetch_decodes_bzip2_body_and_tracks_sync_times(self):
        payload = bz2.compress(json.dumps(USN_DOC).encode())
        connector = UbuntuUsnConnector(
            transport=FakeTransport(script=[response(payload)]),
            origin="fixture",
            sleep=lambda _: None,
        )
        snap = connector.fetch()
        assert snap.origin is Origin.FIXTURE
        assert len(snap.notices) == 2
        assert connector.last_attempt is not None and connector.last_success is not None
        assert connector.transport.calls[0]["url"] == USN_DB_URL

    def test_plain_json_body_also_accepted(self):
        connector = UbuntuUsnConnector(
            transport=FakeTransport(script=[response(json.dumps(USN_DOC).encode())]),
            origin="fixture", sleep=lambda _: None,
        )
        assert len(connector.fetch().notices) == 2

    def test_failed_fetch_records_attempt_not_success(self):
        connector = UbuntuUsnConnector(
            transport=FakeTransport(script=[response(b"x", status=503)]),
            origin="fixture", retry=RetryPolicy(attempts=1), sleep=lambda _: None,
        )
        with pytest.raises(SourceResponseError):
            connector.fetch()
        assert connector.last_attempt is not None
        assert connector.last_success is None

    def test_no_transport_raises(self):
        with pytest.raises(SourceResponseError, match="no transport"):
            UbuntuUsnConnector(origin="fixture").fetch()

    def test_live_claim_constant_is_none(self):
        assert LAST_VERIFIED_LIVE is None


class TestNormalization:
    def test_one_record_per_usn_cve_pair_with_usn_alias(self):
        snap = snapshot_from_document(
            USN_DOC, fetched_at=NOW, origin=Origin.FIXTURE, transport="unaudited"
        )
        records = to_vulnerability_records(snap)
        cves = sorted(str(r.cve) for r in records)
        assert cves == ["CVE-2026-3333", "CVE-2026-4444"]
        for rec in records:
            assert rec.aliases == ("USN-7000-1",)
            assert rec.sources == ("ubuntu-usn",)
            assert rec.severity is Severity.HIGH  # Ubuntu's own claim
            assert rec.verification == "unverified"
            fixed = {a.fixed for a in rec.affected if a.fixed}
            assert "3.0.2-0ubuntu1.20" in fixed
            assert all(a.ecosystem == "ubuntu" for a in rec.affected)

    def test_notice_without_cves_produces_no_record(self):
        snap = snapshot_from_document(
            USN_DOC, fetched_at=NOW, origin=Origin.FIXTURE, transport="unaudited"
        )
        records = to_vulnerability_records(snap)
        assert all("USN-7001-1" not in r.aliases for r in records)
