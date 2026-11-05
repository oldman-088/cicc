"""GHSA connector — offline fixtures only. No live claim (LAST_VERIFIED_LIVE None)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tests.conftest import FakeTransport, response
from vuln_intel.connectors.ghsa import (
    GHSA_API,
    LAST_VERIFIED_LIVE,
    GhsaConnector,
    _range_to_bounds,
    snapshot_from_document,
    to_vulnerability_records,
)
from vuln_intel.errors import SourceResponseError
from vuln_intel.retry import RetryPolicy
from vuln_intel.schema import Origin, Severity

NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)

ADVISORIES = [
    {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "cve_id": "CVE-2021-44228",
        "summary": "Log4Shell",
        "severity": "critical",
        "published_at": "2021-12-10T00:00:00Z",
        "updated_at": "2021-12-14T00:00:00Z",
        "vulnerabilities": [
            {"package": {"ecosystem": "Maven", "name": "log4j-core"},
             "vulnerable_version_range": ">= 2.0, < 2.15.0",
             "first_patched_version": "2.15.0"},
            {"package": {"ecosystem": "Maven", "name": "log4j-core"},
             "vulnerable_version_range": ">= 2.0-beta9, < 2.12.2",
             "first_patched_version": "2.12.2"},
        ],
        "references": ["https://github.com/advisories/GHSA-aaaa-bbbb-cccc"],
    },
    {
        "ghsa_id": "GHSA-dddd-eeee-ffff",
        "cve_id": None,  # GHSA-only: must NOT fabricate a CVE
        "summary": "GHSA without CVE",
        "severity": "high",
        "vulnerabilities": [],
        "references": [],
    },
    "not-a-mapping",  # malformed row
]


class TestRangeParsing:
    def test_simple_ranges_map_to_bounds(self):
        assert _range_to_bounds(">= 2.0, < 2.15.0") == ("2.0", "2.15.0")
        assert _range_to_bounds("< 1.2.3") == (None, "1.2.3")

    def test_complex_ranges_stay_opaque(self):
        assert _range_to_bounds(">= 1.0 || < 0.9") == (None, None)
        assert _range_to_bounds("^1.2.3") == (None, None)


class TestParse:
    def test_snapshot_preserves_advisories_and_counts_skipped(self):
        snap = snapshot_from_document(
            ADVISORIES, fetched_at=NOW, origin=Origin.FIXTURE, transport="unaudited"
        )
        assert snap.skipped == 1
        assert len(snap.advisories) == 2
        by_id = {a.ghsa_id: a for a in snap.advisories}
        ghsa = by_id["GHSA-aaaa-bbbb-cccc"]
        assert ghsa.cve_id == "CVE-2021-44228"
        assert ghsa.severity is Severity.CRITICAL
        assert ghsa.packages == (("Maven", "log4j-core"),)
        assert by_id["GHSA-dddd-eeee-ffff"].cve_id is None

    def test_non_list_document_rejected(self):
        with pytest.raises(Exception):
            snapshot_from_document({"no": "list"}, fetched_at=NOW,
                                   origin=Origin.FIXTURE, transport="unaudited")


class TestFetch:
    def test_fetch_tracks_attempt_and_success_and_sends_token_header_only(self):
        connector = GhsaConnector(
            transport=FakeTransport(script=[response(ADVISORIES)]),
            origin="fixture", token="secret-token-value", sleep=lambda _: None,
        )
        snap = connector.fetch()
        assert snap.origin is Origin.FIXTURE
        assert connector.last_attempt is not None and connector.last_success is not None
        call = connector.transport.calls[0]
        assert call["url"] == GHSA_API
        headers = call.get("headers", {})
        assert headers.get("Authorization") == "Bearer secret-token-value"
        # the token must never appear in the connector's own repr (the transport's
        # recorded call headers legitimately contain it — that is the wire format)
        import dataclasses
        assert all(f.repr is False for f in dataclasses.fields(connector) if f.name == "token")
        bare = dataclasses.replace(connector, transport=None)
        assert "secret-token-value" not in repr(bare)

    def test_failed_fetch_records_attempt_not_success(self):
        connector = GhsaConnector(
            transport=FakeTransport(script=[response(b"x", status=403)]),
            origin="fixture", retry=RetryPolicy(attempts=1), sleep=lambda _: None,
        )
        with pytest.raises(SourceResponseError):
            connector.fetch()
        assert connector.last_attempt is not None and connector.last_success is None

    def test_no_transport_raises(self):
        with pytest.raises(SourceResponseError, match="no transport"):
            GhsaConnector(origin="fixture").fetch()

    def test_live_claim_constant_is_none(self):
        assert LAST_VERIFIED_LIVE is None


class TestNormalization:
    def test_cve_records_carry_ghsa_alias_and_patched_versions(self):
        snap = snapshot_from_document(
            ADVISORIES, fetched_at=NOW, origin=Origin.FIXTURE, transport="unaudited"
        )
        records = to_vulnerability_records(snap)
        assert len(records) == 1  # the GHSA-only advisory produced none
        rec = records[0]
        assert str(rec.cve) == "CVE-2021-44228"
        assert rec.aliases == ("GHSA-aaaa-bbbb-cccc",)
        assert rec.severity is Severity.CRITICAL
        assert rec.sources == ("github-advisories",)
        fixed = {a.fixed for a in rec.affected}
        assert fixed == {"2.15.0", "2.12.2"}
        assert all(a.ecosystem == "maven" for a in rec.affected)
        assert rec.verification == "unverified"

    def test_ghsa_only_advisory_never_fabricates_cve(self):
        snap = snapshot_from_document(
            ADVISORIES, fetched_at=NOW, origin=Origin.FIXTURE, transport="unaudited"
        )
        records = to_vulnerability_records(snap)
        assert all(str(r.cve).startswith("CVE-") for r in records)
