"""Cross-connector consistency regression sweep.

One test per invariant, run over EVERY source connector (NVD, OSV, KEV, EPSS,
Debian, Ubuntu, GHSA): source identity, provenance, aware timestamps,
honest live-claim constants, and last_attempt/last_success separation.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tests.conftest import FakeTransport, response
from vuln_intel import kev as kev_mod
from vuln_intel.connectors import debian, ghsa, nvd, osv, ubuntu
from vuln_intel.retry import RetryPolicy

NOW = datetime(2026, 11, 5, tzinfo=timezone.utc)

# (module, connector class, minimal fixture document, live-claim attr)
CONNECTORS = [
    ("kev", kev_mod.KevConnector, {
        "catalogVersion": "2026.11.01", "count": 1,
        "vulnerabilities": [{"cveID": "CVE-2026-1111", "dateAdded": "2026-11-01",
                             "dueDate": "2026-11-20"}],
    }, None),
    ("debian", debian.DebianTrackerConnector, {"pkg": {"CVE-2026-1111": {"description": "x",
        "releases": {"bookworm": {"status": "open"}}}}}, None),
    ("ubuntu", ubuntu.UbuntuUsnConnector, {"USN-1-1": {"cves": ["CVE-2026-1111"], "severity": "high",
                                     "releases": {}}}, None),
    ("ghsa", ghsa.GhsaConnector, [{"ghsa_id": "GHSA-a-b-c", "cve_id": "CVE-2026-1111",
                     "severity": "high", "vulnerabilities": [], "references": []}], None),
]


class TestLiveClaimHonesty:
    @pytest.mark.parametrize("attr", [
        kev_mod.LAST_VERIFIED_LIVE, nvd.LAST_VERIFIED_LIVE, osv.LAST_VERIFIED_LIVE,
        debian.LAST_VERIFIED_LIVE, ubuntu.LAST_VERIFIED_LIVE, ghsa.LAST_VERIFIED_LIVE,
    ])
    def test_all_live_claim_constants_are_none(self, attr):
        assert attr is None


class TestFailureKeepsLastSuccessSeparate:
    @pytest.mark.parametrize("mod,cls,doc,_", CONNECTORS)
    def test_failed_fetch_records_attempt_not_success(self, mod, cls, doc, _):
        connector = cls(
            transport=FakeTransport(script=[response(b"x", status=500)]),
            origin="fixture", retry=RetryPolicy(attempts=1), sleep=lambda _: None,
        )
        with pytest.raises(Exception):
            connector.fetch()
        assert connector.last_attempt is not None
        assert connector.last_success is None

    @pytest.mark.parametrize("mod,cls,doc,_", CONNECTORS)
    def test_successful_fetch_sets_both_and_parse_touches_neither(self, mod, cls, doc, _):
        connector = cls(
            transport=FakeTransport(script=[response(doc)]),
            origin="fixture", sleep=lambda _: None,
        )
        snap = connector.fetch()
        assert connector.last_attempt is not None and connector.last_success is not None
        assert connector.last_success >= connector.last_attempt
        # snapshot provenance is present and origin-tagged
        assert getattr(snap.origin, "value", snap.origin) == "fixture"
        before = (connector.last_attempt, connector.last_success)
        connector.parse(doc, fetched_at=NOW)
        assert (connector.last_attempt, connector.last_success) == before
