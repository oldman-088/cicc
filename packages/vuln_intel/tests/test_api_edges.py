"""API list edge cases: filters + pagination combined, tenant isolation, bad input."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from vuln_intel.integration.api import ApiError, ListVulnerabilitiesRequest, VulnerabilityApi
from vuln_intel.integration.service import IngestionPolicy, IngestionService
from vuln_intel.integration.store import InMemoryVulnerabilityStore
from vuln_intel.schema import CveId, NormalizedVulnerability, Origin, Severity

NOW = datetime(2026, 11, 5, tzinfo=timezone.utc)


def _store_with(tenant: str, recs) -> InMemoryVulnerabilityStore:
    store = InMemoryVulnerabilityStore(allow_fixture=True)
    service = IngestionService(
        store=store, policy=IngestionPolicy(allow_fixture=True, dry_run=False))
    service.import_records(recs, tenant_id=tenant, collected_at=NOW)
    return store


def _rec(cve: str, severity: Severity | None = None, kev: bool | None = None):
    return NormalizedVulnerability(
        cve=CveId.parse(cve), origin=Origin.FIXTURE, kev=kev,
        severity=severity, sources=("osv",),
    )


RECS = [
    _rec("CVE-2026-0001", Severity.CRITICAL, kev=True),
    _rec("CVE-2026-0002", Severity.HIGH),
    _rec("CVE-2026-0003", Severity.LOW),
]


class TestListEdges:
    def test_pagination_then_filter_keeps_all_matches(self):
        api = VulnerabilityApi(_store_with("t", RECS))
        seen = []
        cursor = None
        while True:
            body = api.list(ListVulnerabilitiesRequest(
                tenant_id="t", limit=1, severity="high", cursor=cursor), now=NOW).body
            seen += [r["cve"] for r in body["data"]]
            cursor = body["page"]["next_cursor"]
            if cursor is None:
                break
        assert seen == ["CVE-2026-0002"]  # only the HIGH one, across pages

    def test_kev_only_excludes_unconsulted(self):
        api = VulnerabilityApi(_store_with("t", RECS))
        body = api.list(ListVulnerabilitiesRequest(
            tenant_id="t", limit=50, kev_only=True), now=NOW).body
        assert [r["cve"] for r in body["data"]] == ["CVE-2026-0001"]

    def test_tenant_isolation(self):
        store = _store_with("a", RECS)
        IngestionService(store=store, policy=IngestionPolicy(allow_fixture=True, dry_run=False)).import_records(
            [_rec("CVE-2026-9999")], tenant_id="b", collected_at=NOW)
        api = VulnerabilityApi(store)
        a = api.list(ListVulnerabilitiesRequest(tenant_id="a", limit=50), now=NOW).body
        b = api.list(ListVulnerabilitiesRequest(tenant_id="b", limit=50), now=NOW).body
        assert {r["cve"] for r in a["data"]} == {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"}
        assert [r["cve"] for r in b["data"]] == ["CVE-2026-9999"]

    def test_every_row_carries_freshness_view(self):
        api = VulnerabilityApi(_store_with("t", RECS))
        body = api.list(ListVulnerabilitiesRequest(tenant_id="t", limit=50), now=NOW).body
        for row in body["data"]:
            assert row["freshness_view"]["state"] in (
                "unknown", "never_verified", "current", "aging", "stale")
            assert row["freshness_view"]["state"] != "current"  # no live success recorded

    def test_invalid_order_rejected(self):
        api = VulnerabilityApi(_store_with("t", RECS))
        with pytest.raises(ApiError):
            api.list(ListVulnerabilitiesRequest(tenant_id="t", limit=50, order="evil"),
                     now=NOW)

    def test_empty_tenant_lists_empty(self):
        api = VulnerabilityApi(InMemoryVulnerabilityStore())
        body = api.list(ListVulnerabilitiesRequest(tenant_id="nobody", limit=10), now=NOW).body
        assert body["data"] == [] and body["page"]["has_more"] is False
