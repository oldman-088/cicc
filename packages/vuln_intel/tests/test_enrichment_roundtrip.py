"""Enrichment provenance round-trip through the REAL path:

connector.parse(fixture doc) -> NormalizedVulnerability -> IngestionService
-> InMemoryVulnerabilityStore -> VulnerabilityApi list/get.

Not hand-built rows: this catches layer-to-layer spelling drift (the class of
bug where the writer and reader of `details`/`cicc_enrichment` disagree).
"""

from __future__ import annotations

from datetime import datetime, timezone

from vuln_intel.connectors.osv import OsvConnector
from vuln_intel.integration.api import (
    GetVulnerabilityRequest,
    ListVulnerabilitiesRequest,
    VulnerabilityApi,
)
from vuln_intel.integration.service import IngestionPolicy, IngestionService
from vuln_intel.integration.store import InMemoryVulnerabilityStore
from vuln_intel.ratelimit import RateGate
from vuln_intel.retry import RetryPolicy
from vuln_intel.schema import Origin

from . import fixtures as fx
from .conftest import FakeTransport, no_wait, response

NOW = datetime(2026, 11, 5, tzinfo=timezone.utc)


def _ingest():
    connector = OsvConnector(
        transport=FakeTransport(script=[response(fx.OSV_CVE)]),
        gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
        retry=RetryPolicy(attempts=1), sleep=no_wait, origin=Origin.FIXTURE,
    )
    record, _ = connector.get_vulnerability("GHSA-0000-aaaa-bbbb")
    assert record is not None
    store = InMemoryVulnerabilityStore(allow_fixture=True)
    IngestionService(
        store=store, policy=IngestionPolicy(allow_fixture=True, dry_run=False)
    ).import_records([record], tenant_id="t1", collected_at=NOW)
    return record, VulnerabilityApi(store)


class TestEnrichmentRoundTrip:
    def test_record_fields_survive_to_api_get(self):
        record, api = _ingest()
        shaped = api.get(GetVulnerabilityRequest(tenant_id="t1", cve=str(record.cve)),
                         now=NOW).body["data"]
        assert shaped["cve"] == str(record.cve)
        assert shaped["origin"] == "fixture"
        assert shaped["sources"] == list(record.sources)
        # severity written by the mapping layer is served back, not null
        assert shaped["severity"] == record.effective_severity.value
        assert shaped["summary"] == record.summary
        assert shaped["affected"], "affected packages must survive the round trip"
        first = shaped["affected"][0]
        assert first["ecosystem"] == record.affected[0].ecosystem
        assert first["name"] == record.affected[0].name
        assert shaped["freshness_view"]["state"] != "current"

    def test_record_fields_survive_to_api_list(self):
        record, api = _ingest()
        rows = api.list(ListVulnerabilitiesRequest(tenant_id="t1", limit=50), now=NOW).body["data"]
        assert len(rows) == 1
        assert rows[0]["cve"] == str(record.cve)
        assert rows[0]["sources"] == list(record.sources)

    def test_severity_filter_matches_normally_ingested_row(self):
        record, api = _ingest()
        body = api.list(ListVulnerabilitiesRequest(
            tenant_id="t1", limit=50, severity=record.effective_severity.value), now=NOW).body
        assert [r["cve"] for r in body["data"]] == [str(record.cve)]

    def test_provenance_events_recorded_on_ingest(self):
        _record, api = _ingest()
        store = api.store
        events = store.provenance_events
        assert events and all(e.get("tenant_id") == "t1" for e in events)
