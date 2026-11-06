"""The collection job: composition with the guarantees intact.

The value of this module is not that it calls five things in order, but that it
keeps the subsystem's invariants through the whole chain — provider isolation,
origin refusal, "unassessed is not false", and dry-run safety. Those are what these
tests assert.
"""

from __future__ import annotations

import pytest

from vuln_intel.errors import SourceRateLimited, SourceResponseError
from vuln_intel.integration.job import CollectionJob, source_state
from vuln_intel.integration.service import IngestionPolicy
from vuln_intel.integration.store import InMemoryVulnerabilityStore
from vuln_intel.schema import (
    CveId,
    CvssScore,
    NormalizedVulnerability,
    Origin,
    Severity,
)

from . import fixtures as fx
from .conftest import FakeTransport, no_wait, response


def _osv_record():
    from vuln_intel.connectors.osv import OsvConnector
    from vuln_intel.ratelimit import RateGate
    from vuln_intel.retry import RetryPolicy

    connector = OsvConnector(
        transport=FakeTransport(script=[response(fx.OSV_CVE)]),
        gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
        retry=RetryPolicy(attempts=1),
        sleep=no_wait,
        origin=Origin.FIXTURE,
    )
    record, _advisory = connector.get_vulnerability("GHSA-0000-aaaa-bbbb")
    assert record is not None
    return record


def _record(cve: str = "CVE-2026-1234", *, origin=Origin.FIXTURE, sources=("nvd",)):
    return NormalizedVulnerability(
        cve=CveId.parse(cve),
        origin=origin,
        sources=sources,
        cvss=(
            CvssScore(
                version="4.0", base_score=9.3, severity=Severity.CRITICAL, assessed=True
            ),
        ),
    )


def _job(**kwargs):
    kwargs.setdefault("collectors", {"osv": lambda: [_osv_record()]})
    kwargs.setdefault("tenant_id", "tenant-a")
    kwargs.setdefault("policy", IngestionPolicy(allow_fixture=True, dry_run=False))
    kwargs.setdefault("ingestion_store", InMemoryVulnerabilityStore(allow_fixture=True))
    return CollectionJob(**kwargs)


class TestHappyPath:
    def test_runs_the_whole_chain(self):
        report = _job().run()
        assert report.complete is True
        assert report.collected_anything is True
        assert len(report.records) == 1
        assert len(report.ranking) == 1
        assert report.ingestion is not None
        assert report.ingestion.created == 1

    def test_report_is_json_safe(self):
        import json

        json.dumps(_job().run().as_dict())

    def test_ranking_carries_its_policy(self):
        report = _job().run()
        assert report.ranking[0].policy
        assert report.ranking[0].policy_approved is False

    def test_limit_is_applied_to_ranking(self):
        job = _job(
            collectors={"a": lambda: [_record("CVE-2026-0001"), _record("CVE-2026-0002")]}
        )
        report = job.run(limit=1)
        assert len(report.ranking) == 1
        assert len(report.records) == 2


class TestProviderIsolation:
    def test_one_failed_source_does_not_block_the_others(self):
        def broken():
            raise SourceResponseError("NVD refused the request", source="nvd")

        report = _job(
            collectors={"nvd": broken, "osv": lambda: [_osv_record()]}
        ).run()
        assert report.complete is False
        assert report.failed_sources == ("nvd",)
        assert len(report.records) == 1, "the healthy source must still be processed"
        assert any("nvd failed" in warning for warning in report.warnings)

    def test_unexpected_exception_is_contained(self):
        def explode():
            raise RuntimeError("bug in a connector")

        report = _job(collectors={"nvd": explode}).run()
        assert report.failed_sources == ("nvd",)
        assert report.records == []

    def test_retry_after_is_preserved(self):
        def limited():
            raise SourceRateLimited("slow down", retry_after=42.0, source="nvd")

        report = _job(collectors={"nvd": limited}).run()
        assert report.sources[0].retry_after == 42.0

    def test_empty_answer_is_not_a_failure(self):
        report = _job(collectors={"nvd": list}).run()
        assert report.sources[0].ok is True
        assert report.sources[0].records == 0
        assert report.collected_anything is False
        assert any("empty answer" in warning for warning in report.warnings)


class TestOriginInvariants:
    def test_mixed_origin_is_refused_before_anything_is_stored(self):
        store = InMemoryVulnerabilityStore(allow_fixture=True)
        job = _job(
            collectors={
                "a": lambda: [_record(origin=Origin.FIXTURE)],
                "b": lambda: [_record("CVE-2026-0002", origin=Origin.DEMO)],
            },
            ingestion_store=store,
        )
        report = job.run()
        assert report.collected_anything is False
        assert report.records == []
        assert store.writes == 0, "a refused batch must not write anything"
        assert any("mixed-origin" in warning for warning in report.warnings)

    def test_fixture_records_are_refused_by_production_policy(self):
        store = InMemoryVulnerabilityStore(allow_fixture=False)
        job = _job(
            ingestion_store=store,
            policy=IngestionPolicy(allow_fixture=False, dry_run=False),
        )
        report = job.run()
        assert report.ingestion is not None
        assert report.ingestion.created == 0
        assert store.writes == 0


class TestEnrichmentHonesty:
    def test_kev_without_a_catalogue_stays_unassessed(self):
        """`None` (not consulted) must never become `False` (checked, absent)."""
        report = _job(kev_catalog=None).run()
        assert report.records[0].kev is None
        assert any("KEV catalogue not configured" in warning for warning in report.warnings)

    def test_loaded_catalogue_marks_absent_entries_as_not_listed(self):
        """Absence from a catalogue we did load IS evidence: checked and not listed."""
        from datetime import datetime, timezone

        from vuln_intel.kev import KevCatalog

        catalog = KevCatalog(
            entries={},
            catalog_version="2026.11.01",
            released_at=None,
            fetched_at=datetime(2026, 11, 1, tzinfo=timezone.utc),
            origin="fixture",
        )
        report = _job(kev_catalog=catalog).run()
        assert report.records[0].kev is False

    def test_listed_entry_is_attached_with_its_deadline(self):
        from datetime import date, datetime, timezone

        from vuln_intel.kev import KevCatalog, KevEntry

        entry = KevEntry(
            cve=CveId.parse("CVE-2026-0001"),
            date_added=datetime(2026, 1, 1, tzinfo=timezone.utc),
            vendor="fixture",
            product="fixture",
            name="fixture",
            ransomware_use="Known",
            due_date=date(2026, 2, 1),
        )
        catalog = KevCatalog(
            entries={"CVE-2026-0001": entry},
            catalog_version="2026.11.01",
            released_at=None,
            fetched_at=datetime(2026, 11, 1, tzinfo=timezone.utc),
            origin="fixture",
        )
        report = _job(kev_catalog=catalog).run()
        assert report.records[0].kev is True

    def test_epss_failure_leaves_scores_unset_not_zero(self):
        class BrokenEpss:
            def fetch(self, _cves):
                raise SourceResponseError("EPSS down", source="epss")

        report = _job(epss_provider=BrokenEpss()).run()
        assert report.records[0].epss_score is None
        assert any("EPSS unavailable" in warning for warning in report.warnings)

    def test_epss_without_a_provider_is_stated(self):
        report = _job(epss_provider=None).run()
        assert report.records[0].epss_score is None
        assert any("no EPSS provider" in warning for warning in report.warnings)


class TestIngestionSafety:
    def test_dry_run_writes_nothing(self):
        store = InMemoryVulnerabilityStore(allow_fixture=True)
        report = _job(
            ingestion_store=store,
            policy=IngestionPolicy(allow_fixture=True, dry_run=True),
        ).run()
        assert store.writes == 0
        # Dry run must still produce the payloads a reviewer inspects.
        assert report.ingestion is not None
        assert report.ingestion.payloads

    def test_no_store_is_stated_rather_than_silently_skipped(self):
        report = _job(ingestion_store=None).run()
        assert report.ingestion is None
        assert any("nothing was written" in warning for warning in report.warnings)

    def test_tenant_is_required(self):
        with pytest.raises(ValueError):
            CollectionJob(collectors={}, tenant_id="   ")

    def test_records_land_only_for_the_job_tenant(self):
        store = InMemoryVulnerabilityStore(allow_fixture=True)
        _job(ingestion_store=store, tenant_id="tenant-a").run()
        assert store.find(tenant_id="tenant-b", cve="CVE-2026-0001") is None
        assert store.find(tenant_id="tenant-a", cve="CVE-2026-0001") is not None


class TestCorrelationStage:
    def test_duplicate_records_across_sources_are_merged(self):
        report = _job(
            collectors={
                "nvd": lambda: [_record(sources=("nvd",))],
                "osv": lambda: [_record(sources=("osv",))],
            }
        ).run()
        assert len(report.records) == 1, "two reports of one CVE must collapse"
        assert any("merged across sources" in warning for warning in report.warnings)


class TestHealthAdapter:
    def test_source_result_maps_to_source_state(self):
        from datetime import datetime, timezone

        report = _job().run()
        state = source_state(report.sources[0], checked_at=datetime(2026, 11, 4, tzinfo=timezone.utc))
        assert state.records == 1
        assert state.checked_at.year == 2026
