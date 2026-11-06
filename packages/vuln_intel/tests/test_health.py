"""Health, readiness and metrics.

A health endpoint that lies is worse than none: it tells an operator to stop
looking.  These tests pin the three states apart and prove the report is derived
from recorded evidence rather than optimism.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vuln_intel.health import (
    ComponentHealth,
    Metrics,
    Readiness,
    build_health_report,
)
from vuln_intel.schema import CollectionStatus, SourceKind, SourceState

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def state(
    kind: SourceKind = SourceKind.NVD,
    status: CollectionStatus = CollectionStatus.OK,
    *,
    last_success: datetime | None = NOW,
    error: str | None = None,
) -> SourceState:
    return SourceState(
        kind=kind,
        status=status,
        checked_at=NOW,
        last_success=last_success,
        error=error,
    )


class TestReadiness:
    def test_fresh_collection_from_required_sources_is_ready(self):
        report = build_health_report(
            [state(SourceKind.NVD), state(SourceKind.OSV)],
            kev_age=timedelta(hours=2),
            now=NOW,
        )
        assert report.readiness is Readiness.READY
        assert report.http_status == 200

    def test_failure_with_previous_data_degrades_not_fails(self):
        report = build_health_report(
            [state(SourceKind.NVD, CollectionStatus.FAILED, last_success=NOW - timedelta(days=1))],
            kev_age=timedelta(hours=2),
            now=NOW,
        )
        assert report.readiness is Readiness.DEGRADED
        nvd = next(s for s in report.sources if s.kind == "nvd")
        assert nvd.health is ComponentHealth.DEGRADED
        assert "previously collected" in nvd.detail

    def test_failure_with_no_previous_data_is_not_ready(self):
        report = build_health_report(
            [state(SourceKind.NVD, CollectionStatus.FAILED, last_success=None, error="no transport")],
            kev_age=timedelta(hours=2),
            now=NOW,
        )
        assert report.readiness is Readiness.NOT_READY
        assert report.http_status == 503

    def test_not_configured_is_never_reported_as_healthy(self):
        report = build_health_report(
            [state(SourceKind.NVD, CollectionStatus.NOT_CONFIGURED, last_success=None)],
            kev_age=timedelta(hours=2),
            now=NOW,
        )
        nvd = next(s for s in report.sources if s.kind == "nvd")
        assert nvd.health is ComponentHealth.NOT_CONFIGURED
        assert nvd.health is not ComponentHealth.OK

    def test_stale_success_degrades(self):
        report = build_health_report(
            [state(SourceKind.NVD, CollectionStatus.OK, last_success=NOW - timedelta(days=30))],
            kev_age=timedelta(hours=2),
            now=NOW,
        )
        nvd = next(s for s in report.sources if s.kind == "nvd")
        assert nvd.health is ComponentHealth.DEGRADED
        assert "stale" in nvd.detail

    def test_partial_collection_degrades(self):
        report = build_health_report(
            [state(SourceKind.OSV, CollectionStatus.PARTIAL, error="3 records failed")],
            kev_age=timedelta(hours=2),
            now=NOW,
        )
        osv = next(s for s in report.sources if s.kind == "osv")
        assert osv.health is ComponentHealth.DEGRADED
        assert "partial" in osv.detail

    def test_epss_unavailable_is_stated_not_zeroed(self):
        report = build_health_report(
            [state(SourceKind.NVD)], kev_age=timedelta(hours=2), now=NOW
        )
        assert any("EPSS" in warning for warning in report.warnings)
        assert any("not assumed zero" in warning for warning in report.warnings)

    def test_stale_kev_cache_is_visible(self):
        report = build_health_report(
            [state(SourceKind.NVD)], kev_age=timedelta(days=30), now=NOW
        )
        kev = next(s for s in report.sources if s.kind == "cisa-kev")
        assert kev.health is ComponentHealth.DEGRADED
        assert "stale" in kev.detail

    def test_report_is_json_safe(self):
        import json

        report = build_health_report(
            [state(SourceKind.NVD)], kev_age=timedelta(hours=2), now=NOW
        )
        assert json.loads(json.dumps(report.as_dict()))["readiness"] == "ready"

    def test_no_sources_at_all_is_not_ready(self):
        report = build_health_report([], now=NOW)
        assert report.readiness is Readiness.NOT_READY


class TestMetrics:
    def test_collection_counters_and_gauges(self):
        metrics = Metrics()
        metrics.record_collection(state(SourceKind.NVD))
        payload = metrics.as_dict()
        assert payload["counters"]["collect.nvd.attempt"] == 1
        assert payload["counters"]["collect.nvd.ok"] == 1
        assert payload["gauges"]["collect.nvd.last_success_epoch"] == NOW.timestamp()

    def test_failed_collection_is_counted_separately(self):
        metrics = Metrics()
        metrics.record_collection(
            state(SourceKind.OSV, CollectionStatus.FAILED, last_success=None, error="down")
        )
        payload = metrics.as_dict()
        assert payload["counters"]["collect.osv.failed"] == 1
        assert "collect.osv.last_success_epoch" not in payload["gauges"]

    def test_counters_accumulate(self):
        metrics = Metrics()
        for _ in range(3):
            metrics.increment("foo")
        assert metrics.counters["foo"] == 3

    @pytest.mark.parametrize("value", [0.5, 1.0, 0.0])
    def test_gauges_store_floats(self, value):
        metrics = Metrics()
        metrics.gauge("x", value)
        assert isinstance(metrics.gauges["x"], float)
