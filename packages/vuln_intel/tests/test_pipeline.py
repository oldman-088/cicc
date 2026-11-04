"""Pipeline behaviour: evidence before derivation, honest failure accounting."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vuln_intel.circuit import BreakerState, CircuitBreaker, CircuitOpen
from vuln_intel.errors import SourceResponseError, SourceUnavailable
from vuln_intel.integration.observations import (
    ImmutableObservationLog,
    digest_payload,
    to_observations,
)
from vuln_intel.kev import KevConnector
from vuln_intel.pipeline import EnrichmentPipeline
from vuln_intel.priorities import PriorityContext
from vuln_intel.ratelimit import RateGate
from vuln_intel.retry import RetryPolicy
from vuln_intel.schema import (
    CollectionStatus,
    CveId,
    CvssScore,
    NormalizedVulnerability,
    Origin,
    ProvenanceRecord,
    Severity,
)

from . import fixtures as fx
from .conftest import FakeTransport, no_wait, response

RUN_AT = datetime(2026, 1, 10, tzinfo=timezone.utc)


def record(cve="CVE-2026-0001", *, origin=Origin.LIVE, sources=("nvd",), **kwargs):
    base = dict(
        cve=CveId.parse(cve),
        origin=origin,
        sources=sources,
        severity=Severity.CRITICAL,
        cvss=(CvssScore("3.1", 9.8, Severity.CRITICAL, vector="v", source="nvd"),),
        modified=RUN_AT - timedelta(days=1),
        provenance=(ProvenanceRecord(source=sources[0], source_ref="ref-1", fetched_at=RUN_AT),),
    )
    base.update(kwargs)
    return NormalizedVulnerability(**base)


def catalog():
    return KevConnector(
        transport=FakeTransport([response(fx.KEV_CATALOG)]),
        gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
        retry=RetryPolicy(attempts=1),
        sleep=no_wait,
    ).fetch()


# -- observations ------------------------------------------------------------
def test_observations_split_a_merged_record_per_source() -> None:
    merged = record(sources=("nvd", "osv"))
    observations = to_observations(merged, tenant_id="t1", collected_at=RUN_AT)
    assert [o.source for o in observations] == ["nvd", "osv"]
    assert all(o.cve == "CVE-2026-0001" for o in observations)
    # Source-scoped payload: only OSV carries affected ranges.
    by_source = {o.source: o.payload for o in observations}
    assert by_source["nvd"]["affected"] == []
    assert "cvss" in by_source["nvd"]


def test_digest_is_stable_and_content_addressed() -> None:
    a = {"cve": "CVE-2026-0001", "score": 9.8}
    b = {"score": 9.8, "cve": "CVE-2026-0001"}  # different key order
    assert digest_payload(a) == digest_payload(b)
    assert digest_payload({**a, "score": 7.5}) != digest_payload(a)


def test_log_is_idempotent() -> None:
    log = ImmutableObservationLog(allow_fixture=False)
    observations = to_observations(record(), tenant_id="t1", collected_at=RUN_AT)
    assert log.append(observations[0]).outcome == "appended"
    assert log.append(observations[0]).outcome == "duplicate"
    assert log.size == 1


def test_log_is_append_only_on_change() -> None:
    log = ImmutableObservationLog(allow_fixture=False)
    first = to_observations(record(), tenant_id="t1", collected_at=RUN_AT)
    later = to_observations(
        record(severity=Severity.HIGH), tenant_id="t1", collected_at=RUN_AT + timedelta(hours=1)
    )
    log.append(first[0])
    log.append(later[0])
    rows = log.list_for(tenant_id="t1", cve="CVE-2026-0001")
    assert len(rows) == 2  # history preserved, nothing overwritten
    assert rows[0].collected_at <= rows[1].collected_at


def test_log_refuses_fixture_observations_by_default() -> None:
    log = ImmutableObservationLog(allow_fixture=False)
    observations = to_observations(
        record(origin=Origin.FIXTURE), tenant_id="t1", collected_at=RUN_AT
    )
    result = log.append(observations[0])
    assert result.outcome == "refused"
    assert log.size == 0
    assert log.refused


def test_log_tenants_are_isolated() -> None:
    log = ImmutableObservationLog(allow_fixture=False)
    a = to_observations(record(), tenant_id="t1", collected_at=RUN_AT)
    b = to_observations(record(), tenant_id="t2", collected_at=RUN_AT)
    log.append(a[0])
    log.append(b[0])
    assert len(log.list_for(tenant_id="t1", cve="CVE-2026-0001")) == 1
    assert len(log.list_for(tenant_id="t3", cve="CVE-2026-0001")) == 0


# -- pipeline ----------------------------------------------------------------
def test_pipeline_merges_orders_and_keeps_evidence() -> None:
    log = ImmutableObservationLog(allow_fixture=False)
    pipeline = EnrichmentPipeline(log=log, kev_catalog=catalog(), now=lambda: RUN_AT)
    report = pipeline.run(
        {
            "nvd": lambda: [record()],
            "osv": lambda: [record(sources=("osv",))],
        },
        tenant_id="t1",
        context=PriorityContext(exposure=0.5),
    )
    assert report.complete is True
    assert report.origin == "live"
    assert len(report.records) == 1
    merged = report.records[0]
    # KEV is a consulted source for this run, so it joins the source list.
    assert merged.sources == ("cisa-kev", "nvd", "osv")
    assert report.observations_appended == 2  # one per contributing source
    assert report.kev_consulted is True
    assert report.ranking and report.ranking[0].cve == merged.cve


def test_pipeline_reports_a_failed_source_without_losing_the_others() -> None:
    def broken():
        raise SourceResponseError("upstream 503", status=503, source="nvd")

    pipeline = EnrichmentPipeline(kev_catalog=catalog(), now=lambda: RUN_AT)
    report = pipeline.run({"nvd": broken, "osv": lambda: [record(sources=("osv",))]}, tenant_id="t1")
    statuses = {o.source: o.status for o in report.outcomes}
    assert statuses["nvd"] is CollectionStatus.FAILED
    assert statuses["osv"] is CollectionStatus.OK
    assert report.complete is False  # partial data is never presented as complete
    assert any("nvd failed" in w for w in report.warnings)


def test_pipeline_distinguishes_empty_from_failed() -> None:
    pipeline = EnrichmentPipeline(now=lambda: RUN_AT)
    report = pipeline.run({"nvd": lambda: []}, tenant_id="t1")
    assert report.outcomes[0].status is CollectionStatus.OK
    assert any("empty answer, not a failure" in w for w in report.warnings)


def test_pipeline_refuses_mixed_origin_input() -> None:
    pipeline = EnrichmentPipeline(now=lambda: RUN_AT)
    report = pipeline.run(
        {
            "nvd": lambda: [record()],
            "osv": lambda: [record("CVE-2026-0002", origin=Origin.DEMO, sources=("osv",))],
        },
        tenant_id="t1",
    )
    assert report.records == []
    assert report.complete is False
    assert any("mixed origins" in w for w in report.warnings)


def test_pipeline_leaves_kev_unknown_when_catalogue_absent() -> None:
    pipeline = EnrichmentPipeline(now=lambda: RUN_AT)
    report = pipeline.run({"nvd": lambda: [record()]}, tenant_id="t1")
    assert report.kev_consulted is False
    assert report.records[0].kev is None
    assert any("left unknown" in w for w in report.warnings)


def test_pipeline_marks_kev_membership_from_the_catalogue() -> None:
    pipeline = EnrichmentPipeline(kev_catalog=catalog(), now=lambda: RUN_AT)
    report = pipeline.run(
        {"nvd": lambda: [record("CVE-2026-0001"), record("CVE-2026-0004")]}, tenant_id="t1"
    )
    by_cve = {str(r.cve): r for r in report.records}
    assert by_cve["CVE-2026-0001"].kev is True
    assert by_cve["CVE-2026-0004"].kev is False  # consulted, genuinely absent


def test_pipeline_flags_a_stale_kev_catalogue() -> None:
    pipeline = EnrichmentPipeline(kev_catalog=catalog(), kev_stale=True, now=lambda: RUN_AT)
    report = pipeline.run({"nvd": lambda: [record()]}, tenant_id="t1")
    assert any("stale" in w for w in report.warnings)


def test_pipeline_epss_unavailable_is_not_zero() -> None:
    class Broken:
        def fetch(self, cves):
            raise SourceUnavailable("first.org unreachable")

    pipeline = EnrichmentPipeline(epss_provider=Broken(), now=lambda: RUN_AT)
    report = pipeline.run({"nvd": lambda: [record()]}, tenant_id="t1")
    assert report.epss_available is False
    assert report.records[0].epss_score is None
    assert any("not zero" in w for w in report.warnings)


def test_pipeline_refuses_fixture_epss_on_live_records() -> None:
    from vuln_intel.connectors.epss import FixtureEpssProvider

    pipeline = EnrichmentPipeline(
        epss_provider=FixtureEpssProvider(scores={"CVE-2026-0001": (0.9, 0.99, "2026-01-01")}),
        now=lambda: RUN_AT,
    )
    with pytest.raises(Exception):
        pipeline.run({"nvd": lambda: [record()]}, tenant_id="t1")


def test_pipeline_report_is_json_shaped_and_states_provenance() -> None:
    pipeline = EnrichmentPipeline(kev_catalog=catalog(), now=lambda: RUN_AT)
    payload = pipeline.run({"nvd": lambda: [record()]}, tenant_id="t1").as_dict()
    assert payload["complete"] is True
    assert "append-only source observations" in payload["notice"]
    assert payload["sources"][0]["status"] == "ok"


def test_pipeline_survives_a_collector_that_raises_a_bug() -> None:
    def buggy():
        raise KeyError("nvd")

    pipeline = EnrichmentPipeline(now=lambda: RUN_AT)
    report = pipeline.run({"nvd": buggy, "osv": lambda: [record(sources=("osv",))]}, tenant_id="t1")
    assert report.outcomes[0].status is CollectionStatus.FAILED
    assert "KeyError" in (report.outcomes[0].error or "")
    assert len(report.records) == 1


# -- circuit breaker ---------------------------------------------------------
class Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


def test_breaker_opens_after_threshold_and_fails_fast() -> None:
    clock = Clock()
    breaker = CircuitBreaker(source="nvd", failure_threshold=3, cooldown=10.0, clock=clock)

    def fail():
        raise SourceUnavailable("down")

    for _ in range(3):
        with pytest.raises(SourceUnavailable):
            breaker.call(fail)
    assert breaker.state == BreakerState.OPEN
    with pytest.raises(CircuitOpen):
        breaker.call(lambda: [])
    assert breaker.retry_in() == pytest.approx(10.0)


def test_breaker_half_opens_then_closes_on_success() -> None:
    clock = Clock()
    breaker = CircuitBreaker(source="nvd", failure_threshold=1, cooldown=5.0, clock=clock)
    with pytest.raises(SourceUnavailable):
        breaker.call(lambda: (_ for _ in ()).throw(SourceUnavailable("down")))
    assert breaker.state == BreakerState.OPEN

    clock.value = 6.0
    assert breaker.allow() is True
    assert breaker.state == BreakerState.HALF_OPEN
    assert breaker.call(lambda: "ok") == "ok"
    assert breaker.state == BreakerState.CLOSED


def test_failed_probe_backs_off_further() -> None:
    clock = Clock()
    breaker = CircuitBreaker(source="nvd", failure_threshold=1, cooldown=5.0, clock=clock)
    with pytest.raises(SourceUnavailable):
        breaker.call(lambda: (_ for _ in ()).throw(SourceUnavailable("down")))
    clock.value = 6.0
    breaker.allow()
    with pytest.raises(SourceUnavailable):
        breaker.call(lambda: (_ for _ in ()).throw(SourceUnavailable("still down")))
    assert breaker.state == BreakerState.OPEN
    assert breaker.retry_in() > 5.0  # backed off


def test_breaker_does_not_hide_programming_errors() -> None:
    breaker = CircuitBreaker(source="nvd", failure_threshold=1)
    with pytest.raises(KeyError):
        breaker.call(lambda: (_ for _ in ()).throw(KeyError("bug")))
    assert breaker.state == BreakerState.CLOSED  # not a source failure
