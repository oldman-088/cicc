"""Tests for apps.threat_intelligence.observability — domain operational visibility."""

import pytest
from datetime import datetime, timedelta, timezone

from apps.threat_intelligence.collection_workers import (
    CircuitBreakerConfig,
    CollectionWorker,
    JobState,
)
from apps.threat_intelligence.conflict_resolution import ConflictResolutionService
from apps.threat_intelligence.observability import (
    MAX_EVENT_RETENTION,
    MAX_SNAPSHOT_HISTORY,
    RUNTIME_CALLER_INVOKED,
    DomainHealthSnapshot,
    DomainObservabilityEvent,
    ObservabilityError,
    SourceHealth,
    SourceHealthView,
    ThreatIntelObservabilityService,
)
from apps.threat_intelligence.relationship_analysis import RelationshipAnalysisService
from apps.threat_intelligence.source_reliability import (
    FreshnessPolicy,
    SourceReliabilityService,
    to_utc,
)

TENANT = "t-obs"
T0 = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)

POLICY = FreshnessPolicy(
    fresh_ttl_seconds=60, stale_after_seconds=3600, expired_after_seconds=86400
)


def _build(**kw):
    reliability = kw.pop("reliability", SourceReliabilityService(freshness_policy=POLICY))
    worker = kw.pop("worker", CollectionWorker(seed=7))
    conflicts = kw.pop("conflicts", ConflictResolutionService(tenant_id=TENANT))
    svc = ThreatIntelObservabilityService(
        tenant_id=TENANT,
        reliability_service=reliability,
        worker=worker,
        conflict_service=conflicts,
        **kw,
    )
    return svc, reliability, worker, conflicts


def _ok(reliability, source_id, when=T0, **kw):
    reliability.record_outcome(
        tenant_id=TENANT, source_id=source_id, success=True, now=when, **kw
    )


def _fail(reliability, source_id, when=T0, **kw):
    reliability.record_outcome(
        tenant_id=TENANT, source_id=source_id, success=False, now=when, note="fixture failure", **kw
    )


# ----------------------------------------------------------------- validation


def test_tenant_id_is_required():
    with pytest.raises(ObservabilityError):
        ThreatIntelObservabilityService(tenant_id="  ")


def test_source_health_requires_a_source_id():
    svc, _, _, _ = _build()
    with pytest.raises(ObservabilityError):
        svc.source_health("   ")


def test_event_kind_and_message_are_required():
    svc, _, _, _ = _build()
    with pytest.raises(ObservabilityError):
        svc.emit("  ", "message")
    with pytest.raises(ObservabilityError):
        svc.emit("kind", "   ")


def test_invalid_severity_is_rejected():
    svc, _, _, _ = _build()
    with pytest.raises(ObservabilityError):
        svc.emit("kind", "message", severity="critical")
    for severity in ("debug", "info", "warning", "error"):
        assert svc.emit("kind", "message", severity=severity).severity == severity


# ----------------------------------------------------------- source health


def test_unscored_source_is_never_reported_as_healthy():
    svc, _, _, _ = _build()
    view = svc.source_health("never-registered", now=T0)
    assert view.health is SourceHealth.UNSCORED
    assert view.reliability_score is None
    assert any("unscored" in n for n in view.notes)


def test_registered_but_never_collected_source():
    svc, reliability, _, _ = _build()
    reliability.register_source(tenant_id=TENANT, source_id="registered-only", now=T0)
    view = svc.source_health("registered-only", now=T0)
    assert view.health is SourceHealth.NEVER_COLLECTED
    assert view.freshness_state == "unknown"


def test_successful_source_is_healthy():
    svc, reliability, _, _ = _build()
    _ok(reliability, "urlhaus", records_ingested=12)
    view = svc.source_health("urlhaus", now=T0 + timedelta(minutes=1))
    assert view.health is SourceHealth.HEALTHY
    assert view.reliability_tier == "tier1_authoritative"
    assert view.total_successes == 1
    assert view.verification_mode == "fixture_tested"


def test_never_succeeded_source_is_failing():
    svc, reliability, _, _ = _build()
    _fail(reliability, "flaky")
    view = svc.source_health("flaky", now=T0)
    assert view.health is SourceHealth.FAILING
    assert view.total_successes == 0
    assert view.total_failures == 1
    assert any("never produced a successful collection" in n for n in view.notes)


def test_weak_reliability_tier_is_degraded():
    svc, reliability, _, _ = _build()
    _ok(reliability, "mixed", when=T0)
    for i in range(6):
        _fail(reliability, "mixed", when=T0 + timedelta(seconds=i + 1))
    view = svc.source_health("mixed", now=T0 + timedelta(minutes=1))
    assert view.reliability_tier in ("tier3_unproven", "tier4_unreliable")
    assert view.health is SourceHealth.DEGRADED


def test_open_circuit_outranks_every_other_condition():
    svc, reliability, worker, _ = _build(
        worker=CollectionWorker(breaker_config=CircuitBreakerConfig(failure_threshold=1), seed=7)
    )
    _fail(reliability, "down-source")
    worker.breaker_for("down-source").record_failure(T0)
    view = svc.source_health("down-source", now=T0)
    assert view.health is SourceHealth.CIRCUIT_OPEN
    assert view.circuit_state == "open"
    assert any("circuit breaker open" in n for n in view.notes)


def test_open_circuit_without_a_reliability_record_is_still_reported():
    svc, _, worker, _ = _build(
        worker=CollectionWorker(breaker_config=CircuitBreakerConfig(failure_threshold=1), seed=7)
    )
    worker.breaker_for("ghost").record_failure(T0)
    view = svc.source_health("ghost", now=T0)
    assert view.health is SourceHealth.CIRCUIT_OPEN
    assert any("no reliability record" in n for n in view.notes)


# -------------------------------------------------- freshness recomputation


def test_freshness_is_recomputed_against_the_query_clock():
    """
    Regression: reading `record.data_age_seconds` verbatim reported the age frozen at the last
    outcome, so a days-old source kept looking fresh forever.
    """
    svc, reliability, _, _ = _build()
    _ok(reliability, "aging", when=T0)
    assert svc.source_health("aging", now=T0 + timedelta(minutes=1)).health is SourceHealth.HEALTHY
    assert svc.source_health("aging", now=T0 + timedelta(minutes=1)).freshness_state == "fresh"

    aged = svc.source_health("aging", now=T0 + timedelta(minutes=30))
    assert aged.freshness_state == "aging"
    assert aged.health is SourceHealth.HEALTHY

    stale = svc.source_health("aging", now=T0 + timedelta(hours=5))
    assert stale.freshness_state == "stale"
    assert stale.health is SourceHealth.STALE
    assert stale.freshness_age_seconds == 18000

    expired = svc.source_health("aging", now=T0 + timedelta(days=2))
    assert expired.freshness_state == "expired"
    assert expired.health is SourceHealth.STALE


def test_stale_after_seconds_is_surfaced_for_the_ui():
    svc, reliability, _, _ = _build()
    _ok(reliability, "s")
    view = svc.source_health("s", now=T0)
    assert view.stale_after_seconds == POLICY.stale_after_seconds


def test_future_dated_last_success_is_unknown_not_fresh():
    svc, reliability, _, _ = _build()
    _ok(reliability, "clock-skew", when=T0 + timedelta(days=3))
    view = svc.source_health("clock-skew", now=T0)
    assert view.freshness_state == "unknown"
    assert view.freshness_age_seconds is None
    assert any("future-dated" in n for n in view.notes)


def test_naive_query_clock_is_accepted():
    """Regression: a naive `now` used to raise TypeError when compared with a Z-suffixed stamp."""
    svc, reliability, _, _ = _build()
    _ok(reliability, "s", when=T0)
    naive_view = svc.source_health("s", now=datetime(2026, 11, 5, 12, 1))
    aware_view = svc.source_health("s", now=T0 + timedelta(minutes=1))
    assert naive_view.freshness_age_seconds == aware_view.freshness_age_seconds == 60


def test_to_utc_treats_naive_as_utc_not_host_local():
    naive = datetime(2026, 11, 5, 12, 0)
    aware = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)
    assert to_utc(naive) == aware
    assert to_utc(aware) == aware
    shifted = datetime(2026, 11, 5, 14, 0, tzinfo=timezone(timedelta(hours=2)))
    assert to_utc(shifted) == aware


# -------------------------------------------------------------- aggregation


def test_all_source_health_covers_reliability_worker_and_breakers():
    svc, reliability, worker, _ = _build()
    _ok(reliability, "from-reliability")
    worker.breaker_for("from-breaker").record_success()
    views = svc.all_source_health(now=T0)
    ids = {v.source_id for v in views}
    assert "from-reliability" in ids
    assert "from-breaker" in ids
    assert [v.source_id for v in views] == sorted(ids)


def test_all_source_health_is_empty_when_nothing_is_known():
    svc, _, _, _ = _build()
    assert svc.all_source_health(now=T0) == []


def test_snapshot_aggregates_health_tiers_and_verification():
    svc, reliability, _, _ = _build()
    _ok(reliability, "good", when=T0)
    _fail(reliability, "bad")
    snap = svc.snapshot(now=T0)
    assert isinstance(snap, DomainHealthSnapshot)
    assert snap.tenant_id == TENANT
    assert snap.source_count == 2
    assert snap.sources_by_health.get("healthy") == 1
    assert snap.sources_by_health.get("failing") == 1
    assert snap.sources_by_tier.get("tier1_authoritative") == 1
    assert set(snap.degraded_sources) == {"bad"}
    assert snap.verification_modes == {"fixture_tested": 2}


def test_snapshot_declares_no_running_worker_and_no_live_source():
    svc, reliability, _, _ = _build()
    _ok(reliability, "good")
    snap = svc.snapshot(now=T0)
    assert snap.runtime_status == RUNTIME_CALLER_INVOKED
    assert any("no worker process or event loop is running" in c for c in snap.caveats)
    assert any("no metrics backend is connected" in c for c in snap.caveats)
    assert any("no source is live_verified" in c for c in snap.caveats)
    assert snap.experimental_label == "EXPERIMENTAL_DEMO_DATA_ONLY"
    assert snap.collection["note"] == "snapshot only - no worker process is running"


def test_snapshot_carries_worker_state_counts():
    svc, _, worker, _ = _build()
    worker.enqueue(tenant_id=TENANT, source_id="s1", kind="full_sync", now=T0)
    snap = svc.snapshot(now=T0)
    assert snap.collection["total_jobs"] == 1
    assert snap.collection["state_counts"][JobState.PENDING.value] == 1


def test_snapshot_includes_conflict_counts():
    svc, _, _, conflicts = _build()
    conflicts.record_claim("e", "f", "x", "s1", observed_at=T0, confidence=0.9, now=T0)
    conflicts.record_claim("e", "f", "y", "s2", observed_at=T0, confidence=0.1, now=T0)
    snap = svc.snapshot(now=T0)
    assert snap.conflicts["claim_count"] == 2
    assert snap.conflicts["open_conflict_count"] == 0


def test_snapshot_includes_relationship_health_when_wired():
    relationships = RelationshipAnalysisService(tenant_id=TENANT)
    relationships.assert_relationship("a", "b", "USES", "s1", provenance="x", now=T0)
    svc, _, _, _ = _build(relationship_service=relationships)
    snap = svc.snapshot(now=T0)
    assert snap.relationships["assertion_count"] == 1
    assert snap.relationships["tenant_id"] == TENANT


def test_snapshot_relationships_absent_when_not_wired():
    svc, _, _, _ = _build()
    assert svc.snapshot(now=T0).relationships == {}


def test_snapshot_history_is_capped():
    svc, _, _, _ = _build()
    for _ in range(5):
        svc.snapshot(now=T0)
    assert len(svc.snapshot_history()) == 5
    assert len(svc.snapshot_history(limit=2)) == 2
    assert MAX_SNAPSHOT_HISTORY >= 5


def test_snapshot_can_skip_retention():
    svc, _, _, _ = _build()
    svc.snapshot(now=T0, retain=False)
    assert svc.snapshot_history() == []


# ------------------------------------------------------------------- events


def test_events_are_bounded_and_filterable():
    svc, _, _, _ = _build()
    for i in range(10):
        svc.emit("collection_failed", f"attempt {i}", severity="warning", source_id="s1", now=T0)
    svc.emit("collection_ok", "recovered", severity="info", source_id="s1", now=T0)
    assert svc.event_count() == 11
    assert len(svc.events(severity="warning")) == 10
    assert len(svc.events(kind="collection_ok")) == 1
    assert len(svc.events(source_id="s1")) == 11
    assert len(svc.events(limit=3)) == 3


def test_event_retention_drops_the_oldest():
    svc, _, _, _ = _build()
    for i in range(MAX_EVENT_RETENTION + 50):
        svc.emit("flood", f"event {i}", now=T0)
    assert svc.event_count() == MAX_EVENT_RETENTION
    remaining = svc.events(limit=MAX_EVENT_RETENTION)
    assert remaining[0].message == "event 50"
    assert remaining[-1].message == f"event {MAX_EVENT_RETENTION + 49}"


def test_event_message_is_truncated():
    svc, _, _, _ = _build()
    event = svc.emit("kind", "x" * 5000)
    assert len(event.message) == 1000


# ---------------------------------------------------------------- ingestion


def test_ingestion_report_reports_zeros_rather_than_inventing_numbers():
    svc, _, _, _ = _build()
    report = svc.ingestion_report()
    assert report["counters"]["jobs_created"] == 0
    assert report["succeeded"] == 0
    assert report["failed"] == 0
    assert "in-memory" in report["note"]


def test_ingestion_report_reflects_real_worker_counters():
    svc, _, worker, _ = _build()
    worker.enqueue(tenant_id=TENANT, source_id="s1", kind="full_sync", now=T0)
    worker.run_pending(lambda job: {"records": 3}, now=T0, max_jobs=1)
    report = svc.ingestion_report()
    assert report["counters"]["jobs_created"] == 1
    assert report["counters"]["attempts_succeeded"] == 1
    assert report["by_source"].get("s1") is not None


def test_ingestion_report_filters_by_source():
    svc, _, worker, _ = _build()
    worker.enqueue(tenant_id=TENANT, source_id="s1", kind="full_sync", now=T0)
    worker.enqueue(tenant_id=TENANT, source_id="s2", kind="full_sync", now=T0)
    worker.run_pending(lambda job: {}, now=T0, max_jobs=5)
    filtered = svc.ingestion_report(source_id="s1")
    assert list(filtered["by_source"]) == ["s1"]
    assert len(svc.ingestion_report()["by_source"]) == 2


# ------------------------------------------------------------ agent 1 bridge


def test_heartbeat_details_stay_proposed_and_secret_free():
    svc, reliability, _, _ = _build()
    _ok(reliability, "good")
    details = svc.to_agent1_heartbeat_details(now=T0)
    assert details.startswith("ti_domain sources=1")
    assert "live_verified=0" in details
    assert RUNTIME_CALLER_INVOKED in details
    assert "runtime=" in details


def test_agent1_payload_marks_the_contract_proposed():
    svc, reliability, worker, _ = _build()
    _ok(reliability, "good")
    worker.enqueue(tenant_id=TENANT, source_id="good", kind="full_sync", now=T0)
    payload = svc.to_agent1_payload(now=T0)
    assert payload["status"] == "online"
    assert payload["meta"]["contract_status"] == "proposed_not_accepted"
    assert payload["meta"]["domain"] == "threat_intelligence"
    assert payload["meta"]["runtime_status"] == RUNTIME_CALLER_INVOKED
    assert payload["active_tasks"] == 0  # pending, not yet running


def test_agent1_payload_counts_running_tasks():
    svc, _, worker, _ = _build()
    worker.enqueue(tenant_id=TENANT, source_id="s1", kind="full_sync", now=T0)
    job_id = worker.list_jobs()[0].job_id
    worker.claim(job_id, now=T0)
    payload = svc.to_agent1_payload(now=T0)
    assert payload["active_tasks"] == 1


def test_heartbeat_bridge_does_not_claim_live_verification():
    svc, reliability, _, _ = _build()
    _ok(reliability, "good")
    payload = svc.to_agent1_payload(now=T0)
    assert payload["meta"]["verification_modes"] == {"fixture_tested": 1}
    assert "live_verified" not in payload["meta"]["verification_modes"]
