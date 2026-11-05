"""
Unit tests for the Threat Intelligence background collection architecture.

Time is injected everywhere, so no test sleeps. Nothing in these tests proves a
worker process is running -- `run_pending` executes synchronously when called,
and `test_no_background_thread_is_started` asserts exactly that.
"""

import threading
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from apps.threat_intelligence.collection_workers import (
    DEFAULT_MAX_ATTEMPTS,
    EXPERIMENTAL_DEMO_DATA_ONLY,
    TERMINAL_STATES,
    CircuitBreakerConfig,
    CollectionJob,
    CollectionWorker,
    CollectionWorkerError,
    JobNotLeasableError,
    JobState,
    LeaseConflictError,
    RetryPolicy,
    SourceCircuitBreaker,
    UnknownJobError,
    derive_idempotency_key,
    utcnow,
)

T0 = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)


def always_fail(job):
    raise RuntimeError("feed unreachable")


def always_ok(job):
    return {"records": 7, "source": job.source_id}


def returns_bad_type(job):
    return "not a dict"


@pytest.fixture
def worker():
    return CollectionWorker(
        retry_policy=RetryPolicy(max_attempts=3, base_delay_seconds=30, jitter_ratio=0.0),
        breaker_config=CircuitBreakerConfig(failure_threshold=5, cooldown_seconds=60),
        seed=42,
    )


class TestRetryPolicy:
    def test_exponential_backoff_without_jitter(self):
        policy = RetryPolicy(max_attempts=5, base_delay_seconds=30,
                             backoff_multiplier=2.0, jitter_ratio=0.0,
                             max_delay_seconds=3600)
        assert [policy.delay_for_attempt(n) for n in (1, 2, 3, 4)] == [30.0, 60.0, 120.0, 240.0]

    def test_backoff_is_capped_at_max_delay(self):
        policy = RetryPolicy(base_delay_seconds=1000, backoff_multiplier=10.0,
                             jitter_ratio=0.0, max_delay_seconds=3600)
        assert policy.delay_for_attempt(5) == 3600.0

    def test_jitter_stays_within_bounds(self):
        policy = RetryPolicy(base_delay_seconds=100, jitter_ratio=0.2,
                             backoff_multiplier=1.0, max_delay_seconds=3600)
        import random
        rng = random.Random(7)
        for _ in range(200):
            delay = policy.delay_for_attempt(1, rng=rng)
            assert 80.0 <= delay <= 120.0

    def test_max_delay_must_not_be_below_base(self):
        with pytest.raises(ValidationError):
            RetryPolicy(base_delay_seconds=100, max_delay_seconds=10)

    def test_attempt_must_be_positive(self):
        with pytest.raises(ValueError):
            RetryPolicy().delay_for_attempt(0)

    def test_defaults_are_bounded(self):
        policy = RetryPolicy()
        assert policy.max_attempts == DEFAULT_MAX_ATTEMPTS
        assert 1 <= policy.max_attempts <= 100
        with pytest.raises(ValidationError):
            RetryPolicy(max_attempts=0)
        with pytest.raises(ValidationError):
            RetryPolicy(jitter_ratio=1.5)
        with pytest.raises(ValidationError):
            RetryPolicy(ttl_seconds=0)


class TestEnqueueAndIdempotency:
    def test_enqueue_sets_pending_state_and_ttl(self, worker):
        job = worker.enqueue(tenant_id="t1", source_id="src-a", kind="osint_sync", now=T0)
        assert job.state is JobState.PENDING
        assert job.attempts == 0
        assert job.expires_at is not None
        assert job.verification_mode == "fixture_tested"
        assert job.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_duplicate_idempotency_key_is_suppressed_not_duplicated(self, worker):
        a = worker.enqueue(tenant_id="t1", source_id="src-a", kind="osint_sync",
                           idempotency_key="key-1", now=T0)
        b = worker.enqueue(tenant_id="t1", source_id="src-a", kind="osint_sync",
                           idempotency_key="key-1", now=T0)
        assert a.job_id == b.job_id
        assert worker.metrics.idempotent_duplicates_suppressed == 1
        assert len(worker.list_jobs()) == 1

    def test_idempotency_key_is_scoped_per_tenant(self, worker):
        a = worker.enqueue(tenant_id="t1", source_id="s", kind="k", idempotency_key="same", now=T0)
        b = worker.enqueue(tenant_id="t2", source_id="s", kind="k", idempotency_key="same", now=T0)
        assert a.job_id != b.job_id

    def test_derived_idempotency_key_is_stable_and_payload_sensitive(self):
        k1 = derive_idempotency_key("t1", "s", "k", {"a": 1, "b": 2})
        k2 = derive_idempotency_key("t1", "s", "k", {"b": 2, "a": 1})
        k3 = derive_idempotency_key("t1", "s", "k", {"a": 1, "b": 3})
        assert k1 == k2, "key ordering must not matter"
        assert k1 != k3

    def test_kind_rejects_whitespace(self, worker):
        with pytest.raises(ValidationError):
            worker.enqueue(tenant_id="t1", source_id="s", kind="osint sync", now=T0)

    def test_unknown_job_lookup_raises(self, worker):
        with pytest.raises(UnknownJobError):
            worker.get_job("nope")


class TestLifecycle:
    def test_success_is_terminal(self, worker):
        job = worker.enqueue(tenant_id="t1", source_id="src-a", kind="k", now=T0)
        out = worker.execute(job.job_id, always_ok, now=T0)
        assert out.state is JobState.SUCCEEDED
        assert out.is_terminal
        assert out.result_summary == {"records": 7, "source": "src-a"}
        assert out.lease_owner is None
        assert worker.metrics.attempts_succeeded == 1

    def test_retry_then_eventual_success(self, worker):
        job = worker.enqueue(tenant_id="t1", source_id="src-a", kind="k", now=T0)
        state = {"n": 0}

        def flaky(j):
            state["n"] += 1
            if state["n"] < 2:
                raise RuntimeError("transient")
            return {"records": 1}

        worker.execute(job.job_id, flaky, now=T0)
        assert worker.get_job(job.job_id).state is JobState.RETRY_SCHEDULED
        out = worker.execute(job.job_id, flaky, now=T0 + timedelta(seconds=30))
        assert out.state is JobState.SUCCEEDED
        assert out.attempts == 2

    def test_attempts_exhaustion_is_terminal_failure(self, worker):
        job = worker.enqueue(tenant_id="t1", source_id="src-a", kind="k", now=T0)
        t = T0
        for _ in range(3):
            out = worker.execute(job.job_id, always_fail, now=t)
            t += timedelta(seconds=120)
        assert out.state is JobState.FAILED
        assert out.is_terminal
        assert out.attempts == 3
        assert worker.metrics.jobs_failed_terminal == 1

    def test_handler_returning_non_dict_counts_as_failure(self, worker):
        job = worker.enqueue(tenant_id="t1", source_id="src-a", kind="k", now=T0)
        out = worker.execute(job.job_id, returns_bad_type, now=T0)
        assert out.state is JobState.RETRY_SCHEDULED
        assert "must return a dict" in out.last_error

    def test_terminal_job_cannot_be_re_executed(self, worker):
        job = worker.enqueue(tenant_id="t1", source_id="src-a", kind="k", now=T0)
        worker.execute(job.job_id, always_ok, now=T0)
        with pytest.raises(JobNotLeasableError):
            worker.execute(job.job_id, always_ok, now=T0)

    def test_job_not_due_cannot_be_claimed_early(self, worker):
        job = worker.enqueue(tenant_id="t1", source_id="src-a", kind="k", now=T0)
        worker.execute(job.job_id, always_fail, now=T0)
        with pytest.raises(JobNotLeasableError):
            worker.claim(job.job_id, now=T0 + timedelta(seconds=1))

    def test_error_detail_is_truncated_and_single_line(self, worker):
        job = worker.enqueue(tenant_id="t1", source_id="src-a", kind="k", now=T0)

        def multiline(job):
            raise RuntimeError("line1\nline2\rline3 " + "x" * 900)

        out = worker.execute(job.job_id, multiline, now=T0)
        assert "\n" not in out.last_error
        assert "\r" not in out.last_error
        assert len(out.last_error) <= 500


class TestLeases:
    def test_lease_conflict_between_workers(self, worker):
        job = worker.enqueue(tenant_id="t1", source_id="src-a", kind="k", now=T0)
        worker.claim(job.job_id, owner="worker-A", now=T0)
        with pytest.raises(LeaseConflictError):
            worker.claim(job.job_id, owner="worker-B", now=T0)

    def test_same_owner_may_reclaim_its_own_lease(self, worker):
        job = worker.enqueue(tenant_id="t1", source_id="src-a", kind="k", now=T0)
        worker.claim(job.job_id, owner="worker-A", now=T0)
        reclaimed = worker.claim(job.job_id, owner="worker-A", now=T0)
        assert reclaimed.lease_owner == "worker-A"

    def test_expired_lease_is_reclaimed_by_another_worker(self, worker):
        job = worker.enqueue(tenant_id="t1", source_id="src-a", kind="k", now=T0)
        worker.claim(job.job_id, owner="worker-A", now=T0)
        later = T0 + timedelta(seconds=worker.retry_policy.lease_seconds + 1)
        reclaimed = worker.claim(job.job_id, owner="worker-B", now=later)
        assert reclaimed.lease_owner == "worker-B"
        assert worker.metrics.leases_expired_reclaimed == 1
        assert worker.events(event_type="lease_expired")

    def test_run_pending_only_takes_due_jobs(self, worker):
        worker.enqueue(tenant_id="t1", source_id="src-a", kind="k", job_id="j-now", now=T0)
        worker.enqueue(tenant_id="t1", source_id="src-a", kind="k", job_id="j-later", now=T0)
        # Force j-later into the future.
        later = worker.get_job("j-later")
        later.state = JobState.RETRY_SCHEDULED
        later.next_attempt_at = (T0 + timedelta(hours=1)).isoformat()

        executed = worker.run_pending(always_ok, now=T0)
        assert [j.job_id for j in executed] == ["j-now"]

    def test_max_jobs_bounds_a_single_run(self, worker):
        for i in range(5):
            worker.enqueue(tenant_id="t1", source_id="src-a", kind="k", job_id=f"j{i}", now=T0)
        executed = worker.run_pending(always_ok, now=T0, max_jobs=2)
        assert len(executed) == 2


class TestCircuitBreaker:
    def test_breaker_opens_after_threshold_and_blocks_claims(self):
        worker = CollectionWorker(
            retry_policy=RetryPolicy(max_attempts=10, base_delay_seconds=1, jitter_ratio=0.0),
            breaker_config=CircuitBreakerConfig(failure_threshold=2, cooldown_seconds=60),
            seed=1,
        )
        job = worker.enqueue(tenant_id="t1", source_id="src-a", kind="k", now=T0)
        t = T0
        for _ in range(2):
            worker.execute(job.job_id, always_fail, now=t)
            t += timedelta(seconds=5)

        assert worker.breaker_for("src-a").state == "open"
        assert worker.metrics.breaker_open_events == 1

        other = worker.enqueue(tenant_id="t1", source_id="src-a", kind="k",
                               job_id="blocked", now=t)
        with pytest.raises(JobNotLeasableError):
            worker.execute(other.job_id, always_ok, now=t)
        assert worker.get_job("blocked").state is JobState.ABANDONED
        assert worker.metrics.breaker_open_rejections == 1

    def test_breaker_closes_after_cooldown_and_successful_probe(self):
        worker = CollectionWorker(
            retry_policy=RetryPolicy(max_attempts=10, base_delay_seconds=1, jitter_ratio=0.0),
            breaker_config=CircuitBreakerConfig(failure_threshold=1, cooldown_seconds=60),
            seed=1,
        )
        job = worker.enqueue(tenant_id="t1", source_id="src-a", kind="k", now=T0)
        worker.execute(job.job_id, always_fail, now=T0)
        assert worker.breaker_for("src-a").state == "open"

        # Still open before cooldown elapses.
        breaker = worker.breaker_for("src-a")
        assert breaker.allow_request(T0 + timedelta(seconds=30)) is False

        # Half-open after cooldown, then closes on success.
        after = T0 + timedelta(seconds=61)
        assert breaker.allow_request(after) is True
        assert breaker.state == "half_open"

        probe = worker.enqueue(tenant_id="t1", source_id="src-a", kind="k",
                               job_id="probe", now=after)
        worker.execute(probe.job_id, always_ok, now=after)
        assert worker.breaker_for("src-a").state == "closed"
        assert worker.events(event_type="breaker_closed")

    def test_breaker_is_per_source(self):
        worker = CollectionWorker(
            retry_policy=RetryPolicy(max_attempts=5, base_delay_seconds=1, jitter_ratio=0.0),
            breaker_config=CircuitBreakerConfig(failure_threshold=1, cooldown_seconds=600),
            seed=1,
        )
        bad = worker.enqueue(tenant_id="t1", source_id="src-bad", kind="k", now=T0)
        worker.execute(bad.job_id, always_fail, now=T0)
        assert worker.breaker_for("src-bad").state == "open"
        assert worker.breaker_for("src-good").state == "closed"

        good = worker.enqueue(tenant_id="t1", source_id="src-good", kind="k", now=T0)
        out = worker.execute(good.job_id, always_ok, now=T0)
        assert out.state is JobState.SUCCEEDED

    def test_half_open_probe_limit(self):
        breaker = SourceCircuitBreaker(
            source_id="s",
            config=CircuitBreakerConfig(failure_threshold=1, cooldown_seconds=10,
                                        half_open_probe_limit=1),
        )
        breaker.record_failure(T0)
        assert breaker.state == "open"
        assert breaker.allow_request(T0 + timedelta(seconds=11)) is True
        breaker.record_probe()
        assert breaker.allow_request(T0 + timedelta(seconds=12)) is False


class TestExpiryAndAbandonment:
    def test_overdue_jobs_move_to_expired(self, worker):
        job = worker.enqueue(tenant_id="t1", source_id="src-a", kind="k",
                             ttl_seconds=60, now=T0)
        expired = worker.expire_overdue_jobs(now=T0 + timedelta(seconds=61))
        assert [j.job_id for j in expired] == [job.job_id]
        assert worker.get_job(job.job_id).state is JobState.EXPIRED
        assert worker.metrics.jobs_expired == 1

    def test_terminal_jobs_are_not_expired_twice(self, worker):
        job = worker.enqueue(tenant_id="t1", source_id="src-a", kind="k", ttl_seconds=60, now=T0)
        worker.execute(job.job_id, always_ok, now=T0)
        assert worker.expire_overdue_jobs(now=T0 + timedelta(seconds=120)) == []

    def test_operator_abandonment_is_terminal(self, worker):
        job = worker.enqueue(tenant_id="t1", source_id="src-a", kind="k", now=T0)
        out = worker.abandon(job.job_id, reason="source_decommissioned", now=T0)
        assert out.state is JobState.ABANDONED
        assert "source_decommissioned" in out.last_error
        with pytest.raises(JobNotLeasableError):
            worker.abandon(job.job_id, now=T0)


class TestObservability:
    def test_events_capture_the_full_lifecycle(self, worker):
        job = worker.enqueue(tenant_id="t1", source_id="src-a", kind="k", now=T0)
        worker.execute(job.job_id, always_fail, now=T0)
        types = [e.event_type for e in worker.events(job_id=job.job_id)]
        assert types[0] == "created"
        assert "leased" in types
        assert "attempt_started" in types
        assert "attempt_failed" in types
        assert "retry_scheduled" in types

    def test_event_filters(self, worker):
        worker.enqueue(tenant_id="t1", source_id="src-a", kind="k", job_id="ja", now=T0)
        worker.enqueue(tenant_id="t1", source_id="src-b", kind="k", job_id="jb", now=T0)
        assert all(e.source_id == "src-a" for e in worker.events(source_id="src-a"))
        assert all(e.event_type == "created" for e in worker.events(event_type="created"))

    def test_event_retention_bounds_memory(self):
        worker = CollectionWorker(
            retry_policy=RetryPolicy(max_attempts=1, base_delay_seconds=1, jitter_ratio=0.0),
            event_retention=50, seed=1,
        )
        for i in range(40):
            j = worker.enqueue(tenant_id="t1", source_id="s", kind="k", job_id=f"j{i}", now=T0)
            worker.execute(j.job_id, always_ok, now=T0)
        assert len(worker.events()) <= 50

    def test_health_snapshot_reports_no_running_worker(self, worker):
        worker.enqueue(tenant_id="t1", source_id="src-a", kind="k", now=T0)
        snap = worker.health_snapshot(now=T0)
        assert snap["note"] == "snapshot only - no worker process is running"
        assert snap["total_jobs"] == 1
        assert snap["state_counts"]["pending"] == 1
        assert snap["verification_mode"] == "fixture_tested"

    def test_metrics_are_broken_down_by_source(self, worker):
        a = worker.enqueue(tenant_id="t1", source_id="src-a", kind="k", now=T0)
        b = worker.enqueue(tenant_id="t1", source_id="src-b", kind="k", now=T0)
        worker.execute(a.job_id, always_ok, now=T0)
        worker.execute(b.job_id, always_fail, now=T0)
        assert worker.metrics.by_source["src-a"]["attempts_succeeded"] == 1
        assert worker.metrics.by_source["src-b"]["attempts_failed"] == 1

    def test_export_state_is_serializable(self, worker):
        import json
        job = worker.enqueue(tenant_id="t1", source_id="src-a", kind="k", now=T0)
        worker.execute(job.job_id, always_ok, now=T0)
        blob = json.dumps(worker.export_state())
        assert "jobs" in json.loads(blob)


class TestNoHiddenSideEffects:
    def test_no_background_thread_is_started(self):
        """Importing and constructing the worker must not spawn threads."""
        before = threading.active_count()
        w = CollectionWorker(seed=1)
        w.enqueue(tenant_id="t1", source_id="s", kind="k")
        after = threading.active_count()
        assert after == before

    def test_module_makes_no_network_calls(self):
        """The module must not import any networking client."""
        import apps.threat_intelligence.collection_workers as mod
        source = open(mod.__file__, encoding="utf-8").read()
        for banned in ("import requests", "import httpx", "import urllib.request",
                       "import socket", "import aiohttp"):
            assert banned not in source, f"collection_workers must not {banned}"

    def test_terminal_states_are_exactly_the_declared_set(self):
        assert TERMINAL_STATES == {
            JobState.SUCCEEDED, JobState.FAILED, JobState.ABANDONED, JobState.EXPIRED
        }
