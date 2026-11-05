"""Scheduling policy: what to decide, and what it must refuse to do.

The design constraint under test is that this module *decides* and never *drives*.
A library that starts a thread, a timer or an event loop cannot be imported safely in
a test, a CLI, a request handler and a serverless function — and this package is
imported by all four. So the tests check the decisions, and one test checks that
nothing was started.
"""

from __future__ import annotations

import ast
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

from vuln_intel.errors import ValidationError
from vuln_intel.scheduling import (
    RunDecision,
    RunLedger,
    SchedulerPolicy,
    _humanise,
)
from vuln_intel.sync import Checkpoint

NOW = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)


def policy(**kwargs) -> SchedulerPolicy:
    return SchedulerPolicy(**kwargs)


def checkpoint(age: timedelta | None = None, **kwargs) -> Checkpoint:
    base = {"source": "nvd", "records": 10, "origin": "fixture"}
    if age is not None:
        base["watermark"] = NOW - age
        base["completed_at"] = NOW - age
    base.update(kwargs)
    return Checkpoint(**base)


class TestFirstAndFullRuns:
    def test_no_checkpoint_means_full_refresh(self) -> None:
        plan = policy().decide(None, now=NOW)
        assert plan.decision is RunDecision.FULL_REFRESH
        assert plan.should_run
        assert plan.full_refresh
        assert plan.since is None

    def test_a_checkpoint_with_no_watermark_is_also_a_full_refresh(self) -> None:
        plan = policy().decide(checkpoint(), now=NOW)
        assert plan.decision is RunDecision.FULL_REFRESH
        assert "first run" in plan.reason

    def test_an_invalidated_checkpoint_forces_a_full_refresh(self) -> None:
        plan = policy().decide(
            checkpoint(timedelta(hours=1), invalidated_reason="schema change"), now=NOW
        )
        assert plan.decision is RunDecision.FULL_REFRESH
        assert "schema change" in plan.reason

    def test_a_failure_streak_outranks_invalidation_but_names_the_remedy(self) -> None:
        """Halting wins, and the reason still says a full refresh will be needed.

        I first assumed invalidation should win. It should not: an invalidated
        checkpoint is normally repaired by a full refresh, but a full refresh that has
        already failed the limit is no longer a checkpoint problem, and retrying it
        forever is how a broken pipeline keeps looking busy. What matters is that the
        operator is told both facts.
        """
        plan = policy().decide(
            checkpoint(timedelta(hours=1), invalidated_reason="corrupt",
                       consecutive_failures=99),
            now=NOW,
        )
        assert plan.decision is RunDecision.HALTED
        assert "corrupt" in plan.reason
        assert "full refresh will be needed" in plan.reason


class TestDueAndNotDue:
    def test_a_fresh_checkpoint_is_not_due(self) -> None:
        plan = policy().decide(checkpoint(timedelta(hours=1)), now=NOW)
        assert plan.decision is RunDecision.NOT_YET_DUE
        assert not plan.should_run
        assert plan.retry_after is not None and plan.retry_after > 0

    def test_an_old_checkpoint_is_incremental(self) -> None:
        plan = policy().decide(checkpoint(timedelta(hours=8)), now=NOW)
        assert plan.decision is RunDecision.INCREMENTAL
        assert plan.should_run
        assert plan.since is not None
        assert not plan.full_refresh

    def test_the_grace_window_prevents_a_skipped_cycle(self) -> None:
        """Six hours exactly minus a few minutes of clock drift must still run."""
        close = policy(interval=timedelta(hours=6), jitter_grace=timedelta(minutes=5))
        plan = close.decide(checkpoint(timedelta(hours=5, minutes=58)), now=NOW)
        assert plan.decision is RunDecision.INCREMENTAL

    def test_not_due_still_carries_a_reason(self) -> None:
        """An empty log is indistinguishable from a scheduler that died."""
        plan = policy().decide(checkpoint(timedelta(minutes=1)), now=NOW)
        assert plan.reason
        assert "due in" in plan.reason

    def test_a_very_old_checkpoint_forces_a_full_refresh(self) -> None:
        plan = policy(max_checkpoint_age=timedelta(days=30)).decide(
            checkpoint(timedelta(days=45)), now=NOW
        )
        assert plan.decision is RunDecision.FULL_REFRESH
        assert "past the" in plan.reason


class TestFailureHandling:
    def test_the_first_failure_backs_off(self) -> None:
        plan = policy().decide(
            checkpoint(timedelta(hours=8), consecutive_failures=1,
                       completed_at=NOW - timedelta(minutes=1)),
            now=NOW,
        )
        assert plan.decision is RunDecision.BACKING_OFF
        assert plan.retry_after is not None

    def test_backoff_grows_then_caps(self) -> None:
        subject = policy(
            backoff_base=timedelta(minutes=10), backoff_cap=timedelta(hours=1)
        )
        assert subject.backoff_for(1) == timedelta(minutes=10)
        assert subject.backoff_for(2) == timedelta(minutes=20)
        assert subject.backoff_for(3) == timedelta(minutes=40)
        assert subject.backoff_for(4) == timedelta(hours=1)  # capped

    def test_a_huge_failure_count_does_not_overflow(self) -> None:
        """2**1000 is an expensive way to reach the cap, and overflows a timedelta."""
        assert policy().backoff_for(10_000) == timedelta(hours=6)

    def test_zero_failures_has_no_delay(self) -> None:
        assert policy().backoff_for(0) == timedelta(0)

    def test_too_many_failures_halts_and_demands_a_human(self) -> None:
        plan = policy(max_consecutive_failures=3).decide(
            checkpoint(timedelta(hours=1), consecutive_failures=3,
                       last_error="connection refused"),
            now=NOW,
        )
        assert plan.decision is RunDecision.HALTED
        assert not plan.should_run
        assert "human" in plan.reason
        assert "connection refused" in plan.warnings

    def test_halting_beats_being_not_due(self) -> None:
        """A halted source must say 'halted', not 'nothing to do'."""
        plan = policy(max_consecutive_failures=2).decide(
            checkpoint(timedelta(minutes=2), consecutive_failures=2), now=NOW
        )
        assert plan.decision is RunDecision.HALTED


class TestLeaseAndSkew:
    def test_a_held_lease_prevents_a_second_run(self) -> None:
        plan = policy().decide(checkpoint(timedelta(hours=8)), now=NOW, lease_held=True)
        assert plan.decision is RunDecision.LEASED
        assert not plan.should_run
        assert "lease" in plan.reason

    def test_a_future_watermark_is_refused_not_synced(self) -> None:
        """A negative window would sync nothing and look like a clean run."""
        future = Checkpoint(
            source="nvd", watermark=NOW + timedelta(hours=3),
            completed_at=NOW + timedelta(hours=3), origin="fixture",
        )
        plan = policy().decide(future, now=NOW)
        assert plan.decision is RunDecision.BACKING_OFF
        assert not plan.should_run
        assert "future" in plan.reason

    def test_a_naive_now_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            policy().decide(checkpoint(timedelta(hours=1)), now=datetime(2026, 11, 4, 12, 0))


class TestPolicyValidation:
    def test_a_non_positive_interval_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            policy(interval=timedelta(0))

    def test_a_zero_failure_limit_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            policy(max_consecutive_failures=0)

    def test_a_cap_below_the_base_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            policy(backoff_base=timedelta(hours=2), backoff_cap=timedelta(minutes=5))


class TestLedger:
    def test_a_success_resets_the_streak(self) -> None:
        ledger = RunLedger()
        plan = policy().decide(None, now=NOW)
        ledger.record(plan, succeeded=False, error="boom")
        ledger.record(plan, succeeded=False, error="boom")
        assert ledger.consecutive_failures == 2
        ledger.record(plan, succeeded=True, records=5)
        assert ledger.consecutive_failures == 0

    def test_an_empty_ledger_has_no_failures(self) -> None:
        assert RunLedger().consecutive_failures == 0


class TestPlansAreSerialisable:
    def test_every_plan_becomes_json_safe_dict(self) -> None:
        import json

        for plan in (
            policy().decide(None, now=NOW),
            policy().decide(checkpoint(timedelta(hours=1)), now=NOW),
            policy().decide(checkpoint(timedelta(hours=9)), now=NOW),
            policy().decide(checkpoint(timedelta(hours=9)), now=NOW, lease_held=True),
        ):
            json.dumps(plan.as_dict())  # must not raise
            assert plan.as_dict()["reason"]

    def test_every_decision_value_is_reachable(self) -> None:
        """A decision nobody can produce is a decision whose text will rot."""
        produced = {
            policy().decide(None, now=NOW).decision,
            policy().decide(checkpoint(timedelta(hours=9)), now=NOW).decision,
            policy().decide(checkpoint(timedelta(minutes=1)), now=NOW).decision,
            policy().decide(checkpoint(timedelta(hours=9)), now=NOW, lease_held=True).decision,
        }
        assert produced == {
            RunDecision.FULL_REFRESH, RunDecision.INCREMENTAL,
            RunDecision.NOT_YET_DUE, RunDecision.LEASED,
        }


class TestHumanisedDurations:
    @pytest.mark.parametrize(
        ("delta", "expected"),
        [
            (timedelta(seconds=30), "30s"),
            (timedelta(minutes=5), "5m"),
            (timedelta(hours=3, minutes=12), "3h 12m"),
            (timedelta(days=2, hours=3), "2d 03h"),
        ],
    )
    def test_durations_read_without_arithmetic(self, delta, expected) -> None:
        assert _humanise(delta) == expected


class TestNothingIsStarted:
    """The design constraint: a policy that decides must not also drive."""

    def test_the_module_imports_no_concurrency_primitive(self) -> None:
        source = (
            pathlib.Path(__file__).parent.parent / "vuln_intel" / "scheduling.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        forbidden = {"threading", "asyncio", "multiprocessing", "signal", "sched", "time"}
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        assert not (imported & forbidden), f"imports {imported & forbidden}"

    def test_the_module_never_sleeps(self) -> None:
        source = (
            pathlib.Path(__file__).parent.parent / "vuln_intel" / "scheduling.py"
        ).read_text(encoding="utf-8")
        assert "sleep(" not in source

    def test_deciding_is_pure(self) -> None:
        """Same inputs, same answer — no hidden clock, no hidden state."""
        subject = policy()
        state = checkpoint(timedelta(hours=9))
        first = subject.decide(state, now=NOW)
        second = subject.decide(state, now=NOW)
        assert first == second

    def test_deciding_does_not_mutate_the_checkpoint(self) -> None:
        state = checkpoint(timedelta(hours=9))
        before = state.as_dict()
        policy().decide(state, now=NOW)
        assert state.as_dict() == before
