"""Scheduling policy for collection runs — decidable, not self-driving.

The host owns the clock: a cron entry, a Kubernetes CronJob, a worker beat. What the
host cannot own is *whether* a run should happen right now, because that depends on
facts only this package holds — checkpoint age, failure streaks, data staleness and
rate-limit pressure.

So this module answers one question and does nothing else:

    >>> plan = SchedulerPolicy().decide(checkpoint, now=utcnow())
    >>> plan.should_run, plan.reason
    (True, 'checkpoint is 3h 12m old (interval 6h, not a full refresh)')

Deliberately **not** implemented here: threads, `asyncio` loops, timers, signals,
daemon processes or `sleep`. A library that starts a background thread is a library
that cannot be imported safely in a test, a CLI, a request handler or a serverless
function — and this package is imported by all four. The host calls `decide()` on
whatever schedule it likes; nothing runs unless someone calls it.

The policy is also the place where the *operational* facts are expressed that a plain
cron cannot: backoff after repeated failure, a forced refresh when a checkpoint is
suspiciously old, and a refusal to run when the previous run left a partial window.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Callable

from .errors import ValidationError
from .schema import utcnow
from .sync import Checkpoint


class RunDecision(str, Enum):
    """Why a run is or is not happening. Every value is actionable."""

    #: First run, or the checkpoint was invalidated: full refresh.
    FULL_REFRESH = "full_refresh"
    #: Normal incremental run over the gap since the watermark.
    INCREMENTAL = "incremental"
    #: Too soon since the last successful run.
    NOT_YET_DUE = "not_yet_due"
    #: The previous run failed; the backoff has not elapsed.
    BACKING_OFF = "backing_off"
    #: The previous run failed too many times: needs a human.
    HALTED = "halted"
    #: A run is already in progress (lease held by another worker).
    LEASED = "leased"


@dataclass(frozen=True)
class SchedulePlan:
    """What the caller should do, and why — never just a boolean."""

    decision: RunDecision
    should_run: bool
    #: Human-readable justification. Always present, including when nothing happens:
    #: "the scheduler is healthy and chose not to run" is information an operator
    #: needs, and an empty log is indistinguishable from a scheduler that died.
    reason: str
    #: How far to look back, when running. ``None`` for a full refresh.
    since: datetime | None = None
    #: Set when the run must ignore the checkpoint entirely.
    full_refresh: bool = False
    #: Seconds until the next attempt is worth making. ``None`` = no scheduled retry.
    retry_after: float | None = None
    warnings: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "decision": self.decision.value,
            "should_run": self.should_run,
            "reason": self.reason,
            "since": self.since.isoformat() if self.since else None,
            "full_refresh": self.full_refresh,
            "retry_after": self.retry_after,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class SchedulerPolicy:
    """How often to collect, and what to do when collection keeps failing."""

    #: Target gap between successful runs.
    interval: timedelta = timedelta(hours=6)
    #: A checkpoint older than this forces a full refresh rather than an incremental
    #: one. NVD's modification window is bounded, so a very old watermark would ask
    #: for a range the API will not serve in one pass.
    max_checkpoint_age: timedelta = timedelta(days=30)
    #: Exponential backoff base after a failure.
    backoff_base: timedelta = timedelta(minutes=15)
    #: Backoff ceiling, so a long outage does not push the retry out for days.
    backoff_cap: timedelta = timedelta(hours=6)
    #: After this many consecutive failures, stop retrying and demand attention.
    #: Silently retrying forever is how a broken pipeline looks healthy.
    max_consecutive_failures: int = 5
    #: Grace subtracted from the interval, so a run scheduled every 6h does not skip
    #: a cycle because the clock drifted a second past the boundary.
    jitter_grace: timedelta = timedelta(minutes=5)

    def __post_init__(self) -> None:
        if self.interval <= timedelta(0):
            raise ValidationError("interval must be positive", field="interval")
        if self.max_consecutive_failures < 1:
            raise ValidationError(
                "max_consecutive_failures must be at least 1",
                field="max_consecutive_failures",
            )
        if self.backoff_cap < self.backoff_base:
            raise ValidationError(
                "backoff_cap must not be smaller than backoff_base", field="backoff_cap"
            )

    def backoff_for(self, failures: int) -> timedelta:
        """Exponential backoff, capped. ``failures`` is the *consecutive* count."""
        if failures <= 0:
            return timedelta(0)
        # Cap the exponent before shifting: 2**1000 is an expensive way to reach the
        # cap, and the multiplication would overflow a timedelta anyway.
        exponent = min(failures, 20)
        delay = self.backoff_base * (2 ** (exponent - 1))
        return min(delay, self.backoff_cap)

    def decide(
        self,
        checkpoint: Checkpoint | None,
        *,
        now: datetime | None = None,
        lease_held: bool = False,
        clock: Callable[[], datetime] = utcnow,
    ) -> SchedulePlan:
        """Decide whether to run now. Pure: no I/O, no clock side effects, no sleeping.

        ``lease_held`` is passed in rather than acquired here, because the lease is
        the host's coordination primitive (a row lock, a Redis key, an advisory lock).
        This policy only says what that fact means.
        """
        moment = now or clock()
        if moment.tzinfo is None:
            raise ValidationError("now must be timezone-aware", field="now")

        if lease_held:
            return SchedulePlan(
                decision=RunDecision.LEASED,
                should_run=False,
                reason="another worker holds the run lease; not starting a second one",
            )

        # A previous run that never completed is the most important signal: retrying
        # immediately would stack partial windows and corrupt the watermark.
        failures = checkpoint.consecutive_failures if checkpoint else 0
        if failures >= self.max_consecutive_failures:
            # Halting is checked **before** invalidation on purpose. An invalidated
            # checkpoint is normally repaired by a full refresh, but a full refresh
            # that has already failed `max_consecutive_failures` times is not a
            # checkpoint problem any more, and retrying it forever is how a broken
            # pipeline keeps looking busy. The remedy is still named in the reason so
            # the operator knows where to start.
            remedy = (
                " The checkpoint is also invalidated "
                f"({checkpoint.invalidated_reason}), so a full refresh will be needed "
                "once the underlying failure is fixed."
                if checkpoint is not None and checkpoint.invalidated_reason
                else ""
            )
            return SchedulePlan(
                decision=RunDecision.HALTED,
                should_run=False,
                reason=(
                    f"halted after {failures} consecutive failures "
                    f"(limit {self.max_consecutive_failures}); "
                    "this needs a human, not another retry." + remedy
                ),
                warnings=(checkpoint.last_error,) if checkpoint and checkpoint.last_error else (),
            )

        if checkpoint is not None and checkpoint.invalidated_reason:
            return SchedulePlan(
                decision=RunDecision.FULL_REFRESH,
                should_run=True,
                full_refresh=True,
                reason=(
                    "checkpoint invalidated: "
                    f"{checkpoint.invalidated_reason}; a full refresh is required"
                ),
            )

        if checkpoint is None or checkpoint.watermark is None:
            return SchedulePlan(
                decision=RunDecision.FULL_REFRESH,
                should_run=True,
                full_refresh=True,
                reason="no checkpoint yet: this is the first run, so it is a full refresh",
            )

        age = moment - checkpoint.watermark
        if age < timedelta(0):
            # A watermark in the future means clock skew or a restored backup. Both
            # are worth refusing to paper over: running would ask for a negative
            # window and silently sync nothing.
            return SchedulePlan(
                decision=RunDecision.BACKING_OFF,
                should_run=False,
                reason=(
                    "checkpoint watermark is in the future "
                    f"({checkpoint.watermark.isoformat()} > {moment.isoformat()}); "
                    "clock skew or a restored backup, refusing to sync a negative window"
                ),
                warnings=("watermark is in the future",),
            )

        if failures:
            wait = self.backoff_for(failures)
            last = checkpoint.completed_at or checkpoint.watermark
            elapsed = moment - last
            if elapsed < wait:
                remaining = (wait - elapsed).total_seconds()
                return SchedulePlan(
                    decision=RunDecision.BACKING_OFF,
                    should_run=False,
                    reason=(
                        f"{failures} consecutive failure(s); backing off for "
                        f"{_humanise(wait)}, {_humanise(wait - elapsed)} to go"
                    ),
                    retry_after=remaining,
                    warnings=(checkpoint.last_error,) if checkpoint.last_error else (),
                )

        if age > self.max_checkpoint_age:
            return SchedulePlan(
                decision=RunDecision.FULL_REFRESH,
                should_run=True,
                full_refresh=True,
                reason=(
                    f"checkpoint is {_humanise(age)} old, past the "
                    f"{_humanise(self.max_checkpoint_age)} limit; an incremental "
                    "window that large would not be served in one pass"
                ),
                warnings=("checkpoint age exceeded max_checkpoint_age",),
            )

        effective_interval = self.interval - self.jitter_grace
        if age < effective_interval:
            return SchedulePlan(
                decision=RunDecision.NOT_YET_DUE,
                should_run=False,
                reason=(
                    f"checkpoint is {_humanise(age)} old; next run due in "
                    f"{_humanise(self.interval - age)}"
                ),
                retry_after=max(0.0, (self.interval - age).total_seconds()),
            )

        return SchedulePlan(
            decision=RunDecision.INCREMENTAL,
            should_run=True,
            reason=f"checkpoint is {_humanise(age)} old (interval {_humanise(self.interval)})",
            since=checkpoint.watermark,
        )


@dataclass
class RunLedger:
    """Records the outcome of runs so ``decide`` has facts to work from.

    In-memory and single-process by design: the host's lease is what makes this safe
    across workers, and pretending to coordinate across processes here would be a
    distributed-systems claim this class cannot keep.
    """

    outcomes: list[dict[str, object]] = field(default_factory=list)

    def record(self, plan: SchedulePlan, *, succeeded: bool, error: str | None = None,
               records: int = 0) -> dict[str, object]:
        entry: dict[str, object] = {
            "decision": plan.decision.value,
            "succeeded": succeeded,
            "error": error,
            "records": records,
        }
        self.outcomes.append(entry)
        return entry

    @property
    def consecutive_failures(self) -> int:
        streak = 0
        for entry in reversed(self.outcomes):
            if entry["succeeded"]:
                break
            streak += 1
        return streak


def _humanise(delta: timedelta) -> str:
    """A duration a person can read without arithmetic."""
    seconds = int(abs(delta.total_seconds()))
    if seconds < 90:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 90:
        return f"{minutes}m"
    hours = minutes // 60
    if hours < 48:
        return f"{hours}h {minutes % 60:02d}m"
    days = hours // 24
    return f"{days}d {hours % 24:02d}h"
