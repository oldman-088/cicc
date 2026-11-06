"""Circuit breaker for upstream sources.

Retry handles transient blips.  A breaker handles a *sustained* outage: after N
consecutive failures the source is opened and calls fail fast with a clear
reason, so a collector cannot hammer a dead provider (which is both impolite and
a self-inflicted denial of service).  A single probe is allowed after a cooldown;
success closes the breaker, failure re-opens it with a doubled cooldown.

States: ``closed`` → ``open`` → ``half_open`` → (closed | open).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from .errors import SourceError, SourceUnavailable

__all__ = ["BreakerState", "CircuitBreaker", "CircuitOpen"]


class BreakerState(str):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpen(SourceUnavailable):
    """Raised instead of calling a source whose breaker is open."""

    def __init__(self, source: str, retry_in: float) -> None:
        self.retry_in = max(0.0, retry_in)
        super().__init__(
            f"circuit open after repeated failures; retry in {self.retry_in:.0f}s",
            source=source,
        )


@dataclass
class CircuitBreaker:
    """Deterministic breaker with an injectable clock."""

    source: str = "source"
    failure_threshold: int = 5
    cooldown: float = 30.0
    max_cooldown: float = 600.0
    clock: Callable[[], float] = time.monotonic
    state: str = BreakerState.CLOSED
    _failures: int = field(default=0, repr=False)
    _opened_at: float | None = field(default=None, repr=False)
    _current_cooldown: float = field(default=0.0, repr=False)

    def __post_init__(self) -> None:
        if self.failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if self.cooldown <= 0:
            raise ValueError("cooldown must be > 0")
        self._current_cooldown = self.cooldown

    # -- queries ---------------------------------------------------------
    def allow(self) -> bool:
        """True if a call may proceed. Moves ``open`` → ``half_open`` when due."""
        if self.state == BreakerState.CLOSED:
            return True
        assert self._opened_at is not None
        if self.clock() - self._opened_at >= self._current_cooldown:
            self.state = BreakerState.HALF_OPEN
            return True
        return False

    def check(self) -> None:
        """Raise :class:`CircuitOpen` when a call must not proceed."""
        if self.allow():
            return
        assert self._opened_at is not None
        remaining = self._current_cooldown - (self.clock() - self._opened_at)
        raise CircuitOpen(self.source, remaining)

    def retry_in(self) -> float:
        if self._opened_at is None:
            return 0.0
        return max(0.0, self._current_cooldown - (self.clock() - self._opened_at))

    # -- transitions -----------------------------------------------------
    def record_success(self) -> None:
        self.state = BreakerState.CLOSED
        self._failures = 0
        self._opened_at = None
        self._current_cooldown = self.cooldown

    def record_failure(self) -> None:
        self._failures += 1
        if self.state == BreakerState.HALF_OPEN:
            # The probe failed: stay open, and back off further.
            self._open()
            self._current_cooldown = min(self.max_cooldown, self._current_cooldown * 2)
            return
        if self._failures >= self.failure_threshold:
            self._open()

    def _open(self) -> None:
        self.state = BreakerState.OPEN
        self._opened_at = self.clock()

    def call(self, func: Callable[[], object]) -> object:
        """Run ``func`` under the breaker.

        Only :class:`SourceError` counts as a source failure; programming errors
        (``TypeError``, ``KeyError``) propagate untouched so bugs stay visible.
        """
        self.check()
        try:
            result = func()
        except SourceError:
            self.record_failure()
            raise
        self.record_success()
        return result

    def as_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "state": self.state,
            "consecutive_failures": self._failures,
            "retry_in": round(self.retry_in(), 1),
        }
