"""Client-side rate gating.

Sources publish quotas (NVD without a key allows a handful of requests per 30
seconds).  A shared gate keeps the platform inside that budget *before* the
source has to reject a request, which is both politer and cheaper.

The gate is a minimum-interval controller, not a token bucket: it is simple,
deterministic under test and adequate for the low, bursty request volume of a
collector that also caches aggressively.  It does not coordinate across
processes — a documented limitation (see README).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable

from .errors import SourceRateLimited

__all__ = ["RateGate", "quota_for_nvd"]


@dataclass
class RateGate:
    """Enforces at least ``min_interval`` seconds between calls.

    ``clock`` and ``sleep`` are injectable so tests never actually wait.
    """

    min_interval: float = 0.0
    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep

    def __post_init__(self) -> None:
        if self.min_interval < 0:
            raise ValueError("min_interval must be >= 0")
        self._last: float | None = None
        self._lock = threading.Lock()

    def wait(self) -> float:
        """Block (or sleep virtually) until the next call is allowed.

        Returns the time actually waited, which callers can log.
        """
        with self._lock:
            now = self.clock()
            waited = 0.0
            if self._last is not None:
                remaining = self.min_interval - (now - self._last)
                if remaining > 0:
                    self.sleep(remaining)
                    waited = remaining
            self._last = self.clock()
            return waited

    def observe_retry_after(self, seconds: float | None) -> None:
        """Widen the interval after the source asked us to slow down."""
        if seconds is None or seconds <= 0:
            return
        with self._lock:
            self.min_interval = max(self.min_interval, float(seconds))


def quota_for_nvd(*, api_key: bool) -> RateGate:
    """Documented NVD rolling limits (requests per 30 s) expressed as an interval.

    * no key: 5 requests / 30 s  -> 6.0 s
    * with key: 50 requests / 30 s -> 0.6 s

    A small safety margin is added because the published window is rolling.
    """
    per_30s = 50 if api_key else 5
    return RateGate(min_interval=(30.0 / per_30s) * 1.1)


def quota_for_osv() -> RateGate:
    """OSV asks for a modest request rate; be conservative at 10 requests/s."""
    return RateGate(min_interval=0.1)


def enforce_retry_after(retry_after: float | None) -> None:
    """Raise :class:`SourceRateLimited` if the source asked for a long pause."""
    if retry_after is not None and retry_after > 0:
        raise SourceRateLimited("source requested a pause", retry_after=retry_after)
