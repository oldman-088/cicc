"""Bounded retry with exponential backoff and jitter.

Only idempotent reads are retried.  ``Retry-After`` from the source is
honoured, and the total number of attempts is capped so a broken source cannot
stall a worker.  Every sleep goes through the injected ``sleep`` callable, which
keeps the tests fast and deterministic.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Callable, TypeVar

from .errors import (
    SourceError,
    SourceRateLimited,
    SourceResponseError,
    SourceTimeout,
    SourceUnavailable,
)

__all__ = ["RetryPolicy", "call_with_retry", "TRANSIENT"]

T = TypeVar("T")

#: Errors considered worth another attempt.
TRANSIENT = (SourceTimeout, SourceUnavailable, SourceRateLimited)


@dataclass(frozen=True)
class RetryPolicy:
    """Bounded retry configuration.

    ``attempts`` counts the first try, so ``attempts=1`` disables retrying.
    """

    attempts: int = 3
    base_delay: float = 0.5
    max_delay: float = 8.0
    jitter: float = 0.25
    #: Honour a ``Retry-After`` longer than this by failing instead of sleeping.
    max_retry_after: float = 60.0

    def __post_init__(self) -> None:
        if self.attempts < 1:
            raise ValueError("attempts must be >= 1")
        if self.base_delay < 0 or self.max_delay < 0:
            raise ValueError("delays must be >= 0")
        if self.max_delay < self.base_delay:
            raise ValueError("max_delay must be >= base_delay")
        if not 0.0 <= self.jitter <= 1.0:
            raise ValueError("jitter must be within [0, 1]")

    def delay_for(self, attempt: int, *, rand: Callable[[], float] = random.random) -> float:
        """Exponential delay for the given zero-based failed ``attempt``."""
        raw = min(self.max_delay, self.base_delay * (2**attempt))
        if self.jitter:
            raw *= 1.0 + self.jitter * (rand() * 2.0 - 1.0)
        return max(0.0, min(self.max_delay, raw))


def _is_retryable(exc: BaseException, policy: RetryPolicy) -> bool:
    if isinstance(exc, SourceRateLimited):
        if exc.retry_after is not None and exc.retry_after > policy.max_retry_after:
            return False
        return True
    if isinstance(exc, SourceResponseError):
        # Only server-side failures and explicit request timeouts are transient.
        return exc.status in (408, 425, 429, 500, 502, 503, 504)
    return isinstance(exc, TRANSIENT)


def call_with_retry(
    func: Callable[[], T],
    *,
    policy: RetryPolicy | None = None,
    sleep: Callable[[float], None] = time.sleep,
    rand: Callable[[], float] = random.random,
    on_retry: Callable[[int, BaseException, float], None] | None = None,
) -> T:
    """Call ``func`` at most ``policy.attempts`` times.

    The final failure is re-raised unchanged so callers keep the precise error
    class.  Non-retryable errors (validation, 404, oversized body) fail fast.
    """
    policy = policy or RetryPolicy()
    last: BaseException | None = None
    for attempt in range(policy.attempts):
        try:
            return func()
        except SourceError as exc:
            last = exc
            if attempt + 1 >= policy.attempts or not _is_retryable(exc, policy):
                raise
            wait = policy.delay_for(attempt, rand=rand)
            if isinstance(exc, SourceRateLimited) and exc.retry_after is not None:
                wait = max(wait, exc.retry_after)
            if on_retry is not None:
                on_retry(attempt + 1, exc, wait)
            # Sleep even for a zero delay: the injected sleep may drive a virtual
            # clock (and tests assert the backoff sequence).
            sleep(wait)
    raise last  # pragma: no cover - loop always returns or raises
