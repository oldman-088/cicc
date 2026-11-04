"""Simple in-memory sliding-window rate limiter for monitoring endpoints.

Monitoring endpoints are polled frequently by dashboards, so the limit is
generous (default 120 req/min per client). Liveness/readiness probes
(/live, /ready, /health) are intentionally NOT rate limited.
"""
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request


class SlidingWindowLimiter:
    def __init__(self, limit: int = 120, window_s: float = 60.0):
        self.limit = limit
        self.window_s = window_s
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            dq = self._hits[key]
            while dq and now - dq[0] > self.window_s:
                dq.popleft()
            if len(dq) >= self.limit:
                return False
            dq.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = SlidingWindowLimiter(
    limit=int(__import__("os").getenv("OPS_RATE_LIMIT", "120")),
    window_s=60.0,
)


def rate_limit_dependency(request: Request) -> None:
    client = request.client.host if request.client else "unknown"
    if not limiter.allow(client):
        raise HTTPException(status_code=429, detail="rate_limited")
