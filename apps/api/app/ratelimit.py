"""Rate limiting + optional auth gates for monitoring endpoints.

- Ops endpoints: sliding-window limit per client (default 120/min via
  OPS_RATE_LIMIT); probes /live, /ready, /health are exempt.
- If CICC_OPS_READ_TOKEN is set, ops GET endpoints require
  `Authorization: Bearer <token>` (interim gate until the platform's real
  auth fronts these endpoints — see docs/MONITORING_CONTRACTS.md §7).
- If CICC_OPS_WRITE_TOKEN is set, write endpoints (POST /tasks,
  /workers/heartbeat) require the same style Bearer token.
"""
import os
import threading
import time
from collections import defaultdict, deque

from fastapi import Header, HTTPException, Request


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
    limit=int(os.getenv("OPS_RATE_LIMIT", "120")),
    window_s=60.0,
)


def rate_limit_dependency(request: Request) -> None:
    client = request.client.host if request.client else "unknown"
    if not limiter.allow(client):
        raise HTTPException(status_code=429, detail="rate_limited")


def read_token_dependency(authorization: str | None = Header(default=None)) -> None:
    token = os.getenv("CICC_OPS_READ_TOKEN")
    if token and authorization != f"Bearer {token}":
        raise HTTPException(status_code=401, detail="invalid or missing read token")


def require_write_token(authorization: str | None) -> None:
    token = os.getenv("CICC_OPS_WRITE_TOKEN")
    if token and authorization != f"Bearer {token}":
        raise HTTPException(status_code=401, detail="invalid or missing write token")
