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
    """Read gate. If platform auth is enabled (CICC_OPS_USE_PLATFORM_AUTH=1 +
    CICC_PLATFORM_DB_URL), verify the platform bearer session instead of the
    static env token (fail closed). Otherwise env-token logic applies: when
    both tokens are configured, the WRITE token also satisfies read access."""
    from app import platform_auth

    if platform_auth.platform_auth_enabled():
        principal = platform_auth.resolve_principal(authorization)
        if not platform_auth.read_allowed(principal):
            raise HTTPException(status_code=401, detail="invalid platform session or role not allowed")
        return
    token = os.getenv("CICC_OPS_READ_TOKEN")
    if token:
        write_token = os.getenv("CICC_OPS_WRITE_TOKEN")
        ok = authorization == f"Bearer {token}" or (
            write_token and authorization == f"Bearer {write_token}"
        )
        if not ok:
            raise HTTPException(status_code=401, detail="invalid or missing read token")


def require_write_token(authorization: str | None) -> None:
    from app import platform_auth

    if platform_auth.platform_auth_enabled():
        principal = platform_auth.resolve_principal(authorization)
        if not platform_auth.write_allowed(principal):
            raise HTTPException(status_code=401, detail="invalid platform session or role not allowed for writes")
        return
    token = os.getenv("CICC_OPS_WRITE_TOKEN")
    if token and authorization != f"Bearer {token}":
        raise HTTPException(status_code=401, detail="invalid or missing write token")
