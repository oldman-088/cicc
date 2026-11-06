"""Individual health checks for monitored components.

Every check is bounded (timeout), failure-isolated (never raises), and
must never leak credentials or configured connection targets. Database
health details expose only the non-sensitive driver type; external service
URLs are reduced to scheme and host. External probes (RabbitMQ management
API, platform API) are additionally protected by a per-probe circuit breaker
so a hanging dependency cannot stall the monitoring API, and so stale statuses
are explicitly flagged.
"""
import base64
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

CHECK_TIMEOUT_S = 2.0
MAX_BODY_BYTES = 16 * 1024


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _host_only(url: str) -> str:
    """Reduce a URL to scheme://host[:port] so credentials can never leak."""
    try:
        p = urllib.parse.urlparse(url)
        return f"{p.scheme}://{p.hostname}" + (f":{p.port}" if p.port else "")
    except Exception:  # noqa: BLE001
        return "unknown-host"


def _get_json(url: str, timeout: float = CHECK_TIMEOUT_S, auth: tuple | None = None) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    if auth:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # admin-configured URL only
        raw = resp.read(MAX_BODY_BYTES)
        return json.loads(raw.decode())


class CircuitBreaker:
    """Per-probe circuit breaker: after N consecutive failures, skip live
    probing for a cooldown and report status 'unknown' with stale=True and
    the last known status — never a false 'ok'."""

    def __init__(self, key: str, failure_threshold: int, cooldown_s: float):
        self.key = key
        self.failure_threshold = failure_threshold
        self.cooldown_s = cooldown_s
        self.state = "closed"  # closed | open | half-open
        self.fail_count = 0
        self.opened_at = 0.0
        self.last_status: str | None = None
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            if self.state == "open":
                if time.monotonic() - self.opened_at >= self.cooldown_s:
                    self.state = "half-open"
                    return True
                return False
            return True

    def record_success(self, status: str) -> None:
        with self._lock:
            self.last_status = status
            self.fail_count = 0
            self.state = "closed"

    def record_failure(self) -> None:
        with self._lock:
            self.fail_count += 1
            self.last_status = "down"  # last OBSERVED status
            if self.fail_count >= self.failure_threshold:
                self.state = "open"
                self.opened_at = time.monotonic()


_cbs: dict[str, CircuitBreaker] = {}
_cbs_lock = threading.Lock()


def _cb(key: str) -> CircuitBreaker:
    with _cbs_lock:
        if key not in _cbs:
            _cbs[key] = CircuitBreaker(
                key,
                failure_threshold=int(os.getenv("OPS_CB_FAILURES", "3")),
                cooldown_s=float(os.getenv("OPS_CB_COOLDOWN_S", "30")),
            )
        return _cbs[key]


def reset_circuit_breakers() -> None:
    with _cbs_lock:
        _cbs.clear()


def guarded_probe(key: str, fn, label: str = "") -> dict:
    """Run a probe under its circuit breaker. Never raises. `label` is a
    host-only string used in failure details (never credentials)."""
    cb = _cb(key)
    if not cb.allow():
        return {
            "status": "unknown",
            "stale": True,
            "detail": f"circuit open (cooldown); last known status: {cb.last_status}",
        }
    try:
        result = fn()
        cb.record_success(result.get("status", "ok"))
        return result
    except Exception as exc:  # noqa: BLE001
        cb.record_failure()
        prefix = f"{label}: " if label else ""
        return {"status": "down", "detail": f"{prefix}probe failed: {type(exc).__name__}"}


def check_database(engine) -> dict:
    """REAL database health check: an actual round trip (SELECT 1)."""
    started = _utcnow()
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        latency_ms = round((_utcnow() - started).total_seconds() * 1000, 2)
        return {
            "status": "ok",
            # Health is commonly surfaced to browsers and external monitors.
            # Keep the useful database type, but never expose host, path, user,
            # port, or database name from the configured connection URL.
            "detail": f"{engine.dialect.name} database connection verified",
            "latency_ms": latency_ms,
        }
    except Exception as exc:  # noqa: BLE001 - report any failure honestly
        return {
            "status": "down",
            "detail": f"connection failed: {type(exc).__name__}",
            "latency_ms": round((_utcnow() - started).total_seconds() * 1000, 2),
        }


def _rabbitmq_probe() -> dict:
    """RabbitMQ management-API check.

    Enabled only when RABBITMQ_MANAGEMENT_URL is configured (optionally
    RABBITMQ_USER / RABBITMQ_PASS). Reports broker availability, queue
    totals, consumer count and dead-letter queue count — never credentials,
    and never claims anything about Arena agent session control (that
    integration is NOT implemented/verified). Secondary endpoints
    (queues, consumers) are best-effort: their failure degrades detail, not
    the broker status.
    """
    base = os.getenv("RABBITMQ_MANAGEMENT_URL")
    if not base:
        return {
            "status": "not_configured",
            "detail": "set RABBITMQ_MANAGEMENT_URL (e.g. http://localhost:15672) to enable RabbitMQ monitoring",
        }
    started = _utcnow()
    user = os.getenv("RABBITMQ_USER")
    password = os.getenv("RABBITMQ_PASS")
    auth = (user, password) if user and password else None
    overview = _get_json(base.rstrip("/") + "/api/overview", auth=auth)
    qt = overview.get("queue_totals", {}) or {}
    result = {
        "status": "ok",
        "detail": f"management API at {_host_only(base)}",
        "latency_ms": round((_utcnow() - started).total_seconds() * 1000, 2),
        "messages_ready": qt.get("messages_ready"),
        "messages_unacknowledged": qt.get("messages_unacknowledged"),
        "queues": qt.get("queues"),
        "consumers": None,
        "dead_letter_queues": None,
    }
    try:
        qs = _get_json(base.rstrip("/") + "/api/queues", auth=auth)
        result["queues"] = len(qs)
        result["dead_letter_queues"] = sum(
            1 for q in qs if (q.get("arguments") or {}).get("x-dead-letter-exchange")
        )
    except Exception:  # noqa: BLE001 - best effort
        pass
    try:
        cs = _get_json(base.rstrip("/") + "/api/consumers", auth=auth)
        result["consumers"] = len(cs)
    except Exception:  # noqa: BLE001 - best effort
        pass
    return result


def check_rabbitmq() -> dict:
    """Circuit-breaker-guarded RabbitMQ check. Never raises."""
    base = os.getenv("RABBITMQ_MANAGEMENT_URL")
    if not base:
        return _rabbitmq_probe()  # returns not_configured without probing
    return guarded_probe("rabbitmq", _rabbitmq_probe, label=_host_only(base))


def _platform_api_probe() -> dict:
    base = os.getenv("CICC_PLATFORM_API_URL")
    if not base:
        return {
            "status": "not_configured",
            "detail": "set CICC_PLATFORM_API_URL to monitor this dependency",
        }
    url = base.rstrip("/") + "/health"
    started = _utcnow()
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=CHECK_TIMEOUT_S) as resp:
        ok = 200 <= resp.status < 300
        body = resp.read(512).decode(errors="replace")
    return {
        "status": "ok" if ok else "degraded",
        "detail": f"{_host_only(base)} returned HTTP {resp.status}",
        "latency_ms": round((_utcnow() - started).total_seconds() * 1000, 2),
        "response_excerpt": body[:200] if ok else None,
    }


def check_external_api(env_var: str, path: str = "/health") -> dict:
    """Generic circuit-breaker-guarded HTTP health probe for an external
    service configured via env (e.g. CICC_PLATFORM_API_URL)."""
    if not os.getenv(env_var):
        return {
            "status": "not_configured",
            "detail": f"set {env_var} to monitor this dependency",
        }
    label = _host_only(os.getenv(env_var, ""))
    return guarded_probe(
        env_var,
        lambda: _platform_api_probe() if env_var == "CICC_PLATFORM_API_URL" else _generic_probe(env_var, path),
        label=label,
    )


def _generic_probe(env_var: str, path: str) -> dict:
    base = os.getenv(env_var, "")
    url = base.rstrip("/") + path
    started = _utcnow()
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=CHECK_TIMEOUT_S) as resp:
        ok = 200 <= resp.status < 300
    return {
        "status": "ok" if ok else "degraded",
        "detail": f"{_host_only(base)} returned HTTP {resp.status}",
        "latency_ms": round((_utcnow() - started).total_seconds() * 1000, 2),
    }
