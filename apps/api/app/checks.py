"""Individual health checks for monitored components.

Every check is bounded (timeout), failure-isolated (never raises), and
must never leak credentials: URLs are reduced to their host in details.
"""
import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

CHECK_TIMEOUT_S = 2.0


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _host_only(url: str) -> str:
    """Reduce a URL to scheme://host so credentials can never leak."""
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
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - admin-configured URL
        return json.loads(resp.read().decode())


def check_database(engine) -> dict:
    """REAL database health check: an actual round trip (SELECT 1)."""
    started = _utcnow()
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        latency_ms = round((_utcnow() - started).total_seconds() * 1000, 2)
        return {
            "status": "ok",
            "detail": engine.url.render_as_string(hide_password=True),
            "latency_ms": latency_ms,
        }
    except Exception as exc:  # noqa: BLE001 - report any failure honestly
        return {
            "status": "down",
            "detail": f"connection failed: {type(exc).__name__}",
            "latency_ms": round((_utcnow() - started).total_seconds() * 1000, 2),
        }


def check_rabbitmq() -> dict:
    """RabbitMQ management-API check.

    Enabled only when RABBITMQ_MANAGEMENT_URL is configured (optionally
    RABBITMQ_USER / RABBITMQ_PASS). Reports broker availability and queue
    totals only — never credentials, and never claims anything about Arena
    agent session control (that integration is NOT implemented/verified).
    """
    base = os.getenv("RABBITMQ_MANAGEMENT_URL")
    if not base:
        return {
            "status": "not_configured",
            "detail": "set RABBITMQ_MANAGEMENT_URL (e.g. http://localhost:15672) to enable RabbitMQ monitoring",
        }
    started = _utcnow()
    try:
        user = os.getenv("RABBITMQ_USER")
        password = os.getenv("RABBITMQ_PASS")
        auth = (user, password) if user and password else None
        data = _get_json(base.rstrip("/") + "/api/overview", auth=auth)
        qt = data.get("queue_totals", {}) or {}
        latency_ms = round((_utcnow() - started).total_seconds() * 1000, 2)
        return {
            "status": "ok",
            "detail": f"management API at {_host_only(base)}",
            "latency_ms": latency_ms,
            "messages_ready": qt.get("messages_ready"),
            "messages_unacknowledged": qt.get("messages_unacknowledged"),
            "queues": qt.get("queues"),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "down",
            "detail": f"management API unreachable at {_host_only(base)}: {type(exc).__name__}",
            "latency_ms": round((_utcnow() - started).total_seconds() * 1000, 2),
        }


def check_external_api(env_var: str, path: str = "/health") -> dict:
    """Generic HTTP health probe for an external service configured via env
    (e.g. CICC_PLATFORM_API_URL to monitor the integration API)."""
    base = os.getenv(env_var)
    if not base:
        return {
            "status": "not_configured",
            "detail": f"set {env_var} to monitor this dependency",
        }
    url = base.rstrip("/") + path
    started = _utcnow()
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=CHECK_TIMEOUT_S) as resp:
            ok = 200 <= resp.status < 300
            body = resp.read(512).decode(errors="replace")
        latency_ms = round((_utcnow() - started).total_seconds() * 1000, 2)
        return {
            "status": "ok" if ok else "degraded",
            "detail": f"{_host_only(base)} returned HTTP {resp.status}",
            "latency_ms": latency_ms,
            "response_excerpt": body[:200] if ok else None,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "down",
            "detail": f"unreachable at {_host_only(base)}: {type(exc).__name__}",
            "latency_ms": round((_utcnow() - started).total_seconds() * 1000, 2),
        }
