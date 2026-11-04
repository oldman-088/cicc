"""Milestone 6 tests (ops): MAINTENANCE health state, time-based + per-rule
alert escalation, alert ownership/assignment, worker registry, task attempts,
per-principal write rate limit, notifications-disabled guarantee."""
import hashlib
from datetime import timedelta

import pytest
from sqlalchemy import text

from app import models, notifications, ops, ratelimit


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    ops._overview_cache["data"] = None
    ops._overview_cache["ts"] = 0.0
    for v in (
        "CICC_OPS_WRITE_TOKEN", "CICC_OPS_READ_TOKEN", "RABBITMQ_MANAGEMENT_URL",
        "OPS_ALERT_ESCALATE_OCCURRENCES", "OPS_ALERT_ESCALATE_AFTER_S",
        "OPS_ALERT_ESCALATE_RULES", "OPS_ALERT_FLAP_WINDOW_S",
        "OPS_DB_LATENCY_WARN_MS", "OPS_WRITE_RATE_LIMIT", "OPS_NOTIFY_ENABLED",
        "OPS_NOTIFY_CHANNELS", "CICC_OPS_USE_PLATFORM_AUTH", "CICC_PLATFORM_DB_URL",
    ):
        monkeypatch.delenv(v, raising=False)
    yield
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def _win(**over):
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    body = {"label": "db maint", "starts_at": (now - timedelta(minutes=5)).isoformat(),
            "ends_at": (now + timedelta(hours=1)).isoformat()}
    body.update(over)
    return body


# ---------- MAINTENANCE health state ----------

def test_active_window_sets_maintenance_state(client, monkeypatch):
    monkeypatch.setattr(ops, "check_database", lambda: {"status": "ok", "detail": "ok", "latency_ms": 1})
    r = client.post("/api/v1/ops/maintenance", json=_win(component_keys=["database"]))
    assert r.status_code == 201
    ov = client.get("/api/v1/ops/overview").json()
    db = next(x for x in ov["services"] if x["key"] == "database")
    assert db["status"] == "maintenance"
    assert "maintenance window" in db["detail"]
    assert ov["overall_status"] in ("ok", "degraded")  # maintenance is not "down"


# ---------- time-based + per-rule escalation ----------

def _force_slow(monkeypatch, latency=50.0):
    monkeypatch.setenv("OPS_DB_LATENCY_WARN_MS", "1")
    monkeypatch.setattr(ops, "check_database",
                        lambda: {"status": "ok", "detail": "ok", "latency_ms": latency})


def test_time_based_escalation(monkeypatch):
    monkeypatch.setenv("OPS_ALERT_ESCALATE_OCCURRENCES", "1000")  # occ-based off
    monkeypatch.setenv("OPS_ALERT_ESCALATE_AFTER_S", "0")          # time-based immediate
    _force_slow(monkeypatch)
    ops.evaluate_alerts()
    a = ops.build_alerts("active")[0]
    assert a["severity"] == "warning" and a["escalated"] is False
    ops.evaluate_alerts()  # same alert, now "old" -> escalate
    a = ops.build_alerts("active")[0]
    assert a["severity"] == "critical" and a["escalated"] is True


def test_per_rule_escalation_override(monkeypatch):
    monkeypatch.setenv("OPS_ALERT_ESCALATE_OCCURRENCES", "1000")
    monkeypatch.setenv("OPS_ALERT_ESCALATE_AFTER_S", "99999")
    monkeypatch.setenv("OPS_ALERT_ESCALATE_RULES", '{"database_slow": {"occurrences": 2, "after_s": 99999}}')
    _force_slow(monkeypatch)
    ops.evaluate_alerts()  # occ=1
    ops.evaluate_alerts()  # occ=2 -> per-rule threshold hits
    a = ops.build_alerts("active")[0]
    assert a["escalated"] is True and a["severity"] == "critical"


# ---------- notifications disabled guarantee ----------

def test_notifications_never_send(monkeypatch):
    import urllib.request

    def _boom(*a, **k):
        raise AssertionError("network call attempted from notifications module")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    monkeypatch.setenv("OPS_NOTIFY_ENABLED", "1")
    monkeypatch.setenv("OPS_NOTIFY_CHANNELS", "email,slack")
    r = notifications.notify_alert({"id": 1, "rule": "r", "severity": "critical"}, reason="test")
    assert r["sent"] is False  # no authorized adapter exists -> still nothing sent
    monkeypatch.delenv("OPS_NOTIFY_ENABLED")
    r = notifications.notify_alert({"id": 1, "rule": "r", "severity": "warning"})
    assert r["sent"] is False and "disabled" in r["reason"]


# ---------- worker registry ----------

def test_worker_register_and_list(client, monkeypatch):
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r")
    H = {"Authorization": "Bearer w"}
    R = {"Authorization": "Bearer r"}
    r = client.post("/api/v1/ops/workers/register", json={"worker": "w-9", "queue": "q1", "version": "1.2.3", "capabilities": ["ingest", "enrich"]}, headers=H)
    assert r.status_code == 201 and r.json()["created"] is True
    r = client.post("/api/v1/ops/workers/register", json={"worker": "w-9", "queue": "q1"}, headers=H)
    assert r.json()["created"] is False  # idempotent
    workers = client.get("/api/v1/ops/workers", headers=R).json()["workers"]
    w9 = next(w for w in workers if w["worker"] == "w-9")
    assert w9["registered"] is True and w9["version"] == "1.2.3" and w9["capabilities"] == ["ingest", "enrich"]
    assert w9["stalled"] is True  # registered but no heartbeat yet
    # heartbeat clears stalled
    client.post("/api/v1/ops/workers/heartbeat", json={"worker": "w-9"}, headers=H)
    workers = client.get("/api/v1/ops/workers", headers=R).json()["workers"]
    assert next(w for w in workers if w["worker"] == "w-9")["stalled"] is False


# ---------- task attempts ----------

def test_task_attempts_recorded(client, monkeypatch):
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r")
    H = {"Authorization": "Bearer w"}
    r = client.post("/api/v1/ops/tasks", json={"worker": "w", "queue": "q", "status": "failed", "error": "x", "attempts": 3}, headers=H)
    assert r.status_code == 201
    tasks = client.get("/api/v1/ops/tasks?status=failed", headers={"Authorization": "Bearer r"}).json()["tasks"]
    assert tasks[0]["attempts"] == 3
    r = client.post("/api/v1/ops/tasks", json={"worker": "w", "queue": "q", "status": "success", "attempts": 0}, headers=H)
    assert r.status_code == 422  # attempts ge=1


# ---------- alert ownership / assign ----------

def test_alert_assign_owner(client, monkeypatch):
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r")
    _force_slow(monkeypatch)
    client.get("/api/v1/ops/alerts", headers={"Authorization": "Bearer r"})
    a = client.get("/api/v1/ops/alerts?state=active", headers={"Authorization": "Bearer r"}).json()["alerts"][0]
    r = client.post(f"/api/v1/ops/alerts/{a['id']}/assign", json={"owner": "agent-1"}, headers={"Authorization": "Bearer w"})
    assert r.status_code == 200 and r.json()["owner"] == "agent-1"
    r = client.post(f"/api/v1/ops/alerts/{a['id']}/assign", json={"owner": "x"})  # no write token
    assert r.status_code == 401
    again = client.get("/api/v1/ops/alerts?state=all", headers={"Authorization": "Bearer r"}).json()["alerts"]
    assert next(x for x in again if x["id"] == a["id"])["owner"] == "agent-1"


# ---------- per-principal write rate limit ----------

def test_keyed_write_rate_limit(monkeypatch, client):
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    monkeypatch.setenv("OPS_WRITE_RATE_LIMIT", "3")
    ratelimit.write_limiter.limit = 3
    H = {"Authorization": "Bearer w"}
    codes = [client.post("/api/v1/ops/tasks", json={"worker": "w", "queue": "q", "status": "success"}, headers=H).status_code for _ in range(5)]
    assert codes[:3] == [201, 201, 201]
    assert codes[3] == 429 and codes[4] == 429
    # a different principal has its own bucket
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w2")
    H2 = {"Authorization": "Bearer w2"}
    assert client.post("/api/v1/ops/tasks", json={"worker": "w", "queue": "q", "status": "success"}, headers=H2).status_code == 201
