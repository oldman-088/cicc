"""Milestone 5 tests: alert escalation + flap detection, SQL-aggregated task
stats (perf regression), additive alert columns, platform-auth adapter
(conformance fixture mirroring the VERIFIED platform contract on
arena/da631853-cicc — fixture, not a live platform)."""
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text

from app import models, ops, platform_auth, ratelimit


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ops._overview_cache["data"] = None
    ops._overview_cache["ts"] = 0.0
    for v in (
        "CICC_OPS_WRITE_TOKEN", "CICC_OPS_READ_TOKEN", "RABBITMQ_MANAGEMENT_URL",
        "CICC_OPS_USE_PLATFORM_AUTH", "CICC_PLATFORM_DB_URL",
        "OPS_ALERT_ESCALATE_OCCURRENCES", "OPS_ALERT_FLAP_WINDOW_S",
        "OPS_DB_LATENCY_WARN_MS", "OPS_WORKER_STALL_S",
    ):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setattr(platform_auth, "_engine", None)
    yield
    ratelimit.limiter.reset()


# ---------- task stats: SQL aggregation regression ----------

def test_task_stats_sql_aggregation_matches_rowwise():
    now = ops.utcnow()
    with ops.SessionLocal() as s:
        for i in range(100):
            s.add(models.TaskRun(worker="w", queue="q", status="success", duration_ms=i, created_at=now))
        for i in range(10):
            s.add(models.TaskRun(worker="w", queue="q", status="failed", duration_ms=1000 + i, error="x", created_at=now))
        for i in range(5):
            s.add(models.TaskRun(worker="w", queue="q", status="running", started_at=now - timedelta(minutes=i), created_at=now))
        s.commit()
    stats = ops.build_task_stats(24)
    assert stats["completed"] == 100
    assert stats["failed"] == 10
    assert stats["pending"] == 5
    expected_avg = round((sum(range(100)) + sum(range(1000, 1010))) / 110, 2)
    assert stats["avg_duration_ms"] == expected_avg
    assert stats["oldest_pending_started"] is not None


# ---------- alert escalation ----------

def _force_database_slow(monkeypatch, latency=50.0):
    monkeypatch.setenv("OPS_DB_LATENCY_WARN_MS", "1")
    monkeypatch.setattr(
        ops, "check_database",
        lambda: {"status": "ok", "detail": "ok", "latency_ms": latency},
    )


def test_alert_escalation_bumps_severity_once(monkeypatch):
    monkeypatch.setenv("OPS_ALERT_ESCALATE_OCCURRENCES", "3")
    _force_database_slow(monkeypatch)
    ops.evaluate_alerts()  # occ=1 warning
    ops.evaluate_alerts()  # occ=2 warning
    a = ops.build_alerts("active")[0]
    assert a["severity"] == "warning" and a["escalated"] is False
    ops.evaluate_alerts()  # occ=3 -> escalate
    a = ops.build_alerts("active")[0]
    assert a["severity"] == "critical" and a["escalated"] is True and a["occurrences"] == 3
    ops.evaluate_alerts()  # occ=4 -> no further change (already escalated)
    a = ops.build_alerts("active")[0]
    assert a["severity"] == "critical" and a["occurrences"] == 4
    with ops.SessionLocal() as s:
        evs = s.execute(text("SELECT message FROM events WHERE source='alerts'")).scalars().all()
    assert any("ESCALATED" in e for e in evs)


# ---------- flap detection ----------

def test_flap_detection_marks_unstable_alert(monkeypatch):
    monkeypatch.setenv("OPS_ALERT_FLAP_WINDOW_S", "300")
    _force_database_slow(monkeypatch)
    ops.evaluate_alerts()                       # fire #1
    monkeypatch.setattr(ops, "check_database", lambda: {"status": "ok", "detail": "ok", "latency_ms": 1})
    ops.evaluate_alerts()                       # resolve #1 (no prior -> not flapping)
    _force_database_slow(monkeypatch)
    ops.evaluate_alerts()                       # fire #2 (no flapping resolved yet)
    monkeypatch.setattr(ops, "check_database", lambda: {"status": "ok", "detail": "ok", "latency_ms": 1})
    ops.evaluate_alerts()                       # resolve #2 (prior resolved within window -> flapping)
    alerts = ops.build_alerts("all")
    flapping = [a for a in alerts if a["flapping"]]
    assert len(flapping) == 1
    _force_database_slow(monkeypatch)
    ops.evaluate_alerts()                       # fire #3 -> new alert flapping=True
    active = ops.build_alerts("active")
    assert len(active) == 1 and active[0]["flapping"] is True


# ---------- additive columns idempotent ----------

def test_ensure_alert_columns_idempotent():
    ops._ensure_alert_columns()
    ops._ensure_alert_columns()  # second run must not error
    with ops.SessionLocal() as s:
        s.add(models.Alert(rule="r", severity="info", status="active", message="m"))
        s.commit()
    a = ops.build_alerts("all")[0]
    assert a["escalated"] is False and a["flapping"] is False


# ---------- platform auth adapter (conformance fixture) ----------

def _make_platform_db(tmp_path):
    url = "sqlite:///" + str(tmp_path / "platform.db")
    eng = create_engine(url)
    with eng.begin() as c:
        c.execute(text("CREATE TABLE tenants (id TEXT PRIMARY KEY)"))
        c.execute(text(
            "CREATE TABLE users (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, "
            "username TEXT, role TEXT, active INTEGER, password_hash TEXT)"))
        c.execute(text(
            "CREATE TABLE auth_sessions (id TEXT PRIMARY KEY, tenant_id TEXT, user_id TEXT, "
            "token_digest TEXT UNIQUE, created_at TEXT, expires_at TEXT, revoked_at TEXT)"))
        now = datetime.now(timezone.utc)
        fut = (now + timedelta(hours=1)).isoformat()
        past = (now - timedelta(hours=1)).isoformat()
        c.execute(text("INSERT INTO tenants VALUES ('t1')"))
        c.execute(text("INSERT INTO users VALUES ('u1','t1','admin','admin',1,'x')"))
        c.execute(text("INSERT INTO users VALUES ('u2','t1','viewer','viewer',1,'x')"))
        for tok, uid, exp, rev in [
            ("good-admin", "u1", fut, None),
            ("good-viewer", "u2", fut, None),
            ("expired", "u1", past, None),
            ("revoked", "u1", fut, now.isoformat()),
        ]:
            c.execute(
                text("INSERT INTO auth_sessions VALUES (:i,'t1',:u,:d,:c,:e,:r)"),
                {"i": "s-" + tok, "u": uid, "d": hashlib.sha256(tok.encode()).hexdigest(),
                 "c": now.isoformat(), "e": exp, "r": rev},
            )
    eng.dispose()
    return url


def test_platform_auth_resolve_principal(tmp_path, monkeypatch):
    url = _make_platform_db(tmp_path)
    monkeypatch.setenv("CICC_OPS_USE_PLATFORM_AUTH", "1")
    monkeypatch.setenv("CICC_PLATFORM_DB_URL", url)
    monkeypatch.setattr(platform_auth, "_engine", None)
    p = platform_auth.resolve_principal("Bearer good-admin")
    assert p and p["role"] == "admin" and p["tenant_id"] == "t1"
    assert platform_auth.read_allowed(p) and platform_auth.write_allowed(p)
    v = platform_auth.resolve_principal("Bearer good-viewer")
    assert v and platform_auth.read_allowed(v) and not platform_auth.write_allowed(v)
    for bad in ("Bearer nope", "Bearer expired", "Bearer revoked", "", None, "Basic x"):
        assert platform_auth.resolve_principal(bad) is None
    # disabled -> inert
    monkeypatch.delenv("CICC_OPS_USE_PLATFORM_AUTH")
    monkeypatch.setattr(platform_auth, "_engine", None)
    assert platform_auth.resolve_principal("Bearer good-admin") is None


def test_platform_auth_http_gate(tmp_path, monkeypatch, client):
    url = _make_platform_db(tmp_path)
    monkeypatch.setenv("CICC_OPS_USE_PLATFORM_AUTH", "1")
    monkeypatch.setenv("CICC_PLATFORM_DB_URL", url)
    monkeypatch.setattr(platform_auth, "_engine", None)
    assert client.get("/api/v1/ops/overview").status_code == 401
    assert client.get("/api/v1/ops/overview", headers={"Authorization": "Bearer bad"}).status_code == 401
    r = client.get("/api/v1/ops/overview", headers={"Authorization": "Bearer good-admin"})
    assert r.status_code == 200
    r = client.get("/api/v1/ops/overview", headers={"Authorization": "Bearer good-viewer"})
    assert r.status_code == 200  # viewer may read
    # writes: viewer denied, admin allowed
    body = {"worker": "w", "queue": "q", "status": "success", "duration_ms": 1}
    assert client.post("/api/v1/ops/tasks", json=body, headers={"Authorization": "Bearer good-viewer"}).status_code == 401
    r = client.post("/api/v1/ops/tasks", json=body, headers={"Authorization": "Bearer good-admin"})
    assert r.status_code == 201


# ---------- RabbitMQ management parsing: FIXTURE test ----------
# Payloads below are FIXTURES modeled on the official RabbitMQ management
# HTTP API schema (rabbitmq-server deps/rabbitmq_management docs). This is
# NOT a live broker response; live verification = scripts/verify_rabbitmq.py.

OVERVIEW_FIXTURE = {
    "cluster_name": "rabbit@broker", "rabbitmq_version": "3.13.7",
    "queue_totals": {"messages_ready": 42, "messages_unacknowledged": 3, "queues": 7},
}
QUEUES_FIXTURE = [
    {"name": "tasks", "messages_ready": 40, "consumers": 2, "arguments": {}},
    {"name": "tasks.dlq", "messages_ready": 2, "consumers": 0,
     "arguments": {"x-dead-letter-exchange": "tasks.dlx"}},
]
CONSUMERS_FIXTURE = [{"queue_name": "tasks", "consumer_tag": "c1"}, {"queue_name": "tasks", "consumer_tag": "c2"}]


def test_rabbitmq_management_parsing_fixture(monkeypatch):
    from app import checks

    monkeypatch.setenv("RABBITMQ_MANAGEMENT_URL", "http://broker:15672")
    monkeypatch.delenv("RABBITMQ_USER", raising=False)
    monkeypatch.delenv("RABBITMQ_PASS", raising=False)
    checks.reset_circuit_breakers()

    def fake_get_json(url, timeout=2.0, auth=None):
        if url.endswith("/api/overview"):
            return OVERVIEW_FIXTURE
        if url.endswith("/api/queues"):
            return QUEUES_FIXTURE
        if url.endswith("/api/consumers"):
            return CONSUMERS_FIXTURE
        raise AssertionError(url)

    monkeypatch.setattr(checks, "_get_json", fake_get_json)
    r = checks.check_rabbitmq()
    assert r["status"] == "ok"
    assert r["messages_ready"] == 42
    assert r["messages_unacknowledged"] == 3
    assert r["queues"] == 2  # from /api/queues (overrides queue_totals.queues)
    assert r["consumers"] == 2
    assert r["dead_letter_queues"] == 1
    # no credentials leak into any output
    assert "guest" not in str(r) and "Authorization" not in str(r)


def test_rabbitmq_not_configured_without_url(monkeypatch):
    from app import checks

    monkeypatch.delenv("RABBITMQ_MANAGEMENT_URL", raising=False)
    checks.reset_circuit_breakers()
    r = checks.check_rabbitmq()
    assert r["status"] == "not_configured"
