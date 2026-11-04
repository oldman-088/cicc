"""Alert engine tests: real rule evaluation, dedup, ack/resolve, thresholds.
Broker-dependent rules use a monkeypatched _get_json (SIMULATED broker —
labelled, never claimed live)."""
import pytest

from app import checks, models, ops, ratelimit


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ops._overview_cache["data"] = None
    ops._overview_cache["ts"] = 0.0
    checks.reset_circuit_breakers()
    for v in (
        "RABBITMQ_MANAGEMENT_URL", "RABBITMQ_USER", "RABBITMQ_PASS",
        "CICC_PLATFORM_API_URL", "CICC_OPS_WRITE_TOKEN", "CICC_OPS_READ_TOKEN",
        "OPS_CB_FAILURES", "OPS_CB_COOLDOWN_S", "OPS_DB_LATENCY_WARN_MS",
        "OPS_WORKER_STALL_S", "OPS_TASK_FAIL_THRESHOLD", "OPS_QUEUE_BACKLOG_THRESHOLD",
    ):
        monkeypatch.delenv(v, raising=False)
    yield
    ratelimit.limiter.reset()
    checks.reset_circuit_breakers()


def _db_alerts(client, rule="component_down", key="database"):
    alerts = client.get("/api/v1/ops/alerts?state=all").json()["alerts"]
    return [a for a in alerts if a["rule"] == rule and a["component_key"] == key]


def test_component_down_creates_critical_active_alert(client, monkeypatch):
    monkeypatch.setattr(ops, "check_database", lambda: {"status": "down", "detail": "boom"})
    r = client.get("/api/v1/ops/alerts")
    assert r.status_code == 200
    matches = [a for a in r.json()["alerts"] if a["rule"] == "component_down" and a["component_key"] == "database"]
    assert len(matches) == 1
    assert matches[0]["severity"] == "critical"
    assert matches[0]["status"] == "active"
    assert matches[0]["occurrences"] == 1
    assert "DOWN" in matches[0]["message"]


def test_alert_dedup_then_resolve(client, monkeypatch):
    monkeypatch.setattr(ops, "check_database", lambda: {"status": "down", "detail": "x"})
    client.get("/api/v1/ops/alerts")
    client.get("/api/v1/ops/alerts")
    client.get("/api/v1/ops/alerts")
    alerts = _db_alerts(client)
    assert len(alerts) == 1  # deduplicated
    assert alerts[0]["occurrences"] >= 3
    assert alerts[0]["status"] == "active"
    # condition clears -> resolved, kept in history
    monkeypatch.setattr(ops, "check_database", lambda: {"status": "ok", "detail": "ok", "latency_ms": 1})
    client.get("/api/v1/ops/alerts")
    alerts = _db_alerts(client)
    assert alerts[0]["status"] == "resolved"
    assert alerts[0]["resolved_at"]
    # active list no longer contains it
    active = client.get("/api/v1/ops/alerts?state=active").json()["alerts"]
    assert not any(a["rule"] == "component_down" and a["component_key"] == "database" for a in active)


def test_ack_and_resolve_flow(client, monkeypatch):
    monkeypatch.setattr(ops, "check_database", lambda: {"status": "down", "detail": "x"})
    a = client.get("/api/v1/ops/alerts").json()["alerts"][0]
    r = client.post(f"/api/v1/ops/alerts/{a['id']}/ack", json={"acked_by": "lead"})
    assert r.status_code == 200
    assert r.json()["status"] == "acknowledged"
    got = client.get("/api/v1/ops/alerts?state=acknowledged").json()["alerts"]
    assert any(x["id"] == a["id"] and x["acked_by"] == "lead" for x in got)
    r2 = client.post(f"/api/v1/ops/alerts/{a['id']}/resolve")
    assert r2.status_code == 200 and r2.json()["status"] == "resolved"
    assert client.post(f"/api/v1/ops/alerts/{a['id']}/ack", json={}).status_code == 409
    assert client.post("/api/v1/ops/alerts/99999/ack", json={}).status_code == 404
    assert client.post("/api/v1/ops/alerts/99999/resolve").status_code == 404


def test_database_slow_threshold(client, monkeypatch):
    monkeypatch.setenv("OPS_DB_LATENCY_WARN_MS", "1")
    monkeypatch.setattr(ops, "check_database", lambda: {"status": "ok", "detail": "ok", "latency_ms": 50})
    alerts = client.get("/api/v1/ops/alerts").json()["alerts"]
    assert any(a["rule"] == "database_slow" for a in alerts)


def test_task_failure_threshold_alert(client, monkeypatch):
    monkeypatch.setenv("OPS_TASK_FAIL_THRESHOLD", "3")
    for _ in range(3):
        client.post("/api/v1/ops/tasks", json={"worker": "w1", "queue": "q", "status": "failed", "error": "boom"})
    alerts = client.get("/api/v1/ops/alerts").json()["alerts"]
    assert any(a["rule"] == "task_failures" for a in alerts)


def test_worker_stalled_alert(client, monkeypatch):
    monkeypatch.setenv("OPS_WORKER_STALL_S", "0")
    client.post("/api/v1/ops/workers/heartbeat", json={"worker": "stale-w"})
    alerts = client.get("/api/v1/ops/alerts").json()["alerts"]
    assert any(a["rule"] == "worker_stalled" and a["component_key"] == "stale-w" for a in alerts)


def test_queue_backlog_alert_simulated_broker(client, monkeypatch):
    """SIMULATED broker: _get_json is monkeypatched; never claimed as live."""
    monkeypatch.setenv("RABBITMQ_MANAGEMENT_URL", "http://broker.sim/")
    monkeypatch.setenv("OPS_QUEUE_BACKLOG_THRESHOLD", "5")

    def fake_get_json(url, timeout=2.0, auth=None):
        if url.endswith("/api/overview"):
            return {"queue_totals": {"messages_ready": 42, "messages_unacknowledged": 3, "queues": 2}}
        if url.endswith("/api/queues"):
            return [{"name": "arena", "arguments": {}}, {"name": "arena.dlx", "arguments": {"x-dead-letter-exchange": "dlx"}}]
        if url.endswith("/api/consumers"):
            return [{"consumer_tag": "c1"}, {"consumer_tag": "c2"}]
        raise AssertionError(url)

    monkeypatch.setattr(checks, "_get_json", fake_get_json)
    services = {s["key"]: s for s in client.get("/api/v1/ops/components").json()["services"]}
    mq = services["rabbitmq"]
    assert mq["status"] == "ok"
    assert mq["check"]["messages_ready"] == 42
    assert mq["check"]["consumers"] == 2
    assert mq["check"]["dead_letter_queues"] == 1
    alerts = client.get("/api/v1/ops/alerts").json()["alerts"]
    assert any(a["rule"] == "queue_backlog" for a in alerts)


def test_alert_state_filter_validation(client):
    assert client.get("/api/v1/ops/alerts?state=bogus").status_code == 422
