"""Milestone 4 tests: maintenance-window suppression, task history/failure
analytics, worker availability history, retention purge."""
from datetime import timedelta

import pytest

from app import checks, models, ops, ratelimit


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ops._overview_cache["data"] = None
    ops._overview_cache["ts"] = 0.0
    checks.reset_circuit_breakers()
    for v in (
        "CICC_OPS_WRITE_TOKEN", "CICC_OPS_READ_TOKEN", "RABBITMQ_MANAGEMENT_URL",
        "CICC_PLATFORM_API_URL", "OPS_WORKER_STALL_S", "OPS_RETENTION_DAYS",
    ):
        monkeypatch.delenv(v, raising=False)
    yield
    ratelimit.limiter.reset()


def _win_payload(**over):
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    body = {
        "label": "db maintenance",
        "starts_at": (now - timedelta(minutes=5)).isoformat(),
        "ends_at": (now + timedelta(hours=1)).isoformat(),
    }
    body.update(over)
    return body


def test_maintenance_window_suppresses_matching_alert(client, monkeypatch):
    monkeypatch.setattr(ops, "check_database", lambda: {"status": "down", "detail": "maintenance"})
    # no window -> alert fires
    client.get("/api/v1/ops/alerts")
    alerts = client.get("/api/v1/ops/alerts?state=all").json()["alerts"]
    assert any(a["rule"] == "component_down" and a["component_key"] == "database" for a in alerts)
    # resolve it by restoring db
    monkeypatch.setattr(ops, "check_database", lambda: {"status": "ok", "detail": "ok", "latency_ms": 1})
    client.get("/api/v1/ops/alerts")
    # now db down again WITH an active maintenance window covering database
    monkeypatch.setattr(ops, "check_database", lambda: {"status": "down", "detail": "maintenance"})
    r = client.post("/api/v1/ops/maintenance", json=_win_payload(component_keys=["database"]))
    assert r.status_code == 201
    client.get("/api/v1/ops/alerts")
    active = client.get("/api/v1/ops/alerts?state=active").json()["alerts"]
    assert not any(a["rule"] == "component_down" and a["component_key"] == "database" for a in active)
    # window listed as active
    wins = client.get("/api/v1/ops/maintenance?active=true").json()["windows"]
    assert len(wins) == 1 and wins[0]["label"] == "db maintenance"


def test_maintenance_window_scoped_to_other_component_does_not_suppress(client, monkeypatch):
    monkeypatch.setattr(ops, "check_database", lambda: {"status": "down", "detail": "x"})
    client.post("/api/v1/ops/maintenance", json=_win_payload(component_keys=["rabbitmq"]))
    client.get("/api/v1/ops/alerts")
    active = client.get("/api/v1/ops/alerts?state=active").json()["alerts"]
    assert any(a["rule"] == "component_down" and a["component_key"] == "database" for a in active)


def test_maintenance_cancel_and_validation(client):
    r = client.post("/api/v1/ops/maintenance", json=_win_payload(ends_at="2020-01-01T00:00:00+00:00", starts_at="2026-01-01T00:00:00+00:00"))
    assert r.status_code == 422  # ends before starts
    wid = client.post("/api/v1/ops/maintenance", json=_win_payload()).json()["id"]
    r = client.post(f"/api/v1/ops/maintenance/{wid}/cancel")
    assert r.status_code == 200
    r2 = client.post(f"/api/v1/ops/maintenance/{wid}/cancel")
    assert r2.status_code == 409  # already ended
    assert client.post("/api/v1/ops/maintenance/99999/cancel").status_code == 404
    # write token gate
    client2 = client
    import os
    os.environ["CICC_OPS_WRITE_TOKEN"] = "t"
    try:
        assert client2.post("/api/v1/ops/maintenance", json=_win_payload()).status_code == 401
    finally:
        del os.environ["CICC_OPS_WRITE_TOKEN"]


def test_task_history_filters_and_failure_groups(client):
    client.post("/api/v1/ops/tasks", json={"worker": "w1", "queue": "q1", "status": "success", "duration_ms": 5})
    client.post("/api/v1/ops/tasks", json={"worker": "w1", "queue": "q1", "status": "failed", "error": "timeout after 30s"})
    client.post("/api/v1/ops/tasks", json={"worker": "w1", "queue": "q1", "status": "failed", "error": "timeout after 30s"})
    client.post("/api/v1/ops/tasks", json={"worker": "w2", "queue": "q2", "status": "failed", "error": "db locked"})
    tasks = client.get("/api/v1/ops/tasks?status=failed").json()["tasks"]
    assert len(tasks) == 3
    tasks_w1 = client.get("/api/v1/ops/tasks?worker=w1&queue=q1").json()["tasks"]
    assert len(tasks_w1) == 3
    assert client.get("/api/v1/ops/tasks?status=bogus").status_code == 422
    failures = client.get("/api/v1/ops/tasks/failures?hours=1").json()["groups"]
    assert failures[0]["count"] == 2 and failures[0]["worker"] == "w1"
    assert "timeout" in failures[0]["error"]
    assert len(failures) == 2


def test_worker_history_samples_throttled(client, monkeypatch):
    client.post("/api/v1/ops/workers/heartbeat", json={"worker": "wh1"})
    client.post("/api/v1/ops/workers/heartbeat", json={"worker": "wh1"})  # within 60s -> no new sample
    h = client.get("/api/v1/ops/workers/history?worker=wh1").json()
    assert h["sample_interval_s"] == 60
    assert len(h["samples"]) == 1
    # force interval to 0 -> second sample recorded
    monkeypatch.setattr(ops, "HEARTBEAT_SAMPLE_INTERVAL_S", 0)
    client.post("/api/v1/ops/workers/heartbeat", json={"worker": "wh1"})
    h2 = client.get("/api/v1/ops/workers/history?worker=wh1").json()
    assert len(h2["samples"]) == 2
    # all workers when no filter
    h_all = client.get("/api/v1/ops/workers/history").json()
    assert h_all["worker"] is None and len(h_all["samples"]) >= 2


def test_retention_purge_only_old_rows(client, monkeypatch):
    monkeypatch.setenv("OPS_RETENTION_DAYS", "30")
    # create an old event and an old snapshot directly
    with ops.SessionLocal() as s:
        old_ts = ops.utcnow() - timedelta(days=40)
        e = models.Event(level="info", source="test", message="old", ts=old_ts)
        s.add(e)
        snap = models.MetricSnapshot(ts=old_ts, entities=0, vulnerabilities=0, campaigns=0, recent_updates_24h=0)
        s.add(snap)
        s.commit()
    counts = ops.purge_old_data(force=True)
    assert counts["events"] >= 1 and counts["metric_snapshots"] >= 1
    from sqlalchemy import func, select

    with ops.SessionLocal() as s:
        remaining_old = s.execute(
            select(func.count(models.Event.id)).where(models.Event.ts < ops.utcnow() - timedelta(days=35))
        ).scalar_one()
        assert remaining_old == 0
    # fresh rows are NOT purged with 30d retention
    ops.record_event("info", "test", "fresh event")
    ops.purge_old_data(force=True)
    with ops.SessionLocal() as s:
        fresh = s.execute(select(func.count(models.Event.id)).where(models.Event.message == "fresh event")).scalar_one()
        assert fresh == 1


def test_write_token_also_satisfies_read(client, monkeypatch):
    """When both tokens are set, the write token authorizes reads too."""
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r-token")
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w-token")
    assert client.get("/api/v1/ops/maintenance").status_code == 401
    r = client.get("/api/v1/ops/maintenance", headers={"Authorization": "Bearer r-token"})
    assert r.status_code == 200
    r = client.get("/api/v1/ops/maintenance", headers={"Authorization": "Bearer w-token"})
    assert r.status_code == 200
    # write endpoint with write token now passes both gates
    r = client.post(
        "/api/v1/ops/maintenance",
        json={"label": "t", "starts_at": "2026-01-01T00:00:00Z", "ends_at": "2026-01-02T00:00:00Z"},
        headers={"Authorization": "Bearer w-token"},
    )
    assert r.status_code == 201
