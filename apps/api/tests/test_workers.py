"""Worker heartbeat / workers-list / stalled detection tests."""
import pytest

from app import checks, models, ops, ratelimit
from app.db import SessionLocal


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ops._overview_cache["data"] = None
    ops._overview_cache["ts"] = 0.0
    checks.reset_circuit_breakers()
    for v in ("CICC_OPS_WRITE_TOKEN", "OPS_WORKER_STALL_S", "RABBITMQ_MANAGEMENT_URL", "CICC_PLATFORM_API_URL"):
        monkeypatch.delenv(v, raising=False)
    yield
    ratelimit.limiter.reset()


def test_heartbeat_upsert(client):
    r = client.post("/api/v1/ops/workers/heartbeat", json={"worker": "w1", "details": "boot"})
    assert r.status_code == 201 and r.json()["created"] is True
    r2 = client.post("/api/v1/ops/workers/heartbeat", json={"worker": "w1", "details": "tick"})
    assert r2.status_code == 201 and r2.json()["created"] is False
    workers = client.get("/api/v1/ops/workers").json()
    assert workers["stall_threshold_s"] == 120.0
    w = [w for w in workers["workers"] if w["worker"] == "w1"]
    assert len(w) == 1
    assert w[0]["stalled"] is False
    assert w[0]["age_s"] is not None and w[0]["age_s"] >= 0


def test_workers_list_task_stats(client):
    client.post("/api/v1/ops/workers/heartbeat", json={"worker": "w2"})
    client.post("/api/v1/ops/tasks", json={"worker": "w2", "queue": "q", "status": "success", "duration_ms": 10})
    client.post("/api/v1/ops/tasks", json={"worker": "w2", "queue": "q", "status": "failed", "error": "x"})
    workers = client.get("/api/v1/ops/workers").json()["workers"]
    w = next(w for w in workers if w["worker"] == "w2")
    assert w["tasks_24h"] == 2
    assert w["failed_24h"] == 1


def test_stalled_worker_detection(client, monkeypatch):
    monkeypatch.setenv("OPS_WORKER_STALL_S", "0")
    client.post("/api/v1/ops/workers/heartbeat", json={"worker": "old-w"})
    workers = client.get("/api/v1/ops/workers").json()["workers"]
    w = next(w for w in workers if w["worker"] == "old-w")
    assert w["stalled"] is True


def test_workers_service_ok_when_heartbeat_fresh(client):
    # default stall threshold is 120 s, so a just-posted heartbeat is fresh
    client.post("/api/v1/ops/workers/heartbeat", json={"worker": "fresh-w"})
    services = {s["key"]: s for s in client.get("/api/v1/ops/components").json()["services"]}
    assert services["workers"]["status"] == "ok"


def test_heartbeat_requires_token_when_set(client, monkeypatch):
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "tok")
    assert client.post("/api/v1/ops/workers/heartbeat", json={"worker": "w"}).status_code == 401
    r = client.post("/api/v1/ops/workers/heartbeat", json={"worker": "w"}, headers={"Authorization": "Bearer tok"})
    assert r.status_code == 201


def test_heartbeat_validation(client):
    assert client.post("/api/v1/ops/workers/heartbeat", json={"worker": ""}).status_code == 422
    assert client.post("/api/v1/ops/workers/heartbeat", json={"worker": "w", "details": "x" * 600}).status_code == 422
