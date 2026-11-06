"""Milestone 10 tests: programmatic task creation (POST /tasks, idempotent),
coordination metrics endpoint, write rate limiting on coordination writes."""
import pytest

from app import ratelimit


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    monkeypatch.delenv("CICC_OPS_WRITE_TOKEN", raising=False)
    monkeypatch.delenv("CICC_OPS_READ_TOKEN", raising=False)
    monkeypatch.delenv("RABBITMQ_AMQP_URL", raising=False)
    yield
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def _task(i=1, **kw):
    body = {"kind": "pr_opened", "title": f"t{i}", "payload": {"n": i},
            "priority": 3, "repo": "oldman-088/cicc", "pr_ref": str(i)}
    body.update(kw)
    return body


def test_create_task_idempotent(client):
    r = client.post("/api/v1/coordination/tasks", json=_task(idempotency_key="k1"))
    assert r.status_code == 201 and r.json()["task_id"].startswith("api-")
    assert r.json()["duplicate"] is False and r.json()["state"] == "CREATED"
    tid = r.json()["task_id"]
    r2 = client.post("/api/v1/coordination/tasks", json=_task(2, idempotency_key="k1"))
    assert r2.status_code == 201 and r2.json()["task_id"] == tid and r2.json()["duplicate"] is True
    # explicit task_id is honored and idempotent too
    r3 = client.post("/api/v1/coordination/tasks", json=_task(3, task_id="my-task-1"))
    assert r3.json()["task_id"] == "my-task-1"
    r4 = client.post("/api/v1/coordination/tasks", json=_task(4, task_id="my-task-1"))
    assert r4.json()["task_id"] == "my-task-1"


def test_create_task_validation(client):
    assert client.post("/api/v1/coordination/tasks", json={"kind": "Bad Kind!"}).status_code == 422
    assert client.post("/api/v1/coordination/tasks", json={"kind": "x", "priority": 99}).status_code == 422
    assert client.post("/api/v1/coordination/tasks", json={"kind": "x", "task_id": "a/b"}).status_code == 422


def test_create_task_requires_approval_goes_waiting(client):
    r = client.post("/api/v1/coordination/tasks", json=_task(requires_approval=True))
    assert r.json()["state"] == "WAITING_FOR_APPROVAL"
    # deliver while waiting -> 409
    tid = r.json()["task_id"]
    assert client.post(f"/api/v1/coordination/tasks/{tid}/deliver").status_code == 409


def test_metrics_endpoint(client):
    client.post("/api/v1/coordination/tasks", json=_task(1))
    client.post("/api/v1/coordination/tasks", json=_task(2))
    client.post("/api/v1/coordination/tasks", json=_task(3, kind="ci_failed"))
    # create a delivery + approval so metrics iterate non-empty tables
    # (regression: field-name mismatch only shows on non-empty rows)
    t1 = client.get("/api/v1/coordination/tasks?kind=pr_opened").json()["tasks"][0]["task_id"]
    client.post(f"/api/v1/coordination/tasks/{t1}/route")
    client.post(f"/api/v1/coordination/tasks/{t1}/deliver")
    client.post("/api/v1/coordination/agents/register", json={"agent": "a1", "capabilities": ["ops"]})
    client.post("/api/v1/coordination/tasks", json=_task(9, requires_approval=True))
    m = client.get("/api/v1/coordination/metrics").json()
    assert m["tasks_total"] == 4
    assert m["by_state"].get("CREATED") == 2 and m["by_state"].get("QUEUED") == 1  # routed task left CREATED
    assert m["by_kind"]["ci_failed"] == 1
    assert m["deliveries_total"] >= 1 and m["deliveries_by_outcome"]
    assert m["agents_registered"] == 1 and m["agents_online"] == 1
    assert m["approvals_pending"] == 1


def test_coordination_writes_rate_limited(client, monkeypatch):
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    monkeypatch.setattr(ratelimit.write_limiter, "limit", 3)
    H = {"Authorization": "Bearer w"}
    codes = [client.post("/api/v1/coordination/tasks", json=_task(i), headers=H).status_code for i in range(5)]
    assert codes[:3] == [201, 201, 201]
    assert codes[3] == 429 and codes[4] == 429
    # reads still fine
    assert client.get("/api/v1/coordination/tasks", headers=H).status_code == 200
