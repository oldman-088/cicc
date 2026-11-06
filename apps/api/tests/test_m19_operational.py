"""M19 — operational quality: dependency gate on complete (defect fix),
dead-letter after max attempts, audit completeness. Fixture traffic only.
"""
import pytest

from app import models, ops, ratelimit

W = {"Authorization": "Bearer w", "Content-Type": "application/json"}
R = {"Authorization": "Bearer r"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r")
    monkeypatch.setenv("CICC_COORD_APPROVERS", "owner")
    monkeypatch.setenv("CICC_COORD_MAX_ATTEMPTS", "2")
    monkeypatch.delenv("RABBITMQ_AMQP_URL", raising=False)
    yield
    # (agent fixture registered per-test via client)
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def _mk(client, tid, **kw):
    body = {"task_id": tid, "kind": "m19", "payload": {}, **kw}
    r = client.post("/api/v1/coordination/tasks", json=body, headers=W)
    assert r.status_code == 201, r.text


def _run_to_running(client, tid, agent="a1"):
    client.post("/api/v1/coordination/agents/register", json={"agent": agent}, headers=W)
    client.post(f"/api/v1/coordination/tasks/{tid}/route", json={"agent": agent}, headers=W)
    client.post(f"/api/v1/coordination/tasks/{tid}/ack", json={}, headers=W)
    client.post(f"/api/v1/coordination/tasks/{tid}/start", json={}, headers=W)


def test_complete_blocked_until_deps_completed(client):
    _mk(client, "m19-blocker")
    _mk(client, "m19-waiting", depends_on=["m19-blocker"])
    # routing with unmet deps blocks the task
    r = client.post("/api/v1/coordination/tasks/m19-waiting/route", json={"agent": "a1"}, headers=W)
    t = client.get("/api/v1/coordination/tasks/m19-waiting", headers=R).json()
    assert t["state"].lower() in ("blocked", "queued"), t["state"]
    r = client.post("/api/v1/coordination/tasks/m19-waiting/complete", json={"result": "x"}, headers=W)
    assert r.status_code == 409, r.text  # gate: deps not COMPLETED
    ev = client.get("/api/v1/coordination/tasks/m19-waiting/events", headers=R).json()["events"]
    assert any("BLOCKED" in (e["kind"] or "") or e["kind"] == "report:complete_blocked_deps" or (e["kind"] or "").startswith("report:complete") for e in ev)
    # complete the blocker, then the waiting task can run to completion
    _run_to_running(client, "m19-blocker")
    assert client.post("/api/v1/coordination/tasks/m19-blocker/complete", json={"result": "ok"}, headers=W).status_code == 200
    client.post("/api/v1/coordination/tasks/m19-waiting/retry", headers=W)
    _run_to_running(client, "m19-waiting")
    r = client.post("/api/v1/coordination/tasks/m19-waiting/complete", json={"result": "x"}, headers=W)
    assert r.status_code == 200 and r.json()["applied"] is True


def test_depends_on_missing_task_blocks(client):
    _mk(client, "m19-ghost", depends_on=["does-not-exist"])
    client.post("/api/v1/coordination/tasks/m19-ghost/route", json={"agent": "a1"}, headers=W)
    r = client.post("/api/v1/coordination/tasks/m19-ghost/complete", json={"result": "x"}, headers=W)
    assert r.status_code == 409  # missing dep counts as not completed


def test_dead_letter_after_max_attempts_and_retry_still_possible(client):
    _mk(client, "m19-dl")
    for i in range(3):  # max attempts = 2 -> dead-letter on 3rd failure path
        _run_to_running(client, "m19-dl")
        client.post("/api/v1/coordination/tasks/m19-dl/fail", json={"result": f"boom{i}"}, headers=W)
        t = client.get("/api/v1/coordination/tasks/m19-dl", headers=R).json()
        if t["state"].lower() in ("blocked", "failed"):
            break
        client.post("/api/v1/coordination/tasks/m19-dl/retry", headers=W)
    t = client.get("/api/v1/coordination/tasks/m19-dl", headers=R).json()
    assert t["dead_letter"] is True or t["state"].lower() == "blocked"
    ev = client.get("/api/v1/coordination/tasks/m19-dl/events", headers=R).json()["events"]
    assert any(e["kind"] == "dead_letter" for e in ev)
    # manual retry from blocked still requeues (M18 fix)
    r = client.post("/api/v1/coordination/tasks/m19-dl/retry", headers=W)
    assert r.status_code == 200, r.text
    assert client.get("/api/v1/coordination/tasks/m19-dl", headers=R).json()["state"].lower() == "queued"


def test_audit_completeness_every_transition_recorded(client):
    _mk(client, "m19-audit")
    _run_to_running(client, "m19-audit")
    client.post("/api/v1/coordination/tasks/m19-audit/complete", json={"result": "done"}, headers=W)
    client.post("/api/v1/coordination/tasks/m19-audit/complete", json={"result": "again"}, headers=W)  # rejected
    ev = client.get("/api/v1/coordination/tasks/m19-audit/events", headers=R).json()["events"]
    kinds = [e["kind"] for e in ev]
    assert "created" in kinds
    assert any(k and k.startswith("state:") and "COMPLETED" in k for k in kinds), kinds
    assert any(k == "transition_rejected" or (k or "").startswith("report:complete") for k in kinds), kinds
