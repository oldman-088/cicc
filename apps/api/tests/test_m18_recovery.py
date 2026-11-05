"""M18 — coordination recovery review: stale-agent sweep, retry semantics,
approval rejection audit, illegal-transition audit. Fixture traffic only.
"""
import pytest

from app import models, ops, ratelimit
from app.coordination import agents as agent_registry

W = {"Authorization": "Bearer w", "Content-Type": "application/json"}
R = {"Authorization": "Bearer r"}
APPROVER = {"Authorization": "Bearer w", "Content-Type": "application/json"}  # write token + decided_by in CICC_COORD_APPROVERS


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r")
    monkeypatch.setenv("CICC_COORD_APPROVERS", "owner")
    monkeypatch.setenv("CICC_STALE_AGENT_S", "60")
    monkeypatch.delenv("RABBITMQ_AMQP_URL", raising=False)
    yield
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def _mk(client, tid, **kw):
    body = {"task_id": tid, "kind": "recovery", "payload": {}, **kw}
    r = client.post("/api/v1/coordination/tasks", json=body, headers=W)
    assert r.status_code == 201, r.text
    return tid


def test_contract_descriptor_served(client):
    r = client.get("/api/v1/coordination/contract", headers=R)
    assert r.status_code == 200
    d = r.json()
    assert d["version"] == "1.0" and d["base"] == "/api/v1/coordination"
    assert d["auth"]["tenant"].startswith("PENDING")
    assert "webhook_replay_after_window" in d["idempotency"]["webhook"]
    assert len(d["endpoints"]) >= 20 and "pending" in d["task_states"]
    # read-only: no token -> 401
    assert client.get("/api/v1/coordination/contract").status_code == 401


def test_stale_agent_sweep_and_effective_status(client):
    client.post("/api/v1/coordination/agents/register", json={"agent": "stale-fixture"}, headers=W)
    from datetime import timedelta
    from app.coordination.registry import utcnow
    with ops.SessionLocal() as s:
        a = s.get(models.CoordinationAgent, "stale-fixture")
        a.last_heartbeat = utcnow() - timedelta(seconds=3600)
        s.commit()
    r = client.get("/api/v1/coordination/agents", headers=R).json()["agents"]
    a = [x for x in r if x["agent"] == "stale-fixture"][0]
    assert a["stale"] is True and a["status"] == "offline"
    r = client.post("/api/v1/coordination/sweep", headers=W).json()
    assert "stale-fixture" in r["stale_agents"]
    with ops.SessionLocal() as s:
        a = s.get(models.CoordinationAgent, "stale-fixture")
        assert a.status == "offline"  # persisted, not just computed


def test_retry_from_failed_and_audit(client):
    tid = _mk(client, "m18-retry")
    client.post(f"/api/v1/coordination/tasks/{tid}/route", json={"agent": "stale-fixture"}, headers=W)
    client.post(f"/api/v1/coordination/tasks/{tid}/ack", json={}, headers=W)
    client.post(f"/api/v1/coordination/tasks/{tid}/start", json={}, headers=W)
    r = client.post(f"/api/v1/coordination/tasks/{tid}/fail", json={"result": "boom"}, headers=W)
    assert r.status_code == 200
    r = client.post(f"/api/v1/coordination/tasks/{tid}/retry", headers=W)
    assert r.status_code == 200, r.text
    t = client.get(f"/api/v1/coordination/tasks/{tid}", headers=R).json()
    assert t["state"].lower() == "queued" and (t.get("retries") or t.get("attempts") or 0) >= 1
    ev = client.get(f"/api/v1/coordination/tasks/{tid}/events", headers=R).json()["events"]
    actions = [e.get("kind") for e in ev]
    assert any(a and a.startswith("report:fail") for a in actions) and any(a and "QUEUED" in a for a in actions)


def test_approval_reject_blocks_complete_and_audits(client):
    tid = _mk(client, "m18-appr", requires_approval=True)
    client.post(f"/api/v1/coordination/tasks/{tid}/route", json={"agent": "stale-fixture"}, headers=W)
    client.post(f"/api/v1/coordination/tasks/{tid}/ack", json={}, headers=W)
    client.post(f"/api/v1/coordination/tasks/{tid}/start", json={}, headers=W)
    r = client.post(f"/api/v1/coordination/tasks/{tid}/complete", json={"result": "x"}, headers=W)
    assert r.status_code == 409  # awaiting approval
    r = client.post(f"/api/v1/coordination/tasks/{tid}/reject", json={"decided_by": "owner", "note": "no"}, headers=APPROVER)
    assert r.status_code == 200, r.text
    t = client.get(f"/api/v1/coordination/tasks/{tid}", headers=R).json()
    # rejection is terminal: task FAILED + approval.status=rejected (contract v1.0 semantic)
    assert t["state"].lower() == "failed"
    ap = client.get(f"/api/v1/coordination/tasks/{tid}/approval", headers=R).json()["approval"]
    assert ap["status"] == "rejected"
    r = client.post(f"/api/v1/coordination/tasks/{tid}/complete", json={"result": "x"}, headers=W)
    assert r.status_code == 409  # rejected is terminal
    ev = client.get(f"/api/v1/coordination/tasks/{tid}/events", headers=R).json()["events"]
    assert any(e.get("kind") in ("reject", "approval_rejected") for e in ev)
    # non-approver cannot reject
    tid2 = _mk(client, "m18-appr2", requires_approval=True)
    r = client.post(f"/api/v1/coordination/tasks/{tid2}/reject", json={"decided_by": "w"}, headers=W)
    assert r.status_code == 403
