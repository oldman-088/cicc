"""M23 — lifecycle & agent-health reliability. Fixture traffic only."""
import pytest

from app import models, ops, ratelimit
from sqlalchemy import select

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
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def _mk(client, tid, **kw):
    body = {"task_id": tid, "kind": "m23", "payload": {}, **kw}
    assert client.post("/api/v1/coordination/tasks", json=body, headers=W).status_code == 201


def _run(client, tid, agent="a1"):
    client.post("/api/v1/coordination/agents/register", json={"agent": agent}, headers=W)
    client.post(f"/api/v1/coordination/tasks/{tid}/route", json={"agent": agent}, headers=W)
    client.post(f"/api/v1/coordination/tasks/{tid}/ack", json={}, headers=W)
    client.post(f"/api/v1/coordination/tasks/{tid}/start", json={}, headers=W)


def test_dead_letter_flag_cleared_on_revive(client):
    """M23 defect: retried task kept dead_letter=true while QUEUED (contradiction)."""
    _mk(client, "m23-dl")
    for i in range(3):
        _run(client, "m23-dl")
        client.post("/api/v1/coordination/tasks/m23-dl/fail", json={"result": f"b{i}"}, headers=W)
        t = client.get("/api/v1/coordination/tasks/m23-dl", headers=R).json()
        if t["dead_letter"]:
            break
        client.post("/api/v1/coordination/tasks/m23-dl/retry", headers=W)
    t = client.get("/api/v1/coordination/tasks/m23-dl", headers=R).json()
    assert t["dead_letter"] is True and t["state"].lower() in ("blocked", "failed")
    assert client.post("/api/v1/coordination/tasks/m23-dl/retry", headers=W).status_code == 200
    t = client.get("/api/v1/coordination/tasks/m23-dl", headers=R).json()
    assert t["state"].lower() == "queued" and t["dead_letter"] is False  # no contradiction


def test_task_state_and_events_never_contradict(client):
    _mk(client, "m23-audit")
    _run(client, "m23-audit")
    client.post("/api/v1/coordination/tasks/m23-audit/complete", json={"result": "ok"}, headers=W)
    client.post("/api/v1/coordination/tasks/m23-audit/complete", json={"result": "again"}, headers=W)  # rejected
    t = client.get("/api/v1/coordination/tasks/m23-audit", headers=R).json()
    ev = client.get("/api/v1/coordination/tasks/m23-audit/events", headers=R).json()["events"]
    # events are newest-first; the latest state: event must match the persisted state
    state_events = [e for e in ev if (e["kind"] or "").startswith("state:")]
    assert state_events, "no state events recorded"
    latest = state_events[0]["kind"].split("->")[-1]
    assert latest.lower() == t["state"].lower(), f"event {latest} != state {t['state']}"
    assert any(e["kind"] == "transition_rejected" or (e["kind"] or "").startswith("report:") for e in ev)


def test_agent_health_classification(client):
    from datetime import timedelta
    from app.coordination.registry import utcnow
    client.post("/api/v1/coordination/agents/register", json={"agent": "h1"}, headers=W)
    client.post("/api/v1/coordination/agents/register", json={"agent": "h2"}, headers=W)
    client.post("/api/v1/coordination/agents/h1/heartbeat", json={"status": "available"}, headers=W)
    with ops.SessionLocal() as s:
        a = s.execute(select(models.CoordinationAgent).where(models.CoordinationAgent.agent == "h1")).scalar_one()
        a.last_heartbeat = utcnow() - timedelta(seconds=99999)
        b = s.execute(select(models.CoordinationAgent).where(models.CoordinationAgent.agent == "h2")).scalar_one()
        b.last_heartbeat = None  # legacy row with no heartbeat ever -> UNKNOWN
        s.commit()
    # h1 stale now; make h3 offline
    client.post("/api/v1/coordination/agents/register", json={"agent": "h3"}, headers=W)
    client.post("/api/v1/coordination/agents/h3/heartbeat", json={"status": "offline"}, headers=W)
    agents = {a["agent"]: a for a in client.get("/api/v1/coordination/agents", headers=R).json()["agents"]}
    assert agents["h1"]["health"] == "STALE"
    assert agents["h2"]["health"] == "UNKNOWN"
    assert agents["h3"]["health"] == "UNAVAILABLE"
    client.post("/api/v1/coordination/agents/h2/heartbeat", json={"status": "busy"}, headers=W)
    agents = {a["agent"]: a for a in client.get("/api/v1/coordination/agents", headers=R).json()["agents"]}
    assert agents["h2"]["health"] == "ACTIVE"


def test_agent_status_transitions_audited(client):
    client.post("/api/v1/coordination/agents/register", json={"agent": "aud"}, headers=W)
    client.post("/api/v1/coordination/agents/aud/heartbeat", json={"status": "available"}, headers=W)
    client.post("/api/v1/coordination/agents/aud/deregister", headers=W)
    with ops.SessionLocal() as s:
        rows = s.execute(select(models.Event).where(models.Event.source == "coordination.agents")).scalars().all()
        msgs = [r.message for r in rows]
    assert any("aud" in m and "available -> offline" in m for m in msgs), msgs
