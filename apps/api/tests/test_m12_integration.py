"""M12 — Cross-agent integration & operational readiness tests.

IMPORTANT LABELING: the "Agent 2" / "Agent 3" actors here are SIMULATED AGENT
FIXTURES driving the real HTTP API (TestClient) — they are NOT Arena sessions
and no Arena session execution is claimed. The GitHub status check in the
Agent-4-view test is a LIVE call to api.github.com (skips honestly if down).
"""
import hashlib
import hmac
import json
import os
import tempfile
import time

import pytest

from app import ops, ratelimit

SECRET = "m12-secret"
W = {"Authorization": "Bearer w", "Content-Type": "application/json"}
R = {"Authorization": "Bearer r"}

# Simulated agent fixtures (labels): agent-2 = threat intel, agent-3 = vuln intel
AGENT2 = {"agent": "agent-2-threat-intel", "capabilities": ["threat_intel"]}
AGENT3 = {"agent": "agent-3-vuln-intel", "capabilities": ["vuln_intel"]}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r")
    monkeypatch.setenv("CICC_GH_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("CICC_COORD_APPROVERS", "owner")
    monkeypatch.setenv("CICC_COORD_MAX_ATTEMPTS", "2")
    monkeypatch.setenv("CICC_COORD_RETRY_BACKOFF_S", "0")
    monkeypatch.setenv("CICC_AGENT_STALE_S", "2")
    monkeypatch.delenv("RABBITMQ_AMQP_URL", raising=False)
    yield
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def _submit(client, key, kind, caps, **kw):
    body = {"kind": kind, "title": f"{kind}-{key}", "payload": {"caps": caps, "key": key},
            "idempotency_key": f"m12-{key}", "priority": 2}
    body.update(kw)
    r = client.post("/api/v1/coordination/tasks", json=body, headers=W)
    assert r.status_code == 201, r.text
    return r.json()["task_id"]


# ---------- M12-02: end-to-end Agent2 -> central -> Agent3 -> Agent4 view ----------

def test_e2e_threat_intel_task_full_flow(client):
    """Simulated Agent 2 submits a threat-intel task; central routes it to the
    threat-intel-capable agent; payload is presented via handoff; progress +
    completion recorded; audit trail complete."""
    assert client.post("/api/v1/coordination/agents/register", json=AGENT2, headers=W).status_code == 201
    assert client.post("/api/v1/coordination/agents/register", json=AGENT3, headers=W).status_code == 201

    # 1-2. submit + route
    tid = _submit(client, "ti-1", "threat_intel", ["threat_intel"])
    r = client.post(f"/api/v1/coordination/tasks/{tid}/route", headers=W)
    assert r.status_code == 200 and r.json()["agent"] == "agent-2-threat-intel"
    assert r.json()["explanation"]["via"] in ("rule", "score")

    # 3. deliver -> handoff payload presented to the agent (human-assisted: no broker)
    d = client.post(f"/api/v1/coordination/tasks/{tid}/deliver", headers=W).json()
    assert d["via"] == "human_assisted" and d["delivered"] is False  # honest
    assert d["handoff"]["task_id"] == tid and d["handoff"]["agent"] == "agent-2-threat-intel"
    hp = d["handoff"].get("event") or {}
    hp = json.loads(hp) if isinstance(hp, str) else hp
    assert hp.get("key") == "ti-1"  # handoff carries the original task payload

    # 4. ack -> progress -> complete (as the simulated worker would)
    assert client.post(f"/api/v1/coordination/tasks/{tid}/ack", headers=W).json()["state"] == "ACKNOWLEDGED"
    assert client.post(f"/api/v1/coordination/tasks/{tid}/start", headers=W).json()["state"] == "RUNNING"
    assert client.post(f"/api/v1/coordination/tasks/{tid}/progress",
                       json={"percent": 100, "note": "intel synthesized"}, headers=W).json()["progress"] == 100
    assert client.post(f"/api/v1/coordination/tasks/{tid}/complete",
                       json={"result": "ttps mapped"}, headers=W).json()["state"] == "COMPLETED"

    # 5. audit trail
    evs = client.get(f"/api/v1/coordination/tasks/{tid}/events", headers=R).json()["events"]
    kinds = [e["kind"] for e in evs]
    for k in ("created", "delivery:published", "state:QUEUED->ACKNOWLEDGED", "progress",
              "state:RUNNING->COMPLETED"):
        assert k in kinds, kinds
    t = client.get(f"/api/v1/coordination/tasks/{tid}", headers=R).json()
    assert t["state"] == "COMPLETED" and t["progress"] == 100 and t["agent"] == "agent-2-threat-intel"
    return tid


def test_e2e_vuln_task_depends_on_threat_task(client):
    """Simulated Agent 3's vuln-intel task depends on Agent 2's threat task:
    blocked (409) until the threat task completes, then routed to agent-3."""
    client.post("/api/v1/coordination/agents/register", json=AGENT2, headers=W)
    client.post("/api/v1/coordination/agents/register", json=AGENT3, headers=W)
    threat = _submit(client, "ti-2", "threat_intel", ["threat_intel"])
    vuln = _submit(client, "vi-1", "vuln_intel", ["vuln_intel"], depends_on=[threat])

    client.post(f"/api/v1/coordination/tasks/{threat}/route", headers=W)
    client.post(f"/api/v1/coordination/tasks/{threat}/deliver", headers=W)
    client.post(f"/api/v1/coordination/tasks/{threat}/ack", headers=W)
    client.post(f"/api/v1/coordination/tasks/{threat}/start", headers=W)

    # vuln task routed but NOT deliverable while dep RUNNING
    r = client.post(f"/api/v1/coordination/tasks/{vuln}/route", headers=W)
    assert r.json()["agent"] == "agent-3-vuln-intel"
    assert client.post(f"/api/v1/coordination/tasks/{vuln}/deliver", headers=W).status_code == 409

    client.post(f"/api/v1/coordination/tasks/{threat}/complete", json={"result": "ok"}, headers=W)
    d = client.post(f"/api/v1/coordination/tasks/{vuln}/deliver", headers=W).json()
    assert d["handoff"]["agent"] == "agent-3-vuln-intel"
    client.post(f"/api/v1/coordination/tasks/{vuln}/ack", headers=W)
    client.post(f"/api/v1/coordination/tasks/{vuln}/start", headers=W)
    client.post(f"/api/v1/coordination/tasks/{vuln}/complete", json={"result": "cves triaged"}, headers=W)
    assert client.get(f"/api/v1/coordination/tasks/{vuln}", headers=R).json()["state"] == "COMPLETED"


def test_agent4_dashboard_view_contract(client):
    """M12-02(7)/M12-05: the exact payloads the Coordination dashboard consumes
    (GET /agents, /tasks, /metrics, /github/status) have the contract shape.
    The github/status call is LIVE (real api.github.com); skips if unreachable."""
    client.post("/api/v1/coordination/agents/register", json=AGENT2, headers=W)
    _submit(client, "dash-1", "threat_intel", ["threat_intel"])

    agents = client.get("/api/v1/coordination/agents", headers=R).json()["agents"]
    assert agents and all("agent" in a and "stale" in a and "status" in a for a in agents)

    tasks = client.get("/api/v1/coordination/tasks", headers=R).json()["tasks"]
    assert tasks and all(k in tasks[0] for k in ("task_id", "state", "kind", "progress",
                                                 "attempts", "routing_explanation", "next_retry_at"))

    m = client.get("/api/v1/coordination/metrics", headers=R).json()
    for k in ("tasks_total", "by_state", "by_kind", "active_by_agent", "deliveries_by_outcome",
              "approvals_pending", "agents_registered", "agents_online", "dead_lettered"):
        assert k in m

    from app import checks
    checks.reset_circuit_breakers()
    gh = client.get("/api/v1/coordination/github/status", headers=R).json()
    if gh.get("status") != "ok":
        pytest.skip(f"api.github.com unreachable: {gh.get('detail')}")
    assert gh["repo"] == "oldman-088/cicc" and isinstance(gh["open_prs"], list)


# ---------- M12-03: operational reliability ----------

def test_stale_agent_detection_and_expiry(client):
    client.post("/api/v1/coordination/agents/register", json=AGENT2, headers=W)
    a = client.get("/api/v1/coordination/agents", headers=R).json()["agents"][0]
    assert a["stale"] is False
    time.sleep(2.2)  # CICC_AGENT_STALE_S=2
    r = client.post("/api/v1/coordination/sweep", headers=W).json()
    assert "agent-2-threat-intel" in r["stale_agents"]
    a = client.get("/api/v1/coordination/agents", headers=R).json()["agents"][0]
    assert a["stale"] is True and a["status"] == "offline"


def test_approval_expiration(client, monkeypatch):
    monkeypatch.setenv("CICC_COORD_APPROVAL_TTL_S", "1")
    # case A: decide after TTL but before sweep -> 410 expired
    tid_a = _submit(client, "ap-a", "deploy", [], requires_approval=True)
    assert client.get(f"/api/v1/coordination/tasks/{tid_a}", headers=R).json()["state"] == "WAITING_FOR_APPROVAL"
    time.sleep(1.1)
    resp = client.post(f"/api/v1/coordination/tasks/{tid_a}/approve",
                       json={"decided_by": "owner"}, headers=W)
    assert resp.status_code == 410
    # case B: sweep first -> listed in expired_approvals; decide then -> 409
    tid_b = _submit(client, "ap-b", "deploy", [], requires_approval=True)
    time.sleep(1.1)
    r = client.post("/api/v1/coordination/sweep", headers=W).json()
    assert tid_b in r["expired_approvals"]
    resp = client.post(f"/api/v1/coordination/tasks/{tid_b}/approve",
                       json={"decided_by": "owner"}, headers=W)
    assert resp.status_code == 409
    ap = client.get(f"/api/v1/coordination/tasks/{tid_b}/approval", headers=R).json()["approval"]
    assert ap["status"] == "expired"


def test_dead_letter_visibility(client):
    tid = _submit(client, "dl-1", "flaky", [])
    client.post(f"/api/v1/coordination/tasks/{tid}/route", headers=W)
    for _ in range(2):  # max_attempts=2
        client.post(f"/api/v1/coordination/tasks/{tid}/deliver", headers=W)
        client.post(f"/api/v1/coordination/tasks/{tid}/ack", headers=W)
        client.post(f"/api/v1/coordination/tasks/{tid}/start", headers=W)
        client.post(f"/api/v1/coordination/tasks/{tid}/fail", json={"reason": "x"}, headers=W)
        client.post("/api/v1/coordination/sweep", headers=W)  # backoff=0 -> requeue
    t = client.get(f"/api/v1/coordination/tasks/{tid}", headers=R).json()
    assert t["dead_letter"] is True and t["state"] == "BLOCKED"
    dl = client.get("/api/v1/coordination/tasks?dead_letter=true", headers=R).json()["tasks"]
    assert [x["task_id"] for x in dl] == [tid]
    assert client.get("/api/v1/coordination/tasks?dead_letter=false", headers=R).json()["tasks"] == []
    evs = client.get(f"/api/v1/coordination/tasks/{tid}/events", headers=R).json()["events"]
    assert any(e["kind"] == "dead_letter" for e in evs)


def test_recovery_after_api_restart(client, monkeypatch, tmp_path):
    """Simulated restart: same DB file, brand-new app instance (TestClient).
    Tasks/agents persist; sweep still works. Uses a file DB (not the per-test
    in-memory one) to model a real restart."""
    db_file = tmp_path / "restart.db"
    os.environ["DATABASE_URL"] = "sqlite:///" + str(db_file)
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app import models
    eng = create_engine(os.environ["DATABASE_URL"], connect_args={"check_same_thread": False})
    models.Base.metadata.create_all(eng)
    monkeypatch.setattr(ops, "engine", eng)
    monkeypatch.setattr(ops, "SessionLocal", sessionmaker(bind=eng, autoflush=False))
    ops.init_db()

    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c1:  # "before restart"
        c1.post("/api/v1/coordination/agents/register", json=AGENT2, headers=W)
        tid = _submit(c1, "rs-1", "threat_intel", ["threat_intel"], ttl_s=3600)
        c1.post(f"/api/v1/coordination/tasks/{tid}/route", headers=W)

    with TestClient(app) as c2:  # "after restart" — same DB file
        t = c2.get(f"/api/v1/coordination/tasks/{tid}", headers=R).json()
        assert t["state"] == "QUEUED" and t["agent"] == "agent-2-threat-intel"
        agents = c2.get("/api/v1/coordination/agents", headers=R).json()["agents"]
        assert agents[0]["agent"] == "agent-2-threat-intel"
        r = c2.post("/api/v1/coordination/sweep", headers=W).json()
        assert isinstance(r["expired_tasks"], list)  # sweep functional after restart
        assert c2.post(f"/api/v1/coordination/tasks/{tid}/deliver", headers=W).status_code == 200
    eng.dispose()
