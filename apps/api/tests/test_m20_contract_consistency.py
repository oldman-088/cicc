"""M20 — contract consistency & reliability edge cases.

Part A: the served /contract descriptor is verified AGAINST the actual
FastAPI app: every documented endpoint exists with the documented method,
DTO field lists match the Pydantic models, and task states match the
implemented state machine. Fixture traffic only.

Part B: reliability edges — approval expiry (410), task timeout expiry via
sweep, stale agent revived by heartbeat, duplicate webhook idempotency.
"""
import hashlib
import hmac
import json

import pytest
from fastapi.routing import APIRoute

from app import models, ops, ratelimit
from app.coordination import contract as contract_desc
from app.coordination import registry

W = {"Authorization": "Bearer w", "Content-Type": "application/json"}
R = {"Authorization": "Bearer r"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r")
    monkeypatch.setenv("CICC_COORD_APPROVERS", "owner")
    monkeypatch.setenv("CICC_GH_WEBHOOK_SECRET", "sec")
    monkeypatch.setenv("CICC_COORD_APPROVAL_TTL_S", "1")
    monkeypatch.delenv("RABBITMQ_AMQP_URL", raising=False)
    yield
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


# ---------- Part A: descriptor vs implementation ----------

def test_every_documented_endpoint_exists(client):
    from app.main import app
    actual = {}
    for r in app.routes:
        if isinstance(r, APIRoute):
            for m in r.methods:
                actual.setdefault(r.path, set()).add(m)
    d = contract_desc.contract_v1()
    missing = []
    for ep in d["endpoints"]:
        path = ep["path"].replace("{task_id}", "{task_id}").replace("{agent}", "{agent}")
        # normalize documented path to FastAPI path template
        norm = path
        for param in ("{task_id}", "{agent}"):
            norm = norm.replace(param, param)
        if norm not in actual or ep["method"] not in actual.get(norm, set()):
            missing.append(f"{ep['method']} {path}")
    assert not missing, f"documented but not implemented: {missing}"


def test_dto_fields_match_pydantic_models(client):
    from app.coordination import router as r
    d = contract_desc.contract_v1()["dtos"]
    models_map = {
        "TaskIn": r.TaskIn, "ReportIn": r.ReportIn, "ProgressIn": r.ProgressIn,
        "DecisionIn": r.DecisionIn, "AgentRegisterIn": r.AgentRegisterIn,
        "AgentHeartbeatIn": r.AgentHeartbeatIn,
    }
    for name, fields in d.items():
        if name not in models_map:  # output DTOs (e.g. AgentDTO) are pinned separately
            continue
        actual = set(models_map[name].model_fields.keys())
        documented = {f.rstrip("?") for f in fields}
        assert documented == actual, f"{name}: documented {sorted(documented)} != actual {sorted(actual)}"


def test_task_states_match_state_machine(client):
    d = contract_desc.contract_v1()
    canonical = {s.lower() for s in registry.CANONICAL_STATES}
    assert set(s.lower() for s in d["task_states"]) == canonical
    # every canonical state reachable in ALLOWED_TRANSITIONS graph
    graph_states = set(registry.ALLOWED_TRANSITIONS.keys()) | {
        t for v in registry.ALLOWED_TRANSITIONS.values() for t in v}
    assert canonical <= {s.lower() for s in graph_states}


def test_error_codes_actually_produced(client):
    assert client.get("/api/v1/coordination/agents").status_code == 401
    assert client.post("/api/v1/coordination/tasks", json={"kind": "x", "payload": {}}, headers=R).status_code in (401, 403)
    assert client.get("/api/v1/coordination/tasks/nope", headers=R).status_code == 404
    body = {"task_id": "m20-err", "kind": "m20", "payload": {}}
    assert client.post("/api/v1/coordination/tasks", json=body, headers=W).status_code == 201
    assert client.post("/api/v1/coordination/tasks/m20-err/complete", json={}, headers=W).status_code == 409
    assert client.post("/api/v1/coordination/tasks", json={"task_id": "bad kind!", "kind": "BAD", "payload": {}}, headers=W).status_code == 422


# ---------- Part B: reliability edges ----------

def test_approval_expiry_returns_410(client):
    import time
    client.post("/api/v1/coordination/agents/register", json={"agent": "a1"}, headers=W)
    client.post("/api/v1/coordination/tasks", json={"task_id": "m20-ap", "kind": "m20", "payload": {}, "requires_approval": True}, headers=W)
    time.sleep(1.2)  # TTL = 1s
    r = client.post("/api/v1/coordination/tasks/m20-ap/approve", json={"decided_by": "owner"}, headers=W)
    assert r.status_code == 410, r.text


def test_task_timeout_expires_via_sweep(client):
    from datetime import timedelta
    from app.coordination.registry import utcnow
    client.post("/api/v1/coordination/agents/register", json={"agent": "a1"}, headers=W)
    client.post("/api/v1/coordination/tasks", json={"task_id": "m20-to", "kind": "m20", "payload": {}, "ttl_s": 1}, headers=W)
    from sqlalchemy import select
    with ops.SessionLocal() as s:
        t = s.execute(select(models.CoordinationTask).where(models.CoordinationTask.task_id == "m20-to")).scalar_one()
        t.expires_at = utcnow() - timedelta(seconds=100)
        s.commit()
    r = client.post("/api/v1/coordination/sweep", headers=W).json()
    assert "m20-to" in r["expired_tasks"]
    assert client.get("/api/v1/coordination/tasks/m20-to", headers=R).json()["state"].lower() == "expired"


def test_stale_agent_revived_by_heartbeat(client):
    from datetime import timedelta
    from app.coordination.registry import utcnow
    client.post("/api/v1/coordination/agents/register", json={"agent": "m20-stale"}, headers=W)
    from sqlalchemy import select
    with ops.SessionLocal() as s:
        a = s.execute(select(models.CoordinationAgent).where(models.CoordinationAgent.agent == "m20-stale")).scalar_one()
        a.last_heartbeat = utcnow() - timedelta(seconds=99999)
        s.commit()
    assert [x for x in client.get("/api/v1/coordination/agents", headers=R).json()["agents"] if x["agent"] == "m20-stale"][0]["stale"] is True
    r = client.post("/api/v1/coordination/agents/m20-stale/heartbeat", json={"status": "available"}, headers=W)
    assert r.status_code == 200
    a = [x for x in client.get("/api/v1/coordination/agents", headers=R).json()["agents"] if x["agent"] == "m20-stale"][0]
    assert a["stale"] is False and a["status"] == "available"


def test_duplicate_webhook_idempotent_repeatedly(client):
    raw = json.dumps({"action": "opened", "repository": {"full_name": "o/r"}, "sender": {"login": "u"},
                      "pull_request": {"number": 77, "title": "t", "labels": [{"name": "ops"}], "head": {"ref": "b"}}}).encode()
    sig = "sha256=" + hmac.new(b"sec", raw, hashlib.sha256).hexdigest()
    h = {"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "m20-dup", "X-Hub-Signature-256": sig, "Content-Type": "application/json"}
    codes = [client.post("/api/v1/coordination/webhook/github", content=raw, headers=h).json() for _ in range(3)]
    assert codes[0]["ok"] and not codes[0]["duplicate"]
    assert all(c["duplicate"] for c in codes[1:])
    tasks = client.get("/api/v1/coordination/tasks?kind=pr_opened", headers=R).json()["tasks"]
    assert [t["task_id"] for t in tasks].count("gh-m20-dup") == 1


def test_agent_dto_matches_documented_fields(client):
    """M21: pin the GET /agents wire fields to the documented AgentDTO
    (Agent 4's PR #2 flagged a doc/wire mismatch — keep them aligned)."""
    from app.coordination import contract as cd
    client.post("/api/v1/coordination/agents/register", json={"agent": "dto-pin"}, headers=W)
    a = client.get("/api/v1/coordination/agents", headers=R).json()["agents"][0]
    documented = set(cd.contract_v1()["dtos"]["AgentDTO (GET /agents)"])
    assert set(a.keys()) == documented, f"wire {sorted(a.keys())} != documented {sorted(documented)}"


def test_heartbeat_documented_fields_persisted(client):
    """M22: heartbeat accepts and persists the documented active_tasks/meta
    (INTEGRATION_CONTRACTS.md #2) — previously silently dropped."""
    client.post("/api/v1/coordination/agents/register", json={"agent": "hb-pin", "meta": {"v": 1}}, headers=W)
    r = client.post("/api/v1/coordination/agents/hb-pin/heartbeat",
                    json={"status": "busy", "active_tasks": 3, "meta": {"note": "scanning"}}, headers=W)
    assert r.status_code == 200 and r.json()["status"] == "busy"
    a = [x for x in client.get("/api/v1/coordination/agents", headers=R).json()["agents"] if x["agent"] == "hb-pin"][0]
    assert a["meta"]["heartbeat"]["active_tasks"] == 3
    assert a["meta"]["heartbeat"]["meta"] == {"note": "scanning"}
    assert a["meta"]["v"] == 1  # registration meta preserved
