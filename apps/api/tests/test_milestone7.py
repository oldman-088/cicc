"""Milestone 7 tests: agent registry & lifecycle, workload-aware explainable
routing, lifecycle v2 (dependencies, timeouts, cancel/retry, dead-letter,
idempotency), approval workflow, delivery records, webhook allowlist,
per-component alert history, latency/retry metrics."""
import hashlib
import hmac
import json
from datetime import timedelta

import pytest
from sqlalchemy import select

from app import models, ops, ratelimit
from app.coordination import agents as agent_registry
from app.coordination import approvals, handoff, registry, routing, webhook

SECRET = "test-webhook-secret"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    ops._overview_cache["data"] = None
    ops._overview_cache["ts"] = 0.0
    monkeypatch.setenv("CICC_GH_WEBHOOK_SECRET", SECRET)
    for v in ("CICC_OPS_WRITE_TOKEN", "CICC_OPS_READ_TOKEN", "RABBITMQ_AMQP_URL",
              "CICC_COORD_APPROVERS", "CICC_AGENT_STALE_S", "CICC_COORD_MAX_ATTEMPTS",
              "CICC_GH_EVENT_ALLOWLIST", "CICC_COORD_APPROVAL_TTL_S"):
        monkeypatch.delenv(v, raising=False)
    yield
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def _payload(labels=None, **extra):
    p = {"action": "opened", "repository": {"full_name": "oldman-088/cicc"},
         "sender": {"login": "u"}, "pull_request": {"number": 1, "title": "t",
                                                     "labels": [{"name": x} for x in (labels or [])],
                                                     "head": {"ref": "b"}}}
    p.update(extra)
    return p


def _post(client, body, delivery="d-1", event="pull_request"):
    raw = json.dumps(body).encode()
    sig = "sha256=" + hmac.new(SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return client.post("/api/v1/coordination/webhook/github", content=raw,
                       headers={"X-GitHub-Event": event, "X-GitHub-Delivery": delivery,
                                "X-Hub-Signature-256": sig, "Content-Type": "application/json"})


# ---------- agent registry ----------

def test_agent_registry_lifecycle(client):
    r = client.post("/api/v1/coordination/agents/register",
                    json={"agent": "agent-1-ops", "specialization": "ops", "capabilities": ["ops", "monitor"], "version": "0.7"})
    assert r.status_code == 201 and r.json()["created"] is True
    r = client.post("/api/v1/coordination/agents/agent-1-ops/heartbeat", json={"status": "busy"})
    assert r.status_code == 200 and r.json()["status"] == "busy"
    agents = client.get("/api/v1/coordination/agents").json()["agents"]
    a = agents[0]
    assert a["agent"] == "agent-1-ops" and a["capabilities"] == ["ops", "monitor"] and a["stale"] is False
    # stale detection
    with ops.SessionLocal() as s:
        row = s.get(models.CoordinationAgent, "agent-1-ops")
        row.last_heartbeat = registry.utcnow() - timedelta(seconds=9999)
        s.commit()
    agents = client.get("/api/v1/coordination/agents").json()["agents"]
    assert agents[0]["stale"] is True and agents[0]["status"] == "offline"
    # sweep + deregister
    r = client.post("/api/v1/coordination/sweep")
    assert "agent-1-ops" in r.json()["stale_agents"]
    assert client.post("/api/v1/coordination/agents/agent-1-ops/deregister").json()["status"] == "offline"
    assert client.post("/api/v1/coordination/agents/nope/deregister").status_code == 404


# ---------- workload-aware routing ----------

def _register_agent(client, agent, caps, status=None):
    client.post("/api/v1/coordination/agents/register", json={"agent": agent, "capabilities": caps})
    if status:
        client.post(f"/api/v1/coordination/agents/{agent}/heartbeat", json={"status": status})


def test_routing_prefers_less_loaded_agent(client):
    _register_agent(client, "agent-a", ["ops"])
    _register_agent(client, "agent-b", ["ops"])
    # give agent-a 2 active tasks
    with ops.SessionLocal() as s:
        for i in range(2):
            t = registry.create_task(s, task_id=f"load-a-{i}", event_id=None, source="manual",
                                     kind="manual", repo="r", pr_ref=None, branch_ref=None,
                                     title="x", payload={})
            t.agent = "agent-a"
            registry.transition(s, t, "QUEUED", "")
            registry.transition(s, t, "ASSIGNED", "")
        s.commit()
    _post(client, _payload(labels=["unrelated-label"]), delivery="d-r1")  # no default rule match
    r = client.post("/api/v1/coordination/tasks/gh-d-r1/route").json()
    assert r["agent"] == "agent-b"  # less loaded wins over agent-a (2 active)
    assert r["explanation"]["via"] == "score"
    assert r["explanation"]["candidates"] == 2


def test_routing_excludes_offline_and_missing_caps(client, monkeypatch):
    _register_agent(client, "agent-a", ["ops"], status="offline")
    _register_agent(client, "agent-b", ["other"])
    _post(client, _payload(labels=["zzz"], required_capabilities=["gpu"]), delivery="d-r2")
    r = client.post("/api/v1/coordination/tasks/gh-d-r2/route").json()
    assert r["agent"] is None and r["state"] == "BLOCKED"
    assert any("no available agents" in x or "missing" in x for x in r["explanation"]["reasons"])


def test_routing_rule_beats_scoring(client):
    _register_agent(client, "agent-x", [])
    _post(client, _payload(labels=["ops"]), delivery="d-r3")
    r = client.post("/api/v1/coordination/tasks/gh-d-r3/route").json()
    assert r["agent"] == "agent-1-ops" and r["explanation"]["via"] in ("rule", "default_rule")


# ---------- lifecycle v2 ----------

def test_dependencies_gate_delivery(client):
    _register_agent(client, "agent-1-ops", ["ops"])
    _post(client, _payload(labels=["ops"]), delivery="d-dep")
    with ops.SessionLocal() as s:
        t = s.execute(select(models.CoordinationTask).where(models.CoordinationTask.task_id == "gh-d-dep")).scalar_one()
        t.depends_on = json.dumps(["gh-other"])
        s.commit()
    r = client.post("/api/v1/coordination/tasks/gh-d-dep/deliver")
    assert r.status_code == 409  # M11: deps gate is a hard 409
    assert r.json()["detail"] == "dependencies not completed"
    evs = client.get("/api/v1/coordination/tasks/gh-d-dep/events").json()["events"]
    assert any("deps" in (e["kind"] or "") for e in evs)


def test_idempotency_key_dedup(client):
    _post(client, _payload(), delivery="d-i1")
    with ops.SessionLocal() as s:
        t = registry.create_task(s, task_id="t-manual", event_id=None, source="manual", kind="manual",
                                 repo="r", pr_ref=None, branch_ref=None, title="x", payload={},
                                 idempotency_key="gh:d-i1")
        assert t.task_id == "gh-d-i1"  # same idempotency key -> same task
        s.rollback()


def test_cancel_and_retry_and_dead_letter(client, monkeypatch):
    monkeypatch.setenv("CICC_COORD_MAX_ATTEMPTS", "2")
    _post(client, _payload(labels=["ops"]), delivery="d-c1")
    assert client.post("/api/v1/coordination/tasks/gh-d-c1/cancel").json()["state"] == "CANCELLED"
    assert client.post("/api/v1/coordination/tasks/gh-d-c1/retry").status_code == 409  # terminal
    # dead-letter after max attempts
    with ops.SessionLocal() as s:
        t = registry.create_task(s, task_id="t-dl", event_id=None, source="manual", kind="manual",
                                 repo="r", pr_ref=None, branch_ref=None, title="x", payload={})
        t.state = "RUNNING"
        t.attempts = 2
        s.commit()
    r = client.post("/api/v1/coordination/tasks/t-dl/fail", json={"result": "boom"}).json()
    assert r["state"] == "BLOCKED" and r["dead_letter"] is True


def test_timeout_sweep(client):
    with ops.SessionLocal() as s:
        t = registry.create_task(s, task_id="t-to", event_id=None, source="manual", kind="manual",
                                 repo="r", pr_ref=None, branch_ref=None, title="x", payload={}, ttl_s=1)
        t.state = "RUNNING"
        t.updated_at = registry.utcnow() - timedelta(seconds=3600)
        t.timeout_s = 60
        s.commit()
    r = client.post("/api/v1/coordination/sweep").json()
    assert "t-to" in r["expired_tasks"]


# ---------- approvals ----------

def test_approval_workflow(client, monkeypatch):
    monkeypatch.setenv("CICC_COORD_APPROVERS", "owner,boss")
    _post(client, _payload(requires_approval=True), delivery="d-ap1")
    tasks = client.get("/api/v1/coordination/tasks").json()["tasks"]
    t = next(x for x in tasks if x["task_id"] == "gh-d-ap1")
    assert t["state"] == "WAITING_FOR_APPROVAL"
    # not deliverable while waiting
    r = client.post("/api/v1/coordination/tasks/gh-d-ap1/deliver")
    assert r.status_code == 409
    # non-approver rejected
    r = client.post("/api/v1/coordination/tasks/gh-d-ap1/approve", json={"decided_by": "random"})
    assert r.status_code == 403
    # approver approves -> QUEUED
    r = client.post("/api/v1/coordination/tasks/gh-d-ap1/approve", json={"decided_by": "owner"})
    assert r.status_code == 200 and r.json()["state"] == "QUEUED"
    ap = client.get("/api/v1/coordination/tasks/gh-d-ap1/approval").json()["approval"]
    assert ap["status"] == "approved" and ap["decided_by"] == "owner"
    # second approve -> 409 (no pending)
    assert client.post("/api/v1/coordination/tasks/gh-d-ap1/approve", json={"decided_by": "owner"}).status_code == 409


def test_approval_reject_and_expiry(client, monkeypatch):
    monkeypatch.setenv("CICC_COORD_APPROVERS", "owner")
    monkeypatch.setenv("CICC_COORD_APPROVAL_TTL_S", "1")
    _post(client, _payload(requires_approval=True), delivery="d-ap2")
    r = client.post("/api/v1/coordination/tasks/gh-d-ap2/reject", json={"decided_by": "owner"})
    assert r.json()["state"] == "FAILED"
    _post(client, _payload(requires_approval=True), delivery="d-ap3")
    import time
    time.sleep(1.1)
    r = client.post("/api/v1/coordination/sweep").json()
    assert "gh-d-ap3" in r["expired_approvals"] + r["expired_tasks"]


# ---------- webhook allowlist ----------

def test_non_allowlisted_event_recorded_not_tasked(client, monkeypatch):
    monkeypatch.setenv("CICC_GH_EVENT_ALLOWLIST", "pull_request")
    r = _post(client, _payload(), delivery="d-al1", event="push")
    assert r.status_code == 200
    d = r.json()
    assert d["task_id"] is None and "not in allowlist" in d["note"]
    assert client.get("/api/v1/coordination/tasks").json()["tasks"] == []
    # oversized payload
    big = {"action": "x", "repository": {"full_name": "r"}, "pad": "y" * (300 * 1024)}
    raw = json.dumps(big).encode()
    sig = "sha256=" + hmac.new(SECRET.encode(), raw, hashlib.sha256).hexdigest()
    r = client.post("/api/v1/coordination/webhook/github", content=raw,
                    headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "d-big",
                             "X-Hub-Signature-256": sig})
    assert r.status_code == 413


# ---------- ops M7: alert history + metrics ----------

def test_alert_history_filter(client):
    with ops.SessionLocal() as s:
        s.add(models.Alert(rule="worker_stalled", component_key="w1", severity="warning", status="active", message="m"))
        s.add(models.Alert(rule="queue_backlog", component_key="rabbitmq", severity="warning", status="resolved", message="m2"))
        s.commit()
    r = client.get("/api/v1/ops/alerts/history?component=rabbitmq")
    assert r.status_code == 200 and len(r.json()["alerts"]) == 1
    assert r.json()["alerts"][0]["rule"] == "queue_backlog"
    assert len(client.get("/api/v1/ops/alerts/history?rule=worker_stalled").json()["alerts"]) == 1


def test_task_stats_latency_and_retry_metrics(client):
    with ops.SessionLocal() as s:
        for i in range(20):
            s.add(models.TaskRun(worker="w", queue="q", status="success", duration_ms=i * 10, created_at=ops.utcnow()))
        s.add(models.TaskRun(worker="w", queue="q", status="failed", error="e", attempts=3, created_at=ops.utcnow()))
        s.add(models.TaskRun(worker="w", queue="q", status="failed", error="e", attempts=1, created_at=ops.utcnow()))
        s.commit()
    st = ops.build_task_stats(1)
    assert st["duration_p50_ms"] is not None and st["duration_p95_ms"] is not None
    assert st["duration_p95_ms"] >= st["duration_p50_ms"]
    assert st["retry_rate"] == 0.5  # 1 of 2 failed had attempts>1


def test_queued_can_be_acked_then_run_completed(client):
    """Human-assisted flow: QUEUED -> ACKNOWLEDGED -> RUNNING -> COMPLETED."""
    _post(client, _payload(labels=["ops"]), delivery="d-lc")
    assert client.post("/api/v1/coordination/tasks/gh-d-lc/route").json()["state"] == "QUEUED"
    client.post("/api/v1/coordination/tasks/gh-d-lc/deliver")
    assert client.post("/api/v1/coordination/tasks/gh-d-lc/ack").json()["state"] == "ACKNOWLEDGED"
    assert client.post("/api/v1/coordination/tasks/gh-d-lc/start").json()["state"] == "RUNNING"
    assert client.post("/api/v1/coordination/tasks/gh-d-lc/complete", json={"result": "ok"}).json()["state"] == "COMPLETED"
