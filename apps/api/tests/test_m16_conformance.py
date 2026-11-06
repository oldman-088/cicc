"""M16-01 — Contract v1.0 CONFORMANCE harness.

IMPORTANT LABEL: these are FIXTURE-BASED conformance tests. The "agent"
actors are in-test fixtures driving the real HTTP API. They validate that the
implemented API matches documented contract v1.0 (DTO keys, types, state
enum, error codes). They are NOT actual Agent 2/3/4 integration — no Arena
agent has confirmed or called these endpoints yet (see
docs/CONTRACT_ADOPTION.md).
"""
import hashlib
import hmac
import json

import pytest

from app import ratelimit

SECRET = "m16-secret"
W = {"Authorization": "Bearer w", "Content-Type": "application/json"}
R = {"Authorization": "Bearer r"}

CANONICAL_STATES = {"CREATED", "VALIDATING", "QUEUED", "ASSIGNED", "DELIVERING",
                    "ACKNOWLEDGED", "RUNNING", "WAITING_FOR_APPROVAL", "COMPLETED",
                    "FAILED", "RETRYING", "BLOCKED", "CANCELLED", "EXPIRED"}

TASK_KEYS = {"task_id", "event_id", "source", "kind", "agent", "state", "priority", "repo",
             "pr_ref", "branch_ref", "title", "attempts", "result", "owner", "depends_on",
             "timeout_s", "expires_at", "dead_letter", "routing_explanation", "progress",
             "next_retry_at", "payload", "handoff", "created_at", "updated_at"}
AGENT_KEYS = {"agent", "status", "stale"}
METRICS_KEYS = {"tasks_total", "by_state", "by_kind", "active_by_agent", "avg_progress_active",
                "dead_lettered", "deliveries_total", "deliveries_by_outcome",
                "approvals_pending", "agents_registered", "agents_online"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r")
    monkeypatch.setenv("CICC_GH_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("CICC_COORD_APPROVERS", "owner")
    monkeypatch.delenv("RABBITMQ_AMQP_URL", raising=False)
    yield
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def test_conformance_agents_dto(client):
    client.post("/api/v1/coordination/agents/register",
                json={"agent": "fx-agent", "capabilities": ["ops"]}, headers=W)
    agents = client.get("/api/v1/coordination/agents", headers=R).json()["agents"]
    assert agents and AGENT_KEYS <= set(agents[0].keys())
    assert agents[0]["stale"] in (True, False)


def test_conformance_tasks_dto_and_state_enum(client):
    r = client.post("/api/v1/coordination/tasks",
                    json={"kind": "fixture_task", "payload": {}, "idempotency_key": "fx-1"}, headers=W)
    assert r.status_code == 201
    tid = r.json()["task_id"]
    tasks = client.get("/api/v1/coordination/tasks", headers=R).json()["tasks"]
    t = next(x for x in tasks if x["task_id"] == tid)
    assert TASK_KEYS <= set(t.keys())
    assert t["state"] in CANONICAL_STATES
    assert isinstance(t["progress"], int) and 0 <= t["progress"] <= 100
    # filters per contract
    assert client.get("/api/v1/coordination/tasks?state=CREATED", headers=R).status_code == 200
    assert client.get("/api/v1/coordination/tasks?kind=fixture_task", headers=R).status_code == 200
    assert client.get("/api/v1/coordination/tasks?dead_letter=false", headers=R).status_code == 200
    # dag
    d = client.get("/api/v1/coordination/tasks/dag", headers=R).json()
    assert {"nodes", "edges", "known_ids"} <= set(d.keys())


def test_conformance_metrics_dto(client):
    m = client.get("/api/v1/coordination/metrics", headers=R).json()
    assert METRICS_KEYS <= set(m.keys())


def test_conformance_error_codes(client):
    # 401 no token when tokens configured
    assert client.get("/api/v1/coordination/tasks").status_code == 401
    # 404 unknown task
    assert client.get("/api/v1/coordination/tasks/nope", headers=R).status_code == 404
    # 422 invalid
    assert client.post("/api/v1/coordination/tasks", json={"kind": "!!"}, headers=W).status_code == 422
    # 409 illegal report (complete from CREATED)
    r = client.post("/api/v1/coordination/tasks",
                    json={"kind": "fixture_task", "idempotency_key": "fx-2"}, headers=W)
    tid = r.json()["task_id"]
    assert client.post(f"/api/v1/coordination/tasks/{tid}/complete",
                       json={"result": "x"}, headers=W).status_code == 409
    # 403 non-approver
    r = client.post("/api/v1/coordination/tasks",
                    json={"kind": "fixture_task", "requires_approval": True,
                          "idempotency_key": "fx-3"}, headers=W)
    tid3 = r.json()["task_id"]
    assert client.post(f"/api/v1/coordination/tasks/{tid3}/approve",
                       json={"decided_by": "intruder"}, headers=W).status_code == 403


def test_conformance_webhook_dto_and_replay_detection(client, monkeypatch):
    body = json.dumps({"action": "opened", "repository": {"full_name": "r"}, "sender": {"login": "u"},
                       "pull_request": {"number": 5, "title": "t", "labels": [{"name": "ops"}],
                                        "head": {"ref": "b"}}}).encode()
    sig = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    h = {"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "fx-wh-1",
         "X-Hub-Signature-256": sig, "Content-Type": "application/json"}
    r1 = client.post("/api/v1/coordination/webhook/github", content=body, headers=h)
    assert r1.status_code == 200 and r1.json()["duplicate"] is False
    r2 = client.post("/api/v1/coordination/webhook/github", content=body, headers=h)
    assert r2.status_code == 200 and r2.json()["duplicate"] is True
    assert r2.json().get("replay_alert") is False  # fresh duplicate, within window
    # events DTO carries task_id (M13)
    evs = client.get("/api/v1/coordination/events", headers=R).json()["events"]
    e = next(x for x in evs if x["delivery_id"] == "fx-wh-1")
    assert e.get("task_id") == "gh-fx-wh-1"
    # force old first_seen -> replay alert (detection only, still deduped)
    monkeypatch.setenv("CICC_GH_MAX_REPLAY_AGE_S", "1")
    from datetime import timedelta
    from app import models, ops
    from app.coordination.registry import utcnow
    with ops.SessionLocal() as s:
        ev = s.get(models.GitHubEvent, "fx-wh-1")
        ev.received_at = utcnow() - timedelta(hours=2)
        s.commit()
    r3 = client.post("/api/v1/coordination/webhook/github", content=body, headers=h)
    assert r3.json()["duplicate"] is True and r3.json()["replay_alert"] is True
    # detection-only alert row exists (rule engine may auto-resolve unknown
    # rules, so query state=all and match on rule name)
    alerts = client.get("/api/v1/ops/alerts?state=all", headers=R).json()
    items = alerts["alerts"] if isinstance(alerts, dict) else alerts
    hit = [a for a in items if a.get("rule") == "webhook_replay_after_window"]
    assert hit and "possible replay" in hit[0]["message"]
