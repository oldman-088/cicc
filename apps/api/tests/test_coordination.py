"""Central coordination tests: GitHub webhook signature/replay/dedup,
normalization (secrets stripped, provenance kept), durable task registry
state machine, routing engine, handoff payloads, agent reporting, HTTP gates.
All local — no broker, no network; broker publish path is covered by the
'no broker configured -> human-assisted' branch only."""
import hashlib
import hmac
import json

import pytest

from app import models, ops, ratelimit
from app.coordination import handoff, registry, routing, webhook

SECRET = "test-webhook-secret"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    ops._overview_cache["data"] = None
    ops._overview_cache["ts"] = 0.0
    monkeypatch.setenv("CICC_GH_WEBHOOK_SECRET", SECRET)
    for v in ("CICC_OPS_WRITE_TOKEN", "CICC_OPS_READ_TOKEN", "RABBITMQ_AMQP_URL"):
        monkeypatch.delenv(v, raising=False)
    yield
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def _payload():
    return {
        "action": "opened",
        "repository": {"full_name": "oldman-088/cicc"},
        "sender": {"login": "agent-4"},
        "pull_request": {"number": 7, "title": "feat", "labels": [{"name": "ops"}],
                         "head": {"ref": "arena/x"}},
        "token": "super-secret-value",  # must be stripped from normalized copy
    }


def _sign(body: bytes) -> str:
    return "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()


def _post(client, body: dict, delivery="d-1", event="pull_request", sig=None):
    raw = json.dumps(body).encode()
    return client.post(
        "/api/v1/coordination/webhook/github",
        content=raw,
        headers={"X-GitHub-Event": event, "X-GitHub-Delivery": delivery,
                 "X-Hub-Signature-256": sig if sig is not None else _sign(raw),
                 "Content-Type": "application/json"},
    )


# ---------- webhook ----------

def test_webhook_ingest_ok_and_task_created(client):
    r = _post(client, _payload())
    assert r.status_code == 200
    d = r.json()
    assert d["ok"] and not d["duplicate"] and d["kind"] == "pr_opened"
    tasks = client.get("/api/v1/coordination/tasks").json()["tasks"]
    assert len(tasks) == 1 and tasks[0]["task_id"] == "gh-d-1" and tasks[0]["state"] == "NEW"
    assert tasks[0]["pr_ref"] == "7" and tasks[0]["branch_ref"] == "arena/x"
    # normalized payload stored with provenance, secret stripped
    assert "super-secret-value" not in json.dumps(tasks[0]["payload"])
    assert tasks[0]["payload"]["sender"] == "agent-4"
    evs = client.get("/api/v1/coordination/events").json()["events"]
    assert evs[0]["delivery_id"] == "d-1" and evs[0]["sender"] == "agent-4"


def test_webhook_bad_signature_rejected(client):
    r = _post(client, _payload(), sig="sha256=deadbeef")
    assert r.status_code == 401
    assert client.get("/api/v1/coordination/tasks").json()["tasks"] == []


def test_webhook_fail_closed_without_secret(client, monkeypatch):
    monkeypatch.delenv("CICC_GH_WEBHOOK_SECRET")
    r = _post(client, _payload(), sig=_sign(json.dumps(_payload()).encode()))
    assert r.status_code == 401


def test_webhook_replay_dedup(client):
    assert _post(client, _payload(), delivery="d-9").status_code == 200
    r = _post(client, _payload(), delivery="d-9")
    assert r.status_code == 200 and r.json()["duplicate"] is True
    assert len(client.get("/api/v1/coordination/tasks").json()["tasks"]) == 1


# ---------- registry state machine ----------

def test_registry_transitions_validated():
    with ops.SessionLocal() as s:
        t = registry.create_task(s, task_id="t-1", event_id=None, source="manual",
                                 kind="manual", repo="r", pr_ref=None, branch_ref=None,
                                 title="x", payload={})
        assert registry.transition(s, t, "WEIRD") is False
        assert registry.transition(s, t, "IN_PROGRESS") is False  # NEW -> IN_PROGRESS illegal
        assert registry.transition(s, t, "QUEUED") is True
        assert registry.transition(s, t, "DELIVERED") is True
        assert registry.transition(s, t, "IN_PROGRESS") is True
        assert registry.transition(s, t, "COMPLETED") is True
        assert registry.transition(s, t, "QUEUED") is False  # terminal
        evs = registry.task_events(s, "t-1")
        kinds = [e["kind"] for e in evs]
        assert any("rejected" in k for k in kinds) and any("COMPLETED" in k for k in kinds)
        s.commit()


# ---------- routing ----------

def test_routing_default_label_rule(client):
    _post(client, _payload())  # label "ops"
    r = client.post("/api/v1/coordination/tasks/gh-d-1/route")
    # no write token configured -> allowed (trusted dev); state QUEUED, agent set
    assert r.status_code == 200
    d = r.json()
    assert d["agent"] == "agent-1-ops" and d["state"] == "QUEUED"


def test_routing_unknown_goes_blocked(client):
    _post(client, {"action": "opened", "repository": {"full_name": "x/y"},
                   "sender": {"login": "u"}, "issue": {"number": 3, "title": "t", "labels": []}})
    d = client.post("/api/v1/coordination/tasks/gh-d-1/route").json()
    assert d["agent"] is None and d["state"] == "BLOCKED"


def test_routing_custom_rule(client, monkeypatch):
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    _post(client, _payload(), delivery="d-5")
    r = client.post("/api/v1/coordination/rules",
                    json={"name": "pr-all", "match": {"kind": "pr_opened"}, "agent": "agent-4-integration", "priority": 1},
                    headers={"Authorization": "Bearer w"})
    assert r.status_code == 201
    d = client.post("/api/v1/coordination/tasks/gh-d-5/route", headers={"Authorization": "Bearer w"}).json()
    assert d["agent"] == "agent-4-integration"
    rules = client.get("/api/v1/coordination/rules").json()["rules"]
    assert any(x["name"] == "pr-all" for x in rules)


# ---------- handoff + reporting ----------

def test_handoff_human_assisted_and_reporting(client):
    _post(client, _payload(), delivery="d-2")
    d = client.post("/api/v1/coordination/tasks/gh-d-2/route").json()
    assert d["state"] == "QUEUED"
    r = client.post("/api/v1/coordination/tasks/gh-d-2/deliver")
    assert r.status_code == 200
    # no RABBITMQ_AMQP_URL -> human-assisted copy-ready payload, NOT delivered
    assert r.json()["via"] == "human_assisted"
    h = r.json()["handoff"]
    assert h["task_id"] == "gh-d-2" and h["agent"] == "agent-1-ops"
    assert "do NOT control Arena sessions" in h["boundary"]
    assert "never push to main" in h["instructions"]
    # agent reports: QUEUED ->(ack requires DELIVERED; ignored) ; use direct transitions
    d = client.post("/api/v1/coordination/tasks/gh-d-2/ack").json()
    assert d["state"] in ("QUEUED",)  # ack from QUEUED is recorded, not a transition
    with ops.SessionLocal() as s:
        t = s.execute(models.CoordinationTask.__table__.select().where(
            models.CoordinationTask.task_id == "gh-d-2")).scalar_one_or_none() if False else None
    # force DELIVERED then ack -> IN_PROGRESS -> complete
    with ops.SessionLocal() as s:
        t = s.execute(__import__("sqlalchemy").select(models.CoordinationTask).where(
            models.CoordinationTask.task_id == "gh-d-2")).scalar_one_or_none()
        assert registry.transition(s, t, "DELIVERED", "test")
        s.commit()
    assert client.post("/api/v1/coordination/tasks/gh-d-2/ack").json()["state"] == "IN_PROGRESS"
    d = client.post("/api/v1/coordination/tasks/gh-d-2/complete", json={"result": "done in PR #9"}).json()
    assert d["state"] == "COMPLETED"
    evs = client.get("/api/v1/coordination/tasks/gh-d-2/events").json()["events"]
    assert any("COMPLETED" in e["kind"] for e in evs)


def test_handoff_broker_failure_falls_back(client, monkeypatch):
    """A configured-but-dead broker must fall back to RETRYING/human-assisted,
    never claim delivery."""
    monkeypatch.setenv("RABBITMQ_AMQP_URL", "amqp://guest:guest@127.0.0.1:1/%2f")  # dead
    _post(client, _payload(), delivery="d-3")
    client.post("/api/v1/coordination/tasks/gh-d-3/route")
    r = client.post("/api/v1/coordination/tasks/gh-d-3/deliver").json()
    assert r["delivered"] is False and r["via"] == "human_assisted"
    assert r["state"] in ("RETRYING", "QUEUED")


# ---------- read/write gates on coordination ----------

def test_coordination_read_gate(client, monkeypatch):
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r")
    assert client.get("/api/v1/coordination/tasks").status_code == 401
    assert client.get("/api/v1/coordination/tasks", headers={"Authorization": "Bearer r"}).status_code == 200
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    assert client.post("/api/v1/coordination/tasks/gh-x/route").status_code == 401


def test_webhook_exempt_from_read_token_gate(client, monkeypatch):
    """GitHub sends no ops read token; the webhook authenticates via HMAC only."""
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r")
    assert client.get("/api/v1/coordination/tasks").status_code == 401
    r = _post(client, _payload(), delivery="d-gate")
    assert r.status_code == 200 and r.json()["ok"] is True
    assert client.get("/api/v1/coordination/tasks", headers={"Authorization": "Bearer r"}).status_code == 200
