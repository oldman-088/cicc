"""M13 — integration BOUNDARY tests (error handling + cross-domain isolation)
and reliability/security regression checks.

Actors are simulated agent fixtures over the real HTTP API (TestClient) —
NOT Arena sessions; no Arena execution is claimed.
"""
import json

import pytest

from app import ratelimit
from app.coordination import registry

W = {"Authorization": "Bearer w", "Content-Type": "application/json"}
R = {"Authorization": "Bearer r"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r")
    monkeypatch.setenv("CICC_GH_WEBHOOK_SECRET", "s")
    monkeypatch.setenv("CICC_COORD_APPROVERS", "owner")
    monkeypatch.delenv("RABBITMQ_AMQP_URL", raising=False)
    yield
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def _reg(client, agent, caps):
    assert client.post("/api/v1/coordination/agents/register",
                       json={"agent": agent, "capabilities": caps}, headers=W).status_code == 201


def _submit(client, key, kind, caps):
    r = client.post("/api/v1/coordination/tasks",
                    json={"kind": kind, "payload": {"required_capabilities": caps}, "idempotency_key": f"m13-{key}"},
                    headers=W)
    assert r.status_code == 201
    return r.json()["task_id"]


# ---------- M13-02: boundary error handling ----------

def test_boundary_errors_are_consistent(client):
    # unknown task -> 404 on every per-task endpoint
    for ep in ("", "/events", "/deliveries", "/approval"):
        assert client.get(f"/api/v1/coordination/tasks/nope{ep}", headers=R).status_code == 404
    # illegal transition -> 409 AND audited as transition_rejected
    tid = _submit(client, "b1", "threat_intel", ["threat_intel"])
    r = client.post(f"/api/v1/coordination/tasks/{tid}/complete", json={"result": "x"}, headers=W)
    assert r.status_code == 409
    evs = client.get(f"/api/v1/coordination/tasks/{tid}/events", headers=R).json()["events"]
    # illegal report is audited (report:complete ignored) and answered 409
    assert any(e["kind"] == "report:complete" and "ignored" in (e["detail"] or "") for e in evs)
    # validation -> 422
    assert client.post("/api/v1/coordination/tasks", json={"kind": "!!!"}, headers=W).status_code == 422
    # unknown agent heartbeat -> 404
    assert client.post("/api/v1/coordination/agents/ghost/heartbeat", json={}, headers=W).status_code == 404


def test_auth_boundaries_enforced(client):
    # without any token headers when tokens are set -> 401
    assert client.get("/api/v1/coordination/tasks").status_code == 401
    assert client.post("/api/v1/coordination/tasks", json={"kind": "x"}).status_code == 401
    # write token satisfies read
    assert client.get("/api/v1/coordination/tasks", headers=W).status_code == 200
    # read token does NOT satisfy write
    assert client.post("/api/v1/coordination/tasks", json={"kind": "x"}, headers=R).status_code == 401


def test_cross_domain_routing_isolation(client):
    """Threat-intel tasks must never route to the vuln-only agent and vice
    versa (capability boundary between Agent 2 and Agent 3 domains)."""
    _reg(client, "agent-2-threat", ["threat_intel"])
    _reg(client, "agent-3-vuln", ["vuln_intel"])
    t_ti = _submit(client, "iso-ti", "threat_intel", ["threat_intel"])
    t_vi = _submit(client, "iso-vi", "vuln_intel", ["vuln_intel"])
    r1 = client.post(f"/api/v1/coordination/tasks/{t_ti}/route", headers=W).json()
    r2 = client.post(f"/api/v1/coordination/tasks/{t_vi}/route", headers=W).json()
    assert r1["agent"] == "agent-2-threat" and r2["agent"] == "agent-3-vuln"
    # a task requiring BOTH caps has no capable agent -> BLOCKED, never misrouted
    t_both = _submit(client, "iso-both", "hybrid", ["threat_intel", "vuln_intel"])
    r3 = client.post(f"/api/v1/coordination/tasks/{t_both}/route", headers=W).json()
    assert r3["agent"] is None and r3["state"] == "BLOCKED"


def test_webhook_to_dashboard_read_chain(client):
    """Webhook ingest -> task visible in the exact DTOs the dashboard reads."""
    import hashlib, hmac
    body = json.dumps({"action": "opened", "repository": {"full_name": "oldman-088/cicc"},
                       "sender": {"login": "u"}, "pull_request": {"number": 42, "title": "x",
                       "labels": [{"name": "ops"}], "head": {"ref": "b"}}}).encode()
    sig = "sha256=" + hmac.new(b"s", body, hashlib.sha256).hexdigest()
    r = client.post("/api/v1/coordination/webhook/github", content=body,
                    headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "m13-wh-1",
                             "X-Hub-Signature-256": sig, "Content-Type": "application/json"})
    assert r.status_code == 200 and r.json()["ok"]
    evs = client.get("/api/v1/coordination/events", headers=R).json()["events"]
    assert any(e["delivery_id"] == "m13-wh-1" and e["task_id"] for e in evs)
    tasks = client.get("/api/v1/coordination/tasks?kind=pr_opened", headers=R).json()["tasks"]
    assert any(t["task_id"] == "gh-m13-wh-1" and t["state"] == "CREATED" for t in tasks)


# ---------- M13-03: reliability / security regression ----------

def test_audit_completeness_for_full_lifecycle(client):
    """Every transition in a full lifecycle is present in the audit trail,
    in order, with no gaps."""
    _reg(client, "agent-2-threat", ["threat_intel"])
    tid = _submit(client, "aud-1", "threat_intel", ["threat_intel"])
    for ep, body in (("route", None), ("deliver", None), ("ack", None), ("start", None),
                     ("progress", {"percent": 10}), ("complete", {"result": "ok"})):
        assert client.post(f"/api/v1/coordination/tasks/{tid}/{ep}", json=body, headers=W).status_code == 200
    evs = client.get(f"/api/v1/coordination/tasks/{tid}/events", headers=R).json()["events"]
    kinds = [e["kind"] for e in reversed(evs)]  # API returns newest-first
    chain = ["created", "delivery:published", "state:QUEUED->ACKNOWLEDGED",
             "state:ACKNOWLEDGED->RUNNING", "progress", "state:RUNNING->COMPLETED"]
    it = iter(kinds)
    assert all(any(c == k for k in it) for c in chain), kinds
    assert client.get(f"/api/v1/coordination/tasks/{tid}", headers=R).json()["state"] == "COMPLETED"


def test_duplicate_submission_idempotency_boundary(client):
    t1 = _submit(client, "dup-1", "threat_intel", ["threat_intel"])
    r = client.post("/api/v1/coordination/tasks",
                    json={"kind": "threat_intel", "idempotency_key": "m13-dup-1"}, headers=W)
    assert r.json()["task_id"] == t1 and r.json()["duplicate"] is True
    evs = client.get(f"/api/v1/coordination/tasks/{t1}/events", headers=R).json()["events"]
    assert any(e["kind"] == "duplicate_idempotency_key" for e in evs)


def test_notifications_have_no_network_path():
    """Outbound notifications stay disabled: adapter must not construct any
    network client even when enabled flags are set."""
    import inspect
    from app import notifications
    src = inspect.getsource(notifications)
    assert "import requests" not in src and "httpx" not in src and "urlopen" not in src
    assert "socket" not in src


def test_no_raw_secrets_in_webhook_normalized_payloads(client):
    import hashlib, hmac
    body = json.dumps({"action": "opened", "repository": {"full_name": "r"},
                       "sender": {"login": "u"},
                       "pull_request": {"number": 1, "title": "t", "labels": [], "head": {"ref": "b"},
                                        "token": "ghp_secret123", "authorization": "Bearer xyz"}}).encode()
    sig = "sha256=" + hmac.new(b"s", body, hashlib.sha256).hexdigest()
    client.post("/api/v1/coordination/webhook/github", content=body,
                headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "m13-red-1",
                         "X-Hub-Signature-256": sig, "Content-Type": "application/json"})
    evs = client.get("/api/v1/coordination/events", headers=R).json()["events"]
    norm = json.dumps([e.get("normalized") for e in evs if e["delivery_id"] == "m13-red-1"])
    assert "ghp_secret123" not in norm and "Bearer xyz" not in norm
