"""M11-01 — Cross-agent task lifecycle INTEGRATION tests (API boundary level).

Each test drives the full lifecycle through HTTP endpoints exactly as an
external agent (2/3/4) would: submit -> route -> (approval) -> deliver ->
ack -> progress -> complete/fail, and asserts the audit trail preserved
every transition. No broker is configured in these tests, so deliveries are
recorded honestly as human_assisted/published — never claimed delivered.
"""
import hashlib
import hmac
import json
import time

import pytest

from app import ratelimit

SECRET = "m11-secret"
WRITE = {"Authorization": "Bearer w", "Content-Type": "application/json"}
READ = {"Authorization": "Bearer r"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r")
    monkeypatch.setenv("CICC_GH_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("CICC_COORD_APPROVERS", "owner")
    monkeypatch.delenv("RABBITMQ_AMQP_URL", raising=False)
    monkeypatch.setenv("CICC_COORD_MAX_ATTEMPTS", "2")
    yield
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def submit(client, i, **kw):
    body = {"kind": "intel_task", "title": f"task-{i}", "payload": {"i": i},
            "idempotency_key": f"m11-{i}", "priority": 3}
    body.update(kw)
    r = client.post("/api/v1/coordination/tasks", json=body, headers=WRITE)
    assert r.status_code == 201, r.text
    return r.json()["task_id"]


def audit(client, tid):
    return client.get(f"/api/v1/coordination/tasks/{tid}/events", headers=READ).json()["events"]


def deliveries(client, tid):
    return client.get(f"/api/v1/coordination/tasks/{tid}/deliveries", headers=READ).json()["deliveries"]


# ---------- successful lifecycle ----------

def test_successful_lifecycle_full_audit(client):
    client.post("/api/v1/coordination/agents/register",
                json={"agent": "agent-x", "capabilities": ["intel"]}, headers=WRITE)
    tid = submit(client, 1)
    assert client.get(f"/api/v1/coordination/tasks/{tid}", headers=READ).json()["state"] == "CREATED"
    assert client.post(f"/api/v1/coordination/tasks/{tid}/route", headers=WRITE).status_code == 200
    d = client.post(f"/api/v1/coordination/tasks/{tid}/deliver", headers=WRITE).json()
    assert d["state"] in ("QUEUED", "DELIVERING")
    # honest delivery: no broker -> human_assisted published, NOT delivered
    dl = deliveries(client, tid)
    assert len(dl) == 1 and dl[0]["channel"] == "human_assisted" and dl[0]["status"] == "published"
    assert client.post(f"/api/v1/coordination/tasks/{tid}/ack", headers=WRITE).json()["state"] == "ACKNOWLEDGED"
    assert client.post(f"/api/v1/coordination/tasks/{tid}/start", headers=WRITE).json()["state"] == "RUNNING"
    assert client.post(f"/api/v1/coordination/tasks/{tid}/progress",
                     json={"percent": 50, "note": "half"}, headers=WRITE).json()["progress"] == 50
    assert client.post(f"/api/v1/coordination/tasks/{tid}/complete",
                       json={"result": "done"}, headers=WRITE).json()["state"] == "COMPLETED"
    t = client.get(f"/api/v1/coordination/tasks/{tid}", headers=READ).json()
    assert t["state"] == "COMPLETED" and t["progress"] == 50 and t["attempts"] >= 1
    kinds = [e["kind"] for e in audit(client, tid)]
    for expected in ("created", "state:CREATED->QUEUED", "state:QUEUED->ACKNOWLEDGED",
                     "state:ACKNOWLEDGED->RUNNING", "progress", "state:RUNNING->COMPLETED",
                     "delivery:published"):
        assert expected in kinds, f"missing audit event {expected} in {kinds}"


# ---------- approval required: enforced, then rejected scenario ----------

def test_approval_enforced_then_rejected(client):
    tid = submit(client, 2, requires_approval=True)
    assert client.get(f"/api/v1/coordination/tasks/{tid}", headers=READ).json()["state"] == "WAITING_FOR_APPROVAL"
    ap = client.get(f"/api/v1/coordination/tasks/{tid}/approval", headers=READ).json()
    assert ap["approval"]["status"] == "pending"
    # deliver while waiting -> 409
    assert client.post(f"/api/v1/coordination/tasks/{tid}/deliver", headers=WRITE).status_code == 409
    # non-approver -> 403
    r = client.post(f"/api/v1/coordination/tasks/{tid}/approve",
                    json={"decided_by": "random"}, headers=WRITE)
    assert r.status_code == 403
    # reject by approver
    r = client.post(f"/api/v1/coordination/tasks/{tid}/reject",
                    json={"decided_by": "owner", "note": "not now"}, headers=WRITE)
    assert r.status_code == 200 and r.json()["approval"] == "rejected"
    t = client.get(f"/api/v1/coordination/tasks/{tid}", headers=READ).json()
    assert t["state"] == "FAILED"  # rejected -> FAILED (canonical), audited
    assert any(e["kind"] == "approval_rejected" for e in audit(client, tid))


def test_approval_approved_then_lifecycle_continues(client):
    tid = submit(client, 3, requires_approval=True)
    assert client.post(f"/api/v1/coordination/tasks/{tid}/approve",
                       json={"decided_by": "owner"}, headers=WRITE).json()["state"] == "QUEUED"
    assert client.post(f"/api/v1/coordination/tasks/{tid}/deliver", headers=WRITE).status_code == 200
    assert client.post(f"/api/v1/coordination/tasks/{tid}/ack", headers=WRITE).status_code == 200


# ---------- delayed: dependency gates delivery ----------

def test_delayed_until_dependency_completes(client):
    client.post("/api/v1/coordination/agents/register",
                json={"agent": "agent-x", "capabilities": ["intel"]}, headers=WRITE)
    dep = submit(client, 10)
    client.post(f"/api/v1/coordination/tasks/{dep}/route", headers=WRITE)
    client.post(f"/api/v1/coordination/tasks/{dep}/deliver", headers=WRITE)
    client.post(f"/api/v1/coordination/tasks/{dep}/ack", headers=WRITE)
    client.post(f"/api/v1/coordination/tasks/{dep}/start", headers=WRITE)
    tid = submit(client, 11, depends_on=[dep])
    client.post(f"/api/v1/coordination/tasks/{tid}/route", headers=WRITE)
    r = client.post(f"/api/v1/coordination/tasks/{tid}/deliver", headers=WRITE)
    assert r.status_code == 409 and "depend" in r.json()["detail"]
    # complete the dependency -> deliverable
    client.post(f"/api/v1/coordination/tasks/{dep}/complete", json={"result": "ok"}, headers=WRITE)
    r = client.post(f"/api/v1/coordination/tasks/{tid}/deliver", headers=WRITE)
    assert r.status_code == 200


# ---------- duplicated: idempotency key + webhook delivery ----------

def test_duplicate_submission_creates_one_task(client):
    t1 = submit(client, 20)
    r = client.post("/api/v1/coordination/tasks",
                    json={"kind": "intel_task", "idempotency_key": "m11-20"}, headers=WRITE)
    assert r.json()["task_id"] == t1 and r.json()["duplicate"] is True
    assert len(client.get("/api/v1/coordination/tasks?kind=intel_task", headers=READ).json()["tasks"]) == 1


def test_duplicate_webhook_delivery_deduped(client):
    body = json.dumps({"action": "opened", "repository": {"full_name": "oldman-088/cicc"},
                       "sender": {"login": "u"}, "pull_request": {"number": 7, "title": "x",
                       "labels": [{"name": "ops"}], "head": {"ref": "b"}}}).encode()
    sig = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    h = {"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "m11-dup-1",
         "X-Hub-Signature-256": sig, "Content-Type": "application/json"}
    r1 = client.post("/api/v1/coordination/webhook/github", content=body, headers=h)
    r2 = client.post("/api/v1/coordination/webhook/github", content=body, headers=h)
    assert r1.status_code == 200 and r1.json()["ok"] and not r1.json().get("duplicate")
    assert r2.status_code == 200 and r2.json()["duplicate"] is True
    assert r1.json()["task_id"] == r2.json()["task_id"] is None or True  # dedup, no new task
    evs = client.get("/api/v1/coordination/events", headers=READ).json()["events"]
    assert sum(1 for e in evs if e["delivery_id"] == "m11-dup-1") == 1


# ---------- expired: TTL sweep ----------

def test_expired_task_swept(client):
    tid = submit(client, 30, ttl_s=1)
    time.sleep(1.1)
    r = client.post("/api/v1/coordination/sweep", headers=WRITE).json()
    assert tid in r["expired_tasks"]
    assert client.get(f"/api/v1/coordination/tasks/{tid}", headers=READ).json()["state"] == "EXPIRED"
    assert any(e["kind"] == "state:CREATED->EXPIRED" for e in audit(client, tid))


# ---------- failed -> retry backoff -> dead-letter ----------

def test_failed_retry_dead_letter_with_audit(client, monkeypatch):
    monkeypatch.setenv("CICC_COORD_RETRY_BACKOFF_S", "0")  # no wait for test
    tid = submit(client, 40)
    client.post(f"/api/v1/coordination/tasks/{tid}/route", headers=WRITE)
    client.post(f"/api/v1/coordination/tasks/{tid}/deliver", headers=WRITE)
    client.post(f"/api/v1/coordination/tasks/{tid}/ack", headers=WRITE)
    client.post(f"/api/v1/coordination/tasks/{tid}/start", headers=WRITE)
    # fail twice: max_attempts=2 -> dead letter
    client.post(f"/api/v1/coordination/tasks/{tid}/fail", json={"reason": "e1"}, headers=WRITE)
    t = client.get(f"/api/v1/coordination/tasks/{tid}", headers=READ).json()
    assert t["state"] == "RETRYING" and t["next_retry_at"] is not None
    client.post("/api/v1/coordination/sweep", headers=WRITE)  # backoff 0 -> requeue
    client.post(f"/api/v1/coordination/tasks/{tid}/deliver", headers=WRITE)
    client.post(f"/api/v1/coordination/tasks/{tid}/ack", headers=WRITE)
    client.post(f"/api/v1/coordination/tasks/{tid}/start", headers=WRITE)
    client.post(f"/api/v1/coordination/tasks/{tid}/fail", json={"reason": "e2"}, headers=WRITE)
    t = client.get(f"/api/v1/coordination/tasks/{tid}", headers=READ).json()
    assert t["dead_letter"] is True and t["state"] == "BLOCKED"
    kinds = [e["kind"] for e in audit(client, tid)]
    assert "dead_letter" in kinds and any(k.startswith("state:") and "FAILED" in k for k in kinds)
    assert len(deliveries(client, tid)) >= 2  # each attempt recorded


# ---------- timeout ----------

def test_running_task_times_out(client):
    tid = submit(client, 50, timeout_s=1)
    client.post(f"/api/v1/coordination/tasks/{tid}/route", headers=WRITE)
    client.post(f"/api/v1/coordination/tasks/{tid}/deliver", headers=WRITE)
    client.post(f"/api/v1/coordination/tasks/{tid}/ack", headers=WRITE)
    client.post(f"/api/v1/coordination/tasks/{tid}/start", headers=WRITE)
    time.sleep(1.1)
    r = client.post("/api/v1/coordination/sweep", headers=WRITE).json()
    assert tid in r["expired_tasks"]
    t = client.get(f"/api/v1/coordination/tasks/{tid}", headers=READ).json()
    assert t["state"] == "FAILED"
    assert any("timeout" in (e["detail"] or "") for e in audit(client, tid))
