"""Milestone 9 tests: webhook secret rotation (dual-secret), retry backoff +
sweep requeue, task list kind filter."""
import hashlib
import hmac
import json

import pytest

from app import ops, ratelimit
from app.coordination import registry

SECRET = "rot-new-secret"
OLD_SECRET = "rot-old-secret"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    monkeypatch.setenv("CICC_GH_WEBHOOK_SECRET", SECRET)
    monkeypatch.delenv("CICC_GH_WEBHOOK_SECRET_PREVIOUS", raising=False)
    monkeypatch.delenv("CICC_COORD_RETRY_BACKOFF_S", raising=False)
    for v in ("CICC_OPS_WRITE_TOKEN", "CICC_OPS_READ_TOKEN", "RABBITMQ_AMQP_URL"):
        monkeypatch.delenv(v, raising=False)
    yield
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def _post(client, body, secret=SECRET, delivery="d-1"):
    raw = json.dumps(body).encode()
    sig = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    return client.post("/api/v1/coordination/webhook/github", content=raw,
                       headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": delivery,
                                "X-Hub-Signature-256": sig, "Content-Type": "application/json"})


def _payload(labels=None, **extra):
    p = {"action": "opened", "repository": {"full_name": "oldman-088/cicc"},
         "sender": {"login": "u"}, "pull_request": {"number": 1, "title": "t",
                                                     "labels": [{"name": x} for x in (labels or [])],
                                                     "head": {"ref": "b"}}}
    p.update(extra)
    return p


# ---------- rotation ----------

def test_rotation_old_secret_accepted_during_grace(client, monkeypatch):
    monkeypatch.setenv("CICC_GH_WEBHOOK_SECRET_PREVIOUS", OLD_SECRET)
    r = _post(client, _payload(labels=["ops"]), secret=OLD_SECRET, delivery="d-rot-old")
    assert r.status_code == 200 and r.json()["ok"]
    r = _post(client, _payload(labels=["ops"]), secret=SECRET, delivery="d-rot-new")
    assert r.status_code == 200 and r.json()["ok"]


def test_rotation_wrong_secret_rejected(client, monkeypatch):
    monkeypatch.setenv("CICC_GH_WEBHOOK_SECRET_PREVIOUS", OLD_SECRET)
    r = _post(client, _payload(), secret="nope", delivery="d-rot-bad")
    assert r.status_code == 401


# ---------- backoff + requeue ----------

def _make_task(client, delivery="d-b1"):
    _post(client, _payload(labels=["ops"]), delivery=delivery)
    return f"gh-{delivery}"


def test_retry_sets_backoff_and_sweep_requeues(client, monkeypatch):
    monkeypatch.setenv("CICC_COORD_RETRY_BACKOFF_S", "30")
    tid = _make_task(client, "d-b1")
    client.post(f"/api/v1/coordination/tasks/{tid}/route")
    r = client.post(f"/api/v1/coordination/tasks/{tid}/fail", json={"reason": "boom"})
    t = client.get(f"/api/v1/coordination/tasks/{tid}").json()
    # fail() routes through dead_letter(): below max attempts it lands in RETRYING
    # with a backoff timestamp set
    assert t["state"] == "RETRYING" and t["next_retry_at"] is not None
    # sweep while backoff pending: not requeued
    r = client.post("/api/v1/coordination/sweep").json()
    assert tid not in r["requeued"]
    # force backoff elapsed
    with ops.SessionLocal() as s:
        from sqlalchemy import select
        from app import models
        task = s.execute(select(models.CoordinationTask).where(
            models.CoordinationTask.task_id == tid)).scalar_one()
        from datetime import timedelta
        from app.coordination.registry import utcnow
        task.next_retry_at = utcnow() - timedelta(seconds=1)
        s.commit()
    r = client.post("/api/v1/coordination/sweep").json()
    assert tid in r["requeued"]
    t = client.get(f"/api/v1/coordination/tasks/{tid}").json()
    assert t["state"] == "QUEUED" and t["next_retry_at"] is None


def test_backoff_exponential():
    import os
    os.environ["CICC_COORD_RETRY_BACKOFF_S"] = "10"
    try:
        assert [registry.backoff_seconds(i) for i in (1, 2, 3, 4)] == [10, 20, 40, 80]
        assert registry.backoff_seconds(20) == 3600  # capped
    finally:
        del os.environ["CICC_COORD_RETRY_BACKOFF_S"]


# ---------- list filters ----------

def test_list_kind_filter(client):
    _post(client, _payload(labels=["ops"]), delivery="d-f1")
    _post(client, _payload(labels=["security"]), delivery="d-f2")
    all_t = client.get("/api/v1/coordination/tasks").json()["tasks"]
    ops_t = client.get("/api/v1/coordination/tasks?kind=pr_opened").json()["tasks"]
    assert len(all_t) >= 2 and all(t["kind"] == "pr_opened" for t in ops_t)
    st = client.get("/api/v1/coordination/tasks?state=CREATED").json()["tasks"]
    assert all(t["state"] == "CREATED" for t in st)
