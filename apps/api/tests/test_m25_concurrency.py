"""M25 P1 — expanded concurrency & recovery (SQLite, real threaded execution).
PostgreSQL concurrency is covered separately in test_m25_pg_concurrency.py —
SQLite results are NOT claimed as PostgreSQL guarantees.
All traffic is fixture-labeled (in-process TestClient), not agent traffic.
"""
import hashlib
import hmac
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from sqlalchemy import select

from app import models, ops, ratelimit
from app.coordination import registry

W = {"Authorization": "Bearer w", "Content-Type": "application/json"}
R = {"Authorization": "Bearer r"}
APPR = W  # write token; decided_by must be in CICC_COORD_APPROVERS

SECRET = "m25-secret"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r")
    monkeypatch.setenv("CICC_COORD_APPROVERS", "owner")
    monkeypatch.setenv("CICC_COORD_MAX_ATTEMPTS", "3")
    monkeypatch.setenv("CICC_COORD_RETRY_BACKOFF_S", "0")
    monkeypatch.setenv("CICC_GH_WEBHOOK_SECRET", SECRET)
    monkeypatch.delenv("RABBITMQ_AMQP_URL", raising=False)
    yield
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def _mk(client, tid, **kw):
    body = {"task_id": tid, "kind": "m25", "payload": {}, **kw}
    r = client.post("/api/v1/coordination/tasks", json=body, headers=W)
    assert r.status_code == 201, r.text


def _run(client, tid, agent="a1"):
    client.post("/api/v1/coordination/agents/register", json={"agent": agent}, headers=W)
    client.post(f"/api/v1/coordination/tasks/{tid}/route", json={"agent": agent}, headers=W)
    client.post(f"/api/v1/coordination/tasks/{tid}/ack", json={}, headers=W)
    client.post(f"/api/v1/coordination/tasks/{tid}/start", json={}, headers=W)


def _wh(delivery):
    raw = json.dumps({"action": "opened", "repository": {"full_name": "o/r"}, "sender": {"login": "u"},
                      "pull_request": {"number": 88, "title": "t", "labels": [{"name": "ops"}], "head": {"ref": "b"}}}).encode()
    sig = "sha256=" + hmac.new(SECRET.encode(), raw, hashlib.sha256).hexdigest()
    h = {"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": delivery,
         "X-Hub-Signature-256": sig, "Content-Type": "application/json"}
    return raw, h


def test_concurrent_webhook_duplicate_deliveries(client):
    """8 threads deliver the SAME X-GitHub-Delivery concurrently -> 1 event row, 1 task."""
    raw, h = _wh("m25-wh-race")
    with ThreadPoolExecutor(max_workers=8) as ex:
        rs = list(ex.map(lambda _: client.post("/api/v1/coordination/webhook/github", content=raw, headers=h), range(8)))
    assert all(r.status_code == 200 for r in rs)
    dups = [r.json() for r in rs if r.json().get("duplicate")]
    assert len(dups) == 7, f"expected 7 duplicates, got {len(dups)}"
    with ops.SessionLocal() as s:
        n_ev = len(s.execute(select(models.GitHubEvent).where(models.GitHubEvent.delivery_id == "m25-wh-race")).scalars().all())
        n_tk = len(s.execute(select(models.CoordinationTask).where(models.CoordinationTask.task_id == "gh-m25-wh-race")).scalars().all())
    assert n_ev == 1 and n_tk == 1


def test_concurrent_approve_reject_race_one_decision_wins(client):
    _mk(client, "m25-ap", requires_approval=True)
    with ThreadPoolExecutor(max_workers=2) as ex:
        r1 = ex.submit(lambda: client.post("/api/v1/coordination/tasks/m25-ap/approve", json={"decided_by": "owner"}, headers=APPR))
        r2 = ex.submit(lambda: client.post("/api/v1/coordination/tasks/m25-ap/reject", json={"decided_by": "owner"}, headers=APPR))
        res = [r1.result(), r2.result()]
    oks = [r for r in res if r.status_code == 200]
    assert len(oks) == 1, f"expected exactly one decision, got {[r.status_code for r in res]}"
    ap = client.get("/api/v1/coordination/tasks/m25-ap/approval", headers=R).json()["approval"]
    assert ap["status"] in ("approved", "rejected")
    # second decision must 409 (no pending approval)
    r = client.post("/api/v1/coordination/tasks/m25-ap/approve", json={"decided_by": "owner"}, headers=APPR)
    assert r.status_code == 409


def test_concurrent_retry_and_fail_on_same_task(client):
    """Concurrent retry vs fail: no contradiction; final state is one of the legal outcomes."""
    _mk(client, "m25-rf")
    _run(client, "m25-rf")
    client.post("/api/v1/coordination/tasks/m25-rf/fail", json={"result": "x"}, headers=W)  # -> RETRYING
    with ThreadPoolExecutor(max_workers=6) as ex:
        rs = list(ex.map(lambda i: client.post("/api/v1/coordination/tasks/m25-rf/retry", headers=W) if i % 2 == 0
                         else client.post("/api/v1/coordination/tasks/m25-rf/fail", json={"result": "y"}, headers=W), range(6)))
    assert all(r.status_code in (200, 409) for r in rs)
    t = client.get("/api/v1/coordination/tasks/m25-rf", headers=R).json()
    assert t["state"].lower() in ("queued", "retrying", "failed", "blocked")
    ev = client.get("/api/v1/coordination/tasks/m25-rf/events", headers=R).json()["events"]
    state_events = [e["kind"] for e in ev if (e["kind"] or "").startswith("state:")]
    assert state_events, "transitions must be audited"
    # latest state event equals persisted state (audit consistency under concurrency)
    latest = state_events[0].split("->")[-1]
    assert latest.lower() == t["state"].lower()


def test_sweep_under_load_requeues_each_retrying_task_once(client):
    for i in range(10):
        _mk(client, f"m25-sw-{i}")
        _run(client, f"m25-sw-{i}")
        client.post(f"/api/v1/coordination/tasks/m25-sw-{i}/fail", json={"result": "x"}, headers=W)
    from app.coordination.registry import utcnow
    with ops.SessionLocal() as s:
        for t in s.execute(select(models.CoordinationTask)).scalars().all():
            if t.state == "RETRYING":
                t.next_retry_at = utcnow() - timedelta(seconds=1)
        s.commit()
    r1 = client.post("/api/v1/coordination/sweep", headers=W).json()
    assert len(r1["requeued"]) == 10
    r2 = client.post("/api/v1/coordination/sweep", headers=W).json()
    assert r2["requeued"] == []  # idempotent: nothing left to requeue
    for i in range(10):
        t = client.get(f"/api/v1/coordination/tasks/m25-sw-{i}", headers=R).json()
        assert t["state"].lower() == "queued" and t["dead_letter"] is False
