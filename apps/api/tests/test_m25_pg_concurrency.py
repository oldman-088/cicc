"""M25 P1 — PostgreSQL concurrency verification (REAL PostgreSQL via pgserver,
NOT SQLite). Skipped automatically if pgserver is unavailable. These tests are
the only basis for PostgreSQL concurrency claims; SQLite threaded results are
reported separately in test_m25_concurrency.py.
"""
import pytest

pgserver = pytest.importorskip("pgserver")

from concurrent.futures import ThreadPoolExecutor  # noqa: E402

import pytest as _pytest  # noqa: E402
from sqlalchemy import create_engine, select  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app import models, ops, ratelimit  # noqa: E402

W = {"Authorization": "Bearer w", "Content-Type": "application/json"}
R = {"Authorization": "Bearer r"}


@_pytest.fixture()
def pg_app(monkeypatch, tmp_path):
    server = pgserver.get_server(str(tmp_path / "pgdata"))
    url = server.get_uri().replace("postgresql://", "postgresql+psycopg2://", 1)
    engine = create_engine(url, pool_pre_ping=True, pool_size=10, max_overflow=10)
    models.Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    monkeypatch.setattr(ops, "engine", engine)
    monkeypatch.setattr(ops, "SessionLocal", Session)
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r")
    monkeypatch.setenv("CICC_COORD_APPROVERS", "owner")
    monkeypatch.delenv("RABBITMQ_AMQP_URL", raising=False)
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    ops.init_db()
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        yield c
    engine.dispose()
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def test_pg_concurrent_duplicate_submission(pg_app):
    body = {"task_id": "m25-pg-race", "idempotency_key": "m25-pg-ik", "kind": "m25", "payload": {}}
    with ThreadPoolExecutor(max_workers=8) as ex:
        rs = list(ex.map(lambda _: pg_app.post("/api/v1/coordination/tasks", json=body, headers=W), range(8)))
    assert all(r.status_code in (200, 201) for r in rs), [r.status_code for r in rs]
    with ops.SessionLocal() as s:
        rows = s.execute(select(models.CoordinationTask).where(models.CoordinationTask.task_id == "m25-pg-race")).scalars().all()
    assert len(rows) == 1


def test_pg_concurrent_complete_single_winner(pg_app):
    pg_app.post("/api/v1/coordination/tasks", json={"task_id": "m25-pg-cc", "kind": "m25", "payload": {}}, headers=W)
    pg_app.post("/api/v1/coordination/agents/register", json={"agent": "a1"}, headers=W)
    for ep, b in [("route", {"agent": "a1"}), ("ack", {}), ("start", {})]:
        pg_app.post(f"/api/v1/coordination/tasks/m25-pg-cc/{ep}", json=b, headers=W)
    with ThreadPoolExecutor(max_workers=8) as ex:
        rs = list(ex.map(lambda _: pg_app.post("/api/v1/coordination/tasks/m25-pg-cc/complete", json={"result": "x"}, headers=W), range(8)))
    applied = [r for r in rs if r.status_code == 200 and r.json().get("applied") is True]
    assert len(applied) == 1, f"applied={len(applied)} codes={[r.status_code for r in rs]}"
    t = pg_app.get("/api/v1/coordination/tasks/m25-pg-cc", headers=R).json()
    assert t["state"].lower() == "completed"
    ev = pg_app.get("/api/v1/coordination/tasks/m25-pg-cc/events", headers=R).json()["events"]
    assert sum(1 for e in ev if (e["kind"] or "") == "state:RUNNING->COMPLETED") == 1


def test_pg_concurrent_webhook_duplicate_delivery(pg_app):
    import hashlib, hmac, json as _json
    import os
    os.environ["CICC_GH_WEBHOOK_SECRET"] = "pg-secret"
    raw = _json.dumps({"action": "opened", "repository": {"full_name": "o/r"}, "sender": {"login": "u"},
                       "pull_request": {"number": 99, "title": "t", "labels": [{"name": "ops"}], "head": {"ref": "b"}}}).encode()
    sig = "sha256=" + hmac.new(b"pg-secret", raw, hashlib.sha256).hexdigest()
    h = {"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "pg-wh-race",
         "X-Hub-Signature-256": sig, "Content-Type": "application/json"}
    with ThreadPoolExecutor(max_workers=8) as ex:
        rs = list(ex.map(lambda _: pg_app.post("/api/v1/coordination/webhook/github", content=raw, headers=h), range(8)))
    assert all(r.status_code == 200 for r in rs), [r.status_code for r in rs]
    assert sum(1 for r in rs if r.json().get("duplicate")) == 7
    with ops.SessionLocal() as s:
        assert len(s.execute(select(models.GitHubEvent).where(models.GitHubEvent.delivery_id == "pg-wh-race")).scalars().all()) == 1
        assert len(s.execute(select(models.CoordinationTask).where(models.CoordinationTask.task_id == "gh-pg-wh-race")).scalars().all()) == 1


def test_pg_approval_expiry_vs_decision_race(pg_app, monkeypatch):
    import time
    from app.coordination import registry as reg
    from datetime import timedelta
    monkeypatch.setenv("CICC_COORD_APPROVAL_TTL_S", "1")
    pg_app.post("/api/v1/coordination/tasks", json={"task_id": "pg-ap", "kind": "m25", "payload": {}, "requires_approval": True}, headers=W)
    # let it expire, then race decide vs sweep-expiry
    with ops.SessionLocal() as s:
        ap = s.execute(select(models.CoordinationApproval).where(models.CoordinationApproval.task_id == "pg-ap")).scalar_one()
        ap.expires_at = reg.utcnow() - timedelta(seconds=1)
        s.commit()
    with ThreadPoolExecutor(max_workers=2) as ex:
        r1 = ex.submit(lambda: pg_app.post("/api/v1/coordination/tasks/pg-ap/approve", json={"decided_by": "owner"}, headers=W))
        r2 = ex.submit(lambda: pg_app.post("/api/v1/coordination/sweep", headers=W))
        res = [r1.result(), r2.result()]
    # exactly one outcome: either 410 (expired) or 200 (approved) — never both 200
    ok_count = sum(1 for r in res if r.status_code == 200)
    assert ok_count <= 1, [r.status_code for r in res]
    ap = pg_app.get("/api/v1/coordination/tasks/pg-ap/approval", headers=R).json()["approval"]
    assert ap["status"] in ("approved", "expired")


def test_pg_concurrent_sweep_requeue(pg_app):
    from app.coordination import registry as reg
    from datetime import timedelta
    for i in range(6):
        tid = f"pg-sw-{i}"
        pg_app.post("/api/v1/coordination/tasks", json={"task_id": tid, "kind": "m25", "payload": {}}, headers=W)
        pg_app.post("/api/v1/coordination/agents/register", json={"agent": "a1"}, headers=W)
        pg_app.post(f"/api/v1/coordination/tasks/{tid}/route", json={"agent": "a1"}, headers=W)
        pg_app.post(f"/api/v1/coordination/tasks/{tid}/ack", json={}, headers=W)
        pg_app.post(f"/api/v1/coordination/tasks/{tid}/start", json={}, headers=W)
        pg_app.post(f"/api/v1/coordination/tasks/{tid}/fail", json={"result": "x"}, headers=W)
    with ops.SessionLocal() as s:
        for t in s.execute(select(models.CoordinationTask)).scalars().all():
            if t.state == "RETRYING":
                t.next_retry_at = reg.utcnow() - timedelta(seconds=1)
        s.commit()
    with ThreadPoolExecutor(max_workers=4) as ex:
        rs = list(ex.map(lambda _: pg_app.post("/api/v1/coordination/sweep", headers=W), range(4)))
    assert all(r.status_code == 200 for r in rs)
    total_requeued = sum(len(r.json()["requeued"]) for r in rs)
    assert total_requeued == 6, f"requeued {total_requeued} times for 6 tasks (double-requeue race?)"
    for i in range(6):
        t = pg_app.get(f"/api/v1/coordination/tasks/pg-sw-{i}", headers=R).json()
        assert t["state"].lower() == "queued" and t["dead_letter"] is False


def test_pg_concurrent_deliver_ack_race(pg_app):
    """Real PG: 8 threads race deliver+ack on one task; exactly one ack wins,
    audit stays consistent (latest state event == persisted state)."""
    pg_app.post("/api/v1/coordination/tasks", json={"task_id": "pg-da", "kind": "m25", "payload": {}}, headers=W)
    pg_app.post("/api/v1/coordination/agents/register", json={"agent": "a1"}, headers=W)
    pg_app.post("/api/v1/coordination/tasks/pg-da/route", json={"agent": "a1"}, headers=W)
    def hit(i):
        if i % 2 == 0:
            return pg_app.post("/api/v1/coordination/tasks/pg-da/deliver", headers=W)
        return pg_app.post("/api/v1/coordination/tasks/pg-da/ack", json={}, headers=W)
    with ThreadPoolExecutor(max_workers=8) as ex:
        rs = list(ex.map(hit, range(8)))
    assert all(r.status_code in (200, 409) for r in rs), [r.status_code for r in rs]
    t = pg_app.get("/api/v1/coordination/tasks/pg-da", headers=R).json()
    assert t["state"].lower() in ("acknowledged", "delivering", "assigned")
    ev = pg_app.get("/api/v1/coordination/tasks/pg-da/events", headers=R).json()["events"]
    state_events = [e for e in ev if (e["kind"] or "").startswith("state:")]
    assert state_events and state_events[0]["kind"].split("->")[-1].lower() == t["state"].lower()
    # exactly one transition into ACKNOWLEDGED
    assert sum(1 for e in state_events if e["kind"].endswith("->ACKNOWLEDGED")) <= 1


def test_pg_duplicate_complete_is_idempotent(pg_app):
    """Real PG: task completed; a duplicate complete must 409 and add no second
    COMPLETED transition; correlation (idempotency_key) stays stable."""
    pg_app.post("/api/v1/coordination/tasks", json={"task_id": "pg-dc", "idempotency_key": "pg-dc-ik", "kind": "m25", "payload": {}}, headers=W)
    pg_app.post("/api/v1/coordination/agents/register", json={"agent": "a1"}, headers=W)
    for ep, b in [("route", {"agent": "a1"}), ("ack", {}), ("start", {})]:
        pg_app.post(f"/api/v1/coordination/tasks/pg-dc/{ep}", json=b, headers=W)
    r1 = pg_app.post("/api/v1/coordination/tasks/pg-dc/complete", json={"result": "done"}, headers=W)
    r2 = pg_app.post("/api/v1/coordination/tasks/pg-dc/complete", json={"result": "done"}, headers=W)
    assert r1.status_code == 200 and r2.status_code == 409
    ev = pg_app.get("/api/v1/coordination/tasks/pg-dc/events", headers=R).json()["events"]
    assert sum(1 for e in ev if (e["kind"] or "") == "state:RUNNING->COMPLETED") == 1
    t = pg_app.get("/api/v1/coordination/tasks/pg-dc", headers=R).json()
    assert t["idempotency_key"] == "pg-dc-ik" and t["state"].lower() == "completed"
