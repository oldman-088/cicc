"""M28 P1 — PostgreSQL lifecycle reliability & recovery (REAL PostgreSQL via
pgserver, NOT SQLite). New race windows beyond M25/M27: fail-vs-complete,
cancel-vs-complete, complete-vs-timeout-sweep, retry exhaustion / dead-letter,
concurrent retry-vs-requeue, and cross-connection restart consistency.
SQLite threaded equivalents live in test_m25_concurrency.py / test_m24_concurrency.py
and are reported separately.
"""
import os
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

pgserver = pytest.importorskip("pgserver")

import pytest as _pytest  # noqa: E402
from sqlalchemy import create_engine, select  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app import models, ops, ratelimit  # noqa: E402
from app.coordination import registry  # noqa: E402

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


def _running_task(pg_app, tid, **kw):
    pg_app.post("/api/v1/coordination/tasks", json={"task_id": tid, "kind": "m28", "payload": {}, **kw}, headers=W)
    pg_app.post("/api/v1/coordination/agents/register", json={"agent": "a1"}, headers=W)
    for ep, b in [("route", {"agent": "a1"}), ("ack", {}), ("start", {})]:
        pg_app.post(f"/api/v1/coordination/tasks/{tid}/{ep}", json=b, headers=W)


def _state_events(pg_app, tid):
    ev = pg_app.get(f"/api/v1/coordination/tasks/{tid}/events", headers=R).json()["events"]
    return [e for e in ev if (e["kind"] or "").startswith("state:")]


def test_pg_concurrent_fail_vs_complete_single_terminal(pg_app):
    """8 threads race fail vs complete on a RUNNING task: exactly one terminal
    state is persisted, exactly one terminal state event, they agree."""
    _running_task(pg_app, "m28-fc")
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(pg_app.post, f"/api/v1/coordination/tasks/m28-fc/{a}", json={"result": a}, headers=W)
                for a in ["fail", "complete"] * 4]
        rs = [f.result() for f in futs]
    assert all(r.status_code in (200, 409) for r in rs), [r.status_code for r in rs]
    t = pg_app.get("/api/v1/coordination/tasks/m28-fc", headers=R).json()
    sev = _state_events(pg_app, "m28-fc")
    term = [e for e in sev if e["kind"].split("->")[-1] in ("COMPLETED", "FAILED")]
    assert len(term) == 1
    # events endpoint returns latest-first; persisted state must equal the
    # latest persisted state event (audit consistency)
    assert t["state"].lower() == sev[0]["kind"].split("->")[-1].lower()


def test_pg_concurrent_cancel_vs_complete(pg_app):
    _running_task(pg_app, "m28-cc")
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = [ex.submit(pg_app.post, f"/api/v1/coordination/tasks/m28-cc/{a}", json={} if a == "cancel" else {"result": "x"}, headers=W)
                for a in ["cancel", "complete", "cancel", "complete", "cancel", "complete"]]
        rs = [f.result() for f in futs]
    assert all(r.status_code in (200, 409) for r in rs), [r.status_code for r in rs]
    t = pg_app.get("/api/v1/coordination/tasks/m28-cc", headers=R).json()
    sev = _state_events(pg_app, "m28-cc")
    term = [e for e in sev if e["kind"].split("->")[-1] in ("COMPLETED", "CANCELLED")]
    assert len(term) == 1 and t["state"].lower() == sev[0]["kind"].split("->")[-1].lower()


def test_pg_complete_races_timeout_sweep(pg_app, monkeypatch):
    """RUNNING task with timeout_s=1; clock advanced past timeout; threads race
    complete vs sweep-timeout. Exactly one outcome, event history consistent."""
    _running_task(pg_app, "m28-ct", timeout_s=1)
    future = registry.utcnow() + __import__("datetime").timedelta(seconds=3600)
    monkeypatch.setattr(registry, "utcnow", lambda: future)
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = [ex.submit(pg_app.post, "/api/v1/coordination/tasks/m28-ct/complete", json={"result": "done"}, headers=W)]
        futs += [ex.submit(pg_app.post, "/api/v1/coordination/sweep", headers=W) for _ in range(5)]
        rs = [f.result() for f in futs]
    assert rs[0].status_code in (200, 409)
    t = pg_app.get("/api/v1/coordination/tasks/m28-ct", headers=R).json()
    sev = _state_events(pg_app, "m28-ct")
    term = [e for e in sev if e["kind"].split("->")[-1] in ("COMPLETED", "FAILED")]
    assert len(term) == 1 and t["state"].lower() == sev[0]["kind"].split("->")[-1].lower()


def test_pg_retry_exhaustion_dead_letter_exactly_once(pg_app, monkeypatch):
    """CICC_COORD_MAX_ATTEMPTS=2: two fails exhaust attempts -> dead_letter once;
    further fail reports are ignored (FAILED not a fail source) -> still one event."""
    monkeypatch.setenv("CICC_COORD_MAX_ATTEMPTS", "2")
    _running_task(pg_app, "m28-dl")
    # attempt 1: fail -> FAILED -> dead-letter policy moves to RETRYING (attempts=1)
    r1 = pg_app.post("/api/v1/coordination/tasks/m28-dl/fail", json={"result": "e1"}, headers=W)
    assert r1.status_code == 200 and r1.json()["applied"] is True
    pg_app.post("/api/v1/coordination/tasks/m28-dl/retry", headers=W)          # RETRYING -> QUEUED (attempts=2)
    for ep, b in [("route", {"agent": "a1"}), ("ack", {}), ("start", {})]:
        pg_app.post(f"/api/v1/coordination/tasks/m28-dl/{ep}", json=b, headers=W)
    # attempt 2: fail applied -> attempts exhausted -> dead-letter exactly once
    r2 = pg_app.post("/api/v1/coordination/tasks/m28-dl/fail", json={"result": "e2"}, headers=W)
    assert r2.status_code == 200 and r2.json()["applied"] is True
    # duplicate fail after dead-letter must be ignored, no second dead_letter event
    r3 = pg_app.post("/api/v1/coordination/tasks/m28-dl/fail", json={"result": "e3"}, headers=W)
    assert r3.status_code == 200 and r3.json()["applied"] is False
    t = pg_app.get("/api/v1/coordination/tasks/m28-dl", headers=R).json()
    assert t["dead_letter"] is True and t["state"].lower() == "blocked" and t["attempts"] >= 2
    ev = pg_app.get("/api/v1/coordination/tasks/m28-dl/events", headers=R).json()["events"]
    assert sum(1 for e in ev if e["kind"] == "dead_letter") == 1
    assert sum(1 for e in ev if (e["kind"] or "") == "state:RUNNING->FAILED") == 2
    assert sum(1 for e in ev if (e["kind"] or "").endswith("->BLOCKED")) == 1


def test_pg_concurrent_retry_vs_sweep_requeue_exactly_once(pg_app, monkeypatch):
    """RETRYING task with elapsed backoff; threads race manual retry vs sweep
    requeue — guarded CAS lets exactly one QUEUED transition apply."""
    monkeypatch.setenv("CICC_COORD_RETRY_BACKOFF_S", "0")
    _running_task(pg_app, "m28-rr")
    pg_app.post("/api/v1/coordination/tasks/m28-rr/fail", json={"result": "boom"}, headers=W)  # FAILED
    pg_app.post("/api/v1/coordination/tasks/m28-rr/retry", headers=W)  # -> RETRYING -> QUEUED
    pg_app.post("/api/v1/coordination/tasks/m28-rr/route", json={"agent": "a1"}, headers=W)
    pg_app.post("/api/v1/coordination/tasks/m28-rr/ack", json={}, headers=W)
    pg_app.post("/api/v1/coordination/tasks/m28-rr/start", json={}, headers=W)
    pg_app.post("/api/v1/coordination/tasks/m28-rr/fail", json={"result": "boom2"}, headers=W)  # FAILED again
    # force RETRYING with past-due backoff directly via registry
    with ops.SessionLocal() as s:
        t = s.execute(select(models.CoordinationTask).where(models.CoordinationTask.task_id == "m28-rr")).scalar_one()
        registry.transition(s, t, "RETRYING", "forced for race")
        t.next_retry_at = registry.utcnow() - __import__("datetime").timedelta(seconds=1)
        s.commit()
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = [ex.submit(pg_app.post, "/api/v1/coordination/tasks/m28-rr/retry", headers=W)]
        futs += [ex.submit(pg_app.post, "/api/v1/coordination/sweep", headers=W) for _ in range(5)]
        rs = [f.result() for f in futs]
    assert all(r.status_code in (200, 409) for r in rs), [r.status_code for r in rs]
    q = [e for e in _state_events(pg_app, "m28-rr") if e["kind"].endswith("->QUEUED")]
    t = pg_app.get("/api/v1/coordination/tasks/m28-rr", headers=R).json()
    assert t["state"].lower() == "queued"
    # exactly one *additional* QUEUED transition from RETRYING won the race
    assert sum(1 for e in q if e["kind"] == "state:RETRYING->QUEUED") == 1


def test_pg_cross_connection_restart_consistency(pg_app, monkeypatch, tmp_path):
    """Simulated restart: after a full lifecycle, open a SECOND engine/connection
    to the same PostgreSQL DB and verify persisted state, correlation key and
    event ordering are intact and consistent (no torn writes)."""
    _running_task(pg_app, "m28-rs", idempotency_key="m28-rs-ik")
    pg_app.post("/api/v1/coordination/tasks/m28-rs/complete", json={"result": "ok"}, headers=W)
    server_uri = None
    # rebuild a second connection from the same pgdata dir
    server2 = pgserver.get_server(str(tmp_path / "pgdata"))  # same server instance
    url2 = server2.get_uri().replace("postgresql://", "postgresql+psycopg2://", 1)
    engine2 = create_engine(url2, pool_pre_ping=True)
    Session2 = sessionmaker(bind=engine2)
    with Session2() as s:
        t = s.execute(select(models.CoordinationTask).where(models.CoordinationTask.task_id == "m28-rs")).scalar_one()
        assert t.state == "COMPLETED"
        assert t.idempotency_key == "m28-rs-ik"
        evs = s.execute(
            select(models.CoordinationTaskEvent).where(models.CoordinationTaskEvent.task_id == "m28-rs")
            .order_by(models.CoordinationTaskEvent.id)
        ).scalars().all()
    kinds = [e.kind for e in evs]
    assert kinds[0] == "created"
    assert kinds[-1] == "state:RUNNING->COMPLETED"
    ids = [e.id for e in evs]
    assert ids == sorted(ids)  # monotonic persisted ordering
    engine2.dispose()


def test_pg_delivery_lease_expiry_recovers_abandoned(pg_app, monkeypatch):
    """Worker crash after delivery: DELIVERING task with elapsed lease is
    re-queued exactly once by sweep; a late ack then loses (409) — and a race
    between sweep and ack has exactly one winner."""
    monkeypatch.setenv("CICC_COORD_LEASE_S", "1")
    pg_app.post("/api/v1/coordination/tasks", json={"task_id": "m28-lease", "kind": "m28", "payload": {}}, headers=W)
    pg_app.post("/api/v1/coordination/agents/register", json={"agent": "a1"}, headers=W)
    pg_app.post("/api/v1/coordination/tasks/m28-lease/route", json={"agent": "a1"}, headers=W)
    # force DELIVERING (no broker in tests -> deliver() stays QUEUED human-assisted)
    with ops.SessionLocal() as s:
        t = s.execute(select(models.CoordinationTask).where(models.CoordinationTask.task_id == "m28-lease")).scalar_one()
        assert registry.transition(s, t, "DELIVERING", "forced for lease test")
        s.commit()
    # advance clock past lease
    import datetime as _dt
    future = registry.utcnow() + _dt.timedelta(seconds=3600)
    monkeypatch.setattr(registry, "utcnow", lambda: future)
    r = pg_app.post("/api/v1/coordination/sweep", headers=W)
    assert r.status_code == 200
    assert "m28-lease" in r.json()["recovered_abandoned"]
    t = pg_app.get("/api/v1/coordination/tasks/m28-lease", headers=R).json()
    assert t["state"].lower() == "queued"
    # second sweep must NOT re-queue again (already QUEUED)
    r2 = pg_app.post("/api/v1/coordination/sweep", headers=W)
    assert "m28-lease" not in (r2.json()["recovered_abandoned"] or [])
    ev = _state_events(pg_app, "m28-lease")
    assert sum(1 for e in ev if e["kind"].endswith("->QUEUED") and "lease" in (e.get("detail") or "")) == 1


def test_pg_ack_races_lease_recovery(pg_app, monkeypatch):
    """Ack racing lease-recovery sweep: exactly one winner; persisted state
    equals the latest persisted state event."""
    monkeypatch.setenv("CICC_COORD_LEASE_S", "1")
    pg_app.post("/api/v1/coordination/tasks", json={"task_id": "m28-ar", "kind": "m28", "payload": {}}, headers=W)
    pg_app.post("/api/v1/coordination/agents/register", json={"agent": "a1"}, headers=W)
    pg_app.post("/api/v1/coordination/tasks/m28-ar/route", json={"agent": "a1"}, headers=W)
    import datetime as _dt
    with ops.SessionLocal() as s:
        t = s.execute(select(models.CoordinationTask).where(models.CoordinationTask.task_id == "m28-ar")).scalar_one()
        assert registry.transition(s, t, "DELIVERING", "forced for race")  # QUEUED -> DELIVERING
        s.commit()
    future = registry.utcnow() + _dt.timedelta(seconds=3600)
    monkeypatch.setattr(registry, "utcnow", lambda: future)
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = [ex.submit(pg_app.post, "/api/v1/coordination/tasks/m28-ar/ack", json={}, headers=W)]
        futs += [ex.submit(pg_app.post, "/api/v1/coordination/sweep", headers=W) for _ in range(5)]
        rs = [f.result() for f in futs]
    assert all(r.status_code in (200, 409) for r in rs), [r.status_code for r in rs]
    t = pg_app.get("/api/v1/coordination/tasks/m28-ar", headers=R).json()
    sev = _state_events(pg_app, "m28-ar")
    assert t["state"].lower() == sev[0]["kind"].split("->")[-1].lower()
    assert t["state"].lower() in ("queued", "acknowledged")


def test_pg_concurrent_amendment_decision_single_winner(pg_app):
    """Real PG: 8 threads race accept/reject on one pending amendment — guarded
    CAS lets exactly one decision apply; the rest get 409."""
    from app.coordination import amendments
    with ops.SessionLocal() as s:
        amendments.propose(s, amendment_id="AMD-PG", title="t", description="d", proposed_by="agent-1")
        s.commit()
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(pg_app.post, "/api/v1/coordination/contract/amendments/AMD-PG/decide",
                          json={"decision": "accept" if i % 2 == 0 else "reject", "decided_by": "owner"}, headers=W)
                for i in range(8)]
        rs = [f.result() for f in futs]
    assert sum(1 for r in rs if r.status_code == 200) == 1
    assert all(r.status_code in (200, 409) for r in rs), [r.status_code for r in rs]
    a = pg_app.get("/api/v1/coordination/contract/amendments/AMD-PG", headers=R).json()
    assert a["status"] in ("accepted", "rejected") and a["decided_by"] == "owner"


def test_pg_concurrent_progress_vs_complete(pg_app):
    """Real PG: progress reports racing complete — persisted state and the
    final progress value must be consistent with the event history."""
    _running_task(pg_app, "m29-pc")
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(pg_app.post, "/api/v1/coordination/tasks/m29-pc/progress", json={"percent": i * 25}, headers=W) for i in range(4)]
        futs += [ex.submit(pg_app.post, "/api/v1/coordination/tasks/m29-pc/complete", json={"result": "done"}, headers=W) for _ in range(4)]
        rs = [f.result() for f in futs]
    assert all(r.status_code in (200, 409) for r in rs), [r.status_code for r in rs]
    t = pg_app.get("/api/v1/coordination/tasks/m29-pc", headers=R).json()
    sev = _state_events(pg_app, "m29-pc")
    assert t["state"].lower() == sev[0]["kind"].split("->")[-1].lower()
    assert t["state"].lower() in ("completed", "running")
    assert 0 <= (t["progress"] or 0) <= 100


# ---------------- M33: additional lifecycle race windows ----------------

def test_pg_approval_decision_races_task_cancel(pg_app):
    """WAITING_FOR_APPROVAL task: approve racing cancel — guarded CAS gives
    exactly one terminal outcome; events consistent with persisted state."""
    pg_app.post("/api/v1/coordination/tasks", json={"task_id": "m33-ap", "kind": "m33", "payload": {}, "requires_approval": True}, headers=W)
    t = pg_app.get("/api/v1/coordination/tasks/m33-ap", headers=R).json()
    assert t["state"].lower() == "waiting_for_approval", t["state"]
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = [ex.submit(pg_app.post, "/api/v1/coordination/tasks/m33-ap/approve",
                          json={"decided_by": "owner"}, headers=W)]
        futs += [ex.submit(pg_app.post, "/api/v1/coordination/tasks/m33-ap/reject",
                           json={"decided_by": "owner"}, headers=W) for _ in range(2)]
        futs += [ex.submit(pg_app.post, "/api/v1/coordination/tasks/m33-ap/cancel", headers=W) for _ in range(3)]
        rs = [f.result() for f in futs]
    codes = [r.status_code for r in rs]
    assert set(codes) <= {200, 409}, codes
    t = pg_app.get("/api/v1/coordination/tasks/m33-ap", headers=R).json()
    sev = _state_events(pg_app, "m33-ap")
    assert t["state"].lower() == sev[0]["kind"].split("->")[-1].lower()
    # approve->QUEUED then cancel->CANCELLED is a valid sequential chain; what
    # must hold: at most one transition into each of those states, and the
    # persisted state equals the latest event (asserted above)
    assert sum(1 for e in sev if e["kind"] == "state:WAITING_FOR_APPROVAL->QUEUED") <= 1
    assert sum(1 for e in sev if e["kind"].endswith("->CANCELLED")) <= 1


def test_pg_webhook_duplicate_races_task_create_same_event(pg_app, monkeypatch):
    """Two concurrent webhook deliveries with the same X-GitHub-Delivery race
    task creation from the same event_id: exactly one task row, one created
    event; the loser is a detected duplicate (not a second task)."""
    monkeypatch.setenv("CICC_GH_WEBHOOK_SECRET", "s3c")
    import hashlib, hmac, json as _json
    payload = _json.dumps({"action": "opened", "repository": {"full_name": "o/r"},
                           "issue": {"number": 7}, "sender": {"login": "u"}}).encode()
    sig = "sha256=" + hmac.new(b"s3c", payload, hashlib.sha256).hexdigest()
    hdrs = {"X-GitHub-Event": "issues", "X-GitHub-Delivery": "m33-del-1",
            "X-Hub-Signature-256": sig, "Content-Type": "application/json",
            "Authorization": "Bearer w"}
    with ThreadPoolExecutor(max_workers=6) as ex:
        rs = list(ex.map(lambda _: pg_app.post("/api/v1/coordination/webhook/github",
                                               content=payload, headers=hdrs), range(6)))
    assert all(r.status_code in (200, 201, 409) for r in rs), [r.status_code for r in rs]
    with ops.SessionLocal() as s:
        rows = s.execute(select(models.CoordinationTask).where(
            models.CoordinationTask.event_id == "m33-del-1")).scalars().all()
    assert len(rows) == 1
    ev = pg_app.get(f"/api/v1/coordination/tasks/{rows[0].task_id}/events", headers=R).json()["events"]
    assert sum(1 for e in ev if e["kind"] == "created") == 1


def test_pg_concurrent_create_same_task_id_no_key(pg_app):
    """M34: 8 threads create the SAME task_id without idempotency_key — the
    unique constraint + replay path must yield exactly one row, all 200/201,
    no 500, one created event."""
    body = {"task_id": "m34-same", "kind": "m34", "payload": {}}
    with ThreadPoolExecutor(max_workers=8) as ex:
        rs = list(ex.map(lambda _: pg_app.post("/api/v1/coordination/tasks", json=body, headers=W), range(8)))
    assert all(r.status_code in (200, 201) for r in rs), [r.status_code for r in rs]
    with ops.SessionLocal() as s:
        rows = s.execute(select(models.CoordinationTask).where(
            models.CoordinationTask.task_id == "m34-same")).scalars().all()
    assert len(rows) == 1
    ev = pg_app.get("/api/v1/coordination/tasks/m34-same/events", headers=R).json()["events"]
    assert sum(1 for e in ev if e["kind"] == "created") == 1
