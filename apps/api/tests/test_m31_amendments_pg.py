"""M31 P0 — amendment governance under REAL PostgreSQL concurrency (pgserver).
Race windows: concurrent duplicate propose, decide-vs-withdraw, supersede vs
decide on overlapping keys, stale-sweep vs decide, effective-version
determinism, history immutability. SQLite behavior is covered by
test_m20_contract_consistency.py and reported separately.
"""
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

pgserver = pytest.importorskip("pgserver")

import pytest as _pytest  # noqa: E402
from sqlalchemy import create_engine, select  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app import models, ops, ratelimit  # noqa: E402
from app.coordination import amendments  # noqa: E402

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


def _amd(aid, **kw):
    b = {"amendment_id": aid, "title": f"t-{aid}", "description": "d", "proposed_by": "agent-1",
         "affects": ["TaskDTO"], "compatibility": {"backward_compatible": True}, "target_version": "1.1"}
    b.update(kw)
    return b


def _db_row(pg_app, aid):
    with ops.SessionLocal() as s:
        return s.execute(select(models.CoordinationAmendment).where(
            models.CoordinationAmendment.amendment_id == aid)).scalar_one()


def test_pg_concurrent_duplicate_propose_single_row(pg_app):
    """8 threads propose the same amendment: exactly one DB row; responses are
    201 (creator) or 200 duplicate:true — never two rows, never 500."""
    body = _amd("AMD-PG-DUP")
    with ThreadPoolExecutor(max_workers=8) as ex:
        rs = list(ex.map(lambda _: pg_app.post("/api/v1/coordination/contract/amendments", json=body, headers=W), range(8)))
    codes = [r.status_code for r in rs]
    assert set(codes) <= {200, 201, 422}, codes
    assert codes.count(201) == 1
    assert all(r.json().get("duplicate") is True for r in rs if r.status_code == 200)
    with ops.SessionLocal() as s:
        n = len(s.execute(select(models.CoordinationAmendment).where(
            models.CoordinationAmendment.amendment_id == "AMD-PG-DUP")).scalars().all())
    assert n == 1


def test_pg_decide_vs_withdraw_race_single_winner(pg_app):
    """decide and withdraw race on one pending amendment: exactly one applies,
    the loser gets 409, and history records exactly one terminal transition."""
    pg_app.post("/api/v1/coordination/contract/amendments", json=_amd("AMD-PG-DW"), headers=W)
    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(pg_app.post, "/api/v1/coordination/contract/amendments/AMD-PG-DW/decide",
                       json={"decision": "accept", "decided_by": "owner"}, headers=W)
        f2 = ex.submit(pg_app.post, "/api/v1/coordination/contract/amendments/AMD-PG-DW/withdraw",
                       json={"by": "agent-1"}, headers=W)
        rs = [f1.result(), f2.result()]
    assert sorted(r.status_code for r in rs) == [200, 409], [r.status_code for r in rs]
    row = _db_row(pg_app, "AMD-PG-DW")
    hist = json.loads(row.history)
    terminal = [h for h in hist if h["to"] in ("accepted", "rejected", "withdrawn")]
    assert len(terminal) == 1


def test_pg_supersede_vs_decide_on_overlapping_keys(pg_app):
    """Two amendments affecting the same contract key: A accepted with
    supersedes=[B] racing a direct decision on B — B ends in exactly one of
    {superseded, accepted, rejected}, never both, history consistent."""
    pg_app.post("/api/v1/coordination/contract/amendments", json=_amd("AMD-PG-A", affects=["TaskDTO"], target_version="1.2"), headers=W)
    pg_app.post("/api/v1/coordination/contract/amendments", json=_amd("AMD-PG-B", affects=["TaskDTO"]), headers=W)
    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(pg_app.post, "/api/v1/coordination/contract/amendments/AMD-PG-A/decide",
                       json={"decision": "accept", "decided_by": "owner", "supersedes": ["AMD-PG-B"]}, headers=W)
        f2 = ex.submit(pg_app.post, "/api/v1/coordination/contract/amendments/AMD-PG-B/decide",
                       json={"decision": "reject", "decided_by": "owner"}, headers=W)
        ra, rb = f1.result(), f2.result()
    # Exactly one terminal outcome for B: either A's supersede won (B=superseded,
    # direct decide 409) or the direct decision won (B=rejected, supersede skipped).
    assert ra.status_code == 200
    assert rb.status_code in (200, 409)
    b = _db_row(pg_app, "AMD-PG-B")
    if rb.status_code == 200:
        assert b.status == "rejected" and ra.json()["superseded"] == []
    else:
        assert b.status == "superseded" and ra.json()["superseded"] == ["AMD-PG-B"]
    hist = json.loads(b.history)
    assert len([h for h in hist if h["to"] in ("superseded", "accepted", "rejected")]) == 1


def test_pg_stale_sweep_vs_decide_race(pg_app, monkeypatch):
    """Pending amendment past stale threshold: sweep-stale races a decide —
    exactly one terminal status, no double transition in history."""
    import datetime as _dt
    pg_app.post("/api/v1/coordination/contract/amendments", json=_amd("AMD-PG-STALE"), headers=W)
    with ops.SessionLocal() as s:
        row = s.execute(select(models.CoordinationAmendment).where(
            models.CoordinationAmendment.amendment_id == "AMD-PG-STALE")).scalar_one()
        row.created_at = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=30)
        s.commit()
    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(pg_app.post, "/api/v1/coordination/sweep", headers=W)
        f2 = ex.submit(pg_app.post, "/api/v1/coordination/contract/amendments/AMD-PG-STALE/decide",
                       json={"decision": "accept", "decided_by": "owner"}, headers=W)
        rs = [f1.result(), f2.result()]
    assert rs[1].status_code in (200, 409)
    row = _db_row(pg_app, "AMD-PG-STALE")
    assert row.status in ("stale", "accepted")
    hist = json.loads(row.history)
    assert len([h for h in hist if h["to"] in ("stale", "accepted", "rejected")]) == 1


def test_pg_effective_version_deterministic(pg_app):
    """Accepted amendments with versions 1.1, 1.2, 1.10 -> effective 1.10
    (numeric compare, deterministic regardless of decision order)."""
    for aid, v in [("AMD-V1", "1.1"), ("AMD-V2", "1.2"), ("AMD-V10", "1.10")]:
        pg_app.post("/api/v1/coordination/contract/amendments", json=_amd(aid, target_version=v), headers=W)
        assert pg_app.post(f"/api/v1/coordination/contract/amendments/{aid}/decide",
                           json={"decision": "accept", "decided_by": "owner"}, headers=W).status_code == 200
    c = pg_app.get("/api/v1/coordination/contract", headers=R).json()
    assert c["version"] == "1.10"
    assert c["amendments"]["effective_version"] == "1.10"


def test_pg_history_immutable_after_decisions(pg_app):
    """History is append-only: after propose+decide+refs, the chain is
    complete and no endpoint can rewrite it."""
    pg_app.post("/api/v1/coordination/contract/amendments", json=_amd("AMD-PG-H"), headers=W)
    pg_app.post("/api/v1/coordination/contract/amendments/AMD-PG-H/refs", json={"refs": ["PR#4@dd0643b"]}, headers=W)
    pg_app.post("/api/v1/coordination/contract/amendments/AMD-PG-H/decide",
                json={"decision": "accept", "decided_by": "owner", "linked_refs": ["PR#4@ba02302"]}, headers=W)
    a = pg_app.get("/api/v1/coordination/contract/amendments/AMD-PG-H", headers=R).json()
    chain = [(h["from"], h["to"]) for h in a["history"]]
    assert chain == [(None, "pending"), ("pending", "accepted")], chain
    # decide again -> 409, history unchanged
    pg_app.post("/api/v1/coordination/contract/amendments/AMD-PG-H/decide",
                json={"decision": "reject", "decided_by": "owner"}, headers=W)
    a2 = pg_app.get("/api/v1/coordination/contract/amendments/AMD-PG-H", headers=R).json()
    assert a2["history"] == a["history"]


def test_pg_compat_validation_unknown_keys(pg_app):
    """Compatibility validation flags affected keys not present in the live
    contract descriptor."""
    pg_app.post("/api/v1/coordination/contract/amendments",
                json=_amd("AMD-PG-C", affects=["NoSuchContractKey"]), headers=W)
    r = pg_app.post("/api/v1/coordination/contract/amendments/AMD-PG-C/decide",
                    json={"decision": "accept", "decided_by": "owner"}, headers=W)
    assert r.status_code == 200
    assert r.json()["compatibility"]["unknown_affected_keys"] == ["NoSuchContractKey"]
    assert r.json()["compatibility"]["ok"] is False


def test_pg_self_approval_prohibited_server_side(pg_app, monkeypatch):
    """M31 policy: proposer cannot decide own amendment (403), even as a
    configured approver; override env permits it with audit flag."""
    monkeypatch.setenv("CICC_COORD_APPROVERS", "owner,agent-1")
    pg_app.post("/api/v1/coordination/contract/amendments", json=_amd("AMD-PG-SA", proposed_by="agent-1"), headers=W)
    r = pg_app.post("/api/v1/coordination/contract/amendments/AMD-PG-SA/decide",
                    json={"decision": "accept", "decided_by": "agent-1"}, headers=W)
    assert r.status_code == 403 and "self-approval" in r.json()["detail"]
    monkeypatch.setenv("CICC_AMENDMENT_ALLOW_SELF_APPROVAL", "1")
    r = pg_app.post("/api/v1/coordination/contract/amendments/AMD-PG-SA/decide",
                    json={"decision": "accept", "decided_by": "agent-1"}, headers=W)
    assert r.status_code == 200 and r.json()["self_approved"] is True
    row = _db_row(pg_app, "AMD-PG-SA")
    assert any(h["by"] == "agent-1" and h["to"] == "accepted" for h in json.loads(row.history))


# ---------------- M32: additional race windows ----------------

def test_pg_decide_vs_attach_refs_race(pg_app):
    """decide racing attach_refs: refs merge and decision both land; final
    history has exactly one terminal transition; linked_refs are the union."""
    pg_app.post("/api/v1/coordination/contract/amendments", json=_amd("AMD-M32-R"), headers=W)
    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(pg_app.post, "/api/v1/coordination/contract/amendments/AMD-M32-R/refs",
                       json={"refs": ["PR#4@151b060"]}, headers=W)
        f2 = ex.submit(pg_app.post, "/api/v1/coordination/contract/amendments/AMD-M32-R/decide",
                       json={"decision": "accept", "decided_by": "owner", "linked_refs": ["PR#7@91a16256"]}, headers=W)
        rs = [f1.result(), f2.result()]
    assert all(r.status_code == 200 for r in rs), [r.status_code for r in rs]
    a = pg_app.get("/api/v1/coordination/contract/amendments/AMD-M32-R", headers=R).json()
    assert a["status"] == "accepted"
    assert set(a["linked_refs"]) >= {"PR#4@151b060", "PR#7@91a16256"}
    hist = a["history"]
    assert len([h for h in hist if h["to"] in ("accepted", "rejected")]) == 1


def test_pg_task_sweep_vs_amendment_sweep_interleaved(pg_app, monkeypatch):
    """POST /sweep runs task sweeps and amendment stale-sweep in one call;
    racing two sweeps must not double-transition anything."""
    import datetime as _dt
    # one expired task + one stale amendment
    pg_app.post("/api/v1/coordination/tasks", json={"task_id": "m32-sw", "kind": "m32", "payload": {}, "ttl_s": 1}, headers=W)
    pg_app.post("/api/v1/coordination/contract/amendments", json=_amd("AMD-M32-SW"), headers=W)
    with ops.SessionLocal() as s:
        row = s.execute(select(models.CoordinationAmendment).where(
            models.CoordinationAmendment.amendment_id == "AMD-M32-SW")).scalar_one()
        row.created_at = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=30)
        t = s.execute(select(models.CoordinationTask).where(models.CoordinationTask.task_id == "m32-sw")).scalar_one()
        t.expires_at = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(seconds=5)
        s.commit()
    with ThreadPoolExecutor(max_workers=4) as ex:
        rs = list(ex.map(lambda _: pg_app.post("/api/v1/coordination/sweep", headers=W), range(4)))
    assert all(r.status_code == 200 for r in rs)
    # task expired exactly once
    ev = pg_app.get("/api/v1/coordination/tasks/m32-sw/events", headers=R).json()["events"]
    assert sum(1 for e in ev if (e["kind"] or "") == "state:CREATED->EXPIRED") == 1
    # amendment stale exactly once
    row = _db_row(pg_app, "AMD-M32-SW")
    assert row.status == "stale"
    hist = json.loads(row.history)
    assert len([h for h in hist if h["to"] == "stale"]) == 1


def test_pg_withdraw_vs_supersede_vs_stale_single_terminal(pg_app, monkeypatch):
    """Three racing terminal transitions (withdraw by proposer, supersede via
    another accept, stale sweep) — exactly one wins; history consistent."""
    import datetime as _dt
    pg_app.post("/api/v1/coordination/contract/amendments", json=_amd("AMD-M32-X"), headers=W)
    pg_app.post("/api/v1/coordination/contract/amendments", json=_amd("AMD-M32-Y"), headers=W)
    with ops.SessionLocal() as s:
        row = s.execute(select(models.CoordinationAmendment).where(
            models.CoordinationAmendment.amendment_id == "AMD-M32-X")).scalar_one()
        row.created_at = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=30)
        s.commit()
    with ThreadPoolExecutor(max_workers=3) as ex:
        f1 = ex.submit(pg_app.post, "/api/v1/coordination/contract/amendments/AMD-M32-X/withdraw", json={"by": "agent-1"}, headers=W)
        f2 = ex.submit(pg_app.post, "/api/v1/coordination/contract/amendments/AMD-M32-Y/decide",
                       json={"decision": "accept", "decided_by": "owner", "supersedes": ["AMD-M32-X"]}, headers=W)
        f3 = ex.submit(pg_app.post, "/api/v1/coordination/sweep", headers=W)
        rs = [f1.result(), f2.result(), f3.result()]
    # sweep and decide-Y may still return 200 for their own targets; what matters
    # is that X received exactly ONE terminal transition (CAS losers get 409 or
    # skip silently) — verified via history below.
    row = _db_row(pg_app, "AMD-M32-X")
    assert row.status in ("withdrawn", "superseded", "stale")
    hist = json.loads(row.history)
    terminal = [h for h in hist if h["to"] in ("withdrawn", "superseded", "stale", "accepted", "rejected")]
    assert len(terminal) == 1


def test_pg_effective_version_under_concurrent_accepts(pg_app):
    """Concurrent accepts of different versions: effective version is the
    deterministic numeric max regardless of commit order."""
    for i, v in enumerate(["1.3", "1.10", "1.2"]):
        aid = f"AMD-M32-V{i}"
        pg_app.post("/api/v1/coordination/contract/amendments", json=_amd(aid, target_version=v), headers=W)
    with ThreadPoolExecutor(max_workers=3) as ex:
        rs = list(ex.map(
            lambda i: pg_app.post(f"/api/v1/coordination/contract/amendments/AMD-M32-V{i}/decide",
                                  json={"decision": "accept", "decided_by": "owner"}, headers=W),
            range(3)))
    assert all(r.status_code == 200 for r in rs)
    c1 = pg_app.get("/api/v1/coordination/contract", headers=R).json()
    c2 = pg_app.get("/api/v1/coordination/contract", headers=R).json()
    assert c1["version"] == c2["version"] == "1.10"  # deterministic


def test_pg_concurrent_domain_invoke_single_execution(pg_app):
    """M35 real-PG race: 8 threads invoke the same domain kind with the SAME
    idempotency_key — the handler executes exactly once; one task row."""
    from app.coordination import domains
    calls = []

    def handler(payload, task):
        calls.append(1)
        return {"result": {"ok": True}, "provenance": {"source": "pg-fixture", "produced_at": "2026-11-06T06:00:00Z"}}

    domains.register_domain("vuln_intel", handler, version="0.0-pg-fixture", source_ref="test-only")
    try:
        body = {"payload": {"x": 1}, "idempotency_key": "pg-dom-ik"}
        with ThreadPoolExecutor(max_workers=8) as ex:
            rs = list(ex.map(lambda _: pg_app.post("/api/v1/coordination/domains/vuln_intel/invoke", json=body, headers=W), range(8)))
        codes = [r.status_code for r in rs]
        assert set(codes) <= {200, 201}, codes
        assert codes.count(201) == 1 and codes.count(200) == 7
        assert len(calls) == 1, f"handler executed {len(calls)} times"
        with ops.SessionLocal() as s:
            n = len(s.execute(select(models.CoordinationTask).where(
                models.CoordinationTask.idempotency_key == "pg-dom-ik")).scalars().all())
        assert n == 1
    finally:
        domains.unregister_domain("vuln_intel")
