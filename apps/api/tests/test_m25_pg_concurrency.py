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
