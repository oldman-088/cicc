"""M36 — logical backup / restore / verify (scripts/backup_restore.py).

SQLite roundtrip: create real coordination rows (tasks + events incl. a
duplicate-idempotency replay), back up, simulate total loss (drop+create),
restore, and assert counts / state / event order / unique idempotency_key are
preserved, then smoke the API against the restored DB.
PostgreSQL roundtrip (pgserver, real PG): same flow — runs in the PG suite
(`-k "postgres or pg"`). Also: restore refuses non-empty targets, verify
detects drift, manifest never contains credentials.
"""
import json
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "scripts"))
import backup_restore as br  # noqa: E402

from app import models, ops  # noqa: E402
from app.coordination import registry  # noqa: E402


def _mk_engine(url):
    engine = create_engine(url, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {})
    models.Base.metadata.create_all(engine)
    return engine


def _seed(engine):
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    with Session() as s:
        t1 = registry.create_task(s, task_id="task-b1", event_id="ev-1", source="github", kind="deploy",
                                  repo="r", pr_ref=None, branch_ref="b", title="bk1",
                                  payload={"x": 1}, idempotency_key="key-b1")
        registry.create_task(s, task_id="task-b1-dup", event_id="ev-1", source="github", kind="deploy",
                             repo="r", pr_ref=None, branch_ref="b", title="bk1",
                             payload={"x": 1}, idempotency_key="key-b1")  # replay -> duplicate event
        registry.create_task(s, task_id="task-b2", event_id=None, source="api", kind="vuln_intel",
                             repo=None, pr_ref=None, branch_ref=None, title="bk2",
                             payload={"y": [1, 2]}, idempotency_key="key-b2")
        registry.transition(s, t1, "QUEUED")
        s.commit()
        n_tasks = s.execute(select(models.CoordinationTask)).all()
        n_events = s.execute(select(models.CoordinationTaskEvent)).all()
        return len(n_tasks), len(n_events)


def test_sqlite_backup_restore_roundtrip(tmp_path, monkeypatch):
    url = "sqlite:///" + str(tmp_path / "live.db")
    engine = _mk_engine(url)
    n_tasks, n_events = _seed(engine)
    assert n_tasks == 2 and n_events >= 3

    bak = str(tmp_path / "backup.json")
    manifest = br.do_backup(url, bak)
    assert manifest["tables"]["coord_tasks"] == 2
    doc = json.load(open(bak))
    assert "password" not in json.dumps(doc["manifest"]).lower()

    # simulate total loss
    models.Base.metadata.drop_all(engine)
    models.Base.metadata.create_all(engine)
    with engine.connect() as c:
        assert c.execute(select(func.count()).select_from(models.CoordinationTask)).scalar() == 0

    r = br.do_restore(url, bak)
    assert r["restored"]["coord_tasks"] == 2

    # verify against live DB
    v = br.do_verify(url, bak)
    assert v["ok"], v["mismatches"]

    # content checks: state + event order + unique key intact
    Session = sessionmaker(bind=engine)
    with Session() as s:
        t1 = s.execute(select(models.CoordinationTask).where(
            models.CoordinationTask.task_id == "task-b1")).scalar_one()
        assert t1.state == "QUEUED"
        assert t1.idempotency_key == "key-b1"
        evs = s.execute(select(models.CoordinationTaskEvent).where(
            models.CoordinationTaskEvent.task_id == "task-b1").order_by(models.CoordinationTaskEvent.id)).all()
        kinds = [e[0].kind for e in evs]
        assert kinds[0] == "created"
        assert "duplicate_idempotency_key" in kinds
        with pytest.raises(IntegrityError):  # unique constraint survived the roundtrip
            s.execute(models.CoordinationTask.__table__.insert().values(
                task_id="task-dup", event_id=None, source="api", kind="x", payload="{}",
                state="NEW", priority=5, idempotency_key="key-b1"))
            s.commit()
        s.rollback()

    # API smoke against the restored DB
    monkeypatch.setattr(ops, "engine", engine)
    monkeypatch.setattr(ops, "SessionLocal", Session)
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r")
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        rr = c.get("/api/v1/coordination/tasks/task-b1/trace", headers={"Authorization": "Bearer r"})
        assert rr.status_code == 200
        body = rr.json()
        assert body["state"] == "QUEUED"
        assert body["events"][0]["kind"] == "created"
    engine.dispose()


def test_restore_refuses_nonempty_and_verify_detects_drift(tmp_path):
    url = "sqlite:///" + str(tmp_path / "live.db")
    engine = _mk_engine(url)
    _seed(engine)
    bak = str(tmp_path / "backup.json")
    br.do_backup(url, bak)
    with pytest.raises(SystemExit):
        br.do_restore(url, bak, force=False)  # non-empty target
    v = br.do_verify(url, bak)
    assert v["ok"]
    with sessionmaker(bind=engine)() as s:  # drift: delete one task
        s.execute(models.CoordinationTask.__table__.delete().where(
            models.CoordinationTask.task_id == "task-b2"))
        s.commit()
    v2 = br.do_verify(url, bak)
    assert not v2["ok"] and "coord_tasks" in v2["mismatches"]
    engine.dispose()


def test_pg_backup_restore_roundtrip(tmp_path):
    pgserver = pytest.importorskip("pgserver")
    server = pgserver.get_server(str(tmp_path / "pgdata"))
    url = server.get_uri().replace("postgresql://", "postgresql+psycopg2://", 1)
    engine = _mk_engine(url)
    n_tasks, n_events = _seed(engine)
    bak = str(tmp_path / "backup_pg.json")
    manifest = br.do_backup(url, bak)
    assert manifest["tables"]["coord_tasks"] == n_tasks == 2
    assert manifest["db"].startswith("postgresql") and "password" not in manifest["db"]
    models.Base.metadata.drop_all(engine)
    models.Base.metadata.create_all(engine)
    r = br.do_restore(url, bak)
    assert r["restored"]["coord_tasks"] == 2
    assert br.do_verify(url, bak)["ok"]
    with sessionmaker(bind=engine)() as s:
        t1 = s.execute(select(models.CoordinationTask).where(
            models.CoordinationTask.task_id == "task-b1")).scalar_one()
        assert t1.state == "QUEUED"
        evs = s.execute(select(models.CoordinationTaskEvent).where(
            models.CoordinationTaskEvent.task_id == "task-b1").order_by(models.CoordinationTaskEvent.id)).all()
        assert evs[0][0].kind == "created" and len(evs) == n_events - 1  # b1: created, dup, ->QUEUED
    engine.dispose()
