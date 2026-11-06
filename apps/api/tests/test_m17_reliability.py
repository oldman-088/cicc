"""M17 — webhook replay-detection persistence & dedup across a simulated
restart (same DB file, new app instance), plus ops regression checks.
Labeled: fixture webhook payloads over the real HTTP API; not agent traffic.
"""
import hashlib
import hmac
import json
import os

import pytest

from app import models, ops, ratelimit

SECRET = "m17-secret"
W = {"Authorization": "Bearer w", "Content-Type": "application/json"}
R = {"Authorization": "Bearer r"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r")
    monkeypatch.setenv("CICC_GH_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("CICC_GH_MAX_REPLAY_AGE_S", "60")
    monkeypatch.delenv("RABBITMQ_AMQP_URL", raising=False)
    yield
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def _wh(body_dict, delivery, secret=SECRET):
    raw = json.dumps(body_dict).encode()
    sig = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    return raw, {"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": delivery,
                 "X-Hub-Signature-256": sig, "Content-Type": "application/json"}


PAYLOAD = {"action": "opened", "repository": {"full_name": "oldman-088/cicc"},
           "sender": {"login": "u"}, "pull_request": {"number": 9, "title": "m17",
           "labels": [{"name": "ops"}], "head": {"ref": "b"}}}


def _app_with_db(db_file, monkeypatch):
    os.environ["DATABASE_URL"] = "sqlite:///" + str(db_file)
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    eng = create_engine(os.environ["DATABASE_URL"], connect_args={"check_same_thread": False})
    models.Base.metadata.create_all(eng)
    monkeypatch.setattr(ops, "engine", eng)
    monkeypatch.setattr(ops, "SessionLocal", sessionmaker(bind=eng, autoflush=False))
    ops.init_db()
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app), eng


def test_replay_alert_persists_across_restart_and_dedup_holds(monkeypatch, tmp_path):
    db = tmp_path / "restart.db"
    c1, eng = _app_with_db(db, monkeypatch)
    with c1:
        raw, h = _wh(PAYLOAD, "m17-r1")
        r1 = c1.post("/api/v1/coordination/webhook/github", content=raw, headers=h).json()
        assert r1["ok"] and not r1["duplicate"] and r1["task_id"] == "gh-m17-r1"
        # age the event beyond the replay window
        from datetime import timedelta
        from app.coordination.registry import utcnow
        with ops.SessionLocal() as s:
            ev = s.get(models.GitHubEvent, "m17-r1")
            ev.received_at = utcnow() - timedelta(hours=3)
            s.commit()
        # duplicate now -> deduped AND replay alert raised
        r2 = c1.post("/api/v1/coordination/webhook/github", content=raw, headers=h).json()
        assert r2["duplicate"] is True and r2["replay_alert"] is True
        with ops.SessionLocal() as s:
            alerts = [(a.rule, a.status) for a in s.execute(
                __import__("sqlalchemy").select(models.Alert)).scalars()]
        assert ("webhook_replay_after_window", "active") in alerts

    # simulated restart: brand-new app instance on the SAME db file
    c2, eng2 = _app_with_db(db, monkeypatch)
    with c2:
        # dedup state survived restart: still a duplicate, no new task
        raw, h = _wh(PAYLOAD, "m17-r1")
        r3 = c2.post("/api/v1/coordination/webhook/github", content=raw, headers=h).json()
        assert r3["duplicate"] is True and r3["replay_alert"] is True
        tasks = c2.get("/api/v1/coordination/tasks?kind=pr_opened", headers=R).json()["tasks"]
        assert [t["task_id"] for t in tasks].count("gh-m17-r1") == 1  # exactly one task
        # alert row survived restart (persistence check)
        with ops.SessionLocal() as s:
            rules = [a.rule for a in s.execute(__import__("sqlalchemy").select(models.Alert)).scalars()]
        assert "webhook_replay_after_window" in rules
        # still exactly one webhook event row
        with ops.SessionLocal() as s:
            n = len(s.execute(__import__("sqlalchemy").select(models.GitHubEvent)).scalars().all())
        assert n == 1
    eng.dispose()
    eng2.dispose()


def test_fresh_duplicate_within_window_no_alert(client):
    raw, h = _wh(PAYLOAD, "m17-r2")
    assert client.post("/api/v1/coordination/webhook/github", content=raw, headers=h).json()["ok"]
    r = client.post("/api/v1/coordination/webhook/github", content=raw, headers=h).json()
    assert r["duplicate"] is True and r.get("replay_alert") is False
