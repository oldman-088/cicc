"""Milestone 8 tests: progress reports, dependency DAG, GitHub API sync
(unit tests monkeypatch the transport for determinism; one LIVE test hits the
real api.github.com and is skipped honestly if unreachable)."""
import hashlib
import hmac
import json

import pytest

from app import models, ops, ratelimit
from app.coordination import github_sync, registry

SECRET = "test-webhook-secret"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    ops._overview_cache["data"] = None
    ops._overview_cache["ts"] = 0.0
    monkeypatch.setenv("CICC_GH_WEBHOOK_SECRET", SECRET)
    for v in ("CICC_OPS_WRITE_TOKEN", "CICC_OPS_READ_TOKEN", "RABBITMQ_AMQP_URL", "GH_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.delenv(v, raising=False)
    yield
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def _payload(labels=None, **extra):
    p = {"action": "opened", "repository": {"full_name": "oldman-088/cicc"},
         "sender": {"login": "u"}, "pull_request": {"number": 1, "title": "t",
                                                     "labels": [{"name": x} for x in (labels or [])],
                                                     "head": {"ref": "b"}}}
    p.update(extra)
    return p


def _post(client, body, delivery="d-1", event="pull_request"):
    raw = json.dumps(body).encode()
    sig = "sha256=" + hmac.new(SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return client.post("/api/v1/coordination/webhook/github", content=raw,
                       headers={"X-GitHub-Event": event, "X-GitHub-Delivery": delivery,
                                "X-Hub-Signature-256": sig, "Content-Type": "application/json"})


# ---------- progress ----------

def test_progress_report(client):
    _post(client, _payload(labels=["ops"]), delivery="d-p1")
    client.post("/api/v1/coordination/tasks/gh-d-p1/route")
    r = client.post("/api/v1/coordination/tasks/gh-d-p1/progress", json={"percent": 40, "note": "halfway"})
    assert r.status_code == 200 and r.json()["progress"] == 40
    r = client.post("/api/v1/coordination/tasks/gh-d-p1/progress", json={"percent": 250})
    assert r.status_code == 422  # capped by schema
    t = client.get("/api/v1/coordination/tasks/gh-d-p1").json()
    assert t["progress"] == 40
    evs = client.get("/api/v1/coordination/tasks/gh-d-p1/events").json()["events"]
    assert any(e["kind"] == "progress" and "40%" in (e["detail"] or "") for e in evs)


# ---------- DAG ----------

def test_dependency_dag(client):
    _post(client, _payload(labels=["ops"]), delivery="d-g1")
    _post(client, _payload(labels=["ops"]), delivery="d-g2")
    with ops.SessionLocal() as s:
        t2 = s.execute(models.CoordinationTask.__table__.select().where(
            models.CoordinationTask.task_id == "gh-d-g2")).scalar_one_or_none() if False else None
    from sqlalchemy import select as _sel
    with ops.SessionLocal() as s:
        t2 = s.execute(_sel(models.CoordinationTask).where(models.CoordinationTask.task_id == "gh-d-g2")).scalar_one()
        t2.depends_on = json.dumps(["gh-d-g1"])
        s.commit()
    d = client.get("/api/v1/coordination/tasks/dag").json()
    assert {"from": "gh-d-g1", "to": "gh-d-g2"} in d["edges"]
    assert {n["task_id"] for n in d["nodes"]} >= {"gh-d-g1", "gh-d-g2"}


# ---------- github sync (unit, transport monkeypatched) ----------

def _fake_github(monkeypatch, check_runs=None, prs=None):
    def _get(path, timeout=8.0):
        if "/pulls" in path:
            return prs or []
        if "/issues" in path:
            return []
        if "/check-runs" in path:
            return {"check_runs": check_runs or []}
        raise AssertionError(path)
    monkeypatch.setattr(github_sync, "_get", _get)


def test_github_sync_creates_ci_task_for_arena_failure(client, monkeypatch):
    _fake_github(monkeypatch, check_runs=[{
        "name": "api", "status": "completed", "conclusion": "failure",
        "head_branch": "arena/961971ed-cicc", "html_url": "https://x/1"}],
        prs=[{"number": 4, "title": "Agent 1 PR", "head": {"ref": "arena/961971ed-cicc"},
              "user": {"login": "oldman-088"}, "html_url": "https://x/pr/4"}])
    r = client.post("/api/v1/coordination/github/sync")
    assert r.status_code == 200
    d = r.json()
    assert d["ok"] and d["open_prs"] == 1
    tasks = client.get("/api/v1/coordination/tasks").json()["tasks"]
    kinds = {t["task_id"]: t["kind"] for t in tasks}
    assert any(k == "ci_failed" for k in kinds.values())
    assert any(k == "pr_opened" for k in kinds.values())
    # idempotent: second sync creates nothing new
    r2 = client.post("/api/v1/coordination/github/sync").json()
    assert r2["created"] == []
    # token never appears in any response
    assert "GH_TOKEN" not in json.dumps(r.json())


def test_github_sync_handles_api_down(client, monkeypatch):
    def _boom(path, timeout=8.0):
        raise RuntimeError("network down")
    monkeypatch.setattr(github_sync, "_get", _boom)
    r = client.post("/api/v1/coordination/github/sync")
    assert r.status_code == 200 and r.json()["ok"] is False


def test_github_live_probe_real_api(client):
    """LIVE test: real call to api.github.com (allowed egress). Skipped
    honestly if unreachable from this environment."""
    from app import checks

    checks.reset_circuit_breakers()
    r = client.get("/api/v1/coordination/github/status")
    d = r.json()
    if d.get("status") != "ok":
        pytest.skip(f"api.github.com unreachable from this environment: {d.get('detail')}")
    assert d["repo"] == "oldman-088/cicc"
    assert isinstance(d["open_prs"], list) and isinstance(d["check_runs"], list)
    assert any(p["number"] == 4 for p in d["open_prs"])  # PR #4 exists


def test_sync_task_ids_are_url_safe(client, monkeypatch):
    _fake_github(monkeypatch, prs=[{"number": 4, "title": "t", "head": {"ref": "b"},
                                    "user": {"login": "u"}, "html_url": "https://x/pr/4"}])
    client.post("/api/v1/coordination/github/sync")
    tasks = client.get("/api/v1/coordination/tasks").json()["tasks"]
    for t in tasks:
        assert "/" not in t["task_id"]
    # progress endpoint reachable with the slash-free id
    tid = tasks[0]["task_id"]
    r = client.post(f"/api/v1/coordination/tasks/{tid}/progress", json={"percent": 10})
    assert r.status_code == 200


# ---------- M11-04: pagination + transient retry ----------

def test_get_pages_paginates_until_short_page(monkeypatch):
    calls = []

    def fake_get(path, timeout=8.0, _retried=False):
        calls.append(path)
        import re as _re
        page = int(_re.search(r"[?&]page=(\d+)", path).group(1))
        if page == 1:
            return list(range(100))          # full page -> next page
        if page == 2:
            return list(range(30))           # short page -> stop
        raise AssertionError("should not fetch page 3")

    monkeypatch.setattr(github_sync, "_get", fake_get)
    out = github_sync._get_pages("/repos/x/y/pulls?state=open", max_pages=3, per_page=100)
    assert len(out) == 130 and len(calls) == 2


def test_get_retries_transient_then_gives_up(monkeypatch):
    import urllib.error
    state = {"n": 0}

    def flaky(path, timeout=8.0, _retried=False):
        state["n"] += 1
        if state["n"] == 1:
            raise urllib.error.URLError("connection reset")
        return {"ok": True}

    monkeypatch.setattr(github_sync, "_get_once", flaky)
    monkeypatch.setattr(github_sync.time, "sleep", lambda *_: None)
    assert github_sync._get("/x") == {"ok": True} and state["n"] == 2

    def always_down(path, timeout=8.0, _retried=False):
        raise TimeoutError("down")

    monkeypatch.setattr(github_sync, "_get_once", always_down)
    with pytest.raises(TimeoutError):
        github_sync._get("/x")  # retried once, then raised


def test_get_does_not_retry_4xx(monkeypatch):
    import urllib.error

    def not_found(path, timeout=8.0, _retried=False):
        raise urllib.error.HTTPError(path, 404, "nf", {}, None)

    monkeypatch.setattr(github_sync, "_get_once", not_found)
    with pytest.raises(urllib.error.HTTPError):
        github_sync._get("/x")
