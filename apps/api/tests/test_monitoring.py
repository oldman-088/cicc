"""Tests for the extended monitoring backend: failure isolation, rate
limiting, readiness/liveness, history, task stats, RabbitMQ adapter and
secret-leak prevention. Degraded/unavailable states are tested explicitly,
not only the happy path."""
import pytest
from sqlalchemy import create_engine

from app import checks, ops, ratelimit


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    ratelimit.limiter.reset()
    ops._overview_cache["data"] = None
    ops._overview_cache["ts"] = 0.0
    monkeypatch.delenv("RABBITMQ_MANAGEMENT_URL", raising=False)
    monkeypatch.delenv("RABBITMQ_USER", raising=False)
    monkeypatch.delenv("RABBITMQ_PASS", raising=False)
    monkeypatch.delenv("CICC_PLATFORM_API_URL", raising=False)
    monkeypatch.delenv("CICC_OPS_WRITE_TOKEN", raising=False)
    yield
    ratelimit.limiter.reset()


# ---------- rate limiting ----------

def test_rate_limit_429_on_ops_endpoints(client):
    codes = [client.get("/api/v1/ops/metrics").status_code for _ in range(125)]
    assert codes[0] == 200
    assert 429 in codes


def test_probes_not_rate_limited(client):
    for _ in range(70):
        assert client.get("/live").status_code == 200
        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 200


# ---------- liveness / readiness ----------

def test_live_and_ready_ok(client):
    assert client.get("/live").json()["status"] == "alive"
    r = client.get("/ready")
    assert r.status_code == 200
    assert r.json()["status"] == "ready"
    assert r.json()["checks"]["database"]["status"] == "ok"


def test_ready_503_when_db_down(client, monkeypatch):
    monkeypatch.setattr(ops, "check_database", lambda: {"status": "down", "detail": "boom"})
    r = client.get("/ready")
    assert r.status_code == 503
    assert r.json()["status"] == "not_ready"


def test_overview_survives_db_down(client, monkeypatch):
    """Failure isolation: a down database degrades its component and the
    overall status, but the overview endpoint still returns 200."""
    monkeypatch.setattr(ops, "check_database", lambda: {"status": "down", "detail": "boom"})
    r = client.get("/api/v1/ops/overview")
    assert r.status_code == 200
    body = r.json()
    services = {s["key"]: s for s in body["services"]}
    assert services["database"]["status"] == "down"
    assert body["overall_status"] == "down"


# ---------- caching ----------

def test_overview_short_ttl_cache(client):
    a = client.get("/api/v1/ops/overview").json()
    b = client.get("/api/v1/ops/overview").json()
    assert a["generated_at"] == b["generated_at"]


# ---------- RabbitMQ / dependency adapters ----------

def test_rabbitmq_not_configured_by_default(client):
    services = {s["key"]: s for s in client.get("/api/v1/ops/components").json()["services"]}
    assert services["rabbitmq"]["status"] == "not_configured"
    assert "RABBITMQ_MANAGEMENT_URL" in services["rabbitmq"]["detail"]


def test_rabbitmq_down_on_unreachable_management_api(client, monkeypatch):
    monkeypatch.setenv("RABBITMQ_MANAGEMENT_URL", "http://127.0.0.1:9/")
    monkeypatch.setenv("RABBITMQ_USER", "guest")
    monkeypatch.setenv("RABBITMQ_PASS", "supersecret")
    r = client.get("/api/v1/ops/overview")
    assert r.status_code == 200  # failure isolation
    services = {s["key"]: s for s in r.json()["services"]}
    assert services["rabbitmq"]["status"] == "down"
    # credentials must never appear in the response
    assert "supersecret" not in r.text
    assert "guest" not in r.text


def test_platform_api_not_configured_by_default(client):
    services = {s["key"]: s for s in client.get("/api/v1/ops/components").json()["services"]}
    assert services["platform_api"]["status"] == "not_configured"


def test_workers_status_honest(client):
    services = {s["key"]: s for s in client.get("/api/v1/ops/components").json()["services"]}
    assert services["workers"]["status"] == "not_configured"
    assert "Arena" in services["workers"]["detail"]


# ---------- secret-leak prevention ----------

def test_db_url_password_hidden():
    e = create_engine("postgresql://user:secretpw@db-host:5432/cicc")
    rendered = e.url.render_as_string(hide_password=True)
    assert "secretpw" not in rendered


def test_health_response_hides_database_connection_target(client, monkeypatch, tmp_path):
    db_path = tmp_path / "private-tenant.sqlite"
    engine = create_engine("sqlite:///" + str(db_path))
    monkeypatch.setattr(ops, "engine", engine)
    response = client.get("/health")
    engine.dispose()

    assert response.status_code == 200
    body = response.text
    assert "sqlite database connection verified" in body
    assert str(tmp_path) not in body
    assert db_path.name not in body
    assert "private-tenant" not in body


def test_database_health_check_reports_driver_not_connection_url(tmp_path):
    db_path = tmp_path / "private.sqlite"
    engine = create_engine("sqlite:///" + str(db_path))
    result = checks.check_database(engine)
    engine.dispose()

    assert result["status"] == "ok"
    assert result["detail"] == "sqlite database connection verified"
    assert str(db_path) not in result["detail"]


def test_db_failure_detail_has_no_url_or_password(client, monkeypatch):
    bad = create_engine("postgresql://user:secretpw@127.0.0.1:1/nope")
    monkeypatch.setattr(ops, "engine", bad)
    r = client.get("/health")
    assert r.status_code == 200
    assert "secretpw" not in r.text
    assert "db-host" not in r.text


# ---------- history ----------

def test_metrics_history_records_real_snapshots(client, monkeypatch):
    monkeypatch.setattr(ops, "SNAPSHOT_MIN_INTERVAL_S", 0)
    ops.build_overview()
    ops.build_overview()
    r = client.get("/api/v1/ops/metrics/history?hours=1")
    assert r.status_code == 200
    snaps = r.json()["snapshots"]
    assert len(snaps) >= 2
    for k in ("ts", "entities", "vulnerabilities", "campaigns", "recent_updates_24h"):
        assert k in snaps[0]
    assert client.get("/api/v1/ops/metrics/history?hours=0").status_code == 422


# ---------- task runs ----------

def test_task_run_post_and_stats(client):
    r = client.post(
        "/api/v1/ops/tasks",
        json={"worker": "w1", "queue": "arena-tasks", "status": "success", "duration_ms": 12},
    )
    assert r.status_code == 201
    assert r.json()["id"] >= 1
    client.post(
        "/api/v1/ops/tasks",
        json={"worker": "w1", "queue": "arena-tasks", "status": "failed", "error": "boom", "duration_ms": 30},
    )
    stats = client.get("/api/v1/ops/tasks/stats?hours=1").json()
    assert stats["completed"] == 1
    assert stats["failed"] == 1
    assert stats["pending"] == 0
    assert stats["avg_duration_ms"] == 21.0
    # workers component becomes ok because a real task run was reported
    services = {s["key"]: s for s in client.get("/api/v1/ops/components").json()["services"]}
    assert services["workers"]["status"] == "ok"


def test_task_run_requires_token_when_configured(client, monkeypatch):
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "tok123")
    payload = {"worker": "w1", "queue": "q", "status": "success"}
    assert client.post("/api/v1/ops/tasks", json=payload).status_code == 401
    r = client.post("/api/v1/ops/tasks", json=payload, headers={"Authorization": "Bearer tok123"})
    assert r.status_code == 201
    wrong = client.post("/api/v1/ops/tasks", json=payload, headers={"Authorization": "Bearer nope"})
    assert wrong.status_code == 401


def test_task_run_validation(client):
    assert client.post("/api/v1/ops/tasks", json={"worker": "", "queue": "q", "status": "bogus"}).status_code == 422
    assert client.post("/api/v1/ops/tasks", json={"worker": "w", "queue": "q", "status": "success", "duration_ms": -1}).status_code == 422


# ---------- dependencies ----------

def test_dependencies_graph_shape(client):
    d = client.get("/api/v1/ops/dependencies").json()
    keys = {n["key"] for n in d["nodes"]}
    assert {"api", "database", "rabbitmq", "platform_api", "workers"} <= keys
    assert len(d["edges"]) >= 3
    for e in d["edges"]:
        assert e["from"] in keys and e["to"] in keys
        assert e["label"]
