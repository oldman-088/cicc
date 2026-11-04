"""Tests for the operations endpoints.

These tests also pin the honesty rules: on a fresh database all counters
must be real zeros, no fabricated intelligence, and unimplemented modules
must report "not_implemented".
"""


def test_overview_structure(client):
    r = client.get("/api/v1/ops/overview")
    assert r.status_code == 200
    body = r.json()
    assert body["data_source"] == "live-ops-database"
    assert body["overall_status"] in {"ok", "degraded", "down", "unknown"}
    assert isinstance(body["services"], list) and isinstance(body["modules"], list)
    assert isinstance(body["metrics"], dict)
    assert isinstance(body["activity"], list)


def test_services_reported_with_real_status(client):
    body = client.get("/api/v1/ops/overview").json()
    services = {s["key"]: s for s in body["services"]}
    assert services["api"]["status"] == "ok"
    assert services["database"]["status"] == "ok"  # real check against test SQLite


def test_unimplemented_modules_are_honest(client):
    body = client.get("/api/v1/ops/overview").json()
    modules = {m["key"]: m for m in body["modules"]}
    for key in ("threat_intelligence", "vulnerability_intelligence", "command_theater_3d"):
        assert modules[key]["status"] == "not_implemented", key
    assert modules["system_health_ops"]["status"] == "ok"


def test_metrics_are_real_zeros_on_fresh_db(client):
    m = client.get("/api/v1/ops/metrics").json()
    assert m["entities"] == 0
    assert m["vulnerabilities"] == 0  # no fabricated CVEs
    assert m["campaigns"] == 0
    assert m["recent_updates_24h"] == 0
    assert m["last_successful_sync"] is None


def test_activity_contains_real_startup_event(client):
    body = client.get("/api/v1/ops/activity").json()
    assert len(body["events"]) >= 1
    first = body["events"][0]
    assert first["source"] == "api"
    assert first["level"] == "info"
    assert "started" in first["message"]


def test_activity_limit_validation(client):
    assert client.get("/api/v1/ops/activity?limit=5").status_code == 200
    assert len(client.get("/api/v1/ops/activity?limit=5").json()["events"]) <= 5
    assert client.get("/api/v1/ops/activity?limit=0").status_code == 422
    assert client.get("/api/v1/ops/activity?limit=9999").status_code == 422


def test_components_endpoint(client):
    body = client.get("/api/v1/ops/components").json()
    assert any(s["key"] == "database" for s in body["services"])
    assert any(m["key"] == "threat_intelligence" for m in body["modules"])


def test_overall_status_logic():
    from app.ops import compute_overall

    assert compute_overall(["ok", "ok"]) == "ok"
    assert compute_overall(["ok", "not_configured"]) == "degraded"
    assert compute_overall(["ok", "down"]) == "down"
    assert compute_overall([]) == "unknown"
    assert compute_overall(["bogus"]) == "unknown"
