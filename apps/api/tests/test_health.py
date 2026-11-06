"""Tests for the real /health endpoint."""


def test_health_ok_with_sqlite(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["service"] == "cicc-api"
    assert body["status"] in {"ok", "degraded"}
    # SQLite test database must be reachable -> real check passes
    assert body["checks"]["database"]["status"] == "ok"
    assert body["checks"]["database"]["latency_ms"] >= 0
    assert body["uptime_seconds"] >= 0
    assert body["started_at"]


def test_health_response_shape(client):
    body = client.get("/health").json()
    for key in ("status", "service", "version", "started_at", "uptime_seconds", "checks"):
        assert key in body
    assert "database" in body["checks"]


def test_root_endpoint(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.json()["service"] == "cicc-operations-api"


def test_unknown_route_404(client):
    assert client.get("/no-such-route").status_code == 404
