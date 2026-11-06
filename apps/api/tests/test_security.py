"""Security tests: optional read/write token gates, body-size limit (413),
generic 500 without internal leakage, no secret leakage in responses."""
import os

import pytest
from fastapi.testclient import TestClient

from app import checks, ops, ratelimit
from app.main import app


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ops._overview_cache["data"] = None
    ops._overview_cache["ts"] = 0.0
    checks.reset_circuit_breakers()
    for v in ("CICC_OPS_READ_TOKEN", "CICC_OPS_WRITE_TOKEN", "RABBITMQ_MANAGEMENT_URL", "CICC_PLATFORM_API_URL"):
        monkeypatch.delenv(v, raising=False)
    yield
    ratelimit.limiter.reset()


def test_read_token_gate(client, monkeypatch):
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "readtok")
    assert client.get("/api/v1/ops/metrics").status_code == 401
    r = client.get("/api/v1/ops/metrics", headers={"Authorization": "Bearer readtok"})
    assert r.status_code == 200
    # probes stay open for orchestrators
    assert client.get("/live").status_code == 200
    assert client.get("/ready").status_code == 200


def test_oversized_post_body_rejected_413(client):
    big = "x" * (20 * 1024)
    r = client.post(
        "/api/v1/ops/tasks",
        json={"worker": big, "queue": "q", "status": "success"},
    )
    assert r.status_code == 413
    assert r.json()["detail"] == "payload_too_large"


def test_generic_500_without_internal_leakage(monkeypatch):
    def boom():
        raise RuntimeError("secret-internal-detail-DO-NOT-LEAK")

    monkeypatch.setattr(ops, "build_metrics", boom)
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/api/v1/ops/metrics")
    assert r.status_code == 500
    assert r.json() == {"detail": "internal_error"}
    assert "DO-NOT-LEAK" not in r.text
    assert "Traceback" not in r.text


def test_rabbitmq_credentials_never_in_response(client, monkeypatch):
    monkeypatch.setenv("RABBITMQ_MANAGEMENT_URL", "http://broker.sim/")
    monkeypatch.setenv("RABBITMQ_USER", "adminuser")
    monkeypatch.setenv("RABBITMQ_PASS", "topsecret-pass")

    def failing(url, timeout=2.0, auth=None):
        raise OSError("nope")

    monkeypatch.setattr(checks, "_get_json", failing)
    r = client.get("/api/v1/ops/components")
    assert "topsecret-pass" not in r.text
    assert "adminuser" not in r.text
    services = {s["key"]: s for s in r.json()["services"]}
    assert services["rabbitmq"]["status"] == "down"
    assert "broker.sim" in services["rabbitmq"]["detail"]  # host only is fine


def test_system_endpoint_reports_real_process_metrics(client):
    r = client.get("/api/v1/ops/system")
    assert r.status_code == 200
    body = r.json()
    assert body["process"]["pid"] == os.getpid()
    assert body["process"]["rss_mb"] > 0
    assert body["python"].startswith("3.")
    assert "sqlite" in body["database"]
