"""Circuit breaker tests for external probes (SIMULATED failures via
monkeypatched _get_json — never claimed as a live broker)."""
import pytest

from app import checks, ops, ratelimit


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    checks.reset_circuit_breakers()
    monkeypatch.setenv("RABBITMQ_MANAGEMENT_URL", "http://broker.sim/")
    monkeypatch.setenv("OPS_CB_FAILURES", "2")
    monkeypatch.setenv("OPS_CB_COOLDOWN_S", "60")
    yield
    checks.reset_circuit_breakers()


def _failing_get_json(url, timeout=2.0, auth=None):
    raise OSError("connection refused")


def test_circuit_opens_after_threshold_and_reports_stale_unknown(monkeypatch):
    monkeypatch.setattr(checks, "_get_json", _failing_get_json)
    r1 = checks.check_rabbitmq()
    assert r1["status"] == "down"
    r2 = checks.check_rabbitmq()
    assert r2["status"] == "down"
    # third call: circuit open -> unknown + stale, NOT a false ok/down
    r3 = checks.check_rabbitmq()
    assert r3["status"] == "unknown"
    assert r3.get("stale") is True
    assert "circuit open" in r3["detail"]
    assert "last known status: down" in r3["detail"]


def test_circuit_recovers_after_cooldown(monkeypatch):
    monkeypatch.setattr(checks, "_get_json", _failing_get_json)
    checks.check_rabbitmq()
    checks.check_rabbitmq()
    assert checks._cb("rabbitmq").state == "open"
    # force cooldown elapsed
    checks._cb("rabbitmq").opened_at -= 120
    monkeypatch.setattr(
        checks,
        "_get_json",
        lambda url, timeout=2.0, auth=None: {"queue_totals": {"messages_ready": 0, "messages_unacknowledged": 0, "queues": 0}},
    )
    r = checks.check_rabbitmq()
    assert r["status"] == "ok"
    assert checks._cb("rabbitmq").state == "closed"


def test_overview_still_works_when_probe_circuit_open(client, monkeypatch):
    monkeypatch.setattr(checks, "_get_json", _failing_get_json)
    for _ in range(3):
        client.get("/api/v1/ops/components")
    r = client.get("/api/v1/ops/overview")
    assert r.status_code == 200  # failure isolation
    services = {s["key"]: s for s in r.json()["services"]}
    assert services["rabbitmq"]["status"] == "unknown"
    assert services["rabbitmq"]["check"].get("stale") is True
