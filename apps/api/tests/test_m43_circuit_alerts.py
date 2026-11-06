"""M43 — circuit breaker, domain alerts, mount history, payload cap (fixture-only).

- circuit breaker: after CICC_DOMAIN_CIRCUIT_FAILURES consecutive failures,
  invokes are fast-rejected 503 domain_circuit_open (handler NOT executed);
  after cooldown, half-open allows again; success closes the circuit
- domain alerts: failing invoke raises a domain_status alert (active), recovery
  resolves it; alert messages are sanitized
- mount history: re-mount replaces handler, mount_count increments,
  previous_version recorded, audit event mentions replacement
- payload cap: >64 KiB payload -> 413
- all M42 behaviors preserved (spot-checked: stale flag, skew, claimed tenant)
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app import models, ops, ratelimit
from app.coordination import domains

W = {"Authorization": "Bearer w", "Content-Type": "application/json"}
R = {"Authorization": "Bearer r"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r")
    monkeypatch.setenv("CICC_COORD_APPROVERS", "owner")
    monkeypatch.setenv("CICC_DOMAIN_INVOKE_TIMEOUT_S", "3")
    monkeypatch.setenv("CICC_DOMAIN_INVOKE_RETRIES", "0")
    monkeypatch.setenv("CICC_DOMAIN_STALE_AFTER_S", "60")
    monkeypatch.setenv("CICC_DOMAIN_CIRCUIT_FAILURES", "3")
    monkeypatch.setenv("CICC_DOMAIN_CIRCUIT_COOLDOWN_S", "0.2")
    monkeypatch.delenv("RABBITMQ_AMQP_URL", raising=False)
    for k in list(domains._REGISTRY):
        domains.unregister_domain(k)
    domains._CIRCUIT.clear()
    yield
    for k in list(domains._REGISTRY):
        domains.unregister_domain(k)
    domains._CIRCUIT.clear()
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def ok_handler(payload, task):
    return {"result": {"ok": True},
            "provenance": {"source": "m43", "produced_at": datetime.now(timezone.utc).isoformat(),
                           "freshness_s": 5, "confidence": 0.9}}


def fail_handler(payload, task):
    raise RuntimeError("down secret=hunter2")


def test_circuit_breaker_open_halfopen_close(client, monkeypatch):
    calls = {"n": 0}
    def flaky(payload, task):
        calls["n"] += 1
        raise RuntimeError("down")
    domains.register_domain("threat_intel", flaky, version="f", source_ref="fx")
    for i in range(3):  # threshold = 3
        r = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                        json={"payload": {}, "idempotency_key": f"cb{i}"}, headers=W)
        assert r.status_code == 502
    assert domains.circuit_state("threat_intel")["open"] is True
    # 4th invoke: fast-rejected 503, handler NOT executed
    r = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                    json={"payload": {}, "idempotency_key": "cb3"}, headers=W)
    assert r.status_code == 503 and "circuit" in r.json()["detail"] and "hunter2" not in r.text
    assert calls["n"] == 3
    tr = client.get("/api/v1/coordination/tasks/" + r.json().get("task_id", ""), headers=R) if False else None
    # cooldown elapses -> half-open allows a new attempt
    import time as _t
    _t.sleep(0.3)
    assert domains.circuit_state("threat_intel")["open"] is False  # cooldown elapsed
    domains._REGISTRY["threat_intel"]["handler"] = ok_handler
    r2 = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                     json={"payload": {}, "idempotency_key": "cb4"}, headers=W)
    assert r2.status_code == 201
    assert domains.circuit_state("threat_intel")["open"] is False  # success closed it
    assert domains.all_statuses()["threat_intel"]["circuit"]["open"] is False


def test_domain_alerts_raise_and_resolve(client):
    domains.register_domain("vuln_intel", fail_handler, version="f", source_ref="fx")
    r = client.post("/api/v1/coordination/domains/vuln_intel/invoke",
                    json={"payload": {}, "idempotency_key": "al1"}, headers=W)
    assert r.status_code == 502
    alerts = client.get("/api/v1/ops/alerts?state=active", headers=R).json()
    dom_alerts = [a for a in alerts.get("alerts", []) if a.get("rule") == "domain_status"
                  and a.get("component_key") == "vuln_intel"]
    assert dom_alerts and dom_alerts[0]["status"] == "active"
    assert "hunter2" not in json.dumps(dom_alerts)
    # recovery resolves the alert
    domains._REGISTRY["vuln_intel"]["handler"] = ok_handler
    r2 = client.post("/api/v1/coordination/domains/vuln_intel/invoke",
                     json={"payload": {}, "idempotency_key": "al2"}, headers=W)
    assert r2.status_code == 201
    alerts = client.get("/api/v1/ops/alerts?state=active", headers=R).json()
    assert not [a for a in alerts.get("alerts", []) if a.get("rule") == "domain_status"
                and a.get("component_key") == "vuln_intel"]
    hist = client.get("/api/v1/ops/alerts/history?component=vuln_intel", headers=R).json()
    assert any(a.get("rule") == "domain_status" and a.get("status") == "resolved"
               for a in hist.get("alerts", hist.get("history", [])))


def test_mount_history_and_replacement_audit(client, tmp_path):
    mod = tmp_path / "dom.py"
    mod.write_text("def handle(payload, task):\n"
                   "    from datetime import datetime, timezone\n"
                   "    return {'result': {'v': 1}, 'provenance': {'source': 'm43', 'produced_at': datetime.now(timezone.utc).isoformat()}}\n")
    r1 = client.post("/api/v1/coordination/domains/threat_intel/mount",
                     json={"module_path": str(mod), "attr": "handle", "version": "1.0",
                           "source_ref": "fx"}, headers=W)
    assert r1.status_code == 201
    r2 = client.post("/api/v1/coordination/domains/threat_intel/mount",
                     json={"module_path": str(mod), "attr": "handle", "version": "2.0",
                           "source_ref": "fx"}, headers=W)
    assert r2.status_code == 201
    st = client.get("/api/v1/coordination/domains/threat_intel/status", headers=R).json()
    assert st["evidence"]["mount_count"] == 2 and st["evidence"]["previous_version"] == "1.0"
    assert st["evidence"]["version"] == "2.0"
    with ops.SessionLocal() as s:
        evs = s.query(models.Event).filter(models.Event.source == "coordination.domains").all()
        mount_msgs = [e.message for e in evs if "mounted" in e.message]
        assert any("replaced 1.0" in m for m in mount_msgs)


def test_payload_cap_413(client):
    domains.register_domain("threat_intel", ok_handler, version="f", source_ref="fx")
    big = {"payload": {"blob": "x" * 70000}}
    r = client.post("/api/v1/coordination/domains/threat_intel/invoke", json=big, headers=W)
    assert r.status_code == 413 and "payload_too_large" in r.json()["detail"]
    r2 = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                     json={"payload": {"small": 1}}, headers=W)
    assert r2.status_code == 201


def test_m42_behaviors_preserved(client):
    # stale flag + clock skew + claimed tenant still work after M43 changes
    def skewed(payload, task):
        return {"result": {}, "provenance": {"source": "m43",
                "produced_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}}
    domains.register_domain("threat_intel", skewed, version="f", source_ref="fx")
    r = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                    json={"payload": {}, "tenant_id": "t1"}, headers=W)
    assert r.status_code == 201
    assert r.json()["stale"] is False and r.json()["freshness"]["clock_skew_s"] > 3500
    tr = client.get(f"/api/v1/coordination/tasks/{r.json()['task_id']}/trace", headers=R).json()
    assert any(e["kind"] == "domain_clock_skew" for e in tr["events"])
    assert any(e["kind"] == "claimed_tenant" for e in tr["events"])
