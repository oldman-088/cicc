"""M45 — cross-domain integration / MVP beta readiness (fixture-only unit level).

- last_success_at / last_invoke_at in status evidence + metrics (Agent 4 contract)
- circuit open/close transitions persisted as audit events (recovery history
  survives restart); circuit STATE stays process-local fail-safe (documented)
- restart recovery: persisted invokes/successes/consecutive_failures restored at
  startup; mounts_total (persisted audit count) survives; mount_count/last_success_at
  are honestly process-local
- auth boundaries: metrics/invoke/mount gating (401/403); read token cannot write
- tenant boundary: claimed_tenant stays UNVERIFIED; no tenant ids in metrics/diagnostics
- error isolation: one failing domain does not affect another; errors sanitized
- startup/shutdown audit events recorded by lifespan
"""
import json
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app import models, ops, ratelimit
from app.coordination import domains, router as coord_router

W = {"Authorization": "Bearer w", "Content-Type": "application/json"}
R = {"Authorization": "Bearer r"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r")
    monkeypatch.setenv("CICC_COORD_APPROVERS", "owner")
    monkeypatch.setenv("CICC_DOMAIN_INVOKE_TIMEOUT_S", "2")
    monkeypatch.setenv("CICC_DOMAIN_INVOKE_RETRIES", "0")
    monkeypatch.setenv("CICC_DOMAIN_STALE_AFTER_S", "60")
    monkeypatch.setenv("CICC_DOMAIN_CIRCUIT_FAILURES", "2")
    monkeypatch.setenv("CICC_DOMAIN_CIRCUIT_COOLDOWN_S", "0.2")
    monkeypatch.delenv("RABBITMQ_AMQP_URL", raising=False)
    for k in list(domains._REGISTRY):
        domains.unregister_domain(k)
    domains._STATS.clear()
    domains._CIRCUIT.clear()
    yield
    for k in list(domains._REGISTRY):
        domains.unregister_domain(k)
    domains._STATS.clear()
    domains._CIRCUIT.clear()
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def mk(ok=True):
    def h(payload, task):
        if not ok:
            raise RuntimeError("fixture down secret=hunter2")
        return {"result": {"ok": True},
                "provenance": {"source": "m45-fixture",
                               "produced_at": datetime.now(timezone.utc).isoformat(),
                               "freshness_s": 5}}
    return h


def inv(client, kind, key, payload=None, tenant=None):
    body = {"payload": payload or {}, "idempotency_key": key}
    if tenant:
        body["tenant_id"] = tenant
    return client.post(f"/api/v1/coordination/domains/{kind}/invoke", json=body, headers=W)


def mount(client, kind, handler_file=None, version="1.0"):
    import tempfile
    if handler_file is None:
        fx = tempfile.NamedTemporaryFile("w", suffix="_m45.py", delete=False)
        fx.write("def handle(payload, task):\n"
                 "    from datetime import datetime, timezone\n"
                 "    return {'result': {'ok': True}, 'provenance': {'source': 'm45',"
                 " 'produced_at': datetime.now(timezone.utc).isoformat(), 'freshness_s': 5}}\n")
        fx.close()
        handler_file = fx.name
    return client.post(f"/api/v1/coordination/domains/{kind}/mount",
                       json={"module_path": handler_file, "attr": "handle",
                             "version": version, "source_ref": "m45 fixture"}, headers=W)


def _simulate_restart():
    """Wipe process-local state, then reload persisted evidence (what lifespan does)."""
    domains._STATS.clear()
    domains._CIRCUIT.clear()
    with ops.SessionLocal() as s:
        coord_router._load_persisted_stats(s)


def _events():
    with ops.SessionLocal() as s:
        return [(e.level, e.source, e.message) for e in
                s.execute(select(models.Event)).scalars().all()]


def test_last_success_and_status_evidence(client):
    domains.register_domain("threat_intel", mk(), version="f", source_ref="fx")
    st = client.get("/api/v1/coordination/domains/threat_intel/status", headers=R).json()
    assert st["evidence"]["last_success_at"] is None and st["evidence"]["invokes"] == 0
    assert inv(client, "threat_intel", "a1").status_code == 201
    st = client.get("/api/v1/coordination/domains/threat_intel/status", headers=R).json()
    ev = st["evidence"]
    assert ev["last_success_at"] is not None and ev["last_invoke_at"] is not None
    assert ev["invokes"] == 1 and ev["successes"] == 1 and st["status"] == "EXECUTION_VERIFIED"
    m = client.get("/api/v1/coordination/domains/metrics", headers=R).json()["domains"]["threat_intel"]
    assert m["last_success_at"] is not None and m["invokes"] == 1


def test_circuit_transitions_persisted_as_audit_events(client):
    domains.register_domain("vuln_intel", mk(ok=False), version="f", source_ref="fx")
    assert inv(client, "vuln_intel", "c1").status_code == 502
    assert inv(client, "vuln_intel", "c2").status_code == 502  # threshold 2 -> opens
    evs = _events()
    assert any("circuit OPENED kind=vuln_intel" in m for _, src, m in evs if src == "coordination.domains")
    assert inv(client, "vuln_intel", "c3").status_code == 503  # fast-reject, no new open event
    import time as _t
    _t.sleep(0.3)  # cooldown 0.2
    domains._REGISTRY["vuln_intel"]["handler"] = mk(ok=True)
    assert inv(client, "vuln_intel", "c4").status_code == 201  # half-open success -> closed
    evs = _events()
    assert any("circuit CLOSED kind=vuln_intel" in m for _, src, m in evs if src == "coordination.domains")
    m = client.get("/api/v1/coordination/domains/metrics", headers=R).json()["domains"]["vuln_intel"]
    assert m["circuit"]["opens"] == 1 and m["circuit"]["closes"] == 1


def test_restart_recovery_persisted_vs_process_local(client):
    domains.register_domain("threat_intel", mk(), version="f", source_ref="fx")
    assert mount(client, "threat_intel").status_code == 201  # mount event persisted
    for k in ("r1", "r2", "r3"):
        assert inv(client, "threat_intel", k).status_code == 201
    domains._REGISTRY["threat_intel"]["handler"] = mk(ok=False)
    assert inv(client, "threat_intel", "r4").status_code == 502

    _simulate_restart()

    # persisted counters restored (startup load path)
    st = client.get("/api/v1/coordination/domains/threat_intel/status", headers=R).json()["evidence"]
    assert st["invokes"] == 4 and st["successes"] == 3 and st["consecutive_failures"] == 1
    # circuit state is fail-safe closed after restart (documented process-local)
    assert st["circuit"]["open"] is False
    # process-local fields honestly reset
    assert st["last_success_at"] is None
    # persisted audit: mount event + circuit transition events survive
    evs = _events()
    assert any(m.startswith("domain mounted kind=threat_intel ") for _, _, m in evs)
    m = client.get("/api/v1/coordination/domains/metrics", headers=R).json()["domains"]["threat_intel"]
    assert m["mounts_total"] == 1  # persisted
    assert m["mount_count"] == 0    # process-local, reset by restart
    assert m["invokes"] == 4 and m["successes"] == 3


def test_mounts_total_counts_remounts_and_survives_restart(client):
    assert mount(client, "vuln_intel", version="1.0").status_code == 201
    assert mount(client, "vuln_intel", version="2.0").status_code == 201
    assert mount(client, "vuln_intel", version="3.0").status_code == 201
    m = client.get("/api/v1/coordination/domains/metrics", headers=R).json()["domains"]["vuln_intel"]
    assert m["mounts_total"] == 3 and m["mount_count"] == 3
    st = client.get("/api/v1/coordination/domains/vuln_intel/status", headers=R).json()["evidence"]
    assert st["mount_count"] == 3 and st["previous_version"] == "2.0"
    _simulate_restart()
    m = client.get("/api/v1/coordination/domains/metrics", headers=R).json()["domains"]["vuln_intel"]
    assert m["mounts_total"] == 3  # persisted across restart


def test_auth_and_tenant_boundaries(client):
    domains.register_domain("threat_intel", mk(), version="f", source_ref="fx")
    assert client.get("/api/v1/coordination/domains/metrics").status_code == 401
    assert client.get("/api/v1/coordination/domains/metrics", headers=R).status_code == 200
    # write ops need the WRITE token; read token is refused
    r = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                    json={"payload": {}, "idempotency_key": "t1"}, headers=R)
    assert r.status_code in (401, 403)  # read token must not write
    r = client.post("/api/v1/coordination/domains/threat_intel/mount",
                    json={"module_path": "/x.py", "attr": "h", "version": "1", "source_ref": "t"},
                    headers=R)
    assert r.status_code in (401, 403)  # valid body, read token still refused
    assert client.post("/api/v1/coordination/domains/threat_intel/invoke",
                       json={"payload": {}}).status_code == 401
    # tenant claim recorded as UNVERIFIED only; never leaks into metrics/diagnostics
    assert inv(client, "threat_intel", "t2", tenant="tenant-secret-1").status_code == 201
    tr = client.get("/api/v1/coordination/tasks", headers=R).json()
    tid = [t for t in tr["tasks"] if t.get("kind") == "threat_intel"][0]["task_id"]
    trace = client.get(f"/api/v1/coordination/tasks/{tid}/trace", headers=R).json()
    ct = [e for e in trace["events"] if e.get("kind") == "claimed_tenant"]
    assert ct and "unverified" in ct[0].get("detail", "")
    blob = json.dumps(client.get("/api/v1/coordination/domains/metrics", headers=R).json())
    blob += json.dumps(client.get("/api/v1/coordination/diagnostics", headers=R).json())
    assert "tenant-secret-1" not in blob


def test_error_isolation_and_sanitization(client):
    domains.register_domain("bad_domain", mk(ok=False), version="f", source_ref="fx")
    domains.register_domain("good_domain", mk(ok=True), version="f", source_ref="fx")
    r = inv(client, "bad_domain", "e1")
    assert r.status_code == 502 and "hunter2" not in r.text and "RuntimeError" not in r.text
    assert inv(client, "good_domain", "e2").status_code == 201  # unaffected
    m = client.get("/api/v1/coordination/domains/metrics", headers=R).json()["domains"]
    assert m["bad_domain"]["failures"] == 1 and m["good_domain"]["successes"] == 1
    assert "hunter2" not in json.dumps(m)


def test_lifespan_startup_events(client):
    evs = _events()
    assert any("CICC operations service started" in m for _, src, m in evs if src == "api")
