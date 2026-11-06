"""M46 — operational reliability edge cases (fixture-only).

- circuit-breaker edges: threshold-1 stays closed, threshold opens, fast-reject
  does not count as invoke/failure, a single concurrent half-open probe is
  admitted, failed probe re-arms cooldown without a second closed->open count
  (opens==1), REMOUNT and DEREGISTER reset breaker state and prior-handler
  consecutive failures (M46)
- alert lifecycle: domain_status alert active -> ack -> assign -> resolved on
  recovery; ack/assign on a resolved alert -> 409; history shows both states
- restart drill: two sequential "processes" (TestClients) on one file-backed DB
  — persisted counters restored by the second process, circuit fail-safe closed
- metrics/status consistency: counters agree between /domains and
  /domains/metrics; labels bounded to kind; success_rate matches counters
- stale detection + recovery: stale invoke -> last_stale true + stale_count 1,
  later fresh invoke -> last_stale false
- sanitized errors: 502 body has no exception class/message internals;
  diagnostics + metrics contain no secrets
"""
import json
import threading
import time
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

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
    monkeypatch.setenv("CICC_DOMAIN_INVOKE_TIMEOUT_S", "2")
    monkeypatch.setenv("CICC_DOMAIN_INVOKE_RETRIES", "0")
    monkeypatch.setenv("CICC_DOMAIN_STALE_AFTER_S", "60")
    monkeypatch.setenv("CICC_DOMAIN_CIRCUIT_FAILURES", "3")
    monkeypatch.setenv("CICC_DOMAIN_CIRCUIT_COOLDOWN_S", "0.3")
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


def mk(ok=True, stale=False):
    def h(payload, task):
        if not ok:
            raise RuntimeError("fixture down secret=hunter2")
        prov = {"source": "m46-fixture",
                "produced_at": datetime.now(timezone.utc).isoformat(),
                "freshness_s": 999999 if stale else 5}
        return {"result": {"ok": True}, "provenance": prov}
    return h


def inv(client, kind, key, payload=None, tenant=None):
    body = {"payload": payload or {}, "idempotency_key": key}
    if tenant:
        body["tenant_id"] = tenant
    return client.post(f"/api/v1/coordination/domains/{kind}/invoke", json=body, headers=W)


def test_circuit_threshold_and_reject_edges(client):
    domains.register_domain("d1", mk(ok=False), version="1", source_ref="fx")
    assert inv(client, "d1", "t1").status_code == 502
    assert inv(client, "d1", "t2").status_code == 502
    # threshold 3: two failures -> still closed
    assert domains.circuit_state("d1")["open"] is False
    assert inv(client, "d1", "t3").status_code == 502  # 3rd -> opens
    assert domains.circuit_state("d1")["open"] is True
    r = inv(client, "d1", "t4")
    assert r.status_code == 503 and "circuit" in r.json()["detail"] and "hunter2" not in r.text
    m = client.get("/api/v1/coordination/domains/metrics", headers=R).json()["domains"]["d1"]
    assert m["invokes"] == 3 and m["failures"] == 3  # fast-reject is NOT an invoke
    assert m["circuit"]["opens"] == 1
    # cooldown boundary: still open just before cooldown elapses
    time.sleep(0.15)
    assert domains.circuit_state("d1")["open"] is True
    assert inv(client, "d1", "t5").status_code == 503
    # after cooldown: half-open probe executes; its failure keeps the circuit open
    # (no NEW closed->open transition, so opens stays 1 — transitions are counted once)
    time.sleep(0.25)
    first_open_at = domains._CIRCUIT["d1"]["opened_at"]
    assert inv(client, "d1", "t6").status_code == 502  # executed (half-open), failed
    assert domains._CIRCUIT["d1"]["open"] is True
    assert domains._CIRCUIT["d1"]["opened_at"] > first_open_at  # failed probe rearms cooldown
    assert domains.circuit_state("d1")["open"] is True
    assert inv(client, "d1", "t7").status_code == 503  # re-armed cooldown fast-rejects
    m = client.get("/api/v1/coordination/domains/metrics", headers=R).json()["domains"]["d1"]
    assert m["circuit"]["opens"] == 1 and m["invokes"] == 4 and m["failures"] == 4
    with ops.SessionLocal() as s:
        msgs = [e.message for e in s.execute(select(models.Event).where(
            models.Event.source == "coordination.domains")).scalars().all()]
    assert any("HALF-OPEN probe failed; cooldown reset kind=d1" in m for m in msgs)


def test_half_open_allows_only_one_concurrent_probe(client, monkeypatch):
    monkeypatch.setenv("CICC_DOMAIN_CIRCUIT_FAILURES", "3")
    domains.register_domain("probe", mk(ok=False), version="1", source_ref="fx")
    for key in ("p1", "p2", "p3"):
        assert inv(client, "probe", key).status_code == 502
    assert domains._CIRCUIT["probe"]["open"] is True
    time.sleep(0.35)

    barrier = threading.Barrier(8)
    admitted = []
    guard = threading.Lock()

    def try_probe():
        barrier.wait()
        lease = {}
        result = domains._begin_invoke("probe", probe_state=lease)
        with guard:
            admitted.append((result, lease))

    threads = [threading.Thread(target=try_probe) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)
    assert all(not thread.is_alive() for thread in threads)
    assert sum(result for result, _ in admitted) == 1
    assert domains._begin_invoke("probe") is False  # outstanding lease rejects another probe
    probe_state = next(lease for result, lease in admitted if result)
    assert probe_state["half_open_probe"] is True
    opened_at = domains._CIRCUIT["probe"]["opened_at"]
    domains.record_outcome("probe", False, error="fixture sanitized failure",
                           half_open_probe=probe_state["half_open_probe"])
    assert domains._CIRCUIT["probe"]["opened_at"] > opened_at
    assert domains._CIRCUIT["probe"].get("probe_inflight") is False
    assert domains._STATS["probe"]["circuit_opens"] == 1


def test_only_admitted_probe_success_closes_open_circuit(monkeypatch):
    domains.register_domain("probe_success", mk(ok=True), version="1", source_ref="fx")
    normal_call = {}
    assert domains._begin_invoke("probe_success", probe_state=normal_call)
    assert normal_call["half_open_probe"] is False

    # Model a threshold crossing while that earlier call is still outstanding.
    domains._STATS["probe_success"]["consecutive_failures"] = 3
    domains._STATS["probe_success"]["circuit_opens"] = 1
    domains._CIRCUIT["probe_success"] = {
        "open": True, "opened_at": time.time() - 1, "probe_inflight": False,
    }
    domains.record_outcome("probe_success", True,
                           half_open_probe=normal_call["half_open_probe"])
    assert domains._CIRCUIT["probe_success"]["open"] is True
    assert domains._STATS["probe_success"]["circuit_closes"] == 0

    actual_probe = {}
    assert domains._begin_invoke("probe_success", probe_state=actual_probe)
    assert actual_probe["half_open_probe"] is True
    domains.record_outcome("probe_success", True,
                           half_open_probe=actual_probe["half_open_probe"])
    assert domains._CIRCUIT["probe_success"]["open"] is False
    assert domains._STATS["probe_success"]["circuit_closes"] == 1


def test_remount_and_deregister_reset_circuit(client, monkeypatch):
    monkeypatch.setenv("CICC_DOMAIN_CIRCUIT_FAILURES", "2")
    domains.register_domain("d2", mk(ok=False), version="1", source_ref="fx")
    assert inv(client, "d2", "r1").status_code == 502
    assert inv(client, "d2", "r2").status_code == 502
    assert domains.circuit_state("d2")["open"] is True
    assert inv(client, "d2", "r3").status_code == 503
    # M46: remount installs a fresh handler and clears both the breaker state
    # and the previous handler's consecutive-failure threshold.
    domains.register_domain("d2", mk(ok=False), version="2", source_ref="fx")
    assert domains.circuit_state("d2")["open"] is False
    assert domains._STATS["d2"]["consecutive_failures"] == 0
    assert inv(client, "d2", "r4-reset").status_code == 502
    assert domains.circuit_state("d2")["open"] is False  # prior failures did not carry over
    domains.register_domain("d2", mk(ok=True), version="3", source_ref="fx")
    assert inv(client, "d2", "r5").status_code == 201
    # Open it again, then deregister -> circuit cleared; fresh mount can run.
    domains.register_domain("d2", mk(ok=False), version="4", source_ref="fx")
    assert inv(client, "d2", "r6").status_code == 502
    assert inv(client, "d2", "r7").status_code == 502
    assert domains.circuit_state("d2")["open"] is True
    domains.unregister_domain("d2")
    assert "d2" not in domains._CIRCUIT
    domains.register_domain("d2", mk(ok=True), version="5", source_ref="fx")
    assert inv(client, "d2", "r8").status_code == 201  # no stale circuit blocks it


def test_alert_lifecycle_ack_assign_resolve_history(client):
    domains.register_domain("d3", mk(ok=False), version="1", source_ref="fx")
    for k in ("a1", "a2", "a3"):
        inv(client, "d3", k)  # 3 failures -> FAILED -> critical domain_status alert
    r = client.get("/api/v1/ops/alerts?state=active", headers=R)
    da = [a for a in r.json()["alerts"] if a.get("rule") == "domain_status"
          and a.get("component_key") == "d3"]
    assert len(da) == 1 and da[0]["severity"] == "critical" and "hunter2" not in json.dumps(da)
    aid = da[0]["id"]
    occurrences_before_ack = da[0]["occurrences"]
    # ack (read token allowed) + assign (write token required)
    r = client.post(f"/api/v1/ops/alerts/{aid}/ack", json={"acked_by": "ops"}, headers=R)
    assert r.status_code == 200 and r.json()["status"] == "acknowledged"
    r = client.post(f"/api/v1/ops/alerts/{aid}/assign", json={"owner": "agent-1"}, headers=R)
    assert r.status_code in (401, 403)  # write-gated
    r = client.post(f"/api/v1/ops/alerts/{aid}/assign", json={"owner": "agent-1"}, headers=W)
    assert r.status_code == 200 and r.json()["owner"] == "agent-1"
    # A new half-open failure re-activates the acknowledged alert, increments
    # occurrences, and records a sanitized lifecycle event.
    time.sleep(0.35)
    assert inv(client, "d3", "a3-retry").status_code == 502
    r = client.get("/api/v1/ops/alerts?state=active", headers=R)
    da = [a for a in r.json()["alerts"] if a.get("id") == aid]
    assert (len(da) == 1 and da[0]["status"] == "active"
            and da[0]["occurrences"] == occurrences_before_ack + 1
            and da[0]["acked_at"] is None and da[0]["acked_by"] is None)
    with ops.SessionLocal() as s:
        msgs = [e.message for e in s.execute(select(models.Event).where(
            models.Event.source == "alerts")).scalars().all()]
    assert any("domain alert re-activated kind=d3" in m for m in msgs)
    # Recovery resolves the re-activated alert after the new cooldown.
    domains._REGISTRY["d3"]["handler"] = mk(ok=True)
    time.sleep(0.35)
    assert inv(client, "d3", "a4").status_code == 201
    r = client.get("/api/v1/ops/alerts?state=active", headers=R)
    da = [a for a in r.json()["alerts"] if a.get("rule") == "domain_status"
          and a.get("component_key") == "d3"]
    assert not da
    # ack/assign on the resolved alert -> 409 conflict
    r = client.post(f"/api/v1/ops/alerts/{aid}/ack", json={"acked_by": "ops"}, headers=R)
    assert r.status_code == 409
    r = client.post(f"/api/v1/ops/alerts/{aid}/assign", json={"owner": "x"}, headers=W)
    assert r.status_code == 409
    # history shows the full lifecycle (acknowledged/resolved rows, sanitized)
    r = client.get("/api/v1/ops/alerts/history?rule=domain_status", headers=R)
    hist = [a for a in r.json()["alerts"] if a.get("component_key") == "d3"]
    assert hist and hist[0]["status"] == "resolved" and "hunter2" not in json.dumps(hist)


def test_restart_drill_two_processes_one_db(client, monkeypatch, tmp_path):
    """Simulate a full process restart: a second TestClient on the SAME file DB
    must see persisted counters (startup load) and a fail-safe closed circuit."""
    dbfile = str(tmp_path / "drill.db")
    engine = create_engine("sqlite:///" + dbfile, connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _wal(c, _):
        cur = c.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.close()

    models.Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    monkeypatch.setattr(ops, "engine", engine)
    monkeypatch.setattr(ops, "SessionLocal", Session)
    ops.init_db()

    domains.register_domain("d4", mk(ok=True), version="1", source_ref="fx")
    assert inv(client, "d4", "p1").status_code == 201
    assert inv(client, "d4", "p2").status_code == 201
    domains._REGISTRY["d4"]["handler"] = mk(ok=False)
    assert inv(client, "d4", "p3").status_code == 502

    # ---- "process 2": wipe process-local state, new TestClient, same DB file ----
    domains._STATS.clear()
    domains._CIRCUIT.clear()
    domains._REGISTRY.clear()
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c2:  # lifespan startup load runs here (M45)
        st = c2.get("/api/v1/coordination/domains/d4/status", headers=R).json()
        assert st["status"] == "NOT_MOUNTED"  # honest: handler gone after restart
        ev = st["evidence"]
        assert ev["invokes"] == 3 and ev["successes"] == 2 and ev["consecutive_failures"] == 1
        assert ev["circuit"]["open"] is False  # fail-safe process-local
        m = c2.get("/api/v1/coordination/domains/metrics", headers=R).json()["domains"]["d4"]
        assert m["invokes"] == 3 and m["successes"] == 2 and m["mounts_total"] == 0
        # remount after restart -> works, evidence carries on (not clobbered)
        domains.register_domain("d4", mk(ok=True), version="2", source_ref="fx")
        assert inv(c2, "d4", "p4").status_code == 201
        st = c2.get("/api/v1/coordination/domains/d4/status", headers=R).json()
        assert st["status"] == "EXECUTION_VERIFIED" and st["evidence"]["invokes"] == 4
    engine.dispose()


def test_metrics_status_consistency_and_bounded_labels(client):
    domains.register_domain("d5", mk(), version="1", source_ref="fx")
    assert inv(client, "d5", "m1", payload={"secret_marker": "tok-d5"},
               tenant="tenant-d5").status_code == 201
    domains._REGISTRY["d5"]["handler"] = mk(ok=False)
    assert inv(client, "d5", "m2").status_code == 502
    status = client.get("/api/v1/coordination/domains", headers=R).json()["statuses"]["d5"]
    metrics = client.get("/api/v1/coordination/domains/metrics", headers=R).json()
    d = metrics["domains"]["d5"]
    assert metrics["labels"] == ["kind"]
    assert d["invokes"] == status["invokes"] == 2 and d["successes"] == status["successes"] == 1
    assert d["failures"] == 1 and d["success_rate"] == round(1 / 2, 4)
    assert d["status"] == status["status"] == "DEGRADED"
    assert set(metrics["domains"]) == {"d5"}  # bounded cardinality: kind only
    blob = json.dumps(metrics) + json.dumps(status)
    assert "tenant-d5" not in blob and "tok-d5" not in blob


def test_stale_detection_and_recovery(client):
    domains.register_domain("d6", mk(stale=True), version="1", source_ref="fx")
    r = inv(client, "d6", "s1")
    assert r.status_code == 201 and r.json()["stale"] is True
    st = client.get("/api/v1/coordination/domains/d6/status", headers=R).json()["evidence"]
    assert st["last_stale"] is True
    m = client.get("/api/v1/coordination/domains/metrics", headers=R).json()["domains"]["d6"]
    assert m["stale_count"] == 1
    # recovery with a fresh result resets last_stale (never silently fresh->stale)
    domains._REGISTRY["d6"]["handler"] = mk(stale=False)
    assert inv(client, "d6", "s2").status_code == 201
    st = client.get("/api/v1/coordination/domains/d6/status", headers=R).json()["evidence"]
    assert st["last_stale"] is False


def test_sanitized_errors_and_diagnostics(client):
    domains.register_domain("d7", mk(ok=False), version="1", source_ref="fx")
    r = inv(client, "d7", "x1", payload={"secret_marker": "tok-zz"}, tenant="tenant-zz")
    assert r.status_code == 502
    assert "hunter2" not in r.text and "RuntimeError" not in r.text and "tok-zz" not in r.text
    blob = json.dumps(client.get("/api/v1/coordination/domains/metrics", headers=R).json())
    blob += json.dumps(client.get("/api/v1/coordination/diagnostics", headers=R).json())
    blob += json.dumps(client.get("/api/v1/ops/alerts/history", headers=R).json())
    assert "tok-zz" not in blob and "tenant-zz" not in blob and "hunter2" not in blob
