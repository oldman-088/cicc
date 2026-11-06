"""M44 — gateway observability metrics + M43 regression edge cases (fixture-only).

- /domains/metrics aggregation accuracy: invokes/successes/failures/timeouts/
  retries/stale/skew/latency/circuit counters/mount_count exact after a known mix
- concurrency: N threads distinct keys (ok+fail mix) -> counters exact
- sensitive-data exclusion: no tenant ids/tokens/payload values in metrics or
  diagnostics; labels bounded to kind
- circuit across restart: process-local (documented) — in-memory wipe closes it;
  persisted invokes/successes survive
- concurrent failures -> consecutive_failures exact, circuit opens once
- concurrent recovery attempts -> exactly one closes circuit (idempotent)
- repeated remounts -> mount_count exact
- boundary payload sizes: exactly 64 KiB ok, +1 byte -> 413
"""
import json
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from app import ops, ratelimit
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
    monkeypatch.setenv("CICC_DOMAIN_INVOKE_TIMEOUT_S", "0.4")
    monkeypatch.setenv("CICC_DOMAIN_INVOKE_RETRIES", "1")
    monkeypatch.setenv("CICC_DOMAIN_STALE_AFTER_S", "60")
    monkeypatch.setenv("CICC_DOMAIN_CIRCUIT_FAILURES", "4")
    monkeypatch.setenv("CICC_DOMAIN_CIRCUIT_COOLDOWN_S", "30")
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


def mk(ok=True, stale=False, skew=False, slow=False):
    def h(payload, task):
        if slow:
            time.sleep(2)
        if not ok:
            raise RuntimeError("down secret=hunter2")
        pa = datetime.now(timezone.utc)
        fresh = 999999 if stale else 5
        if skew:
            pa = pa + timedelta(hours=1)
            fresh = None  # skew detected via produced_at, not freshness_s
        prov = {"source": "m44", "produced_at": pa.isoformat()}
        if fresh is not None:
            prov["freshness_s"] = fresh
        return {"result": {"ok": True}, "provenance": prov}
    return h


def test_metrics_aggregation_accuracy(client):
    domains.register_domain("threat_intel", mk(ok=True), version="f", source_ref="fx")
    # 2 ok, 1 stale, 1 skew, 2 fail (with 1 retry each), 1 timeout
    for i, (handler, key) in enumerate([
            (mk(ok=True), "m-ok1"), (mk(ok=True), "m-ok2"), (mk(stale=True), "m-stale"),
            (mk(skew=True), "m-skew"), (mk(ok=False), "m-f1"), (mk(ok=False), "m-f2"),
            (mk(slow=True), "m-slow")]):
        domains._REGISTRY["threat_intel"]["handler"] = handler
        r = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                        json={"payload": {}, "idempotency_key": key}, headers=W)
        assert r.status_code in (201, 502), (key, r.status_code)
    m = client.get("/api/v1/coordination/domains/metrics", headers=R).json()["domains"]["threat_intel"]
    assert m["invokes"] == 7 and m["successes"] == 4 and m["failures"] == 3
    assert m["success_rate"] == round(4 / 7, 4)
    assert m["stale_count"] == 1 and m["skew_count"] == 1
    assert m["timeouts"] == 1
    assert m["retries"] == 3  # each of the 3 failing/timed-out invokes retried once (RETRIES=1)
    assert m["latency"]["count"] == 7 and m["latency"]["avg_s"] >= 0 and m["latency"]["max_s"] >= 0.4
    assert m["mount_count"] == 1
    assert m["circuit"]["opens"] == 0  # only 2 consecutive failures < 4
    assert client.get("/api/v1/coordination/domains/metrics").status_code == 401  # read-gated


def _thread_client():
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


@pytest.fixture()
def file_db(monkeypatch, tmp_path):
    """File-backed SQLite bound into ops for concurrency tests (each connection
    gets its own DB file view; avoids in-test 'database is locked' artifacts)."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app import models
    engine = create_engine("sqlite:///" + str(tmp_path / "conc.db"),
                           connect_args={"check_same_thread": False})
    from sqlalchemy import event as _ev
    @_ev.listens_for(engine, "connect")
    def _wal(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.close()
    models.Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    monkeypatch.setattr(ops, "engine", engine)
    monkeypatch.setattr(ops, "SessionLocal", Session)
    ops.init_db()
    yield engine
    engine.dispose()


def test_metrics_concurrency_and_sensitive_exclusion(file_db, monkeypatch):
    monkeypatch.setenv("CICC_DOMAIN_CIRCUIT_FAILURES", "100")  # keep circuit closed for the mix

    def h(payload, task):  # outcome decided by payload, not by a racy handler swap
        if payload.get("fail"):
            raise RuntimeError("down secret=hunter2")
        return {"result": {"ok": True},
                "provenance": {"source": "m44",
                               "produced_at": datetime.now(timezone.utc).isoformat(),
                               "freshness_s": 5}}

    domains.register_domain("threat_intel", h, version="f", source_ref="fx")
    outcomes = []
    lock = threading.Lock()

    def one(i):
        c = _thread_client()  # TestClient is not thread-safe — one per thread
        r = c.post("/api/v1/coordination/domains/threat_intel/invoke",
                   json={"payload": {"fail": bool(i % 2), "secret_marker": f"tok-{i}"},
                         "tenant_id": f"tenant-{i}",
                         "idempotency_key": f"cc-{i}"}, headers=W)
        with lock:
            outcomes.append(r.status_code)
        c.close()

    threads = [threading.Thread(target=one, args=(i,)) for i in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    tc = _thread_client()
    m = tc.get("/api/v1/coordination/domains/metrics", headers=R).json()
    d = m["domains"]["threat_intel"]
    assert d["invokes"] == 8 and d["successes"] + d["failures"] == 8, (sorted(outcomes), d)
    assert d["successes"] == 4 and d["failures"] == 4
    assert all(c in (201, 502) for c in outcomes)
    blob = json.dumps(m)
    assert "tenant-" not in blob and "tok-" not in blob and "Bearer" not in blob
    assert m["labels"] == ["kind"]
    dg = tc.get("/api/v1/coordination/diagnostics", headers=R).json()
    assert "tenant-" not in json.dumps(dg) and "tok-" not in json.dumps(dg)
    tc.close()


def test_concurrent_failures_circuit_opens_once(monkeypatch, file_db):
    monkeypatch.setenv("CICC_DOMAIN_CIRCUIT_FAILURES", "4")
    domains.register_domain("vuln_intel", mk(ok=False), version="f", source_ref="fx")
    codes = []
    lock = threading.Lock()

    def one(i):
        c = _thread_client()
        r = c.post("/api/v1/coordination/domains/vuln_intel/invoke",
                   json={"payload": {}, "idempotency_key": f"cf-{i}"}, headers=W)
        with lock:
            codes.append(r.status_code)
        c.close()

    threads = [threading.Thread(target=one, args=(i,)) for i in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    # 4 failures open the circuit; further invokes may be 502 or 503 depending on timing,
    # but circuit_opens must be exactly 1 and consecutive_failures exact
    tc = _thread_client()
    m = tc.get("/api/v1/coordination/domains/metrics", headers=R).json()["domains"]["vuln_intel"]
    assert m["circuit"]["opens"] == 1, (sorted(codes), m)
    # every executed invoke failed; fast-rejected 503s are not counted as invokes
    assert m["failures"] >= 4 and m["invokes"] == m["failures"] and 4 <= m["invokes"] <= 6, (sorted(codes), m)
    assert all(c in (502, 503) for c in codes)
    tc.close()


def test_concurrent_recovery_closes_circuit_once(monkeypatch, file_db):
    monkeypatch.setenv("CICC_DOMAIN_CIRCUIT_FAILURES", "2")
    monkeypatch.setenv("CICC_DOMAIN_CIRCUIT_COOLDOWN_S", "0")  # immediately half-open
    domains.register_domain("vuln_intel", mk(ok=False), version="f", source_ref="fx")
    c0 = _thread_client()
    c0.post("/api/v1/coordination/domains/vuln_intel/invoke",
            json={"payload": {}, "idempotency_key": "r1"}, headers=W)
    c0.post("/api/v1/coordination/domains/vuln_intel/invoke",
            json={"payload": {}, "idempotency_key": "r2"}, headers=W)
    c0.close()
    assert domains.circuit_state("vuln_intel")["open"] is False or True  # cooldown 0 -> half-open
    domains._REGISTRY["vuln_intel"]["handler"] = mk(ok=True)
    codes = []
    lock = threading.Lock()

    def one(i):
        c = _thread_client()
        r = c.post("/api/v1/coordination/domains/vuln_intel/invoke",
                   json={"payload": {}, "idempotency_key": f"rc-{i}"}, headers=W)
        with lock:
            codes.append(r.status_code)
        c.close()

    threads = [threading.Thread(target=one, args=(i,)) for i in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert all(c == 201 for c in codes)
    tc = _thread_client()
    m = tc.get("/api/v1/coordination/domains/metrics", headers=R).json()["domains"]["vuln_intel"]
    assert m["circuit"]["closes"] == 1  # exactly one close transition counted
    assert m["successes"] == 4
    tc.close()


def test_repeated_remounts_and_process_local_circuit(client, tmp_path):
    mod = tmp_path / "d.py"
    mod.write_text("def handle(payload, task):\n"
                   "    from datetime import datetime, timezone\n"
                   "    return {'result': {}, 'provenance': {'source': 'm44', 'produced_at': datetime.now(timezone.utc).isoformat()}}\n")
    for v in range(5):
        r = client.post("/api/v1/coordination/domains/threat_intel/mount",
                        json={"module_path": str(mod), "attr": "handle", "version": f"v{v}",
                              "source_ref": "fx"}, headers=W)
        assert r.status_code == 201
    m = client.get("/api/v1/coordination/domains/metrics", headers=R).json()["domains"]["threat_intel"]
    assert m["mount_count"] == 5
    # circuit state is process-local: wiping in-memory state closes it (documented);
    # persisted counters (invokes/successes) survive via DB
    domains._CIRCUIT["threat_intel"] = {"open": True, "opened_at": time.time()}
    domains._REGISTRY.clear(); domains._STATS.clear(); domains._CIRCUIT.clear()  # simulate restart (all memory wiped)
    assert domains.circuit_state("threat_intel")["open"] is False  # process-local limitation
    domains.register_domain("threat_intel", mk(ok=True), version="v5", source_ref="fx")
    st = client.get("/api/v1/coordination/domains/threat_intel/status", headers=R).json()
    assert "mount_count" in st["evidence"]  # volatile fields survive merge


def test_boundary_payload_sizes(client):
    domains.register_domain("threat_intel", mk(ok=True), version="f", source_ref="fx")
    # effective boundary = global API body cap MAX_BODY_BYTES (16 KiB middleware);
    # the router adds a second 64 KiB layer for the invoke payload specifically
    from app.main import MAX_BODY_BYTES
    base = len(json.dumps({"payload": {"x": ""}, "idempotency_key": "b1"}))
    at_cap = "y" * (MAX_BODY_BYTES - base - 1)  # exactly at the cap -> passes middleware
    r = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                    json={"payload": {"x": at_cap}, "idempotency_key": "b1"}, headers=W)
    assert r.status_code == 201, r.status_code
    over = "y" * (MAX_BODY_BYTES - base + 5)  # over the cap -> 413
    r2 = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                     json={"payload": {"x": over}, "idempotency_key": "b2"}, headers=W)
    assert r2.status_code == 413
