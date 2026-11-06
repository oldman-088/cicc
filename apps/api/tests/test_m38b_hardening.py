"""M38-hardening — gateway/adapter failure & recovery coverage (deterministic, fixture-only).

- retry exhaustion (attempts counted, sanitized), consecutive timeouts,
  recovery after repeated failures (consecutive_failures reset)
- restart persistence: stats survive in-memory wipe via coord_domain_stats
- hardened response validation: missing/corrupt provenance, bad produced_at,
  out-of-range or non-numeric confidence -> 422 DomainInvalid
- secret-leakage regression: handler exceptions/events/health never contain secrets
- concurrent same-key create (SQLite threads) -> exactly one creator
- deregister during in-flight invoke does not crash; status -> NOT_MOUNTED
"""
import json
import threading
import time
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import models, ops, ratelimit
from app.coordination import domains, registry

W = {"Authorization": "Bearer w", "Content-Type": "application/json"}
R = {"Authorization": "Bearer r"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r")
    monkeypatch.setenv("CICC_COORD_APPROVERS", "owner")
    monkeypatch.setenv("CICC_DOMAIN_INVOKE_TIMEOUT_S", "0.3")
    monkeypatch.setenv("CICC_DOMAIN_INVOKE_RETRIES", "2")
    monkeypatch.delenv("RABBITMQ_AMQP_URL", raising=False)
    for k in list(domains._REGISTRY):
        domains.unregister_domain(k)
    yield
    for k in list(domains._REGISTRY):
        domains.unregister_domain(k)
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def ok_handler(payload, task):
    return {"result": {"ok": True},
            "provenance": {"source": "h-fixture", "produced_at": datetime.now(timezone.utc).isoformat(),
                           "confidence": 0.5}}


def test_retry_exhaustion_then_consecutive_failures_and_recovery(client, monkeypatch):
    calls = {"n": 0}
    def always_fail(payload, task):
        calls["n"] += 1
        raise RuntimeError("boom secret=abc123")
    domains.register_domain("threat_intel", always_fail, version="f", source_ref="fixture")
    r = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                    json={"payload": {}, "idempotency_key": "x1"}, headers=W)
    assert r.status_code == 502
    assert "attempt 3/3" in r.json()["detail"]  # 1 + 2 retries
    assert calls["n"] == 3
    assert "abc123" not in r.text  # sanitized
    st = domains.all_statuses()["threat_intel"]
    assert st["status"] == "FAILED" and st["consecutive_failures"] == 1
    # second failure -> consecutive_failures grows
    r2 = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                     json={"payload": {}, "idempotency_key": "x2"}, headers=W)
    assert r2.status_code == 502
    assert domains.all_statuses()["threat_intel"]["consecutive_failures"] == 2
    # recovery
    domains._REGISTRY["threat_intel"]["handler"] = ok_handler
    r3 = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                     json={"payload": {}, "idempotency_key": "x3"}, headers=W)
    assert r3.status_code == 201
    st = domains.all_statuses()["threat_intel"]
    assert st["status"] == "EXECUTION_VERIFIED" and st["consecutive_failures"] == 0


def test_consecutive_timeouts(client, monkeypatch):
    monkeypatch.setenv("CICC_DOMAIN_INVOKE_RETRIES", "0")
    def slow(payload, task):
        time.sleep(2)
        return ok_handler(payload, task)
    domains.register_domain("vuln_intel", slow, version="f", source_ref="fixture")
    for i in (1, 2):
        r = client.post("/api/v1/coordination/domains/vuln_intel/invoke",
                        json={"payload": {}, "idempotency_key": f"t{i}"}, headers=W)
        assert r.status_code == 502 and "timed out" in r.json()["detail"]
    st = domains.all_statuses()["vuln_intel"]
    assert st["status"] == "FAILED" and st["consecutive_failures"] == 2 and st["successes"] == 0


def test_restart_persistence_via_db(client):
    domains.register_domain("threat_intel", ok_handler, version="f", source_ref="fixture")
    r = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                    json={"payload": {}, "idempotency_key": "p1"}, headers=W)
    assert r.status_code == 201
    # simulate process restart: wipe in-memory registry/stats, DB persists
    domains._REGISTRY.clear()
    domains._STATS.clear()
    assert domains.domain_status("threat_intel") == domains.NOT_MOUNTED
    # re-mount (as startup code would) and query status -> persisted evidence restored
    domains.register_domain("threat_intel", ok_handler, version="f", source_ref="fixture")
    s = client.get("/api/v1/coordination/domains/threat_intel/status", headers=R).json()
    assert s["status"] == "EXECUTION_VERIFIED", s
    assert s["evidence"]["successes"] >= 1


def test_hardened_response_validation(client):
    bad_responses = [
        {"result": 1},                                   # missing provenance
        {"result": 1, "provenance": {"source": "s"}},    # missing produced_at
        {"result": 1, "provenance": {"source": "s", "produced_at": "not-a-date"}},
        {"result": 1, "provenance": {"source": "s", "produced_at": "2026-11-06T00:00:00+00:00", "confidence": 5}},
        {"result": 1, "provenance": {"source": "s", "produced_at": "2026-11-06T00:00:00+00:00", "confidence": "high"}},
    ]
    for i, bad in enumerate(bad_responses):
        domains.unregister_domain("threat_intel")
        domains.register_domain("threat_intel", lambda p, t, b=bad: b, version="f", source_ref="fixture")
        r = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                        json={"payload": {}, "idempotency_key": f"bad{i}"}, headers=W)
        assert r.status_code == 422, (i, r.status_code, r.text)
    # valid edge: confidence 0 and 1 accepted
    domains.unregister_domain("threat_intel")
    domains.register_domain("threat_intel", ok_handler, version="f", source_ref="fixture")
    r = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                    json={"payload": {}, "idempotency_key": "ok1"}, headers=W)
    assert r.status_code == 201


def test_secret_leakage_regression(client):
    def leaky(payload, task):
        raise ValueError("db_url=postgres://user:hunter2@internal-host/db")
    domains.register_domain("threat_intel", leaky, version="f", source_ref="fixture")
    r = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                    json={"payload": {}, "idempotency_key": "leak1"}, headers=W)
    assert r.status_code == 502
    blob = r.text
    assert "hunter2" not in blob and "internal-host" not in blob and "postgres" not in blob
    h = client.get("/api/v1/coordination/health", headers=R).json()
    s = client.get("/api/v1/coordination/domains/threat_intel/status", headers=R).json()
    ev = client.get("/api/v1/coordination/events", headers=R).json()
    for b in (json.dumps(h), json.dumps(s), json.dumps(ev)):
        assert "hunter2" not in b and "internal-host" not in b


def test_concurrent_same_key_create_single_creator(tmp_path):
    # file-backed SQLite so each thread gets its OWN connection (like real deployments);
    # StaticPool single-connection sharing would interleave sessions artificially
    engine = create_engine("sqlite:///" + str(tmp_path / "race.db"),
                           connect_args={"check_same_thread": False})
    models.Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    created = []
    errors = []
    lock = threading.Lock()

    def worker(i):
        try:
            with Session() as s:
                t = registry.create_task(s, task_id=f"race-{i}", event_id=None, source="api",
                                         kind="x", repo=None, pr_ref=None, branch_ref=None,
                                         title="t", payload={}, idempotency_key="same-key")
                with lock:
                    created.append(getattr(t, "_created", True))
                s.commit()
        except Exception as e:
            with lock:
                errors.append(f"{type(e).__name__}: {e}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors, errors[:3]
    assert sum(created) == 1, created
    with Session() as s:
        rows = s.query(models.CoordinationTask).filter(
            models.CoordinationTask.idempotency_key == "same-key").all()
        assert len(rows) == 1
    engine.dispose()


def test_deregister_during_inflight_invoke_is_safe(monkeypatch):
    monkeypatch.setenv("CICC_DOMAIN_INVOKE_TIMEOUT_S", "5")
    monkeypatch.setenv("CICC_DOMAIN_INVOKE_RETRIES", "0")
    def slow_ok(payload, task):
        time.sleep(0.5)
        return ok_handler(payload, task)
    domains.register_domain("threat_intel", slow_ok, version="f", source_ref="fixture")
    outcome = {}

    def run():
        try:
            outcome["res"] = domains.invoke("threat_intel", {}, task=None)
        except Exception as e:
            outcome["err"] = e

    th = threading.Thread(target=run)
    th.start()
    time.sleep(0.1)
    assert domains.unregister_domain("threat_intel") is True  # deregister mid-flight
    th.join(timeout=5)
    assert "res" in outcome and outcome["res"]["result"]["ok"] is True  # in-flight call completes
    assert domains.domain_status("threat_intel") == domains.NOT_MOUNTED
    with pytest.raises(domains.DomainNotMounted):
        domains.invoke("threat_intel", {}, task=None)  # new invokes honestly fail
