"""M41 — gateway reliability edge cases (fixture-only, deterministic).

- stale-data detection: freshness_s beyond CICC_DOMAIN_STALE_AFTER_S -> 201 with
  stale=true + domain_stale event + evidence.last_stale; fresh -> stale=false
- lifecycle transition correctness: invoke trace has the exact ordered chain
  created -> domain_result -> state:* -> RUNNING->COMPLETED
- concurrent invocation with DISTINCT keys on the same domain all succeed and
  the invoke counter is exact
- health component reports worst domain status (FAILED -> degraded component)
- PG: restart persistence of domain stats (pgserver)
"""
import json
import threading
from datetime import datetime, timedelta, timezone

import pytest

from app import ratelimit
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
    monkeypatch.delenv("RABBITMQ_AMQP_URL", raising=False)
    for k in list(domains._REGISTRY):
        domains.unregister_domain(k)
    yield
    for k in list(domains._REGISTRY):
        domains.unregister_domain(k)
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def handler_with_freshness(payload, task, freshness_s=5, age_s=0):
    produced = datetime.now(timezone.utc) - timedelta(seconds=age_s)
    return {"result": {"ok": True},
            "provenance": {"source": "m41-fixture", "produced_at": produced.isoformat(),
                           "confidence": 0.9, "freshness_s": freshness_s}}


def test_stale_detection_freshness_and_age(client, monkeypatch):
    domains.register_domain("threat_intel",
                            lambda p, t: handler_with_freshness(p, t, freshness_s=5),
                            version="f", source_ref="fixture")
    r = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                    json={"payload": {}, "idempotency_key": "st-fresh"}, headers=W)
    assert r.status_code == 201 and r.json()["stale"] is False
    tr = client.get(f"/api/v1/coordination/tasks/{r.json()['task_id']}/trace", headers=R).json()
    assert not any(e["kind"] == "domain_stale" for e in tr["events"])

    # stale via explicit freshness_s
    domains._REGISTRY["threat_intel"]["handler"] = lambda p, t: handler_with_freshness(p, t, freshness_s=999)
    r2 = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                     json={"payload": {}, "idempotency_key": "st-stale"}, headers=W)
    assert r2.status_code == 201 and r2.json()["stale"] is True
    tr2 = client.get(f"/api/v1/coordination/tasks/{r2.json()['task_id']}/trace", headers=R).json()
    assert any(e["kind"] == "domain_stale" for e in tr2["events"])
    assert json.loads(tr2["result"])["stale"] is True if isinstance(tr2["result"], str) else tr2["result"]["stale"] is True
    st = client.get("/api/v1/coordination/domains/threat_intel/status", headers=R).json()
    assert st["evidence"]["last_stale"] is True and st["evidence"]["stale_after_s"] == 60

    # stale via produced_at age when freshness_s absent
    domains._REGISTRY["threat_intel"]["handler"] = lambda p, t: handler_with_freshness(p, t, freshness_s=None, age_s=3600)
    domains._REGISTRY["threat_intel"]["handler"] = lambda p, t: {"result": {"ok": True},
        "provenance": {"source": "m41", "produced_at": (datetime.now(timezone.utc) - timedelta(seconds=3600)).isoformat()}}
    r3 = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                     json={"payload": {}, "idempotency_key": "st-old"}, headers=W)
    assert r3.status_code == 201 and r3.json()["stale"] is True


def test_lifecycle_trace_exact_order(client):
    domains.register_domain("vuln_intel", lambda p, t: handler_with_freshness(p, t),
                            version="f", source_ref="fixture")
    r = client.post("/api/v1/coordination/domains/vuln_intel/invoke",
                    json={"payload": {}, "idempotency_key": "lc-1"}, headers=W)
    assert r.status_code == 201
    tr = client.get(f"/api/v1/coordination/tasks/{r.json()['task_id']}/trace", headers=R).json()
    kinds = [e["kind"] for e in tr["events"]]
    assert kinds[0] == "created"
    assert "domain_result" in kinds
    assert kinds[-1] == "state:RUNNING->COMPLETED"
    assert kinds == ["created", "domain_result"] + [
        "state:CREATED->QUEUED", "state:QUEUED->ASSIGNED", "state:ASSIGNED->DELIVERING",
        "state:DELIVERING->ACKNOWLEDGED", "state:ACKNOWLEDGED->RUNNING", "state:RUNNING->COMPLETED"]
    assert tr["state"] == "COMPLETED"


def test_concurrent_distinct_keys_all_succeed(client):
    domains.register_domain("threat_intel", lambda p, t: handler_with_freshness(p, t),
                            version="f", source_ref="fixture")
    outcomes = []
    lock = threading.Lock()

    def one(i):
        r = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                        json={"payload": {}, "idempotency_key": f"cc-{i}"}, headers=W)
        with lock:
            outcomes.append(r.status_code)

    threads = [threading.Thread(target=one, args=(i,)) for i in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert outcomes == [201] * 6, outcomes
    st = client.get("/api/v1/coordination/domains/threat_intel/status", headers=R).json()
    assert st["evidence"]["invokes"] == 6 and st["evidence"]["successes"] == 6


def test_health_worst_status_reflects_failed_domain(client):
    domains.register_domain("threat_intel", lambda p, t: handler_with_freshness(p, t),
                            version="f", source_ref="fixture")
    client.post("/api/v1/coordination/domains/threat_intel/invoke",
                json={"payload": {}, "idempotency_key": "h-ok"}, headers=W)
    domains.register_domain("vuln_intel", lambda p, t: (_ for _ in ()).throw(RuntimeError("down")),
                            version="f", source_ref="fixture")
    client.post("/api/v1/coordination/domains/vuln_intel/invoke",
                json={"payload": {}, "idempotency_key": "h-bad"}, headers=W)
    h = client.get("/api/v1/coordination/health", headers=R).json()
    comp = next(c for c in h["components"] if c["key"] == "domains")
    assert comp["status"] == "degraded" and "FAILED" in comp["detail"]
    assert comp["domains"]["vuln_intel"]["status"] == "FAILED"
    assert comp["domains"]["threat_intel"]["status"] == "EXECUTION_VERIFIED"
    # recovery flips it back
    domains._REGISTRY["vuln_intel"]["handler"] = lambda p, t: handler_with_freshness(p, t)
    client.post("/api/v1/coordination/domains/vuln_intel/invoke",
                json={"payload": {}, "idempotency_key": "h-rec"}, headers=W)
    h2 = client.get("/api/v1/coordination/health", headers=R).json()
    comp2 = next(c for c in h2["components"] if c["key"] == "domains")
    assert comp2["status"] == "healthy" and "EXECUTION_VERIFIED" in comp2["detail"]


def test_pg_restart_persistence_of_domain_stats(tmp_path):
    pgserver = pytest.importorskip("pgserver")
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import sessionmaker
    from app import models, ops
    from app.coordination import registry
    server = pgserver.get_server(str(tmp_path / "pgdata"))
    url = server.get_uri().replace("postgresql://", "postgresql+psycopg2://", 1)
    engine = create_engine(url, pool_pre_ping=True)
    models.Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)
    domains.register_domain("threat_intel", lambda p, t: handler_with_freshness(p, t),
                            version="f", source_ref="pg-fixture")
    with Session() as s:
        t = registry.create_task(s, task_id="pg-dom-1", event_id=None, source="domain_gateway",
                                 kind="threat_intel", repo=None, pr_ref=None, branch_ref=None,
                                 title="t", payload={}, idempotency_key="pg-k1")
        out = domains.invoke("threat_intel", {}, task=t)
        domains.record_outcome("threat_intel", True, stale=False)
        t.result = json.dumps(out)
        s.commit()
        # persist stats row the way the router does
        row = models.CoordinationDomainStat(kind="threat_intel", version="f", source_ref="pg-fixture",
                                            validated=1, invokes=1, successes=1, consecutive_failures=0,
                                            last_stale=0, last_status="ok")
        s.add(row)
        s.commit()
        row = s.execute(select(models.CoordinationDomainStat)).scalars().all()
    # simulate restart: wipe memory, reload from DB
    domains._REGISTRY.clear()
    domains._STATS.clear()
    domains.register_domain("threat_intel", lambda p, t: handler_with_freshness(p, t),
                            version="f", source_ref="pg-fixture")
    domains.load_persisted_stats(list(row))
    assert domains.domain_status("threat_intel") == domains.EXECUTION_VERIFIED
    assert domains.all_statuses()["threat_intel"]["successes"] == 1
    engine.dispose()
