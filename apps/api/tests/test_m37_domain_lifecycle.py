"""M37 — domain gateway lifecycle, reliability, and evidence-based health.

Covers the REAL integration lifecycle (register -> validate -> invoke ->
persist result+provenance -> trace -> failure/degraded -> deregister), not
synthetic registration only:
- TI-shaped fixture handler (result + provenance with source, produced_at,
  confidence, freshness) passes through the gateway and trace intact
- retry: flaky handler fails once then succeeds, same idempotency_key
- timeout: slow handler -> sanitized 502, status FAILED
- failure after success -> DEGRADED; deregister -> NOT_MOUNTED
- duplicate invoke with same key executes the handler exactly once
- unmounted kind -> 409 + NOT_MOUNTED; missing stats -> UNKNOWN
- mount/deregister endpoints are write-token gated
- load_handler_from_module mounts a real module file read-only
- health exposes a domains component with evidence; no secrets leak
"""
import json
import time
from datetime import datetime, timezone

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
    monkeypatch.setenv("CICC_DOMAIN_INVOKE_TIMEOUT_S", "2")
    monkeypatch.setenv("CICC_DOMAIN_INVOKE_RETRIES", "1")
    monkeypatch.delenv("RABBITMQ_AMQP_URL", raising=False)
    for k in list(domains._REGISTRY):
        domains.unregister_domain(k)
    yield
    for k in list(domains._REGISTRY):
        domains.unregister_domain(k)
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def ti_handler(payload, task):
    """TI-shaped domain handler (fixture): report list + provenance with
    confidence / freshness / source timestamps."""
    return {
        "result": {"reports": [{"id": "RPT-1", "title": payload.get("query", "x"),
                                 "confidence": 0.8}], "count": 1},
        "provenance": {
            "source": "ti-fixture-osint",
            "produced_at": datetime.now(timezone.utc).isoformat(),
            "confidence": 0.8,
            "freshness_s": 300,
            "input_fingerprint": json.dumps(payload, sort_keys=True)[:64],
            "task_id": getattr(task, "task_id", None),
            "idempotency_key": getattr(task, "idempotency_key", None),
        },
    }


def test_full_lifecycle_and_provenance_passthrough(client):
    assert domains.domain_status("threat_intel") == domains.NOT_MOUNTED
    domains.register_domain("threat_intel", ti_handler, version="0.1-fixture",
                            source_ref="fixture (not a PR)")
    assert domains.domain_status("threat_intel") == domains.AVAILABLE

    r = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                    json={"payload": {"query": "apt29"}, "idempotency_key": "ti-1"}, headers=W)
    assert r.status_code == 201
    body = r.json()
    assert body["state"] == "COMPLETED"
    prov = body["provenance"]
    # provenance preserved end-to-end: source, produced_at, confidence, freshness
    assert prov["source"] == "ti-fixture-osint"
    assert prov["confidence"] == 0.8 and prov["freshness_s"] == 300
    assert prov["idempotency_key"] == "ti-1"
    assert domains.domain_status("threat_intel") == domains.EXECUTION_VERIFIED

    # trace correlation exposes result + provenance
    tr = client.get(f"/api/v1/coordination/tasks/{body['task_id']}/trace", headers=R).json()
    assert tr["state"] == "COMPLETED"
    assert tr["result"]["provenance"]["source"] == "ti-fixture-osint"
    kinds = [e["kind"] for e in tr["events"]]
    assert "domain_result" in kinds and kinds[0] == "created"

    # status endpoint + domains list reflect the evidence
    s = client.get("/api/v1/coordination/domains/threat_intel/status", headers=R).json()
    assert s["status"] == "EXECUTION_VERIFIED" and s["evidence"]["successes"] == 1
    lst = client.get("/api/v1/coordination/domains", headers=R).json()
    assert lst["domains"][0]["status"] == "EXECUTION_VERIFIED"
    assert "EXECUTION_VERIFIED" in lst["states"]

    # duplicate invoke: handler executed exactly once
    calls = {"n": 0}
    orig = domains._REGISTRY["threat_intel"]["handler"]
    def counting(payload, task):
        calls["n"] += 1
        return orig(payload, task)
    domains._REGISTRY["threat_intel"]["handler"] = counting
    r2 = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                     json={"payload": {"query": "apt29"}, "idempotency_key": "ti-1"}, headers=W)
    assert r2.status_code == 200 and r2.json()["duplicate"] is True
    assert calls["n"] == 0  # replayed from the unique key — handler NOT re-executed

    # failure after success -> DEGRADED, sanitized error
    def boom(payload, task):
        raise RuntimeError("db password=hunter2 internal path /x")
    domains._REGISTRY["threat_intel"]["handler"] = boom
    r3 = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                     json={"payload": {}, "idempotency_key": "ti-2"}, headers=W)
    assert r3.status_code == 502
    assert "hunter2" not in r3.text and "/x" not in r3.text  # sanitized
    assert domains.domain_status("threat_intel") == domains.DEGRADED
    s = client.get("/api/v1/coordination/domains/threat_intel/status", headers=R).json()
    assert s["status"] == "DEGRADED" and "hunter2" not in json.dumps(s)

    # deregister -> NOT_MOUNTED
    r4 = client.post("/api/v1/coordination/domains/threat_intel/deregister", headers=W)
    assert r4.status_code == 200 and r4.json()["status"] == "NOT_MOUNTED"
    assert domains.domain_status("threat_intel") == domains.NOT_MOUNTED
    r5 = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                     json={"payload": {}}, headers=W)
    assert r5.status_code == 409 and "domain_not_mounted" in r5.json()["detail"]


def test_retry_same_idempotency_key_then_success(client):
    attempts = {"n": 0}
    def flaky(payload, task):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise ConnectionError("transient")
        return ti_handler(payload, task)
    domains.register_domain("vuln_intel", flaky, version="0.1", source_ref="fixture")
    r = client.post("/api/v1/coordination/domains/vuln_intel/invoke",
                    json={"payload": {"cve": "CVE-2026-1"}, "idempotency_key": "vi-1"}, headers=W)
    assert r.status_code == 201, r.text
    assert attempts["n"] == 2  # retried once
    assert r.json()["provenance"]["idempotency_key"] == "vi-1"  # same key on every attempt
    assert domains.domain_status("vuln_intel") == domains.EXECUTION_VERIFIED


def test_timeout_is_sanitized_and_marks_failed(client, monkeypatch):
    monkeypatch.setenv("CICC_DOMAIN_INVOKE_TIMEOUT_S", "0.3")
    monkeypatch.setenv("CICC_DOMAIN_INVOKE_RETRIES", "0")
    def slow(payload, task):
        time.sleep(2)
        return ti_handler(payload, task)
    domains.register_domain("threat_intel", slow, version="0.1", source_ref="fixture")
    t0 = time.time()
    r = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                    json={"payload": {}, "idempotency_key": "to-1"}, headers=W)
    assert r.status_code == 502 and "timed out" in r.json()["detail"]
    assert time.time() - t0 < 2  # did not wait for the handler
    assert domains.domain_status("threat_intel") == domains.FAILED


def test_invalid_response_422_and_write_token_gate(client):
    domains.register_domain("threat_intel", lambda p, t: {"nope": 1}, version="0.1",
                            source_ref="fixture")
    r = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                    json={"payload": {}}, headers=W)
    assert r.status_code == 422  # domain_invalid (schema violation)
    # write token required for invoke/mount/deregister
    assert client.post("/api/v1/coordination/domains/threat_intel/invoke",
                       json={"payload": {}}).status_code == 401
    assert client.post("/api/v1/coordination/domains/threat_intel/deregister").status_code == 401
    assert client.post("/api/v1/coordination/domains/x/mount",
                       json={"module_path": "/nope.py", "attr": "h",
                             "version": "1", "source_ref": "x"}).status_code == 401


def test_mount_from_module_file_readonly(client, tmp_path):
    mod = tmp_path / "my_ti_domain.py"
    mod.write_text(
        "def handle(payload, task):\n"
        "    return {'result': {'ok': True, 'echo': payload},\n"
        "            'provenance': {'source': 'module-ti', 'produced_at': '2026-11-06T00:00:00+00:00'}}\n")
    before = mod.read_text()
    r = client.post("/api/v1/coordination/domains/threat_intel/mount",
                    json={"module_path": str(mod), "attr": "handle",
                          "version": "1.0", "source_ref": "fixture module (tmp)"}, headers=W)
    assert r.status_code == 201 and r.json()["status"] == domains.AVAILABLE
    assert mod.read_text() == before  # read-only mount: file untouched
    r2 = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                     json={"payload": {"q": 1}, "idempotency_key": "m-1"}, headers=W)
    assert r2.status_code == 201 and r2.json()["result"]["echo"] == {"q": 1}
    assert domains.domain_status("threat_intel") == domains.EXECUTION_VERIFIED
    # missing module -> honest 409, not mounted
    r3 = client.post("/api/v1/coordination/domains/vuln_intel/mount",
                     json={"module_path": "/nonexistent/vi.py", "attr": "h",
                           "version": "1", "source_ref": "x"}, headers=W)
    assert r3.status_code == 409 and "not present" in r3.json()["detail"]
    assert domains.domain_status("vuln_intel") == domains.NOT_MOUNTED


def test_unknown_status_when_stats_missing(client):
    domains._REGISTRY["threat_intel"] = {"kind": "threat_intel", "handler": ti_handler,
                                         "version": "0.1", "source_ref": "fixture",
                                         "mounted_at": "now", "validated": True}
    domains._STATS.pop("threat_intel", None)  # inconsistent state -> UNKNOWN
    assert domains.domain_status("threat_intel") == domains.UNKNOWN
    s = client.get("/api/v1/coordination/domains/threat_intel/status", headers=R).json()
    assert s["status"] == "UNKNOWN"


def test_health_domains_component_evidence_based_and_secret_free(client):
    domains.register_domain("threat_intel", ti_handler, version="0.1", source_ref="fixture")
    client.post("/api/v1/coordination/domains/threat_intel/invoke",
                json={"payload": {}, "idempotency_key": "h-1"}, headers=W)
    h = client.get("/api/v1/coordination/health", headers=R).json()
    comp = next(c for c in h["components"] if c["key"] == "domains")
    assert comp["status"] == "healthy"
    assert comp["domains"]["threat_intel"]["status"] == "EXECUTION_VERIFIED"
    blob = json.dumps(h)
    assert "Bearer" not in blob and "smoke" not in blob and "hunter2" not in blob
    # a domain whose package exists but is NOT mounted must not appear healthy
    assert "vuln_intel" not in comp["domains"]
    s = client.get("/api/v1/coordination/domains/vuln_intel/status", headers=R).json()
    assert s["status"] == "NOT_MOUNTED"
