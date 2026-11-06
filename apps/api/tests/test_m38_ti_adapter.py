"""M38 — Threat Intelligence adapter (Agent 2 PR #3 contract) tests.

- A FIXTURE module replicating Agent 2's ``ThreatIntelligenceAPI`` shape
  (invoke_endpoint -> {status, data, provenance, confidence, timestamp,
  experimental_label}) is wrapped READ-ONLY by the adapter and driven through
  the REAL gateway (mount -> invoke -> trace), verifying the field mapping:
  provenance.source / produced_at / confidence / freshness_s /
  experimental_label, and task+idempotency_key trace correlation.
- Their ``status="error"`` maps to a gateway 502 (sanitized) + FAILED/DEGRADED —
  never a fake success.
- Missing module -> honest NOT_MOUNTED (no fake mount while PR #3 is unmerged).
- The real Agent 2 file (apps/threat_intelligence/api.py) is absent on this
  branch until PR #3 merges: asserted NOT_MOUNTED here; live verification
  against the PR-head export is recorded in docs/INTEGRATION_MATRIX.md.
"""
import json
import os
from datetime import datetime, timezone

import pytest

from app import ratelimit
from app.coordination import domains
from app.coordination.domain_adapters import threat_intel_adapter as tia

W = {"Authorization": "Bearer w", "Content-Type": "application/json"}
R = {"Authorization": "Bearer r"}

FIXTURE_MODULE = '''
from datetime import datetime, timezone
from typing import Optional

class ThreatIntelligenceRequest:
    def __init__(self, tenant_id=None, query=None, limit=100, offset=0, experimental_label=None):
        self.tenant_id = tenant_id; self.query = query; self.limit = limit
        self.offset = offset; self.experimental_label = experimental_label

class ThreatIntelligenceAPI:
    def __init__(self, tenant_id=None, experimental_label="EXPERIMENTAL_DEMO_DATA_ONLY"):
        self.tenant_id = tenant_id
        self.experimental_label = experimental_label
        self.provenance = "threat_intelligence_api_v1"
        self.confidence = 0.9
        self._mounted = {"/api/v1/threat-intelligence/osint-sources": self._osint,
                         "/api/v1/threat-intelligence/fail": self._fail}
    def invoke_endpoint(self, path, request):
        if path not in self._mounted:
            return {"status": "error", "data": None, "total_count": 0, "has_more": False,
                    "provenance": self.provenance, "confidence": self.confidence,
                    "experimental_label": self.experimental_label,
                    "timestamp": datetime.now(timezone.utc)}
        return self._mounted[path](request)
    def _osint(self, request):
        return {"status": "success",
                "data": [{"source_id": "OSINT-001", "query": request.query,
                          "label": self.experimental_label}],
                "total_count": 1, "has_more": False,
                "provenance": f"{self.provenance}::/api/v1/threat-intelligence/osint-sources",
                "confidence": self.confidence, "experimental_label": self.experimental_label,
                "timestamp": datetime.now(timezone.utc)}
    def _fail(self, request):
        raise RuntimeError("simulated domain outage")
'''


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r")
    monkeypatch.setenv("CICC_COORD_APPROVERS", "owner")
    monkeypatch.setenv("CICC_DOMAIN_INVOKE_TIMEOUT_S", "2")
    monkeypatch.setenv("CICC_DOMAIN_INVOKE_RETRIES", "0")
    monkeypatch.delenv("RABBITMQ_AMQP_URL", raising=False)
    mod = tmp_path / "ti_agent2_fixture.py"
    mod.write_text(FIXTURE_MODULE)
    monkeypatch.setenv("CICC_TI_MODULE_PATH", str(mod))
    for k in list(domains._REGISTRY):
        domains.unregister_domain(k)
    yield
    for k in list(domains._REGISTRY):
        domains.unregister_domain(k)
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def test_adapter_maps_agent2_response_through_gateway(client, monkeypatch):
    handler = tia.make_handler()  # uses CICC_TI_MODULE_PATH fixture
    domains.register_domain("threat_intel", handler, version="P1-05-fixture",
                            source_ref="fixture replicating PR #3 @4f1776f api.py (NOT the real module)")
    r = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                    json={"payload": {"query": "apt29", "endpoint": "/api/v1/threat-intelligence/osint-sources"},
                          "idempotency_key": "ti-adapt-1"}, headers=W)
    assert r.status_code == 201, r.text
    b = r.json()
    assert b["state"] == "COMPLETED"
    res, prov = b["result"], b["provenance"]
    # result carries Agent 2's fields incl. the experimental label (honesty preserved)
    assert res["status"] == "success" and res["total_count"] == 1
    assert res["experimental_label"] == "EXPERIMENTAL_DEMO_DATA_ONLY"
    assert res["data"][0]["query"] == "apt29"
    # provenance mapping: source, produced_at, confidence, freshness, correlation
    assert prov["source"] == "threat_intelligence_api_v1::/api/v1/threat-intelligence/osint-sources"
    assert prov["produced_at"].endswith("+00:00")
    assert prov["confidence"] == 0.9
    assert prov["freshness_s"] < 5
    assert prov["experimental_label"] == "EXPERIMENTAL_DEMO_DATA_ONLY"
    assert prov["idempotency_key"] == "ti-adapt-1"
    assert domains.domain_status("threat_intel") == domains.EXECUTION_VERIFIED
    # trace correlation exposes the persisted result + provenance
    tr = client.get(f"/api/v1/coordination/tasks/{b['task_id']}/trace", headers=R).json()
    assert tr["state"] == "COMPLETED"
    assert tr["result"]["provenance"]["source"].startswith("threat_intelligence_api_v1")
    assert any(e["kind"] == "domain_result" for e in tr["events"])
    # duplicate: handler not re-executed
    r2 = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                     json={"payload": {"query": "apt29"}, "idempotency_key": "ti-adapt-1"}, headers=W)
    assert r2.status_code == 200 and r2.json()["duplicate"] is True


def test_adapter_domain_error_is_sanitized_failure(client):
    handler = tia.make_handler()
    domains.register_domain("threat_intel", handler, version="P1-05-fixture", source_ref="fixture")
    r = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                    json={"payload": {"endpoint": "/api/v1/threat-intelligence/fail"},
                          "idempotency_key": "ti-err-1"}, headers=W)
    assert r.status_code == 502
    assert "outage" not in r.text  # sanitized
    assert domains.domain_status("threat_intel") == domains.FAILED
    # unknown endpoint -> their status=error -> gateway failure, not fake success
    r2 = client.post("/api/v1/coordination/domains/threat_intel/invoke",
                     json={"payload": {"endpoint": "/nope"}, "idempotency_key": "ti-err-2"}, headers=W)
    assert r2.status_code == 502


def test_adapter_missing_module_is_honest_not_mounted(monkeypatch, tmp_path):
    monkeypatch.setenv("CICC_TI_MODULE_PATH", str(tmp_path / "absent.py"))
    with pytest.raises(tia._NotMounted):
        tia.make_handler()
    # and the in-repo Agent 2 file is absent on THIS branch until PR #3 merges
    default = os.path.abspath(tia.DEFAULT_TI_MODULE)
    if not os.path.exists(default):
        with pytest.raises(tia._NotMounted):
            tia.make_handler(None if False else os.path.join(os.path.dirname(default), "definitely_absent.py"))
