"""M39 — Vulnerability Intelligence adapter preparation (Replacement Agent 3).

- Fixture package replicating the PR #8 `packages/vuln_intel` entry points
  (search.search_records / health.build_health_report / schema.NormalizedVulnerability,
  SourceState, utcnow) is wrapped READ-ONLY by the VI adapter and driven through
  the REAL gateway: mount -> invoke op=search / op=health -> provenance mapping
  (source=vuln_intel::<op>, produced_at, confidence, package path, task+key).
- Missing package (PR #8/#1 unmerged on this branch) -> honest _NotMounted.
- Real PR #8-head package verification is done live via codeload export
  (recorded in docs/INTEGRATION_MATRIX.md); NOT a production mount.
"""
import os
from datetime import datetime, timezone

import pytest

from app import ratelimit
from app.coordination import domains
from app.coordination.domain_adapters import vuln_intel_adapter as via

W = {"Authorization": "Bearer w", "Content-Type": "application/json"}
R = {"Authorization": "Bearer r"}

SCHEMA = '''
from dataclasses import dataclass, field
from datetime import datetime, timezone

def utcnow():
    return datetime.now(timezone.utc)

class _Origin(str):
    @property
    def is_real(self):
        return self == "live"

@dataclass
class NormalizedVulnerability:
    cve: str = ""
    origin: object = "demo"
    severity: str = "UNKNOWN"
    kev: object = None
    summary: str = ""
    details: str = ""
    aliases: tuple = ()

@dataclass
class SourceState:
    kind: str = "nvd"
    ok: bool = True
'''
SEARCH = '''
def _tokens(text):
    return {t for t in (text or "").lower().split() if t}

class SearchHit:
    def __init__(self, record, score, matched_fields):
        self.record = record; self.score = score; self.matched_fields = matched_fields
    def as_dict(self):
        return {"cve": self.record.cve, "score": self.score,
                "severity": self.record.severity, "kev": self.record.kev,
                "matched_fields": list(self.matched_fields)}

def search_records(records, query, *, kev_only=False, limit=100):
    terms = _tokens(query)
    hits = []
    for r in records:
        if kev_only and r.kev is not True:
            continue
        text = _tokens(r.cve + " " + r.summary)
        m = terms & text
        if m:
            hits.append(SearchHit(r, 100 if terms & _tokens(r.cve) else 10, tuple(sorted(m))))
    hits.sort(key=lambda h: (-h.score, h.record.cve))
    return tuple(hits[:limit])
'''
HEALTH = '''
from .schema import utcnow

def build_health_report(states, *, kev_age=None, epss_available=False, now=None, required_sources=("nvd", "cisa-kev")):
    now = now or utcnow()
    sources = [{"kind": s.kind, "ok": s.ok} for s in states]
    ready = all(s.ok for s in states) and bool(states)
    return {"readiness": "READY" if ready else "NOT_READY", "checked_at": now.isoformat(),
            "sources": sources, "warnings": [] if epss_available else ["EPSS provider unavailable"]}
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
    pkg = tmp_path / "pkg"
    (pkg / "vuln_intel").mkdir(parents=True)
    (pkg / "vuln_intel" / "__init__.py").write_text("")
    (pkg / "vuln_intel" / "schema.py").write_text(SCHEMA)
    (pkg / "vuln_intel" / "search.py").write_text(SEARCH)
    (pkg / "vuln_intel" / "health.py").write_text(HEALTH)
    monkeypatch.setenv("CICC_VI_PACKAGE_PATH", str(pkg))
    monkeypatch.syspath_prepend(str(pkg))
    for mod in [m for m in list(__import__("sys").modules) if m.startswith("vuln_intel")]:
        del __import__("sys").modules[mod]
    for k in list(domains._REGISTRY):
        domains.unregister_domain(k)
    yield str(pkg)
    for k in list(domains._REGISTRY):
        domains.unregister_domain(k)
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def test_vi_adapter_search_and_health_through_gateway(client, _clean):
    handler = via.make_handler()  # uses CICC_VI_PACKAGE_PATH fixture
    domains.register_domain("vuln_intel", handler, version="fixture-pkg",
                            source_ref="fixture replicating PR #8 package layout (NOT the real package)")
    recs = [{"cve": "CVE-2026-0001", "origin": "demo", "severity": "CRITICAL", "kev": True,
             "summary": "log4shell remote code execution"}]
    r = client.post("/api/v1/coordination/domains/vuln_intel/invoke",
                    json={"payload": {"op": "search", "query": "log4shell", "records": recs},
                          "idempotency_key": "vi-s1"}, headers=W)
    assert r.status_code == 201, r.text
    b = r.json()
    assert b["result"]["count"] == 1 and b["result"]["hits"][0]["cve"] == "CVE-2026-0001"
    prov = b["provenance"]
    assert prov["source"] == "vuln_intel::search"
    assert prov["produced_at"].endswith("+00:00")
    assert prov["confidence"] == 1.0
    assert prov["package_path"].endswith("pkg")
    assert prov["data_origin"].startswith("non-live")  # fixture origin preserved honestly
    assert prov["idempotency_key"] == "vi-s1"
    assert domains.domain_status("vuln_intel") == domains.EXECUTION_VERIFIED

    r2 = client.post("/api/v1/coordination/domains/vuln_intel/invoke",
                     json={"payload": {"op": "health", "states": [{"kind": "nvd", "ok": True}],
                                       "epss_available": True},
                           "idempotency_key": "vi-h1"}, headers=W)
    assert r2.status_code == 201
    assert r2.json()["result"]["readiness"] == "READY"
    assert r2.json()["provenance"]["source"] == "vuln_intel::health"

    # duplicate: handler once
    r3 = client.post("/api/v1/coordination/domains/vuln_intel/invoke",
                     json={"payload": {"op": "search", "query": "x", "records": []},
                           "idempotency_key": "vi-s1"}, headers=W)
    assert r3.status_code == 200 and r3.json()["duplicate"] is True

    # unknown op -> sanitized 422
    r4 = client.post("/api/v1/coordination/domains/vuln_intel/invoke",
                     json={"payload": {"op": "rm-rf"}, "idempotency_key": "vi-bad"}, headers=W)
    assert r4.status_code == 422


def test_vi_adapter_missing_package_honest(monkeypatch, tmp_path):
    monkeypatch.setenv("CICC_VI_PACKAGE_PATH", str(tmp_path / "absent"))
    with pytest.raises(via._NotMounted):
        via.make_handler()
    # default in-repo packages/vuln_intel is absent on THIS branch until PR #8/#1 merge
    if not os.path.isdir(os.path.abspath(via.DEFAULT_VI_PACKAGE_PARENT) + "/vuln_intel"):
        with pytest.raises(via._NotMounted):
            via.make_handler(None)
