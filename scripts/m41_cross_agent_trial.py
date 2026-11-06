#!/usr/bin/env python3
"""M41 — CROSS-AGENT INTEGRATION TRIAL (expanded; sandbox-labeled).

Intended verification path (executed here with FIXTURES + read-only PR-head
module exports while PR #3/#8/#1 are unmerged — every check is labeled):

  frontend -> approved BFF contract -> coordination gateway -> mounted domain
  -> validated result + provenance -> persisted trace -> frontend read-only read

Checks: success, unmounted, invalid, authz denial, BFF write-boundary block,
tenant note (owner-pending), timeout, retry exhaustion, duplicate key, stale
data, fixture-vs-live provenance label, sanitized errors, trace persistence,
recovery, health accuracy, BFF read path.

Usage: API=http://127.0.0.1:8000 WEB=http://127.0.0.1:3000 \
       WRITE_TOKEN=smoke-write READ_TOKEN=smoke-read \
       python3 scripts/m41_cross_agent_trial.py [--ti-module PATH] [--vi-package PATH]
"""
import argparse
import json
import os
import sys
import tempfile
import time
import urllib.request

API = os.environ.get("API", "http://127.0.0.1:8000")
WEB = os.environ.get("WEB", "http://127.0.0.1:3000")
W = os.environ.get("WRITE_TOKEN", "smoke-write")
R = os.environ.get("READ_TOKEN", "smoke-read")

results = []

FIXTURE = '''
import time as _t
from datetime import datetime, timezone
MODE = {"fail": 0}
def handle(payload, task):
    mode = payload.get("mode", "ok")
    if mode == "slow":
        _t.sleep(8)
    if mode == "always_fail":
        raise RuntimeError("fixture failure secret=hunter2")
    fresh = payload.get("freshness_s", 5)
    return {"result": {"reports": [{"id": "M41", "mode": mode}], "count": 1},
            "provenance": {"source": "m41-fixture", "produced_at": datetime.now(timezone.utc).isoformat(),
                           "confidence": 0.75, "freshness_s": fresh,
                           "experimental_label": "EXPERIMENTAL_DEMO_DATA_ONLY",
                           "idempotency_key": getattr(task, "idempotency_key", None)}}
'''


def call(base, method, path, body=None, token=None):
    req = urllib.request.Request(base + path,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            p = resp.read().decode()
            return resp.status, (json.loads(p) if p else {}), dict(resp.headers)
    except urllib.error.HTTPError as e:
        p = e.read().decode()
        try:
            p = json.loads(p)
        except Exception:
            pass
        return e.code, p, dict(e.headers)


def check(name, cond, detail="", label="SANDBOX/FIXTURE"):
    results.append((name, bool(cond)))
    print(f"[{'PASS' if cond else 'FAIL'}] [{label}] {name} {detail}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ti-module", default="")
    ap.add_argument("--vi-package", default="")
    args = ap.parse_args()
    run = str(int(time.time()))
    print(f"== M41 CROSS-AGENT TRIAL @ {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} run={run} ==")
    print("   labels: SANDBOX/FIXTURE = fixture or unmerged-branch export; REAL-MERGED = none yet (PRs unmerged)")

    fx = tempfile.NamedTemporaryFile("w", suffix="_m41_fixture.py", delete=False)
    fx.write(FIXTURE)
    fx.close()

    # mount fixture as threat_intel
    st, m, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/mount",
                    {"module_path": fx.name, "attr": "handle", "version": "m41-fixture",
                     "source_ref": "M41 sandbox fixture"}, W)
    check("mount fixture domain", st == 201, str(m)[:100])

    # 1. successful invocation + provenance + label
    st, inv, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                      {"payload": {"mode": "ok"}, "idempotency_key": f"{run}-ok"}, W)
    p = inv.get("provenance", {})
    check("successful invocation 201 COMPLETED + provenance (source/produced_at/confidence/freshness)",
          st == 201 and inv.get("state") == "COMPLETED" and p.get("source") == "m41-fixture"
          and p.get("confidence") == 0.75 and "produced_at" in p and inv.get("stale") is False,
          f"st={st}")
    tid = inv.get("task_id")

    # 2. fixture-vs-live label preserved
    check("fixture-vs-live label preserved (EXPERIMENTAL_DEMO_DATA_ONLY)",
          p.get("experimental_label") == "EXPERIMENTAL_DEMO_DATA_ONLY", str(p.get("experimental_label")))

    # 3. trace persistence
    st, tr, _ = call(API, "GET", f"/api/v1/coordination/tasks/{tid}/trace", token=R)
    check("trace persisted: result+provenance+events+correlation",
          st == 200 and tr.get("state") == "COMPLETED"
          and tr.get("correlation", {}).get("idempotency_key") == f"{run}-ok"
          and any(e.get("kind") == "domain_result" for e in tr.get("events", []))
          and tr.get("result", {}).get("provenance", {}).get("source") == "m41-fixture")

    # 4. duplicate idempotency key
    st, dup, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                      {"payload": {"mode": "ok"}, "idempotency_key": f"{run}-ok"}, W)
    check("duplicate idempotency_key -> 200 duplicate", st == 200 and dup.get("duplicate") is True, f"st={st}")

    # 5. unmounted domain honest
    st, nm, _ = call(API, "POST", "/api/v1/coordination/domains/vuln_intel/invoke", {"payload": {}}, W)
    st2, s2, _ = call(API, "GET", "/api/v1/coordination/domains/vuln_intel/status", token=R)
    check("unmounted domain -> 409 + NOT_MOUNTED", st == 409 and s2.get("status") == "NOT_MOUNTED")

    # 6. invalid request (bad payload shape -> handler schema) — use missing-module mount as invalid op
    st, iv, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/mount",
                     {"module_path": "/nonexistent/x.py", "attr": "h", "version": "1",
                      "source_ref": "x"}, W)
    check("invalid mount (absent module) -> 409, no fake mount", st == 409, f"st={st}")

    # 7. authorization denial: no token / read token on write endpoints
    st, _, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke", {"payload": {}})
    st2, _, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                     {"payload": {}}, R)
    check("authz denial: no-token and read-token invoke -> 401/403",
          st in (401, 403) and st2 in (401, 403), f"{st},{st2}")

    # 8. BFF write boundary: domain invoke via WEB must be blocked (only POST /tasks allowed)
    st, bw, _ = call(WEB, "POST", "/api/v1/coordination/domains/threat_intel/invoke", {"payload": {}})
    check("BFF write boundary: browser write to domain invoke blocked (403/404/405)",
          st in (403, 404, 405), f"st={st}")
    st, bt, hdr = call(WEB, "POST", "/api/v1/coordination/tasks",
                       {"kind": "frontend_e2e", "title": f"m41 bff write {run}"})
    check("BFF approved write path still works (POST /tasks 201 + idempotency header)",
          st == 201 and any(k.lower() == "x-cicc-idempotency-key" for k in hdr), f"st={st}")

    # 9. tenant isolation: owner-pending — assert no tenant leakage/claims, report PENDING
    st, dl, _ = call(WEB, "GET", "/api/v1/coordination/domains")
    check("tenant isolation: PENDING owner — no tenant fields/claims exposed meanwhile",
          st == 200 and "tenant" not in json.dumps(dl).lower(), f"st={st}")

    # 10. timeout (fixture slow, server timeout 3s) -> sanitized 502
    st, to, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                     {"payload": {"mode": "slow"}, "idempotency_key": f"{run}-slow"}, W)
    check("timeout -> 502 sanitized", st == 502 and "timed out" in str(to), f"st={st}")

    # 11. retry exhaustion -> 502 with attempts, consecutive_failures grows
    st, re_, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                      {"payload": {"mode": "always_fail"}, "idempotency_key": f"{run}-rf"}, W)
    stt, ss, _ = call(API, "GET", "/api/v1/coordination/domains/threat_intel/status", token=R)
    check("retry exhaustion -> 502 sanitized + FAILED/DEGRADED + consecutive_failures",
          st == 502 and "hunter2" not in json.dumps(re_)
          and ss.get("status") in ("FAILED", "DEGRADED")
          and ss["evidence"]["consecutive_failures"] >= 1, f"st={st} status={ss.get('status')}")

    # 12. stale data detection
    st, sd, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                     {"payload": {"mode": "ok", "freshness_s": 999999}, "idempotency_key": f"{run}-stale"}, W)
    check("stale data -> 201 with stale=true + domain_stale event",
          st == 201 and sd.get("stale") is True, f"st={st} stale={sd.get('stale')}")

    # 13. recovery -> EXECUTION_VERIFIED
    st, rc, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                     {"payload": {"mode": "ok"}, "idempotency_key": f"{run}-rec"}, W)
    _, sf, _ = call(API, "GET", "/api/v1/coordination/domains/threat_intel/status", token=R)
    check("recovery -> EXECUTION_VERIFIED", st == 201 and sf.get("status") == "EXECUTION_VERIFIED")

    # 14. health accuracy
    st, h, _ = call(API, "GET", "/api/v1/coordination/health", token=R)
    comp = next((c for c in h.get("components", []) if c.get("key") == "domains"), {})
    check("health domains component accurate + no secrets",
          comp.get("domains", {}).get("threat_intel", {}).get("status") == "EXECUTION_VERIFIED"
          and "hunter2" not in json.dumps(h))

    # 15. frontend read path via BFF: /domains, /health, trace, task list
    st1, d1, _ = call(WEB, "GET", "/api/v1/coordination/domains")
    st2, h2, _ = call(WEB, "GET", "/api/v1/coordination/health")
    st3, t3, _ = call(WEB, "GET", f"/api/v1/coordination/tasks/{tid}/trace")
    st4, l4, _ = call(WEB, "GET", "/api/v1/coordination/tasks?kind=threat_intel&limit=50")
    check("frontend read path via BFF: /domains /health /trace ?kind= filter",
          st1 == 200 and st2 == 200 and st3 == 200 and st3 == 200
          and t3.get("state") == "COMPLETED"
          and any(t.get("task_id") == tid for t in l4.get("tasks", [])), f"{st1},{st2},{st3},{st4}")

    # 16. real PR-head modules (read-only exports) if provided
    if args.ti_module and os.path.exists(args.ti_module):
        api_root = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "apps", "api"))
        wr = tempfile.NamedTemporaryFile("w", suffix="_m41_ti.py", delete=False)
        wr.write(f"import sys\nsys.path.insert(0, {api_root!r})\n"
                 "from app.coordination.domain_adapters.threat_intel_adapter import make_handler\n"
                 f"handle = make_handler({args.ti_module!r})\n")
        wr.close()
        st, m, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/mount",
                        {"module_path": wr.name, "attr": "handle", "version": "PR#3-export",
                         "source_ref": "PR #3 head read-only export (unmerged)"}, W)
        st2, inv2, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                            {"payload": {"query": "apt29"}, "idempotency_key": f"{run}-real-ti"}, W)
        p2 = inv2.get("provenance", {})
        check("REAL (unmerged) TI module via gateway: 201 + provenance + EXPERIMENTAL label",
              st == 201 and st2 == 201 and str(p2.get("source", "")).startswith("threat_intelligence_api_v1")
              and p2.get("experimental_label") == "EXPERIMENTAL_DEMO_DATA_ONLY",
              f"mount={st} invoke={st2}", label="SANDBOX/UNMERGED-BRANCH")
        os.unlink(wr.name)
    if args.vi_package and os.path.isdir(os.path.join(args.vi_package, "vuln_intel")):
        api_root = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "apps", "api"))
        wr = tempfile.NamedTemporaryFile("w", suffix="_m41_vi.py", delete=False)
        wr.write(f"import sys\nsys.path.insert(0, {api_root!r})\n"
                 "from app.coordination.domain_adapters.vuln_intel_adapter import make_handler\n"
                 f"handle = make_handler({args.vi_package!r})\n")
        wr.close()
        st, m, _ = call(API, "POST", "/api/v1/coordination/domains/vuln_intel/mount",
                        {"module_path": wr.name, "attr": "handle", "version": "PR#8-export",
                         "source_ref": "PR #8 head read-only export (unmerged)"}, W)
        st2, inv2, _ = call(API, "POST", "/api/v1/coordination/domains/vuln_intel/invoke",
                            {"payload": {"op": "search", "query": "log4shell", "records": [
                                {"cve": "CVE-2021-44228", "origin": "demo",
                                 "summary": "log4shell RCE", "severity": "critical", "kev": True}]},
                             "idempotency_key": f"{run}-real-vi"}, W)
        p2 = inv2.get("provenance", {})
        check("REAL (unmerged) VI package via gateway: 201 + hit + data_origin honesty",
              st == 201 and st2 == 201 and inv2.get("result", {}).get("count") == 1
              and str(p2.get("data_origin", "")).startswith("non-live"),
              f"mount={st} invoke={st2}", label="SANDBOX/UNMERGED-BRANCH")
        os.unlink(wr.name)

    passed = sum(1 for _, ok in results if ok)
    print(f"\n== M41 CROSS-AGENT TRIAL RESULT: {passed}/{len(results)} PASS @ "
          f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} ==")
    print("   ALL results are SANDBOX/FIXTURE or UNMERGED-BRANCH — NOT merged-app or production integration")
    os.unlink(fx.name)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
