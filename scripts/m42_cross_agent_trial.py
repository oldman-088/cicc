#!/usr/bin/env python3
"""M42 — CROSS-AGENT INTEGRATION TRIAL v2 (successor of m41; sandbox-labeled).

Evidence classifications (never promoted without verification):
  SANDBOX/FIXTURE        fixture handler mounted in a sandbox API
  SANDBOX/UNMERGED-BRANCH  read-only export of another agent's PR head
  MERGED-APPLICATION     only if the domain package is present in THIS repo
                         checkout AND mounted — auto-detected, reported honestly
  PRODUCTION-VERIFIED    never claimed by this script

Full-path: frontend(BFF read) -> gateway -> domain -> result+provenance ->
persisted trace -> BFF read. Negative cases: unmounted, unauthorized, missing
tenant (safe, unverified-claim semantics), cross-tenant (owner-pending note),
invalid payload, malformed freshness, timeout, retry exhaustion, duplicate,
stale, clock skew, fixture-vs-live label, sanitized errors, recovery, health.

Usage: API=http://127.0.0.1:8000 WEB=http://127.0.0.1:3000 \
       WRITE_TOKEN=smoke-write READ_TOKEN=smoke-read \
       python3 scripts/m42_cross_agent_trial.py [--ti-module PATH] [--vi-package PATH]
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
REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

results = []

FIXTURE = '''
import time as _t
from datetime import datetime, timezone

def handle(payload, task):
    mode = payload.get("mode", "ok")
    if mode == "slow":
        _t.sleep(8)
    if mode == "always_fail":
        raise RuntimeError("fixture failure secret=hunter2")
    if mode == "skewed":
        produced = datetime.now(timezone.utc).timestamp() + 3600
        pa = datetime.fromtimestamp(produced, timezone.utc).isoformat()
        fresh = None
    else:
        pa = datetime.now(timezone.utc).isoformat()
        fresh = payload.get("freshness_s", 5)
    prov = {"source": "m42-fixture", "produced_at": pa, "confidence": 0.7,
            "experimental_label": "EXPERIMENTAL_DEMO_DATA_ONLY",
            "idempotency_key": getattr(task, "idempotency_key", None)}
    if fresh is not None:
        prov["freshness_s"] = fresh
    return {"result": {"reports": [{"id": "M42", "mode": mode}], "count": 1}, "provenance": prov}
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
    print(f"== M42 CROSS-AGENT TRIAL v2 @ {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} run={run} ==")

    # MERGED-APPLICATION auto-detection (honest)
    ti_merged = os.path.exists(os.path.join(REPO, "apps", "threat_intelligence", "api.py"))
    vi_merged = os.path.isdir(os.path.join(REPO, "packages", "vuln_intel", "vuln_intel"))
    print(f"MERGED-APPLICATION detection: TI package in this checkout: {ti_merged}; VI package: {vi_merged} "
          f"(both False while PR #3/#8 are unmerged -> merged-app tests NOT RUN, not claimed)")

    fx = tempfile.NamedTemporaryFile("w", suffix="_m42_fixture.py", delete=False)
    fx.write(FIXTURE)
    fx.close()
    for k in ("threat_intel", "vuln_intel"):
        call(API, "POST", f"/api/v1/coordination/domains/{k}/deregister", None, W)
    st, m, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/mount",
                    {"module_path": fx.name, "attr": "handle", "version": "m42-fixture",
                     "source_ref": "M42 sandbox fixture"}, W)
    check("mount fixture", st == 201, f"st={st}")

    st, inv, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                      {"payload": {"mode": "ok"}, "idempotency_key": f"{run}-ok", "tenant_id": "tenant-a"}, W)
    p = inv.get("provenance", {})
    check("success + provenance + freshness + unverified tenant claim recorded",
          st == 201 and p.get("source") == "m42-fixture" and inv.get("stale") is False
          and inv.get("freshness", {}).get("basis") == "freshness_s", f"st={st}")
    tid = inv.get("task_id")
    tr = call(API, "GET", f"/api/v1/coordination/tasks/{tid}/trace", token=R)[1]
    check("trace persisted + claimed_tenant is UNVERIFIED + EXPERIMENTAL label kept",
          tr.get("state") == "COMPLETED"
          and any(e.get("kind") == "claimed_tenant" and "unverified" in (e.get("detail") or "").lower()
                  for e in tr.get("events", []))
          and tr.get("result", {}).get("provenance", {}).get("experimental_label") == "EXPERIMENTAL_DEMO_DATA_ONLY")

    st, dup, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                      {"payload": {"mode": "ok"}, "idempotency_key": f"{run}-ok"}, W)
    check("duplicate key -> 200", st == 200 and dup.get("duplicate") is True, f"st={st}")

    st, nm, _ = call(API, "POST", "/api/v1/coordination/domains/vuln_intel/invoke", {"payload": {}}, W)
    check("unmounted -> 409 domain_not_mounted", st == 409, f"st={st}")

    st, _, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke", {"payload": {}})
    check("unauthorized (no token) -> 401/403", st in (401, 403), f"st={st}")

    st, bw, _ = call(WEB, "POST", "/api/v1/coordination/domains/threat_intel/invoke", {"payload": {}})
    check("BFF write boundary: browser domain invoke blocked", st in (403, 404, 405), f"st={st}")

    # missing tenant: safe, no claim
    st, nt, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                     {"payload": {"mode": "ok"}, "idempotency_key": f"{run}-nt"}, W)
    tr2 = call(API, "GET", f"/api/v1/coordination/tasks/{nt.get('task_id')}/trace", token=R)[1]
    check("missing tenant -> safe, no claimed_tenant event, no crash",
          st == 201 and not any(e.get("kind") == "claimed_tenant" for e in tr2.get("events", [])), f"st={st}")
    print("[NOTE] cross-tenant access-denial enforcement: PENDING owner (tenant isolation decision) — "
          "not claimed here; status/diagnostics expose no per-tenant fields meanwhile")

    st, to, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                     {"payload": {"mode": "slow"}, "idempotency_key": f"{run}-slow"}, W)
    check("timeout -> 502 sanitized", st == 502 and "timed out" in str(to), f"st={st}")

    st, re_, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                      {"payload": {"mode": "always_fail"}, "idempotency_key": f"{run}-rf"}, W)
    check("retry exhaustion -> 502 sanitized (no secret)", st == 502 and "hunter2" not in json.dumps(re_), f"st={st}")

    st, sd, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                     {"payload": {"mode": "ok", "freshness_s": 999999}, "idempotency_key": f"{run}-st"}, W)
    check("stale -> 201 stale=true basis=freshness_s", st == 201 and sd.get("stale") is True, f"st={st}")

    st, sk, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                     {"payload": {"mode": "skewed"}, "idempotency_key": f"{run}-sk"}, W)
    check("clock skew -> stale=false but clock_skew_s>0 (never silently fresh)",
          st == 201 and sk.get("stale") is False and sk.get("freshness", {}).get("clock_skew_s", 0) > 3000,
          f"skew={sk.get('freshness', {}).get('clock_skew_s')}")

    st, rc, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                     {"payload": {"mode": "ok"}, "idempotency_key": f"{run}-rec"}, W)
    _, sf, _ = call(API, "GET", "/api/v1/coordination/domains/threat_intel/status", token=R)
    check("recovery -> EXECUTION_VERIFIED, last_stale reset",
          st == 201 and sf.get("status") == "EXECUTION_VERIFIED" and sf["evidence"]["last_stale"] is False)

    d = call(API, "GET", "/api/v1/coordination/diagnostics", token=R)[1]
    check("diagnostics: db_ok + domains + no secrets", d.get("db_ok") is True
          and "threat_intel" in d.get("domain_statuses", {}) and "Bearer" not in json.dumps(d))

    h = call(API, "GET", "/api/v1/coordination/health", token=R)[1]
    comp = next((c for c in h.get("components", []) if c.get("key") == "domains"), {})
    check("health domains component accurate", comp.get("domains", {}).get("threat_intel", {}).get("status")
          == "EXECUTION_VERIFIED" and "hunter2" not in json.dumps(h))

    st1, d1, _ = call(WEB, "GET", "/api/v1/coordination/domains")
    st3, t3, _ = call(WEB, "GET", f"/api/v1/coordination/tasks/{tid}/trace")
    st4, l4, _ = call(WEB, "GET", "/api/v1/coordination/tasks?kind=threat_intel&limit=50")
    check("frontend read path via BFF (domains/trace/kind-filter)",
          st1 == 200 and st3 == 200 and st4 == 200 and t3.get("state") == "COMPLETED"
          and any(t.get("task_id") == tid for t in l4.get("tasks", [])), f"{st1},{st3},{st4}")

    # real unmerged-branch modules (read-only exports)
    if args.ti_module and os.path.exists(args.ti_module):
        api_root = os.path.join(REPO, "apps", "api")
        wr = tempfile.NamedTemporaryFile("w", suffix="_m42_ti.py", delete=False)
        wr.write(f"import sys\nsys.path.insert(0, {api_root!r})\n"
                 "from app.coordination.domain_adapters.threat_intel_adapter import make_handler\n"
                 f"handle = make_handler({args.ti_module!r})\n")
        wr.close()
        call(API, "POST", "/api/v1/coordination/domains/threat_intel/deregister", None, W)
        st, m, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/mount",
                        {"module_path": wr.name, "attr": "handle", "version": "PR#3-export",
                         "source_ref": "PR #3 head read-only export (unmerged)"}, W)
        st2, inv2, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                            {"payload": {"query": "apt29"}, "idempotency_key": f"{run}-rti"}, W)
        p2 = inv2.get("provenance", {})
        check("REAL unmerged TI module via gateway (EXPERIMENTAL label preserved)",
              st == 201 and st2 == 201 and str(p2.get("source", "")).startswith("threat_intelligence_api_v1")
              and p2.get("experimental_label") == "EXPERIMENTAL_DEMO_DATA_ONLY",
              f"mount={st} invoke={st2}", label="SANDBOX/UNMERGED-BRANCH")
        os.unlink(wr.name)
    if args.vi_package and os.path.isdir(os.path.join(args.vi_package, "vuln_intel")):
        api_root = os.path.join(REPO, "apps", "api")
        wr = tempfile.NamedTemporaryFile("w", suffix="_m42_vi.py", delete=False)
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
                             "idempotency_key": f"{run}-rvi"}, W)
        p2 = inv2.get("provenance", {})
        check("REAL unmerged VI package via gateway (data_origin honest)",
              st == 201 and st2 == 201 and inv2.get("result", {}).get("count") == 1
              and str(p2.get("data_origin", "")).startswith("non-live"),
              f"mount={st} invoke={st2}", label="SANDBOX/UNMERGED-BRANCH")
        os.unlink(wr.name)

    passed = sum(1 for _, ok in results if ok)
    print(f"\n== M42 TRIAL v2 RESULT: {passed}/{len(results)} PASS @ "
          f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} ==")
    print("   Evidence classes used: SANDBOX/FIXTURE, SANDBOX/UNMERGED-BRANCH. "
          f"MERGED-APPLICATION: {'RUN' if (ti_merged or vi_merged) else 'NOT RUN (PRs unmerged)'}; "
          "PRODUCTION-VERIFIED: never claimed.")
    os.unlink(fx.name)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
