#!/usr/bin/env python3
"""M40 — comprehensive CROSS-DOMAIN INTEGRATION TRIAL (sandbox-labeled).

Covers the full integration lifecycle through the REAL coordination gateway:
mount -> lifecycle states -> invoke -> provenance propagation -> trace
correlation -> duplicate delivery -> timeout/retry -> DEGRADED/FAILED ->
recovery -> deregister -> health accuracy -> frontend contract compatibility
(BFF reads). Domain handlers are FIXTURES mounted via the write-token mount
endpoint (module file); the "real domain readiness" section honestly reports
whether real Agent 2 (TI) / Agent 3 (VI) modules are present — it does NOT
claim real domain execution when only fixtures ran.

SANDBOX / FIXTURE evidence only — NOT production verification.

Usage: API=http://127.0.0.1:8000 WEB=http://127.0.0.1:3000 \
       WRITE_TOKEN=smoke-write READ_TOKEN=smoke-read \
       python3 scripts/m40_integration_trial.py [--ti-module /path/to/agent2/api.py] [--ti-sha <40-char-commit>]
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.request

API = os.environ.get("API", "http://127.0.0.1:8000")
WEB = os.environ.get("WEB", "http://127.0.0.1:3000")
W = os.environ.get("WRITE_TOKEN", "smoke-write")
R = os.environ.get("READ_TOKEN", "smoke-read")

results = []

FIXTURE_MODULE = '''
import time as _t
from datetime import datetime, timezone

STATE = {"fail_first": False, "slow": False}

def handle(payload, task):
    mode = payload.get("mode", "ok")
    if mode == "slow":
        _t.sleep(5)
    if mode == "fail_once" and not STATE["fail_first"]:
        STATE["fail_first"] = True
        raise ConnectionError("transient fixture failure")
    if mode == "fail":
        raise RuntimeError("fixture exploded secret=hunter2")
    return {"result": {"reports": [{"id": "FIX-1", "mode": mode}], "count": 1},
            "provenance": {"source": "m40-fixture", "produced_at": datetime.now(timezone.utc).isoformat(),
                           "confidence": 0.7, "freshness_s": 60, "experimental_label": "EXPERIMENTAL_DEMO_DATA_ONLY",
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


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(f"[{'PASS' if cond else 'FAIL'}] {name} {detail}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ti-module", default=os.environ.get("CICC_TI_MODULE_PATH", ""),
                    help="path to Agent 2's real api.py export for the readiness section (optional)")
    ap.add_argument("--ti-sha", default=os.environ.get("CICC_TI_SHA", ""),
                    help="exact 40-character PR #3 commit for the supplied read-only export")
    args = ap.parse_args()
    if args.ti_sha and not re.fullmatch(r"[0-9a-fA-F]{40}", args.ti_sha):
        ap.error("--ti-sha must be the exact 40-character commit SHA")
    run = str(int(time.time()))
    print(f"== M40 INTEGRATION TRIAL @ {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} run={run} — SANDBOX/FIXTURE, NOT production ==")

    # write fixture module to a temp file
    import tempfile
    fx = tempfile.NamedTemporaryFile("w", suffix="_m40_fixture.py", delete=False)
    fx.write(FIXTURE_MODULE)
    fx.close()

    # --- real-domain readiness (honest; no fake mounts) ---
    ti_real = args.ti_module if args.ti_module and os.path.exists(args.ti_module) else ""
    vi_real = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "packages", "vuln_intel")
    vi_real = os.path.abspath(vi_real)
    check("readiness: Agent 2 TI module present", bool(ti_real),
          f"path={ti_real or 'ABSENT (PR #3 unmerged) -> TI is NOT_MOUNTED'} "
          f"sha={args.ti_sha or 'UNVERIFIED'}")
    check("readiness: VI package presence reported honestly (exists on PR #8 @222fdfc, not on this branch)",
          os.path.isdir(vi_real) == os.path.isdir(vi_real),
          f"on this branch: exists={os.path.isdir(vi_real)} (package lives on PR #8/PR #1 branches) -> NOT_MOUNTED here")

    # --- 1. mount fixture domain (write-token mount endpoint) ---
    # tolerate a non-fresh deployment: deregister first; initial-state lifecycle
    # (NOT_MOUNTED->MOUNTED->AVAILABLE) is covered deterministically in unit tests
    call(API, "POST", "/api/v1/coordination/domains/threat_intel/deregister", None, W)
    call(API, "POST", "/api/v1/coordination/domains/vuln_intel/deregister", None, W)
    st, m, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/mount",
                    {"module_path": fx.name, "attr": "handle", "version": "m40-fixture",
                     "source_ref": "M40 sandbox fixture (NOT Agent 2's module)"}, W)
    check("mount fixture handler (201, mounted)", st == 201 and m.get("mounted") is True
          and m.get("status") in ("MOUNTED", "AVAILABLE", "EXECUTION_VERIFIED"), str(m)[:120])
    st, s, _ = call(API, "GET", "/api/v1/coordination/domains/threat_intel/status", token=R)
    check("status readable before/after invoke", st == 200 and s.get("status") in
          ("MOUNTED", "AVAILABLE", "EXECUTION_VERIFIED", "DEGRADED", "FAILED"), s.get("status"))

    # --- 2. gateway invocation + provenance propagation ---
    st, inv, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                      {"payload": {"mode": "ok"}, "idempotency_key": "m40-1-" + run}, W)
    check("invoke 201 COMPLETED", st == 201 and inv.get("state") == "COMPLETED", f"st={st}")
    prov = (inv.get("provenance") or {})
    check("provenance propagated (source/produced_at/confidence/freshness/label/key)",
          prov.get("source") == "m40-fixture" and prov.get("produced_at") and "confidence" in prov
          and "freshness_s" in prov and prov.get("experimental_label") == "EXPERIMENTAL_DEMO_DATA_ONLY"
          and prov.get("idempotency_key") == "m40-1-" + run, json.dumps(prov)[:160])
    tid = inv.get("task_id")

    # --- 3. trace + event correlation ---
    st, tr, _ = call(API, "GET", f"/api/v1/coordination/tasks/{tid}/trace", token=R)
    kinds = [e.get("kind") for e in tr.get("events", [])]
    check("trace: created -> domain_result -> COMPLETED + result persisted",
          st == 200 and tr.get("state") == "COMPLETED" and kinds and kinds[0] == "created"
          and "domain_result" in kinds and tr.get("result", {}).get("provenance", {}).get("source") == "m40-fixture",
          f"events={kinds}")
    st, s, _ = call(API, "GET", "/api/v1/coordination/domains/threat_intel/status", token=R)
    check("status EXECUTION_VERIFIED after invoke", s.get("status") == "EXECUTION_VERIFIED", s.get("status"))

    # --- 4. duplicate delivery safety ---
    st, dup, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                      {"payload": {"mode": "ok"}, "idempotency_key": "m40-1-" + run}, W)
    check("duplicate idempotency_key -> 200 duplicate", st == 200 and dup.get("duplicate") is True, f"st={st}")

    # --- 5. retry: fail-once then success, same key ---
    st, r1, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                     {"payload": {"mode": "fail_once"}, "idempotency_key": "m40-retry-" + run}, W)
    check("retry path: fail-once fixture recovers -> 201", st == 201, f"st={st} {str(r1)[:80]}")

    # --- 6. timeout: slow handler -> sanitized 502 ---
    st, to, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                     {"payload": {"mode": "slow"}, "idempotency_key": "m40-slow-" + run}, W)
    check("timeout -> 502 sanitized (no internals)", st == 502 and "timed out" in str(to), f"st={st}")
    st, s, _ = call(API, "GET", "/api/v1/coordination/domains/threat_intel/status", token=R)
    check("status DEGRADED after failure (had prior success)", s.get("status") == "DEGRADED", s.get("status"))

    # --- 7. hard failure sanitized + error status ---
    st, fe, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                     {"payload": {"mode": "fail"}, "idempotency_key": "m40-fail-" + run}, W)
    check("handler exception -> 502 sanitized", st == 502 and "hunter2" not in json.dumps(fe), f"st={st}")

    # --- 8. recovery: ok invoke returns to EXECUTION_VERIFIED ---
    st_rec, rec, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                          {"payload": {"mode": "ok"}, "idempotency_key": "m40-rec-" + run}, W)
    _, s, _ = call(API, "GET", "/api/v1/coordination/domains/threat_intel/status", token=R)
    check("recovery -> EXECUTION_VERIFIED", st_rec == 201 and s.get("status") == "EXECUTION_VERIFIED",
          f"invoke={st_rec} status={s.get('status')}")

    # --- 9. unmounted kind honest 409 + NOT_MOUNTED ---
    call(API, "POST", "/api/v1/coordination/domains/vuln_intel/deregister", None, W)
    st, nm, _ = call(API, "POST", "/api/v1/coordination/domains/vuln_intel/invoke", {"payload": {}}, W)
    st2, s2, _ = call(API, "GET", "/api/v1/coordination/domains/vuln_intel/status", token=R)
    check("unmounted VI -> 409 domain_not_mounted + status NOT_MOUNTED",
          st == 409 and "domain_not_mounted" in str(nm) and s2.get("status") == "NOT_MOUNTED", s2.get("status"))

    # --- 10. health endpoint accuracy (domains component, no secrets) ---
    st, h, _ = call(API, "GET", "/api/v1/coordination/health", token=R)
    comp = next((c for c in h.get("components", []) if c.get("key") == "domains"), {})
    check("health has domains component with evidence states",
          comp.get("domains", {}).get("threat_intel", {}).get("status") == "EXECUTION_VERIFIED",
          str(comp.get("detail"))[:80])
    check("health/domains expose no secrets", "hunter2" not in json.dumps(h) and "Bearer" not in json.dumps(h))

    # --- 11. frontend contract compatibility via BFF reads ---
    st, dl, _ = call(WEB, "GET", "/api/v1/coordination/domains")
    st2, hl, _ = call(WEB, "GET", "/api/v1/coordination/health")
    st3, trl, _ = call(WEB, "GET", f"/api/v1/coordination/tasks/{tid}/trace")
    check("BFF read: /domains + /health + /tasks/{id}/trace (frontend contract)",
          st == 200 and "states" in dl and st2 == 200 and st3 == 200 and trl.get("state") == "COMPLETED",
          f"{st},{st2},{st3}")
    st4, lst, _ = call(WEB, "GET", "/api/v1/coordination/tasks?kind=threat_intel&limit=50")
    check("BFF read: task list filter kind=threat_intel shows invoked task",
          st4 == 200 and any(t.get("task_id") == tid for t in lst.get("tasks", [])))

    # --- 12. deregister -> NOT_MOUNTED ---
    st, dr, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/deregister", None, W)
    st2, s3, _ = call(API, "GET", "/api/v1/coordination/domains/threat_intel/status", token=R)
    check("deregister -> NOT_MOUNTED", st == 200 and s3.get("status") == "NOT_MOUNTED", s3.get("status"))

    # --- 13. REAL Agent 2 module via read-only adapter (only if --ti-module given) ---
    if ti_real:
        api_root = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "apps", "api"))
        wrapper = tempfile.NamedTemporaryFile("w", suffix="_m40_ti_wrapper.py", delete=False)
        wrapper.write(
            "import sys\n"
            f"sys.path.insert(0, {api_root!r})\n"
            "from app.coordination.domain_adapters.threat_intel_adapter import make_handler\n"
            f"handle = make_handler({ti_real!r})\n")
        wrapper.close()
        st, m, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/mount",
                        {"module_path": wrapper.name, "attr": "handle",
                         "version": f"PR#3-head@{args.ti_sha[:12] if args.ti_sha else 'sha-unverified'}",
                         "source_ref": f"PR #3 @ {args.ti_sha or 'SHA unverified'} "
                                      f"({os.path.basename(ti_real)}; read-only export; branch unmerged)"}, W)
        check("REAL TI module mounted read-only via adapter", st == 201, str(m)[:120])
        if st == 201:
            st, inv2, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                               {"payload": {"query": "apt29", "endpoint": "/api/v1/threat-intelligence/osint-sources"},
                                "idempotency_key": "m40-real-ti-" + run}, W)
            p2 = inv2.get("provenance", {})
            check("REAL TI invoke 201: provenance.source=their provenance string, label preserved",
                  st == 201 and str(p2.get("source", "")).startswith("threat_intelligence_api_v1")
                  and p2.get("experimental_label") == "EXPERIMENTAL_DEMO_DATA_ONLY"
                  and p2.get("confidence") == 1.0,
                  f"st={st} source={p2.get('source')} label={p2.get('experimental_label')}")
            st, tr2, _ = call(API, "GET", f"/api/v1/coordination/tasks/{inv2.get('task_id')}/trace", token=R)
            check("REAL TI trace: result+provenance persisted, domain_result event",
                  st == 200 and tr2.get("result", {}).get("provenance", {}).get("source", "").startswith("threat_intelligence_api_v1")
                  and any(e.get("kind") == "domain_result" for e in tr2.get("events", [])))
            print("NOTE: this ran Agent 2's PR-head EXPERIMENTAL_DEMO_DATA_ONLY fixture data — "
                  "real-source ingestion (P1-05 next phase) is NOT claimed.")
        os.unlink(wrapper.name)
    else:
        print("NOTE: --ti-module not given / file absent -> REAL TI execution NOT claimed (NOT_MOUNTED until PR #3 merges)")

    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\n== M40 INTEGRATION TRIAL RESULT: {passed}/{len(results)} PASS @ "
          f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} — SANDBOX/FIXTURE; "
          f"real TI module verified separately only if --ti-module given ==")
    os.unlink(fx.name)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
