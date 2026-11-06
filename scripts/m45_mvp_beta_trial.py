#!/usr/bin/env python3
"""M45 — cross-domain integration / MVP beta readiness trial.

One reproducible trial covering the M45 acceptance items:
 1. CICC startup + database readiness
 2. coordination health
 3. Threat Intelligence availability + authenticated invocation (REAL PR #3
    head module, read-only export — SANDBOX/UNMERGED-BRANCH)
 4. Vulnerability Intelligence availability + invocation (REAL PR #1 head
    package, read-only export — SANDBOX/UNMERGED-BRANCH)
 5. authentication / authorization gating
 6. tenant-boundary checks (claimed != authenticated; no leaks)
 7. provenance + freshness (stale / clock skew)
 8. trace + audit persistence (mount/invoke/circuit events, alert history)
 9. timeout + failure recovery (circuit open -> sanitized 503 -> cooldown ->
    recovery; alert raised then resolved)
 10. frontend read-only visibility via BFF (domains + metrics; browser write 403)
 11. restart + operational recovery (only with --manage-api: kills and
     restarts the API on the same DB; persisted counters survive, circuit
     state is process-local fail-safe, mounts_total + alert history persist)

Evidence classes are printed per check. MERGED-APPLICATION is NOT RUN unless
the domain PRs are merged into main; PRODUCTION-VERIFIED is never claimed.

Usage (external API, items 1-10):
  API=http://127.0.0.1:8000 WEB=http://127.0.0.1:3000 \
  WRITE_TOKEN=smoke-write READ_TOKEN=smoke-read \
  python3 scripts/m45_mvp_beta_trial.py \
    --ti-module /tmp/pr3m45/apps/threat_intelligence/api.py \
    --vi-package /tmp/pr1m45/packages/vuln_intel

Full lifecycle incl. item 11 (trial starts/stops its own API on :8000):
  python3 scripts/m45_mvp_beta_trial.py --manage-api [--ti-module ...] [--vi-package ...]
"""
import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

API = os.environ.get("API", "http://127.0.0.1:8000")
WEB = os.environ.get("WEB", "http://127.0.0.1:3000")
W = os.environ.get("WRITE_TOKEN", "smoke-write")
R = os.environ.get("READ_TOKEN", "smoke-read")
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
results = []

FIXTURE = '''
from datetime import datetime, timedelta, timezone
import time as _t
def handle(payload, task):
    if payload.get("mode") == "fail":
        raise RuntimeError("fixture down secret=hunter2")
    if payload.get("mode") == "slow":
        _t.sleep(30)
    pa = datetime.now(timezone.utc)
    fresh = payload.get("freshness_s", 5)
    if payload.get("mode") == "skew":
        pa = pa + timedelta(hours=1)
        fresh = None
    prov = {"source": "m45-fixture", "produced_at": pa.isoformat(),
            "experimental_label": "EXPERIMENTAL_DEMO_DATA_ONLY"}
    if fresh is not None:
        prov["freshness_s"] = fresh
    return {"result": {"ok": True}, "provenance": prov}
'''


def call(base, method, path, body=None, token=None, timeout=60):
    req = urllib.request.Request(base + path,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
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
    results.append((name, bool(cond), label))
    print(f"[{'PASS' if cond else 'FAIL'}] [{label}] {name} {detail}")


def wait_api(base, tries=60):
    for _ in range(tries):
        try:
            st, _, _ = call(base, "GET", "/live", timeout=5)
            if st == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def start_api(db_path):
    env = dict(os.environ)
    env.update({
        "DATABASE_URL": f"sqlite:///{db_path}",
        "CICC_OPS_WRITE_TOKEN": W, "CICC_OPS_READ_TOKEN": R,
        "CICC_COORD_APPROVERS": "owner",
        "CICC_DOMAIN_INVOKE_TIMEOUT_S": "3", "CICC_DOMAIN_INVOKE_RETRIES": "1",
        "CICC_DOMAIN_STALE_AFTER_S": "60",
        "CICC_DOMAIN_CIRCUIT_FAILURES": "3", "CICC_DOMAIN_CIRCUIT_COOLDOWN_S": "2",
    })
    env.pop("RABBITMQ_AMQP_URL", None)
    py = os.path.join(REPO, "apps", "api", ".venv", "bin", "python")
    log = open(db_path + ".api.log", "a")
    proc = subprocess.Popen([py, "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0",
                             "--port", "8000"], cwd=os.path.join(REPO, "apps", "api"),
                            env=env, stdout=log, stderr=subprocess.STDOUT)
    return proc


def mount_real_domain(kind, wrapper_body, version, source_ref):
    wr = tempfile.NamedTemporaryFile("w", suffix=f"_m45_{kind}.py", delete=False)
    wr.write(wrapper_body)
    wr.close()
    call(API, "POST", f"/api/v1/coordination/domains/{kind}/deregister", None, W)
    st, m, _ = call(API, "POST", f"/api/v1/coordination/domains/{kind}/mount",
                    {"module_path": wr.name, "attr": "handle", "version": version,
                     "source_ref": source_ref}, W)
    os.unlink(wr.name)
    return st, m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ti-module", default="/tmp/pr3m45/apps/threat_intelligence/api.py")
    ap.add_argument("--vi-package", default="/tmp/pr1m45/packages/vuln_intel")
    ap.add_argument("--manage-api", action="store_true",
                    help="trial starts/stops its own API on :8000 with a fresh temp DB (enables item 11)")
    args = ap.parse_args()
    run = str(int(time.time()))
    print(f"== M45 MVP BETA TRIAL @ {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} run={run} ==")

    proc = None
    db = None
    if args.manage_api:
        db = tempfile.mktemp(suffix="_m45live.db")
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(db + suffix)
            except FileNotFoundError:
                pass
        proc = start_api(db)
        check("item 1a: managed API process started on :8000", proc.poll() is None, f"pid={proc.pid}")
    check("item 1b: API liveness (/live) after startup", wait_api(API), "")

    # ---- item 1: database readiness ----
    st, health, _ = call(API, "GET", "/api/v1/ops/components", token=R)
    dbc = [c for c in health.get("components", []) if "database" in str(c.get("key", "")).lower()
           or "db" == str(c.get("key", "")).lower()]
    check("item 1c: database readiness check reported by ops health",
          st == 200 and (not dbc or all(c.get("status") in ("healthy", "ok", "up") for c in dbc)),
          f"st={st} db_components={dbc[:1]}")

    # ---- item 2: coordination health ----
    st, tasks, _ = call(API, "GET", "/api/v1/coordination/tasks", token=R)
    st2, ov, _ = call(API, "GET", "/api/v1/ops/overview", token=R)
    check("item 2: coordination health (tasks API 200, ops overview 200)",
          st == 200 and st2 == 200 and isinstance(tasks.get("tasks"), list), f"{st},{st2}")

    # ---- items 3+4: REAL unmerged-branch domain modules through the gateway ----
    ti_ok = vi_ok = False
    if os.path.exists(args.ti_module):
        api_root = os.path.join(REPO, "apps", "api")
        st, _ = mount_real_domain(
            "threat_intel",
            f"import sys\nsys.path.insert(0, {api_root!r})\n"
            "from app.coordination.domain_adapters.threat_intel_adapter import make_handler\n"
            f"handle = make_handler({args.ti_module!r})\n",
            "PR#3-head", "PR #3 head read-only codeload export (unmerged branch)")
        st2, inv, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                           {"payload": {"query": "apt29"}, "idempotency_key": f"{run}-ti"}, W)
        p = inv.get("provenance", {})
        ti_ok = (st == 201 and st2 == 201
                 and str(p.get("source", "")).startswith("threat_intelligence_api_v1")
                 and p.get("experimental_label") == "EXPERIMENTAL_DEMO_DATA_ONLY")
        check("item 3: TI mounted + authenticated invoke via gateway (EXPERIMENTAL label preserved)",
              ti_ok, f"mount={st} invoke={st2} prov_source={p.get('source')}",
              label="SANDBOX/UNMERGED-BRANCH")
    else:
        check("item 3: TI module export present", False, args.ti_module, label="SANDBOX/UNMERGED-BRANCH")
    if os.path.isdir(os.path.join(args.vi_package, "vuln_intel")):
        api_root = os.path.join(REPO, "apps", "api")
        st, _ = mount_real_domain(
            "vuln_intel",
            f"import sys\nsys.path.insert(0, {api_root!r})\n"
            "from app.coordination.domain_adapters.vuln_intel_adapter import make_handler\n"
            f"handle = make_handler({args.vi_package!r})\n",
            "PR#1-head", "PR #1 head read-only codeload export (PR #8 merged into its branch; not on main)")
        st2, inv, _ = call(API, "POST", "/api/v1/coordination/domains/vuln_intel/invoke",
                           {"payload": {"op": "search", "query": "log4shell", "records": [
                               {"cve": "CVE-2021-44228", "origin": "demo", "summary": "log4shell RCE",
                                "severity": "critical", "kev": True}]},
                            "idempotency_key": f"{run}-vi"}, W)
        p = inv.get("provenance", {})
        vi_ok = (st == 201 and st2 == 201 and inv.get("result", {}).get("count") == 1
                 and str(p.get("data_origin", "")).startswith("non-live"))
        check("item 4: VI mounted + authenticated invoke via gateway (data_origin honest non-live)",
              vi_ok, f"mount={st} invoke={st2} count={inv.get('result', {}).get('count')}",
              label="SANDBOX/UNMERGED-BRANCH")
    else:
        check("item 4: VI package export present", False, args.vi_package, label="SANDBOX/UNMERGED-BRANCH")

    # honest NOT_MOUNTED for a kind never mounted
    st, s, _ = call(API, "GET", "/api/v1/coordination/domains/unknown_kind/status", token=R)
    check("honest NOT_MOUNTED for unregistered kind", st == 200 and s.get("status") == "NOT_MOUNTED",
          f"st={st} status={s.get('status')}")

    # ---- item 5: auth / authz ----
    st1, _, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                     {"payload": {}, "idempotency_key": f"{run}-nt"})
    st2, _, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                     {"payload": {}, "idempotency_key": f"{run}-wt"}, token="wrong")
    st3, _, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                     {"payload": {}, "idempotency_key": f"{run}-rt"}, token=R)
    st4, _, _ = call(API, "GET", "/api/v1/coordination/domains/metrics")
    check("item 5: invoke/metrics gated (401 no token, 401 wrong token, read token cannot write, metrics 401)",
          st1 == 401 and st2 == 401 and st3 in (401, 403) and st4 == 401, f"{st1},{st2},{st3},{st4}")

    # ---- item 6: tenant boundary ----
    st, inv6, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                       {"payload": {"query": "apt29"}, "tenant_id": "tenant-m45-secret",
                        "idempotency_key": f"{run}-ten"}, W)
    tr = call(API, "GET", f"/api/v1/coordination/tasks/{inv6.get('task_id')}/trace", token=R)[1]
    ct = [e for e in tr.get("events", []) if e.get("kind") == "claimed_tenant"]
    blob = json.dumps(call(API, "GET", "/api/v1/coordination/domains/metrics", token=R)[1])
    blob += json.dumps(call(API, "GET", "/api/v1/coordination/diagnostics", token=R)[1])
    check("item 6: tenant claim recorded UNVERIFIED; tenant id absent from metrics/diagnostics",
          st == 201 and ct and "unverified" in ct[0].get("detail", "")
          and "tenant-m45-secret" not in blob, f"st={st} claimed_events={len(ct)}")

    # ---- item 7: provenance + freshness on a fixture probe domain ----
    fx = tempfile.NamedTemporaryFile("w", suffix="_m45_probe.py", delete=False)
    fx.write(FIXTURE)
    fx.close()
    call(API, "POST", "/api/v1/coordination/domains/resilience_probe/deregister", None, W)
    st, _, _ = call(API, "POST", "/api/v1/coordination/domains/resilience_probe/mount",
                    {"module_path": fx.name, "attr": "handle", "version": "1.0",
                     "source_ref": "m45 fixture"}, W)
    st, sd, _ = call(API, "POST", "/api/v1/coordination/domains/resilience_probe/invoke",
                     {"payload": {"freshness_s": 999999}, "idempotency_key": f"{run}-stale"}, W)
    st2, sk, _ = call(API, "POST", "/api/v1/coordination/domains/resilience_probe/invoke",
                      {"payload": {"mode": "skew"}, "idempotency_key": f"{run}-skew"}, W)
    tr2 = call(API, "GET", f"/api/v1/coordination/tasks/{sk.get('task_id')}/trace", token=R)[1]
    check("item 7: provenance/freshness (stale=true; clock_skew_s>0 + domain_clock_skew trace event)",
          st == 201 and sd.get("stale") is True and st2 == 201
          and sk.get("freshness", {}).get("clock_skew_s", 0) > 3000
          and any(e.get("kind") == "domain_clock_skew" for e in tr2.get("events", [])),
          f"stale={sd.get('stale')} skew={sk.get('freshness', {}).get('clock_skew_s')}")

    # ---- item 8: trace + audit persistence ----
    _, m8, _ = call(API, "GET", "/api/v1/coordination/domains/metrics", token=R)
    _, ah, _ = call(API, "GET", "/api/v1/ops/alerts/history?rule=domain_status", token=R)
    _, act, _ = call(API, "GET", "/api/v1/ops/activity?limit=50", token=R)
    mounts_seen = sum(d.get("mounts_total", 0) for d in m8.get("domains", {}).values())
    audit_txt = json.dumps(act)
    check("item 8: trace/audit (mounts_total persisted in metrics; domain audit events in ops activity; alert history endpoint live)",
          mounts_seen >= 3 and "domain mounted" in audit_txt and "alerts" in ah,
          f"mounts_total_sum={mounts_seen}")

    # ---- item 9: timeout + failure recovery on the probe domain ----
    st_t, to, _ = call(API, "POST", "/api/v1/coordination/domains/resilience_probe/invoke",
                       {"payload": {"mode": "slow"}, "idempotency_key": f"{run}-slow"}, W)
    codes = [call(API, "POST", "/api/v1/coordination/domains/resilience_probe/invoke",
                  {"payload": {"mode": "fail"}, "idempotency_key": f"{run}-f{i}"}, W)[0] for i in range(3)]
    st_503, co, _ = call(API, "POST", "/api/v1/coordination/domains/resilience_probe/invoke",
                         {"payload": {"mode": "ok"}, "idempotency_key": f"{run}-f3"}, W)
    _, m9, _ = call(API, "GET", "/api/v1/coordination/domains/metrics", token=R)
    d9 = m9["domains"].get("resilience_probe", {})
    _, al, _ = call(API, "GET", "/api/v1/ops/alerts?state=active", token=R)
    da = [a for a in al.get("alerts", []) if a.get("rule") == "domain_status"
          and a.get("component_key") == "resilience_probe"]
    check("item 9a: slow invoke timed out (502, timeout counted)",
          st_t == 502 and d9.get("timeouts") == 1, f"st={st_t} timeouts={d9.get('timeouts')}")
    # the item-9a timeout already counts as 1 consecutive failure, so the circuit
    # may open on the 2nd or 3rd fail invoke — either way opens==1 and later 503
    check("item 9b: consecutive failures -> circuit OPENED exactly once, later invokes fast-rejected 503 sanitized",
          codes[:2] == [502, 502] and codes[2] in (502, 503) and st_503 == 503
          and d9.get("circuit", {}).get("opens") == 1 and "hunter2" not in json.dumps(co),
          f"codes={codes} st={st_503} opens={d9.get('circuit', {}).get('opens')}")
    check("item 9c: domain_status alert active + sanitized", bool(da) and "hunter2" not in json.dumps(da),
          f"alerts={len(da)}")
    time.sleep(2.2)  # cooldown 2s
    st_r, _, _ = call(API, "POST", "/api/v1/coordination/domains/resilience_probe/invoke",
                      {"payload": {"mode": "ok"}, "idempotency_key": f"{run}-rec"}, W)
    _, m9b, _ = call(API, "GET", "/api/v1/coordination/domains/metrics", token=R)
    d9b = m9b["domains"]["resilience_probe"]
    _, al2, _ = call(API, "GET", "/api/v1/ops/alerts?state=active", token=R)
    da2 = [a for a in al2.get("alerts", []) if a.get("rule") == "domain_status"
           and a.get("component_key") == "resilience_probe"]
    check("item 9d: after cooldown recovery 201, circuit CLOSED (closes==1), alert resolved",
          st_r == 201 and d9b["circuit"]["closes"] == 1 and d9b["circuit"]["open"] is False and not da2,
          f"st={st_r} closes={d9b['circuit']['closes']} active_alerts={len(da2)}")
    _, ah2, _ = call(API, "GET", "/api/v1/ops/alerts/history?rule=domain_status", token=R)
    hist = [a for a in ah2.get("alerts", []) if a.get("component_key") == "resilience_probe"]
    check("item 9e: alert recovery history persisted (resolved row visible)",
          any(a.get("status") == "resolved" for a in hist), f"statuses={sorted({a.get('status') for a in hist})}")

    # ---- item 10: frontend read-only visibility via BFF ----
    st_w1, dw, _ = call(WEB, "GET", "/api/v1/coordination/domains")
    st_w2, mw, _ = call(WEB, "GET", "/api/v1/coordination/domains/metrics")
    st_w3, _, _ = call(WEB, "POST", "/api/v1/coordination/domains/resilience_probe/invoke",
                       {"payload": {}, "idempotency_key": f"{run}-web"})
    kinds = {d.get("kind") for d in dw.get("domains", [])}
    check("item 10a: BFF read-only domains+metrics visible to frontend (no token in browser)",
          st_w1 == 200 and st_w2 == 200 and {"threat_intel", "vuln_intel"} <= kinds,
          f"{st_w1},{st_w2} kinds={sorted(k for k in kinds if k)}")
    check("item 10b: frontend shows circuit state + mount history in metrics DTO",
          st_w2 == 200 and "resilience_probe" in mw.get("domains", {})
          and "circuit" in mw["domains"].get("resilience_probe", {})
          and "mounts_total" in mw["domains"].get("resilience_probe", {}))
    check("item 10c: browser domain invoke blocked by BFF write boundary (403)",
          st_w3 == 403, f"st={st_w3}")

    # ---- item 11: restart + operational recovery (managed API only) ----
    if args.manage_api and proc is not None:
        _, before, _ = call(API, "GET", "/api/v1/coordination/domains/metrics", token=R)
        b_ti = before["domains"].get("threat_intel", {})
        b_probe = before["domains"].get("resilience_probe", {})
        proc.send_signal(signal.SIGKILL)  # hard kill: no safe shutdown on purpose
        proc.wait(timeout=10)
        check("item 11a: API hard-killed (SIGKILL) for restart test", True)
        proc = start_api(db)  # same DB file
        ok = wait_api(API)
        _, after, _ = call(API, "GET", "/api/v1/coordination/domains/metrics", token=R)
        a_ti = after["domains"].get("threat_intel", {})
        a_probe = after["domains"].get("resilience_probe", {})
        check("item 11b: API restarted on same DB, /live 200", ok, "")
        check("item 11c: persisted counters survive restart (invokes/successes/mounts_total)",
              a_ti.get("invokes") == b_ti.get("invokes") and a_ti.get("successes") == b_ti.get("successes")
              and a_probe.get("invokes") == b_probe.get("invokes")
              and a_probe.get("mounts_total") == b_probe.get("mounts_total"),
              f"ti {b_ti.get('invokes')}->{a_ti.get('invokes')} ok={a_ti.get('successes')}, "
              f"probe invokes {b_probe.get('invokes')}->{a_probe.get('invokes')}, "
              f"mounts_total {b_probe.get('mounts_total')}->{a_probe.get('mounts_total')}")
        check("item 11d: circuit state is process-local fail-safe (closed after restart, opens reset)",
              a_probe.get("circuit", {}).get("open") is False and a_probe.get("circuit", {}).get("opens") == 0,
              f"circuit={a_probe.get('circuit')}")
        check("item 11e: last_success_at process-local (null after restart) — documented",
              a_ti.get("last_success_at") is None, f"last_success_at={a_ti.get('last_success_at')}")
        _, ah3, _ = call(API, "GET", "/api/v1/ops/alerts/history?rule=domain_status", token=R)
        hist3 = [a for a in ah3.get("alerts", []) if a.get("component_key") == "resilience_probe"]
        check("item 11f: alert recovery history survives restart (resolved row still present)",
              any(a.get("status") == "resolved" for a in hist3))
        _, act3, _ = call(API, "GET", "/api/v1/ops/activity?limit=20", token=R)
        check("item 11g: api start/stop audit events persisted across restart",
              "service started" in json.dumps(act3), "")
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    else:
        print("[SKIP] item 11 (restart recovery) — run with --manage-api for the full lifecycle check")

    os.unlink(fx.name)
    passed = sum(1 for _, ok, _ in results if ok)
    labels = sorted({l for _, _, l in results})
    print(f"\n== M45 MVP BETA TRIAL RESULT: {passed}/{len(results)} PASS @ "
          f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} ==")
    print(f"   Evidence classes used: {', '.join(labels)}. MERGED-APPLICATION: NOT RUN "
          f"(domain PRs unmerged on main; PR #8 merged into PR #1 branch only). "
          "PRODUCTION-VERIFIED: never claimed.")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
