#!/usr/bin/env python3
"""M43 — circuit-breaker / domain-alert / mount-history trial (sandbox-labeled).

Covers the M43 gateway features live: circuit open after N consecutive
failures (503, handler not executed), half-open after cooldown, alert
raise/resolve via ops alerts, mount history (re-mount replaces + audit),
payload cap 413, plus M42 regression spot-checks (stale, skew, tenant claim).

Usage: API=http://127.0.0.1:8000 WEB=http://127.0.0.1:3000 \
       WRITE_TOKEN=smoke-write READ_TOKEN=smoke-read \
       CICC_DOMAIN_CIRCUIT_FAILURES=3 CICC_DOMAIN_CIRCUIT_COOLDOWN_S=2 \
       python3 scripts/m43_trial.py
"""
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
from datetime import datetime, timezone
def handle(payload, task):
    if payload.get("mode") == "fail":
        raise RuntimeError("fixture down secret=hunter2")
    pa = datetime.now(timezone.utc).isoformat()
    fresh = payload.get("freshness_s", 5)
    if payload.get("mode") == "skew":
        import datetime as _d
        pa = (_d.datetime.now(_d.timezone.utc) + _d.timedelta(hours=1)).isoformat()
        fresh = None  # skew detected via produced_at age, not freshness_s
    prov = {"source": "m43-fixture", "produced_at": pa, "experimental_label": "EXPERIMENTAL_DEMO_DATA_ONLY"}
    if fresh is not None:
        prov["freshness_s"] = fresh
    return {"result": {"ok": True}, "provenance": prov}
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
    results.append((name, bool(cond)))
    print(f"[{'PASS' if cond else 'FAIL'}] [SANDBOX/FIXTURE] {name} {detail}")


def main():
    run = str(int(time.time()))
    print(f"== M43 TRIAL @ {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} run={run} (SANDBOX/FIXTURE) ==")
    fx = tempfile.NamedTemporaryFile("w", suffix="_m43.py", delete=False)
    fx.write(FIXTURE)
    fx.close()
    call(API, "POST", "/api/v1/coordination/domains/threat_intel/deregister", None, W)
    st, m, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/mount",
                    {"module_path": fx.name, "attr": "handle", "version": "1.0", "source_ref": "m43 fixture"}, W)
    check("mount v1.0", st == 201, f"st={st}")
    st, m2, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/mount",
                     {"module_path": fx.name, "attr": "handle", "version": "2.0", "source_ref": "m43 fixture"}, W)
    _, s, _ = call(API, "GET", "/api/v1/coordination/domains/threat_intel/status", token=R)
    check("re-mount v2.0: mount_count=2, previous_version=1.0",
          st == 201 and s["evidence"].get("mount_count") == 2 and s["evidence"].get("previous_version") == "1.0",
          json.dumps({k: s["evidence"].get(k) for k in ("mount_count", "previous_version", "version")}))

    # 3 consecutive failures -> circuit opens
    for i in range(3):
        st, _, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                        {"payload": {"mode": "fail"}, "idempotency_key": f"{run}-f{i}"}, W)
    check("3 failures -> 502 each", st == 502, f"st={st}")
    _, s, _ = call(API, "GET", "/api/v1/coordination/domains/threat_intel/status", token=R)
    check("circuit open in evidence", s["evidence"]["circuit"]["open"] is True, str(s["evidence"]["circuit"]))
    st, co, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                     {"payload": {"mode": "fail"}, "idempotency_key": f"{run}-f3"}, W)
    check("4th invoke fast-rejected 503 domain_circuit_open (sanitized)",
          st == 503 and "circuit" in str(co) and "hunter2" not in json.dumps(co), f"st={st}")

    # alert raised and visible in ops alerts
    _, alerts, _ = call(API, "GET", "/api/v1/ops/alerts?state=active", token=R)
    da = [a for a in alerts.get("alerts", []) if a.get("rule") == "domain_status"
          and a.get("component_key") == "threat_intel"]
    check("domain_status alert active in ops alerts, sanitized", bool(da) and "hunter2" not in json.dumps(da),
          str(da[:1])[:120])

    # cooldown -> half-open success -> circuit closed + alert resolved
    time.sleep(2.2)
    st, ok, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                     {"payload": {"mode": "ok"}, "idempotency_key": f"{run}-ok"}, W)
    _, s, _ = call(API, "GET", "/api/v1/coordination/domains/threat_intel/status", token=R)
    check("after cooldown: invoke 201, circuit closed, EXECUTION_VERIFIED",
          st == 201 and s["evidence"]["circuit"]["open"] is False and s["status"] == "EXECUTION_VERIFIED",
          f"st={st} status={s['status']}")
    _, alerts, _ = call(API, "GET", "/api/v1/ops/alerts?state=active", token=R)
    da = [a for a in alerts.get("alerts", []) if a.get("rule") == "domain_status"
          and a.get("component_key") == "threat_intel"]
    check("alert resolved after recovery", not da)

    # payload cap
    st, big, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                      {"payload": {"blob": "x" * 70000}, "idempotency_key": f"{run}-big"}, W)
    check("payload >64 KiB -> 413", st == 413, f"st={st}")

    # M42 regression spot-checks: stale, skew, tenant claim
    st, sd, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                     {"payload": {"freshness_s": 999999}, "idempotency_key": f"{run}-stale"}, W)
    check("M42 stale still works", st == 201 and sd.get("stale") is True)
    st, sk, _ = call(API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                     {"payload": {"mode": "skew"}, "idempotency_key": f"{run}-skew", "tenant_id": "t-1"}, W)
    tr = call(API, "GET", f"/api/v1/coordination/tasks/{sk.get('task_id')}/trace", token=R)[1]
    check("M42 clock-skew + claimed_tenant still work",
          st == 201 and sk.get("freshness", {}).get("clock_skew_s", 0) > 3000
          and any(e.get("kind") == "domain_clock_skew" for e in tr.get("events", []))
          and any(e.get("kind") == "claimed_tenant" for e in tr.get("events", [])), f"st={st}")

    passed = sum(1 for _, ok in results if ok)
    print(f"\n== M43 TRIAL RESULT: {passed}/{len(results)} PASS @ "
          f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} — SANDBOX/FIXTURE, NOT production ==")
    os.unlink(fx.name)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
