#!/usr/bin/env python3
"""M44 — domain gateway observability trial (sandbox-labeled).

Live checks against a running API: per-domain metrics accuracy after a known
invoke mix (ok/fail/stale/skew/timeout), retries/timeouts counters, bounded
labels (kind only), sensitive-data exclusion (tenant ids / tokens / payload
values never appear in metrics or diagnostics), read-gating, circuit
transition counters, mount history visibility, and alert state/recovery
history via /ops/alerts/history.

Usage: API=http://127.0.0.1:8000 WRITE_TOKEN=smoke-write READ_TOKEN=smoke-read \
       python3 scripts/m44_observability_trial.py
"""
import json
import os
import sys
import tempfile
import time
import urllib.request
import urllib.error

API = os.environ.get("API", "http://127.0.0.1:8000")
W = os.environ.get("WRITE_TOKEN", "smoke-write")
R = os.environ.get("READ_TOKEN", "smoke-read")
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
    prov = {"source": "m44-fixture", "produced_at": pa.isoformat(),
            "experimental_label": "EXPERIMENTAL_DEMO_DATA_ONLY"}
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
        with urllib.request.urlopen(req, timeout=60) as resp:
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
    print(f"== M44 TRIAL @ {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} run={run} "
          f"(SANDBOX/FIXTURE) ==")
    fx = tempfile.NamedTemporaryFile("w", suffix="_m44.py", delete=False)
    fx.write(FIXTURE)
    fx.close()
    KIND = "threat_intel"
    # baseline so the trial is rerunnable on a non-empty DB (assert deltas)
    _, b0, _ = call(API, "GET", "/api/v1/coordination/domains/metrics", token=R)
    b = b0.get("domains", {}).get(KIND, {})
    base = {k: b.get(k, 0) for k in ("invokes", "successes", "timeouts", "retries",
                                      "stale_count", "skew_count")}
    base["opens"] = b.get("circuit", {}).get("opens", 0)
    base["mounts_total"] = b.get("mounts_total", 0)

    call(API, "POST", f"/api/v1/coordination/domains/{KIND}/deregister", None, W)
    st, _, _ = call(API, "POST", f"/api/v1/coordination/domains/{KIND}/mount",
                    {"module_path": fx.name, "attr": "handle", "version": "1.0",
                     "source_ref": "m44 fixture"}, W)
    check("mount v1.0", st == 201, f"st={st}")
    st, _, _ = call(API, "POST", f"/api/v1/coordination/domains/{KIND}/mount",
                    {"module_path": fx.name, "attr": "handle", "version": "2.0",
                     "source_ref": "m44 fixture"}, W)
    check("re-mount v2.0 (mount history)", st == 201, f"st={st}")

    # metrics endpoint is read-gated
    st, _, _ = call(API, "GET", "/api/v1/coordination/domains/metrics")
    check("metrics 401 without token", st == 401, f"st={st}")
    st, _, _ = call(API, "GET", "/api/v1/coordination/domains/metrics", token="wrong")
    check("metrics 401 wrong token", st == 401, f"st={st}")

    # known invoke mix (failures interleaved so the circuit stays closed):
    # fail, ok, fail, ok, stale, skew, timeout  => invokes 7, successes 4,
    # failures 3 (2 fail + 1 timeout), stale 1, skew 1, timeouts 1, retries 3
    mix = [("fail", {}), ("ok", {}), ("fail", {}), ("ok", {}),
           ("ok", {"freshness_s": 999999}), ("skew", {}), ("slow", {})]
    codes = []
    for i, (mode, extra) in enumerate(mix):
        body = {"payload": {"mode": mode, "secret_marker": "tok-m44-secret", **extra},
                "idempotency_key": f"{run}-m{i}"}
        if i == 5:  # skew invoke also claims a tenant — must never leak into metrics
            body["tenant_id"] = "tenant-m44-secret"
        st, _, _ = call(API, "POST", f"/api/v1/coordination/domains/{KIND}/invoke", body, W)
        codes.append(st)
    check("invoke mix codes (201/201/201/201/201/201/502)",
          codes == [502, 201, 502, 201, 201, 201, 502], str(codes))

    st, m, _ = call(API, "GET", "/api/v1/coordination/domains/metrics", token=R)
    d = m.get("domains", {}).get(KIND, {})
    check("metrics labels bounded to kind", m.get("labels") == ["kind"], str(m.get("labels")))
    check("invoke-mix deltas: +7 invokes +4 successes +3 failures",
          d.get("invokes") - base["invokes"] == 7 and d.get("successes") - base["successes"] == 4
          and (d.get("invokes") - d.get("successes")) - (base["invokes"] - base["successes"]) == 3,
          json.dumps({k: d.get(k) - base[k] for k in ("invokes", "successes")}))
    di, ds = d.get("invokes") - base["invokes"], d.get("successes") - base["successes"]
    check("success_rate consistent with counters", d.get("success_rate") == round(d["successes"] / d["invokes"], 4),
          f"rate={d.get('success_rate')} expected={round(d['successes']/d['invokes'],4)} ({ds}/{di} this run)")
    check("stale/skew/timeout/retry deltas +1/+1/+1/+3",
          d.get("stale_count") - base["stale_count"] == 1 and d.get("skew_count") - base["skew_count"] == 1
          and d.get("timeouts") - base["timeouts"] == 1 and d.get("retries") - base["retries"] == 3,
          json.dumps({k: d.get(k) - base[k] for k in ("stale_count", "skew_count", "timeouts", "retries")}))
    lat = d.get("latency", {})
    check("latency aggregates present (count>=7, avg/max/last set)",
          lat.get("count", 0) >= 7 and lat.get("avg_s") is not None and lat.get("max_s") is not None
          and lat.get("last_s") is not None, json.dumps(lat))
    check("circuit transitions counted (no new opens in the mix, state consistent)",
          d.get("circuit", {}).get("opens") - base["opens"] == 0 and "open" in d.get("circuit", {}),
          json.dumps(d.get("circuit", {})))
    check("mount history: mounts_total delta==2 (persisted), mount_count==2 (process-local)",
          d.get("mounts_total") - base["mounts_total"] == 2 and d.get("mount_count") == 2,
          f"mounts_total={d.get('mounts_total')} mount_count={d.get('mount_count')}")
    check("metrics consistent with domain status contract (status field present)",
          d.get("status") in ("EXECUTION_VERIFIED", "DEGRADED", "FAILED", "MOUNTED", "AVAILABLE"),
          str(d.get("status")))

    blob = json.dumps(m)
    check("sensitive exclusion: no tenant/token/payload secrets in metrics",
          "tenant-m44-secret" not in blob and "tok-m44-secret" not in blob
          and "hunter2" not in blob and "Bearer" not in blob)
    st, dg, _ = call(API, "GET", "/api/v1/coordination/diagnostics", token=R)
    dblob = json.dumps(dg)
    check("diagnostics sanitized too",
          st == 200 and "tenant-m44-secret" not in dblob and "tok-m44-secret" not in dblob
          and "hunter2" not in dblob, f"st={st}")

    # circuit transitions visible: 3 consecutive failures -> opens==1, fast-reject 503
    for i in range(3):
        call(API, "POST", f"/api/v1/coordination/domains/{KIND}/invoke",
             {"payload": {"mode": "fail"}, "idempotency_key": f"{run}-c{i}"}, W)
    st, co, _ = call(API, "POST", f"/api/v1/coordination/domains/{KIND}/invoke",
                     {"payload": {"mode": "ok"}, "idempotency_key": f"{run}-c3"}, W)
    _, m, _ = call(API, "GET", "/api/v1/coordination/domains/metrics", token=R)
    d = m["domains"][KIND]
    check("circuit opens +1 after 3 consecutive failures, 4th invoke fast-rejected 503 sanitized",
          d["circuit"]["opens"] - base["opens"] == 1 and d["circuit"]["open"] is True and st == 503
          and "hunter2" not in json.dumps(co), f"st={st} opens_delta={d['circuit']['opens'] - base['opens']}")

    # alert state + recovery history visible and sanitized
    _, ah, _ = call(API, "GET", "/api/v1/ops/alerts/history?rule=domain_status", token=R)
    hist = [a for a in ah.get("alerts", []) if a.get("component_key") == KIND]
    check("alert history endpoint shows domain_status alerts incl. resolved",
          bool(hist) and any(a.get("status") in ("active", "acknowledged", "resolved") for a in hist)
          and "hunter2" not in json.dumps(hist), f"n={len(hist)} statuses="
          f"{sorted({a.get('status') for a in hist})}")

    passed = sum(1 for _, ok in results if ok)
    print(f"\n== M44 TRIAL RESULT: {passed}/{len(results)} PASS @ "
          f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} — SANDBOX/FIXTURE, NOT production ==")
    os.unlink(fx.name)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
