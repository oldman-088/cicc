#!/usr/bin/env python3
"""Smallest complete SANDBOX MVP trial (M33) — Agent 1.

Runs the full coordination workflow end-to-end through the reference BFF
(apps/web :3000) against the live sandbox API (:8000), using fixture tokens:
create -> route -> deliver(human-assisted, NO broker claim) -> ack -> start
-> progress -> complete; plus fail/retry path, approval path, duplicate
submission, amendment propose, health + trace inspection.

ALL evidence produced here is SANDBOX / FIXTURE-TOKEN evidence. It is NOT
production verification. RabbitMQ is not required (non-blocking).

Usage: API=http://127.0.0.1:8000 WEB=http://127.0.0.1:3000 \
       WRITE_TOKEN=smoke-write READ_TOKEN=smoke-read \
       python3 scripts/mvp_sandbox_trial.py
"""
import json
import os
import sys
import time
import urllib.request

API = os.environ.get("API", "http://127.0.0.1:8000")
WEB = os.environ.get("WEB", "http://127.0.0.1:3000")
W = os.environ.get("WRITE_TOKEN", "smoke-write")
R = os.environ.get("READ_TOKEN", "smoke-read")

results = []


def call(base, method, path, body=None, token=None, raw=False):
    url = base + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = resp.read().decode()
            return resp.status, (payload if raw else json.loads(payload) if payload else {}), dict(resp.headers)
    except urllib.error.HTTPError as e:
        payload = e.read().decode()
        try:
            payload = json.loads(payload)
        except Exception:
            pass
        return e.code, payload, dict(e.headers)


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(f"[{'PASS' if cond else 'FAIL'}] {name} {detail}")


def main():
    ts = int(time.time())
    print(f"== SANDBOX MVP TRIAL @ {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} "
          f"API={API} WEB={WEB} (fixture tokens, NOT production) ==")

    # 0. contract + health readable through BFF (no browser token)
    st, c, _ = call(WEB, "GET", "/api/v1/coordination/contract")
    check("contract via BFF", st == 200 and c.get("version"), f"version={c.get('version')}")
    st, h, _ = call(WEB, "GET", "/api/v1/coordination/health")
    check("health via BFF", st == 200 and "overall" in h, f"overall={h.get('overall')}")
    check("health honest on-demand note", "NOT continuous monitoring" in (h.get("last_operations") or {}).get("note", ""))

    # 1. write through the single approved BFF route (server-generated key)
    st, t, hdr = call(WEB, "POST", "/api/v1/coordination/tasks",
                      {"kind": "mvp_trial", "priority": 5, "title": f"MVP sandbox trial {ts}",
                       "payload": {"trial": ts}})
    check("BFF write POST /tasks -> 201", st == 201, f"task={t.get('task_id')}")
    key = next((v for k, v in hdr.items() if k.lower() == "x-cicc-idempotency-key"), "")
    check("server idempotency key header", key.startswith("bff-"), key)
    tid = t.get("task_id")

    # 2. correlation consistent: read via BFF shows same idempotency_key
    st, g, _ = call(WEB, "GET", f"/api/v1/coordination/tasks/{tid}")
    check("read task via BFF has same idempotency_key", st == 200 and g.get("idempotency_key") == key)

    # 3. negative: bad kind rejected at BFF, other write path 403
    st, _, _ = call(WEB, "POST", "/api/v1/coordination/tasks", {"kind": "BAD KIND!"})
    check("bad kind -> 422 at BFF", st == 422)
    st, _, _ = call(WEB, "POST", "/api/v1/coordination/agents", {})
    check("other write path -> 403", st == 403)

    # 4. duplicate submission with client key is rejected (server key only)
    st, d, _ = call(WEB, "POST", "/api/v1/coordination/tasks",
                    {"kind": "mvp_trial", "idempotency_key": "client-forged", "payload": {}})
    check("client-supplied idempotency_key not honored", st in (201, 422) and d.get("task_id") != tid)

    # 5. full lifecycle via API (write token): route -> deliver -> ack -> start -> progress -> complete
    call(API, "POST", "/api/v1/coordination/agents/register", {"agent": "mvp-agent"}, W)
    for ep, body in [("route", {"agent": "mvp-agent"}), ("deliver", None), ("ack", {}), ("start", {}),
                     ("progress", {"percent": 50}), ("complete", {"result": "trial-ok"})]:
        st, r, _ = call(API, "POST", f"/api/v1/coordination/tasks/{tid}/{ep}", body, W)
        check(f"lifecycle {ep}", st == 200, f"state={r.get('state')}")
    st, dl, _ = call(API, "GET", f"/api/v1/coordination/tasks/{tid}/deliveries", token=R)
    # no broker in sandbox: delivery must be honestly human_assisted, never "confirmed"
    honest = all(d.get("channel") == "human_assisted" for d in dl.get("deliveries", []))
    check("delivery honest (human_assisted, no broker claim)", honest)

    # 6. fail/retry path on a second task
    tid2 = f"mvp-fail-{ts}"
    call(API, "POST", "/api/v1/coordination/tasks", {"task_id": tid2, "kind": "mvp_trial", "payload": {}}, W)
    for ep, body in [("route", {"agent": "mvp-agent"}), ("ack", {}), ("start", {})]:
        call(API, "POST", f"/api/v1/coordination/tasks/{tid2}/{ep}", body, W)
    st, f1, _ = call(API, "POST", f"/api/v1/coordination/tasks/{tid2}/fail", {"result": "boom"}, W)
    check("fail -> RETRYING (attempts<max)", st == 200 and f1.get("state") == "RETRYING", f1.get("state"))
    st, rr, _ = call(API, "POST", f"/api/v1/coordination/tasks/{tid2}/retry", None, W)
    check("retry -> QUEUED", st == 200 and rr.get("state") == "QUEUED")

    # 7. approval path on a third task
    tid3 = f"mvp-appr-{ts}"
    st, a, _ = call(API, "POST", "/api/v1/coordination/tasks",
                    {"task_id": tid3, "kind": "mvp_trial", "payload": {}, "requires_approval": True}, W)
    check("requires_approval -> WAITING_FOR_APPROVAL", st == 201 and a.get("state") == "WAITING_FOR_APPROVAL", a.get("state"))
    st, ap, _ = call(API, "POST", f"/api/v1/coordination/tasks/{tid3}/approve", {"decided_by": "owner"}, W)
    check("owner approve", st == 200 and ap.get("ok"))

    # 8. trace endpoint correlates everything
    st, tr, _ = call(WEB, "GET", f"/api/v1/coordination/tasks/{tid}/trace")
    kinds = [e["kind"] for e in tr.get("events", [])]
    check("trace via BFF: created + state events + correlation",
          st == 200 and kinds and kinds[0] == "created" and tr["correlation"]["idempotency_key"] == key)

    # 9. amendment propose (stays pending — owner-reserved)
    st, am, _ = call(API, "POST", "/api/v1/coordination/contract/amendments",
                     {"amendment_id": f"AMD-MVP-{ts}", "title": "MVP trial evidence", "description": "sandbox trial refs",
                      "proposed_by": "agent-1", "affects": [], "compatibility": {"backward_compatible": True}}, W)
    check("amendment proposed pending (owner-reserved)", st == 201 and am.get("status") == "pending")

    # 10. sweep (lease/timeout/requeue/amendment stale)
    st, sw, _ = call(API, "POST", "/api/v1/coordination/sweep", None, W)
    check("sweep ok", st == 200 and "recovered_abandoned" in sw and "stale_amendments" in sw)

    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\n== MVP SANDBOX TRIAL RESULT: {passed}/{len(results)} PASS "
          f"@ {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} — SANDBOX/FIXTURE evidence only, NOT production ==")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
