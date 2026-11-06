#!/usr/bin/env python3
"""Smallest complete CROSS-DOMAIN CICC workflow (M34) — coordination layer only.

Drives one task per domain kind (threat_intel, vuln_intel, frontend_e2e)
through the reference BFF + coordination API: register a domain agent per
kind, submit via the approved BFF write route, route, deliver (human-assisted,
NO broker claim), ack, start, progress, complete; then verify per-domain
visibility (?kind= filter), trace correlation, and health. Domain *content*
is owned by the domain agents — this trial only exercises the coordination
integration surface.

SANDBOX / FIXTURE-TOKEN evidence only — NOT production verification.

Usage: API=http://127.0.0.1:8000 WEB=http://127.0.0.1:3000 \
       WRITE_TOKEN=smoke-write READ_TOKEN=smoke-read \
       python3 scripts/cross_domain_trial.py
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

DOMAINS = [
    ("threat_intel", "agent-ti"),        # Agent 2 (unavailable) / Agent 6 backup domain
    ("vuln_intel", "agent-vi"),          # Replacement Agent 3 domain
    ("frontend_e2e", "agent-frontend"),  # Backup Agent 4 domain
]

results = []


def call(base, method, path, body=None, token=None):
    req = urllib.request.Request(base + path,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
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
    ts = int(time.time())
    print(f"== CROSS-DOMAIN SANDBOX TRIAL @ {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} "
          f"(coordination-layer integration only; domain content owned by domain agents; NOT production) ==")
    tasks = {}
    for kind, agent in DOMAINS:
        # register the domain agent (idempotent)
        st, _, _ = call(API, "POST", "/api/v1/coordination/agents/register",
                        {"agent": agent, "specialization": kind}, W)
        check(f"[{kind}] register agent {agent}", st in (200, 201))
        # submit through the approved BFF write route
        st, t, hdr = call(WEB, "POST", "/api/v1/coordination/tasks",
                          {"kind": kind, "priority": 5, "title": f"cross-domain {kind} {ts}",
                           "payload": {"domain": kind, "trial": ts}})
        key = next((v for k, v in hdr.items() if k.lower() == "x-cicc-idempotency-key"), "")
        check(f"[{kind}] BFF write 201 + server key", st == 201 and key.startswith("bff-"),
              f"task={t.get('task_id')} key={key[:20]}...")
        tid = t.get("task_id")
        tasks[kind] = (tid, key)
        # drive lifecycle via API
        for ep, body in [("route", {"agent": agent}), ("deliver", None), ("ack", {}),
                         ("start", {}), ("progress", {"percent": 100}), ("complete", {"result": f"{kind}-done"})]:
            st, r, _ = call(API, "POST", f"/api/v1/coordination/tasks/{tid}/{ep}", body, W)
            check(f"[{kind}] {ep}", st == 200, f"state={r.get('state')}")
        # per-domain read visibility
        st, lst, _ = call(API, "GET", f"/api/v1/coordination/tasks?kind={kind}&limit=50", token=R)
        check(f"[{kind}] visible via ?kind= filter", st == 200 and any(x["task_id"] == tid for x in lst.get("tasks", [])))
        # trace correlation
        st, tr, _ = call(WEB, "GET", f"/api/v1/coordination/tasks/{tid}/trace")
        ok = (st == 200 and tr.get("correlation", {}).get("idempotency_key") == key
              and [e["kind"] for e in tr.get("events", [])][0] == "created"
              and any(e["kind"].endswith("->COMPLETED") for e in tr.get("events", [])))
        check(f"[{kind}] trace: correlation + created + COMPLETED", ok)

    # cross-domain health view
    st, h, _ = call(WEB, "GET", "/api/v1/coordination/health")
    agents = next((c for c in h.get("components", []) if c["key"] == "agents"), {})
    check("health shows 3 domain agents active", st == 200 and "3 active" in agents.get("detail", ""), agents.get("detail", ""))
    st, m, _ = call(API, "GET", "/api/v1/coordination/metrics", token=R)
    check("metrics by_kind covers all 3 domains",
          st == 200 and all(k in m.get("by_kind", {}) for k, _ in DOMAINS), str(m.get("by_kind")))

    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\n== CROSS-DOMAIN TRIAL RESULT: {passed}/{len(results)} PASS @ "
          f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} — SANDBOX/FIXTURE, coordination-layer only ==")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
