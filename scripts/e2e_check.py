#!/usr/bin/env python3
"""M15 end-to-end integration check against LIVE running servers.

Usage:
  API=http://127.0.0.1:8000 WEB=http://127.0.0.1:3000 \
  WRITE_TOKEN=... python scripts/e2e_check.py

Flow (all real HTTP against the running API; the "Agent 2/3" actors are
SIMULATED submissions via this script — NOT Arena agent sessions):
  1. register simulated agent-2-threat-intel / agent-3-vuln-intel
  2. submit threat-intel task -> route (capability) -> deliver (honest
     human_assisted) -> ack -> progress -> complete; audit trail asserted
  3. submit vuln-intel task depends_on threat task -> 409 until COMPLETED
  4. approval flow: requires_approval task -> 409 deliver -> approve -> QUEUED
  5. frontend integration: read agents/tasks/metrics/events/github-status
     through the WEB BFF (:3000) with NO browser token (server-side injection)
  6. print PASS/FAIL per step with timestamps (evidence for PR #4)
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error

API = os.getenv("API", "http://127.0.0.1:8000").rstrip("/")
WEB = os.getenv("WEB", "http://127.0.0.1:3000").rstrip("/")
W = {"Authorization": f"Bearer {os.getenv('WRITE_TOKEN', '')}", "Content-Type": "application/json"}
R = {"Authorization": f"Bearer {os.getenv('READ_TOKEN', '')}"}

results = []


def call(base, method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers or R)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}


def check(name, ok, extra="", mode="LIVE-API"):
    """mode: LIVE-API = real HTTP to the running API; LIVE-BFF = real HTTP to
    the running web BFF (no browser token); SIMULATED-FIXTURE = submission by
    this script acting as a stand-in agent (NOT an Arena session)."""
    results.append((name, ok))
    print(f"[{time.strftime('%H:%M:%S')}] {'PASS' if ok else 'FAIL'}  [{mode}]  {name} {extra}")


def main():
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(f"E2E integration check started {ts}  API={API} WEB={WEB}")
    print("EXECUTION MODES: [LIVE-API]=real HTTP vs running API+its persistence; "
          "[LIVE-BFF]=real HTTP vs running web BFF (server-side token, no browser token); "
          "agent-2/3 actors are SIMULATED-FIXTURE submissions by this script — NOT Arena sessions. "
          "Real-PostgreSQL coverage is separate (pytest -k 'postgres or pg').\n")

    # 1. register simulated agents
    c, _ = call(API, "POST", "/api/v1/coordination/agents/register",
                {"agent": "agent-2-threat-intel", "capabilities": ["threat_intel"]}, W)
    check("register agent-2-threat-intel", c == 201, f"-> {c}", mode="SIMULATED-FIXTURE")
    c, _ = call(API, "POST", "/api/v1/coordination/agents/register",
                {"agent": "agent-3-vuln-intel", "capabilities": ["vuln_intel"]}, W)
    check("register agent-3-vuln-intel", c == 201, f"-> {c}", mode="SIMULATED-FIXTURE")

    # 2. threat-intel task lifecycle
    c, p = call(API, "POST", "/api/v1/coordination/tasks",
                {"kind": "threat_intel", "title": "e2e TTP mapping",
                 "payload": {"required_capabilities": ["threat_intel"]},
                 "idempotency_key": f"e2e-ti-{ts}"}, W)
    tid = p.get("task_id", "")
    check("submit threat_intel task", c == 201, f"-> {tid}")
    c, p = call(API, "POST", f"/api/v1/coordination/tasks/{tid}/route", headers=W)
    check("route by capability -> agent-2", p.get("agent") == "agent-2-threat-intel", str(p.get("agent")))
    c, p = call(API, "POST", f"/api/v1/coordination/tasks/{tid}/deliver", headers=W)
    check("deliver (honest human_assisted, no broker)",
          p.get("via") == "human_assisted" and p.get("delivered") is False)
    for step, body in (("ack", None), ("start", None), ("progress", {"percent": 100}),
                       ("complete", {"result": "ttps mapped"})):
        c, _ = call(API, "POST", f"/api/v1/coordination/tasks/{tid}/{step}", body, W)
        check(f"{step}", c == 200, f"-> {c}")
    c, p = call(API, "GET", f"/api/v1/coordination/tasks/{tid}")
    check("task COMPLETED with progress=100", p.get("state") == "COMPLETED" and p.get("progress") == 100)
    c, p = call(API, "GET", f"/api/v1/coordination/tasks/{tid}/events")
    kinds = [e["kind"] for e in p.get("events", [])]
    check("audit trail has full chain",
          all(k in kinds for k in ("created", "delivery:published", "progress", "state:RUNNING->COMPLETED")))

    # 3. vuln task depends_on threat task
    c, p = call(API, "POST", "/api/v1/coordination/tasks",
                {"kind": "vuln_intel", "title": "e2e CVE triage",
                 "payload": {"required_capabilities": ["vuln_intel"]}, "depends_on": [tid],
                 "idempotency_key": f"e2e-vi-{ts}"}, W)
    vid = p.get("task_id", "")
    call(API, "POST", f"/api/v1/coordination/tasks/{vid}/route", headers=W)
    c, _ = call(API, "POST", f"/api/v1/coordination/tasks/{vid}/deliver", headers=W)
    check("vuln task deliverable after dep COMPLETED", c == 200, f"-> {c}")
    # fresh dep-gate check with a new unfinished dep
    c, p = call(API, "POST", "/api/v1/coordination/tasks",
                {"kind": "threat_intel", "payload": {"required_capabilities": ["threat_intel"]},
                 "idempotency_key": f"e2e-dep-{ts}"}, W)
    dep2 = p.get("task_id", "")
    check("submit fresh dep task", c == 201 and dep2, f"-> {c} {dep2}")
    c, p = call(API, "POST", "/api/v1/coordination/tasks",
                {"kind": "vuln_intel", "payload": {"required_capabilities": ["vuln_intel"]},
                 "depends_on": [dep2], "idempotency_key": f"e2e-vi2-{ts}"}, W)
    vid2 = p.get("task_id", "")
    call(API, "POST", f"/api/v1/coordination/tasks/{vid2}/route", headers=W)
    c, _ = call(API, "POST", f"/api/v1/coordination/tasks/{vid2}/deliver", headers=W)
    check("deliver 409 while depends_on not COMPLETED", c == 409, f"-> {c}")

    # 4. approval flow
    c, p = call(API, "POST", "/api/v1/coordination/tasks",
                {"kind": "deploy", "title": "e2e approval", "requires_approval": True,
                 "idempotency_key": f"e2e-ap-{ts}"}, W)
    aid = p.get("task_id", "")
    check("requires_approval -> WAITING_FOR_APPROVAL", p.get("state") == "WAITING_FOR_APPROVAL")
    c, _ = call(API, "POST", f"/api/v1/coordination/tasks/{aid}/deliver", headers=W)
    check("deliver 409 while waiting", c == 409, f"-> {c}")
    c, p = call(API, "POST", f"/api/v1/coordination/tasks/{aid}/approve",
                {"decided_by": "owner"}, W)
    check("approve by configured approver -> QUEUED", c == 200 and p.get("state") == "QUEUED")

    # 5. frontend integration via BFF (no browser token)
    c, p = call(WEB, "GET", "/api/v1/coordination/agents", headers={})
    check("BFF: agents readable with NO browser token", c == 200 and len(p.get("agents", [])) >= 2, f"-> {c}", mode="LIVE-BFF")
    c, p = call(WEB, "GET", "/api/v1/coordination/tasks?kind=threat_intel", headers={})
    check("BFF: tasks readable", c == 200 and len(p.get("tasks", [])) >= 1, f"-> {c}", mode="LIVE-BFF")
    c, p = call(WEB, "GET", "/api/v1/coordination/metrics", headers={})
    check("BFF: metrics readable (real counts)", c == 200 and p.get("tasks_total", 0) > 0, mode="LIVE-BFF")
    c, p = call(WEB, "GET", "/api/v1/coordination/github/status", headers={})
    check("BFF: LIVE github status (real api.github.com)", c == 200 and p.get("status") == "ok",
          f"PRs={[x['number'] for x in p.get('open_prs', [])]}", mode="LIVE-BFF")
    c, _ = call(WEB, "POST", "/api/v1/coordination/tasks", {"kind": "x"}, headers={"Content-Type": "application/json"})
    check("BFF: write via browser -> 403", c == 403, f"-> {c}", mode="LIVE-BFF")

    failed = [n for n, ok in results if not ok]
    print(f"\nE2E finished {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}: "
          f"{len(results) - len(failed)}/{len(results)} PASS" + (f"; FAILED: {failed}" if failed else ""))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
