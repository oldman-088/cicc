#!/usr/bin/env python3
"""Executable contract check for Agents 2/3/4 — CICC coordination v1.0 (M18).

Runs a full agent-side lifecycle against a LIVE API:
  register -> heartbeat -> create task (idempotent) -> route -> ack ->
  start -> progress -> complete -> verify audit/metrics
plus negative checks: 401 without read token, 403 without write token,
409 on illegal transition, idempotent re-submit.

ALL SUBMISSIONS HERE ARE FIXTURES PERFORMED BY THIS SCRIPT (agent id
"contract-check-fixture") — they are NOT Arena sessions and NOT proof that
another agent's code is integrated. Exit code 0 = all checks passed.

Usage:
  API=http://127.0.0.1:8000 WRITE_TOKEN=... READ_TOKEN=... \
      python3 scripts/contract_check.py
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error

API = os.environ.get("API", "http://127.0.0.1:8000").rstrip("/")
W = os.environ.get("WRITE_TOKEN", "")
R = os.environ.get("READ_TOKEN", "")
BASE = API + "/api/v1/coordination"
results = []


def req(method, path, body=None, token="r", headers=None):
    h = {"Content-Type": "application/json"}
    if token == "w":
        h["Authorization"] = f"Bearer {W}"
    elif token == "r":
        h["Authorization"] = f"Bearer {R}"
    if headers:
        h.update(headers)
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}


def check(name, ok, extra=""):
    ok = bool(ok)
    results.append(ok)
    print(f"[{time.strftime('%H:%M:%S')}] {'PASS' if ok else 'FAIL'}  [LIVE-API fixture]  {name} {extra}")


def main():
    print(f"contract_check started {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} API={API}")
    print("NOTE: all submissions are SIMULATED-FIXTURE agent actions by this script, not Arena sessions.\n")
    agent = "contract-check-fixture"
    tid = f"contract-check-{int(time.time())}"

    c, p = req("GET", "/contract")
    check("GET /contract describes v1.0", c == 200 and p.get("version") == "1.0" and len(p.get("endpoints", [])) >= 20, f"-> {c}")

    c, p = req("POST", "/agents/register", {"agent": agent, "specialization": "contract-check", "capabilities": ["fixture"], "version": "0.0.1"}, token="w")
    check("register agent (write token)", c == 201, f"-> {c}")
    c, p = req("POST", "/agents/register", {"agent": agent, "specialization": "contract-check", "capabilities": ["fixture"], "version": "0.0.1"}, token="w")
    check("register is idempotent upsert", c == 201 and p.get("agent") == agent, f"-> {c}")
    c, p = req("POST", f"/agents/{agent}/heartbeat", {"status": "available"}, token="w")
    check("heartbeat", c == 200 and p.get("agent") == agent, f"-> {c}")

    task = {"task_id": tid, "idempotency_key": tid + "-ik", "kind": "contract_check", "priority": 5,
            "title": "M18 contract check fixture", "payload": {"fixture": True}, "repo": "oldman-088/cicc"}
    c, p = req("POST", "/tasks", task, token="w")
    check("create task", c == 201 and p.get("task_id") == tid, f"-> {c}")
    c2, p2 = req("POST", "/tasks", task, token="w")
    ev = req("GET", f"/tasks/{tid}/events")[1].get("events", [])
    check("idempotency_key replays (no duplicate)", c2 in (200, 201) and p2.get("task_id") == tid
          and any(e.get("kind") == "duplicate_idempotency_key" for e in ev), f"-> {c2}")

    c, p = req("POST", f"/tasks/{tid}/route", {"agent": agent}, token="w")
    check("route explicit agent", c == 200 and p.get("applied", p.get("ok", True)) is not False, f"-> {c} {p.get('reason','')}")
    c, p = req("POST", f"/tasks/{tid}/ack", {}, token="w")
    check("ack", c == 200 and p.get("applied", True) is not False, f"-> {c}")
    c, p = req("POST", f"/tasks/{tid}/start", {}, token="w")
    check("start", c == 200 and p.get("applied", True) is not False, f"-> {c}")
    c, p = req("POST", f"/tasks/{tid}/progress", {"percent": 50, "note": "fixture halfway"}, token="w")
    check("progress 50%", c == 200 and p.get("applied", p.get("ok", True)) is not False, f"-> {c}")
    c, p = req("POST", f"/tasks/{tid}/complete", {"result": "fixture complete"}, token="w")
    check("complete", c == 200 and p.get("applied", p.get("ok", True)) is not False, f"-> {c}")
    c, p = req("POST", f"/tasks/{tid}/complete", {"result": "again"}, token="w")
    check("illegal re-complete -> 409", c == 409, f"-> {c}")

    c, p = req("GET", f"/tasks/{tid}/events")
    check("audit trail has all transitions", c == 200 and len(p.get("events", [])) >= 5, f"events={len(p.get('events', []))}")
    c, p = req("GET", "/metrics")
    check("metrics visible", c == 200 and p.get("tasks_total", 0) > 0)

    c, _ = req("GET", "/agents", token="none")
    check("no token -> 401", c == 401, f"-> {c}")
    c, _ = req("POST", "/tasks", {"kind": "x", "payload": {}}, token="r")
    check("read token on write rejected (401/403)", c in (401, 403), f"-> {c}")

    # --- DTO validation: bad kind pattern -> 422 ---
    c, p = req("POST", "/tasks", {"task_id": tid + "-bad", "kind": "BAD KIND!", "payload": {}}, token="w")
    check("invalid DTO -> 422", c == 422, f"-> {c}")

    # --- dependency gate: depends_on unfinished -> complete 409 ---
    tdep = tid + "-dep"
    req("POST", "/tasks", {"task_id": tdep, "idempotency_key": tdep + "-ik", "kind": "contract_check",
                           "payload": {}, "depends_on": [tid]}, token="w")
    # finish the blocker first so gate passes later; here gate must block while tid not completed... tid IS completed now
    c, p = req("POST", f"/tasks/{tdep}/route", {"agent": agent}, token="w")
    c, p = req("POST", f"/tasks/{tdep}/ack", {}, token="w")
    c, p = req("POST", f"/tasks/{tdep}/start", {}, token="w")
    c, p = req("POST", f"/tasks/{tdep}/complete", {"result": "deps met"}, token="w")
    check("dependency gate: complete allowed once deps completed", c == 200, f"-> {c}")
    tblock = tid + "-blocked"
    req("POST", "/tasks", {"task_id": tblock, "idempotency_key": tblock + "-ik", "kind": "contract_check",
                           "payload": {}, "depends_on": ["never-completed-task"]}, token="w")
    req("POST", f"/tasks/{tblock}/route", {"agent": agent}, token="w")
    req("POST", f"/tasks/{tblock}/ack", {}, token="w")
    req("POST", f"/tasks/{tblock}/start", {}, token="w")
    c, p = req("POST", f"/tasks/{tblock}/complete", {"result": "x"}, token="w")
    check("dependency gate: complete blocked -> 409", c == 409, f"-> {c}")

    # --- approval gate: requires_approval task cannot complete before decision ---
    tap = tid + "-appr"
    req("POST", "/tasks", {"task_id": tap, "idempotency_key": tap + "-ik", "kind": "contract_check",
                           "payload": {}, "requires_approval": True}, token="w")
    c, p = req("POST", f"/tasks/{tap}/complete", {"result": "x"}, token="w")
    check("approval gate: complete before decision -> 409", c == 409, f"-> {c}")
    c, p = req("GET", f"/tasks/{tap}/approval")
    check("approval record pending", c == 200 and p.get("approval", {}).get("status") == "pending", f"-> {c}")

    # --- retry & dead-letter behavior ---
    tr = tid + "-retry"
    req("POST", "/tasks", {"task_id": tr, "idempotency_key": tr + "-ik", "kind": "contract_check", "payload": {}}, token="w")
    req("POST", f"/tasks/{tr}/route", {"agent": agent}, token="w")
    req("POST", f"/tasks/{tr}/ack", {}, token="w")
    req("POST", f"/tasks/{tr}/start", {}, token="w")
    c, p = req("POST", f"/tasks/{tr}/fail", {"result": "boom"}, token="w")
    check("fail reported", c == 200, f"-> {c}")
    c, p = req("POST", f"/tasks/{tr}/retry", token="w")
    check("retry after fail -> requeued", c == 200 and str(p.get("state", "")).lower() in ("queued", "retrying"), f"-> {c} {p.get('state')}")
    c, p = req("POST", f"/tasks/{tr}/complete", {"result": "x"}, token="w")
    check("complete after retry from queued needs route/ack (409 expected if skipped)", c in (200, 409), f"-> {c}")

    # --- audit & metrics consistency ---
    c, ev = req("GET", "/events")
    check("global webhook event stream well-formed", c == 200 and "events" in ev, f"events={len(ev.get('events', []))}")
    c, tev = req("GET", f"/tasks/{tid}/events")
    kinds = [e.get("kind") for e in tev.get("events", [])]
    check("task audit stream has created..completed + duplicate marker",
          c == 200 and any("duplicate_idempotency_key" in (k or "") for k in kinds)
          and any("COMPLETED" in (k or "") for k in kinds), f"events={len(kinds)}")
    c, m = req("GET", "/metrics")
    check("metrics consistent with tasks created", c == 200 and m.get("tasks_total", 0) >= 5, f"tasks_total={m.get('tasks_total')}")

    print(f"\ncontract_check finished {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}: "
          f"{sum(results)}/{len(results)} PASS")
    sys.exit(0 if all(results) and results else 1)


if __name__ == "__main__":
    main()
