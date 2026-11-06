#!/usr/bin/env python3
"""Benchmark the coordination task path end-to-end against a RUNNING API.

Usage:
  BASE_URL=http://127.0.0.1:8000 WRITE_TOKEN=... READ_TOKEN=... \
    python scripts/bench_coordination.py --tasks 50

Measures: create (POST /tasks), route, deliver, ack, start, complete —
latency p50/p95/max per step. LABEL: this is a LIVE benchmark against the
given URL (no mocks); set BASE_URL to a throwaway instance, not production.
"""
import argparse
import json
import os
import statistics
import time
import urllib.request

BASE = os.getenv("BASE_URL", "http://127.0.0.1:8000").rstrip("/")
W = {"Authorization": f"Bearer {os.getenv('WRITE_TOKEN', '')}", "Content-Type": "application/json"}
R = {"Authorization": f"Bearer {os.getenv('READ_TOKEN', '')}"}


def call(method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers=headers or W)
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            code, payload = r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        code, payload = e.code, json.loads(e.read() or b"{}")
    return code, payload, (time.perf_counter() - t0) * 1000


def pct(xs, p):
    if not xs:
        return 0.0
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p * len(xs)))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tasks", type=int, default=50)
    args = ap.parse_args()
    steps = {k: [] for k in ("create", "route", "deliver", "ack", "start", "complete")}
    fails = 0
    for i in range(args.tasks):
        code, p, ms = call("POST", "/api/v1/coordination/tasks",
                           {"kind": "bench", "title": f"bench-{i}", "payload": {"i": i},
                            "idempotency_key": f"bench-{i}"})
        steps["create"].append(ms)
        if code != 201:
            fails += 1
            continue
        tid = p["task_id"]
        for step, path in (("route", f"/api/v1/coordination/tasks/{tid}/route"),
                           ("deliver", f"/api/v1/coordination/tasks/{tid}/deliver"),
                           ("ack", f"/api/v1/coordination/tasks/{tid}/ack"),
                           ("start", f"/api/v1/coordination/tasks/{tid}/start"),
                           ("complete", f"/api/v1/coordination/tasks/{tid}/complete")):
            code, _, ms = call("POST", path, {"result": "ok"} if step == "complete" else None)
            steps[step].append(ms)
            if code not in (200, 201):
                fails += 1
    print(f"LIVE benchmark vs {BASE} — tasks={args.tasks} failed_calls={fails}")
    print(f"{'step':10} {'n':>4} {'p50_ms':>8} {'p95_ms':>8} {'max_ms':>8}")
    for k, xs in steps.items():
        print(f"{k:10} {len(xs):>4} {pct(xs, .5):>8.1f} {pct(xs, .95):>8.1f} {max(xs) if xs else 0:>8.1f}")
    m = call("GET", "/api/v1/coordination/metrics", headers=R)[1]
    print("metrics:", json.dumps({k: m[k] for k in ("tasks_total", "by_state", "deliveries_total")}))


if __name__ == "__main__":
    main()
