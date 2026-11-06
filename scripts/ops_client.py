#!/usr/bin/env python3
"""Reference ops client for integration agents (e.g. Agent 4).

Sends REAL heartbeats / task events to the ops API, conforming to the
contract in docs/MONITORING_CONTRACTS.md §5/§9 and coordination issue #5.

Env:
  OPS_BASE_URL     default http://127.0.0.1:8000
  OPS_WRITE_TOKEN  bearer token for writes (CICC_OPS_WRITE_TOKEN on the API;
                   when platform auth is enabled, a platform session token
                   with a write-allowed role is used instead)

Examples:
  python scripts/ops_client.py heartbeat --worker worker-01 --queue tasks --every 30
  python scripts/ops_client.py task --worker worker-01 --queue tasks --status success --duration-ms 42
  python scripts/ops_client.py task --worker worker-01 --queue tasks --status failed --error "boom"
  python scripts/ops_client.py heartbeat --worker worker-01 --dry-run   # prints payload, sends nothing
"""
import argparse
import json
import os
import sys
import time
import urllib.request

BASE = os.getenv("OPS_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
TOKEN = os.getenv("OPS_WRITE_TOKEN", "")


def _post(path: str, payload: dict, dry_run: bool) -> int:
    body = json.dumps(payload).encode()
    if dry_run:
        print(f"DRY-RUN POST {BASE}{path} Authorization: Bearer <token>\n{json.dumps(payload, indent=2)}")
        return 0
    req = urllib.request.Request(
        BASE + path, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 **({"Authorization": f"Bearer {TOKEN}"} if TOKEN else {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(resp.status, resp.read().decode())
            return 0
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}: {e.read().decode()[:200]}", file=sys.stderr)
        return 1


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("heartbeat")
    h.add_argument("--worker", required=True)
    h.add_argument("--queue", default="default")
    h.add_argument("--details", default="")
    h.add_argument("--every", type=int, default=0, help="loop every N seconds (0 = once)")
    h.add_argument("--dry-run", action="store_true")
    t = sub.add_parser("task")
    t.add_argument("--worker", required=True)
    t.add_argument("--queue", default="default")
    t.add_argument("--status", required=True, choices=["running", "success", "failed"])
    t.add_argument("--duration-ms", type=int, default=None)
    t.add_argument("--error", default=None)
    t.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.cmd == "heartbeat":
        payload = {"worker": args.worker, "queue": args.queue, "details": args.details}
        while True:
            rc = _post("/api/v1/ops/workers/heartbeat", payload, args.dry_run)
            if rc or args.every <= 0:
                return rc
            time.sleep(args.every)
    payload = {"worker": args.worker, "queue": args.queue, "status": args.status}
    if args.duration_ms is not None:
        payload["duration_ms"] = args.duration_ms
    if args.error:
        payload["error"] = args.error
    return _post("/api/v1/ops/tasks", payload, args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
