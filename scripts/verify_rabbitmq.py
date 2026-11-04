#!/usr/bin/env python3
"""REAL RabbitMQ verification procedure (supervised, live).

Run where a real broker exists. Requires:
  RABBITMQ_MANAGEMENT_URL (e.g. http://localhost:15672)
  optionally RABBITMQ_USER / RABBITMQ_PASS

Performs REAL management-API calls (overview, queues, consumers) through the
same checks module the API uses, prints evidence, and exits non-zero if the
broker is not configured/reachable. Mocked responses are never used here.

Usage:  cd apps/api && . .venv/bin/activate && RABBITMQ_MANAGEMENT_URL=http://localhost:15672 python ../../scripts/verify_rabbitmq.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app import checks  # noqa: E402


def main() -> int:
    if not os.getenv("RABBITMQ_MANAGEMENT_URL"):
        print("SKIP: RABBITMQ_MANAGEMENT_URL not set — broker verification requires a real broker.")
        return 2
    checks.reset_circuit_breakers()
    result = checks.check_rabbitmq()
    print("REAL broker check result:")
    print(json.dumps(result, indent=2, default=str))
    if result.get("status") != "ok":
        print("FAIL: broker not reachable/healthy")
        return 1
    print("PASS: broker reachable, queue totals reported.")
    print("NOTE: this verifies BROKER availability only — not workers, not Arena sessions.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
