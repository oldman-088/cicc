#!/usr/bin/env python3
"""REAL RabbitMQ verification procedure (supervised, live — never mocked).

Two independent REAL checks, run only against a reachable broker:

1. Management API (HTTP): GET /api/overview, /api/queues, /api/consumers via
   the same checks module the ops API uses. Prints real queue totals,
   consumer count, DLQ count.
2. AMQP 0-9-1 protocol (only when RABBITMQ_AMQP_URL is set): real TCP
   handshake, server-named exclusive queue declare, publish + basic_get
   roundtrip, queue delete. Proves the broker speaks AMQP, not just HTTP.

Required env:
  RABBITMQ_MANAGEMENT_URL  (e.g. http://localhost:15672 or http://rabbitmq:15672)
  optional RABBITMQ_USER / RABBITMQ_PASS
  optional RABBITMQ_AMQP_URL (e.g. amqp://guest:guest@localhost:5672/%2f)

Exit codes: 0 = PASS (all configured checks passed), 1 = FAIL, 2 = SKIP
(no broker configured). Run where a real broker is reachable, e.g.:
  docker compose -f docker-compose.yml -f docker-compose.verify.yml up -d
  cd apps/api && . .venv/bin/activate && \
    RABBITMQ_MANAGEMENT_URL=http://127.0.0.1:15672 \
    RABBITMQ_AMQP_URL=amqp://guest:guest@127.0.0.1:5672/%2f \
    RABBITMQ_USER=guest RABBITMQ_PASS=guest \
    python ../../scripts/verify_rabbitmq.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app import checks  # noqa: E402


def management_check() -> dict:
    checks.reset_circuit_breakers()
    return checks.check_rabbitmq()


def amqp_roundtrip(url: str) -> dict:
    """Real AMQP 0-9-1 publish/consume roundtrip on a server-named queue."""
    import pika  # verification-only dependency (requirements-dev.txt)

    params = pika.URLParameters(url)
    params.socket_timeout = 5
    params.connection_attempts = 2
    conn = pika.BlockingConnection(params)  # real protocol handshake
    try:
        ch = conn.channel()
        declared = ch.queue_declare(queue="", exclusive=True, auto_delete=True)
        qname = declared.method.queue
        body = b"cicc-verify-payload"
        ch.basic_publish(exchange="", routing_key=qname, body=body)
        method, _props, got = ch.basic_get(queue=qname, auto_ack=True)
        roundtrip = method is not None and got == body
        ch.queue_delete(queue=qname)
        return {
            "amqp_handshake": True,
            "server_named_queue": qname,
            "publish_get_roundtrip": roundtrip,
            "queue_deleted": True,
        }
    finally:
        conn.close()


def main() -> int:
    mgmt_url = os.getenv("RABBITMQ_MANAGEMENT_URL")
    amqp_url = os.getenv("RABBITMQ_AMQP_URL")
    if not mgmt_url and not amqp_url:
        print("SKIP: set RABBITMQ_MANAGEMENT_URL and/or RABBITMQ_AMQP_URL to a REAL broker.")
        print("No broker was contacted; nothing here is mocked.")
        return 2

    ok = True
    if mgmt_url:
        result = management_check()
        print("REAL management-API check:")
        print(json.dumps(result, indent=2, default=str))
        if result.get("status") != "ok":
            print("FAIL: broker management API not reachable/healthy")
            ok = False
        else:
            print(
                "PASS: management API reachable. queues={queues} consumers={consumers} "
                "messages_ready={messages_ready} dlq={dead_letter_queues}".format(**result)
            )
        print("NOTE: this verifies BROKER availability only — not workers, not Arena sessions.")

    if amqp_url:
        try:
            res = amqp_roundtrip(amqp_url)
            print("REAL AMQP 0-9-1 check:", json.dumps(res))
            if not (res["amqp_handshake"] and res["publish_get_roundtrip"]):
                print("FAIL: AMQP roundtrip failed")
                ok = False
            else:
                print(f"PASS: AMQP handshake + publish/get roundtrip on queue {res['server_named_queue']}")
        except Exception as e:  # noqa: BLE001 - report real failure, never fake pass
            print(f"FAIL: AMQP check raised: {type(e).__name__}: {e}")
            ok = False

    print("VERIFY RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
