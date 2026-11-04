# RabbitMQ Live Verification — procedure, evidence policy, current status

## Policy

- Live broker verification is NEVER substituted with mocked results.
  Fixture-based parsing tests are labeled as fixtures; live checks use
  `scripts/verify_rabbitmq.py` against a real broker only.
- The ops API itself never claims broker→Arena-session control (documented
  boundary in MONITORING_CONTRACTS §6).

## Current status (2026-11-04, Arena sandbox)

- **NOT executed here**: the sandbox has **no Docker** and egress is restricted
  to github.com / codeload.github.com / api.github.com / registry.npmjs.org /
  pypi.org / files.pythonhosted.org — no VPS or broker host is reachable, and
  no VPS credentials exist in this environment. A real RabbitMQ broker cannot
  be started or reached from this sandbox. This is recorded honestly instead
  of simulated.
- What IS done: the full procedure + tooling are committed and ready to run
  in any environment with Docker (see below), and the management-API parsing
  is covered by a labeled fixture test (73/73 API tests green).

## Procedure (run where Docker exists)

```bash
docker compose -f docker-compose.yml -f docker-compose.verify.yml up -d rabbitmq
# wait for healthcheck, then:
cd apps/api && . .venv/bin/activate
RABBITMQ_MANAGEMENT_URL=http://127.0.0.1:15672 \
RABBITMQ_AMQP_URL=amqp://guest:guest@127.0.0.1:5672/%2f \
RABBITMQ_USER=guest RABBITMQ_PASS=guest \
python ../../scripts/verify_rabbitmq.py
# or the whole stack incl. secret scan:
VERIFY_RABBITMQ=1 bash scripts/validate_compose.sh
```

## What gets verified (real evidence to record)

1. Management API: `GET /api/overview` → status ok, queue_totals
   (messages_ready/unacknowledged/queues), `GET /api/queues` → queue count +
   DLQ detection (`x-dead-letter-exchange`), `GET /api/consumers` → consumer
   count; latency; circuit-breaker behavior on failure (CB opens after
   `OPS_CB_FAILURES`, recovers after `OPS_CB_COOLDOWN_S`).
2. AMQP 0-9-1 protocol: real handshake, server-named exclusive queue declare,
   publish → basic_get roundtrip, queue delete (pika, requirements-dev).
3. Failure handling: stop the broker → ops API reports component `unknown`
   (CB open) then `down` (probe fails), overview stays 200 (failure isolation);
   restart broker → `ok` again and a recovery event is logged.

## Evidence to attach when run

Paste the `verify_rabbitmq.py` output (management JSON + AMQP result + VERIFY
RESULT: PASS) and the compose validation log into PR #4 / this doc's history.
