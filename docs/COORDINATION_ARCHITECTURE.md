# Central Autonomous Agent Coordination — architecture (M6, first implementation)

Scope note: Arena session rules tie this work to branch `arena/961971ed-cicc` /
PR #4, so the coordination system lives in `apps/api/app/coordination/` as a
separately reviewable subpackage. It can be split into its own PR later without
code changes.

## Pipeline

```
GitHub Events ──▶ POST /api/v1/coordination/webhook/github
                 (HMAC sha256 signature, fail-closed when secret unset;
                  replay-safe dedup by X-GitHub-Delivery; secrets stripped;
                  provenance kept in coord_github_events)
                      │ normalized canonical event
                      ▼
              Task Registry (coord_tasks + coord_task_events audit)
              states: NEW QUEUED DELIVERED IN_PROGRESS WAITING_FOR_APPROVAL
                      COMPLETED FAILED RETRYING BLOCKED (validated transitions)
                      │
                      ▼
              Routing engine (coord_routing_rules, priority-ordered JSON
              match on kind/event/labels; defaults by agent specialization;
              unmatched → BLOCKED, never silently dropped)
                      │
                      ▼
              Delivery: RabbitMQ per-agent queue `cicc.agent.<agent>`
              (durable, persistent, ONLY when RABBITMQ_AMQP_URL points at a
              real broker; publish failure → RETRYING + human-assisted)
              OR copy-ready handoff payload (task.handoff) for human-assisted
              handoff when no broker is configured
                      │
                      ▼
              Agent reporting: POST /tasks/{id}/ack|complete|fail
```

## Hard boundary (always stated in handoff payloads)

RabbitMQ / local workers distribute tasks; they do **NOT** launch or control
Arena sessions. No unauthorized Arena APIs, browser automation, or CAPTCHA
bypasses are used anywhere.

## API (all under read-token gate except the webhook)

| Endpoint | Notes |
|---|---|
| POST `/webhook/github` | HMAC-verified; 401 without `CICC_GH_WEBHOOK_SECRET`; dedup by delivery id |
| GET `/events` | ingested GitHub events w/ provenance |
| GET `/tasks?state&agent` | registry listing |
| GET `/tasks/{id}/events` | per-task audit history |
| POST `/tasks/{id}/route` | write-gated; runs routing engine |
| POST `/tasks/{id}/deliver` | write-gated; broker publish or human-assisted handoff |
| POST `/tasks/{id}/ack\|complete\|fail` | write-gated agent reporting |
| GET/POST `/rules` | routing rules CRUD (POST write-gated, 409 on dup name) |

## What is verified vs not

- Verified by automated tests (93/93 API suite) and live smoke: signature
  validation, replay dedup, secret stripping, state machine, routing
  (default + custom rules + BLOCKED), human-assisted handoff, dead-broker
  fallback to RETRYING (never false "delivered"), read/write gates, webhook
  exemption from the read gate.
- NOT yet live-verified: real RabbitMQ delivery (environment-blocked, same as
  ops broker verification — see docs/RABBITMQ_VERIFICATION.md). The publish
  path uses pika with durable queue + persistent messages and is only
  exercised when `RABBITMQ_AMQP_URL` is set.
- CI status (check_run) normalization is defined; wiring real CI events into
  routing is next.

## Next (coordination backlog)

1. Real broker delivery + consumer-side ack loop when a broker is reachable.
2. Workload/availability-aware routing (agent load from coord_tasks).
3. WAITING_FOR_APPROVAL flow for owner-gated tasks (e.g. destructive ops).
4. Dashboard: coordination tab shipped (M6); add agent workload + PR/CI joins.
5. GitHub App/webhook secret rotation procedure doc.
