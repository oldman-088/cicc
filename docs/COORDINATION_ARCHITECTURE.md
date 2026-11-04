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


## v2 (Milestone 7)

- **Agent registry** (`coord_agents` + `/api/v1/coordination/agents/*`):
  register (idempotent), heartbeat with status (available/busy/draining/offline),
  deregister, stale detection (`CICC_AGENT_STALE_S`, default 300s, sweep marks
  offline), per-agent workload + completion/failure/retry stats. A registered
  agent is a live WORKER, never an Arena session.
- **Workload-aware routing v2**: explicit DB rules still win (explainable by
  rule name); otherwise deterministic scoring over eligible agents
  (not stale/offline/draining, all required capabilities) weighing active
  workload, busy status, specialization match, capabilities, completion rate,
  retry history, priority-vs-load. Every decision stores
  `routing_explanation` (reasons list) on the task. No eligible agent → BLOCKED.
- **Lifecycle v2**: canonical states CREATED, VALIDATING, QUEUED,
  WAITING_FOR_APPROVAL, ASSIGNED, DELIVERING, ACKNOWLEDGED, RUNNING, COMPLETED,
  FAILED, RETRYING, BLOCKED, CANCELLED, EXPIRED; legacy NEW/DELIVERED/
  IN_PROGRESS normalized (backward compatible). Explicit transition policy,
  every rejection audited. Tasks support owner, depends_on (delivery gated
  until deps COMPLETED), timeout_s, TTL expires_at (sweep → EXPIRED), cancel,
  retry, idempotency_key dedup, dead_letter after `CICC_COORD_MAX_ATTEMPTS`.
- **Approval workflow**: `requires_approval` payloads / review events enter
  WAITING_FOR_APPROVAL with a `coord_approvals` record; only
  `CICC_COORD_APPROVERS` may approve/reject (403 otherwise); approvals expire
  (`CICC_COORD_APPROVAL_TTL_S`); deliver is 409 while waiting; approve→QUEUED,
  reject→FAILED; all audited.
- **Delivery records** (`coord_deliveries`): every attempt recorded with
  channel/queue/message_id/status/error; with a real broker (`RABBITMQ_AMQP_URL`)
  we use durable queue + persistent message + **publisher confirms** and only
  then mark DELIVERING; without a broker the record is channel=human_assisted
  status=published and the task stays QUEUED — never "delivered" for a prepared
  message. Broker failure → RETRYING + fallback.
- **Webhook hardening**: event allowlist (`CICC_GH_EVENT_ALLOWLIST`), 256KiB
  body cap (413), JSON-object validation, signature + replay dedup unchanged,
  secrets stripped, non-allowlisted events recorded but never create tasks.
- **Ops M7**: per-component/per-rule alert history (`GET /ops/alerts/history`),
  task-stats latency percentiles (p50/p95/max) + `retry_rate`.
- Dashboard: agent registry table + routing explanations (EN/AR 168 keys).

Verified: API 107/107 (incl. 7 real-PG), web 17/17 + tsc + build; live smoke of
webhook→approval→route→deliver→ack/start/complete + sweep on :8000/:3000.
Still environment-blocked: real-broker delivery/confirm (no Docker/broker here).
