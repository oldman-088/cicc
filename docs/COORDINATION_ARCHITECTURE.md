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


## v3 (Milestone 8)

- **LIVE GitHub API sync** (`app/coordination/github_sync.py`,
  `GET /github/status`, `POST /github/sync`): real calls to api.github.com
  (reachable egress), circuit-breaker guarded, rate-limit aware, token used
  header-only and never logged/returned. Creates coordination tasks for
  failed CI on arena/* branches (`ci_failed`, priority 2) and open PRs;
  idempotent via idempotency keys; check-runs endpoint falls back to
  workflow runs on 404. **Verified live in-sandbox**: probe ok, PRs #1–#4,
  20 check runs, sync created 4 PR tasks; API suite includes 1 live test
  (skips honestly if unreachable).
- **Progress reports**: `POST /tasks/{id}/progress {percent, note}` (0–100,
  audited event, stored on task).
- **Dependency DAG**: `GET /tasks/dag` → nodes+edges from depends_on.
- **OSS research decisions**: docs/OSS_RESEARCH.md (queues, orchestration,
  registries, approvals; reuse/adapt/reject rationale + re-evaluation triggers).
- **Security review**: docs/SECURITY_REVIEW.md (controls table + findings).
- Dashboard: live GitHub panel (PRs/issues/CI) in Coordination tab.


## v3.1 (Milestone 9 — hardening)

- **Webhook secret rotation**: dual-secret HMAC verification
  (`CICC_GH_WEBHOOK_SECRET` + `CICC_GH_WEBHOOK_SECRET_PREVIOUS`); rotation
  procedure in docs/SECURITY_REVIEW.md.
- **Retry backoff**: RETRYING tasks carry `next_retry_at = now +
  min(3600, CICC_COORD_RETRY_BACKOFF_S * 2^(attempts-1))`; the sweep only
  requeues them to QUEUED after the backoff elapses.
- **Task list filters**: `GET /tasks?state=&agent=&kind=`; responses include
  `progress` and `next_retry_at`. Dashboard task table shows a progress bar.


## v3.2 (Milestone 10 — programmatic enqueue + metrics + write rate limits)

- `POST /api/v1/coordination/tasks` — Agents 2/3/4 enqueue work programmatically;
  idempotent on task_id + idempotency_key; full field validation; contract in
  docs/INTEGRATION_CONTRACTS.md.
- `GET /api/v1/coordination/metrics` — aggregate honest counts (by state/kind,
  active per agent, avg progress, deliveries by outcome, dead letters,
  pending approvals, agents online/registered). Dashboard shows them as chips.
- All coordination write endpoints are now rate-limited per principal (429)
  in addition to the write-token gate.
- `scripts/bench_coordination.py` — LIVE end-to-end benchmark (create→route→
  deliver→ack→start→complete, p50/p95/max per step).


## v4 (Milestone 11 — integration & reliability proof)

- **M11-01**: full cross-agent lifecycle proven at the HTTP boundary
  (`tests/test_m11_lifecycle.py`, 9 scenarios): success w/ complete audit
  trail; approval enforced (409 deliver while waiting, 403 non-approver,
  reject→FAILED); delayed via `depends_on` (**deliver now returns hard 409**);
  duplicates (idempotency_key + webhook delivery); TTL expiry (**CREATED/
  VALIDATING → EXPIRED transition added** — sweep previously could not expire
  them); fail→RETRYING (backoff)→dead-letter→BLOCKED; RUNNING timeout.
- **M11-04**: GitHub sync hardened — paginated list endpoints (per_page=100,
  ≤3 pages), one transient retry (5xx/429/timeout/conn, never 4xx), full-body
  read (1 MB cap truncated large pages — live-caught), rate-limit guard kept.
- **M11-02**: contract v1.0 table (25 endpoints) + Agent 4 dashboard contract
  in INTEGRATION_CONTRACTS.md; confirmation requested on PR #4.
- **M11-06**: dashboard shows broker connected/unavailable chip and
  broker-confirmed vs human-assisted delivery split; failed fetches render
  as unavailable.


## v5 (Milestone 12 — cross-agent integration & operational readiness)

- **M12-01 adoption record** (`docs/CONTRACT_ADOPTION.md`): Agent 2 doc-level only,
  Agent 3 proposed-not-wired, Agent 4 awaiting path/DTO alignment (their PR #2 quotes
  our contract as unconfigured at c610917). Contract v1.0 unchanged; confirmations
  requested on PR #4.
- **M12-02 E2E** (`tests/test_m12_integration.py`): simulated Agent 2 (threat_intel)
  submits → central routes by capability → honest handoff payload → ack/progress/
  complete + full audit; simulated Agent 3 vuln task blocked (409) on depends_on
  until threat completes; Agent-4 dashboard payload shapes verified (agents/tasks/
  metrics/github-status; github part LIVE). Actors are labeled test fixtures —
  no Arena session execution claimed.
- **M12-03 reliability**: stale-agent sweep, approval expiry (410 pre-sweep /
  409 post-sweep), dead-letter visibility (`GET /tasks?dead_letter=true` + audit
  event), restart recovery (file DB, new app instance, state persists, sweep works),
  task timeout, duplicates — all covered by tests, every transition audited.


## v5.1 (Milestone 13 — integration stabilization)

- **Agent 4's 4 blockers answered on PR #4** (paths, auth/tenancy, DTOs/errors,
  frontend ownership); new `docs/API_REFERENCE.md` is the read-side reference
  (exact DTOs, error codes 401/403/404/409/410/413/422/429, cache semantics).
- **Boundary fixes from M13 tests**: report endpoints (ack/start/complete)
  now return **409** when the report doesn't apply to the current state
  (was 200 + audited "ignored"); `GET /coordination/events` items now include
  `task_id`; cross-domain capability isolation verified (threat task never
  routes to vuln-only agent; no capable agent -> BLOCKED, never misrouted).
- Boundary error contract is uniform: 404 unknown id, 409 illegal transition /
  deps unmet / waiting approval / no pending approval, 410 expired approval,
  401/403 auth gates, 422 validation, 429 rate limit — all audited where state
  is involved.
