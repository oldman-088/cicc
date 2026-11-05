# Operations Devlog — System Health & Operations subsystem

Running log; newest entries last. Checkpoint on interruption: this file +
`docs/OPERATIONS_BACKLOG.md` + PR #4 body describe exact state.

## 2026-11-04 — Milestone 4 (branch arena/961971ed-cicc, PR #4)

- Backend: maintenance windows (create/cancel/list, rule/component-scoped alert
  suppression, 422/401/404/409), task list + failure groups, throttled worker
  heartbeat history (60s samples), throttled retention purge (own 4 tables only,
  OPS_RETENTION_DAYS=30), additive idempotent indexes, recovery events.
- Auth: write token now satisfies read gate too (single-header writer clients).
- Verification tooling: bench_scale.py (real seeded scale numbers),
  verify_rabbitmq.py (real broker only), docker-compose.verify.yml,
  check_no_secrets.sh wired into validate_compose.sh. Docker NOT available in
  Arena sandbox → compose/broker verification is an external procedure.
- Web: Workers tab += recent task runs (25) + top failure groups (24h), EN/AR
  141 keys each, tsc clean, 17/17 tests, next build OK.
- Tests: API 65/65 (incl. 7 real-PG: 80-row concurrent writes, dead-engine down).
- Live smoke on uvicorn:8000 + next:3000 — all new endpoints verified direct +
  via proxy incl. error paths.
- Coordination: docs/APPS_INTEGRATION_STRATEGY.md (apps/ domain subdirs
  proposal); GitHub issue opened for heartbeat-contract alignment with the
  integration agent. Other agents' branches untouched.

## 2026-11-04 — Milestone 5 (branch arena/961971ed-cicc, PR #4)

- Alerting: escalation + flap detection (+ tests), additive columns, dashboard
  chips; notifications remain disabled.
- Perf: task-stats SQL aggregation (224ms→21ms p50 @20k rows), regression test.
- Auth: inspected VERIFIED platform contract on arena/da631853-cicc (read-only);
  implemented inert platform-auth adapter + role gates + conformance tests;
  wrote TENANT_ISOLATION_PLAN.md (scoping deferred to owner decision).
- RabbitMQ: sandbox has no Docker and no reachable VPS/broker (egress
  allowlist) — live verification recorded as blocked-external with exact
  procedure (RABBITMQ_VERIFICATION.md); AMQP roundtrip capability added to
  verify_rabbitmq.py (pika, dev-only dep); fixture parsing tests labeled.
- Coordination: issue #5 commented with final heartbeat/task contract +
  scripts/ops_client.py reference client; no other branches touched.
- API 73/73 (7 real-PG), web 17/17 + tsc clean.

## 2026-11-04 — Milestone 6 (branch arena/961971ed-cicc, PR #4)

- Ops M6: maintenance health state, escalation policy engine (time+occurrence,
  per-rule JSON overrides), alert owner/assign, worker registry, task attempts,
  tasks_per_min, per-principal write rate limit (auth before 429), notifications
  adapter (disabled by design, suppression events).
- Coordination M6 (new subpackage app/coordination + docs/COORDINATION_ARCHITECTURE.md):
  GitHub webhook (HMAC, fail-closed, replay dedup, secret stripping), durable
  task registry (validated 10-state machine + audit), routing engine (DB rules
  + defaults, BLOCKED on no match), handoff (real broker publish when
  configured, human-assisted otherwise, dead-broker fallback to RETRYING),
  agent reporting endpoints, dashboard tab. Kept on this branch per Arena
  session rules; splittable into its own PR later.
- Fixed: webhook exempt from read-token gate (HMAC-only auth); conftest resets
  write_limiter; registry events flush under autoflush=False.
- API 93/93 (7 real-PG), web 17/17 + tsc + build; live smoke full pipeline.
- Env-blocked (honest): real broker delivery/verification — no Docker/reachable
  broker in sandbox; procedures committed.

## 2026-11-04 — Milestone 7 (branch arena/961971ed-cicc, PR #4)

- Coordination v2 shipped (see COORDINATION_ARCHITECTURE.md): agents registry,
  explainable workload-aware routing, lifecycle v2 with audited transitions,
  approvals, delivery records w/ publisher confirms, webhook hardening.
- Ops: alert history endpoint, latency percentiles + retry_rate in task stats.
- Bugs found & fixed by tests/live smoke: missing approval record on webhook,
  tz-naive expiry compare, required_capabilities nesting, QUEUED->ACKNOWLEDGED
  policy gap, coord_tasks additive migration for pre-existing dev DB.
- API 107/107 (7 real-PG), web 17/17 + tsc + build; live smoke full lifecycle.
- Still environment-blocked: real RabbitMQ broker verification/delivery.

## 2026-11-04 — Milestone 8 (branch arena/961971ed-cicc, PR #4)

- OSS research documented (docs/OSS_RESEARCH.md): adapt patterns from
  Dramatiq/RabbitMQ (quorum+confirms), LangGraph/Temporal (state machine,
  interrupts≈approvals); reject whole-platform adoption at current scale.
- LIVE GitHub API sync implemented + verified live (api.github.com reachable):
  probe, PR/issue/check-run ingestion as tasks, idempotent, CB+rate-limit.
- Progress reports + DAG endpoint; SECURITY_REVIEW.md; root deliverable docs.
- Fixed: check-runs 404 fallback to actions/runs; sync idempotency on CI path;
  dag route shadowing; CB reset ordering in live test.
- API 112/112 (7 real-PG + 1 live GitHub), web 17/17 + tsc + build.

- M8 follow-up fix (live-smoke caught): sync-derived task_ids contained '/'
  from the repo slug, breaking path params — sanitized to REPO_ID; regression
  test added. API 113/113.

## 2026-11-04 — Milestone 9 (branch arena/961971ed-cicc, PR #4)

- Webhook dual-secret rotation (current + previous, fail-closed when both
  unset) with tests; rotation procedure added to SECURITY_REVIEW.md.
- Retry backoff: CICC_COORD_RETRY_BACKOFF_S exponential (cap 1h) as
  next_retry_at on RETRYING; sweep requeues only when elapsed (requeue_ready).
- GET /tasks filters (state/agent/kind); dashboard progress bar (EN/AR).
- Test fix: fail() lands in RETRYING via dead_letter below max attempts —
  backoff assertions adjusted accordingly. API 118/118.

## 2026-11-04 — Milestone 10 (branch arena/961971ed-cicc, PR #4)

- POST /coordination/tasks (programmatic, idempotent, validated) + GET
  /coordination/metrics; all coordination writes now per-principal rate
  limited; bench_coordination.py; dashboard metric chips (EN/AR 182).
- Fixed cross-test leak: test_milestone6 set write_limiter.limit=3 permanently;
  now monkeypatch-restored (was invisible until coordination writes were
  rate-limited). API 123/123.

- M10 live-smoke catches: metrics() used wrong column names (outcome/decision/
  status) -> fixed to status fields; API-created requires_approval tasks now
  also create the coord_approvals row (request_approval made idempotent —
  webhook path called it separately, caused MultipleResultsFound). Regression
  test strengthened to iterate non-empty tables. API 123/123.
