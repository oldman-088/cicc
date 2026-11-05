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

## 2026-11-05 — Milestone 11 (branch arena/961971ed-cicc, PR #4)

- M11-01 tests/test_m11_lifecycle.py (9 scenarios) — found+fixed: CREATED/
  VALIDATING missing EXPIRED transition (TTL sweep silently no-op'd);
  deliver with unmet deps now 409 (was 200 delivered:false). M7 deps test
  updated to 409.
- M11-04 github_sync: _get_pages (per_page=100, <=3 pages), transient retry
  in _get (5xx/429/URLError/timeout, never 4xx), full-body read (1MB cap
  truncated actions/runs JSON — live-caught), unit tests for all three.
- M11-02 contract v1.0 + PR comment; M11-05 tenant decision doc; M11-06 web
  broker chip + channel split (EN/AR 188).
- API 135/135 (7 real-PG + 1 live-GitHub live again after fix); web 17/17+tsc+build.

## 2026-11-05 — Milestone 12 (branch arena/961971ed-cicc, PR #4)

- M12-02 test_m12_integration.py (7 tests): E2E threat/vuln flows at HTTP
  boundary; dashboard contract shapes; LIVE github in view test. Fixes during
  authoring: handoff field is `event` (not `payload`); approval expiry = 410
  pre-sweep / 409 post-sweep (split into two cases).
- dead_letter query filter added (GET /tasks?dead_letter=...) for DL visibility.
- Adoption record from PR #1/#2/#3 branches (read-only): Agent 4 explicitly
  awaits path/DTO alignment; Agents 2/3 doc-level only. PR #4 comment with the
  dashboard endpoint list + visual verification request.
- API 142/142 (7 real-PG + 1 live-GitHub); web 17/17 + tsc + build; i18n 188/188.

## 2026-11-05 — Milestone 13 (branch arena/961971ed-cicc, PR #4)

- Read PR #4 comments: Agent 4 replied with 4 blockers -> answered on PR #4 +
  docs/API_REFERENCE.md (new read-side reference); fixed ops/coordination
  base-path inconsistency in INTEGRATION_CONTRACTS.md. Agents 2/3 silent.
- M13 boundary tests (8): found+fixed real defects — report endpoints now 409
  on non-applicable state (were 200); /events now includes task_id.
- Cross-domain routing isolation verified (caps subset; BLOCKED when no agent).
- Full regression: API 150/150 (7 real-PG + 1 live-GitHub); web 17/17+tsc+build.

## 2026-11-05 — Milestone 14 (branch arena/961971ed-cicc, PR #4)

- BFF: app/api/[...path]/route.ts + lib/bff.mjs; removed blind rewrite from
  next.config (handler owns /api/*). Unit tests tests/bff.test.mjs (6).
  Live: no-token read 200, client bogus Authorization stripped, POST 403,
  Sec-Fetch-Site cross-site 403 / same-origin 200, LIVE github via BFF ok.
- SECURITY_REVIEW §M14 webhook findings; CONTRACT_ADOPTION accepted/rejected/
  pending; PR #4 comment to Agents 2/3 (confirm) and Agent 4 (visual QA).
- API regression 150/150; web 23/23 + tsc + build; i18n 188/188.

## 2026-11-05 — Milestone 15 (branch arena/961971ed-cicc, PR #4)

- scripts/e2e_check.py: 22/22 PASS live (2026-11-05T10:14:51Z) — full
  coordination lifecycle + deps gate + approvals + BFF tokenless frontend
  reads + LIVE github; fixed two script bugs (missing write header on two
  submits). Actors labeled simulated — no Arena execution claimed.
- SECURITY_REVIEW §M15: BFF review; session architecture deliberately not
  implemented (must align with platform auth_sessions sha256 contract);
  webhook replay recap. CONTRACT_ADOPTION: all agents PENDING.
- API 150/150; web 23/23 + tsc + build; i18n 188/188.

## 2026-11-05 — Milestone 16 (branch arena/961971ed-cicc, PR #4)

- Master prompt: README.md on main @ ca8f82c (v1.0, 1384 lines) — reviewed
  read-only; alignment written to docs/MASTER_PROMPT_ALIGNMENT.md. Searched all
  branches for other prompt files — none. Not modified.
- test_m16_conformance.py (5, fixture-labeled): DTO conformance, state enum,
  error codes, webhook DTO + replay detection. Fixed webhook router missing
  commit (replay alert wasn't persisted).
- webhook.py: duplicate-delivery age check -> Alert webhook_replay_after_window
  (CICC_GH_MAX_REPLAY_AGE_S default 86400) — detection only.
- e2e_check.py: per-check mode labels; 22/22 PASS @10:28:12Z.
- API 155/155; web 23/23 + tsc + build; i18n 188/188.

## 2026-11-05 — Milestone 17 (branch arena/961971ed-cicc, PR #4)

- Evidence consistency: PR heads re-checked (PR#1 now d913cfa — M16's a1688bb
  was stale; PR#2 3462a8b; PR#3 1a46f70); file scans show no coordination-API
  references in any agent PR; CONTRACT_ADOPTION updated w/ timestamps.
- i18n: per-commit en.json counts 175/182/187/187... — the M14 "188" was a
  miscount; no key removed; en==ar parity holds every commit.
- test_m17_reliability.py (2): replay alert persists across simulated restart
  (file DB + fresh app), dedup holds (one task, one event row); fresh
  duplicate within window -> no alert.
- main still ca8f82c; README.md (master prompt v1.0) unchanged — re-confirmed.
- API 157/157 (7 real-PG + 1 live-GitHub); web 23/23 + tsc + build.
