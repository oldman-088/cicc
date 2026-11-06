# CICC — Agent 1 Central Coordination & System Health/Operations Handover

**For:** incoming Lead Autonomous Engineer accountable for CICC integration and Beta delivery.
**Repository:** `oldman-088/cicc`
**Agent 1 branch:** `arena/961971ed-cicc` · **PR #4:** <https://github.com/oldman-088/cicc/pull/4>
**Snapshot date:** 2026-11-06 (GitHub times below are UTC).
**Scope:** technical handover plus M47 implementation in progress. This is not a merge, approval, production-readiness attestation, or permission to stop independent Agent 1 work.

> **Never put secrets in this document.** Environment variable names are listed without values. The initial handover verification was made at pre-publication HEAD `4a797f480377bc94fa8eec56ae692a8fc337db5d`; M47/handover edits were then uncommitted and the remote branch still pointed to that SHA. This document and M47 work are being published on the same authorized PR #4 branch. Since a commit cannot contain its own SHA, the authoritative *post-publication* head is `git rev-parse HEAD` / `gh pr view 4 --json headRefOid`; the final Agent 1 report records that exact SHA.

## 1. Repository, GitHub, and CI verification

### Agent 1 branch / PR snapshot

| Item | Verified value |
|---|---|
| Official repository | `oldman-088/cicc` |
| Current branch | `arena/961971ed-cicc` (do not rename or switch) |
| Pre-publication `HEAD` | `4a797f480377bc94fa8eec56ae692a8fc337db5d` (`Record M46 implementation commit in project state`) |
| Remote branch before this handover push | `origin/arena/961971ed-cicc` also pointed at `4a797f480377bc94fa8eec56ae692a8fc337db5d` |
| PR | [#4 — Agent 1: System Health & Operations Dashboard](https://github.com/oldman-088/cicc/pull/4) |
| PR state at review | `OPEN`, non-draft, base `main`, mergeable, `mergeStateStatus=CLEAN`, no review decision reported |
| PR #4 head at review | `4a797f480377bc94fa8eec56ae692a8fc337db5d` |
| Main at review | `ca8f82c0500637e22851d7128cddf99081ef3c08` |
| Working tree before publication | M47 code, tests and docs were modified/untracked; not yet published at that instant. They are part of this handover push, not unrelated user work. |

Refresh these values before acting; PRs and workflow runs move. The supported verification commands are:

```bash
git status --short --branch
git rev-parse HEAD
git ls-remote origin refs/heads/arena/961971ed-cicc
gh pr view 4 --json number,url,state,isDraft,headRefName,headRefOid,baseRefName,updatedAt,mergeStateStatus,reviewDecision,statusCheckRollup
gh pr checks 4
```

Do not merge PR #4, push to `main`, or modify other agents' branches/PRs. The handover was appended to the existing PR #4 body with the repository's guarded body updater so its prior milestone history is preserved.

### CI/workflow evidence

GitHub Actions reported these repository workflows as active: `CI`, `Frontend CI`, `VI candidate PostgreSQL`, `vuln-intel`, and `web-ci`. The Agent 1 checkout at the reviewed commit contains no `.github/workflows/` source tree, and no checks were attached to PR #4: `gh run list --branch arena/961971ed-cicc` returned no runs, `gh pr checks 4` reported no checks, `statusCheckRollup=[]`, and the commit's GitHub check-run count was zero. Therefore **no CI result is claimed for Agent 1's pre-publication HEAD**.

Latest relevant workflow runs visible at the review point (all are for other branches, not PR #4):

| Workflow | Observed run | Result / scope |
|---|---|---|
| `CI` | [41737737335](https://github.com/oldman-088/cicc/actions/runs/41737737335), 2026-11-03, branch `arena/da631853-cicc`, SHA `2dc1a7b2…` | Success on that other branch; not Agent 1 HEAD. |
| `Frontend CI` | [42213869662](https://github.com/oldman-088/cicc/actions/runs/42213869662), branch `arena/09952395-cicc`, SHA `e745cc2b…` | Success for Agent 4 PR #2 head; not PR #4. |
| `VI candidate PostgreSQL` | [42224836523](https://github.com/oldman-088/cicc/actions/runs/42224836523), branch `arena/93315d2c-cicc`, SHA `7136538f…` | Success for PR #3; does **not** run the 8 actual-host tests (0 executed / 8 skipped in the current PR #3 report). |
| `vuln-intel` | [42224686079](https://github.com/oldman-088/cicc/actions/runs/42224686079), branch `arena/fa0df787-cicc`, SHA `a942baab…` | Success for PR #1. |
| `web-ci` | [42045271331](https://github.com/oldman-088/cicc/actions/runs/42045271331), branch `arena/6a028355-cicc`, SHA `63a60646…` | Success for Agent 6 backup branch, not Agent 1. |

These are workflow outcomes, **not** cross-agent approvals, merged-app evidence, or production evidence. CI and PR heads must be refreshed after this publication; the final response reports what GitHub actually shows then.

## 2. Executive status

Agent 1 has implemented and tested a substantial coordination/control-plane and System Health/Operations service: audited agent/task lifecycle, GitHub webhook/sync, routing and approvals, human-assisted delivery, health/metrics/alerts/history, read-only coordination diagnostics, a read-gated domain gateway, restart-stat restoration, a Next.js operations dashboard and server-side BFF, plus backup/restore tooling.

M47 now hardens domain concurrency (unique expiring half-open probe leases and mount generations), makes the specified coordination GETs SQL-DML-free, exposes optional build revision diagnostics, adds regression tests, and prepares an exact-revision merged-app runner. M47 implementation has strong local tests, but **the exact merged application runner has not been run**: PR #1/#3 are open, the module-to-owner/source mapping is unresolved, and no owner-approved manifest or tenant driver exists.

This system is **not production-ready and not Beta-ready for real multi-tenant or sensitive intelligence data**. The API's bearer-token gates are optional environment gates, not verified user authentication. Tenant IDs are untrusted metadata. There is no deployed RLS, actor-specific data pool, or verified cross-tenant denial. The current domain modules are unmounted. Do not call any fixture, open-PR branch, codeload, standalone service, or synthetic test a merged application or production integration.

## 3. Architecture and runtime handover

### Service relationships

```text
Browser
  └─ relative /api/* calls (no browser-held Ops token)
       └─ Next.js server-side BFF (apps/web/app/api/[...path]/route.ts)
            └─ API_INTERNAL_URL → FastAPI (apps/api/app/main.py)
                 ├─ /api/v1/ops/*          health, checks, metrics, alerts, workers, history
                 ├─ /api/v1/coordination/* agents, tasks, routing, approvals, audit, domain gateway
                 └─ SQLAlchemy SessionLocal → DATABASE_URL (SQLite by default; PostgreSQL supported)

Coordination domain gateway → Agent 1 adapter → trusted, exact-revision module (currently NOT mounted)
```

`API_INTERNAL_URL` is used by the Next.js server, not by browser code. The browser uses relative URLs. The FastAPI lifespan calls `ops.init_db()`, restores persisted domain statistics, and disposes the engine on shutdown. There is no persistent worker/scheduler process in this Agent 1 service; health checks and some alert evaluation are on-demand. RabbitMQ is optional for autonomous background delivery; human-assisted handoff works without it and remains the default honest path.

### Entry points and commands

**API — verified local startup pattern:**

```bash
cd apps/api
.venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The API process was actually started in this sandbox from the branch with an isolated SQLite database and temporary test-only Ops tokens (not production credentials). M44 fixture trials were run through that live FastAPI process on an alternate port. For a new checkout, create/activate a venv and install `requirements.txt` first; never put credentials in shell history, this document, logs, or chat.

**Frontend — package-defined command (not restarted in this handover):**

```bash
cd apps/web
npm ci
npm run dev                 # next dev -H 0.0.0.0 -p 3000
```

For a production bundle, the package defines `npm run build` and `npm run start`; this handover reran `npm run typecheck` and tests, but did not rerun `npm run build` or deploy the production server. Set server-only BFF configuration in the deployment environment. Do not add `NEXT_PUBLIC_` credentials.

### Database/schema behavior

- `apps/api/app/db.py` reads `DATABASE_URL`; default is a local SQLite file. PostgreSQL is supported via SQLAlchemy and the configured PostgreSQL driver.
- `apps/api/app/ops.py:init_db()` calls `models.Base.metadata.create_all(bind=engine)` at startup. **There is no Alembic migration directory or migration ledger in this checkout.** `create_all` is not a safe schema-evolution/release migration strategy; the Lead must establish an approved versioned migration process before Beta schema evolution.
- Core models live in `apps/api/app/models.py`: Ops components/events/entities/vulnerabilities/campaigns/snapshots/alerts/workers/maintenance, coordination tasks/events/GitHub events/routing rules/agents/approvals/amendments/deliveries, and `CoordinationDomainStat`.
- Agent 1's M47 work adds **no database schema or migration**. Existing persisted task/event/domain-stat and ops histories remain in the configured database.
- `scripts/backup_restore.py` plus `docs/DISASTER_RECOVERY.md` provide a tested SQLite/PostgreSQL backup/restore utility/procedure; restoration still must be exercised against the intended deployment's exact schema and storage.

### Environment variable names (names only)

Never copy values from `.env`, `.env.example`, GitHub secrets, or shell environments. Main names used by the checked-out services include:

- Host/database: `DATABASE_URL`, `CORS_ORIGINS`, `API_INTERNAL_URL`, `API_PORT`, `WEB_PORT`, `CICC_BUILD_SHA`.
- API auth/configuration: `CICC_OPS_READ_TOKEN`, `CICC_OPS_WRITE_TOKEN`, `CICC_OPS_USE_PLATFORM_AUTH`, `CICC_PLATFORM_DB_URL`, `CICC_OPS_READ_ROLES`, `CICC_OPS_WRITE_ROLES`, `CICC_OPS_TRUSTED_SINGLE_TENANT`.
- BFF: `WEB_BFF_API_TOKEN`, `WEB_BFF_WRITE_TOKEN`, `WEB_BFF_ALLOW_COORD_WRITE`, `WEB_BFF_ALLOW_WRITES`, `WEB_BFF_ENFORCE_SAME_ORIGIN`.
- Coordination/GitHub/webhook: `CICC_COORD_APPROVERS`, `CICC_COORD_APPROVAL_TTL_S`, `CICC_COORD_LEASE_S`, `CICC_COORD_MAX_ATTEMPTS`, `CICC_COORD_RETRY_BACKOFF_S`, `CICC_AMENDMENT_STALE_S`, `CICC_AMENDMENT_ALLOW_SELF_APPROVAL`, `CICC_GH_REPO`, `GH_TOKEN`, `GITHUB_TOKEN`, `CICC_GH_WEBHOOK_SECRET`, `CICC_GH_WEBHOOK_SECRET_PREVIOUS`, `CICC_GH_EVENT_ALLOWLIST`, `CICC_GH_MAX_REPLAY_AGE_S`.
- Domain gateway: `CICC_DOMAIN_INVOKE_TIMEOUT_S`, `CICC_DOMAIN_INVOKE_RETRIES`, `CICC_DOMAIN_STALE_AFTER_S`, `CICC_DOMAIN_CIRCUIT_FAILURES`, `CICC_DOMAIN_CIRCUIT_COOLDOWN_S`, `CICC_DOMAIN_CIRCUIT_PROBE_LEASE_S`, `CICC_TI_MODULE_PATH`, `CICC_VI_PACKAGE_PATH`.
- Optional broker/ops: `RABBITMQ_AMQP_URL`, `RABBITMQ_MANAGEMENT_URL`, `RABBITMQ_USER`, `RABBITMQ_PASS`, `OPS_RATE_LIMIT`, `OPS_WRITE_RATE_LIMIT`, `OPS_RETENTION_DAYS`.
- M47 acceptance-only: `CICC_M47_DATABASE_URL`, `CICC_M47_TENANT_A_TOKEN`, `CICC_M47_TENANT_B_TOKEN`.

`CICC_OPS_TRUSTED_SINGLE_TENANT` is a declaration/contract hint, not enforcement. Setting optional tokens/platform auth does not create production identity or tenant isolation.

### Health, diagnostics, and traces

- `GET /live`: process liveness.
- `GET /ready`: DB-backed readiness; returns 503 when the DB check fails.
- `GET /health`: process and database health details.
- `GET /api/v1/ops/components`, `/api/v1/ops/overview`, `/api/v1/ops/metrics`, `/api/v1/ops/metrics/history`, `/api/v1/ops/activity`, `/api/v1/ops/alerts/history` and related Ops reads: token-gated only when configured.
- `GET /api/v1/coordination/health` and `/api/v1/coordination/diagnostics`: coordination health/status and sanitized diagnostics. M47 adds nullable `build_commit` from `CICC_BUILD_SHA`; this is only as trustworthy as the deployment setting.
- `GET /api/v1/coordination/domains`, `/api/v1/coordination/domains/{kind}/status`, `/api/v1/coordination/domains/metrics` and `GET /api/v1/coordination/tasks/{task_id}/trace` expose the domain lifecycle/metrics and task audit trace.
- **Side-effect caveat:** M47 makes the specified coordination GETs read-only at the SQL DML boundary. `GET /api/v1/ops/alerts` still evaluates rules and may persist derived alert state; use `/api/v1/ops/alerts/history` for history-only reads until the policy is changed separately.

### Dependencies and current runtime limitations

FastAPI, Uvicorn, Pydantic, SQLAlchemy, SQLite/PostgreSQL drivers; Next.js/React/TypeScript; `pgserver` supports isolated real-PostgreSQL tests. The optional RabbitMQ path uses publisher confirms when configured, but no broker was verified in this environment. GitHub REST sync/webhook is present; live sync was verified earlier in M8, not re-exercised during this handover. No Redis, Celery, distributed scheduler, tenant-aware connection pool, or production IdP integration is active in the Agent 1 host. Notifications are disabled by default. `apps/web/app/api/health/route.ts` reports backend reachability; it does not authenticate a user.

## 4. Agent 1 implementation inventory

Statuses refer to the checked-out Agent 1 branch and its tests, not to open PRs from other agents.

| Capability | Classification | Main files | Evidence / relevant commit anchors |
|---|---|---|---|
| Central coordination engine: task registry, 14-state lifecycle, guarded transitions, event history, approvals, DAG/dependencies, sweep/recovery, task retry/idempotency | **Implemented and tested** | `apps/api/app/coordination/{router.py,registry.py,approvals.py,amendments.py,contract.py}`; `apps/api/app/models.py` | M6 `478f820` / M7 `89e3a3c`; M28 recovery `a85845b`; M29 amendments `185150f`; M30 hardening `ba02302`; API and PostgreSQL suites. |
| Agent lifecycle, capability/workload routing, GitHub webhook HMAC/replay/allowlist, repo sync | **Implemented and tested; live GitHub sync historically verified, not rerun in this handover** | `apps/api/app/coordination/{agents.py,routing.py,webhook.py,github_sync.py}` | M7 `89e3a3c`; M8 live GitHub API sync `814ea2c`; current API suite. Webhook callbacks are HMAC/replay bounded; GitHub sync requires authorized env configuration. |
| Human-assisted task dispatch and execution tracking | **Implemented and tested** | `apps/api/app/coordination/{handoff.py,router.py,registry.py}` | M7/M28; no broker means copy-ready human handoff and task remains honestly not broker-delivered. RabbitMQ publisher-confirmed path is optional, not an Agent session launcher. |
| System Health & Operations API | **Implemented and tested locally** | `apps/api/app/{main.py,checks.py,ops.py,schemas.py,ratelimit.py,routers/ops.py}` | M1–M10; Ops health, component checks, metrics/history, alerts/history, workers, maintenance, task statistics, activity and system views; full API and PG suites. |
| Database models and persistence | **Implemented and tested; migration lifecycle incomplete** | `apps/api/app/{db.py,models.py,ops.py}` | M37 `f59223d`; tables created with `Base.metadata.create_all`; 42 PG-selected tests pass. No versioned migration tool/process in this checkout. |
| Next.js dashboard and server-side BFF | **Implemented and tested; reference UI, not full CICC product** | `apps/web/app/page.tsx`, `apps/web/app/api/[...path]/route.ts`, `apps/web/app/api/health/route.ts`, `apps/web/lib/bff.mjs`, `apps/web/components/*` | M14–M30 history; 35 Node tests and `npm run typecheck` pass in this handover. Dashboard reads Ops/Coordination; browser create-task is the approved narrow BFF write. No Agent1 domain lifecycle UI is wired in this checked-out tree. |
| Domain integration gateway and adapters | **Gateway implemented/tested; real modules candidate/unmounted** | `apps/api/app/coordination/{domains.py,router.py,domain_adapters/threat_intel_adapter.py,domain_adapters/vuln_intel_adapter.py}` | M35 `9d5669f`; lifecycle M37 `f59223d`; adapter M38/M39 `014a096`; M41–M46. No TI/VI handler auto-mounts at startup. Exact PR3/PR1 modules are not proven present or approved in this application checkout. |
| M47 leases, mount generations, stats/read-only GET | **Implemented and tested locally** | `apps/api/app/coordination/domains.py`, `apps/api/app/coordination/router.py`, `apps/api/tests/test_m47_reliability.py`, `apps/api/tests/test_m46_ops_reliability.py` | New M47 tests cover UUID expiring probe ownership, late callback rejection after lease supersession, remount/deregister outcome rejection, SQL-DML-free GETs and repeated persisted-stat restore. |
| M47 exact-revision acceptance gate | **Implemented/preflight tested; actual application run blocked** | `scripts/m47_merged_app_acceptance.py`, `apps/api/tests/test_m47_acceptance_preflight.py`, `docs/M47_MERGED_APPLICATION_ACCEPTANCE.md` | Requires clean exact app SHA, PR #1/#3 merge result reachability, exact module tree equality, owner-approved adapter/payload and actual host tests. Current no-manifest preflight returned `BLOCKED` before starting an API. |
| Diagnostics/metrics/traces/audit/recovery | **Implemented and regression-tested; contracts partly unapproved** | `apps/api/app/coordination/router.py`, `domains.py`, `registry.py`, `ops.py` | M42 `f96037b`; M43 `6c2c2a1`; M44 `2ef50e7`; M45 `5213c8b`; M46 `9bd9594`; M47 build SHA and lease metrics. Trace exposes task/event/idempotency correlations, not a verified actor or a full W3C tracing contract. |
| Backup/restore | **Implemented and historically tested** | `scripts/backup_restore.py`, `docs/DISASTER_RECOVERY.md`, `apps/api/tests/test_m36_backup_restore.py` | M36; SQLite and PostgreSQL round-trips were tested in prior milestone evidence; not rerun in M47 handover. |
| RabbitMQ, notifications, production platform auth, tenant isolation | **Optional/candidate/blocked** | `apps/api/app/coordination/handoff.py`, `apps/api/app/notifications.py`, `apps/api/app/platform_auth.py`, `docs/TENANT_AUTH_READINESS.md` | Human-assisted flow is supported; broker-confirmed delivery, outbound notification, real platform identity and tenant enforcement are not established. |

### Domain gateway semantics currently implemented

The Agent 1 callable contract is `handle(payload: dict, task) -> {"result": ..., "provenance": {"source", "produced_at", ...}}`. Inputs/outputs are validated; per-attempt timeouts and retries reuse the same idempotency key. The lifecycle distinguishes `NOT_MOUNTED`, `MOUNTED`, `AVAILABLE`, `EXECUTION_VERIFIED`, `DEGRADED`, `FAILED`, and `UNKNOWN`. A missing module is NOT_MOUNTED, not a fake healthy module.

M47's breaker uses a UUID half-open lease with monotonic expiry (`CICC_DOMAIN_CIRCUIT_PROBE_LEASE_S`, default 30s), reclaimed when a new probe is admitted; a stale lease callback cannot transition the current breaker. A per-mount UUID generation rejects late outcomes after remount/deregister. The domain GETs can restore stats into process memory but do not issue SQL DML. Volatile latency/circuit/lease counters remain process-local; the code is not distributed across replicas.

## 5. Security and integration status

| Security surface | Actual state in Agent 1 host | Owner / missing artifact | Minimum acceptance evidence |
|---|---|---|---|
| Authentication | `CICC_OPS_READ_TOKEN` / `CICC_OPS_WRITE_TOKEN` gates apply only when configured; write token also satisfies reads. With token vars absent, these dependency gates do not create auth. | Lead/platform security; choose IdP/session contract and safe deployment config. | Live API tests with missing/invalid/expired/revoked identity, least-privilege roles, rate limits, secret rotation and denied requests. |
| Verified user/service principal | `platform_auth.py` is optional/inert unless enabled; it checks an external `auth_sessions`/`users` schema and role allowlists, but route handlers do not receive a verified principal for tenant-scoped data/audit. | Platform-auth owner + Agent 1; approved schema/API and principal context propagation. | Signed/opaque session validation, issuer/audience or digest semantics, revoked/expired/disabled tests, principal passed through service calls; no body/header identity. |
| Tenant binding/isolation | `tenant_id` in domain invoke is recorded as a **claimed/unverified** event only. No row filter or policy is derived from it. `CICC_OPS_TRUSTED_SINGLE_TENANT` is a declaration, not enforcement. | Lead/security/DB owner; approve single-tenant deployment boundary or multi-tenant resolver. | Two distinct real principals/tenants, read/write cross-tenant denial, no side channels in metrics/diagnostics/traces, restart and concurrent tests. |
| Database roles/pools | Agent 1 data paths use one shared `engine`/`SessionLocal`. The optional platform-auth engine is for auth lookup, not actor-specific tenant data. | Security/DB + host owners; principal-bound pool factory, restricted role, lifecycle and rollback. | Tests prove each verified actor gets only its approved DB role/pool; privilege-denial tests on the real PG role. |
| RLS / shared schema | No Agent 1 RLS migration or M47 schema change. PR #3 SQL files are unmerged proposals; AMD-003 remains pending and owner-reserved. | Schema/security owner; formal approval, reviewed migration and rollback plan. | Apply only to an approved isolated DB; prove direct SQL, connection pooler, role switch, bypass-role and cross-tenant denials. |
| Authorization | Coarse read/write bearer gates, approver list and narrow BFF task-create path exist. No per-tenant/domain RBAC. The general BFF `WEB_BFF_ALLOW_WRITES` escape hatch can allow broader server-side writes; leave disabled unless separately threat-modeled. | Lead/security + Agent 4 for UI permissions. | Route-by-route positive/negative permissions and unauthorized BFF writes; verify client credentials/headers never reach the API. |
| Mount/import trust | `POST /domains/{kind}/mount` imports a server-local Python file. This executes trusted Python code; it is **not** a sandbox. | Agent 1/Lead; enforce operator-only mount, allowlisted paths/revisions or remove generic mount from untrusted surfaces. | Attempt path escape/unapproved module/tenant caller, verify rejection and audit; only pinned owner-approved module can mount. |
| Audit and transactions | Ops events and coordination task events persist. Gateway writes use SQLAlchemy sessions/commits and trace events; audit actor labels such as `api-write-token` are not verified identities. External handler side effects cannot be atomically rolled back with the host DB. | Security/DB + Agent 1/2/3; trusted actor, event schema, atomic audit/rollback and redaction. | Inject DB/audit failure; prove transaction outcome, no false success, retry/idempotency, tamper/access policy and correct actor/tenant attribution. |
| Error/trace contract | FastAPI commonly returns `{"detail": ...}`; domain status codes are documented, but there is no approved stable per-route envelope shared with frontend. Trace has task ID, event ID, idempotency key; no verified actor, tenant-scoped trace filter, or complete W3C `traceparent` contract. | Agent 1 + Agent 2/3 + Agent 4; approve codes, status, retryability, correlation/redaction. | Versioned error and trace contract tests across host/domain/BFF; unknown-code behavior and no sensitive leakage. |
| Limits/idempotency | Global POST body cap is 16 KiB; domain invoke also checks 64 KiB (the HTTP middleware cap is effective first). Ops/read/write rate limiters exist. Coordination task keys are persisted/idempotent; domain retries reuse caller's key; BFF generates a server-side task key. | Agent 1 + domain owners; agree budgets and per-principal limits. | Boundary tests, concurrent duplicate tests, retry-after-timeout/restart and bounded-resource tests. |

The route's internal SQL transaction is not a distributed transaction with a mounted module. A handler can have external side effects before a later database commit fails; current adapters are intended to be read-only and must be reviewed before use. No security mechanism above should be described as production-authenticated or tenant-isolated by itself.

## 6. Cross-agent integration inventory

### Agent 2 — Threat Intelligence

Current GitHub state is intentionally more nuanced than the legacy Agent 1 adapter docstring:

- PR #3 is currently the open **draft** `arena/93315d2c-cicc` branch at `7136538f74ab08b33607774c507785fc0c59cd03`. Its current description says Replacement Agent 3 owns full VI M51–M54, while the branch also contains `docs/handover/AGENT2_THREAT_INTELLIGENCE_HANDOVER.md`. That handover says the branch began as Agent 2 TI, then replacement Agent 3 work was assigned; both areas coexist. PR #6 is a separate Agent 6 backup, not a current Agent 2 source approval.
- Agent 2's handover identifies an **experimental standalone** relationship API: `apps/threat_intelligence/relationship_api.py`, relationship models/analysis/storage, and a separate `host_adapter.create_host_application`. Candidate route paths include `POST/GET /api/v1/threat-intelligence/relationships`, `GET /relationships/{relationship_id}`, and `POST /relationship-analysis/traverse` (prefix is subject to host approval). It requires a trusted `Principal(subject, tenant_id, permissions)` and callbacks for `resolve_principal`, `engine_for_principal`, durable `security_audit`, and optional `link_trace`.
- The handover explicitly says this subapplication is **not mounted** in Agent 1's actual host; the default principal dependency returns 503. Actual host tests are **0 executed / 8 skipped**. TI schema/role/RLS SQL is proposal-only. The one-shot CISA GitHub mirror collector and isolated PG tests are separate evidence; they do not establish a scheduled live connector, publisher authenticity, trusted host or production data flow.
- Critical compatibility mismatch: Agent 1's current `threat_intel_adapter.py` targets legacy `apps/threat_intelligence/api.py` / `ThreatIntelligenceAPI` and a simulated dispatcher. Agent 2's handover says that dispatcher is not a real HTTP API and must not be treated as the approved host. Do not mount it as TI production integration.
- **Required:** Lead/Agent 2 must select an exact source revision, confirm ownership and module/route path, approve the host mount and principal/DB/audit/trace/error/payload contract, and supply an isolated executable host harness. No approval is inferred from a handover document or CI run.

### Replacement Agent 3 — Vulnerability Intelligence / conflict / quality / SBOM

- PR #3's current draft body identifies Replacement Agent 3 and reports candidate VI evidence/quality/conflict/SBOM work. PR #1 is a separate original VI contribution and remains open; do not merge, reorder or choose a source without owner approval.
- PR #3's current report says its isolated-PG candidate suite passed **316** with **10** skips, while its actual Agent 1 host suite remains **0 executed / 8 skipped**. Agent 2's handover on the same branch reports a separate broader TI+VI run count; these test categories overlap and must not be combined. GitHub Actions for PR #3 are branch-local, not merged-app acceptance.
- The checked-out Agent 1 `vuln_intel_adapter.py` targets the older `packages/vuln_intel` package (historically PR #8/PR #1). Replacement Agent 3's current work is on PR #3 and is not shown to match that adapter/path. No VI domain is auto-mounted. `docs/vi_candidate_contracts/*` and branch SQL are not approved shared APIs/schema.
- **Required:** exact module source/entrypoint and adapters; eight real-host tests with verified host/PG harness, in addition to actual VI read/denial/data/error/trace tests; owner decisions for conflict/quality/SBOM operations and source-of-record; no shared schema or AMD-003 change without approval.

### Agent 4 — Frontend and UI/UX

- PR #2 is open at `e745cc2b8ff995b040896212eab2995607c48963`; its `Frontend CI` succeeded on that head. It includes candidate Agent 1 lifecycle/metrics/diagnostic TypeScript decoders under `apps/web/src/lib/contracts/agent1-domains.ts` and a readiness UI. Those files are **on PR #2**, not in the checked-out Agent 1 `apps/web/app` tree.
- PR #2's body says its readiness panel reads only configured Ops/Coordination resources and does not call Agent 1 lifecycle/diagnostics or the TI/VI routes. Its candidate types label errors and diagnostics unapproved. M47 adds nullable `build_commit` and `probe_inflight`, `probe_lease_expires_in_s`, `probe_lease_expirations`; no frontend implementation/test for these was run here.
- PR #2's body contains stale references to earlier Agent 1/2/3 heads. Refresh metadata before decisions. The checked-out Agent 1 dashboard tests do not establish Agent 4 UI readiness.
- **Required:** confirm additive/unknown-field handling, state/null/freshness/error/read-only semantics; update the candidate decoder for M47 fields; demonstrate real BFF→current backend→UI behavior and accessibility/localization states. Keep Agent 4's branch untouched and don't imply approval.

Detailed Agent 1 contract/readiness ledger: `docs/M47_CROSS_AGENT_CONTRACT_STATUS.md`. No other agent branch or PR was modified for this handover.

## 7. Test evidence and acceptance boundaries

### Verified locally in this handover

| Check | Result | Evidence class / notes |
|---|---|---|
| Full API test suite | **309 passed**, 2 existing warnings | Local Agent 1 checkout; SQLite/default pytest suite. Warnings: Starlette/AnyIO deprecation and existing test returning a value. |
| PostgreSQL-selected suite | **42 passed**, 267 deselected, 1 deprecation warning | Isolated `pgserver` tests; no shared/production database. |
| Web tests | **35 passed** | Checked-out Agent 1 Node test suite. |
| Web TypeScript typecheck | **passed** (`npm run typecheck`) | Checked-out Agent 1 web app. |
| M47 preflight/reliability set | **23 passed**, 1 deprecation warning | Lease/generation/read-only/restore and fail-closed exact manifest tests. |
| Live M44 fixture trial — clean SQLite | **17/17 passed** | Actual local FastAPI process, disposable clean SQLite and synthetic handler; SANDBOX/FIXTURE only. Trial requires API configured with failure threshold 3; no production claim. |
| Live M44 fixture trial — non-empty SQLite | **17/17 passed** | Same local app against a non-empty disposable DB; SANDBOX/FIXTURE only. |
| M47 no-manifest preflight | **BLOCKED**, exited 2 before app startup | PR #1/#3 open and no owner-approved manifest supplied. No merged-app tests ran. |
| API/web production build | Not rerun in this handover | `npm run build` is defined; do not represent it as a current test pass. |

The first M44 trial used the API's normal circuit threshold 5 while that legacy script expects threshold 3 for its final failure assertion, so it reported 16/17. Re-running clean and non-empty DB trials with `CICC_DOMAIN_CIRCUIT_FAILURES` configured to the script's expected 3 passed both 17/17. This was a trial-configuration mismatch, not a product-code failure; the trial docstring now explains it.

### Evidence that is explicitly *not* available

- No Agent 1 CI result for PR #4 at the pre-publication HEAD.
- No owner-approved exact module manifest, approved tenant driver, or exact merged application run.
- No actual Agent 2/3 host mount or approved host test; PR #3 currently reports 0/8 actual host tests.
- No production identity/RLS/tenant-isolation result.
- M44/M47 local fixture tests and branch-local CI are not merged-application or production evidence.

The reproducible exact-revision procedure is `docs/M47_MERGED_APPLICATION_ACCEPTANCE.md`; code is `scripts/m47_merged_app_acceptance.py`. It checks exact app commit, PR merge-result reachability, exact module subtree identity, real FastAPI startup, auth, diagnostics/metrics, trace/audit and a two-process restart. It returns INCOMPLETE without an approved tenant driver. It has **not** been run against a merged or approved application.

## 8. Beta readiness and minimum safe plan

### What can be demonstrated now

- Local Ops and Coordination API with a disposable SQLite or test PostgreSQL database.
- The checked-out reference dashboard reading health/Ops/Coordination data through a same-origin server-side BFF; a narrowly allowlisted browser task-creation path when its separate server-side configuration is explicitly enabled.
- Task/agent registration, routing, audit lifecycle, approvals, retry/sweep and copy-ready human handoff.
- Fixture domain mount/invoke and M47 breaker/metrics/read-only/restart behavior in a sandbox.

These are internal development/demo demonstrations. Domain modules remain unmounted in the normal Agent 1 host; the dashboard does not constitute a live TI/VI product; no tenant isolation or production authentication is established.

### Beta blockers (security cannot be deferred for real users/data)

1. **Identity/authentication and authorization:** select the platform auth contract, propagate a verified principal and implement route/resource-level permissions. Optional static Ops tokens are not user identity.
2. **Tenant boundary:** decide and enforce a single-tenant isolation boundary or implement approved principal→tenant binding, actor-specific DB pools/roles and RLS/DB separation; run real cross-tenant negative tests. Do not accept caller-supplied tenant IDs.
3. **Trusted audit and trace:** actor-attributed, redacted, durable audit for reads/writes and module actions; define transaction/failure semantics and correlation across host/domain/BFF.
4. **Migration/deployment lifecycle:** add owner-approved versioned migrations, repeatable configuration, secrets management, deployment health, backup/restore in the intended environment, and an actual Agent 1 CI check on PR #4.
5. **Domain integration:** resolve Agent 2/Replacement Agent 3 ownership, exact revisions, module API and error/payload contracts; run the eight actual host tests plus additional TI/VI reads/denials/provenance/trace/restart checks. Keep all unapproved schema proposals unapplied (AMD-003 pending).
6. **Exact application acceptance:** run the M47 runner on the final merged/explicitly approved checkout with a secrets-free manifest and approved tenant evidence; keep application, sandbox, unmerged branch and production claims distinct.

### Safe to postpone only by explicit product/owner decision

- RabbitMQ-backed autonomous background task delivery; human-assisted workflow is valid and broker confirmation remains distinct.
- 3D Command Theater and advanced visualization; not needed to prove the coordination/ops control plane.
- Live OSINT/VI provider synchronization without authorized keys/terms, advanced conflict execution, or full SBOM coverage; do not substitute synthetic data or claim live status.
- Persian/RTL and full product-wide UX beyond the existing tested English/Arabic reference surface; this is a whole-product requirement, not an Agent 1 completion.

### Prioritized lead plan

1. Recheck current branch/PR heads and review this document plus `PROJECT_STATE.json`, `MASTER_TASK_QUEUE.md`, `DEVELOPMENT_LOG.md`, `BLOCKERS.md` and `README.md` before merging anything.
2. Establish one explicit integration source-of-record and owner-approved host contract for Agent 2 TI and Replacement Agent 3 VI. Reconcile the legacy Agent 1 adapter mismatch, module paths, auth, DB pools, errors, payload budgets, audit/trace, frontend shape and role ownership. Do not alter their branches.
3. Convene security/DB owners on principal/tenant/RLS and migration strategy; decide whether Beta is single-tenant with hard isolation or multi-tenant with tested separation. Keep AMD-003 pending until explicit owner approval.
4. Add/enable CI for the Agent 1 branch and pin tests/migrations/build; run the eight real-host tests and additional domain/BFF integration tests against an isolated approved PG host.
5. Produce a final owner-approved exact revision manifest, execute M47 against the exact application checkout and module commits, then attach sanitized results to PR #4. Do not pass the tenant gate using synthetic tenant claims.
6. Only after security, data provenance, deployment/restore and acceptance gates pass, select a restricted internal Beta cohort. Defer optional broker automation/3D rather than weakening security.

## 9. Original Master Prompt alignment (required)

- **Exact source:** repository `README.md`.
- **Version:** `ULTIMATE MASTER PROMPT v1.0`.
- **Commit reviewed:** `4a797f480377bc94fa8eec56ae692a8fc337db5d` (the original file is unchanged from `main` `ca8f82c0500637e22851d7128cddf99081ef3c08`).
- **SHA-256:** `6249373bd3c19602b4a92f217afa3236ad18b5b51feea188bf1b791fbbb611d1`.
- I re-read the original prompt in full from the repository for this work. It was **not modified**.

Role-relevant objectives in the original include: central modular FastAPI services, PostgreSQL/transaction and migration discipline, environment-based secrets, authentication/RBAC/least privilege/tenant isolation, structured audit/health/metrics/monitoring, a multilingual accessible Next.js interface, integration/source provenance, recoverable backups, mandatory tests, project state/traceability, and no false claims. Relevant sections are §§2–3, 5.15–5.19, 10, 12–17.

| Original README scope (exact section) | Current Agent 1 evidence / classification |
|---|---|
| §1 Role: build, execute, test, secure, document and avoid false claims | **Applied within assigned Agent 1 scope.** This branch implements coordination/operations and the M47 reliability handover; the owner-authorized four-agent split means Agent 1 is not the CTO/implementer of every domain. |
| §2.2 objectives 1–4: collect, normalize/enrich, correlate, find relationships/patterns | **Not complete.** GitHub API synchronization is for coordination, not a live threat-intel source connector. No unified intelligence normalization/correlation/relationship graph is mounted in this Agent 1 host. |
| §2.2 objectives 5–8: investigations, AI decision support, live/history, evidence/provenance/confidence | **Partial.** Ops metrics/alerts/history and task traces exist; domain gateway preserves handler provenance/freshness/confidence fields for sandbox tests. No full investigation workspace, AI layer, or unified intelligence evidence lifecycle is implemented here. |
| §2.2 objectives 9–14: governance, organizations/tenants, immersive 3D, Arabic/English/Persian, modularity, deployment targets | **Partial/missing.** Ops governance/history and modular FastAPI/Next.js exist. No verified tenant isolation, 3D command environment, or Persian localization; English/Arabic parity is a tested reference-app property. Local/development deployment is documented; staging/production are not verified. |
| §3 preferred architecture: Next/React/TypeScript plus 3D/i18n; FastAPI/Pydantic/SQLAlchemy/Alembic/REST/WebSockets/workers; PostgreSQL/JSONB, Redis/object storage/migrations; CI/CD/monitoring | **Partial.** FastAPI/Pydantic/SQLAlchemy, Next/React/TypeScript, REST, SQLite-default operation, PostgreSQL tests, health/metrics and BFF are present. No Alembic/versioned migration ledger, Redis, graph DB, S3, continuous worker/scheduler, WebSocket, 3D framework, or Agent 1 CI run at the reviewed head. `create_all` is not production migration discipline. |
| §4 DOMAIN A — Command Center (items 1–9) | **Partial.** A local Ops dashboard, operational alerts/history, activity and task/worker views exist; global intelligence overview/map/3D threat landscape/mission management are not delivered as product modules. |
| §4 DOMAIN B — Threat Intelligence (items 10–24) | **Blocked/unmounted.** No approved live TI host/source in Agent 1. Current Agent 1 adapter targets a legacy simulated dispatcher; PR #3's experimental relationship API is not mounted and is not approved. |
| §4 DOMAIN C — Vulnerability Intelligence (items 25–33) | **Blocked/unmounted.** The Agent 1 VI adapter targets an older package; current Replacement Agent 3 PR #3 source/entrypoint is not proven compatible or approved. No live vulnerability integration claim. |
| §4 DOMAIN D — Investigation and Analysis (items 34–43) | **Missing as a product module.** Coordination task trace is operational task audit, not a case/evidence/investigation workspace or attack-path graph. |
| §4 DOMAIN E — Security Monitoring (items 44–50) | **Partial.** Ops health, event/activity history and alert rules/history exist; this is not full security-event/log management, detection authoring, anomaly detection or incident response. |
| §4 DOMAIN F — Intelligence Collection (items 51–59) | **Missing/unverified.** GitHub coordination sync does not satisfy OSINT/feed/API threat-source collection. No current live ingestion connector or source-completeness claim. Demo data remains labeled. |
| §4 DOMAIN G — Organizational Security (items 60–69) | **Partial/missing.** Ops/admin and maintenance exist; no full asset inventory, attack-surface/third-party exposure, risk/compliance register, executive intelligence reporting or organization administration suite. |
| §5 extensions 5.1–5.14 and 5.19–5.20 (fusion, trust, provenance graph, intelligence requirements, third-party/SBOM/business impact, memory/pattern/gap/simulation, 3D/spatial, federation, benchmark) | **Not implemented as an integrated CICC capability in Agent 1.** Gateway provenance is an interface/evidence field, not the §5.3 provenance graph. Other agents' candidate PR code is not Agent 1 approval or merged integration. |
| §5.15 Zero Trust; §5.16 AI governance; §5.17 Audit/compliance; §5.18 Disaster recovery | **Partial.** Some coarse API/BFF gates, audited coordination transitions and backup/restore tools/tests exist. Strong auth/RBAC/tenant isolation, model registry, auth/data-access audit/compliance evidence and deployment-specific DR readiness remain missing or owner-blocked. |
| §6 unified intelligence knowledge graph | **Missing.** No unified tenant-scoped entity/relationship schema or graph across the listed intelligence domains. No shared migration was applied. |
| §7 real data/integrations and integrity | **Partial.** Demo/experimental labeling and provenance honesty are implemented in gateway tests; no complete live source connector fleet, sync coverage or real-source freshness is claimed. |
| §8 AI intelligence engine/governance | **Missing.** No provider-backed AI summarization, investigation, contradiction, prioritization, or model-governance service is claimed. |
| §9 3D design system and i18n | **Partial/missing.** Agent 1's tested reference frontend provides English/Arabic basics; Persian, product-wide localization, immersive 3D, interactive intelligence graph and full design-system requirements are not complete. |
| §10 Security requirements | **Partial, with Beta blockers.** Validation, rate limits, redaction, optional tokens, BFF server-side credential handling and task audit exist. Secure login/MFA/revocation, route/resource RBAC, trusted tenant boundary, secure uploads/quarantine, trusted data-access audit and full security test evidence are not established. |
| §11 project structure | **Adapted, not copied.** Existing `apps/api` + `apps/web`, `packages`, `docs`, `scripts` are preserved under the prompt's instruction to adapt a useful established repository; missing service/database/infrastructure split is not silently represented as implemented. |
| §§12–15 recovery, task management, execution/testing, Git discipline | **Applied to Agent 1 scope.** This handover, project state, task queue, development log, blockers, traceability, test evidence and branch restrictions are updated; original README and other branches were not changed. |
| §16 automated continuation/orchestration | **Not claimed.** Agent sessions/background orchestration are not implemented as a product capability. Human-assisted task handoff is supported; RabbitMQ automation is optional and unverified. |
| §17 Definition of Done | **NOT MET.** Product, data, tenant-security, integration, build/deploy and release criteria remain incomplete; no production readiness is claimed. |
| §18 final directive | **Applied within permissions and scope.** Inspected current repository/PR state, implemented code/tests/docs, and continued independent Agent 1 work without waiting on PR #1/#3, modifying another agent's work, or inventing functionality. |

For exact §5 name-to-status traceability, the prompt's 20 extensions are: Intelligence Fusion & Decision Engine; Confidence & Trust Framework; Provenance Graph; Intelligence Requirements Management; Third-Party Risk Intelligence; SBOM Intelligence; Business Impact Intelligence; Knowledge Memory; Pattern Discovery; Gap Analysis; Impact Simulator; 3D Command Theater; 3D Investigation Replay; Spatial Workspace; Zero Trust Architecture; AI Governance & Model Registry; Audit & Compliance; Disaster Recovery; Federated Intelligence Network; Intelligence Benchmark. Only a partial operations/audit/recovery foundation exists in Agent 1; none of the full intelligence, AI, graph, 3D, federation or benchmark capabilities is claimed complete.

Deviations are deliberate and documented: this is the existing four-agent split and `apps/api` + `apps/web` architecture, not a rewrite of the prompt; the current dashboard is not presented as a complete CICC product; RabbitMQ remains non-blocking for human-assisted workflows; demo/unmerged data is labeled; AMD-003 is unapplied. The whole product does **not** meet the prompt's production Definition of Done.

## 10. Key files and further reading

- `apps/api/app/main.py`, `db.py`, `models.py`, `ops.py`, `routers/ops.py`, `ratelimit.py` — FastAPI host, DB lifecycle, models, Ops routes and gates.
- `apps/api/app/coordination/` — coordination router, registry, agents, routing, approvals/amendments, webhook/GitHub sync, handoff, domain lifecycle, adapters.
- `apps/web/app/` and `apps/web/lib/bff.mjs` — checked-out reference UI and BFF (distinguish from PR #2's open `apps/web/src/` additions).
- `docs/DEPLOYMENT.md`, `docs/DOMAIN_STATUS_CONTRACT.md`, `docs/TENANT_AUTH_READINESS.md`, `docs/DISASTER_RECOVERY.md`, `docs/INTEGRATION_MATRIX.md` — current operational/contract limitations.
- `docs/M47_MERGED_APPLICATION_ACCEPTANCE.md`, `docs/M47_CROSS_AGENT_CONTRACT_STATUS.md` — M47 gate and cross-agent ledger.
- `docs/MASTER_PROMPT_ALIGNMENT.md`, `PROJECT_STATE.json`, `MASTER_TASK_QUEUE.md`, `DEVELOPMENT_LOG.md`, `BLOCKERS.md` — project recovery/ownership record.

**Incoming lead: start with a fresh `git status` and PR #4 head check. Keep the branch open, do not merge yourself, do not reset user/agent work, do not expose credentials, and do not convert a sandbox or unmerged branch result into a Beta/production claim.**

## Publication and final verification addendum

The detailed handover was published with M47 implementation commit `7e480d26be3b07515b6bc63b722f5b61b37e43f4`; a project-state refresh followed in commit `42e0aa0849d9d1f5579078ea7b3b512c461d8656`. At the final GitHub verification of that state-refresh head:

- Local branch and `origin/arena/961971ed-cicc` both resolved to `42e0aa0849d9d1f5579078ea7b3b512c461d8656`; the worktree was clean.
- PR #4 was **OPEN**, non-draft, based on `main`, `mergeStateStatus=CLEAN`, with empty `statusCheckRollup` and no review decision. `gh pr checks 4` reported no checks; `gh run list --branch arena/961971ed-cicc` returned `[]`. This is no Agent 1 CI run, not a CI pass.
- The PR body update was verified: the existing 46,345-character description was preserved and extended with `## M47 Lead Handover`; the section links this document and summarizes tests, blockers, and evidence boundaries.
- `main` remained `ca8f82c0500637e22851d7128cddf99081ef3c08`. Read-only heads: PR #1 `a942baabc3260683ec1a2b8c9d953c04dceaae9a` OPEN; PR #2 `e745cc2b8ff995b040896212eab2995607c48963` OPEN; PR #3 `7136538f74ab08b33607774c507785fc0c59cd03` OPEN/Draft; PR #6 `02616bb5a34bc0dfa6beaee598948b09b7ba1127` OPEN. No other branch or PR was modified.
- Other-branch Actions evidence remains separate: PR #1 `vuln-intel` run `42224686079` succeeded; PR #2 `Frontend CI` run `42213869662` succeeded; PR #3 `VI candidate PostgreSQL` run `42224836523` succeeded. None is an Agent 1 PR #4 check or actual-host acceptance.

These are timestamped observations, not a guarantee that GitHub metadata stays unchanged. Always use the commands in §1 immediately before an integration or merge decision. The handover changes do not merge PR #4 or alter `main`.

## M48 — CI and whole-product completion status (2026-11-06)

- Product-code evidence baseline: `157645e9d46bef4c120ff46fc3028320971fe286` on `arena/961971ed-cicc` / PR #4. Added `.github/workflows/agent1-ci.yml` for full API, PostgreSQL-selected, Web tests, typecheck and production build; runner/action versions pinned to Ubuntu 24.04, setup-node v7 and Node 22.
- Verified locally: API 309/309 (two existing warnings), PostgreSQL-selected 42/42 (267 deselected; one warning), Web 35/35, typecheck PASS, production Next.js build PASS. GitHub PR run `42246801975` and push run `42246787299` each passed all three jobs. PR #4 is OPEN/CLEAN; no review approval/merge is implied.
- Re-ran exact-revision runner `scripts/m47_merged_app_acceptance.py --checkout .`: exit 2 / BLOCKED because no owner-approved exact source/module/host/tenant manifest exists; it started no app. PR #1/#3 remain open. Do not label isolated suite results as merged-app/production acceptance.
- **M48 ownership statement corrected by M49:** exact-head records support PR #1 = original Agent 3 VI and PR #3 = replacement Agent 3 VI with earlier Agent 2 TI history. PR #1's current handover says its earlier commissioning brief was inverted; the M48 report incorrectly described the current handover as reversing roles. Both branches remain untouched. Shared-account public records do not independently authenticate human identity. Correction and current evidence are at PR #1 comment `6689778670` and `docs/M49_CROSS_AGENT_INTEGRATION_REVIEW.md`; M49 follow-ups are PR #3 comment `6689783355` and PR #2 comment `6689786705`.
- The PR #1 CI job passed with a host-branch fetch and no-skip guard; its handover reports 6/6 actual-host checks, but raw logs/count could not be retrieved in this audit and this is not full merged-app acceptance. PR #3 CI explicitly excludes live/actual-host tests; handover remains 0/8.
- `docs/handover/CICC_PROJECT_COMPLETION_STATUS.md` is the whole-product status source: **29%** weighted integrated Beta estimate, candidate code scored separately, tenant-isolation acceptance 0%, no production-readiness claim. Original README Master Prompt v1.0 remains byte-unchanged; AMD-003, production auth and tenant isolation remain pending.

## M49 continuation — current code, alignment and handover (2026-11-06)

### Current Agent 1 branch evidence

- Tested code commit `e1122bd3aed644af8607bd0873f1863a2a2edf94` was pushed to `arena/961971ed-cicc` / PR #4. The code adds a read-only Coordination panel for domain gateway lifecycle/probe evidence, a fail-closed client normalizer and declaration, five Web tests, a disposable API-to-production-BFF smoke, and a workflow step that runs the smoke after the production build.
- At the 2026-11-06 16:45 UTC verification snapshot, PR #4 head was docs commit `4e8da4da2d7e4c11fef72705211aa76b1d955866`. After the M49 docs were pushed, PR run `42255068598` and push run `42255057408` each passed all three CI jobs (API, PostgreSQL-selected, Web/typecheck/build plus BFF smoke); PR #4 was OPEN/CLEAN with no review decision.
- Local evidence: Web **40/40**, typecheck and production build **PASS**; API **309/309**; PostgreSQL-selected **42/42**; `scripts/m49_domain_gateway_smoke.py` **PASS**. GitHub PR run [42252536511](https://github.com/oldman-088/cicc/actions/runs/42252536511) and push run [42252527313](https://github.com/oldman-088/cicc/actions/runs/42252527313) each passed all three jobs; Web job includes `Verify domain gateway through the production BFF`.
- The smoke uses a temporary API DB/tokens and a production Next.js server. Direct no-token API read returned 401; relative BFF reads returned 200 without browser credentials; cross-site GET and POST returned 403; no TI/VI handler was mounted; no server credential appeared in returned status/metrics. This is isolated PR #4 behavior, not production identity, tenant isolation, or a live data feed.
- The panel reads only the existing authenticated `/api/v1/coordination/domains` and `/api/v1/coordination/domains/metrics` endpoints through the server-side BFF. It displays TI/VI as `NOT_MOUNTED` when absent; malformed responses are unavailable and inconsistent/unknown states fail to `UNKNOWN`. No API schema, DB schema, migration, other branch, or data route changed.

### Master Prompt status and cross-agent corrections

- Re-read `/home/user/cicc/README.md` directly: **ULTIMATE MASTER PROMPT v1.0**, revision `ca8f82c0500637e22851d7128cddf99081ef3c08`, SHA-256 `6249373bd3c19602b4a92f217afa3236ad18b5b51feea188bf1b791fbbb611d1`; source unchanged. Full requirement-by-requirement status is `docs/M49_MASTER_PROMPT_REQUIREMENT_STATUS.md` (all 14 objectives, 69 modules, 20 extensions, deliverables, §§2–18 and §17 DoD).
- Exact current PR #1/#3 heads support the working role map PR #1 = original Agent 3 VI and PR #3 = replacement Agent 3 VI with earlier Agent 2 TI history. The M48 claim that the current PR #1 handover reversed these roles was wrong; it was the earlier commissioning brief that was inverted. Public records share one account and do not independently authenticate a human's identity. Full review: `docs/M49_CROSS_AGENT_INTEGRATION_REVIEW.md`; public correction at PR #1 comment `6689778670`.
- PR #1 contains migration `0043_vuln_intel_records.py`, marked unapplied by its current handover, despite the current PR-body claim that no migration exists. Do not apply/adapt it without owner, AMD-003 and schema approval. PR #1's six claimed actual-host tests use a floating host ref and test direct host callbacks/handler/middleware; they do not mount the candidate API or establish persistence through the current Agent 1 app. PR #3 actual-host tests remain **0/8 executed**.
- M49 requests are posted at PR #3 comment `6689783355` (TI/VI owner-scope evidence) and PR #2 comment `6689786705` (own-branch tolerant/accessibility UI work). No response or owner approval was observed. These are requests, not acceptance.

### Current blockers and next lead actions

- The exact-revision acceptance runner remains fail-closed/BLOCKED pending owner-approved application/source/module/host/tenant/auth/DB/audit/trace manifest and executable isolated host harness. No candidate branch test or M49 smoke substitutes for it.
- Production principal/auth, tenant resolver/pool/RLS/cross-tenant acceptance, AMD-003 and schema/migration approval remain unavailable; tenant-isolation acceptance is **0%**. Do not claim production authentication, tenant isolation or Beta acceptance.
- M49 does not integrate TI/VI or update their integrated score. Whole-product integrated Beta estimate remains **29%**. Detailed current records: `docs/handover/CICC_PROJECT_COMPLETION_STATUS.md`, `docs/MASTER_PROMPT_ALIGNMENT.md`, `REQUIREMENTS_TRACEABILITY.md`, `BLOCKERS.md`, `RELEASE_READINESS.md`, `docs/INTEGRATION_MATRIX.md`, `PROJECT_STATE.json`, and M49 development/operations logs.
- Continue only on `arena/961971ed-cicc`; preserve PRs #1/#3 and all other branches; wait for owner approval before any reserved schema, auth, host or tenant work. Recheck local status and PR #4 head before further publication.
