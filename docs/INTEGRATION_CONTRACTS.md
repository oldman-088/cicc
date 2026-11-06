# Frontend integration contracts

## Scope and evidence

This document describes the web adapter in this repository, not a production deployment. The Coordination provider contract was inspected in the API implementation proposed in PR #4 (`apps/api/app/coordination/router.py`, `apps/api/app/coordination/contract.py`, and the API schemas) at PR #4 source revision `6c2c2a1fa2904b0ee13263421674ed22fe8e9d26` (M43, reviewed 2026-11-06), with the M44 read-only metrics addition separately reviewed at `2ef50e77a429fed35b8cc3991301608e9537d313`. The existence of those source routes does **not** prove that an API is deployed, reachable, or returning these DTOs. The adapter fails closed when `API_INTERNAL_URL` is not configured and validates every JSON response before presenting it.

`README.md` is the original **ULTIMATE MASTER PROMPT v1.0** and remains unchanged. This file documents the implementation boundary without rewriting that source prompt.

## Browser-to-BFF contract

The browser uses same-origin relative URLs under `/api/integrations/`; it never receives or sends a provider bearer token. The server-side catch-all adapter in `apps/web/src/app/api/integrations/[...path]/route.ts` allowlists paths and query parameters, strips browser-controlled authorization, injects optional server-only tokens, uses `no-store`, rejects redirects, bounds JSON bodies, and returns sanitized errors.

| Purpose | Browser endpoint | Provider endpoint |
| --- | --- | --- |
| Coordination health | `GET /api/integrations/coordination/health` | `GET /api/v1/coordination/health` |
| Agents | `GET /api/integrations/coordination/agents` | `GET /api/v1/coordination/agents` |
| Tasks | `GET /api/integrations/coordination/tasks` | `GET /api/v1/coordination/tasks` |
| Metrics | `GET /api/integrations/coordination/metrics` | `GET /api/v1/coordination/metrics` |
| Events | `GET /api/integrations/coordination/events` | `GET /api/v1/coordination/events` |
| One task trace | `GET /api/integrations/coordination/task-trace?task_id=…` | `GET /api/v1/coordination/tasks/{task_id}/trace` |
| Write capabilities | `GET /api/integrations/coordination/write-capabilities` | Local configuration only; no provider request |

Task-list filters accepted by the BFF are `state`, `agent`, `kind`, `dead_letter`, and `limit` (1–500). Duplicate and unknown query keys are rejected. The browser's search, state filter, and page controls operate only on the returned task array; they do not claim server-side search or pagination. The UI labels the loaded scope accordingly.

The Coordination header's localized “Refresh all provider data” action refreshes the six configured read resources (health, metrics, agents, tasks, events, and write capabilities). It remains disabled while any read is pending and uses only the allowlisted GET endpoints; it does not refresh the lazy task trace or expand browser writes.

`apps/web/src/lib/integration-api.ts` defines and validates the coordination DTOs. Provider-reported progress, results, attempts, health, and routing explanations remain nullable/optional where the source may omit them; the UI does not infer missing values. Invalid response shapes become `invalid_response` rather than fabricated records. The API health route is an on-demand check, not a promise of continuous monitoring.

## Gated coordination writes

Writes require all of the following server-side configuration:

- A valid `API_INTERNAL_URL`.
- `WEB_BFF_WRITE_TOKEN` (never a browser value).
- `CICC_OPS_TRUSTED_SINGLE_TENANT=true`.
- `WEB_BFF_ALLOW_COORD_WRITE=1` for task creation. No routing toggle or routing write endpoint is exposed by this frontend.
- A same-origin `Origin` on each browser POST; cross-origin and non-same-origin fetch metadata are rejected.

The capability endpoint reports only whether task creation is configured; it does not contact the provider and is not a health check. The create flag is off unless explicitly configured. The workspace warns that it has no user authentication or tenant isolation; the gate is not a substitute for trusted network access controls.

### Create a task

`POST /api/integrations/coordination/tasks` accepts JSON fields from the Coordination `TaskIn` contract, subject to an additional BFF allowlist and validation. The current form sends `kind`, `title`, `priority`, `payload`, and `requires_approval`. The BFF caps the request body at 256,000 bytes, rejects unknown fields and browser-supplied `task_id`/`idempotency_key`, and creates a `bff-<UUID>` `idempotency_key` server-side. The provider endpoint is the source-confirmed `POST /api/v1/coordination/tasks`; the BFF accepts its `201 application/json` response only when it contains `task_id`, `kind`, `state`, and `duplicate`, and exposes the generated correlation key in `X-CICC-Idempotency-Key`.

The idempotency key correlates a single submitted request with the provider record. A retry after an uncertain network outcome creates a new key; the UI therefore tells the operator to refresh the task list and trace before retrying. It does not claim automatic retry deduplication across separate submissions.

### Routing remains provider-owned and read-only in this frontend

The Coordination API source at PR #4 head `6c2c2a1fa2904b0ee13263421674ed22fe8e9d26` documents `POST /api/v1/coordination/tasks/{task_id}/route` with an empty request body and a response containing `task_id`, `agent`, `state`, and an `explanation`. Its handler first depends on `read_token_dependency`, then explicitly calls `require_write_token(Authorization)` and `write_rate_limit_dependency`; it accepts no routing payload or caller-selected agent. The handler invokes routing policy and mutates the task's assigned agent, routing explanation, and state (`QUEUED` when an agent is selected, otherwise `BLOCKED`). This is not a harmless read operation.

The reference web BFF in PR #4 (`apps/web/lib/bff.mjs`) explicitly allowlists only task creation; its source comments and tests deny other browser writes. PR #2 previously added a second browser-facing BFF route behind `WEB_BFF_ALLOW_COORD_ROUTING=1`, but no explicit BFF-policy approval for that extension was found. **That extension has been removed.** PR #2 does not expose a browser route, capability flag, or UI action for routing. Provider-returned assignment and routing explanations on existing task records remain visible as read-only data. The BFF returns `404` for `/api/integrations/coordination/tasks/{task_id}/route` regardless of the old routing environment variable, and tests pin that denial while keeping the create-only path covered.

This boundary matches the reviewed reference policy and avoids broadening writes from a frontend that has no user authentication or tenant isolation. Reconsider only after Agent 1 records explicit owner approval and the required principal, same-origin/CSRF, tenant-resolution, and server-side gate controls in the authoritative BFF policy.

### Agent 1 domain-gateway contract (reviewed separately from the browser BFF)

Latest reviewed PR #4 head: `2ef50e77a429fed35b8cc3991301608e9537d313` (M44). M44 adds a read-gated `GET /api/v1/coordination/domains/metrics` with per-kind invoke/success/failure rates, latency, timeout/retry, stale/skew and circuit-transition counters; labels are bounded to registered domain `kind`. Agent 1 reports M44 tests 6/6 and a 17/17 `SANDBOX/FIXTURE` observability trial. These are branch-local evidence, not verification against an actually deployed CICC host.

`docs/DOMAIN_STATUS_CONTRACT.md` now describes M44 metrics but still has an M41 title. `_persist_domain_stats()` stores version/source/mount timestamp, validation status, invokes/successes/consecutive failures, last-stale, last-invoke, last status and sanitized last error. Circuit state (`open`/`opened_at`), latency/timeouts/retries/stale/skew/circuit-transition counters are process-local; the current contract says they reset on restart. `mount_count` and `previous_version` are held in `_STATS` as volatile mount history and are not written by `_persist_domain_stats()` or represented in the current `coord_domain_stats` schema. The public contract still needs an explicit field-by-field restart/persistence guarantee for these fields and their reconstruction semantics.

`TENANT_AUTH_READINESS.md` remains a proposal: status and metrics are global ops views behind a shared read token, and trusted principal-to-tenant binding remains owner-pending; a request-supplied `tenant_id` is not identity. `AMD003_DOMAIN_LIFECYCLE.md` remains `PENDING — owner-reserved`; it does not list the separately added `/diagnostics` or new `/domains/metrics` endpoint/M43/M44 shape. The status contract still has the unknown-kind DTO mismatch (handler returns only `{invokes, successes, note}` evidence), and lists status codes without a complete typed per-route error-envelope schema. `GET /domains`, `/domains/{kind}/status`, `/diagnostics`, and `/health` still call `_persist_domain_stats()` and commit; `/domains/metrics` loads persisted stats without that write path. Owner acceptance/removal of GET-side writes remains open.

No domain-status adapter is implemented. Circuit/mount fields will not be presented as durable history or healthy status inferred. The M42/M43/M44 trials remain sandbox/fixture evidence, not actual host integration. Agent 4's explicit persistence/DTO/principal/AMD-003 questions: [M43 follow-up 6682030526](https://github.com/oldman-088/cicc/pull/4#issuecomment-6682030526); [M44 follow-up 6682210838](https://github.com/oldman-088/cicc/pull/4#issuecomment-6682210838).

## Threat and vulnerability intelligence

Neither domain is wired to a confirmed CICC host HTTP endpoint, and neither page issues an intelligence request or displays provider records. No provider URL, fixture-backed dashboard, indicator/CVE count, or inferred source health is added.

- **Threat Intelligence — Agent 2 / PR #3** (current head `f3d3a7f9c17e6fa4f11d2539853bc5a777ab57aa`, open against `main`): recent commits add an optional restricted-role PostgreSQL adapter for controlled relationship create and single-record GET with DB-derived actor/tenant/event/time/correlation and transactional audit. Its own docs say list and traversal still fail closed with 503; the adapter, roles, SQL and rollback are isolated proposals, not approved/mounted in Agent 1's host. Actual principal-to-login-pool mapping, gateway-to-router wiring, task/trace correlation, shared migration/role approval, audit guarantees and six actual-host acceptance cases remain open; those six host cases are skipped. Agent 2 also reports one opt-in real network read against the fixed CISA GitHub KEV mirror. This is not a scheduled/persisted CICC feed or frontend data: the collector contract says no scheduling, persistence, tenant boundary or host integration, and default fixtures remain explicitly experimental. Agent 2 reports **173 passed / 7 skipped** in its latest opt-in full run (six actual-host and one live-source opt-in skipped), **128 passed / 52 skipped** by default, and a separate one-test live-mirror read passed; categories overlap. These are Agent 2 reports, not Agent 4 reruns or host/provider integration evidence. Agent 4 keeps TI disconnected and browser writes create-only. Previous review: [comment 6682030554](https://github.com/oldman-088/cicc/pull/3#issuecomment-6682030554); latest review: [comment 6682210811](https://github.com/oldman-088/cicc/pull/3#issuecomment-6682210811).
- **Vulnerability Intelligence — Agent 3 / PR #1 with stacked PR #8**: PR #8 head `3bc65275a941b7cb53202516d81add1dac650e99` was merged into PR #1's branch `arena/fa0df787-cicc`, **not into `main`**. PR #1 remains open against `main` at head `f8e96c78795ed88f86b6504791c2a5e6a4a86a00`; its latest CI run [42197674091](https://github.com/oldman-088/cicc/actions/runs/42197674091) passed all five jobs. PR #8 adds CycloneDX/SPDX JSON SBOM ingestion, explicit incomplete-inventory reporting, VEX export and package-name normalization; the subsequent PR #1 head includes the M15 SBOM/reporting work. This remains package-level implementation: Agent 3's latest `docs/vulnerability-intelligence/INTEGRATION.md` states host files touched **none**, mounted host endpoints **none**, migrations authored **none**, and live connectivity **none**; its OpenAPI remains proposed. Agent 3 reports local package tests and oracle checks, not a CICC host mount or live-provider verification. The required host prefix, trusted authentication/tenant binding, storage/migration, DTO/provenance/freshness, pagination/limits, error semantics and owner decisions remain open. The earlier Agent 4 boundary review is [PR #8 comment 6681216531](https://github.com/oldman-088/cicc/pull/8#issuecomment-6681216531).

Until the owner-approved contracts are confirmed and mounted, the shared `ResourceState<T>` remains an integration boundary, but no domain endpoint is guessed and no package fixture is rendered as live data.

## Test and deployment status

- On Agent 4 code head `698294f65877e6cf177ed4022092018082a96d67`, Vitest discovered/executed **114 tests across 18 files: 114 passed, 0 failed, 0 skipped**. This includes per-resource race/unmount coverage, all six Coordination read categories and independent failure cases. Typecheck, production build, `git diff --check`, and repository-root `npm audit --audit-level=high` passed; audit reported **0 vulnerabilities**.
- Playwright discovery lists **22 tests**. In CI [run 42198384237](https://github.com/oldman-088/cicc/actions/runs/42198384237) on exact code head `698294f65877e6cf177ed4022092018082a96d67`, Chromium installation and browser E2E passed: **22 discovered, 22 executed, 22 passed, 0 failed, 0 skipped**. The suite has no test-skip directives. The local Playwright list is discovery only; **0 browser tests were executed locally** because no Playwright browser binary is installed in the local cache. The docs-only follow-up head `b6cf81769306716cc28254a65729ec356a1279b1` passed all workflow steps in CI [run 42198710084](https://github.com/oldman-088/cicc/actions/runs/42198710084). Both browser runs use deterministic mocks, not live-provider integration.
- Current host integration remains unverified: no approved CICC TI/VI mount, trusted principal/tenant binding, owner-approved status DTO/error contract, or live-provider UI evidence has been established. No deployment or production-readiness claim is made.
