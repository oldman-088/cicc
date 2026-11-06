# Frontend integration contracts

## Scope and evidence

This document describes the web adapter in this repository, not a production deployment. The Coordination provider contract was inspected in the API implementation proposed in PR #4 (`apps/api/app/coordination/router.py`, `apps/api/app/coordination/contract.py`, and the API schemas) at PR #4 source revision `6c2c2a1fa2904b0ee13263421674ed22fe8e9d26` (M43, reviewed 2026-11-06). The existence of those source routes does **not** prove that an API is deployed, reachable, or returning these DTOs. The adapter fails closed when `API_INTERNAL_URL` is not configured and validates every JSON response before presenting it.

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

Latest reviewed PR #4 head: `6c2c2a1fa2904b0ee13263421674ed22fe8e9d26` (M43). `docs/DOMAIN_STATUS_CONTRACT.md` still carries an M41 title and older PR #3/#8 heads. It documents stable IDs `threat_intel` and `vuln_intel`, seven evidence-based lifecycle states, `GET /api/v1/coordination/domains`, `GET /domains/{kind}/status`, and the `domains` health component, but has not been reconciled with M42/M43 wire changes. Known-kind evidence now includes the earlier `version`, `source_ref`, `mounted_at`, `invokes`, `successes`, `consecutive_failures`, `last_stale`, `stale_after_s`, `last_invoke_at`, and sanitized `last_error`, plus M43 `circuit {open, opened_at, threshold, cooldown_s}`, `mount_count`, and `previous_version`.

M42 adds invoke freshness `{stale, age_s, clock_skew_s, basis}` (`freshness_s`, `produced_at`, or no usable signal), flags future timestamps rather than treating them as fresh evidence, and resets `last_stale` on a later fresh result. M43 adds a circuit breaker (defaults: five consecutive failures / 30-second cooldown), half-open recovery, `503 domain_circuit_open`, a 64 KiB invoke-payload cap with `413 payload_too_large`, domain-status ops alerts, and mount history. `last_invoke_at` remains execution time, not provider-data freshness or live-source verification. The new circuit/mount-history fields are produced by in-memory state; the reviewed M43 change does not add them to the persisted `coord_domain_stats` schema or `_persist_domain_stats()`. Their restart semantics must be explicitly documented or made durable before the UI treats them as persistent evidence.

`TENANT_AUTH_READINESS.md` explicitly says request `tenant_id` is only an `UNVERIFIED` claim, not identity or enforcement; status/diagnostics remain global ops views with no tenant binding while the platform principal-to-tenant decision is pending. The owner/integration gates remain open. `AMD003_DOMAIN_LIFECYCLE.md` reserves the shared status endpoint, mount/deregister, extended `/domains` and `/health` shapes, and `coord_domain_stats`; it does not list the M42 `/diagnostics` route or the M43 status/error additions. Independently, `list_domains()`, `domain_status()`, `coordination_diagnostics()`, and `coordination_health()` call `_persist_domain_stats()` and commit during GET requests. The owner must accept those database write side effects or require a pure read before frontend polling/mapping.

Two wire-contract inconsistencies also remain: the status doc says unknown kinds use the same evidence fields as known kinds, but the handler returns only `{invokes: 0, successes: 0, note}`; and the docs do not pin typed per-route error envelopes for the new 503/413 or existing status codes. No domain-status mapping is implemented in this branch. Agent 4 recorded the M42 gates at [PR #4 comment 6681438788](https://github.com/oldman-088/cicc/pull/4#issuecomment-6681438788), corrected the `/diagnostics` wording at [6681521234](https://github.com/oldman-088/cicc/pull/4#issuecomment-6681521234), reviewed the M43 wire/persistence gaps at [6681655389](https://github.com/oldman-088/cicc/pull/4#issuecomment-6681655389), and explicitly asked Agent 1 for process-vs-persistent circuit fields, mount-history durability, approved DTO/error envelope, principal/tenant scope, and AMD-003 approval at [6682030526](https://github.com/oldman-088/cicc/pull/4#issuecomment-6682030526).

`POST /domains/{kind}/mount`, `/deregister`, and `/invoke` remain server/API write-token operations; browser writes stay limited to gated task creation. M42/M43 trials are explicitly `SANDBOX/FIXTURE` or unmerged-branch evidence, not actual deployed CICC host verification. No approved principal-to-tenant binding, actual deployed host route, or live provider verification was established by those trials.

## Threat and vulnerability intelligence

Neither domain is wired to a confirmed CICC host HTTP endpoint, and neither page issues an intelligence request or displays provider records. No provider URL, fixture-backed dashboard, indicator/CVE count, or inferred source health is added.

- **Threat Intelligence — Agent 2 / PR #3** (current head `5d2ab6b09100f6209c38b8a1ba3a1e16c44e49e7`, reviewed 2026-11-06): PR #3 remains open against `main`. The latest commit adds an optional role-bound PostgreSQL RLS design using per-tenant DB login roles and a protected `session_user` mapping, plus caller-defined collection-age analysis. These are proposals only: no shared migration/role or host adapter was changed, and the role design is not owner-approved or production isolation. Isolated PostgreSQL tests cover cross-tenant access, role changes, policy drift, pool reuse and rollback; the report explicitly demonstrates that arbitrary SQL under a tenant login can forge that tenant's audit, and documents credential/ownership/pooler risks. `collection_freshness` takes an explicit caller-supplied horizon and `as_of`; it is collection-age classification, not provider freshness, live intelligence or host health. `HOST_INTEGRATION_HANDOFF.md` now defines six opt-in actual-host acceptance cases, all **6 skipped / 0 run** without an approved real host and owner-supplied harness. Agent 2 reports **154 passed / 6 skipped** in its full isolated run and **120 passed / 40 skipped** in its default run (test categories overlap); these are Agent 2 reports, not Agent 4 reruns or host evidence. The package still has no approved CICC host route/prefix, trusted platform principal-to-tenant binding, shared migration, or frontend-ready host DTO/error envelope. Agent 4 keeps TI disconnected and will not present fixtures as live intelligence. Prior coordination: [PR #3 comment 6681650781](https://github.com/oldman-088/cicc/pull/3#issuecomment-6681650781); latest review: [comment 6682030554](https://github.com/oldman-088/cicc/pull/3#issuecomment-6682030554).
- **Vulnerability Intelligence — Agent 3 / PR #1 with stacked PR #8**: PR #8 head `3bc65275a941b7cb53202516d81add1dac650e99` was merged into PR #1's branch `arena/fa0df787-cicc`, **not into `main`**. PR #1 remains open against `main` at head `f8e96c78795ed88f86b6504791c2a5e6a4a86a00`; its latest CI run [42197674091](https://github.com/oldman-088/cicc/actions/runs/42197674091) passed all five jobs. PR #8 adds CycloneDX/SPDX JSON SBOM ingestion, explicit incomplete-inventory reporting, VEX export and package-name normalization; the subsequent PR #1 head includes the M15 SBOM/reporting work. This remains package-level implementation: Agent 3's latest `docs/vulnerability-intelligence/INTEGRATION.md` states host files touched **none**, mounted host endpoints **none**, migrations authored **none**, and live connectivity **none**; its OpenAPI remains proposed. Agent 3 reports local package tests and oracle checks, not a CICC host mount or live-provider verification. The required host prefix, trusted authentication/tenant binding, storage/migration, DTO/provenance/freshness, pagination/limits, error semantics and owner decisions remain open. The earlier Agent 4 boundary review is [PR #8 comment 6681216531](https://github.com/oldman-088/cicc/pull/8#issuecomment-6681216531).


Until the owner-approved contracts are confirmed and mounted, the shared `ResourceState<T>` remains an integration boundary, but no domain endpoint is guessed and no package fixture is rendered as live data.

## Test and deployment status

- On the current Agent 4 worktree (based on prior PR #2 head `a76518864dfdffd71fa03022833fdceda1d256a9`), Vitest discovered/executed **114 tests across 18 files: 114 passed, 0 failed, 0 skipped**. This includes per-resource race/unmount coverage, all six Coordination read categories and independent failure cases. Typecheck, production build, `git diff --check`, and repository-root `npm audit --audit-level=high` passed; audit reported **0 vulnerabilities**.
- Playwright discovery lists **22 tests**. **0 browser tests have been run locally** in this worktree because no Playwright browser binary is installed in the local cache; do not count discovery as execution. The previous GitHub Actions [run 42195521586](https://github.com/oldman-088/cicc/actions/runs/42195521586) passed on the *previous* PR #2 head `a765188`; it does not include these latest changes. The new concurrent-refresh E2E is awaiting Chromium CI on the updated head. E2E fixtures are deterministic mocks, not live-provider integration.
- Earlier PR #2 CI and local results are historical. Current host integration remains unverified: no approved CICC TI/VI mount, trusted principal/tenant binding, owner-approved status DTO/error contract, or live-provider evidence has been established. No deployment or production-readiness claim is made.
