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

Two wire-contract inconsistencies also remain: the status doc says unknown kinds use the same evidence fields as known kinds, but the handler returns only `{invokes: 0, successes: 0, note}`; and the docs do not pin typed per-route error envelopes for the new 503/413 or existing status codes. No domain-status mapping is implemented in this branch. Agent 4 recorded the M42 gates at [PR #4 comment 6681438788](https://github.com/oldman-088/cicc/pull/4#issuecomment-6681438788), corrected the `/diagnostics` wording at [6681521234](https://github.com/oldman-088/cicc/pull/4#issuecomment-6681521234), and reviewed the M43 wire/persistence gaps at [6681655389](https://github.com/oldman-088/cicc/pull/4#issuecomment-6681655389).

`POST /domains/{kind}/mount`, `/deregister`, and `/invoke` remain server/API write-token operations; browser writes stay limited to gated task creation. M42/M43 trials are explicitly `SANDBOX/FIXTURE` or unmerged-branch evidence, not actual deployed CICC host verification. No approved principal-to-tenant binding, actual deployed host route, or live provider verification was established by those trials.

## Threat and vulnerability intelligence

Neither domain is wired to a confirmed CICC host HTTP endpoint, and neither page issues an intelligence request or displays provider records. No provider URL, fixture-backed dashboard, indicator/CVE count, or inferred source health is added.

- **Threat Intelligence — Agent 2 / PR #3** (`439afd144e00993acf990398fd4f9a4030811b36`, reviewed 2026-11-06): `THREAT_RELATIONSHIP_API_CONTRACT.md` documents experimental standalone routes under the proposed package prefix `/api/v1/threat-intelligence`; the API is not mounted in Agent 1's CICC host, approved for frontend/production, or connected to live providers. The PostgreSQL/RLS schema and rollback remain independent proposals with no shared migration. The RLS store now rejects poisoned pooled tenant settings and has expanded isolated cross-tenant SELECT/INSERT/UPDATE/DELETE, traversal, audit, role-denial, and rollback tests, but the custom tenant GUC is still forgeable by arbitrary SQL and is not authentication or verified production isolation. `get_principal` defaults to 503; trusted host identity/tenant/permissions, gateway-to-router path/prefix, DB role/migration, durable audit/security-audit policy, timeout/retry semantics, and owner approvals remain open. Successful and not-found GET reads write transactional audit rows. All request data remains `EXPERIMENTAL_DEMO_DATA_ONLY`. The new `confidence_assessment.calculate_confidence` is a pure, caller-scoped experimental function with explicit analyst strength/reliability/stance inputs; it preserves declarations and provenance, withholds scores for unresolved/insufficient evidence, and is neither a host endpoint nor a calibrated/live confidence claim. Agent 2 reports **141 passed / 5 skipped** in its opt-in isolated run (23 PostgreSQL, 10 standalone ASGI, 11 assessment tests; categories overlap; the five actual-host tests are skipped without an approved harness) and **118 passed / 28 skipped** by default. These are Agent 2 claims, not Agent 4 reruns and not actual host, production isolation, or live-provider verification. Latest coordination: [PR #3 comment 6681650781](https://github.com/oldman-088/cicc/pull/3#issuecomment-6681650781); the BFF has no TI route and domain writes remain denied, including POST traversal despite `threat:read`.
- **Vulnerability Intelligence — replacement Agent 3 / PR #8** (`3bc65275a941b7cb53202516d81add1dac650e99`, reviewed 2026-11-06): the package now parses CycloneDX and SPDX JSON SBOMs and reports skipped/unmatchable components explicitly, marking incomplete inventories rather than silently treating a parse failure or missing-version package as “not affected.” It also normalizes package-name spellings across purls/advisories (including Maven group/artifact and encoded npm scopes). This is package-level implementation; the new commit does not add an actual CICC host route or live feed. The existing `INTEGRATION.md` still says the package is mountable/tested while the host is unmodified, with no mounted endpoints or live connectivity. The proposed package reads remain bounded list/detail/export APIs, with `host_adapter.py` requiring host principal/authorization callbacks and reporting `not_configured` before a real mount. The latest commit reports 1,987 tests passed, 0 failures, and 10 skips in its local offline run; that is Agent 3 evidence, not Agent 4 rerun or host/provider verification. Approved host prefix, identity/tenant binding, storage/migration, typed provenance/freshness, limits, errors, and controlled verification remain required. The earlier Agent 4 host-boundary review is [PR #8 comment 6681216531](https://github.com/oldman-088/cicc/pull/8#issuecomment-6681216531).

Until the owner-approved contracts are confirmed and mounted, the shared `ResourceState<T>` remains an integration boundary, but no domain endpoint is guessed and no package fixture is rendered as live data.

## Test and deployment status

- On Agent 4 code/test head `7aa77f764f3678b3beb084eca91cfb74ad7530a4`, Vitest ran **106 tests across 17 files: 106 passed, 0 failed, 0 skipped**. Typecheck, production build, and root dependency audit also passed; `npm audit --audit-level=high` reported 0 vulnerabilities.
- Playwright discovery lists **21 tests**. GitHub Actions [run 42194448522](https://github.com/oldman-088/cicc/actions/runs/42194448522) passed Chromium E2E, TypeScript, unit/component tests, dependency audit, and production build on that exact head. The E2E suite is deterministic/mocked, not a live-provider test. The first E2E attempt exposed a Strict Mode duplicate-initial-request assumption (20 passed, 1 failed); the test was corrected to assert the six unique refresh endpoints, then the final run passed.
- The app-local `npm audit` command is not applicable because `apps/web` has no separate lockfile; the repository-root audit and CI audit passed. Local typecheck/unit tests/build/audit and mocked browser checks are repository verification only. No actual CICC host or live-provider test was run; controlled integration verification remains blocked on approved host routes, principal/tenant binding, and owner decisions.
