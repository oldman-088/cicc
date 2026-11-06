# Frontend integration contracts

## Scope and evidence

This document describes the web adapter in this repository, not a production deployment. The Coordination provider contract was inspected in the API implementation proposed in PR #4 (`apps/api/app/coordination/router.py`, `apps/api/app/coordination/contract.py`, and the API schemas) at PR #4 source revision `f96037b00f03018d6bca6c11cfd1bec407cdf7fa` (M42, reviewed 2026-11-06). The existence of those source routes does **not** prove that an API is deployed, reachable, or returning these DTOs. The adapter fails closed when `API_INTERNAL_URL` is not configured and validates every JSON response before presenting it.

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

The Coordination API source at PR #4 head `f96037b00f03018d6bca6c11cfd1bec407cdf7fa` documents `POST /api/v1/coordination/tasks/{task_id}/route` with an empty request body and a response containing `task_id`, `agent`, `state`, and an `explanation`. Its handler first depends on `read_token_dependency`, then explicitly calls `require_write_token(Authorization)` and `write_rate_limit_dependency`; it accepts no routing payload or caller-selected agent. The handler invokes routing policy and mutates the task's assigned agent, routing explanation, and state (`QUEUED` when an agent is selected, otherwise `BLOCKED`). This is not a harmless read operation.

The reference web BFF in PR #4 (`apps/web/lib/bff.mjs`) explicitly allowlists only task creation; its source comments and tests deny other browser writes. PR #2 previously added a second browser-facing BFF route behind `WEB_BFF_ALLOW_COORD_ROUTING=1`, but no explicit BFF-policy approval for that extension was found. **That extension has been removed.** PR #2 does not expose a browser route, capability flag, or UI action for routing. Provider-returned assignment and routing explanations on existing task records remain visible as read-only data. The BFF returns `404` for `/api/integrations/coordination/tasks/{task_id}/route` regardless of the old routing environment variable, and tests pin that denial while keeping the create-only path covered.

This boundary matches the reviewed reference policy and avoids broadening writes from a frontend that has no user authentication or tenant isolation. Reconsider only after Agent 1 records explicit owner approval and the required principal, same-origin/CSRF, tenant-resolution, and server-side gate controls in the authoritative BFF policy.

### Agent 1 domain-gateway contract (reviewed separately from the browser BFF)

Latest reviewed PR #4 head: `f96037b00f03018d6bca6c11cfd1bec407cdf7fa` (M42). `docs/DOMAIN_STATUS_CONTRACT.md` describes stable IDs `threat_intel` and `vuln_intel`, seven evidence-based lifecycle states, `GET /api/v1/coordination/domains`, `GET /domains/{kind}/status`, and the `domains` health component. Known-kind evidence includes `version`, `source_ref`, `mounted_at`, `invokes`, `successes`, `consecutive_failures`, `last_stale`, `stale_after_s`, `last_invoke_at`, and sanitized `last_error`. The doc still cites older PR #3/#8 heads and an M41 title despite M42 additions; those references need refreshing.

M42 adds invoke freshness `{stale, age_s, clock_skew_s, basis}` (`freshness_s`, `produced_at`, or no usable signal), flags future timestamps rather than treating them as fresh evidence, and resets `last_stale` on a later fresh result. `last_invoke_at` remains execution time, not provider-data freshness or live-source verification. M42 also adds read-gated `GET /diagnostics` (DB connectivity/version/uptime/domain status, no secrets) and audit events. `TENANT_AUTH_READINESS.md` explicitly says a request `tenant_id` is only an `UNVERIFIED` claim, not identity or enforcement; status/diagnostics remain global ops views with no tenant binding while the platform principal-to-tenant decision is pending.

The owner/integration gates remain open. `AMD003_DOMAIN_LIFECYCLE.md` reserves the shared status endpoint, mount/deregister, extended `/domains` and `/health` shapes, and `coord_domain_stats`; it does not yet list the new M42 `/diagnostics` route, whose owner/change-control status needs clarification. Independently, `list_domains()`, `domain_status()`, `coordination_diagnostics()`, and `coordination_health()` call `_persist_domain_stats()` and commit during GET requests. The owner must accept those database write side effects or require a pure read before frontend polling/mapping.

Two wire-contract inconsistencies also remain: the status doc says unknown kinds use the same evidence fields as known kinds, but the handler returns only `{invokes: 0, successes: 0, note}`; and the docs list error status codes without pinning the exact typed per-route error envelope. No domain-status mapping is implemented in this branch. Agent 4 recorded the remaining gates at [PR #4 comment 6681438788](https://github.com/oldman-088/cicc/pull/4#issuecomment-6681438788) and clarified the `/diagnostics` approval wording at [6681521234](https://github.com/oldman-088/cicc/pull/4#issuecomment-6681521234).

`POST /domains/{kind}/mount`, `/deregister`, and `/invoke` remain server/API write-token operations; browser writes stay limited to gated task creation. The M42 cross-agent trial labels evidence as sandbox/unmerged branches and explicitly does not claim a merged-application or production verification. No actual deployed CICC host route, approved principal-to-tenant binding, or live provider verification was established by that trial.

## Threat and vulnerability intelligence

Neither domain is wired to a confirmed CICC host HTTP endpoint, and neither page issues an intelligence request or displays provider records. No provider URL, fixture-backed dashboard, indicator/CVE count, or inferred source health is added.

- **Threat Intelligence — Agent 2 / PR #3** (`643a334d1b324cc58ead40eca61a776d63749c67`, reviewed 2026-11-06): `THREAT_RELATIONSHIP_API_CONTRACT.md` documents experimental routes under the proposed package prefix `/api/v1/threat-intelligence`: `GET /relationships`, `GET /relationships/{relationship_id}`, `POST /relationships`, and `POST /relationship-analysis/traverse`. The standalone `apps.threat_intelligence.api:app` includes the router; it is not mounted in Agent 1's CICC host, approved for frontend/production, or connected to live providers. `PostgresRelationshipStore`, `p2_01_postgres_proposal.sql`, and the newer FORCE-RLS/rollback SQL are independent proposals tested only on disposable local PostgreSQL; no shared migration was applied. RLS uses a transaction-local custom tenant GUC that the same application DB role can set arbitrarily, so it is **not tenant authentication or verified production isolation**; role, policy, grants, schema/search path, platform identity, and host trust still need owner review. `get_principal` defaults to 503 and the host must inject verified identity/tenant/permissions, storage, and audit dependencies. Successful and not-found GET reads write transactional audit rows; denied requests and DB failures need an independent host security-audit path. All records remain `EXPERIMENTAL_DEMO_DATA_ONLY`, and no source freshness or calculated confidence is produced. The new internal `intelligence_assessment` is a pure summary/timeline/conflict-preservation function, not an endpoint or a computed confidence/reliability score. Agent 2 reports **132 passed** in its opt-in isolated suite (including 20 PostgreSQL, 10 standalone ASGI, and 5 assessment tests; categories overlap) and **112 passed / 20 skipped** in its default run. These are Agent 2 claims, not Agent 4 reruns and not Agent 1 host, production auth/RLS, or live-provider verification. The legacy `invoke_endpoint` remains a separate demo dispatcher; its confidence `1.0` is not intelligence confidence. Agent 4 maps no route in the BFF and keeps domain writes denied, including POST traversal despite `threat:read`. Latest coordination: [PR #3 comment 6681367025](https://github.com/oldman-088/cicc/pull/3#issuecomment-6681367025); actual gateway-to-router path, host prefix, trusted principal/tenant/permission, DB/migration, audit, timeout/retry, and AMD-003 decisions remain open.
- **Vulnerability Intelligence — replacement Agent 3 / PR #8** (`700e30f185ef6ba6e67f136e96f0a4a1322065c6`, reviewed 2026-11-06): `INTEGRATION.md` still says the package is mountable/tested but the host is not modified; no host endpoints are mounted and no live connectivity has been verified. The package read surface remains `GET /v1/vulnerabilities`, `GET /v1/vulnerabilities/{cve}`, and `GET /v1/vulnerabilities/export/{format}` (`vex`, `openvex`, or `sarif`), with host-resolved tenant scope. The list uses bounded pagination; exports preserve unassessed/empty-inventory semantics and refuse truncation above 5,000 records. OpenAPI remains `PROPOSED`, with the actual host prefix owned by Agent 1. The latest `host_adapter.py` composes host-provided principal and authorization callbacks, takes tenant from the principal, defaults to HTTPS, and reports `not_configured` until a real mount; tests use a stand-in for the host security contract. This is useful package-level adapter work, not authentication or a host integration by itself: no `apps/api` mount/prefix was added, the host `read_principal`/authorization wiring and approved storage/migration remain outstanding, and no live provider was verified. Agent 4's latest follow-up is [PR #8 comment 6681216531](https://github.com/oldman-088/cicc/pull/8#issuecomment-6681216531), after [6681157373](https://github.com/oldman-088/cicc/pull/8#issuecomment-6681157373).

Until the owner-approved contracts are confirmed and mounted, the shared `ResourceState<T>` remains an integration boundary, but no domain endpoint is guessed and no package fixture is rendered as live data.

## Test and deployment status

- Vitest tests cover response parsers, fixed BFF routes, write gates, body validation, origin checks, and browser workspace behavior. Their fixtures are tests only.
- Playwright E2E tests use deterministic route mocks and are not evidence of a live provider. The CI Chromium suite also validates responsive viewports, locale direction, keyboard navigation, and axe-core WCAG A/AA rules; a passing browser check does not prove provider connectivity.
- Local typecheck, unit tests, audit, and production build are repository checks only. Provider connectivity and production readiness require a separately configured deployment and an actual request/response verification.
