# Frontend integration contracts

## Scope and evidence

This document describes the web adapter in this repository, not a production deployment. The Coordination provider contract was inspected in the API implementation proposed in PR #4 (`apps/api/app/coordination/router.py`, `apps/api/app/coordination/contract.py`, and the API schemas) at PR #4 source revision `ab458ec11ec685c4d9364cb6f865d63c4d460d81` (reviewed 2026-11-06). The existence of those source routes does **not** prove that an API is deployed, reachable, or returning these DTOs. The adapter fails closed when `API_INTERNAL_URL` is not configured and validates every JSON response before presenting it.

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

The Coordination API source at PR #4 head `014a096b506645b7ab0b04b9fdbe320e02240276` documents `POST /api/v1/coordination/tasks/{task_id}/route` with an empty request body and a response containing `task_id`, `agent`, `state`, and an `explanation`. Its handler first depends on `read_token_dependency`, then explicitly calls `require_write_token(Authorization)` and `write_rate_limit_dependency`; it accepts no routing payload or caller-selected agent. The handler invokes routing policy and mutates the task's assigned agent, routing explanation, and state (`QUEUED` when an agent is selected, otherwise `BLOCKED`). This is not a harmless read operation.

The reference web BFF in PR #4 (`apps/web/lib/bff.mjs`) explicitly allowlists only task creation; its source comments and tests deny other browser writes. PR #2 previously added a second browser-facing BFF route behind `WEB_BFF_ALLOW_COORD_ROUTING=1`, but no explicit BFF-policy approval for that extension was found. **That extension has been removed.** PR #2 does not expose a browser route, capability flag, or UI action for routing. Provider-returned assignment and routing explanations on existing task records remain visible as read-only data. The BFF returns `404` for `/api/integrations/coordination/tasks/{task_id}/route` regardless of the old routing environment variable, and tests pin that denial while keeping the create-only path covered.

This boundary matches the reviewed reference policy and avoids broadening writes from a frontend that has no user authentication or tenant isolation. Reconsider only after Agent 1 records explicit owner approval and the required principal, same-origin/CSRF, tenant-resolution, and server-side gate controls in the authoritative BFF policy.

### Agent 1 domain-gateway contract (reviewed separately from the browser BFF)

Latest reviewed PR #4 head: `752dc99ececef934fef2d699aae571502639bc1f`. Agent 1 has now added `docs/DOMAIN_STATUS_CONTRACT.md`, naming stable IDs `threat_intel` and `vuln_intel`, read-token-only BFF access, `GET /api/v1/coordination/domains`, `GET /domains/{kind}/status`, and the `domains` component on `/health`. The document lists all seven lifecycle states and the UI mapping, and the latest source evidence includes `version`, `source_ref`, `mounted_at`, `invokes`, `successes`, `consecutive_failures`, `last_stale`, `stale_after_s`, `last_invoke_at`, and sanitized `last_error`. An unknown kind returns HTTP 200 with `NOT_MOUNTED`, but the implementation currently returns only `invokes`, `successes`, and a note in that evidence object, rather than the full documented field set. The previous M37 examples and contract descriptor also omit some M41 fields and need reconciliation.

The M41 contract clarifies provenance/freshness at the gateway level: invoke results carry source/produced time/confidence/freshness, `stale` reflects the configured freshness threshold, and `evidence.last_stale` summarizes the last result. `last_invoke_at` remains execution time, not provider-data freshness or live-source verification. This is now a published technical proposal, but not an owner-approved integration: the descriptor and `docs/DOMAIN_STATUS_CONTRACT.md` still say tenant context is **PENDING owner decision**, single-tenant now with no tenant header, and AMD-003 remains owner-reserved for the shared status routes/extended health shape.

Two owner gates and one contract consistency item remain before frontend binding. First, both `list_domains()` and `domain_status()` load persisted stats, call `_persist_domain_stats()`, and commit the session while serving GETs; the owner must accept that side effect or require a pure read. Second, reconcile the unknown-kind evidence shape and older examples/descriptor with the new M41 field allowlist. Third, define the exact per-route error-body envelope (the docs list general status codes but do not provide a typed envelope). Agent 4 raised these on [PR #4 follow-up 6680919000](https://github.com/oldman-088/cicc/pull/4#issuecomment-6680919000) and checked the now-present contract doc in [comment 6680981341](https://github.com/oldman-088/cicc/pull/4#issuecomment-6680981341). No status mapping is implemented in this branch pending owner confirmation.

`POST /domains/{kind}/mount`, `/deregister`, and `/invoke` require write authorization in addition to the read dependency. In particular, `/invoke` creates a task, invokes the mounted handler, and persists its result, provenance, and trace. PR #2 does not expose these domain routes; its browser-write contract remains task-creation-only. Agent 1's M39 `vuln_intel` adapter is an internal package adapter, not a host HTTP mount or a browser API.

Agent 1 reports a sandbox M40 mount/invoke trial for `threat_intel`, with `EXPERIMENTAL_DEMO_DATA_ONLY` preserved and a trace persisted. That is Agent 1-reported sandbox evidence, not an Agent 4 rerun, deployed provider verification, or evidence that sample intelligence is live. The Threat and Vulnerability pages remain disconnected; gateway and package fixtures are not rendered as live intelligence data.

## Threat and vulnerability intelligence

Neither domain is wired to a confirmed CICC host HTTP endpoint, and neither page issues an intelligence request or displays provider records. No provider URL, fixture-backed dashboard, indicator/CVE count, or inferred source health is added.

- **Threat Intelligence — Agent 2 / PR #3** (`17e118902a66339b6efbc165d10ffe9116f081a3`, reviewed 2026-11-06): `THREAT_RELATIONSHIP_API_CONTRACT.md` documents experimental routes under the proposed package prefix `/api/v1/threat-intelligence`: `GET /relationships`, `GET /relationships/{relationship_id}`, `POST /relationships`, and `POST /relationship-analysis/traverse`. The standalone `apps.threat_intelligence.api:app` and a separately constructed test host include the router; neither is a mount in Agent 1's CICC host. The contract says **not host-mounted, not frontend/production approved**. The new `PostgresRelationshipStore` and `schema/p2_01_postgres_proposal.sql` add tenant predicates/composite constraints, per-tenant advisory locking and transactional metadata audit, tested against an isolated PostgreSQL server. They remain an independently owned proposal: no shared migration, production identity binding, database RLS, or host integration was performed. `get_principal` still defaults to 503; a host must supply verified identity/tenant/permissions, the DB engine/store and audit integration. Successful GET reads also write transactional audit rows, so they are not pure reads and require owner/host policy review. All records carry `EXPERIMENTAL_DEMO_DATA_ONLY`; no source freshness is calculated. Agent 2 reports 118 passes in the opt-in isolated PostgreSQL run (11 PostgreSQL and 10 ASGI tests, overlapping categories) and 107 passes/11 skips in the default environment; these are not Agent 1 host, production auth/RLS, or live-provider tests. The legacy `invoke_endpoint` remains a separate demo dispatcher; its confidence `1.0` is not intelligence confidence. Agent 4 maps no route in the BFF and keeps domain writes denied, including POST traversal despite `threat:read`. Latest coordination: [PR #3 comment 6681241962](https://github.com/oldman-088/cicc/pull/3#issuecomment-6681241962); owner-approved host route/prefix, tenant/RLS, schema/audit, read semantics, and AMD-003 remain open.
- **Vulnerability Intelligence — replacement Agent 3 / PR #8** (`700e30f185ef6ba6e67f136e96f0a4a1322065c6`, reviewed 2026-11-06): `INTEGRATION.md` still says the package is mountable/tested but the host is not modified; no host endpoints are mounted and no live connectivity has been verified. The package read surface remains `GET /v1/vulnerabilities`, `GET /v1/vulnerabilities/{cve}`, and `GET /v1/vulnerabilities/export/{format}` (`vex`, `openvex`, or `sarif`), with host-resolved tenant scope. The list uses bounded pagination; exports preserve unassessed/empty-inventory semantics and refuse truncation above 5,000 records. OpenAPI remains `PROPOSED`, with the actual host prefix owned by Agent 1. The latest `host_adapter.py` composes host-provided principal and authorization callbacks, takes tenant from the principal, defaults to HTTPS, and reports `not_configured` until a real mount; tests use a stand-in for the host security contract. This is useful package-level adapter work, not authentication or a host integration by itself: no `apps/api` mount/prefix was added, the host `read_principal`/authorization wiring and approved storage/migration remain outstanding, and no live provider was verified. Agent 4's latest follow-up is [PR #8 comment 6681216531](https://github.com/oldman-088/cicc/pull/8#issuecomment-6681216531), after [6681157373](https://github.com/oldman-088/cicc/pull/8#issuecomment-6681157373).

Until the owner-approved contracts are confirmed and mounted, the shared `ResourceState<T>` remains an integration boundary, but no domain endpoint is guessed and no package fixture is rendered as live data.

## Test and deployment status

- Vitest tests cover response parsers, fixed BFF routes, write gates, body validation, origin checks, and browser workspace behavior. Their fixtures are tests only.
- Playwright E2E tests use deterministic route mocks and are not evidence of a live provider. The CI Chromium suite also validates responsive viewports, locale direction, keyboard navigation, and axe-core WCAG A/AA rules; a passing browser check does not prove provider connectivity.
- Local typecheck, unit tests, audit, and production build are repository checks only. Provider connectivity and production readiness require a separately configured deployment and an actual request/response verification.
