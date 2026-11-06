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

Latest reviewed PR #4 head: `014a096b506645b7ab0b04b9fdbe320e02240276`. The source exposes read-token `GET /api/v1/coordination/domains` and `GET /api/v1/coordination/domains/{kind}/status` for handler lifecycle status (`NOT_MOUNTED`, `MOUNTED`, `AVAILABLE`, `EXECUTION_VERIFIED`, `DEGRADED`, `FAILED`, `UNKNOWN`). For a mounted handler, status evidence includes code/version reference, mount time, invoke/success/consecutive-failure counts, last invocation time, last status, and sanitized last error. An unknown or unregistered kind currently returns HTTP 200 with `NOT_MOUNTED` and a `no handler registered` note. This is source evidence, not yet an owner-approved frontend DTO. In particular, `last_invoke_at` is execution time, not provider-data freshness; the status route does not itself establish provenance or freshness of intelligence records.

Agent 1 has since published `docs/FRONTEND_CONTRACTS.md` and `docs/INTEGRATION_EXAMPLES.md` at PR #4 head `014a096b506645b7ab0b04b9fdbe320e02240276`. They document the stable IDs `threat_intel` and `vuln_intel`, the BFF-proxied `GET /health` domains component plus `GET /domains` and `GET /domains/{kind}/status` shapes, the seven lifecycle states, and loading/empty/unmounted/unavailable/verified/unknown UI mapping. They specify server-side `CICC_OPS_READ_TOKEN` auth and list the general error status codes. This is useful source-level contract evidence, but the descriptor still calls tenant context **PENDING owner decision** (single-tenant now, no tenant header); AMD-003 also remains pending owner approval for the shared status routes/extended health shape.

Two additional gates remain before frontend binding. First, `list_domains()` and `domain_status()` load persisted stats, call `_persist_domain_stats()`, and commit the session while serving GETs; the owner must confirm whether that write side effect is acceptable or require a pure read. Second, the DTO details are not fully pinned across the descriptor, examples, and source: the descriptor/example omit fields that `domains.all_statuses()` currently returns (such as `mounted_at` and `consecutive_failures`), and the exact per-route error envelope still needs a typed definition. Agent 4 has asked Agent 1 to reconcile the DTO and confirm the owner gates on [PR #4 follow-up 6680919000](https://github.com/oldman-088/cicc/pull/4#issuecomment-6680919000), building on the initial contract request [6680159032](https://github.com/oldman-088/cicc/pull/4#issuecomment-6680159032). No status mapping is implemented in this branch pending owner confirmation.

`POST /domains/{kind}/mount`, `/deregister`, and `/invoke` require write authorization in addition to the read dependency. In particular, `/invoke` creates a task, invokes the mounted handler, and persists its result, provenance, and trace. PR #2 does not expose these domain routes; its browser-write contract remains task-creation-only. Agent 1's M39 `vuln_intel` adapter is an internal package adapter, not a host HTTP mount or a browser API.

Agent 1 reports a sandbox M40 mount/invoke trial for `threat_intel`, with `EXPERIMENTAL_DEMO_DATA_ONLY` preserved and a trace persisted. That is Agent 1-reported sandbox evidence, not an Agent 4 rerun, deployed provider verification, or evidence that sample intelligence is live. The Threat and Vulnerability pages remain disconnected; gateway and package fixtures are not rendered as live intelligence data.

## Threat and vulnerability intelligence

Neither domain is wired to a confirmed CICC host HTTP endpoint, and neither page issues an intelligence request or displays provider records. No provider URL, fixture-backed dashboard, indicator/CVE count, or inferred source health is added.

- **Threat Intelligence — Agent 2 / PR #3** (`4f1776f83d929aa7ef951952808fa6d1569a2a1c`, reviewed 2026-11-06): `apps/threat_intelligence/api.py` declares in-process paths described as simulated mount points. Its handlers return experimental sample records and `invoke_endpoint` is an in-process dispatcher. The reviewed changes do not establish a host-mounted HTTP route or host auth/tenant binding. Agent 1's separate sandbox gateway adapter is not a substitute for that host contract. Agent 4's current request for the route, DTO, auth/tenant, provenance, and verification details is [PR #3 comment 6680818606](https://github.com/oldman-088/cicc/pull/3#issuecomment-6680818606).
- **Vulnerability Intelligence — replacement Agent 3 / PR #8** (`7f6db2a8cb92f186f16ab35e2af882efca2d6b99`, reviewed 2026-11-06): the package now contains a tested, mountable ASGI read app with `GET /v1/vulnerabilities`, `GET /v1/vulnerabilities/{cve}`, and `GET /v1/vulnerabilities/export/{format}` (`vex`, `openvex`, or `sarif`). The list supports bounded pagination (`limit` up to 200 plus a cursor); exports accept an optional JSON `dependencies` inventory and refuse to truncate above 5,000 records. Export metadata distinguishes `generated_at`, `record_count`, whether exposure was evaluated, `unassessed` records, and an empty tenant. The OpenAPI also describes record origin, provenance/confidence, and a separate freshness view. These are package-level contract facts only: `openapi.yaml` still labels itself `PROPOSED`; no CICC host mount or prefix is selected; and the app relies on the host to inject `resolve_tenant(scope)` from an authenticated principal. The package itself does not authenticate, and its demo header resolver is not safe deployment auth. It is not evidence of a CICC host route, live provider data, or deployed verification. Agent 4's current request is [PR #8 comment 6680818578](https://github.com/oldman-088/cicc/pull/8#issuecomment-6680818578).

Until the owner-approved contracts are confirmed and mounted, the shared `ResourceState<T>` remains an integration boundary, but no domain endpoint is guessed and no package fixture is rendered as live data.

## Test and deployment status

- Vitest tests cover response parsers, fixed BFF routes, write gates, body validation, origin checks, and browser workspace behavior. Their fixtures are tests only.
- Playwright E2E tests use deterministic route mocks and are not evidence of a live provider. The CI Chromium suite also validates responsive viewports, locale direction, keyboard navigation, and axe-core WCAG A/AA rules; a passing browser check does not prove provider connectivity.
- Local typecheck, unit tests, audit, and production build are repository checks only. Provider connectivity and production readiness require a separately configured deployment and an actual request/response verification.
