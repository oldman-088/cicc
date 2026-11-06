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

The Coordination API source at PR #4 head `ab458ec11ec685c4d9364cb6f865d63c4d460d81` documents `POST /api/v1/coordination/tasks/{task_id}/route` with an empty request body and a response containing `task_id`, `agent`, `state`, and an `explanation`. Its handler first depends on `read_token_dependency`, then explicitly calls `require_write_token(Authorization)` and `write_rate_limit_dependency`; it accepts no routing payload or caller-selected agent. The handler invokes routing policy and mutates the task's assigned agent, routing explanation, and state (`QUEUED` when an agent is selected, otherwise `BLOCKED`). This is not a harmless read operation.

The reference web BFF in PR #4 (`apps/web/lib/bff.mjs`) explicitly allowlists only task creation; its source comments and tests deny other browser writes. PR #2 previously added a second browser-facing BFF route behind `WEB_BFF_ALLOW_COORD_ROUTING=1`, but no explicit BFF-policy approval for that extension was found. **That extension has been removed.** PR #2 does not expose a browser route, capability flag, or UI action for routing. Provider-returned assignment and routing explanations on existing task records remain visible as read-only data. The BFF returns `404` for `/api/integrations/coordination/tasks/{task_id}/route` regardless of the old routing environment variable, and tests pin that denial while keeping the create-only path covered.

This boundary matches the reviewed reference policy and avoids broadening writes from a frontend that has no user authentication or tenant isolation. Reconsider only after Agent 1 records explicit owner approval and the required principal, same-origin/CSRF, tenant-resolution, and server-side gate controls in the authoritative BFF policy.

### Agent 1 domain-gateway contract (reviewed separately from the browser BFF)

PR #4 head `ab458ec11ec685c4d9364cb6f865d63c4d460d81` also contains `GET /api/v1/coordination/domains` and `GET /api/v1/coordination/domains/{kind}/status` read-token endpoints for evidence-based handler lifecycle status (`NOT_MOUNTED`, `MOUNTED`, `AVAILABLE`, `EXECUTION_VERIFIED`, `DEGRADED`, `FAILED`, `UNKNOWN`). `POST /domains/{kind}/mount`, `/deregister`, and `/invoke` require the read dependency plus the API write token. In particular, `/invoke` creates a task, calls the mounted handler, then persists the result, provenance, and trace; the contract descriptor explicitly says the BFF write surface stays `POST /tasks`. PR #2 exposes none of these new domain endpoints today: it does not expose `invoke`, and a per-domain status BFF/UI mapping is pending confirmation from Agent 1 of stable kind IDs and the accepted status DTO/semantics. This does not widen the approved browser write policy.

Agent 1 reports a sandbox M40 mount/invoke trial for `threat_intel`, with `EXPERIMENTAL_DEMO_DATA_ONLY` preserved and a trace persisted. That is Agent 1-reported sandbox evidence, not an Agent 4 rerun, deployed provider verification, or evidence that sample intelligence is live. Until the status contract is confirmed and a real host integration is independently verified, the frontend keeps the Threat and Vulnerability pages disconnected and does not render gateway or package fixtures as intelligence data.

## Threat and vulnerability intelligence

Neither domain is wired to a CICC host HTTP endpoint, and neither page issues a request or displays provider data. The pages remain explicit not-connected states; no provider URL, fixture-backed dashboard, indicator/CVE count, or inferred source health is added.

- **Threat Intelligence — Agent 2 / PR #3** (`4f1776f83d929aa7ef951952808fa6d1569a2a1c`, reviewed 2026-11-06): `apps/threat_intelligence/api.py` declares 12 in-process paths, explicitly described as simulated mount points. Its handlers return experimental sample records and `invoke_endpoint` is an in-process dispatcher. The changed files do not add a host-mounted FastAPI/ASGI route or host auth/tenant binding. This is not a browser API contract and its sample records are not live intelligence.
- **Vulnerability Intelligence — replacement Agent 3 / PR #8** (`1524c923d4ef081938db67ed5a0641bc5e426e28`, reviewed 2026-11-06): the package contains a tested ASGI read surface and an OpenAPI proposal for `GET /v1/vulnerabilities` and `GET /v1/vulnerabilities/{cve}`. The OpenAPI itself labels the contract `PROPOSED`; it says the host prefix/mount and authentication/tenant binding are pending. The package requires an injected tenant resolver and does not authenticate a host principal. It is not evidence of a CICC host route or a deployed service.

Agent 4 has requested the missing owner-confirmed mounting and auth/tenant evidence on PRs #3 and #8. Until those contracts are accepted and mounted, the shared `ResourceState<T>` remains available as an integration boundary, but no domain endpoint is guessed and no package fixture is rendered as live data.

## Test and deployment status

- Vitest tests cover response parsers, fixed BFF routes, write gates, body validation, origin checks, and browser workspace behavior. Their fixtures are tests only.
- Playwright E2E tests use deterministic route mocks and are not evidence of a live provider. The CI Chromium suite also validates responsive viewports, locale direction, keyboard navigation, and axe-core WCAG A/AA rules; a passing browser check does not prove provider connectivity.
- Local typecheck, unit tests, audit, and production build are repository checks only. Provider connectivity and production readiness require a separately configured deployment and an actual request/response verification.
