# Frontend integration contracts

## Scope and evidence

This document describes the web adapter in this repository, not a production deployment. The Coordination provider contract was inspected in the API implementation proposed in PR #4 (`apps/api/app/coordination/router.py`, `apps/api/app/coordination/contract.py`, and the API schemas) at source revision `9d5669f01cfd38c6b30b1c5dada66f10c6c3f84e`. The existence of those source routes does **not** prove that an API is deployed, reachable, or returning these DTOs. The adapter fails closed when `API_INTERNAL_URL` is not configured and validates every JSON response before presenting it.

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
- `WEB_BFF_ALLOW_COORD_WRITE=1` for task creation and, separately, `WEB_BFF_ALLOW_COORD_ROUTING=1` for routing.
- A same-origin `Origin` on each browser POST; cross-origin and non-same-origin fetch metadata are rejected.

The capability endpoint reports whether each action is configured; it does not contact the provider and is not a health check. Both write flags are off unless explicitly configured. The workspace warns that it has no user authentication or tenant isolation; these flags are not a substitute for trusted network access controls.

### Create a task

`POST /api/integrations/coordination/tasks` accepts JSON fields from the Coordination `TaskIn` contract, subject to an additional BFF allowlist and validation. The current form sends `kind`, `title`, `priority`, `payload`, and `requires_approval`. The BFF caps the request body at 256,000 bytes, rejects unknown fields and browser-supplied `task_id`/`idempotency_key`, and creates a `bff-<UUID>` `idempotency_key` server-side. The provider endpoint is the source-confirmed `POST /api/v1/coordination/tasks`; the BFF accepts its `201 application/json` response only when it contains `task_id`, `kind`, `state`, and `duplicate`, and exposes the generated correlation key in `X-CICC-Idempotency-Key`.

The idempotency key correlates a single submitted request with the provider record. A retry after an uncertain network outcome creates a new key; the UI therefore tells the operator to refresh the task list and trace before retrying. It does not claim automatic retry deduplication across separate submissions.

### Route an existing task

The source API documents and implements `POST /api/v1/coordination/tasks/{task_id}/route` with an empty request body and a response containing `task_id`, `agent`, `state`, and an `explanation`. The web adapter exposes only this fixed operation with a validated task ID and no caller-selected agent or arbitrary path/body. It is separately gated by `WEB_BFF_ALLOW_COORD_ROUTING=1` and validates the response before returning it.

**Security/scope note:** the earlier reference web BFF in PR #4 explicitly allowed task creation only. This frontend adds routing as a deliberate extension based on the independently documented API route, not as an inherited approval from that BFF. Keep the routing flag unset unless the deployment owner has reviewed and approved this additional write action. The route flag is independent from the create flag and disabled by default.

## Threat and vulnerability intelligence

No verified Threat Intelligence or Vulnerability Intelligence provider contract is currently wired into this frontend. Consequently, this implementation adds no provider URL, route, DTO, fixture-backed dashboard, CVE/indicator count, or inferred health state for either domain. The `/threat-intelligence` and `/vulnerability-intelligence` pages use a typed module identifier and an explicit not-connected state; they state what data is unavailable and what future scope is planned. The shared generic `ResourceState<T>` boundary is available for a future typed adapter, but a domain DTO and endpoint must come from an authoritative API contract before any request is added.

## Test and deployment status

- Vitest tests cover response parsers, fixed BFF routes, write gates, body validation, origin checks, and browser workspace behavior. Their fixtures are tests only.
- Playwright E2E tests use deterministic route mocks and are not evidence of a live provider.
- Local typecheck, unit tests, audit, and production build are repository checks only. Provider connectivity and production readiness require a separately configured deployment and an actual request/response verification.
