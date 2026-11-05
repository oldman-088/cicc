# CICC frontend API integration contracts

**Status:** frontend contract inventory and adapter record · **Updated:** 2026-11-05

## Repository and trust boundary

This branch contains the Next.js frontend only; it does not contain PR #4's API server, deployment credentials, a user-authentication flow, or tenant isolation for Ops/Coordination records. The frontend does not define backend routes or grant authorization. Contract evidence below was re-reviewed on the current PR #4 head `43c90259b3868340d4e1b929a9fb2b74250b6c29`, including its M14 BFF update, `docs/API_REFERENCE.md`, `docs/INTEGRATION_CONTRACTS.md`, `docs/CONTRACT_ADOPTION.md`, `docs/TENANT_ISOLATION_DECISION.md`, the Ops router/schemas, Coordination router, and M20 contract descriptor/tests. Compared with the previously reviewed `f0589f3935f8918e54b7fa54b983d646e87775b2`, M20 changed the machine-readable coordination descriptor and conformance/reliability tests/documentation. It did not change `docs/API_REFERENCE.md`, `agents.py`, `registry.py`, or the `GET /agents` response DTO; its DTO consistency checks cover request Pydantic models, not the agent-list response. The `last_seen` / `completed_tasks` / `failed_tasks` versus `last_heartbeat` / `completed` / `failed` mismatch remains.

Agent 1 confirmed the Ops and Coordination paths, read DTOs, selected error meanings, cache metadata, and current trust model in PR #4 comment [#6655128197](https://github.com/oldman-088/cicc/pull/4#issuecomment-6655128197). This is the service owner's contract evidence for those two domains; it is **not** agreement from Agents 2/3, a merged/deployed API, or proof of a multi-tenant authorization boundary. PR #4 also states that it ships a reference dashboard while Agent 4 owns the final frontend. Agents 2/3 have not confirmed adoption.

The current backend contract is **trusted, single-tenant only**. Ops/Coordination tables have no `tenant_id`; the platform-auth adapter is inert unless deployment-configured and does not add tenant scoping. This frontend has no user/session authorization. A server-side shared read token protects the API credential from the browser, but does not authenticate frontend users or isolate tenants. The app and API must therefore be restricted by trusted deployment/network controls; the UI warning is informational, not an access-control mechanism. Do not expose this adapter to untrusted or multi-tenant users.

Never put `WEB_BFF_API_TOKEN`, `CICC_OPS_READ_TOKEN`, `API_INTERNAL_URL`, or other service credentials in `NEXT_PUBLIC_*`, browser storage, client props, URLs, or logs. Do not implement guessed paths, direct browser calls to private services, write actions, or synthetic operational records.

## Integration inventory

| Domain / capability | Frontend state | Contract and boundary |
| --- | --- | --- |
| Command Theater graph | Typed injected presentation adapter, runtime validation, explicit development-only synthetic provider | Frontend presentation contract only; no production CICC provider/API contract |
| Threat Intelligence | Explicit unconfigured page | PR #3 reviewed diff contains ingestion/service work but no frontend-consumable HTTP/OpenAPI contract; no adapter |
| Vulnerability Intelligence | Explicit unconfigured page | PR #1 documents package-level reads, not mounted in the host; tenant/auth ownership remains proposed; no adapter |
| System Health | Read-only server-side BFF and localized dashboard | PR #4 M13 Ops contract below; configured runtime provider is **not verified in this checkout** |
| Agent Coordination | Read-only server-side BFF and localized dashboard | PR #4 coordination v1.0 DTOs below; Agent 1 confirms paths, but Agents 2/3 have not confirmed adoption; provider is **not verified in this checkout** |
| Global entity search | Sidebar filters page destinations only | No entity-search/index contract; not implemented |
| User authentication, roles, tenants | Not implemented | No frontend host/session-to-service contract; the API's current Ops/Coordination scope is single-tenant trusted only |
| User preferences | EN/AR/FA and reduced-motion are browser-local | No account preferences or cross-device sync |

## PR #4 contract evidence (current head)

The backend remains on an open, separate PR branch and is not edited or copied by this PR. The current source artifacts are `docs/API_REFERENCE.md` (M13 read-side DTOs plus M14 BFF behavior), `docs/INTEGRATION_CONTRACTS.md` (Coordination v1.0), `docs/TENANT_ISOLATION_DECISION.md`, `apps/api/app/routers/ops.py`, `apps/api/app/schemas.py`, `apps/api/app/coordination/agents.py`, `apps/api/app/coordination/registry.py`, and `apps/api/app/coordination/router.py`.

### Operations

- Base: `/api/v1/ops`.
- Contract schemas: `OverviewResponse`, `ComponentListResponse`, `AlertsResponse`, `WorkersResponse`, and related Pydantic models in `apps/api/app/schemas.py`.
- This UI reads only `GET /overview`, `GET /alerts?state=active&limit=100`, and `GET /workers`. The overview provides `generated_at`, `overall_status`, `services[]`, `modules[]`, metrics/activity, `data_source`, optional `cached`, and optional `cache_age_s`.
- The reviewed `ops.py` implementation currently returns `data_source: "live-ops-database"`; the UI displays those overview counters only when that exact reviewed source label is returned. For an unknown label it withholds the counters while retaining the provider-supplied status/components and source label. The API's `cached` and `cache_age_s` fields are displayed as supplied; the UI does not call cached data live.
- Active-alert empty state explicitly does not claim that all services are healthy. Worker records say only what the Ops API reports; they are not Arena agent/session claims.

### Coordination

- Base: `/api/v1/coordination`.
- This UI reads `GET /agents`, `GET /tasks?limit=100`, `GET /metrics`, and `GET /events?limit=100`.
- `tasks[]`, metrics, and events are runtime-validated against the M13 reference and current router/registry fields. A fresh source review found an **Agent DTO mismatch**: `docs/API_REFERENCE.md` says `last_seen`, `completed_tasks`, and `failed_tasks`, while the current `agents.py` → `registry.task_stats_by_agent()` implementation returns `last_heartbeat`, `completed`, and `failed`; the router returns this object without renaming. This discrepancy is unresolved; Agent 1 was asked to align the docs and wire response in [PR #4 follow-up](https://github.com/oldman-088/cicc/pull/4#issuecomment-6656004782), and it is not treated as resolved. The adapter accepts only these two explicitly observed spellings, rejects conflicting duplicate aliases, and the UI exposes the actual timestamp field name; confirm the canonical DTO before live promotion.
- Task search and state filtering happen only over the returned response (at most 100 records in this adapter); the UI does not claim a global query or pagination contract. State values are displayed as returned. A stale-agent flag is shown only when `stale: true` is supplied by the API.
- This adapter implements **GET only**. It does not create tasks, heartbeat/register agents, route/deliver/ack tasks, approve/reject work, or call `github/status`/`github/sync`. Counts of deliveries are not claims of broker-confirmed delivery.

### Authentication, tenancy, errors, and cache

- PR #4 documents optional `CICC_OPS_READ_TOKEN` Bearer protection for Ops/Coordination reads; a configured write token also satisfies the read gate. Its M14 reference BFF reads server-only `WEB_BFF_API_TOKEN` and injects that value as `Authorization: Bearer …`. If the backend read gate is enabled, the deployer must provision the matching value; do not put either name in `NEXT_PUBLIC_*`. The platform-auth adapter remains inert unless configured and does not add tenant scope.
- This frontend uses its own **fixed-path GET allowlist** at `/api/integrations/{ops|coordination}/...`, not the reference BFF's generic `/api/[...path]` proxy. The browser calls same-origin relative URLs only. The Node handler builds a fresh upstream header set (`Accept` plus the server-only BFF token), so client `Authorization`, cookies, and `x-cicc-*` headers are not forwarded. It accepts no arbitrary proxy destination, exposes no write methods, returns 405 for `HEAD` rather than implicitly proxying it through `GET`, rejects redirects, bounds queries and time (5 seconds) and streams no more than 2 MB of response JSON, and returns no-store sanitized responses. When `WEB_BFF_ENFORCE_SAME_ORIGIN=1`, requests marked `Sec-Fetch-Site: cross-site` are rejected; a missing header is allowed for non-browser clients, as in the PR #4 BFF utility.
- This frontend additionally requires `CICC_OPS_TRUSTED_SINGLE_TENANT=true` in every deployment because the UI has no user/session auth and the upstream data is global. This is a local operator acknowledgement, **not** user authentication or network isolation, and is not an API contract from PR #4. A tokenless backend is permitted only after that acknowledgement and must be restricted to a trusted private network. If `API_INTERNAL_URL` or the acknowledgement is missing, the BFF fails closed with `provider_not_configured` and makes no upstream request.
- Upstream error details are not reflected to the browser. The BFF normalizes known HTTP failures (401, 403, 404, 409, 410, 413, 422, 429, and upstream failures) to a small error code, preserves only a safe numeric `Retry-After`, and returns no-store responses. The UI distinguishes not configured, unauthorized/forbidden, rate-limited, invalid payload, not found, and unavailable states. Runtime DTO validation prevents malformed JSON from becoming records.
- Coordination has no separate cache metadata in the reviewed DTOs. The UI labels only the browser's last successful response-receipt time; it does not label it as source freshness. Ops overview cache metadata remains provider-supplied (`OVERVIEW_CACHE_TTL_S=2.0` in the reference docs).

## Frontend adapter and tests

- Server BFF: `src/app/api/integrations/[...path]/route.ts` (Node runtime, GET-only allowlist, no token in client bundle).
- Relative endpoint names and runtime response decoders: `src/lib/integration-api.ts`.
- Data state: `useIntegrationResource` and `ResourcePanel` distinguish loading, unconfigured, provider error, malformed response, empty success, retry, and a prior successful response shown as stale after refresh failure. Requests are manual-refresh only; there is no polling.
- System Health and Coordination pages are localized EN/AR/FA and read-only. Both visibly disclose the trusted single-tenant/no-user-auth boundary. The other domains stay unconfigured.
- Automated fixtures are synthetic and isolated in tests only; they do not feed production UI. BFF tests verify fixed destinations, `WEB_BFF_API_TOKEN` server-side injection without forwarding client authorization/cookies/tenant headers, trusted single-tenant gating, tokenless opt-in, `HEAD` rejection, same-origin enforcement, query bounds, streaming response-size limits, and error sanitization. Component tests verify no-token same-origin client requests, source handling, unconfigured/error states, local task filtering, DTO aliases, and provider-reported stale state. These tests are not a live integration verification.
- This checkout has no configured `API_INTERNAL_URL`, BFF token/trust acknowledgement, or approved integration environment, so no request to PR #4's service has been verified. Do not advertise a connected/live badge until a deployment and authorization/network review plus reproducible integration check exist.

## Other open-PR contracts remain unbound

### Vulnerability Intelligence — PR #1

`docs/vulnerability-intelligence/API.md` describes package-level `GET /v1/vulnerabilities` and `GET /v1/vulnerabilities/{cve}`, with list filters/pagination and provenance/freshness fields. The package does not authenticate and is not mounted in the host application; its cross-system contract leaves tenant scope to the host and is proposed, not agreed. The sample host's HTTP error envelope may differ from the package example. No network client is implemented. Owner discussion: [PR #1](https://github.com/oldman-088/cicc/pull/1#issuecomment-6654459415).

### Threat Intelligence — PR #3

The reviewed PR #3 diff contains ingestion/service and architecture work but no frontend-consumable HTTP router/OpenAPI DTO, auth/session contract, tenant-resolution behavior, or verified-vs-fixture wire semantics. No network client is implemented. Owner discussion: [PR #3](https://github.com/oldman-088/cicc/pull/3#issuecomment-6654459704).

## Remaining decisions and verification

- Agents 2/3 have not confirmed Coordination v1.0; do not claim their adoption or bind their workflows to the API.
- Current Ops/Coordination scope is single-tenant trusted only. Any move to multi-tenant or user-facing exposure requires an owner-approved auth/tenant isolation design and an actual enforced implementation, not just a shared read token or this UI warning.
- Backend deployment URL, DNS/network path, token provisioning/rotation, API availability, and browser-visible deployment access controls must be verified by the deployer.
- No browser visual QA or screenshot could be performed in this environment. Automated JSDOM/axe checks (where applicable), typecheck, build, audit, and HTTP smoke do not constitute visual/device/AT validation.
- Before promoting either page to “connected/live”, record the deployed contract version/owner, successful authenticated integration test, network/auth review, source/cache semantics, error behavior, and manual browser/a11y evidence.

## General mapping rules

- Keep backend transport behind the host-owned BFF; frontend components consume validated typed DTOs only.
- Keep configured provider failures distinct from unconfigured, empty-success, malformed, cached, and test-fixture states. Preserve prior data only with an explicit stale warning.
- Never infer entity confidence, provenance, status, health, delivery confirmation, freshness, or tenant access beyond returned contract fields.
- Add integration tests only against an approved service environment; label all local test fixtures as synthetic and never substitute them after failure.
