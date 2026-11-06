# CICC frontend API integration contracts

**Status:** frontend contract inventory and adapter record · **Updated:** 2026-11-06

## Repository and trust boundary

This branch contains the Next.js frontend only; it does not contain PR #4's API server, deployment credentials, a user-authentication flow, or tenant isolation for Ops/Coordination records. The frontend does not define backend routes or grant authorization. External contract evidence was re-reviewed at current PR #4 head `e10e9f57afed4da715949ac3b3038116977029f2` (M34), including `docs/API_REFERENCE.md`, the Coordination router/registry, health/trace implementations, adoption record, and BFF. M34 adds adoption-stage vocabulary and a sandbox/fixture-token cross-domain trial; it does not change the M33 health/trace route implementations. The source returns canonical agent keys `last_heartbeat`, `completed`, `failed`, and `health`; this supersedes the DTO mismatch recorded against M20 head `43c90259b3868340d4e1b929a9fb2b74250b6c29`. The current API reference still omits the `health` agent field and the `/health` and task `/trace` read schemas; alignment requests are recorded at [PR #4 comment #6678099565](https://github.com/oldman-088/cicc/pull/4#issuecomment-6678099565) and the M34 follow-up [#6678515605](https://github.com/oldman-088/cicc/pull/4#issuecomment-6678515605). No deployed service is configured for this checkout; an isolated local source/API request-response smoke is documented below, not a production integration.

Agent 1's PR #4 documents the trusted, single-tenant trust boundary and read credentials. Agents 2 and Replacement Agent 3 have not confirmed coordination v1.0 adoption. The latest PR #4 checkpoint records Agent 2 as unavailable and Agent 6 as active Threat Intelligence backup; no task or approval is inferred from silence. PR #4 remains separate and unmerged, and none of this evidence establishes a deployed multi-tenant authorization boundary.

PR #4 M34 records a 32/32 `scripts/cross_domain_trial.py` run using sandbox/fixture tokens and synthetic domain-agent IDs, against its coordination/reference-BFF workflow. That is useful fixture-labelled coordination-layer evidence, not production/live verification, not a request through this branch's `/api/integrations/...` BFF, and not evidence that Agent 2 or Replacement Agent 3 adopted the contract. Separately, on 2026-11-06 an isolated copy of PR #4 M34's API was run on a temporary SQLite database with test-only tokens; a direct API POST created synthetic task `arena-frontend-smoke-20261106`, then this branch's actual BFF handler made real local HTTP GETs for `/health` and `/tasks/{task_id}/trace`. Both returned 200 and their JSON passed `parseCoordinationHealth` / `parseCoordinationTaskTrace`, including the task's idempotency key and `created` trace event. The temporary service, database, tokens, and smoke test were removed. This verifies the local source-to-adapter request/response path only—not a deployed/live service or the current preview. No persistent upstream URL/token/trust acknowledgement is configured.

The current backend contract is **trusted, single-tenant only**. Ops/Coordination tables have no `tenant_id`; the platform-auth adapter is inert unless deployment-configured and does not add tenant scoping. This frontend has no user/session authorization. A server-side shared read token protects the API credential from the browser, but does not authenticate frontend users or isolate tenants. The app and API must therefore be restricted by trusted deployment/network controls; the UI warning is informational, not an access-control mechanism. Do not expose this adapter to untrusted or multi-tenant users.

Never put `WEB_BFF_API_TOKEN`, `CICC_OPS_READ_TOKEN`, `API_INTERNAL_URL`, or other service credentials in `NEXT_PUBLIC_*`, browser storage, client props, URLs, or logs. Do not implement guessed paths, direct browser calls to private services, write actions, or synthetic operational records.

## Integration inventory

| Domain / capability | Frontend state | Contract and boundary |
| --- | --- | --- |
| Command Theater graph | Typed injected presentation adapter, runtime validation, explicit development-only synthetic provider | Frontend presentation contract only; no production CICC provider/API contract |
| Threat Intelligence | Explicit unconfigured page | PR #3 has no frontend-consumable HTTP/OpenAPI binding; PR #6's domain/contract modules remain proposed and fixture-tested, not mounted; no adapter |
| Vulnerability Intelligence | Explicit unconfigured page | PR #1 package reads plus PR #8's OpenAPI are still proposed and not mounted; no host auth/tenant binding; no adapter |
| System Health | Read-only server-side BFF and localized dashboard | PR #4 Ops GETs; the configured runtime provider is **not verified in this checkout** |
| Agent Coordination | Read-only server-side BFF and localized dashboard, now including API-reported health and on-demand task trace | Current PR #4 M34 head retains M33 GET source. An isolated local M34 API + SQLite request/response smoke passed through this BFF handler; the persistent preview has **no provider configured and no deployed/live verification**. Agents 2/Replacement Agent 3 adoption remains unconfirmed |
| Global entity search | Sidebar filters page destinations only | No entity-search/index contract; not implemented |
| User authentication, roles, tenants | Not implemented | No frontend host/session-to-service contract; the API's current Ops/Coordination scope is single-tenant trusted only |
| User preferences | EN/AR/FA and reduced-motion are browser-local | No account preferences or cross-device sync |

## PR #4 contract evidence (current head M34; read-route source introduced at M33)

The backend remains on an open, separate PR branch and is not edited or copied by this PR. Current PR #4 head is `e10e9f57afed4da715949ac3b3038116977029f2`; M34 changes adoption-stage documentation and adds the fixture-labelled cross-domain trial, while the health/trace router implementations remain the M33 source at `b112d4c522aed996e1466040774db04f1e1711f4`. The reviewed artifacts include `docs/API_REFERENCE.md`, `docs/CONTRACT_ADOPTION.md`, `docs/TENANT_ISOLATION_DECISION.md`, the Ops schemas/router, Coordination router, `agents.py`, and `registry.py`. The reference API document has not yet caught up with all read routes in the current router; health and task-trace shapes below are derived from the source implementation and need Agent 1's documentation confirmation. PR #4 is open and unmerged; source review and its separate sandbox trial are not a live request from this frontend checkout.

### Operations

- Base: `/api/v1/ops`.
- Contract schemas: `OverviewResponse`, `ComponentListResponse`, `AlertsResponse`, `WorkersResponse`, and related Pydantic models in `apps/api/app/schemas.py`.
- This UI reads only `GET /overview`, `GET /alerts?state=active&limit=100`, and `GET /workers`. The overview provides `generated_at`, `overall_status`, `services[]`, `modules[]`, metrics/activity, `data_source`, optional `cached`, and optional `cache_age_s`.
- The reviewed `ops.py` implementation currently returns `data_source: "live-ops-database"`; the UI displays those overview counters only when that exact reviewed source label is returned. For an unknown label it withholds the counters while retaining the provider-supplied status/components and source label. The API's `cached` and `cache_age_s` fields are displayed as supplied; the UI does not call cached data live.
- Active-alert empty state explicitly does not claim that all services are healthy. Worker records say only what the Ops API reports; they are not Arena agent/session claims.

### Coordination

- Base: `/api/v1/coordination`.
- The page reads `GET /agents`, `GET /tasks?limit=100`, `GET /metrics`, `GET /events?limit=100`, and `GET /health`. A task's `GET /tasks/{task_id}/trace` is fetched only when the analyst expands that task's trace control.
- At reviewed PR #4 M33 source, `GET /agents` includes `health`, `last_heartbeat`, `completed`, and `failed`; `agents.py` returns the health classification and registry stats. The frontend still accepts the two previously observed DTO spellings with conflict rejection for compatibility, but current source is canonical for these field names. The public `docs/API_REFERENCE.md` currently omits `health` from its agent DTO line.
- The M33 router source implements `GET /health` as an **on-demand status check**, not continuous monitoring. Its DTO contains `overall`, `components[{key,status,detail,reasons[]}]`, top-level `reasons[]`, `last_operations` timestamps and a source note, and `at`. Health statuses are validated against the source's finite set; the frontend displays provider-reported statuses/reasons and does not infer recovery or freshness.
- The M33 router source implements read-only `GET /tasks/{task_id}/trace` with `task_id`, `correlation{idempotency_key,event_id}`, `state`, `agent`, `attempts`, `dead_letter`, `events[]`, `deliveries[]`, and `approvals[]`. The UI displays each returned record as API-reported; a `human_assisted`/`prepared` delivery is never described as broker-confirmed. The BFF exposes a fixed `coordination/task-trace?task_id=…` GET route, validates a single backend-compatible task-ID segment of 1–128 characters (`[A-Za-z0-9_.:-]`, excluding `.` and `..`), then constructs the reviewed upstream path; browser input cannot choose an upstream URL or path.
- The frontend runtime-validates DTOs. Task search and state filtering apply only to the returned response (maximum 100 in this adapter); this is not global search or API pagination. Stale-agent state is shown only if `stale: true` is supplied by the API. `idempotency_key` is displayed only if the provider returns it.
- This adapter remains **GET only**. It does not create tasks, heartbeat/register agents, route/deliver/ack tasks, approve/reject work, or call GitHub sync. Counts or trace records are not claims of broker-confirmed delivery.

### Authentication, tenancy, errors, and cache

- PR #4 documents optional `CICC_OPS_READ_TOKEN` Bearer protection for Ops/Coordination reads; a configured write token also satisfies the read gate. Its M14 reference BFF reads server-only `WEB_BFF_API_TOKEN` and injects that value as `Authorization: Bearer …`. If the backend read gate is enabled, the deployer must provision the matching value; do not put either name in `NEXT_PUBLIC_*`. The platform-auth adapter remains inert unless configured and does not add tenant scope.
- This frontend uses its own **fixed-path GET allowlist** at `/api/integrations/{ops|coordination}/...`, not the reference BFF's generic `/api/[...path]` proxy. The browser calls same-origin relative URLs only. The Node handler builds a fresh upstream header set (`Accept` plus the server-only BFF token), so client `Authorization`, cookies, and `x-cicc-*` headers are not forwarded. It accepts no arbitrary proxy destination, exposes no write methods, returns 405 for `HEAD` rather than implicitly proxying it through `GET`, rejects redirects, bounds queries and time (5 seconds) and streams no more than 2 MB of response JSON, and returns no-store sanitized responses. When `WEB_BFF_ENFORCE_SAME_ORIGIN=1`, requests marked `Sec-Fetch-Site: cross-site` are rejected; a missing header is allowed for non-browser clients, as in the PR #4 BFF utility.
- This frontend additionally requires `CICC_OPS_TRUSTED_SINGLE_TENANT=true` in every deployment because the UI has no user/session auth and the upstream data is global. This is a local operator acknowledgement, **not** user authentication or network isolation, and is not an API contract from PR #4. A tokenless backend is permitted only after that acknowledgement and must be restricted to a trusted private network. If `API_INTERNAL_URL` or the acknowledgement is missing, the BFF fails closed with `provider_not_configured` and makes no upstream request.
- Upstream error details are not reflected to the browser. The BFF normalizes known HTTP failures (401, 403, 404, 409, 410, 413, 422, 429, and upstream failures) to a small error code, preserves only a safe numeric `Retry-After`, and returns no-store responses. The UI distinguishes not configured, unauthorized/forbidden, rate-limited, invalid payload, not found, and unavailable states. Runtime DTO validation prevents malformed JSON from becoming records.
- Coordination has no separate cache metadata in the reviewed DTOs. The UI labels only the browser's last successful response-receipt time; it does not label it as source freshness. Ops overview cache metadata remains provider-supplied (`OVERVIEW_CACHE_TTL_S=2.0` in the reference docs).

## Frontend adapter and tests

- Server BFF: `src/app/api/integrations/[...path]/route.ts` (Node runtime, fixed GET-only allowlist, no token in client bundle). Added the source-reviewed `/coordination/health` read and lazy `/coordination/tasks/{id}/trace` read.
- Relative endpoint names and strict runtime response decoders: `src/lib/integration-api.ts`.
- `useIntegrationResource` and `ResourcePanel` distinguish loading, unconfigured, provider error (including permission denied), malformed response, empty success, retry, and prior successful data shown as stale after refresh failure. Health/trace resources use this common state model; trace requests are on-demand, not loaded for every task.
- System Health and Coordination are localized EN/AR/FA and read-only. Both disclose the trusted single-tenant/no-user-auth boundary. Threat/Vulnerability remain explicitly disconnected.
- Automated fixtures are synthetic and isolated in unit/E2E tests only; they do not feed production UI. Unit tests cover source health/trace DTO validation, safe task path handling, server-side token injection, no browser credential forwarding, errors and stale states. Playwright coverage intercepts API requests with labelled test-only payloads; it does not prove a deployed integration.
- This checkout has no `API_INTERNAL_URL`, BFF token/trust acknowledgement, or approved integration environment. The configured path therefore fails closed and no request to PR #4's service has been verified. Do not advertise a connected/live badge until a deployment/network/auth review and reproducible request/response evidence exist.

## Other open-PR contracts remain unbound

### Vulnerability Intelligence — PR #1 and Replacement Agent 3 PR #8

At PR #1 head `84fca769f78c1ebede13a22529719f0735cf1afc`, the framework-neutral package exposes/test-drives `/v1/vulnerabilities` and `/v1/vulnerabilities/{cve}`. Current Replacement Agent 3 PR #8 head is `a48e82cb14364de6361ec41cee749b801ffa34de`; its OpenAPI 3.1 document remains explicitly marked `PROPOSED`, with host prefix and binding pending, and VEX/mapping changes remain package-level; no FastAPI host router is mounted. The package itself does not authenticate. Host principal/tenant binding and error-envelope compatibility remain undecided. The candidate paths are **not** called by this frontend until a host route, auth/tenant behavior, and request/response example are confirmed. Host-mount evidence requests are recorded on PR #8 comments [#6678099551](https://github.com/oldman-088/cicc/pull/8#issuecomment-6678099551) and the current-head follow-up [#6678515587](https://github.com/oldman-088/cicc/pull/8#issuecomment-6678515587). No live CVE data is shown.

### Threat Intelligence — Agent 2 PR #3 and active backup PR #6

PR #3 head `1a46f704bc09207d2755fbfd5a7e8ae48b646e1b` has no frontend-consumable HTTP router/OpenAPI DTO. PR #6 head `02616bb5a34bc0dfa6beaee598948b09b7ba1127` adds domain/API-surface and proposed cross-domain contracts, but its current record says no HTTP API is mounted and the implementations are fixture-tested, not verified against live source feeds. The latest PR #4 owner checkpoint says Agent 2 is unavailable and Agent 6 is the active TI backup. No route, provider result, or availability is invented in the UI.

## Remaining decisions and verification

- Agent 2 and Replacement Agent 3 have not confirmed Coordination v1.0 adoption; do not claim their adoption or bind their workflows to it. Agent 2 is recorded unavailable in the latest PR #4 checkpoint; a non-tasking status request is posted on [PR #3 comment #6678099552](https://github.com/oldman-088/cicc/pull/3#issuecomment-6678099552).
- Current Ops/Coordination scope is single-tenant trusted only. Any move to multi-tenant or user-facing exposure requires an owner-approved auth/tenant isolation design and an actual enforced implementation, not just a shared read token or this UI warning.
- Backend deployment URL, DNS/network path, token provisioning/rotation, API availability, and browser-visible deployment access controls must be verified by the deployer.
- Three Playwright Coordination E2E specs are present and discoverable, but the actual run cannot launch because this environment has no Chromium binary; assertions did not execute. No browser visual QA or screenshot could be performed. JSDOM/axe checks (where applicable), typecheck, build, audit, and ordinary HTTP smoke do not constitute visual/device/AT or deployed-service API validation; the separate local API+BFF request/response smoke is described above.
- Before promoting either page to “connected/live”, record the deployed contract version/owner, successful authenticated integration test, network/auth review, source/cache semantics, error behavior, and manual browser/a11y evidence.

## General mapping rules

- Keep backend transport behind the host-owned BFF; frontend components consume validated typed DTOs only.
- Keep configured provider failures distinct from unconfigured, empty-success, malformed, cached, and test-fixture states. Preserve prior data only with an explicit stale warning.
- Never infer entity confidence, provenance, status, health, delivery confirmation, freshness, or tenant access beyond returned contract fields.
- Add integration tests only against an approved service environment; label all local test fixtures as synthetic and never substitute them after failure.
