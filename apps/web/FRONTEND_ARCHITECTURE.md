# CICC frontend architecture

**Status:** living document · **Updated:** 2026-11-06

## Product and trust boundary

`apps/web` is a Next.js App Router frontend. The current checkout does not contain the API server or deployment credentials. PR #4 is open at current M34 head `e10e9f57afed4da715949ac3b3038116977029f2`; its read-only Coordination health and per-task trace routes remain the M33 source introduced at `b112d4c522aed996e1466040774db04f1e1711f4`, consumed through fixed GET-only BFF mappings here. M34 also records a sandbox/fixture-token cross-domain trial through the reference workflow, not this frontend BFF or a production integration. No persistent provider is configured in this checkout; a separate ephemeral local API+BFF request/response smoke is recorded in `DEVELOPMENT_LOG.md`, but no deployed/live service is verified. Threat Intelligence, Vulnerability Intelligence, Command Theater production data, global entity search, identity, and tenant preferences remain unconnected.

The Ops/Coordination contract is explicitly **trusted single-tenant only**: its tables have no `tenant_id`, the frontend does not authenticate users, and a shared API read token does not create user or tenant authorization. The deployment must provide network/access controls and must not expose this UI to untrusted or multiple tenants. The visible page warning is not an access-control mechanism.

A route is not evidence of a connected provider. Do not invent backend paths, payloads, records, status, freshness, provenance, tenant access, or successful actions. Synthetic data is isolated to Command Theater's explicitly selected development demo and test-only API fixtures; neither is used as an operational fallback.

## Route map

| Route | Component | Responsibility | Data availability |
| --- | --- | --- | --- |
| `/` | `WorkspaceOverview` | Module launchpad and integration/trust disclosures | No aggregate provider; no synthetic live counts |
| `/command-theater` | `CommandTheater` | Relationship exploration, evidence/provenance presentation, accessible 2D graph and optional 3D view | Host-injected presentation adapter only; no production CICC provider |
| `/threat-intelligence` | `UnconfiguredModulePage` | Localized destination and planned threat-analysis scope | No API contract/provider |
| `/vulnerability-intelligence` | `UnconfiguredModulePage` | Localized destination and planned exposure/remediation scope | No mounted API or approved host contract |
| `/system-health` | `SystemHealthWorkspace` | Read-only Ops overview/components/metrics/activity, active alerts, and workers | Server-side adapter wired to PR #4 contract; runtime service not configured/verified here |
| `/coordination` | `CoordinationWorkspace` | Read-only agents, tasks, aggregates, webhook events, on-demand health and per-task trace; local filtering of returned tasks | Fixed server-side GET adapter wired to PR #4 M33 reads; ephemeral local API request/response smoke passed; no persistent provider or deployed/live service configured/verified; Agent 2/Replacement Agent 3 adoption is not assumed |
| `/settings` | `SettingsPage` | EN/AR/FA locale and local reduced-motion preference | Browser-local only; no account, user, tenant, or preference-service integration |

## Component and state ownership

```text
src/app/layout.tsx
└── CiccApplication
    └── ApplicationShell
        ├── sticky top bar (brand, breadcrumb, EN/AR/FA selector)
        ├── responsive primary navigation and page-only search
        └── main route content
            ├── WorkspaceOverview
            ├── CommandTheater
            ├── UnconfiguredModulePage (Threat/Vulnerability)
            ├── SystemHealthWorkspace
            │   ├── ResourcePanel (overview / alerts / workers)
            │   └── runtime-validated Ops DTOs
            ├── CoordinationWorkspace
            │   ├── ResourcePanel (metrics / agents / tasks / events)
            │   └── runtime-validated Coordination DTOs
            └── SettingsPage

src/app/api/integrations/[...path]/route.ts
└── fixed GET-only server BFF allowlist
    ├── API_INTERNAL_URL (server-only)
    ├── WEB_BFF_API_TOKEN (server-only, optional if trusted backend is tokenless)
    └── CICC_OPS_TRUSTED_SINGLE_TENANT=true deployment acknowledgement
```

- **`CiccApplication`** owns locale and reduced-motion context. It synchronizes `lang`/`dir` to `<html>` and saves preferences only in browser storage. The motion option is additive to OS reduced motion.
- **`ApplicationShell`** owns responsive navigation, route-label-only search, breadcrumbs, and the `Ctrl/⌘+K` focus shortcut. Search never claims entity/IOC/CVE/alert search.
- **`WorkspaceOverview`** describes what is and is not configured; it does not aggregate backend health/events.
- **`CommandTheater`** owns graph filters, visualization, local selection history, and fallback state. Its typed source boundary is a frontend presentation contract, not a backend schema; see `src/components/command-theater/COMMAND_THEATER_INTEGRATION.md`.
- **`SystemHealthWorkspace`** independently loads the documented Ops overview, active alerts, and worker list. It renders provider fields without inferring health; the exact `live-ops-database` source label is required before counters are displayed. Empty alerts do not imply system health.
- **`CoordinationWorkspace`** independently loads agents, tasks, metrics, webhook events, and the source-reviewed M33 health route. Agent staleness is shown only from the provider's `stale` boolean; the current source also returns a provider health classification. Its decoder retains compatibility with the two previously observed timestamp/counter spellings while rejecting conflicting aliases. Health status and reasons are API-reported; the on-demand response explicitly says it is not continuous monitoring. Each task can lazily load its read-only correlation/audit trace (events, delivery attempts, approval records) from a fixed BFF path. State/search filters still apply only to the maximum 100 task records returned; no write controls exist. PR #4's public API reference currently omits some M33 health/trace details, and Agent 1 has been asked to align it.
- **`ResourcePanel` / `useIntegrationResource`** distinguish initial loading, unconfigured provider, request/authorization/rate-limit errors, malformed DTO, empty success, retry, and prior successful data shown as stale after refresh failure. Refresh is manual; there is no polling.
- **`src/lib/integration-api.ts`** declares the reviewed DTO shapes and validates unknown JSON at runtime. It never substitutes fixtures after a provider error.

## Server-side integration boundary

The browser calls only relative same-origin endpoints under `/api/integrations/...`. The BFF maps a finite list of UI resources to the owner-confirmed Ops and Coordination base paths; it does not accept arbitrary proxy URLs or methods beyond GET, returns 405 for HEAD instead of implicitly proxying it, does not forward browser cookies or client authorization/tenant headers, rejects redirects, constrains query names/values, uses no-store behavior and a 5-second timeout, streams at most 2 MB of response JSON, and returns sanitized error codes. `WEB_BFF_API_TOKEN` is injected only by the Node route handler; no `NEXT_PUBLIC_*` credential is used. When `WEB_BFF_ENFORCE_SAME_ORIGIN=1`, cross-site browser requests are rejected.

`API_INTERNAL_URL` and `CICC_OPS_TRUSTED_SINGLE_TENANT=true` are mandatory in every deployment. With `WEB_BFF_API_TOKEN` configured, the BFF sends `Authorization: Bearer …` to the backend; if the backend read gate uses `CICC_OPS_READ_TOKEN`, the server-side BFF value must match it. Without a BFF token, the flag explicitly acknowledges a tokenless trusted-network deployment. This flag does not authenticate users or isolate tenants; the actual deployment remains responsible for network and user access controls. If the URL or flag is missing, the route fails closed as not configured. The UI never labels that state as a backend outage or an empty result.

Exact API versions, paths, DTOs, errors, cache handling, and unresolved adoption/security limits are maintained in `API_INTEGRATION_CONTRACTS.md`. PR #4 remains open and separate; this frontend does not modify its branch or backend files.

## Runtime and localization rules

1. Route modules import page components; app metadata/provider/styles live in `src/app/layout.tsx` and `src/app/globals.css`.
2. Typed EN/AR/FA messages update language and direction. English is LTR; Arabic/Persian are RTL. Use logical CSS and isolate mixed-direction technical IDs.
3. All service requests from components go to the same-origin BFF. No browser code reads `API_INTERNAL_URL` or a service token.
4. Only owner-documented GET endpoints are mapped. Do not add API writes, GitHub synchronization, mutation buttons, or tenant assumptions without a new owner review.
5. Render source status, cache fields, timestamps, and error semantics only as provided. Unknown operational source labels withhold counters; last response-receipt time is explicitly browser-local, not source freshness.
6. Keep test fixtures synthetic, test-only, and isolated. A 200 route or fixture test is not a live integration check.

## Rendering, accessibility, and performance boundaries

- Next.js route splitting and dynamic Command Theater 3D import remain in place; accessible 2D and explorer paths are preserved.
- Graph limits remain 250 nodes/relationships per visualization and 50 visible explorer rows per page.
- Shared tokens are in `src/app/globals.css`; page styles are CSS Modules. System Health and Coordination use responsive two-column layouts that collapse on narrow screens.
- `prefers-reduced-motion`, local motion reduction, visible focus, and forced-color focus styles are implemented; browser validation remains outstanding.
- Current unit/component coverage is 91 tests across 17 files. JSDOM/axe checks are structural and do not establish visual contrast or WCAG conformance. Three Coordination Playwright E2E specs are present and discoverable, but the suite cannot launch in this sandbox because its Chromium binary is absent; no E2E assertions have passed here.
- No automated or HTTP check establishes screen-reader, device, real-browser layout, browser/GPU, or WCAG conformance. See `ACCESSIBILITY_REVIEW.md` and `PERFORMANCE_REPORT.md`.

## Extension checklist

Before extending any domain:

- Identify the service owner and reviewed versioned contract; record whether each consumer has agreed.
- Define and enforce user identity, tenant isolation, secret handling, network access, data classification, cache/freshness, pagination, and failure behavior.
- Keep transport behind the server BFF; add runtime schema validation and tests for success, empty, unconfigured, malformed, errors, cancellation/retry, and partial states.
- Define EN/AR/FA, RTL/LTR, keyboard/focus/announcement behavior before adding controls.
- Keep synthetic fixtures out of production paths and preserve their labels.
- Update the contract inventory, architecture, backlog, UX/accessibility docs, and development log with evidence.
- Never claim browser, device, AT, GPU, live API, or tenant-isolation verification that was not performed.
