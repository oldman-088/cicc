# CICC frontend architecture

**Status:** living document · **Updated:** 2026-11-05

## Product and trust boundary

`apps/web` is a Next.js App Router frontend. The current checkout does not contain the API server or deployment credentials. System Health and Agent Coordination now consume Agent 1's read-side contract documented on open PR #4, current reviewed head `f0589f3935f8918e54b7fa54b983d646e87775b2`; that server is not merged or running in this checkout. Threat Intelligence, Vulnerability Intelligence, Command Theater production data, global search, identity, and tenant preferences remain unconnected.

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
| `/coordination` | `CoordinationWorkspace` | Read-only agents, tasks, aggregates, webhook events; local filtering of returned tasks | Server-side adapter wired to PR #4 contract; consumer adoption from Agents 2/3 is not assumed |
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
- **`CoordinationWorkspace`** independently loads documented agent, task, metric, and event reads. Agent staleness is shown only from the provider's `stale` boolean. The current API reference and `agents.py` disagree on timestamp/counter property names; the decoder accepts only the two reviewed spellings, rejects conflicts, and shows the provider's actual timestamp field name. Agent 1 was asked to align docs/source in [PR #4 follow-up](https://github.com/oldman-088/cicc/pull/4#issuecomment-6656004782). State/search filters apply only to the maximum 100 task records returned by this adapter; there are no write controls.
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
- Automated component tests and JSDOM/axe checks do not establish visual contrast, screen-reader, device, browser/GPU, or WCAG conformance. See `ACCESSIBILITY_REVIEW.md` and `PERFORMANCE_REPORT.md`.

## Extension checklist

Before extending any domain:

- Identify the service owner and reviewed versioned contract; record whether each consumer has agreed.
- Define and enforce user identity, tenant isolation, secret handling, network access, data classification, cache/freshness, pagination, and failure behavior.
- Keep transport behind the server BFF; add runtime schema validation and tests for success, empty, unconfigured, malformed, errors, cancellation/retry, and partial states.
- Define EN/AR/FA, RTL/LTR, keyboard/focus/announcement behavior before adding controls.
- Keep synthetic fixtures out of production paths and preserve their labels.
- Update the contract inventory, architecture, backlog, UX/accessibility docs, and development log with evidence.
- Never claim browser, device, AT, GPU, live API, or tenant-isolation verification that was not performed.
