# CICC frontend architecture

**Status:** living document · **Updated:** 2026-11-05

## Product boundary

`apps/web` is a Next.js App Router frontend, not the CICC backend or an API specification. No backend service, OpenAPI document, generated client, authentication contract, tenant contract, or operational-health source is present in this checkout. The frontend owns presentation, local interaction state, adapter validation, and explicit unavailable/error states; a host application/API owner must own transport, credentials, authorization, and any real service state.

A navigable route is not evidence of connected data. Do not add invented endpoints, entity fields, counts, feed status, service state, or agent activity. Synthetic fixtures are allowed only through Command Theater's explicit development-only demo mode and remain visibly marked as synthetic.

## Route map

| Route | Component | Responsibility | Data availability |
| --- | --- | --- | --- |
| `/` | `WorkspaceOverview` | Module launchpad and truthful integration disclosure | No live provider; Command Theater may show isolated synthetic development data |
| `/command-theater` | `CommandTheater` | Relationship exploration, evidence/provenance display, accessible 2D graph and optional 3D graph | Host-owned adapter boundary exists; no production backend adapter is wired |
| `/threat-intelligence` | `UnconfiguredModulePage` | Localized destination and declared threat-analysis scope | Explicitly not configured |
| `/vulnerability-intelligence` | `UnconfiguredModulePage` | Localized destination and declared exposure/remediation scope | Explicitly not configured |
| `/system-health` | `UnconfiguredModulePage` | Localized destination and declared operational scope | Explicitly not configured |
| `/coordination` | `UnconfiguredModulePage` | Localized destination and declared agent/task coordination scope | Explicitly not configured |
| `/settings` | `SettingsPage` | Session-scoped interface locale and local reduced-motion preference | No account, tenant, identity, or preference-service integration |

The four `UnconfiguredModulePage` routes are intentional transparent shells, not data workflows. They explicitly name the absent contract/provider and planned scope; they render no records or status claims. Replace them with real workflows only after the relevant API and product semantics are reviewed.

## Component and state ownership

```text
src/app/layout.tsx
└── CiccApplication
    └── ApplicationShell
        ├── sticky top bar (brand, breadcrumb, EN/AR/FA selector)
        ├── responsive primary navigation
        │   ├── page-only search/filter
        │   └── separate Preferences route
        └── main route content
            ├── WorkspaceOverview
            ├── CommandTheater
            ├── UnconfiguredModulePage(moduleId)
            └── SettingsPage
```

- **`CiccApplication`** (`src/components/application/CiccApplication.tsx`) owns one locale context and a user-level reduced-motion boolean. It synchronizes language/direction to `<html>` and provides the preference actions. Locale is currently in-memory for the active app session and resets on reload. Reduced motion is additive to the operating-system preference; its boolean is saved only in browser `localStorage` (never credentials or account data).
- **`ApplicationShell`** owns shell-only state: mobile-navigation visibility and a query that filters known frontend route labels. Its search scope is deliberately limited to pages. It does not claim entity, IOC, vulnerability, alert, or operational search.
- **`WorkspaceOverview`** chooses the disclosure for the explicit Command Theater demo prop and lists the modules with their availability labels. It creates no counts or inferred status.
- **`CommandTheater`** owns graph filters, visualization selection, selection history, and display fallback state. It accepts an optional host-owned `CommandTheaterDataSource`; the typed adapter interface is a frontend presentation contract, not a server schema. Detailed semantics are in `src/components/command-theater/COMMAND_THEATER_INTEGRATION.md`.
- **`UnconfiguredModulePage`** renders only translated static scope and integration information. It has no transport or data model.
- **`SettingsPage`** writes locale to the app context and the reduced-motion preference to the app context/browser storage. Identity, tenant, theme persistence, and server preference settings are not implemented.

## Runtime and data-flow rules

1. Route modules import the relevant page component; global metadata, styles, and the app provider are defined in `src/app/layout.tsx`.
2. Shell and page strings use EN/AR/FA message maps. The selected locale propagates to `lang`/`dir`; `en` uses LTR, `ar` and `fa` use RTL. Direction must affect layout, focus order, icons, spacing, and mixed-direction IDs, not just text.
3. No page performs an API request except through a host-supplied, reviewed adapter. The frontend must not guess a URL from a service name.
4. A host adapter owns its authenticated transport, tenant boundary, endpoint/schema mapping, retry policy, and server-side filtering. The UI validates the presentation shape and reports provider failures; it does not convert errors into demo results.
5. Status labels describe the **data source state** (`demo`, `not connected`, `unavailable`, `cached`, `live`, or `unverified`) only when supported by source metadata. Never equate a rendered component or an HTTP 200 route with a healthy backend.
6. Search is navigation-only today. Expanding it to entity search requires a search contract, authorization semantics, pagination/ranking, errors, freshness, and provenance.

## Rendering, performance, and failure boundaries

- The Next.js App Router provides route-level code splitting. Command Theater's 3D scene is dynamically imported without SSR; the default/accessible 2D view remains available when WebGL is unavailable or fails.
- Graph rendering is bounded to 250 entities and 250 relationships per visualization; the accessible entity/relationship explorer reveals 50 items at a time. The exact filtering and layout rules are maintained with the Command Theater source.
- Responsive shell breakpoints are 960px and 640px. Shared design variables are in `src/app/globals.css`; component rules are CSS Modules.
- `prefers-reduced-motion`, a local app-level reduction option, visible focus, and forced-color focus rules are supported in CSS. This does not establish cross-browser accessibility without manual testing.
- Graph CPU timings are isolated Node microbenchmarks. Browser route weight, hydration, memory, GPU frame time, and visual layout have not been measured in this task; see `PERFORMANCE_REPORT.md`.

## Extension checklist

Before adding a data-backed route or control:

- Identify the API/product owner and link an approved, versioned contract.
- Define auth and tenant isolation outside browser code, freshness/caching, pagination, source metadata, empty/error/offline behavior, and demo separation.
- Map the verified contract to a typed frontend adapter; add runtime validation at untrusted boundaries.
- Define EN/AR/FA labels, RTL/LTR layout, keyboard behavior, focus and announcements before presenting the control.
- Add unit/component tests for success, loading, empty, provider-unavailable, malformed response, cancellation/retry, and locale behavior as applicable.
- Update `API_INTEGRATION_CONTRACTS.md`, `UX_GUIDELINES.md`, the module backlog, accessibility/performance docs, and `DEVELOPMENT_LOG.md` with actual evidence.
- Do not claim browser, device, screen-reader, GPU, or WCAG validation from jsdom tests.
