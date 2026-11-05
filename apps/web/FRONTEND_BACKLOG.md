# CICC frontend engineering backlog

Updated: 2026-11-05

## Current frontend scope

This repository contains one Next.js App Router frontend. The browser-accessible routes are:

| Route | Frontend state | Data state |
| --- | --- | --- |
| `/` | Workspace overview with linked module cards and integration disclosure | No aggregate provider; Command Theater alone can opt into visibly synthetic development fixtures |
| `/command-theater` | Investigation graph, accessible entity explorer, filters, 2D map, optional 3D view | Typed host-owned adapter boundary; no production CICC provider is connected |
| `/threat-intelligence` | Localized module shell with explicit planned scope | Not configured; no threat records or feed-health data |
| `/vulnerability-intelligence` | Localized module shell with explicit planned scope | Not configured; no CVEs, scores, or remediation states |
| `/system-health` | Localized read-only operations dashboard | Server-side fixed-path GET BFF is implemented; no provider is configured or live-verified in this checkout |
| `/coordination` | Localized read-only agent/task/metric/event dashboard | Server-side fixed-path GET BFF is implemented; no provider is configured or live-verified in this checkout |
| `/settings` | EN/AR/FA language choice and reduced-motion preference | Saved only in this browser; no account/tenant sync |

A route does not imply a working data integration. Threat/Vulnerability and production Command Theater stay unconnected. System Health and Coordination render only valid provider responses; absent configuration yields an explicit error, not synthetic operational data. Their local test fixtures are synthetic and isolated in tests. The overview does not aggregate backend metrics or events.

## Trust and contract boundary

- PR #4 is open at reviewed head `43c90259b3868340d4e1b929a9fb2b74250b6c29`. Its M13 Ops/Coordination reads and M14 BFF behavior are documented in `API_INTEGRATION_CONTRACTS.md`; PR #4 is not merged or running in this checkout.
- The Coordination agent DTO mismatch is **resolved**: Agent 1 (PR #4 M21/M23) established the canonical wire DTO (`last_heartbeat`, `completed`, `failed`, `active_tasks`, `retries`, `by_state`, plus M23 `health`); the frontend decoder now accepts only canonical fields and rejects obsolete aliases. Adoption was implemented by Backup Agent 4 under owner-authorized takeover (2026-11-05).
- The frontend BFF uses server-only `WEB_BFF_API_TOKEN`; if the backend `CICC_OPS_READ_TOKEN` gate is enabled, those values must match. `API_INTERNAL_URL` and the frontend's explicit `CICC_OPS_TRUSTED_SINGLE_TENANT=true` acknowledgement are required. This does not authenticate users or provide tenant isolation; Ops/Coordination must remain behind trusted deployment/network controls.
- Agents 2/3 have not confirmed Coordination adoption. No authenticated request to a deployed PR #4 service has been verified.
- Sidebar search filters frontend page destinations only; entity search, notifications, identity, roles, tenant management, and saved views are not implemented.

## Prioritized backlog

### P0 — Canonical DTO and live integration evidence — owner/deployment dependent

1. ~~Align PR #4's documented and implemented Coordination agent field names~~ — done (canonical DTO adopted, see above). Re-verify if PR #4 changes the AgentDTO again.
2. Before any live/connected claim, confirm Agents 2/3 adoption separately, provision server-only credentials, verify deployment/network access and user-access controls, and run an approved authenticated integration test against the deployed API.
3. Define real user/session authorization and tenant isolation before exposing Ops/Coordination beyond a trusted single-tenant deployment. A shared read token and UI warning are not substitutes.

### P1 — Real-browser, responsive, and assistive-technology review — environment-dependent

Validate all routes at narrow/mobile through large desktop widths, zoom/reflow, EN/AR/FA wrapping and mixed-direction IDs, keyboard-only operation, visible focus, screen-reader output, forced colors, reduced motion, contrast, and actual 2D/3D/WebGL behavior. The current environment provides no browser/screenshot tool; document the missing visual evidence rather than infer it from JSDOM or HTTP smoke.

### P1 — Translation review — fluent-speaker dependent

Have fluent speakers review EN/AR/FA product terminology and verify text expansion, numerals, punctuation, mixed-direction identifiers, breadcrumbs, and control order in real browsers.

### P2 — Threat Intelligence and Vulnerability Intelligence — contract dependent

Replace explicit route shells with usable list/detail/evidence workflows only after entity semantics, provenance, pagination, freshness, authorization, and failure behavior are reviewed. Show verification and confidence separately; keep unavailable, cached, demo, and live records distinct.

### P2 — Global entity search and alerts — product/contract dependent

Keep current navigation search explicitly route-only. Entity search, notifications, alert triage, and saved views require product semantics and verified data/search contracts before being surfaced as working features.

### P2 — Settings and identity — auth/persistence dependent

The current settings page persists locale and reduced-motion locally in this browser. Add account, tenant, theme persistence, cross-device sync, or server preference controls only with explicit product and identity/preferences contracts.

### P3 — Performance and reliability — limited measurements only

Current graph timing data is isolated Node CPU work, not browser rendering. Measure production bundle size, route/hydration cost, browser memory/long tasks, and WebGL frame time when a reproducible browser/GPU environment is available. No fabricated performance budgets are claimed.

### P3 — Browser E2E/visual regression — runner not configured

Typecheck, component tests, axe-core structural checks, and production builds are available. A reproducible browser E2E/visual regression suite is not configured in this checkout. Add one when CI can run it reliably.

## Latest verification

- `npm run typecheck` — passed.
- `npm test -- --reporter=dot` — **85 tests across 17 files passed**, including Arabic/Persian RTL page direction and LTR technical-identifier isolation on the operations pages. Axe checks are structural in JSDOM and disable `color-contrast`; they are not visual or WCAG validation.
- `npm run build --workspace=@cicc/web` — passed on Next.js 16.4.5; all seven page routes were generated and the integration API route remained dynamic.
- `npm audit --audit-level=high` — 0 vulnerabilities.
- `git diff --check` — passed.
- Local HTTP smoke on the existing port-3000 Next server returned 200 for all seven pages. `GET /api/integrations/ops/overview` returned the expected `503 provider_not_configured`; `HEAD` and `POST` returned 405. The preview process had no API URL/token/trust-acknowledgement environment variables, so no upstream service request was made. These checks do not verify PR #4's deployed API.
- No browser visual inspection or screenshot, manual keyboard/device testing, screen-reader session, fluent-speaker review, real contrast measurement, or GPU/WebGL validation was performed.

---

Command Theater's presentation-adapter rules are in `src/components/command-theater/COMMAND_THEATER_INTEGRATION.md`; graph follow-ups and isolated CPU measurements are in `src/components/command-theater/COMMAND_THEATER_BACKLOG.md` and `PERFORMANCE_REPORT.md`.
