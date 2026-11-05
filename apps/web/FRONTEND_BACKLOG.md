# CICC frontend engineering backlog

Updated: 2026-11-05

## Current frontend scope

This repository contains one Next.js App Router frontend. The browser-accessible routes are:

| Route | Frontend state | Data state |
| --- | --- | --- |
| `/` | Workspace overview with linked module cards and integration disclosure | No live provider; only Command Theater can opt into visibly synthetic development fixtures |
| `/command-theater` | Investigation graph, accessible entity explorer, filters, 2D map, optional 3D view | Typed host-owned adapter boundary; no production CICC provider is connected |
| `/threat-intelligence` | Localized, navigable module shell with explicit planned scope | Not configured; no threat records or feed health |
| `/vulnerability-intelligence` | Localized, navigable module shell with explicit planned scope | Not configured; no CVEs, scores, or remediation states |
| `/system-health` | Localized, navigable module shell with explicit planned scope | Not configured; no service, worker, queue, or throughput claims |
| `/coordination` | Localized, navigable module shell with explicit planned scope | Not configured; no agents, assignments, or task events |
| `/settings` | Session language choice and app/browser reduced-motion preference | Locale is session-only; motion preference uses local browser storage; account/tenant settings are unavailable |

A present route does not imply a working data integration. The four domain shells above explain the missing provider/API contract and show planned work only; they do not present fixtures as operational records. No backend endpoints, authentication behavior, tenant scope, API fields, or service states have been invented.

The shared shell owns responsive navigation, page-only navigation search, breadcrumbs, EN/AR/FA locale, document/component direction, skip-to-content, and global landmarks. Navigation search filters workspace pages only; entity search, alerts, notifications, account/tenant management, and global saved views are not connected or implied. The app-level reduced-motion option only adds to the operating-system preference and stores a non-sensitive boolean in this browser.

Command Theater's presentation adapter and data-integrity rules are documented in `src/components/command-theater/COMMAND_THEATER_INTEGRATION.md`; graph follow-ups and existing CPU measurements are in `src/components/command-theater/COMMAND_THEATER_BACKLOG.md`.

## Prioritized backlog

### P0 — Verified data/auth contracts — blocked on API owners

No backend/API application, OpenAPI document, generated client, auth contract, or tenant-scoping contract exists in this checkout. Request reviewed contracts for each data domain before building record lists, search, filters, saved investigations, live updates, or operational dashboards. Do not invent endpoints or payloads. Continue to expose explicit not-configured/error states until contracts and owners are confirmed.

### P1 — Real-browser, responsive, and assistive-technology review — environment-dependent

Validate 320px through large desktop, zoom/reflow, EN/AR/FA wrapping and mixed-direction identifiers, keyboard-only operation, visible focus, screen-reader output, forced colors, motion preference, color contrast, and actual 2D/3D/WebGL behavior in browsers/devices. Keep manual/browser evidence distinct from jsdom.

### P1 — Command Theater integration and analyst workflows — contract/browser dependent

Continue dense-graph readability, 2D/3D parity, real WebGL loss/recovery, source/provenance presentation, and route performance review. Connect only a host-owned adapter mapped from an approved API contract. Preserve graph rendering caps and do not give display coordinates analytic meaning.

### P2 — Threat Intelligence and Vulnerability Intelligence — contracts required

Replace the explicit route shells with usable list/detail/filter/evidence workflows only after entity semantics, provenance, pagination, freshness, authorization, and failure behavior are reviewed. Show verification and confidence separately. Keep unavailable, cached, demo, and live records distinct.

### P2 — System Health and Coordination — contracts required

Build source-backed service, worker, queue, agent, task, alert, and audit views only after owners define status/freshness semantics, authorization, and failure modes. The current routes intentionally claim no operational state.

### P2 — Global entity search and alerts — contract/product dependent

Current sidebar search covers frontend destinations only and says so. Entity search, notifications, alert triage, and saved views need product semantics and verified data/search contracts before they can be surfaced as working features.

### P2 — Settings and identity — auth/persistence dependent

The current settings page supports interface language for this session and local reduced-motion preference. Add account, tenant, theme, or persisted locale controls only with explicit product and identity/preferences contracts.

### P3 — Translation review — fluent-speaker review outstanding

Review EN/AR/FA product terminology with fluent speakers. Verify text expansion, numerals, punctuation, mixed-direction IDs, bidi isolation, breadcrumbs, and control order in actual browsers; tests cover selected labels and direction mechanics only.

### P3 — Accessibility — automated foundation in place; manual review outstanding

Automated component tests and axe-core structural checks cover app shell, overview, settings, unconfigured modules, and Command Theater. Color contrast is excluded in jsdom; no screen-reader, browser, or conformance claim has been made. Perform manual keyboard/focus, zoom, contrast, NVDA/JAWS/VoiceOver/TalkBack as available, and forced-colors checks.

### P3 — Performance and reliability — limited measurements only

Current graph timing data is isolated Node CPU work, not browser rendering. Add production bundle analysis, route/hydration profiling, browser memory/long-task checks, and WebGL frame-time measurements when a reproducible browser/GPU environment is available. No fabricated performance budgets are claimed.

### P3 — Browser E2E/visual regression — runner not configured

Typecheck, component tests, axe-core checks, and production builds are available. A browser E2E/visual regression suite is not configured in this checkout. Add one when the project can run it reproducibly in CI.

## Latest verification

- `npm run typecheck` passed; production `npm run build` passed and statically generated all seven app routes (`/`, `/command-theater`, `/threat-intelligence`, `/vulnerability-intelligence`, `/system-health`, `/coordination`, `/settings`).
- `npm test -- --reporter=dot`: 60 tests across 13 files passed. axe-core structural checks run in JSDOM with the color-contrast rule disabled.
- `npm audit --omit=dev --audit-level=high`: 0 vulnerabilities.
- HTTP smoke requests to the existing port-3000 Next server returned 200 for all seven routes. PID 2368 remained alive; the server was not stopped. This is not visual/device/browser accessibility validation.
- `git diff --cached --check` passed for the staged change set.
- No browser visual inspection, screen-reader, manual keyboard/device, fluent-speaker, contrast, or GPU/WebGL verification was performed.
