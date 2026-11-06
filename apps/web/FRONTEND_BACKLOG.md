# CICC frontend engineering backlog

Updated: 2026-11-06

## Current frontend scope

This repository contains one Next.js App Router frontend. The browser-accessible routes are:

| Route | Frontend state | Data state |
| --- | --- | --- |
| `/` | Workspace overview with linked module cards and integration disclosure | No aggregate provider; Command Theater alone can opt into visibly synthetic development fixtures |
| `/command-theater` | Investigation graph, accessible entity explorer, filters, 2D map, optional 3D view | Typed host-owned adapter boundary; no production CICC provider is connected |
| `/threat-intelligence` | Localized module shell with explicit planned scope | Not configured; no threat records or feed-health data |
| `/vulnerability-intelligence` | Localized module shell with explicit planned scope | Not configured; no CVEs, scores, or remediation states |
| `/system-health` | Localized read-only operations dashboard | Server-side fixed-path GET BFF is implemented; no provider is configured or live-verified in this checkout |
| `/coordination` | Localized read-only agent/task/metric/event/health dashboard; per-task trace loads on demand | Fixed-path GET BFF and validated health/trace views target PR #4 M33 source; an isolated local API/BFF request-response smoke passed, but no persistent provider or deployed/live verification is configured in this checkout |
| `/settings` | EN/AR/FA language choice and reduced-motion preference | Saved only in this browser; no account/tenant sync |

A route does not imply a working data integration. Threat/Vulnerability and production Command Theater stay unconnected. System Health and Coordination render only valid provider responses; absent configuration yields an explicit error, not synthetic operational data. Their local test fixtures are synthetic and isolated in tests. The overview does not aggregate backend metrics or events.

## Trust and contract boundary

- PR #4 is open at current M34 head `e10e9f57afed4da715949ac3b3038116977029f2`; the Coordination health/trace router source remains as introduced at M33 head `b112d4c522aed996e1466040774db04f1e1711f4`. The current source uses canonical agent fields `health`, `last_heartbeat`, `completed`, and `failed`, and implements read-only `/health` and `/tasks/{id}/trace`. The frontend decodes those fields and keeps strict alias conflict checks for older observed spellings. The current API reference omits the health/trace schemas and health field; alignment requests are posted at [PR #4 comment #6678099565](https://github.com/oldman-088/cicc/pull/4#issuecomment-6678099565) and the M34 follow-up [#6678515605](https://github.com/oldman-088/cicc/pull/4#issuecomment-6678515605). M34 records a separate 32/32 sandbox/fixture-token coordination trial through the reference workflow; it is not production/live verification or a request through this branch's BFF. The PR is not merged, and no provider is configured in this checkout.
- The frontend BFF uses server-only `WEB_BFF_API_TOKEN`; if the backend `CICC_OPS_READ_TOKEN` gate is enabled, those values must match. `API_INTERNAL_URL` and the frontend's explicit `CICC_OPS_TRUSTED_SINGLE_TENANT=true` acknowledgement are required. This does not authenticate users or provide tenant isolation; Ops/Coordination must remain behind trusted deployment/network controls.
- PR #4's latest checkpoint records Agent 2 unavailable (Agent 6 is active TI backup). Replacement Agent 3's PR #8 remains stacked on PR #1. Neither has confirmed Coordination adoption. No authenticated request to a deployed PR #4 service has been verified.
- PR #1/PR #8 Vulnerability reads remain package-level/proposed and not host-mounted; PR #3/PR #6 Threat code has no host-mounted frontend HTTP contract. Those routes stay unconfigured; no candidate API path or fixture is rendered as production data.
- Sidebar search filters frontend page destinations only; entity search, notifications, identity, roles, tenant management, and saved views are not implemented.

## Prioritized backlog

### P0 — Contract documentation, mount evidence, and safe live verification — owner/deployment dependent

1. Agent 1: align the PR #4 public API reference/descriptor with the current source DTO (`health`) and the new Coordination `/health` and `/tasks/{id}/trace` read contracts. The frontend consumes only these source-reviewed GETs and keeps a compatibility decoder while documentation catches up.
2. Before any live/connected claim, confirm Agent 2/Replacement Agent 3 adoption separately, provision server-only credentials, verify deployment/network/user-access controls, and execute approved authenticated requests against the deployed API.
3. Define real user/session authorization and tenant isolation before exposing Ops/Coordination beyond a trusted single-tenant deployment. A shared read token and UI warning are not substitutes.
4. Threat/Vulnerability UI consumption is blocked until an owner-approved host route, auth/tenant resolution, and exact request/response schema are mounted; do not wire to package-only or proposed OpenAPI paths.

### P1 — Real-browser, responsive, and assistive-technology review — environment-dependent

Validate all routes at narrow/mobile through large desktop widths, zoom/reflow, EN/AR/FA wrapping and mixed-direction IDs, keyboard-only operation, visible focus, screen-reader output, forced colors, reduced motion, contrast, and actual 2D/3D/WebGL behavior. The current environment has no installed Chromium binary or manual screenshot/browser QA capability; document the missing visual evidence rather than infer it from JSDOM or HTTP smoke.

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

### P3 — Browser E2E/visual regression — suite added; local execution blocked by browser binary

A Playwright config, `test:e2e` script, and three mocked-network coordination E2E specs now exist. `playwright test --list` discovers all three. This sandbox has no Chromium executable; running the suite fails before test code executes. Install a pinned browser in CI or use an approved browser environment before calling E2E behavior tested. No visual regression or screenshot claim is made.

## Latest verification (2026-11-06)

- `npm run typecheck` — passed.
- `npm test -- --reporter=dot` — **91 tests across 17 files passed**. Axe checks remain structural JSDOM checks with color contrast disabled; they are not visual or WCAG validation.
- `npm run test:e2e --workspace=@cicc/web -- --list` — discovers all three Playwright specs. An actual run failed before test code/assertions because Chromium is not installed at `/home/user/.cache/ms-playwright/chromium_headless_shell-1254/chrome-headless-shell-linux64/chrome-headless-shell`; E2E behavior is not claimed as tested.
- Next.js 16.4.5 production build — passed in an isolated temporary in-repository copy to avoid writing into the active dev server's `.next`; all seven application routes were generated and the integration API route remained dynamic.
- `npm audit --audit-level=high` — 0 vulnerabilities; `git diff --check` passed at verification time.
- Port-3000 HTTP smoke — all seven application pages returned 200. The Coordination health and valid trace BFF requests returned the expected `503 provider_not_configured`; a traversal-like task ID returned 400, while `HEAD` and `POST` returned 405. The persistent preview has no API URL/token/trust acknowledgement and made no upstream request.
- Separate local request/response smoke — against an ephemeral copy of PR #4 M34's API, the BFF handler made real local HTTP reads for health and the seeded task trace; both returned 200 and passed the runtime DTO parsers. Temporary service/database/test were removed. This is code-level sandbox verification only, not a deployed/live PR #4 integration.
- No browser visual inspection/screenshot, manual keyboard/device testing, screen-reader session, fluent-speaker review, real contrast measurement, or GPU/WebGL validation was performed.

---

Command Theater's presentation-adapter rules are in `src/components/command-theater/COMMAND_THEATER_INTEGRATION.md`; graph follow-ups and isolated CPU measurements are in `src/components/command-theater/COMMAND_THEATER_BACKLOG.md` and `PERFORMANCE_REPORT.md`.
