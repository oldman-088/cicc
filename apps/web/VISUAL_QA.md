# Browser visual QA — status and reproducible procedure

**Status (2026-11-05, updated): EXECUTED AND PASSED IN CI — GitHub Actions run 42032057257 (`web-ci`, success): typecheck, 104 unit tests, production build, Chromium install, and all 22 Playwright tests passed (desktop + mobile, 8 routes, EN/AR/FA directionality, keyboard focus, graph mount). Screenshots/traces are CI artifacts of that run (artifact download is not reachable from the dev sandbox, so no screenshots are embedded here). In the sandbox itself a browser still cannot be downloaded; local execution remains unavailable. First CI execution (run 42031636411) was 20/22 — the two failures were a test assumption that the Command Theater mounts a WebGL canvas by default; the default graph is an accessible SVG, and the test was corrected to accept SVG/canvas/fallback while still failing on a blank region.

## Exact environment limitation
- `npm install @playwright/test` succeeds (npm registry reachable), and the suite in
  `e2e/visual-qa.spec.ts` is discovered (`npx playwright test --list` → 20 tests, desktop + mobile projects).
- `npx playwright install chromium` **fails**: the Chromium/Chrome-for-Testing binary download host is not
  reachable from this sandbox (egress allowlist permits npm/PyPI/GitHub only). No system Chromium/Chrome
  binary is installed. Therefore no real browser has rendered this app yet in this environment.
- HTTP 200 smoke checks and JSDOM/axe structural tests are **not** visual QA and are never reported as such.

## How to execute (browser-capable environment)
```bash
cd apps/web
npm ci
npx playwright install chromium
npm run build
npm run test:e2e        # starts the production server, captures full-page screenshots per route/viewport
```
Artifacts: screenshots + traces land in `test-results/`, HTML report in `playwright-report/`.

## Coverage in the suite
- All 7 routes at desktop (1440×900) and mobile (390×844): render, main landmark visible, no horizontal overflow, screenshot.
- Locale switching EN→AR→FA→EN asserting `dir=ltr/rtl` on `<html>`.
- Keyboard Tab focus visibility (computed outline not `none`).
- Command Theater: WebGL canvas mounts or an accessible fallback is visible.
Still manual-only after automation: screen-reader sessions, true contrast measurement, WebGL context-loss, fluent-speaker review.

## Update — journey coverage (2026-11-05)
Suite grew to **30 tests** (`e2e/journeys.spec.ts`: investigation create/annotate/reload persistence, local reminder read/unread persistence, honest unavailable failure states, cross-workspace navigation). First journey run (42033874095) was 29/30 — mobile navigation is collapsed, so the journey now opens the toggle like a real user. Run **42034338021: full success (30/30)**, with typecheck, 104 unit tests, and build also green.

## Update — health/trace + import journeys (2026-11-05)
Suite grew to **34 tests** (coordination-health unavailable journey; malformed-import rejection journey). First run (42035492189) was 30/34: the health on-demand note only rendered on success (now always visible — a genuine UX fix) and the import alert needed a scoped locator. Run **42035974098: full success (34/34)**, typecheck + 108 unit tests + build green.

## Update — local search journey (2026-11-05)
Suite grew to **36 tests** (+local cross-data search journey). Run **42038523984: full success (36/36)** with typecheck, 114 unit tests, and build green.
