# Browser visual QA — status and reproducible procedure

**Status (2026-11-05, Backup Agent 4 takeover): NOT YET EXECUTED. No screenshots exist and none are claimed.**

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
