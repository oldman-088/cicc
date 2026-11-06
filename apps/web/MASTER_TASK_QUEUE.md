# CICC frontend master task queue

**Updated:** 2026-11-06 · **Branch:** `arena/09952395-cicc` · **PR:** #2 (open; do not merge)

Status legend: **Done** = implemented and checked to the stated level; **In progress** = current branch work; **Blocked** = requires an owner/contract/environment; **Queued** = not started.

## Completed frontend work

- [x] Shared responsive CICC shell, workspace overview, separate Command Theater route, breadcrumbs, skip link, semantic navigation, and responsive navigation behavior.
- [x] EN/AR/FA locale handling, document `lang`/`dir`, RTL/LTR layout support, reduced-motion preference, and browser-local locale persistence.
- [x] Page-only navigation search with an explicit scope notice and `Ctrl/⌘+K` shortcut; entity search is not claimed.
- [x] Honest unconfigured Threat Intelligence and Vulnerability Intelligence shells; no fabricated data or operational status.
- [x] Command Theater typed presentation adapter, runtime validation, isolated synthetic development provider, accessible 2D/3D fallback, graph limits, and no fixture fallback after provider failure.
- [x] Read-only System Health and Agent Coordination workspaces with explicit loading, unconfigured/error, malformed, empty, stale-after-failure, and retry states; EN/AR/FA copy and RTL-safe technical IDs.
- [x] Server BFF with fixed GET allowlist, server-only `WEB_BFF_API_TOKEN`, mandatory trusted single-tenant acknowledgement, optional `WEB_BFF_ENFORCE_SAME_ORIGIN=1`, no forwarding of browser credentials/tenant headers, redirects rejected, bounded query/timeout/streaming response size, and no write methods. `HEAD` is explicitly rejected.
- [x] Coordination agent decoder consumes the current source-reported `health` field plus `last_heartbeat`/`completed`/`failed`; it retains the previously observed alias conflict checks for compatibility.
- [x] Added the current PR #4 source-backed read-only Coordination health panel and lazily requested per-task audit/correlation trace through fixed GET-only BFF mappings. Health preserves provider status/reasons and labels the check as on-demand, not continuous. Trace shows correlation IDs, lifecycle events, delivery attempts, and approvals without claiming broker delivery.
- [x] Added BFF path/query safety tests, runtime DTO tests, localized EN/AR/FA health/trace UI, permission-denied coverage, and Playwright E2E specs with test-only network interception.
- [x] Updated API contract inventory, architecture, UX/design/accessibility, backlog, and development records with current PR #4/PR #1/#3/#6/#8 evidence and verification limits.

## Current blockers and owner follow-up

- [ ] **PR #4 API-reference alignment:** current PR #4 head is M34 `e10e9f57afed4da715949ac3b3038116977029f2`; its canonical agent fields and read-only `/health` and `/tasks/{task_id}/trace` implementations remain the M33 source at `b112d4c522aed996e1466040774db04f1e1711f4`. `docs/API_REFERENCE.md` still omits the `health` property and health/trace response shapes. Alignment requests are posted to Agent 1 in [PR #4 comment #6678099565](https://github.com/oldman-088/cicc/pull/4#issuecomment-6678099565) and the M34 follow-up [#6678515605](https://github.com/oldman-088/cicc/pull/4#issuecomment-6678515605); frontend code does not edit PR #4 files or branch. M34's 32/32 sandbox/fixture-token coordination trial uses the reference workflow and does not establish production access or adoption by the domain agents.
- [ ] Agent 2 is recorded unavailable in PR #4's latest owner checkpoint; Replacement Agent 3 and Agent 2 have not confirmed Coordination v1.0 adoption. Do not claim their approval or bind their workflows. A non-tasking status/contract request is posted on [PR #3 comment #6678099552](https://github.com/oldman-088/cicc/pull/3#issuecomment-6678099552). Agent 6 is the active TI backup, but its domain API remains unmounted.
- [ ] PR #1's vulnerability API and PR #8's OpenAPI are package-level/proposed, not host-mounted. Mounting-evidence requests are posted on [PR #8 comment #6678099551](https://github.com/oldman-088/cicc/pull/8#issuecomment-6678099551) and the latest-head follow-up [#6678515587](https://github.com/oldman-088/cicc/pull/8#issuecomment-6678515587). PR #3 and PR #6 have no mounted threat HTTP contract; keep both UI routes unconfigured until route/auth/tenant/request-response evidence exists.
- [ ] No `API_INTERNAL_URL`, BFF credential/trust acknowledgement, or approved integration environment is configured for this preview. The local BFF must fail closed with `provider_not_configured`; do not claim live PR #4 verification.
- [ ] No user authentication or tenant isolation exists for Ops/Coordination. Keep this behind trusted single-tenant deployment/network controls; do not present the local trust flag as authentication.
- [ ] No Chromium binary is installed in this sandbox. Playwright can list the three E2E specs, but a real run stops at browser launch before assertions; no screenshot or manual browser QA has been performed. Do not claim visual, device, assistive-technology, contrast, fluent-speaker, or GPU validation.

## Verification completed

- [x] `npm run typecheck` passed.
- [x] `npm test -- --reporter=dot` passed: **91 tests across 17 files**. Axe checks are structural JSDOM checks with color contrast disabled; this is not visual or WCAG validation.
- [x] `npm run test:e2e --workspace=@cicc/web -- --list` discovers three Playwright specs.
- [ ] Full Playwright run is blocked before assertions because Chromium is not installed at `/home/user/.cache/ms-playwright/chromium_headless_shell-1254/chrome-headless-shell-linux64/chrome-headless-shell`; no E2E pass is claimed.
- [x] Next.js 16.4.5 production build passed in an isolated temporary in-repository copy; all seven page routes generated and the integration API route remained dynamic.
- [x] `npm audit --audit-level=high` reported 0 vulnerabilities.
- [x] `git diff --check` passed at verification time.
- [x] Local port-3000 HTTP smoke: all seven app pages returned 200; the persistent preview's Coordination health/trace BFF reads returned 503 `provider_not_configured`; unsafe task ID returned 400; HEAD and POST returned 405. No API URL/token/trust acknowledgement is configured for this preview.
- [x] Separate request/response integration smoke: an ephemeral copy of PR #4 M34's API with a temporary SQLite database and test-only tokens was queried through this branch's actual BFF handler. Health and a directly seeded task trace returned 200 and passed the production DTO parsers. All temporary runtime files were removed. This does not verify a deployed service, user auth/tenant isolation, or TI/Vulnerability integrations.
- [ ] Browser visual, screenshot, device, screen-reader, contrast, fluent-speaker, and real GPU/WebGL validation remain unperformed.

## PR #2 handling

- [x] Reviewed the current PR #2 description, changed-file list, branch head, and final diff; typecheck, 91-test suite, production build, audit, local HTTP smoke, and isolated API/BFF request-response smoke passed. Playwright E2E is explicitly blocked before assertions by the missing Chromium binary.
- [x] Commit `33b3f967abfc5f65d52b2ca81229de75d385357f` (`feat(web): add coordination health and task traces`) was pushed only to `arena/09952395-cicc`.
- [x] PR #2 description was refreshed via REST after the push; PR #2 remains open, targets `main`, and is unmerged. No push to `main`, PR #7, or any owner branch occurred.
- [x] Earlier frontend foundation/review commits `ab549b8` and `b5d6273` were also pushed only to the same branch; the earlier PR description refresh history is preserved in `DEVELOPMENT_LOG.md`.

## Later work (contract/product dependent)

- [ ] Connect Threat Intelligence or Vulnerability Intelligence only after owner-approved HTTP/auth/tenant/provenance contracts.
- [ ] Add global entity search, alert triage, notifications, identity, or tenant settings only after product and API contracts.
- [ ] Add account/cross-device preferences only after identity and persistence contracts.
- [ ] Run the existing Playwright E2E specs in a reproducible Chromium runner; consider visual regression only after stable browser-based coverage exists. Keep JSDOM/HTTP evidence clearly separate.
- [ ] Measure browser bundle/hydration, responsive layouts, real contrast, screen-reader output, GPU/context loss, and device performance in an approved environment.
