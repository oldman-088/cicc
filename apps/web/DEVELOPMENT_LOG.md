# CICC frontend development log

Updated: 2026-11-05 · Working branch: `arena/09952395-cicc`

## 2026-11-05 — read-only Ops/Coordination adapters and current PR #4 review

### Changes

- Re-reviewed PR #4 at current head `43c90259b3868340d4e1b929a9fb2b74250b6c29`, including its M14 reference BFF, current adoption record, and M20 descriptor/conformance tests. Compared it with the previously reviewed `f0589f3935f8918e54b7fa54b983d646e87775b2`: M20 updates the machine-readable coordination descriptor and reliability/conformance tests, but not `docs/API_REFERENCE.md`, `agents.py`, `registry.py`, or the `GET /agents` response DTO. M20's DTO checks compare request Pydantic models; they do not reconcile the agent-list response. The documented `last_seen` / `completed_tasks` / `failed_tasks` versus implemented `last_heartbeat` / `completed` / `failed` mismatch remains. Matched the frontend server-only credential to `WEB_BFF_API_TOKEN` and its optional same-origin enforcement setting; this is not a verified deployment or live API connection.
- Added a fixed-path, GET-only Next BFF allowlist, mandatory local trusted-single-tenant acknowledgement, 5-second timeout, streaming 2 MB response cap, redirect rejection, query validation, no-store responses, sanitized errors, and optional `Sec-Fetch-Site: cross-site` rejection. Browser authorization/cookie/tenant headers are not forwarded; `HEAD` and writes are not proxied.
- Added runtime-validated API adapters and localized read-only System Health/Coordination workspaces with explicit loading, unconfigured, error, malformed, empty, retry, and stale-after-failure states. Fixtures remain synthetic and isolated to tests.
- Found and reported the PR #4 Coordination agent DTO discrepancy: the reference documents `last_seen`/`completed_tasks`/`failed_tasks`, while the current `agents.py`/registry source returns `last_heartbeat`/`completed`/`failed`. The strict decoder accepts these two observed spellings, rejects conflicting duplicate aliases, and exposes the timestamp field actually supplied; this does not resolve the upstream mismatch. Clarification request: [PR #4 comment #6656004782](https://github.com/oldman-088/cicc/pull/4#issuecomment-6656004782).
- Did not modify backend files or other agents' branches. Agents 2/3 have not confirmed adoption; no user authentication or tenant isolation is claimed.
- Reviewed the 35-file frontend/documentation diff (`ab549b8`) and follow-up review-status commit (`b5d6273`); both were pushed only to `arena/09952395-cicc`. Updated PR #2's description via REST and refreshed its PR #4 reference after M20 advanced the reviewed head to `43c90259b3868340d4e1b929a9fb2b74250b6c29`. PR #2 remains open and unmerged; no push to `main`.

### Verification

- `npm run typecheck` passed.
- `npm test -- --reporter=dot` passed: **85 tests across 17 files**, including Arabic/Persian RTL page direction and LTR technical-identifier isolation for System Health/Coordination. JSDOM/axe checks are structural; color contrast is disabled.
- `npm run build --workspace=@cicc/web` passed; all seven page routes were generated and the API route remained dynamic.
- `npm audit --audit-level=high` found 0 vulnerabilities; `git diff --check` passed.
- Local port-3000 HTTP smoke returned 200 for all seven pages. The unconfigured BFF returned `503 provider_not_configured`; `HEAD` and `POST` returned 405. The preview process had no upstream URL/token/trust acknowledgement, so no request was made to PR #4's API.
- No browser/screenshot, device, manual keyboard, screen-reader, fluent-speaker, contrast, or real GPU/WebGL QA could be performed. Automated checks and HTTP smoke are not visual QA.

## 2026-11-05 — local preferences, navigation shortcut, and contract refresh

### Changes

- Settings now restores and persists EN/AR/FA locale alongside the existing reduced-motion preference, both in this browser only. Hydration is gated so the default state is not written over a saved preference before it is read; no account/tenant sync was added.
- Added a visible, bidi-isolated `Ctrl/⌘+K` hint and shortcut for the route-only search. It opens the collapsed mobile navigation, focuses/selects the search field, and deliberately does not intercept the shortcut while an input, textarea, select, or contenteditable is active.
- Re-reviewed current external PR heads #1 (`b988e869`), #3 (`480fa3d8`), and #4 (`b1b2f1b`). Expanded the contract inventory with candidate endpoints/interfaces, auth, error, schema, and tenant-scope evidence. PR #4's M11-02 v1.0 proposal has a path mismatch between docs and router and an unimplemented tenant-isolation gap; asked the owner to clarify these and the frontend/auth boundary in [PR #4 follow-up](https://github.com/oldman-088/cicc/pull/4#issuecomment-6654937068).
- Kept Threat Intelligence, Vulnerability Intelligence, System Health, and Coordination visibly disconnected. No API client was added against the unmounted PR #1 package contract, missing PR #3 HTTP contract, or unconfirmed PR #4 read/auth contract. No other branch was modified.

### Verification

- `npm run typecheck` passed.
- `npm test -- --reporter=dot` passed: 62 tests across 13 files, including preference restore/persistence and Ctrl/Meta+K behavior. The axe-core checks are structural only; color contrast is disabled in JSDOM.
- Browser visual QA remains blocked: no Chromium/Chrome/Firefox executable, Playwright/Puppeteer package, or browser-control tool was available. No desktop/tablet/mobile or manual keyboard/contrast/screen-reader claims are made.
- Post-change verification also passed: isolated production build generated all seven routes; `npm audit --omit=dev --audit-level=high` found 0 vulnerabilities; `git diff --check` passed; and all seven HTTP route smoke requests returned 200 with PID 2368 still running. These are automated/build/HTTP checks, not visual QA.

## 2026-11-05 — dashboard transparency and cross-PR API coordination

### Changes

- Added explicit **Data sources and freshness** and **Recent events** panels to the workspace dashboard. They state when no verified source/event provider is configured; Command Theater's synthetic development graph is explicitly excluded from live freshness and recent-event claims. The activity panel links to System Health and Agent Coordination.
- Added matching English, Arabic, and Persian copy and responsive styling. Extended component tests to check the no-provider and synthetic-demo distinctions.
- Updated `API_INTEGRATION_CONTRACTS.md` with evidence pointers to PRs #1, #3, and #4 and each contract's current implementation/approval limits. Owner coordination questions are posted on those PRs; at the last REST check (2026-11-05 09:36 UTC), no replies had arrived.
- No transport client, backend endpoint, credential flow, or live status was added: the external contracts are on unmerged PR branches, and host/auth/tenant boundaries remain unresolved. No other agent branch was modified.

### Verification

- `npm run typecheck` passed.
- `npm test -- --reporter=dot` passed: 60 tests across 13 files. The workspace overview axe-core structural check passed with color-contrast disabled; this is not a visual or full WCAG audit.
- The production build passed with all seven application routes generated; it ran in an isolated temporary copy and was removed afterward to avoid disturbing the live dev server. `npm audit --omit=dev --audit-level=high` reported 0 vulnerabilities, `git diff --check` passed, and current HTTP smoke requests returned 200 for all seven routes.
- No browser/device QA was possible in this environment. HTTP smoke is not visual verification. Next dev server PID 2368 on port 3000 remains running.

## 2026-11-05 — application-wide frontend alpha foundation

### Scope implemented in the working tree

- Kept `/` as a truthful workspace overview, `/command-theater` as a distinct investigation module, and the app-wide shell as the shared surface.
- Extended navigation and browser-accessible route coverage to `/threat-intelligence`, `/vulnerability-intelligence`, `/system-health`, `/coordination`, and `/settings`. The four data-domain pages are explicitly **unconfigured frontend shells**: each states that no verified provider/contract is connected and lists planned scope without synthesizing records, counts, alerts, or service/agent status.
- Added sidebar search over workspace page labels only. Its copy explicitly says this is not entity/IOC/CVE/alert search and that entity search requires a verified data provider.
- Added a working Settings page for EN/AR/FA locale and a reduced-motion option that adds to (never overrides) the operating-system preference. Both preferences are saved only in this browser; account/tenant preferences remain unavailable without a verified identity/preferences contract.
- Added shared semantic tokens and styles for an original CICC analyst workspace, route-specific active states, RTL-aware navigation, and focus/reduced-motion/forced-colors foundations.
- Preserved Command Theater's injected frontend adapter boundary, production no-provider behavior, isolated development-only synthetic fixtures, graph caps, and no-fallback-on-request-error rule.

### Open-source pattern and license review

Research reviewed public repository LICENSE/README/source content through GitHub on 2026-11-04 to identify general interface and architecture patterns. It was not a live visual audit of deployed products and is not legal advice. No source code, product assets, diagrams, or complete product identity was copied into CICC.

| Repository reviewed | License observation | General pattern considered (principles only) |
| --- | --- | --- |
| [OpenCTI](https://github.com/OpenCTI-Platform/opencti) | Community Edition is identified under Apache-2.0; source files with different headers may be Enterprise Edition, so the repository license alone is not a per-file grant | Reusable dashboard composition, explicit no-data components, and separation of refresh/loading state |
| [OpenCTEM](https://github.com/openctemio/openctem) | GPL-3.0 | Feature-oriented Next.js architecture, typed contract thinking, and CTEM lifecycle information architecture |
| [MISP](https://github.com/MISP/MISP) | AGPL-3.0 | Relationship exploration, customizable dashboards, and analyst investigation workflow as concepts only |
| [OpenSearch Dashboards](https://github.com/opensearch-project/OpenSearch-Dashboards) | Apache-2.0 | A modular platform with bounded plugin/module responsibilities |
| [wazuh/wazuh-dashboard](https://github.com/wazuh/wazuh-dashboard) | Apache-licensed platform base; README points to a separate dashboard-plugins repository | Distinguish a platform repository from the product's actual UI implementation |
| [wazuh/wazuh-dashboard-plugins](https://github.com/wazuh/wazuh-dashboard-plugins) | GPL-2.0 | No code or assets used; checked to avoid assuming the platform repository's license applied to plugins |

OpenCTI's licensing varies at file level; Wazuh's plugin repository has a separate license. Do not copy code/assets from GPL/AGPL projects or assume the license of a platform applies to a separate plugin repository. Any future code reuse needs explicit per-file license and notice review. Current visuals and inline SVGs are authored in this project.

### Automated work and verification

- Added route, localization, no-provider, navigation-search-scope, settings preference, and unconfigured-module tests; automated tests use fixtures and JSDOM.
- At the earlier foundation checkpoint: TypeScript typecheck and production build passed (all seven frontend routes generated), 60 tests across 13 files passed, and `npm audit --omit=dev --audit-level=high` reported 0 vulnerabilities. Those are historical checkpoint results; the current batch's final build, audit, and smoke results are recorded in the 2026-11-05 Ops/Coordination entry above.
- At that checkpoint, HTTP smoke requests to the existing Next development server on port 3000 returned 200 for all seven routes; PID 2368 remained alive. This verifies route responses only, not rendering or browser interaction.
- axe-core structural checks disable color contrast because JSDOM cannot validate rendered contrast. No browser, device, GPU, manual keyboard, screen-reader, or fluent-speaker verification is claimed.
- Historic isolated Node graph microbenchmarks remain 3.10ms median for 10,000-node layout and 6.37ms median for a 10,000-node/50,001-edge view-selection input. They are not browser/GPU performance measurements.
- `git diff --cached --check` passed after staging the scoped frontend/doc change set. Commit `860ead9` was pushed to `arena/09952395-cicc`; PR #2 title/body were updated via GitHub API and the PR remains open, unmerged, and targeted at `main`.

### Decisions and outstanding work

- No backend/API route was found; no endpoint, payload, identity contract, or service state was invented.
- The route shells are explicitly unavailable states, not delivered data workflows. Replacing them with live features is blocked on reviewed contracts and product semantics.
- The page search is a useful local navigation filter only, not a substitute for global entity search.
- At that earlier checkpoint, build, package audit, route smoke requests, and `git diff --check` still needed to be rerun after the then-current batch; the later 2026-11-05 Ops/Coordination entry above records those completed checks. The Next dev server on port 3000 is intentionally kept running. HTTP smoke checks do not count as visual QA.
- Real browser/device/assistive-technology verification remains outstanding; the next task queue is in `MASTER_TASK_QUEUE.md`.
