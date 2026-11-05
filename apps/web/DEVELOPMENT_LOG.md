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


## 2026-11-05 — Backup Agent 4 takeover: canonical AgentDTO adoption + local live BFF verification

- Owner explicitly authorized Backup Agent 4 takeover of Agent 4's frontend role. Work is based on PR #2 head `744ccd3` merged into the takeover branch; Agent 4's branch was not modified.
- **P0 canonical DTO:** `parseCoordinationAgents` now accepts only the canonical PR #4 AgentDTO (M21 wire fields + M23 `health`), rejects obsolete aliases (`last_seen`/`completed_tasks`/`failed_tasks`), missing/null/malformed/numeric-string values, and unknown `health` values. Types use wire names (`last_heartbeat`, `completed`, `failed`, `retries`, `by_state`, `health`, `version`, `meta`, `registered_at`). Coordination UI shows backend `health` plus the provider `stale` tag. Tests: canonical acceptance + obsolete/missing/null/malformed/numeric-string rejection.
- **Verification:** `npm run typecheck` passed; `npm test` — 85 tests / 17 files passed; `npm run build` passed (7 routes + dynamic BFF route).
- **Live local integration (not production):** ran PR #4's API (`2c6af20`) locally with sqlite and server-side read/write tokens, registered a clearly-labeled fixture agent (`backup-agent4-localtest`), and verified through the Next BFF (configured via server-only env): `coordination/agents`, `coordination/metrics`, and `ops/overview` returned real upstream DTOs; unauthenticated upstream returns 401 at the API; unconfigured BFF returns `503 provider_not_configured`; POST returns 405; no token string appears in page HTML. This is local fixture evidence only — no production/deployed upstream, user auth, or tenant isolation is claimed.
- **Visual QA:** still **not performed** — no browser binary is available in this environment (no Chromium/Playwright). HTTP 200 smoke for all seven routes was re-verified but is not visual QA.


## 2026-11-05 — Milestone 4: retry/backoff UX + cross-agent coordination requests

- **Retry UX (P2):** `useIntegrationResource` now performs at most 2 automatic retries for `rate_limited`/`unavailable` only, honoring server `Retry-After` (clamped 1–60s) or 1s/2s exponential backoff (cap 30s); timers are cleaned up on unmount/refresh and no success is implied until a real response arrives. `ResourcePanel` announces retry attempts via `aria-live` and shows anti-reload-loop guidance in EN/AR/FA. Regression tests cover Retry-After recovery, no-retry on 401, and delay clamping (92 tests total passing).
- **Write path (P0): BLOCKED pending Agent 1 approval.** The BFF remains GET-only by design. A concrete approval request (fixed POST route, separate server-only write token, server-generated idempotency key + correlation ID, strict DTO allowlist) was posted to PR #4 (comment 6657783475). No write integration is implemented or claimed until Agent 1 replies ACCEPT/AMEND.
- **Threat Intel contract (P1):** reviewed Agent 6's actual `integration_contracts.py` on PR #6; posted frontend-owner ACCEPT-IN-PRINCIPLE with 7 required amendments (typed entity DTOs, tz-aware timestamps, remove/non-authoritative `tenant_id`, error-envelope alignment + correlation ID, nullable cursor totals, freshness enums/thresholds, list-level provenance). Status: proposed, not accepted, not mounted (comment 6657783177).
- **Browser QA:** still BLOCKED (Chromium download unreachable in this sandbox); 22 Playwright tests are discovered, 0 executed. No visual QA claimed.


## 2026-11-05 — Milestone 5 (expanded autonomy): real read-flow evidence + Threat adapter preparation

- **First VERIFIED frontend→BFF→API→DB read flow (local fixture environment):** PR #4 API at head `0572f73` run locally; fixture agent `backup-agent-4-e2e` and task `api-30cb0817917f` seeded server-side; the PR #7 BFF (server-only token) returned canonical `agents`/`tasks` DTOs to the browser path; DB rows confirmed in `coord_tasks`/`coord_task_events`. Evidence posted to PR #4 (comment 6657859934) per Agent 1's M25 invitation. Correlation ID: the API returns none on these responses (recorded gap). Frontend-originated **write** remains BLOCKED pending Agent 1's reply to comment 6657783475. Local evidence only — not production.
- **Threat Intelligence adapter prepared (not bound):** `src/lib/threat-intel-api.ts` implements the frontend owner's amended envelope (typed entities, tz-aware freshness, nullable cursor totals, aligned error envelope with correlation ID, `threatDataPresentation` guard that refuses to present unmounted/unverified data as live). Decoders only — no endpoint, no fetch, no UI binding. Fixture-labeled tests cover decoding and rejection paths.
- Agent 1 M25 also confirmed: PR #4's reference BFF is read-only for coordination (writes 403 by design) — consistent with this frontend's GET-only boundary.


## 2026-11-05 — Milestone 6: approved write path implemented + executed; Vuln adapter; CI-configured browser QA

- **Write path (Agent 1 ACCEPT, PR #4 M26):** implemented the single fixed BFF `POST /api/integrations/coordination/tasks` in the existing integrations route — gated by `WEB_BFF_ALLOW_COORD_WRITE=1`, separate server-only `WEB_BFF_WRITE_TOKEN`, trusted-single-tenant requirement, strict DTO allowlist (unknown fields/bad kind/empty title → 422 before upstream), server-generated `bff-<uuid>` idempotency key returned as `x-cicc-idempotency-key`, browser auth stripped, 256 KiB body cap, sanitized error mapping. Other POST paths → 403 `method_not_allowed_via_bff`.
- **Verified locally (fixture, not production):** browser-style POST through the PR #7 web app → 201 `api-be4338ee4efc`; DB row persisted with the generated idempotency key; duplicate submission with a supplied key → same task, `duplicate: true`; task + `/tasks/{id}/events` verified through the BFF (both parameterized reads added after Agent 1's M26 confirmation). Evidence posted to PR #4. Discrepancy noted to Agent 1: `GET /tasks/{id}` does not serialize `idempotency_key` (DB has it).
- **TaskSubmissionPanel** added to the Coordination workspace (EN/AR/FA): pending/accepted/rejected states, duplicate-submit prevention, correlation key display. It honestly surfaces server refusals (e.g. `write_not_enabled`) in unconfigured deployments.
- **Vulnerability adapter prepared (not bound):** `src/lib/vuln-intel-api.ts` decoders (canonical CVE pattern, tri-state KEV/EPSS nulls preserved, provenance) + fail-closed presentation guard. PR #1 contract remains unmounted.
- **Browser QA:** CI workflow `.github/workflows/web-ci.yml` added (typecheck/unit/build + Playwright Chromium install + `test:e2e` with artifact upload) — status **CI_CONFIGURED**, not EXECUTED (no CI run has occurred; sandbox still cannot download Chromium). 22 tests DISCOVERED, 0 EXECUTED, 0 PASSED claimed.


## 2026-11-05 — Milestone 7: task lifecycle events, intelligence workspace foundations

- Agent 1 M27 serialized `idempotency_key` on task reads (additive). Frontend `CoordinationTask` now decodes it and the Coordination UI displays it as the correlation key in task details.
- Added `parseCoordinationTaskEvents`/`parseCoordinationTaskDetail` decoders and a per-task lifecycle-events viewer in the Coordination workspace (loading/error/empty states, EN/AR/FA, on-demand — no polling loops).
- Threat and Vulnerability pages now render a dedicated `IntelligenceWorkspace` foundation (localized headers, disabled search/filter structure, detail/provenance placeholder, planned scope) while remaining honestly not-connected; adapters stay unbound until contracts are accepted and mounted. The previous generic unconfigured page remains for other modules.


## 2026-11-05 — Continuous execution batch: coordination sorting/pagination/deep-links, investigation entities/timeline, local reminders, intelligence list

- Coordination tasks: client-side sorting (newest/priority/state), 10-per-page pagination over the returned set (scope note preserved), `?task=<id>` deep-link support (opening Coordination with that query pre-fills task search), copy-task-link button, correlation key shown per task.
- Investigations: associated entities (add/search), linked coordination task ID with a cross-workspace link into Coordination, chronological timeline (creation + timestamped notes), legacy plain-string notes migrated on load. Still browser-local only, labeled as such.
- Notification center: user-created local reminders with category (investigation/operations/intelligence) and read/unread state, persisted locally. No delivered/server notifications are claimed; the service-unavailable notice remains.
- Intelligence presentation: reusable `IntelligenceList` (query/kind filtering, detail with confidence-vs-verification and provenance) with labeled-fixture tests. It is a presentation component only; workspaces still present the honest not-connected state until contracts are accepted and mounted.
- CI: web-ci has been executing on PR #7 pushes (GitHub Actions is the browser-capable runner). The last inspected run failed at the unit-test step; Actions log download is blocked from this sandbox (result-storage host is outside the egress allowlist), so failure diagnosis uses step-level results after each push. Playwright execution status remains EXECUTED only when a run proves it.


## 2026-11-05 — Continuous batch: CI diagnosis, first browser execution, coordination/investigation depth

- **CI root cause found and fixed:** `web-ci` unit-test step failed on Node 20 (`ERR_REQUIRE_ESM` from jsdom's `@exodus/bytes` under `html-encoding-sniffer`); reproduced locally with Node 20.18.0 via the npm `node` package. Workflow now uses Node 22 — CI unit tests (104), typecheck, and build pass.
- **Browser QA EXECUTED:** GitHub Actions is the authorized browser-capable runner. Run 42031636411: **20/22 Playwright tests passed** in real Chromium (all 8 routes desktop+mobile screenshots, no-overflow, RTL/LTR locale switching, keyboard focus). The 2 failures corrected a wrong test assumption (default Command Theater graph is accessible SVG, not WebGL canvas). Run **42032057257: full success, 22/22**.
- Coordination: task sorting/pagination/deep-links/copy-link; Investigations: entities, linked coordination task, timeline, note migration; Notifications: local reminders with categories/read-unread; IntelligenceList presentation component with fixture tests. See the milestone commit list on PR #7.


## 2026-11-05 — M28 health/trace consumption, import feedback, journey expansion

- **Coordination health + task trace (Agent 1 PR #4 M28, @ `185150f`):** BFF GET routes `coordination/health` and `coordination/tasks/{id}/trace` (same parameterized gates; unknown suffix 404, bad id 400). Strict decoders with closed health-status enum (fail-closed). UI: Coordination health panel (overall/components/reasons/checked-at, explicit on-demand-not-continuous-monitoring note) + on-demand per-task trace viewer (correlation idempotency/event IDs, events, deliveries, approvals; honest empty states), EN/AR/FA. **LOCAL FIXTURE VERIFIED**: seeded agent/task `health-trace-1` on PR #4 @185150f; BFF health → overall `degraded`, broker `not_configured`, deliveries `degraded`; trace → correlation `ht-key-1`, 4 events, 1 delivery, approvals `[]`; negatives 400/404/404. Evidence posted on PR #4 (comment 6659120296), including a non-blocking note that trace timestamps are naive ISO while health `at` is tz-aware. Not production.
- **Investigations import feedback:** malformed/non-list/empty imports now show a localized visible error (`role=alert`) and leave local state unchanged; successful imports report the added count (`role=status`). Previously malformed files were silently rejected.
- **Playwright:** suite now 34 tests — added coordination-health unavailable journey and malformed-import journey (rejection visible, state persists across reload).
- Coordination requests posted: PR #6 comment 6659120763 (explicit Agent 2 domain-owner confirmation of Threat v1.1.0-proposed; frontend acceptance ≠ domain acceptance); PR #1 comment 6659121176 (Vulnerability mounting-evidence request; adapter prepared, tri-state KEV/EPSS preserved).


## 2026-11-05 — Timestamp hardening, last_operations, local search, notification filters

- **Trace timestamp root cause (investigated, not guessed):** Agent 1 `registry._iso()` is a bare `isoformat()`; health `now` is tz-aware while sqlite read-back of `DateTime(timezone=True)` event/delivery rows drops tzinfo, so trace timestamps serialize naive (storage-backend-dependent). Frontend: `parseProviderTimestamp` (tz-aware verbatim, naive ISO → documented UTC assumption, garbage → null), all coordination timestamps formatted in UTC. Backend normalization proposed to Agent 1 through the M29 amendment process (PR #4 comment 6659523023, field format matching `AmendmentIn`; AMD id left for their registry).
- **M29 `last_operations` consumed:** health decoder accepts the additive M29 block (still parses M28 payloads), health panel shows last webhook/sync-success/sync-attempt/task-event with the provider's own "NOT continuous monitoring" note verbatim.
- **Local cross-data search:** home page gains `LocalDataSearch` over browser-local investigations + reminders with an explicit boundary note (server-side global search unavailable; nothing leaves the device). Malformed local data is ignored, never fabricated.
- **NotificationCenter:** unread count (`role=status`), category filter, mark-all-read; still local-only with the service-unavailable notice intact.
- Tests: 114 unit tests (25 files) incl. timestamp/vuln-guard-matrix/notification/search suites; Playwright 36 listed (+local-search journey).


## 2026-11-05 — Shared health panel, decoder hardening, readiness checklists, investigation sorting

- **CoordinationHealthPanel extracted** (`components/coordination/CoordinationHealthPanel.tsx`) and reused in both Coordination and System Health workspaces; M28 backward compatibility preserved (M29 `last_operations` optional). System Health now shows on-demand coordination health next to ops overview/alerts/workers.
- **Decoder hardening tests:** partial health components default reasons to `[]` (never invented), missing structural fields fail closed, trace DTO keeps naive timestamps verbatim (UTC interpretation only at display via `parseProviderTimestamp`), malformed dates → null → honest fallback.
- **Threat/Vulnerability workspaces:** integration-readiness checklist with precise states (contract / host mounting / real verification / UI binding) in EN/AR/FA — still not connected, adapters unbound.
- **Investigations:** sort control (newest/oldest/status). Playwright +Arabic RTL investigation journey (38 listed).
