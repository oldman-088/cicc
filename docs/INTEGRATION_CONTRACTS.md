# Frontend integration contracts

## Scope and evidence

This document describes the web adapter in this repository, not a production deployment. The proposed Coordination contract was inspected read-only at open PR #4 head `5213c8be726f26def0dca21984dab0b7ee680779` (router, domain module, and contract descriptor; reviewed 2026-11-06). This head includes M45's nullable no-invoke metrics, process-local `last_success_at`, persisted audit-derived `mounts_total`, and a documented diagnostics candidate. The existence of proposed source routes does **not** prove that an API is deployed, reachable, host-mounted, or returning these DTOs. The browser adapter fails closed when `API_INTERNAL_URL` is not configured and validates every JSON response before presenting it.

`README.md` is the original **ULTIMATE MASTER PROMPT v1.0** and remains unchanged. This file documents the implementation boundary without rewriting that source prompt.

## Browser-to-BFF contract

The browser uses same-origin relative URLs under `/api/integrations/`; it never receives or sends a provider bearer token. The server-side catch-all adapter in `apps/web/src/app/api/integrations/[...path]/route.ts` allowlists paths and query parameters, strips browser-controlled authorization, injects optional server-only tokens, uses `no-store`, rejects redirects, bounds JSON bodies, and returns sanitized errors.

| Purpose | Browser endpoint | Provider endpoint |
| --- | --- | --- |
| Coordination health | `GET /api/integrations/coordination/health` | `GET /api/v1/coordination/health` |
| Agents | `GET /api/integrations/coordination/agents` | `GET /api/v1/coordination/agents` |
| Tasks | `GET /api/integrations/coordination/tasks` | `GET /api/v1/coordination/tasks` |
| Metrics | `GET /api/integrations/coordination/metrics` | `GET /api/v1/coordination/metrics` |
| Events | `GET /api/integrations/coordination/events` | `GET /api/v1/coordination/events` |
| One task trace | `GET /api/integrations/coordination/task-trace?task_id=…` | `GET /api/v1/coordination/tasks/{task_id}/trace` |
| Write capabilities | `GET /api/integrations/coordination/write-capabilities` | Local configuration only; no provider request |

Task-list filters accepted by the BFF are `state`, `agent`, `kind`, `dead_letter`, and `limit` (1–500). Duplicate and unknown query keys are rejected. The browser's search, state filter, and page controls operate only on the returned task array; they do not claim server-side search or pagination. The UI labels the loaded scope accordingly.

The Coordination header's localized “Refresh all provider data” action refreshes the six configured read resources (health, metrics, agents, tasks, events, and write capabilities). It remains disabled while any read is pending and uses only the allowlisted GET endpoints; it does not refresh the lazy task trace or expand browser writes.

`apps/web/src/lib/integration-api.ts` defines and validates the coordination DTOs. Provider-reported progress, results, attempts, health, and routing explanations remain nullable/optional where the source may omit them; the UI does not infer missing values. Invalid response shapes become `invalid_response` rather than fabricated records. The API health route is an on-demand check, not a promise of continuous monitoring.

## Gated coordination writes

Writes require all of the following server-side configuration:

- A valid `API_INTERNAL_URL`.
- `WEB_BFF_WRITE_TOKEN` (never a browser value).
- `CICC_OPS_TRUSTED_SINGLE_TENANT=true`.
- `WEB_BFF_ALLOW_COORD_WRITE=1` for task creation. No routing toggle or routing write endpoint is exposed by this frontend.
- A same-origin `Origin` on each browser POST; cross-origin and non-same-origin fetch metadata are rejected.

The capability endpoint reports only whether task creation is configured; it does not contact the provider and is not a health check. The create flag is off unless explicitly configured. The workspace warns that it has no user authentication or tenant isolation; the gate is not a substitute for trusted network access controls.

### Create a task

`POST /api/integrations/coordination/tasks` accepts JSON fields from the Coordination `TaskIn` contract, subject to an additional BFF allowlist and validation. The current form sends `kind`, `title`, `priority`, `payload`, and `requires_approval`. The BFF caps the request body at 256,000 bytes, rejects unknown fields and browser-supplied `task_id`/`idempotency_key`, and creates a `bff-<UUID>` `idempotency_key` server-side. The provider endpoint is the source-confirmed `POST /api/v1/coordination/tasks`; the BFF accepts its `201 application/json` response only when it contains `task_id`, `kind`, `state`, and `duplicate`, and exposes the generated correlation key in `X-CICC-Idempotency-Key`.

The idempotency key correlates a single submitted request with the provider record. A retry after an uncertain network outcome creates a new key; the UI therefore tells the operator to refresh the task list and trace before retrying. It does not claim automatic retry deduplication across separate submissions.

### Routing remains provider-owned and read-only in this frontend

The Coordination API source at PR #4 head `5213c8be726f26def0dca21984dab0b7ee680779` documents `POST /api/v1/coordination/tasks/{task_id}/route` with an empty request body and a response containing `task_id`, `agent`, `state`, and an `explanation`. Its handler first depends on `read_token_dependency`, then explicitly calls `require_write_token(Authorization)` and `write_rate_limit_dependency`; it accepts no routing payload or caller-selected agent. The handler invokes routing policy and mutates the task's assigned agent, routing explanation, and state (`QUEUED` when an agent is selected, otherwise `BLOCKED`). This is not a harmless read operation.

The reference web BFF in PR #4 (`apps/web/lib/bff.mjs`) explicitly allowlists only task creation; its source comments and tests deny other browser writes. PR #2 previously added a second browser-facing BFF route behind `WEB_BFF_ALLOW_COORD_ROUTING=1`, but no explicit BFF-policy approval for that extension was found. **That extension has been removed.** PR #2 does not expose a browser route, capability flag, or UI action for routing. Provider-returned assignment and routing explanations on existing task records remain visible as read-only data. The BFF returns `404` for `/api/integrations/coordination/tasks/{task_id}/route` regardless of the old routing environment variable, and tests pin that denial while keeping the create-only path covered.

This boundary matches the reviewed reference policy and avoids broadening writes from a frontend that has no user authentication or tenant isolation. Reconsider only after Agent 1 records explicit owner approval and the required principal, same-origin/CSRF, tenant-resolution, and server-side gate controls in the authoritative BFF policy.

### Agent 1 domain-gateway contract (reviewed separately from the browser BFF)

Latest reviewed open PR #4 head: `5213c8be726f26def0dca21984dab0b7ee680779` (M45). Its proposed read-gated metrics route reports per-kind invoke/success/failure, latency, timeout/retry, stale/skew, circuit and mount-history data with labels bounded to registered `kind`. The M45 source returns `success_rate: null` before invokes and nullable `latency.avg_s` / `latency.last_s` when no latency sample exists; the candidate decoder preserves these unknown measurements instead of turning them into zero. It also adds `mounts_total`, calculated from persisted `coordination.domains` audit events. `mount_count`, `previous_version`, `last_success_at`, and fine-grained latency/circuit/retry counters remain process-local; the source notes that invokes/successes persist via `coord_domain_stats`. These are source-contract observations, not verification against a deployed CICC host.

The same head describes the diagnostics candidate `{status, db_ok, version, uptime_s, mounted_domains[], domain_statuses{}, stale_after_s, note}`. This shape is now represented by an isolated TypeScript candidate type and strict decoder; neither the DTO nor route has been owner-approved or wired into the web adapter. `AMD003_DOMAIN_LIFECYCLE.md` remains `PENDING — owner-reserved`. `TENANT_AUTH_READINESS.md` remains a proposal: status/metrics are global ops views behind a shared read token, trusted principal-to-tenant binding remains owner-pending, and a request-supplied `tenant_id` is not identity. The status contract also retains an unknown-kind DTO mismatch (handler evidence is only `{invokes, successes, note}`) and lacks a complete typed per-route error-envelope schema.

The GET side-effect policy is unresolved: `/domains`, `/domains/{kind}/status`, `/diagnostics`, and `/health` call `_persist_domain_stats()` and commit, whereas `/domains/metrics` loads persisted stats and derives `mounts_total` from audit events. No runtime domain-status adapter is enabled. `apps/web/src/lib/contracts/agent1-domains.ts` now decodes the documented candidate lifecycle, metrics, diagnostics, provenance/freshness and alert shapes for tests only. It keeps `mounts_total` distinct from process-local `mount_count` and does not render circuit/mount fields as durable healthy status. Agent 4's follow-ups: [M43 6682030526](https://github.com/oldman-088/cicc/pull/4#issuecomment-6682030526), [M44 6682210838](https://github.com/oldman-088/cicc/pull/4#issuecomment-6682210838), and [M45 6682595545](https://github.com/oldman-088/cicc/pull/4#issuecomment-6682595545). No Agent 1 host integration was exercised.

## M45 beta-readiness UI and isolated contract candidates

`BetaReadinessPanel` is now mounted in Workspace Overview. It uses only the two already-configured, read-only browser resources: the operations overview and Coordination health. Each loads, refreshes, fails, and recovers independently; refresh busy state spans concurrent reads, and the existing request-generation, abort, and unmount guards remain in force. The panel labels status as provider-reported/on-demand, shows last successful browser check and source-reported freshness where available, preserves partial data with a stale/error indication, and warns that a source label is not proof of authenticity or whole-platform health. It does not expose TI, VI, domain lifecycle, upload, mount/deregister, routing, or task-state endpoints.

The `apps/web/src/lib/contracts/` modules add strict candidate DTO types/decoders and unresolved-gate metadata for Agent 1 lifecycle/metrics/diagnostics/circuit/mount history/provenance/freshness/alerts (including M45 nullable empty-measurement values); Agent 2 relationship pages/traversal/evidence/confidence/provenance/conflicts/collection-freshness; and Agent 3 vulnerability records, affected packages, severity/EPSS/confidence, freshness, conflicts, fixture-origin reports, exposure warnings, pagination/errors, and VEX/OpenVEX/SARIF export metadata. M15's package-local CycloneDX/SPDX ingest result is typed so skipped components, warnings, counts, and `complete: false` cannot be hidden. That is **not** an upload or validation HTTP contract: no CICC SBOM upload route is documented, and no browser upload form is enabled. Candidate decoders are used only in tests; they are not wired as live providers or fixtures.

The readiness registry carries exact reviewed source heads and explicit unresolved host bindings: Agent 1 PR #4 `5213c8be726f26def0dca21984dab0b7ee680779`, Agent 2 PR #3 `5e0e6df793c623c99e4566cac911d84609ca9ea4`, and Agent 3 PR #1 `25108f72e001ba42d25378079683487bbeba8e2b`. Agent 1's diagnostics and lifecycle additions remain unapproved; Agent 2's prepared adapter is not mounted in the actual host and actual-host acceptance tests remain gated; Agent 3's OpenAPI/handoff remain proposed and disagree on `record_status`. All three domains remain disconnected in the UI. EN/AR/FA copy and RTL/LTR layouts are retained, with keyboard-operable refresh controls, live busy/error announcements, and axe checks. Browser writes remain create-only under the existing server-side gates. The original Master Prompt (`README.md`, ULTIMATE MASTER PROMPT v1.0, source commit `ca8f82c0500637e22851d7128cddf99081ef3c08`) remains unchanged.

## Threat and vulnerability intelligence

Neither domain is wired to a confirmed CICC host HTTP endpoint, and neither page issues an intelligence request or displays provider records. No provider URL, fixture-backed dashboard, indicator/CVE count, or inferred source health is added.

- **Threat Intelligence — Agent 2 / PR #3** (current open head `5e0e6df793c623c99e4566cac911d84609ca9ea4`): M46 prepares a separately injectable `create_host_application` ASGI adapter, but it is not mounted in Agent 1's actual host. Eight actual-host acceptance tests remain opt-in/skipped pending an approved host and isolated harness; the two CISA GitHub-mirror tests against disposable PostgreSQL do not establish real host integration or broad live-provider coverage. No shared migration was applied. Principal/login-pool mapping, gateway-to-router wiring, task/trace correlation, shared migration/role approval, and audit guarantees remain open. The relationship package and internal observation assessment are not connected through HTTP/gateway in this CICC frontend. Package fixtures remain explicitly experimental; the frontend types these candidates only and does not fetch or render them as connected data. Agent 4 follow-ups: [M43 6682030554](https://github.com/oldman-088/cicc/pull/3#issuecomment-6682030554); [M44 6682210811](https://github.com/oldman-088/cicc/pull/3#issuecomment-6682210811); [M45 6682595508](https://github.com/oldman-088/cicc/pull/3#issuecomment-6682595508).
- **Vulnerability Intelligence — Agent 3 / PR #1** (current open head `25108f72e001ba42d25378079683487bbeba8e2b`; stacked PR #8 was merged into PR #1's branch, **not into `main`**): the internal package parser accepts CycloneDX JSON and SPDX JSON/tag-value, and reports package-local components, skipped entries, completeness, relationships, licenses and inventory data. This is not a CICC upload/validation route or mounted host API; no host mount, CICC SBOM upload route, or UI is defined. Agent 3's M47 report records 2,123 collected, 2,113 passed and 10 skipped; that is Agent 3's historical branch evidence, not an Agent 4 rerun, frontend integration, or live-provider verification. The current OpenAPI `record_status` enum `[published, disputed, rejected, withdrawn]` conflicts with the handoff's additional `undergoing_analysis` value; OpenAPI's EPSS `available` field is absent from generated fixtures. No provider record or SBOM inventory is rendered as live here. Host prefix, trusted authentication/tenant binding, storage/migration, DTO/provenance/freshness, pagination/limits, error semantics and owner decisions remain open. Agent 4 boundary reviews: [PR #8 6681216531](https://github.com/oldman-088/cicc/pull/8#issuecomment-6681216531) and [M45 PR #1 6682595498](https://github.com/oldman-088/cicc/pull/1#issuecomment-6682595498).

Until the owner-approved contracts are confirmed and mounted, the shared `ResourceState<T>` remains an integration boundary, but no domain endpoint is guessed and no package fixture is rendered as live data.

## Test and deployment status

- Latest local verification after adding the M45 metrics/diagnostics candidate decoder: `npm --prefix apps/web run typecheck` passed; `npm --prefix apps/web test -- --reporter=dot` passed **130/130 tests across 20 files**; `npm --prefix apps/web run build` passed; `git diff --check` passed; `npm --prefix apps/web run test:e2e -- --list` discovered **26 tests across 2 specs**. These are local checks, not a browser run.
- Prior full CI run [42205142667](https://github.com/oldman-088/cicc/actions/runs/42205142667) passed typecheck, unit/component tests, dependency audit, Chromium setup, all **26/26 Playwright tests**, and production build on code head `960d3f12d616a257a590b2c1b499ef9df391b79a`. It predates this final candidate-decoder refresh; CI on the final refreshed head is required before treating these last decoder changes as CI-verified.
- No browser was installed locally: Playwright Chromium's expected executable `/home/user/.cache/ms-playwright/chromium-1254/chrome-linux64/chrome` is absent, so **0 M45 browser tests have run locally**. The beta-readiness Playwright cases include mobile/tablet/desktop layout, keyboard refresh, and axe-core WCAG A/AA checks in English and Arabic RTL. All readiness/E2E provider payloads are deterministic mocks; no live-provider integration has occurred.
- Current host integration remains unverified: no approved CICC TI/VI mount, trusted principal/tenant binding, owner-approved status DTO/error contract, or live-provider UI evidence has been established. No deployment or production-readiness claim is made.
