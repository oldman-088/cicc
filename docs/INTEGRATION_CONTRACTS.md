# Frontend integration contracts

## Scope and evidence

This document describes the web adapter in this repository, not a production deployment. The Coordination provider contract was inspected in the API implementation proposed in PR #4 (`apps/api/app/coordination/router.py`, `apps/api/app/coordination/contract.py`, and the API schemas) at PR #4 source revision `6c2c2a1fa2904b0ee13263421674ed22fe8e9d26` (M43, reviewed 2026-11-06), with the M44 read-only metrics addition separately reviewed at `2ef50e77a429fed35b8cc3991301608e9537d313`. The existence of those source routes does **not** prove that an API is deployed, reachable, or returning these DTOs. The adapter fails closed when `API_INTERNAL_URL` is not configured and validates every JSON response before presenting it.

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

The Coordination API source at PR #4 head `6c2c2a1fa2904b0ee13263421674ed22fe8e9d26` documents `POST /api/v1/coordination/tasks/{task_id}/route` with an empty request body and a response containing `task_id`, `agent`, `state`, and an `explanation`. Its handler first depends on `read_token_dependency`, then explicitly calls `require_write_token(Authorization)` and `write_rate_limit_dependency`; it accepts no routing payload or caller-selected agent. The handler invokes routing policy and mutates the task's assigned agent, routing explanation, and state (`QUEUED` when an agent is selected, otherwise `BLOCKED`). This is not a harmless read operation.

The reference web BFF in PR #4 (`apps/web/lib/bff.mjs`) explicitly allowlists only task creation; its source comments and tests deny other browser writes. PR #2 previously added a second browser-facing BFF route behind `WEB_BFF_ALLOW_COORD_ROUTING=1`, but no explicit BFF-policy approval for that extension was found. **That extension has been removed.** PR #2 does not expose a browser route, capability flag, or UI action for routing. Provider-returned assignment and routing explanations on existing task records remain visible as read-only data. The BFF returns `404` for `/api/integrations/coordination/tasks/{task_id}/route` regardless of the old routing environment variable, and tests pin that denial while keeping the create-only path covered.

This boundary matches the reviewed reference policy and avoids broadening writes from a frontend that has no user authentication or tenant isolation. Reconsider only after Agent 1 records explicit owner approval and the required principal, same-origin/CSRF, tenant-resolution, and server-side gate controls in the authoritative BFF policy.

### Agent 1 domain-gateway contract (reviewed separately from the browser BFF)

Latest reviewed PR #4 head: `2ef50e77a429fed35b8cc3991301608e9537d313` (M44). M44 adds a read-gated `GET /api/v1/coordination/domains/metrics` with per-kind invoke/success/failure rates, latency, timeout/retry, stale/skew and circuit-transition counters; labels are bounded to registered domain `kind`. Agent 1 reports M44 tests 6/6 and a 17/17 `SANDBOX/FIXTURE` observability trial. These are branch-local evidence, not verification against an actually deployed CICC host.

`docs/DOMAIN_STATUS_CONTRACT.md` now describes M44 metrics but still has an M41 title. `_persist_domain_stats()` stores version/source/mount timestamp, validation status, invokes/successes/consecutive failures, last-stale, last-invoke, last status and sanitized last error. Circuit state (`open`/`opened_at`), latency/timeouts/retries/stale/skew/circuit-transition counters are process-local; the current contract says they reset on restart. `mount_count` and `previous_version` are held in `_STATS` as volatile mount history and are not written by `_persist_domain_stats()` or represented in the current `coord_domain_stats` schema. The public contract still needs an explicit field-by-field restart/persistence guarantee for these fields and their reconstruction semantics.

`TENANT_AUTH_READINESS.md` remains a proposal: status and metrics are global ops views behind a shared read token, and trusted principal-to-tenant binding remains owner-pending; a request-supplied `tenant_id` is not identity. `AMD003_DOMAIN_LIFECYCLE.md` remains `PENDING — owner-reserved`; it does not list the separately added `/diagnostics` or new `/domains/metrics` endpoint/M43/M44 shape. The status contract still has the unknown-kind DTO mismatch (handler returns only `{invokes, successes, note}` evidence), and lists status codes without a complete typed per-route error-envelope schema. `GET /domains`, `/domains/{kind}/status`, `/diagnostics`, and `/health` still call `_persist_domain_stats()` and commit; `/domains/metrics` loads persisted stats without that write path. Owner acceptance/removal of GET-side writes remains open.

No runtime domain-status adapter is enabled. M45 adds isolated, type-only candidate decoders in `apps/web/src/lib/contracts/agent1-domains.ts` for documented lifecycle evidence, metrics, provenance/freshness and alert shapes. They are deliberately not wired to an endpoint; diagnostics remain untyped because Agent 1 has not published a diagnostics DTO. Circuit/mount fields will not be presented as durable history or healthy status inferred. The M42/M43/M44 trials remain sandbox/fixture evidence, not actual host integration. Agent 4's explicit persistence/DTO/principal/AMD-003 questions: [M43 follow-up 6682030526](https://github.com/oldman-088/cicc/pull/4#issuecomment-6682030526); [M44 follow-up 6682210838](https://github.com/oldman-088/cicc/pull/4#issuecomment-6682210838).

## M45 beta-readiness UI and isolated contract candidates

`BetaReadinessPanel` is now mounted in Workspace Overview. It uses only the two already-configured, read-only browser resources: the operations overview and Coordination health. Each loads, refreshes, fails, and recovers independently; refresh busy state spans concurrent reads, and the existing request-generation, abort, and unmount guards remain in force. The panel labels status as provider-reported/on-demand, shows last successful browser check and source-reported freshness where available, preserves partial data with a stale/error indication, and warns that a source label is not proof of authenticity or whole-platform health. It does not expose TI, VI, domain lifecycle, upload, mount/deregister, routing, or task-state endpoints.

The `apps/web/src/lib/contracts/` modules add strict candidate DTO types/decoders and unresolved-gate metadata for Agent 1 lifecycle/metrics/circuit/mount history/provenance/freshness/alerts; Agent 2 relationship pages/traversal/evidence/confidence/provenance/conflicts/collection-freshness; and Agent 3 vulnerability records, affected packages, severity/EPSS/confidence, freshness, conflicts, fixture-origin reports, exposure warnings, pagination/errors, and VEX/OpenVEX/SARIF export metadata. M15's package-local CycloneDX/SPDX ingest result is typed so skipped components, warnings, counts, and `complete: false` cannot be hidden. That is **not** an upload or validation HTTP contract: no CICC SBOM upload route is documented, and no browser upload form is enabled. Candidate decoders are used only in tests; they are not wired as live providers or fixtures.

The readiness registry carries the exact reviewed source heads and explicit unresolved host bindings. Agent 1 remains owner-pending; Agent 2 routes are standalone package proposals without host auth/tenant binding; Agent 3 OpenAPI/handoff remain proposed and disagree on fields. All three domains remain disconnected in the UI. EN/AR/FA copy and RTL/LTR layouts are retained, with keyboard-operable refresh controls, live busy/error announcements, and axe checks. Browser writes remain create-only under the existing server-side gates. The original Master Prompt (`README.md`, ULTIMATE MASTER PROMPT v1.0, source commit `ca8f82c0500637e22851d7128cddf99081ef3c08`) remains unchanged.

## Threat and vulnerability intelligence

Neither domain is wired to a confirmed CICC host HTTP endpoint, and neither page issues an intelligence request or displays provider records. No provider URL, fixture-backed dashboard, indicator/CVE count, or inferred source health is added.

- **Threat Intelligence — Agent 2 / PR #3** (reviewed package head `2752b48f0b6244b4f17dffa1986165d1832e89ef`, open against `main`): the relationship API and optional restricted-role PostgreSQL adapter now document create, single-record read, list/filter/page, and bounded traversal with DB-derived actor/tenant/event/time/correlation and transactional audit. The adapter, roles, SQL and rollback remain isolated proposals, not approved/mounted in Agent 1's host. Actual principal-to-login-pool mapping, gateway-to-router wiring, task/trace correlation, shared migration/role approval, audit guarantees and six actual-host acceptance cases remain open; those host cases are opt-in/skipped. Evidence provenance records caller/source labels and collection times; these are not a CICC source-freshness schedule or authenticity proof. The opt-in collector's CISA GitHub KEV read is not scheduled/persisted CICC feed or frontend data, and default relationship fixtures remain explicitly experimental. The frontend therefore types these package candidates but does not fetch them or show the fixtures as connected. Agent 4 follow-ups: [M43 6682030554](https://github.com/oldman-088/cicc/pull/3#issuecomment-6682030554); [M44 6682210811](https://github.com/oldman-088/cicc/pull/3#issuecomment-6682210811); [M45 6682595508](https://github.com/oldman-088/cicc/pull/3#issuecomment-6682595508).
- **Vulnerability Intelligence — Agent 3 / PR #1 with stacked PR #8**: PR #8 was merged into PR #1's branch, **not into `main`**. The reviewed PR #1 package head is `1b945c04e609de00b7e13d0523d87ec931eaafc`. The M15 code includes internal CycloneDX JSON, SPDX JSON, and SPDX tag-value parsing, duplicate/skipped-component/warning reporting, explicit inventory completeness, exposure analysis, and VEX/OpenVEX/SARIF serializers. This is package-level functionality, not a CICC upload/validation route or mounted host API: Agent 3's handoff says mounted host endpoints, migrations, and live connectivity remain none. Its OpenAPI/fixtures are proposed (`origin: fixture`, `live_verified: false`); OpenAPI and handoff still disagree on `record_status`, and OpenAPI's EPSS `available` field is absent from generated fixtures. No provider record or SBOM inventory is rendered as live in this frontend. Required host prefix, trusted authentication/tenant binding, storage/migration, DTO/provenance/freshness, pagination/limits, error semantics and owner decisions remain open. Agent 4 boundary reviews: [PR #8 6681216531](https://github.com/oldman-088/cicc/pull/8#issuecomment-6681216531) and [M45 PR #1 6682595498](https://github.com/oldman-088/cicc/pull/1#issuecomment-6682595498).

Until the owner-approved contracts are confirmed and mounted, the shared `ResourceState<T>` remains an integration boundary, but no domain endpoint is guessed and no package fixture is rendered as live data.

## Test and deployment status

- Prior Agent 4 baseline `698294f65877e6cf177ed4022092018082a96d67`: **114 Vitest tests / 18 files passed**, typecheck/build/diff-check passed, and root `npm audit --audit-level=high` reported **0 vulnerabilities**. Historical Chromium CI [42198384237](https://github.com/oldman-088/cicc/actions/runs/42198384237) executed **22/22 Playwright tests** on that older code head; docs-only CI [42198710084](https://github.com/oldman-088/cicc/actions/runs/42198710084) passed.
- M45 working-tree verification after the UI and candidate decoders: `npm --prefix apps/web run typecheck` passed; `npm --prefix apps/web test -- --reporter=dot` passed **130/130 tests across 20 files**; `npm --prefix apps/web run build` passed; `git diff --check` passed; `npm --prefix apps/web run test:e2e -- --list` discovered **26 tests across 2 specs**. Re-run these commands against the final commit before release.
- No browser was installed locally: Playwright Chromium's expected executable `/home/user/.cache/ms-playwright/chromium-1254/chrome-linux64/chrome` is absent, so **0 M45 browser tests have run locally**. The new beta-readiness Playwright cases (mobile/tablet/desktop overflow, keyboard refresh, and full axe-core WCAG A/AA in English and Arabic RTL) are authored and should be verified by CI; do not report them as passed until that run completes. Vitest axe checks are structural and explicitly disable color-contrast. All frontend readiness/E2E provider payloads are deterministic mocks; no live-provider integration has occurred.
- Current host integration remains unverified: no approved CICC TI/VI mount, trusted principal/tenant binding, owner-approved status DTO/error contract, or live-provider UI evidence has been established. No deployment or production-readiness claim is made.
