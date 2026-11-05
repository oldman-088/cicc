# CICC frontend master task queue

**Updated:** 2026-11-05 · **Branch:** `arena/09952395-cicc` · **PR:** #2 (open; do not merge)

Status legend: **Done** = implemented and checked to the stated level; **In progress** = current branch work; **Blocked** = requires an owner/contract/environment; **Queued** = not started.

## Completed frontend work

- [x] Shared responsive CICC shell, workspace overview, separate Command Theater route, breadcrumbs, skip link, semantic navigation, and responsive navigation behavior.
- [x] EN/AR/FA locale handling, document `lang`/`dir`, RTL/LTR layout support, reduced-motion preference, and browser-local locale persistence.
- [x] Page-only navigation search with an explicit scope notice and `Ctrl/⌘+K` shortcut; entity search is not claimed.
- [x] Honest unconfigured Threat Intelligence and Vulnerability Intelligence shells; no fabricated data or operational status.
- [x] Command Theater typed presentation adapter, runtime validation, isolated synthetic development provider, accessible 2D/3D fallback, graph limits, and no fixture fallback after provider failure.
- [x] Read-only System Health and Agent Coordination workspaces with explicit loading, unconfigured/error, malformed, empty, stale-after-failure, and retry states; EN/AR/FA copy and RTL-safe technical IDs.
- [x] Server BFF with fixed GET allowlist, server-only `WEB_BFF_API_TOKEN`, mandatory trusted single-tenant acknowledgement, optional `WEB_BFF_ENFORCE_SAME_ORIGIN=1`, no forwarding of browser credentials/tenant headers, redirects rejected, bounded query/timeout/streaming response size, and no write methods. `HEAD` is explicitly rejected.
- [x] Coordination DTO decoder/tests cover the two observed documented/implemented field spellings, reject conflicting duplicate aliases, and show which timestamp property was supplied. This is compatibility handling only; it does not resolve the upstream DTO mismatch.
- [x] Updated API contract inventory, architecture, UX/design/accessibility, backlog, and development records with current PR #4 evidence and verification limits.

## Current blockers and owner follow-up

- [ ] **PR #4 Agent DTO mismatch:** at current reviewed head `f0589f3935f8918e54b7fa54b983d646e87775b2` (compared with the previously reviewed `2f647f18577278c83cb4b1c1927e889c060058e8`), `docs/API_REFERENCE.md` documents `last_seen` / `completed_tasks` / `failed_tasks`, while `apps/api/app/coordination/agents.py` plus `registry.task_stats_by_agent()` returns `last_heartbeat` / `completed` / `failed`. M16–M19 added a read-only `/contract` descriptor and coordination lifecycle fixes, but did not change `docs/API_REFERENCE.md`, `agents.py`, `registry.py`, or the `GET /agents` DTO; mismatch persists. Clarification/alignment request posted at [PR #4 comment #6656004782](https://github.com/oldman-088/cicc/pull/4#issuecomment-6656004782). Do not edit backend files or other agents' branches.
- [ ] Agents 2/3 have not confirmed Coordination v1.0 adoption. Do not claim their approval or bind their workflows.
- [ ] No `API_INTERNAL_URL`, BFF credential/trust acknowledgement, or approved integration environment is configured for this preview. The local BFF correctly returns `provider_not_configured`; do not claim live PR #4 service verification.
- [ ] No user authentication or tenant isolation exists for Ops/Coordination. Keep this behind trusted single-tenant deployment/network controls; do not present the local trust flag as authentication.
- [ ] Visual screenshot/browser QA is not possible here: no browser/screenshot control tool is available. Do not claim manual visual, device, assistive-technology, contrast, fluent-speaker, or GPU checks.

## Verification completed

- [x] `npm run typecheck` passed.
- [x] `npm test -- --reporter=dot` passed: **85 tests across 17 files**, including Arabic/Persian RTL and LTR identifier-isolation checks on System Health/Coordination. Axe checks are JSDOM structural checks with color contrast disabled.
- [x] `npm run build --workspace=@cicc/web` passed; all seven pages generated and the integration API route remained dynamic.
- [x] `npm audit --audit-level=high` reported 0 vulnerabilities.
- [x] `git diff --check` passed.
- [x] Local port-3000 HTTP smoke: all seven app pages returned 200; unconfigured BFF GET returned 503 `provider_not_configured`; HEAD and POST returned 405. The preview process had no API URL/token/trust environment variables, so this did not contact PR #4's service.
- [ ] Browser visual, screenshot, device, screen-reader, contrast, fluent-speaker, and real GPU/WebGL validation remain unperformed.

## PR #2 handling

- [x] Reviewed the current PR #2 description, changed-file list, branch head, and this batch's source/documentation diff; typecheck, full suite, build, audit, and smoke checks passed before updating the PR.
- [x] Reviewed and finalized the 35-file frontend/documentation diff, committed as `ab549b8`, pushed only to `arena/09952395-cicc`, and updated PR #2's description. PR #2 remains open and unmerged; no push to `main`.

## Later work (contract/product dependent)

- [ ] Connect Threat Intelligence or Vulnerability Intelligence only after owner-approved HTTP/auth/tenant/provenance contracts.
- [ ] Add global entity search, alert triage, notifications, identity, or tenant settings only after product and API contracts.
- [ ] Add account/cross-device preferences only after identity and persistence contracts.
- [ ] Add browser E2E/visual regression when a reproducible browser runner is available; keep JSDOM/HTTP evidence clearly separate.
- [ ] Measure browser bundle/hydration, responsive layouts, real contrast, screen-reader output, GPU/context loss, and device performance in an approved environment.
