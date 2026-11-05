# CICC frontend master task queue

**Updated:** 2026-11-05 · **Branch:** `arena/09952395-cicc` · **PR:** #2 (open; do not merge)

Status legend: **Done** = implemented and checked to the stated level; **In progress** = current branch work; **Blocked** = requires an owner/contract/environment; **Queued** = not started.

## Completed foundations

- [x] Shared responsive application shell, overview route, and separate Command Theater route.
- [x] EN/AR/FA locale context, document language/direction synchronization, translated navigation, RTL-aware shell, and skip link.
- [x] Navigation search that filters known frontend pages and explicitly disclaims entity search.
- [x] Explicit, localized, navigable shells for Threat Intelligence, Vulnerability Intelligence, System Health, and Coordination. No fabricated data or service state.
- [x] Settings route for session locale and locally stored additional reduced-motion preference; unsupported identity/tenant controls are called out.
- [x] Existing Command Theater adapter boundary, runtime validation, isolated synthetic development provider, data-failure behavior, graph limits, and keyboard-aware visualization preserved.
- [x] Architecture/design/UX/API/accessibility/performance/development documentation and this task queue authored and reviewed; manual/browser validation remains separately blocked.

## Immediate acceptance / validation

- [x] Typecheck passed on the current implementation pass.
- [x] 60 automated tests across 13 files passed, including axe-core structural checks with color contrast disabled.
- [x] Fresh typecheck, 60-test suite, production build, package audit, and staged `git diff --check` passed; results are recorded in the backlog and development log.
- [x] All seven route responses returned HTTP 200 on the existing port-3000 server; PID 2368 stayed running. This is HTTP smoke only.
- [x] Reviewed the scoped Git diff (37 frontend/doc files; no unrelated work or untracked files removed), committed as `860ead9`, and pushed only to `origin arena/09952395-cicc`.
- [x] Updated PR #2 title/body through GitHub API. It targets `main`, remains open, and was not merged.

## P0 — data integrity and integration governance

- [ ] **Blocked: approve API/auth/tenant contracts.** Obtain owner-approved versioned contracts before implementing data transport, live search, notification, identity, or operational status. No backend contract is present in this checkout.
- [x] Current Command Theater fixtures are development-only, visibly synthetic, and isolated from provider failures; regression tests cover the rule.
- [ ] Add corresponding isolation tests whenever a new provider or source state is introduced.
- [ ] Preserve `unconfigured`, `unavailable/error`, `empty`, `cached`, `live`, and `unverified` as distinct states; only assert source states supported by actual metadata.

## P1 — manual alpha validation

- [ ] **Blocked: browser/device environment.** Test desktop/tablet/mobile (including 320px), zoom/reflow, EN/AR/FA wrapping, bidi identifiers, focus visibility, keyboard navigation, forced colors, reduced motion, and screenshot consistency.
- [ ] **Blocked: assistive technology.** Record keyboard-only and screen-reader review with actual browser/AT versions. Automated JSDOM/axe checks do not satisfy this task.
- [ ] **Blocked: browser/GPU.** Verify real WebGL initialization, context loss/recovery, focus restoration, 2D/3D parity, dense-graph frame time, and device memory.
- [ ] Request fluent-speaker review of EN/AR/FA wording and terminology.

## P1 — Command Theater

- [ ] Connect a host-owned adapter only after reviewed API, auth, and tenant contracts exist.
- [ ] Run browser-based analyst workflow checks for source/provenance visibility, 2D keyboard map, explorer parity, bounded view disclosure, pagination, error/retry, and optional 3D fallback.
- [ ] Measure browser bundle/route/hydration/memory/graphics performance separately from the existing Node CPU microbenchmarks.

## P2 — data-backed feature modules (contract-gated)

- [ ] **Threat Intelligence:** replace the no-provider shell with reviewed actor/campaign/indicator/evidence workflows after entity semantics and source contracts exist.
- [ ] **Vulnerability Intelligence:** define exposure/CVE/prioritization/remediation workflows from verified inputs (including any external scoring source semantics); do not assume fields or status.
- [ ] **System Health:** add source-backed service/worker/queue/alert views only after freshness, health, failure, and authorization semantics are defined by the operations owner.
- [ ] **Coordination:** implement agent/task/routing/approval workflows only from a reviewed registry and task contract.
- [ ] **Global entity search:** expand beyond page navigation only when an authorized search/index contract, ranking/pagination, stale behavior, and empty/error states are agreed.
- [ ] **Notifications/alerts:** do not add notification bells or simulated counts before delivery, acknowledgement, ordering, and ownership semantics exist.

## P2 — preferences and identity

- [ ] Persist locale or account preferences only when product and identity owners approve scope and conflict behavior.
- [ ] Add account, tenant, role, or theme controls only with a verified auth/preferences contract and real supported behaviors.

## P3 — engineering quality

- [ ] Add browser E2E/visual-regression automation when a reproducible browser runner is available in CI.
- [ ] Continue consolidating hardcoded component CSS values onto documented design tokens without reducing measured contrast/focus visibility.
- [ ] Add real browser performance and memory baselines on named devices after a production-like build/provider is available; do not invent budgets from Node timings.
- [ ] Re-review source code/asset licenses before any reuse. The current UI uses original markup/styles/icons and only borrows general interaction patterns.

## Completion policy

A task that needs a backend/API owner or real browser/GPU/AT environment remains **Blocked** until that dependency is available. Do not satisfy it with invented contracts, dummy operational data, synthetic service health, or claims based only on jsdom/HTTP checks. Keep the browser-preview server on port 3000 running while doing code work.
