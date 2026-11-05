# CICC frontend API integration contracts

**Status:** contract inventory, not a backend spec · **Updated:** 2026-11-05

## Repository finding

The checked-out branch contains a Next.js frontend only. It has no backend routes, generated API client, auth implementation, tenant-isolation contract, notification/search service, or system-health source. This inventory does not define a backend contract on behalf of another service; it records pointers to contract artifacts on open PR branches below, with their review/implementation status. Those branches are not part of this checkout, and the frontend domains other than Command Theater remain explicitly not configured.

Do not implement guessed REST paths, direct browser connections to private services, hardcoded demo credentials, or inferred health. A team-owned, versioned contract and integration owner are prerequisites; an unmerged branch is not by itself proof of a deployable or authorized frontend integration.

## Existing frontend presentation boundary: Command Theater

`src/components/command-theater/types.ts` defines a host-injected **frontend presentation adapter**, not a claim about the backend schema:

```ts
interface CommandTheaterDataSource {
  readonly kind: "demo" | "backend";
  loadPage(request: GraphPageRequest, signal: AbortSignal): Promise<GraphPage>;
}
```

The actual aliases include `GraphDataSourceKind`, `GraphPageRequest`, `GraphPage`, and `GraphFilters`. The UI requests an opaque cursor (`null` initially), a page limit of 250, and normalized search/entity-type/relationship-type filters, plus an `AbortSignal`. The adapter returns presentation nodes and relationships, `nextCursor`, and optional authoritative totals. This shape must be mapped from a real service by its host; it is not sent to a presumed endpoint.

The presentation records currently support:

- Entity types `threat-actor`, `campaign`, `domain`, `incident`, `asset`.
- Relationship types `associated-with`, `uses`, `observed-in`, `affects`.
- Distinct confidence basis (`illustrative`, `analyst-assessed`, `model-assessed`, or `unavailable`) and verification status (`verified`, `unverified`, `inferred`, `illustrative`, `unknown`).
- Optional provenance/evidence references with source labels and timestamps; missing provenance remains `null`.
- Optional normalized layout coordinates. Generated coordinates are a display-only layout, never an intelligence fact.

`validateGraphPage` performs runtime validation, including IDs, enum values, timestamps, score range, pagination cursor, duplicate IDs, and totals. Pages merge by record ID. Request cancellation is not reported as a normal error. Provider errors and malformed data produce distinct error kinds; no demo records are substituted after failure. The exact details are maintained in `src/components/command-theater/COMMAND_THEATER_INTEGRATION.md`.

The synthetic provider is dynamically imported only when the route explicitly passes `demoMode` in a development build (`NODE_ENV === "development"`). Production uses the unconfigured state unless the host injects a real adapter. Automated fixtures validate the frontend boundary; they do not validate a live API or authorization.

## Integration inventory

| Domain / capability | Current frontend state | Contract status |
| --- | --- | --- |
| Command Theater graph pages | Typed injected adapter and runtime validation | Frontend contract only; no production provider/API contract |
| Threat Intelligence records/feeds | Explicit unconfigured route | PR #3 describes ingestion/service work, but no HTTP router or OpenAPI contract was present in the reviewed files; owner confirmation requested |
| Vulnerability exposure/CVE/remediation | Explicit unconfigured route | PR #1 documents package-level read APIs, but says they are not mounted in the host and its cross-system contract is proposed/unagreed; owner confirmation requested |
| System health/worker/queue telemetry | Explicit unconfigured route | PR #4 contains an implemented backend router and Pydantic contracts on an open branch; not merged, and status/auth details still need reconciliation |
| Agent coordination/tasks | Explicit unconfigured route | PR #4 contains coordination proposals, but endpoint ownership/path alignment and the heartbeat/task identity contract remain unconfirmed |
| Global entity search | Not implemented; sidebar searches route labels only | No contract identified in the reviewed PRs |
| Alerts/notifications | Not surfaced as operational feature | PR #4 documents ops alerts; the frontend is not wired and authorization/ownership remain pending |
| Authentication/authorization/tenant scope | No frontend integration contract | No host/session-to-service authorization contract confirmed |
| User preferences | Locale in app memory; reduced-motion boolean in local browser storage | Local UI only; no account preferences service |

### Open-PR source artifacts (not integrated)

Reviewed against the following PR heads on 2026-11-05. These links are evidence pointers, **not** declarations that the APIs are deployed, approved for production, or safe to expose to browser users:

- [PR #1 — Vulnerability Intelligence](https://github.com/oldman-088/cicc/pull/1), reviewed at `84d32aa`. `docs/vulnerability-intelligence/API.md` describes `GET /v1/vulnerabilities` and `GET /v1/vulnerabilities/{cve}` with cursor/error behavior. The accompanying integration-contract document calls the cross-system contract proposed/not agreed, and the API package is not mounted in the host application. Asked the owner to confirm DTOs, auth/tenant boundaries, and host binding: [discussion](https://github.com/oldman-088/cicc/pull/1#issuecomment-6654459415).
- [PR #3 — Threat Intelligence](https://github.com/oldman-088/cicc/pull/3), reviewed at `805cd2b`. The reviewed preparation/architecture documents describe module interfaces, but the inspected diff did not expose an HTTP router or OpenAPI schema. Asked for the current/planned DTOs and a clear distinction between fixtures and live records: [discussion](https://github.com/oldman-088/cicc/pull/3#issuecomment-6654459704).
- [PR #4 — System Health and Coordination](https://github.com/oldman-088/cicc/pull/4), reviewed at `c610917`. Its docs and backend source describe the `/api/v1/ops` family (overview, components, metrics/history, activity, dependencies, tasks, workers, and alerts). The branch is open and not present in this checkout. Items requiring owner alignment include the documented `maintenance` status versus the initial status list, read-token/platform-auth behavior and user/tenant scope, final coordination path/DTO agreement, and the direct `apps/web/` overlap with this frontend. Coordination was requested here: [discussion](https://github.com/oldman-088/cicc/pull/4#issuecomment-6654459950); heartbeat/task identity is separately discussed in [issue #5](https://github.com/oldman-088/cicc/issues/5).

As of 2026-11-05 09:36 UTC, those coordination comments had no owner replies. Do not copy or edit another agent's branch. Recheck the threads before making transport/schema assumptions; keep these modules in their explicit not-configured state until the relevant owner and auth boundary are confirmed.

## Contract decisions required before implementation

For each API-owned domain, review and record the following with the service/product owner; this list is a request for real decisions, not a proposed server schema:

1. **Ownership/versioning:** service owner, API version/deprecation policy, environment and availability expectations.
2. **Identity and tenancy:** where credentials live, how authorization is checked, tenant scoping, least privilege, and whether browser access is permitted. Never expose service secrets in client bundles.
3. **Domain semantics:** source-of-truth for entities/relationships, stable IDs, verification vs. confidence, provenance/evidence, timestamps/time zones, deletion and merge semantics.
4. **Query behavior:** supported search/filter/sort fields, pagination/cursor guarantees, maximum page sizes, partial results, totals, and rate limits.
5. **Freshness/caching:** server and client cache policy, source timestamp meaning, stale behavior, revalidation, and whether a response can legitimately be called live.
6. **Failures:** authentication, authorization, validation, rate limit, timeout, upstream error, partial response, cancellation, and retry semantics. Define which are safe to retry.
7. **Operational telemetry:** authoritative health source, what “healthy/degraded/down” means, probe timestamps, worker/queue semantics, retention, alert ownership, and what is intentionally unknown.
8. **Search/notifications:** index scope, authorization, ranking, query limits, paging, deduplication, notification acknowledgement, and event ordering before designing global search or an alert center.
9. **Privacy/security:** data classification, redaction, audit expectations, log policy, URL handling, and retention.

## Mapping and validation rules

- Keep backend transport behind a host-owned adapter/BFF; UI components should depend on typed data-source interfaces, not guessed URLs.
- Validate untrusted provider data at runtime. A TypeScript annotation alone is not network validation.
- Preserve previous valid records on page failure only when the UX clearly reports partial/stale state; do not relabel old data as current/live.
- Keep empty-success, unconfigured, request error, invalid response, cancellation, stale/cached, demo, and live states distinct.
- Do not mark data verified, attach provenance, compute confidence, or synthesize an evidence source unless the real source/contract supplies that meaning.
- Never use presentation defaults (e.g. graph coordinates, display titles, local history) as durable backend facts.
- Add contract tests against owner-provided schemas/fixtures and integration tests against an approved service environment; label fixtures and keep their claims separate from live verification.

## Required evidence to promote a module beyond “not configured”

Before changing a module status or adding a live badge, record: contract URL/version and owner; implemented host adapter; auth/tenant review; data freshness/provenance behavior; loading/empty/error/cancellation tests; and a reproducible integration verification result. Browser visual/accessibility and performance evidence is tracked separately in `ACCESSIBILITY_REVIEW.md` and `PERFORMANCE_REPORT.md`.
