# CICC frontend API integration contracts

**Status:** contract inventory, not a backend spec · **Updated:** 2026-11-05

## Repository finding

The checked-out repository contains a Next.js frontend only. No backend routes, OpenAPI/JSON Schema documents, generated API client, auth implementation, tenant-isolation contract, notification/search service, or system-health source was found. Consequently this document intentionally defines **no HTTP endpoint, method, URL, header, payload, or server field**. The domain pages other than Command Theater currently display explicit not-configured states.

Do not implement guessed REST paths, direct browser connections to private services, hardcoded demo credentials, or inferred health. A team-owned, versioned contract and integration owner are prerequisites.

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
| Threat Intelligence records/feeds | Explicit unconfigured route | None in checkout |
| Vulnerability exposure/CVE/remediation | Explicit unconfigured route | None in checkout |
| System health/worker/queue telemetry | Explicit unconfigured route | None in checkout |
| Agent coordination/tasks | Explicit unconfigured route | None in checkout |
| Global entity search | Not implemented; sidebar searches route labels only | None in checkout |
| Alerts/notifications | Not surfaced as operational feature | None in checkout |
| Authentication/authorization/tenant scope | No frontend integration contract | None in checkout |
| User preferences | Locale in app memory; reduced-motion boolean in local browser storage | Local UI only; no account preferences service |

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
