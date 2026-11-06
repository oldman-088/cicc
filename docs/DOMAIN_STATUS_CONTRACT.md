# DOMAIN STATUS CONTRACT for Agent 4 (read-only, M41, 2026-11-06)

Authoritative read-only contract for frontend domain badges/status. Owner:
Agent 1 (PR #4). Browser access goes through the BFF (relative `/api/...`,
server-side token) — **read-only**; the BFF write path stays limited to
`POST /api/v1/coordination/tasks`. No browser-side domain invocation, routing,
assignment, or state mutation is exposed or planned.

## Stable domain IDs (task `kind` == domain id)

| domain_id | Owner | Current status on merged surface |
|---|---|---|
| `threat_intel` | Agent 2 (PR #3, head `4f1776f`, unmerged) | NOT_MOUNTED |
| `vuln_intel` | Replacement Agent 3 (PR #8 head `7f6db2a` / PR #1, unmerged; merge order owner-reserved) | NOT_MOUNTED |
| `frontend_e2e` | Agent 4 self-verification kind | n/a (not a gateway domain) |

New domains register under their `kind`; IDs are stable once registered.

## Read-only status DTO

`GET /api/v1/coordination/domains` (BFF-proxied) →
```json
{"domains": [{"kind", "version", "source_ref", "mounted_at", "status"}],
 "statuses": {"<kind>": {"status", "version", "source_ref", "mounted_at",
    "invokes", "successes", "consecutive_failures", "last_stale", "stale_after_s",
    "last_invoke_at", "last_error"}},
 "states": ["NOT_MOUNTED","MOUNTED","AVAILABLE","EXECUTION_VERIFIED","DEGRADED","FAILED","UNKNOWN"],
 "note": "empty list = no domain API mounted in this deployment"}
```
`GET /api/v1/coordination/domains/{kind}/status` → `{"kind", "status", "evidence": {…same fields…}}`
(`NOT_MOUNTED` with zeroed evidence for unknown kinds — 200, not an error).
`GET /api/v1/coordination/health` → `components[]` includes
`{"key":"domains","status":"healthy"|"degraded","detail","domains":{…}}`.

## Lifecycle values (evidence-based; a domain is never healthy because its package exists)

- `NOT_MOUNTED` — no handler registered
- `MOUNTED` — registered, not yet validated
- `AVAILABLE` — validated, never invoked
- `EXECUTION_VERIFIED` — last invoke succeeded, result+provenance persisted with trace
- `DEGRADED` — prior success, last invoke failed
- `FAILED` — invokes attempted, none succeeded (incl. retry exhaustion / consecutive failures)
- `UNKNOWN` — handler mounted but stats missing/inconsistent

## Provenance & freshness semantics

Domain results carry `provenance{source, produced_at, confidence∈[0,1],
freshness_s, …domain-specific…}`. `stale=true` on invoke responses and
`evidence.last_stale` when freshness exceeds `stale_after_s`
(`CICC_DOMAIN_STALE_AFTER_S`, default 3600). Experimental/fixture data keeps
its label (`EXPERIMENTAL_DEMO_DATA_ONLY`, `data_origin=non-live:…`) end-to-end —
the frontend must render that label, never as verified live intelligence.

## Task trace (for result display)

`GET /api/v1/coordination/tasks/{task_id}/trace` → `{task_id, state,
correlation{idempotency_key,…}, result{result, provenance, stale}, events[],
deliveries[], approvals[]}`; `GET /api/v1/coordination/tasks?kind=<domain_id>`
lists domain tasks.

## Authorization & tenant scoping

Reads: API read token (injected server-side by the BFF; browser holds none).
Writes (invoke/mount/deregister): API write token, server-side only — NOT
exposed to the browser. Tenant scoping: **pending owner decision** — until
then, no tenant claim is made; do not build tenant-filtered UI assumptions.

## Error / unavailable-state behavior

Uniform codes: 401/403/404/409/410/413/422/429/502. Domain-specific: 409
`domain_not_mounted:{kind}`, 422 `domain_invalid`, 502 `domain_error`
(sanitized — never internals/credentials). UI mapping: loading = in-flight;
empty = `domains:[]`; unmounted = NOT_MOUNTED; unavailable = DEGRADED/FAILED
(show `last_error`, sanitized); verified = EXECUTION_VERIFIED; unknown = UNKNOWN.
