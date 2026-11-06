# DOMAIN STATUS CONTRACT for Agent 4 (read-only, M41, 2026-11-06)

Authoritative read-only contract for frontend domain badges/status. Owner:
Agent 1 (PR #4). Browser access goes through the BFF (relative `/api/...`,
server-side token) — **read-only**; the BFF write path stays limited to
`POST /api/v1/coordination/tasks`. No browser-side domain invocation, routing,
assignment, or state mutation is exposed or planned.

## Stable domain IDs (task `kind` == domain id)

| domain_id | Owner | Current status on merged surface |
|---|---|---|
| `threat_intel` | Agent 2 (PR #3, head `f3d3a7f` @2026-11-06T10:05Z, unmerged) | NOT_MOUNTED |
| `vuln_intel` | Agent 3 (PR #8 `3bc6527` merged into PR #1 branch 09:33Z; PR #1 head `f8e96c7`; none on main `ca8f82c`) | NOT_MOUNTED |
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

## Freshness / stale semantics (M42)

- Invoke responses include `freshness: {stale, age_s, clock_skew_s, basis}` where
  `basis` is `freshness_s` (domain-reported freshness wins) or `produced_at`
  (age of the tz-aware timestamp; naive = UTC). `stale=true` when age exceeds
  `stale_after_s` (`CICC_DOMAIN_STALE_AFTER_S`, default 3600). A future
  `produced_at` is **never treated as fresh**: `stale=false` but
  `clock_skew_s > 0` and a `domain_clock_skew` trace event fires. Malformed
  `freshness_s` (non-numeric/negative) → 422 `domain_invalid`.
- `evidence.last_stale` (status DTO) is true iff the most recent successful
  invoke was stale; a later fresh result resets it — stale results are never
  silently represented as fresh across recovery.
- Trace events: `domain_stale` (with basis/age/skew detail), `domain_clock_skew`.

## Authorization & tenant scoping

Reads: API read token (injected server-side by the BFF; browser holds none).
Writes (invoke/mount/deregister): API write token, server-side only — NOT
exposed to the browser. Tenant scoping: **pending owner decision** — until
then, no tenant claim is made; do not build tenant-filtered UI assumptions.

## Circuit breaker (M43)

- Open after `CICC_DOMAIN_CIRCUIT_FAILURES` (default 5) consecutive failures;
  while open, invokes fast-reject **503 `domain_circuit_open`** (sanitized; the
  handler is NOT executed). After `CICC_DOMAIN_CIRCUIT_COOLDOWN_S` (default 30)
  the circuit is half-open: one probe invoke; success closes it, failure
  re-opens. Circuit state is exposed in status `evidence.circuit`.
- **Process-local limitation:** circuit state lives in the API process memory.
  A restart resets it to closed (failures are re-counted from persisted
  `consecutive_failures` where applicable; an open circuit does NOT survive a
  restart). This is intentional fail-safe behavior and is documented here.
- Domain health alerts: rule `domain_status` per kind in
  `GET /api/v1/ops/alerts` (critical on FAILED), auto-resolved on
  EXECUTION_VERIFIED; full state/recovery history (incl. resolved) via
  `GET /api/v1/ops/alerts/history?rule=domain_status`. The generic alert
  evaluator never auto-resolves `domain_*` rules.

## Gateway observability metrics (M44)

`GET /api/v1/coordination/domains/metrics` (read token) →
```json
{"domains": {"<kind>": {"invokes", "successes", "failures", "success_rate",
   "timeouts", "retries", "stale_count", "skew_count",
   "latency": {"count", "avg_s", "max_s", "last_s"},
   "circuit": {"open", "opened_at", "threshold", "cooldown_s", "opens", "closes"},
   "mount_count", "status"}},
 "labels": ["kind"],
 "note": "bounded-cardinality labels (kind only); no tenant ids / tokens /
 payloads; latency+retry counters are process-local (restart resets them;
 invokes/successes persist via coord_domain_stats)"}
```
- Labels are bounded to `kind` — kinds are server-registered only; tenant ids,
  tokens, payload values, and any user-controlled strings NEVER appear in
  metrics or diagnostics (enforced by tests).
- `status` per kind is the same lifecycle value as the status DTO above —
  metrics are consistent with this contract.
- M45 additions for beta readiness: status evidence and metrics now include
  `last_success_at` (process-local) and `mounts_total` (persisted audit-event
  count, survives restart; `mount_count` stays process-local). Circuit
  open/close transitions are persisted as sanitized audit events
  (`coordination.domains`: "domain circuit OPENED/CLOSED kind=…"). On startup
  the API restores persisted stats for ALL kinds, so after a restart an
  unmounted domain honestly shows NOT_MOUNTED with its historical counters
  still visible in `statuses`/metrics. 502 `domain_error` messages no longer
  include even the exception class name (M45 sanitization hardening).
- **Process-local limitation:** latency aggregates, timeout/retry counters,
  stale/skew counts, and circuit transition counters live in process memory
  and reset on restart; `invokes`/`successes`/`consecutive_failures` persist
  in `coord_domain_stats`. Single-process deployments (current) are exact;
  multi-replica deployments would need external aggregation (not present).

## Error / unavailable-state behavior

Uniform codes: 401/403/404/409/410/413/422/429/502/503. Domain-specific: 409
`domain_not_mounted:{kind}`, 422 `domain_invalid`, 502 `domain_error`
(sanitized — never internals/credentials). UI mapping: loading = in-flight;
empty = `domains:[]`; unmounted = NOT_MOUNTED; unavailable = DEGRADED/FAILED
(show `last_error`, sanitized); verified = EXECUTION_VERIFIED; unknown = UNKNOWN.
