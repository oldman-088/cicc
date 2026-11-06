# FRONTEND CONTRACTS for Agent 4 (coordination-side, M37, 2026-11-06)

Stable examples Agent 4 can build against. Browser calls go through the BFF
(relative `/api/...`, no token in browser JS; server injects the API token).
**Write path via BFF stays limited to `POST /api/v1/coordination/tasks`** —
domain invoke/mount/deregister are API-write-token only, NOT browser-exposed.
All examples verified against the live API in sandbox (read token used here
for illustration; the browser never holds it).

## 1. System health + domain status (GET, BFF-proxied)

`GET /api/v1/coordination/health` →
```json
{"status": "healthy", "components": [
  {"key": "agents", "status": "healthy", "detail": "2 active, 0 stale/unknown of 2 registered"},
  {"key": "domains", "status": "healthy", "detail": "1 mounted, worst=EXECUTION_VERIFIED",
   "domains": {"threat_intel": {"status": "EXECUTION_VERIFIED", "version": "0.1-fixture",
     "source_ref": "fixture", "invokes": 3, "successes": 3, "last_invoke_at": "...", "last_error": null}}}]}
```
Domain states (evidence-based): `NOT_MOUNTED | MOUNTED | AVAILABLE | EXECUTION_VERIFIED | DEGRADED | FAILED | UNKNOWN`.
`GET /api/v1/coordination/domains` → `{"domains": [...same items...], "statuses": {...}, "states": [...], "note": "..."}`
`GET /api/v1/coordination/domains/{kind}/status` → `{"kind": "vuln_intel", "status": "NOT_MOUNTED", "evidence": {...}}`

UI state mapping: loading = request in flight; empty = `domains: []` (note explains);
unmounted = status NOT_MOUNTED; unavailable = DEGRADED/FAILED (show last_error, sanitized);
verified = EXECUTION_VERIFIED; unknown = UNKNOWN.

## 2. Task submission + lifecycle (the ONLY BFF write route)

`POST /api/v1/coordination/tasks` (BFF adds `x-cicc-idempotency-key` on the response) →
```json
201 {"task_id": "tsk-...", "state": "CREATED", "idempotency_key": "bff-..."}
```
409 on duplicate/illegal, 401 without server auth (BFF handles), 413 body > 16 KiB.
Lifecycle (API write-token, or agent-side): `POST /tasks/{id}/route|deliver|ack|start|progress|complete|fail|cancel|retry|approve|reject`,
`POST /sweep`. States: CREATED, VALIDATING, QUEUED, WAITING_FOR_APPROVAL, ASSIGNED,
DELIVERING, ACKNOWLEDGED, RUNNING, COMPLETED, FAILED, RETRYING, BLOCKED, CANCELLED, EXPIRED.

## 3. Task trace + provenance (GET, BFF-proxied)

`GET /api/v1/coordination/tasks/{task_id}/trace` →
```json
{"task_id": "dom-threat_intel-...", "state": "COMPLETED",
 "correlation": {"idempotency_key": "ti-1", "event_id": null, "source": "domain_gateway"},
 "result": {"result": {"reports": [...]}, "provenance": {"source": "ti-fixture-osint",
    "produced_at": "2026-11-06T...", "confidence": 0.8, "freshness_s": 300}},
 "events": [{"kind": "created", ...}, {"kind": "domain_result", ...}, ...],
 "deliveries": [], "approvals": []}
```

## 4. Domain results for TI/VI display

Domain invoke itself is server-side (API write token). The frontend consumes
**results** via: `GET /tasks?kind=threat_intel` (filter), `GET /tasks/{id}`,
`GET /tasks/{id}/trace` (result + provenance), and `GET /domains` / `/domains/{kind}/status`
for mount/health badges. When no domain is mounted, show the honest
NOT_MOUNTED state — do not render placeholder data as real.

## 5. Error surface (uniform)

401 missing/invalid token (BFF-injected server-side) · 403 not allowed (e.g. non-approver) ·
404 unknown id · 409 illegal transition / domain_not_mounted · 410 approval expired ·
413 too large · 422 schema · 429 rate limited (back off) · 502 domain_error (sanitized —
never contains internals/credentials). Domain-specific: 409 `domain_not_mounted: {kind}`,
422 `domain_invalid`, 502 `domain_error`.
