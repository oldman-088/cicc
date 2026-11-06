# TI CONTRACT COMPARISON — Agent 2 (PR #3 @ `4f1776f`) vs Coordination Gateway (Agent 1)

Reviewed: `apps/threat_intelligence/api.py` at PR #3 head `4f1776f83d929aa7ef951952808fa6d1569a2a1c`
(fetched read-only 2026-11-06T07:19Z; branch not modified).

## Agent 2 side (as implemented)
- `ThreatIntelligenceRequest(tenant_id?, query?, limit=100, offset=0, experimental_label?)` — pydantic, extra=forbid, label must be EXPERIMENTAL_DEMO_DATA_ONLY.
- `ThreatIntelligenceAPI.invoke_endpoint(path, request) -> dict` with keys:
  `status, data, total_count, has_more, provenance (str "threat_intelligence_api_v1::<path>"),
  confidence (1.0), experimental_label, timestamp (utcnow)`.
- Mount points: 12 simulated endpoints (actors/malware/.../osint-sources); `Agent1CoordinationContract.register_domain_gateway` is **simulated** (returns True) — real gateway registration is Agent 1's side.
- All current data labeled EXPERIMENTAL_DEMO_DATA_ONLY (honest; no live-source claim).

## Gateway handler contract (Agent 1, M35/M37)
- `handler(payload: dict, task) -> {"result": <json>, "provenance": {"source", "produced_at", ...}}`
- provenance must include source + produced_at; confidence/freshness/source-ts/idempotency_key recommended.
- handlers must be idempotent (gateway retries with same key); status errors -> sanitized DomainError.

## Compatibility changes (implemented in MY adapter, their branch untouched)
1. `domain_adapters/threat_intel_adapter.py` `make_handler(module_path)` wraps their class:
   payload -> ThreatIntelligenceRequest; their response dict -> gateway schema:
   `result={status,data,total_count,has_more,experimental_label}`,
   `provenance={source=<their provenance str>, produced_at=<their timestamp, tz-aware>,
   confidence, freshness_s=<age>, experimental_label, module_path, endpoint, task_id, idempotency_key}`.
2. Their `status != "success"` -> DomainError (sanitized) so the gateway records FAILED/DEGRADED, never fake success.
3. experimental_label defaults to the module's EXPERIMENTAL_DEMO_DATA_ONLY when absent — experimental data never looks verified.
4. Missing module (PR #3 unmerged) -> DomainNotMounted: honest NOT_MOUNTED.

## Verified (M38/M40, sandbox-labeled)
- Adapter unit tests 3/3 (fixture replicating their exact class shape; field mapping; error mapping; missing-module honesty).
- Live M40 trial 23/23 @2026-11-06T07:52Z incl. REAL PR-head `api.py` executed read-only through the gateway:
  mount 201 -> invoke 201 (source=`threat_intelligence_api_v1::/api/v1/threat-intelligence/osint-sources`,
  confidence=1.0, label=EXPERIMENTAL_DEMO_DATA_ONLY) -> trace persisted with domain_result event.
- NOT claimed: production mount (PR #3 unmerged), live OSINT ingestion (their data is experimental demo data).
