"""Machine-readable self-description of coordination contract v1.0 (M18).

Served read-only at GET /api/v1/coordination/contract. Additive only — this
does NOT change contract v1.0 semantics; it mirrors docs/INTEGRATION_CONTRACTS.md
so other agents can discover paths/DTOs/states/errors programmatically.
"""

# the 14 canonical states as returned by the API (normalize_state), lowercase
TASK_STATES = ["created", "validating", "queued", "waiting_for_approval",
               "assigned", "delivering", "acknowledged", "running", "completed",
               "failed", "retrying", "blocked", "cancelled", "expired"]

ERROR_CODES = {
    "401": "missing/invalid CICC_OPS_READ_TOKEN on reads (except webhook)",
    "403": "missing/invalid CICC_OPS_WRITE_TOKEN or approver on writes/approvals",
    "404": "unknown task_id / agent",
    "409": "illegal state transition, dependency gate, duplicate idempotency_key",
    "413": "webhook body > 256 KiB",
    "422": "request DTO validation failed",
    "429": "rate limited (read or write limiter)",
}

ENDPOINTS = [
    {"method": "GET", "path": "/api/v1/coordination/contract", "auth": "read", "summary": "this descriptor"},
    {"method": "GET", "path": "/api/v1/coordination/agents", "auth": "read", "summary": "registered agents (+stale flag)"},
    {"method": "POST", "path": "/api/v1/coordination/agents/register", "auth": "write", "summary": "idempotent agent upsert; DTO AgentRegisterIn"},
    {"method": "POST", "path": "/api/v1/coordination/agents/{agent}/heartbeat", "auth": "write", "summary": "status heartbeat"},
    {"method": "POST", "path": "/api/v1/coordination/agents/{agent}/deregister", "auth": "write", "summary": "mark offline"},
    {"method": "POST", "path": "/api/v1/coordination/tasks", "auth": "write", "summary": "create task; DTO TaskIn; idempotent via idempotency_key"},
    {"method": "GET", "path": "/api/v1/coordination/tasks", "auth": "read", "summary": "list, filters state/agent/kind"},
    {"method": "GET", "path": "/api/v1/coordination/tasks/{task_id}", "auth": "read", "summary": "task incl. deps, retries, correlation_id"},
    {"method": "GET", "path": "/api/v1/coordination/tasks/{task_id}/events", "auth": "read", "summary": "audit trail for the task"},
    {"method": "GET", "path": "/api/v1/coordination/tasks/{task_id}/deliveries", "auth": "read", "summary": "delivery records (delivered:true only with broker confirm, else human_assisted)"},
    {"method": "POST", "path": "/api/v1/coordination/tasks/{task_id}/route", "auth": "write", "summary": "route to agent (rules or explicit)"},
    {"method": "POST", "path": "/api/v1/coordination/tasks/{task_id}/ack", "auth": "write", "summary": "agent acknowledges -> acknowledged"},
    {"method": "POST", "path": "/api/v1/coordination/tasks/{task_id}/start", "auth": "write", "summary": "-> in_progress"},
    {"method": "POST", "path": "/api/v1/coordination/tasks/{task_id}/progress", "auth": "write", "summary": "ProgressIn {percent, note}"},
    {"method": "POST", "path": "/api/v1/coordination/tasks/{task_id}/deliver", "auth": "write", "summary": "record delivery attempt"},
    {"method": "POST", "path": "/api/v1/coordination/tasks/{task_id}/complete", "auth": "write", "summary": "ReportIn {result}; 409 if deps unmet/illegal state/approval required"},
    {"method": "POST", "path": "/api/v1/coordination/tasks/{task_id}/fail", "auth": "write", "summary": "ReportIn {result}; retryable via /retry"},
    {"method": "POST", "path": "/api/v1/coordination/tasks/{task_id}/cancel", "auth": "write", "summary": "-> cancelled"},
    {"method": "POST", "path": "/api/v1/coordination/tasks/{task_id}/retry", "auth": "write", "summary": "failed/cancelled -> queued (retries+1)"},
    {"method": "POST", "path": "/api/v1/coordination/tasks/{task_id}/approve", "auth": "write + approver", "summary": "DecisionIn {decided_by, note}; approver allowlist"},
    {"method": "POST", "path": "/api/v1/coordination/tasks/{task_id}/reject", "auth": "write + approver", "summary": "same; rejection is terminal (failed) with approval.status=rejected"},
    {"method": "GET", "path": "/api/v1/coordination/tasks/{task_id}/approval", "auth": "read", "summary": "approval status"},
    {"method": "GET", "path": "/api/v1/coordination/tasks/dag", "auth": "read", "summary": "dependency graph view"},
    {"method": "GET", "path": "/api/v1/coordination/metrics", "auth": "read", "summary": "counts by state/agent + delivery honesty"},
    {"method": "GET", "path": "/api/v1/coordination/events", "auth": "read", "summary": "global audit stream (carries task_id)"},
    {"method": "POST", "path": "/api/v1/coordination/sweep", "auth": "write", "summary": "expire timeouts, requeue retries, expire approvals, mark stale agents"},
    {"method": "GET", "path": "/api/v1/coordination/rules", "auth": "read", "summary": "routing rules"},
    {"method": "POST", "path": "/api/v1/coordination/rules", "auth": "write", "summary": "add routing rule"},
    {"method": "POST", "path": "/api/v1/coordination/webhook/github", "auth": "HMAC only", "summary": "GitHub webhook; X-GitHub-Delivery idempotent dedup; replay-age detection alert"},
]


def contract_v1() -> dict:
    return {
        "contract": "cicc.coordination",
        "version": "1.0",
        "status": "proposed — pending explicit adoption by Agents 2/3/4 (see docs/CONTRACT_ADOPTION.md)",
        "base": "/api/v1/coordination",
        "auth": {
            "reads": "Authorization: Bearer $CICC_OPS_READ_TOKEN",
            "writes": "Authorization: Bearer $CICC_OPS_WRITE_TOKEN (write also satisfies read)",
            "approvals": "additionally require approver principal (CICC_OPS_APPROVERS)",
            "webhook": "X-Hub-Signature-256 HMAC-SHA256 with CICC_GH_WEBHOOK_SECRET (no bearer token)",
            "bff": "browser clients never hold tokens; apps/web BFF proxies server-side",
            "tenant": "PENDING owner decision — single-tenant now; no tenant header required or accepted. BFF deployments that gate on a single-tenant declaration should set CICC_OPS_TRUSTED_SINGLE_TENANT=true (see .env.example)",
        },
        "endpoints": ENDPOINTS,
        "task_states": TASK_STATES,
        "dtos": {
            "TaskIn": ["task_id?", "idempotency_key?", "kind", "priority", "title?", "payload", "repo?", "pr_ref?", "branch_ref?", "owner?", "depends_on?", "timeout_s?", "ttl_s?", "requires_approval?"],
            "ReportIn": ["result?", "provenance?"],
            "ProgressIn": ["percent", "note?"],
            "DecisionIn": ["decided_by", "note?"],
            "AgentRegisterIn": ["agent", "specialization?", "capabilities?", "version?", "meta?"],
            "AgentHeartbeatIn": ["status?", "active_tasks?", "meta?"],
            "POST /sweep response": ["expired_tasks", "requeued", "recovered_abandoned", "expired_approvals", "stale_agents", "stale_amendments"],
            "Amendment status lifecycle": ["pending", "accepted", "rejected", "withdrawn (proposer-only)", "superseded (via accept supersedes[])", "stale (sweep, CICC_AMENDMENT_STALE_S)"],
            "Amendment fields": ["amendment_id", "title", "description", "proposed_by", "affects[]", "compatibility", "target_version", "status", "decided_by", "decision_note", "linked_refs[]", "history[]", "duplicate?"],
            "POST /contract/amendments/{id}/decide": ["decision(accept|reject)", "decided_by(approver-only)", "note? (required if not backward_compatible)", "linked_refs[]", "supersedes[]"],
            "self-approval policy": "M31: PROHIBITED server-side by default — proposer cannot decide own amendment (403); only explicit CICC_AMENDMENT_ALLOW_SELF_APPROVAL=1 permits it, always flagged self_approved=true in history",
            "POST /contract/amendments/{id}/withdraw": ["by(proposer-only)"],
            "POST /contract/amendments (duplicate)": "identical re-proposal of a pending amendment returns 200 with duplicate:true (idempotent)",
            "POST /contract/amendments": ["amendment_id", "title", "description", "proposed_by", "affects[]", "compatibility", "target_version?"],
            "GET /contract/amendments[?status]": ["amendments[]: amendment_id,title,status,proposed_by,decided_by,affects,compatibility,target_version,linked_refs,created_at,decided_at"],
            "POST /contract/amendments/{id}/decide": ["decision(accept|reject)", "decided_by(approver-only)", "note?", "linked_refs[]"],
            "POST /contract/amendments/{id}/refs": ["refs[]"],
            "GET /health component": ["key", "status", "detail", "reasons"],  # keys incl. contract_governance (M30)
            "GET /health.last_operations": ["last_webhook_received", "last_github_sync_success", "last_github_sync_attempt", "last_task_event", "checked_at", "note"],
            "GET /tasks/{id}/trace": ["task_id", "correlation.idempotency_key", "correlation.event_id", "state", "agent", "attempts", "dead_letter", "result", "events[]", "deliveries[]", "approvals[]"],
            "TaskDTO (GET /tasks, /tasks/{id})": ["id", "task_id", "event_id", "source", "idempotency_key", "kind", "agent", "state", "priority", "repo", "pr_ref", "branch_ref", "title", "attempts", "result", "owner", "depends_on", "timeout_s", "expires_at", "dead_letter", "routing_explanation", "progress", "next_retry_at", "payload", "handoff", "created_at", "updated_at"],
            "AgentDTO (GET /agents)": ["agent", "specialization", "capabilities", "status", "stale", "health", "version", "meta", "last_heartbeat", "registered_at", "active_tasks", "completed", "failed", "retries", "by_state"],
        },
        "error_codes": ERROR_CODES,
        "idempotency": {
            "tasks": "idempotency_key replays the original task (no duplicate)",
            "webhook": "X-GitHub-Delivery dedups; duplicate older than CICC_GH_MAX_REPLAY_AGE_S raises detection alert webhook_replay_after_window (not rejected — GitHub sends no signed timestamp)",
        },
        "provenance": "every transition writes an audit event (actor, action, detail) visible via /events and /tasks/{id}/events; tasks carry correlation_id",
        "retry": "failed tasks are retried via POST /retry (retries counter) or sweep requeue; 409 on illegal transitions; clients should back off on 429",
                "GET /domains": ["domains[]: kind, version, source_ref, mounted_at, status", "statuses: kind -> {status, invokes, successes, last_invoke_at, last_error(sanitized)}", "states[]: NOT_MOUNTED|MOUNTED|AVAILABLE|EXECUTION_VERIFIED|DEGRADED|FAILED|UNKNOWN", "note"],
                        "GET /domains/{kind}/status (read)": "{kind, status, evidence{...}} — evidence-based lifecycle status; NOT_MOUNTED for unregistered kinds",
                        "GET /diagnostics (read)": "{status, db_ok, version, uptime_s, mounted_domains[], domain_statuses{}, stale_after_s, note} — no credentials/internal details",
                        "invoke response freshness (M42)": "201 gains freshness {stale, age_s, clock_skew_s, basis: freshness_s|produced_at|none}; stale=true when age > CICC_DOMAIN_STALE_AFTER_S; future produced_at -> clock_skew_s>0 + domain_clock_skew event (never treated as fresh); malformed freshness_s (non-numeric/negative) -> 422 domain_invalid; optional body.tenant_id recorded as UNVERIFIED claimed_tenant event — no tenant enforcement until owner approves",
                        "POST /domains/{kind}/mount (write-token only)": "body: module_path, attr, version, source_ref -> 201 {kind, mounted, status} — read-only import of a server-side module; 409 domain_not_mounted if module absent; 502 domain_mount_failed (sanitized); 422 invalid handler",
                        "POST /domains/{kind}/deregister (write-token only)": "200 {kind, deregistered, status=NOT_MOUNTED} | 409 domain_not_mounted",
                        "POST /domains/{kind}/invoke (API write-token only; BFF write path stays POST /tasks)": "body: payload, task_id?, idempotency_key?, title? -> 201 {task_id, state, result, provenance, stale (M41: freshness_s or produced_at age > CICC_DOMAIN_STALE_AFTER_S), idempotency_key} | 200 duplicate:true | 409 domain_not_mounted | 502 domain_error (sanitized) | 422 domain_invalid; per-attempt timeout CICC_DOMAIN_INVOKE_TIMEOUT_S (10s), retries CICC_DOMAIN_INVOKE_RETRIES (1) with the SAME idempotency_key (handlers must be idempotent)",
                        "GET /health": "components[] gains key=domains: {status, detail, domains: kind -> status+evidence} — a domain is healthy only on observable evidence, never because its package exists",
            "ReportIn.provenance?": "additive (M35, proposed as AMD-002, pending owner): agent/domain-reported results may carry provenance persisted with the result and shown in /tasks/{id}/trace",
            "adoption_stages": "PROPOSED -> ACCEPTED -> IMPLEMENTED -> MOUNTED -> CONSUMED -> EXECUTED -> END_TO_END_VERIFIED (Agent 1 registry; CONSUMED = a consumer actively calls the endpoint, END_TO_END_VERIFIED = cross-domain sandbox/live trial green); domain handler lifecycle (M37): NOT_MOUNTED -> MOUNTED -> AVAILABLE -> EXECUTION_VERIFIED, with DEGRADED/FAILED on observed failures, UNKNOWN on missing evidence",
        "lease_recovery": "M28: POST /sweep re-queues ASSIGNED/DELIVERING/ACKNOWLEDGED tasks whose delivery lease elapsed (timeout_s or CICC_COORD_LEASE_S, default 600s) — worker crash/abandon recovery; reported in sweep response field recovered_abandoned; additive transition (QUEUED reachable from those states)",
    }
