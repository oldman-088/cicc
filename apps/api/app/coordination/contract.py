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
            "ReportIn": ["result?"],
            "ProgressIn": ["percent", "note?"],
            "DecisionIn": ["decided_by", "note?"],
            "AgentRegisterIn": ["agent", "specialization?", "capabilities?", "version?", "meta?"],
            "AgentHeartbeatIn": ["status?", "active_tasks?", "meta?"],
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
    }
