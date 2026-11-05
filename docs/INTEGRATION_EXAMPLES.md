# Integration Examples — coordination contract v1.0 (M18)

Executable: `API=http://<api-host>:8000 WRITE_TOKEN=... READ_TOKEN=... python3 scripts/contract_check.py`
runs a full agent-side lifecycle against the live API (all submissions are
SIMULATED-FIXTURE actions by the script — not Arena sessions, not proof that
another agent's code is integrated). Machine-readable descriptor:
`GET /api/v1/coordination/contract` (read token).

## 1. AuthN/AuthZ
- Reads: `Authorization: Bearer $CICC_OPS_READ_TOKEN`; writes: `Bearer $CICC_OPS_WRITE_TOKEN`
  (write also satisfies read). Approvals additionally require `decided_by` ∈ `CICC_COORD_APPROVERS`.
- Webhook is HMAC-only (`X-Hub-Signature-256`), no bearer token.
- Browser clients never hold tokens — use the BFF (`/api/*` on the web app), which
  injects the server-side token and rejects writes (403).
- **Tenant context: PENDING owner decision** — single-tenant now; no tenant header
  is required or accepted.

## 2. Task lifecycle (canonical states)
`pending → queued → routed/assigned → acknowledged → in_progress → completed | failed → (retry) → queued`;
`awaiting_approval` gate when `requires_approval`; `cancelled`/`expired` terminal; rejection → `failed` + `approval.status=rejected`.
Illegal transitions → **409** and are audited (`transition_rejected`).

## 3. Idempotency & duplicates
- `POST /tasks` with the same `idempotency_key` replays the original task (no duplicate).
- Webhook `X-GitHub-Delivery` dedups; a duplicate older than `CICC_GH_MAX_REPLAY_AGE_S`
  (default 24h) raises a **detection** alert `webhook_replay_after_window` — detection,
  not rejection (GitHub sends no signed timestamp).

## 4. Errors & retry expectations
401 missing/invalid read token · 403 write/approver · 404 unknown id · 409 illegal
transition/dependency gate/duplicate · 413 >256 KiB · 422 DTO validation · 429 rate limit
(back off). Failed tasks: `POST /tasks/{id}/retry` (works from failed/retrying/blocked —
fixed in M18) or automatic requeue via `POST /sweep`.

## 5. Provenance / audit / correlation
Every transition writes an event: `GET /tasks/{id}/events`, global `GET /events`;
tasks carry `correlation_id`; deliveries via `GET /tasks/{id}/deliveries`
(`delivered:true` only with broker confirm, else honest `human_assisted`).

## 6. Concrete example (curl)
```
H='Content-Type: application/json'
# register + heartbeat (write token)
curl -s -XPOST $API/api/v1/coordination/agents/register -H "$H" -H "Authorization: Bearer $W" \
  -d '{"agent":"agent-2-threat-intel","specialization":"threat-intel","capabilities":["ti"],"version":"1.0"}'
curl -s -XPOST $API/api/v1/coordination/agents/agent-2-threat-intel/heartbeat -H "$H" -H "Authorization: Bearer $W" -d '{"status":"available"}'
# create task (idempotent via idempotency_key)
curl -s -XPOST $API/api/v1/coordination/tasks -H "$H" -H "Authorization: Bearer $W" \
  -d '{"task_id":"ti-42","idempotency_key":"ti-42-ik","kind":"threat_intel","priority":3,"title":"...","payload":{...}}'
# route/ack/start/progress/complete
curl -s -XPOST $API/api/v1/coordination/tasks/ti-42/route -H "$H" -H "Authorization: Bearer $W" -d '{"agent":"agent-2-threat-intel"}'
curl -s -XPOST $API/api/v1/coordination/tasks/ti-42/ack    -H "$H" -H "Authorization: Bearer $W" -d '{}'
curl -s -XPOST $API/api/v1/coordination/tasks/ti-42/start  -H "$H" -H "Authorization: Bearer $W" -d '{}'
curl -s -XPOST $API/api/v1/coordination/tasks/ti-42/progress -H "$H" -H "Authorization: Bearer $W" -d '{"percent":50,"note":"halfway"}'
curl -s -XPOST $API/api/v1/coordination/tasks/ti-42/complete -H "$H" -H "Authorization: Bearer $W" -d '{"result":"..."}'
# audit + metrics
curl -s $API/api/v1/coordination/tasks/ti-42/events -H "Authorization: Bearer $R"
curl -s "$API/api/v1/coordination/metrics" -H "Authorization: Bearer $R"
```
