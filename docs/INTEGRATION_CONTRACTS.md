# Integration Contracts

Contracts between Agent 1 (coordination/ops) and Agents 2/3/4.


## Programmatic task creation (M10) — for Agents 2/3/4 to ENQUEUE work

`POST /api/v1/coordination/tasks` (write token + per-principal rate limit):

```json
{"kind": "vuln_scan", "title": "scan main", "payload": {"target": "main"},
 "priority": 3, "idempotency_key": "scan-main-2026-11-04",
 "repo": "oldman-088/cicc", "branch_ref": "main",
 "depends_on": ["task-id-..."], "timeout_s": 3600, "ttl_s": 86400,
 "requires_approval": false}
```

- Response 201 `{task_id, state, kind, duplicate}` — idempotent on `task_id` AND `idempotency_key` (re-POST with same key returns the existing task, `duplicate: true`).
- `task_id` auto-generated (`api-<hex12>`) when omitted; charset `[A-Za-z0-9_.:-]` (no slashes — path-safe).
- `kind` `[a-z0-9_]+`; `priority` 1–10; `requires_approval: true` → task starts in WAITING_FOR_APPROVAL (deliver → 409 until approved by `CICC_COORD_APPROVERS`).
- `depends_on` gates delivery until dependencies COMPLETED.
- Consumption (unchanged): route → deliver → ack → start → progress → complete/fail; `GET /coordination/metrics` for aggregate state; `GET /coordination/tasks/dag` for dependencies.
- Bench: `BASE_URL=... WRITE_TOKEN=... python scripts/bench_coordination.py --tasks 50` (LIVE benchmark, p50/p95/max per step).

## GitHub webhook contract (inbound)

`POST /api/v1/coordination/webhook/github` — headers `X-GitHub-Event`,
`X-GitHub-Delivery`, `X-Hub-Signature-256` (sha256 HMAC of raw body with
`CICC_GH_WEBHOOK_SECRET`; previous secret accepted during rotation).
Allowlist via `CICC_GH_EVENT_ALLOWLIST`; 256 KiB cap; replay dedup on
delivery id; normalized payloads redact secret-like keys. Events create
registry tasks (`gh-<delivery>`), idempotent.

## GitHub API sync (inbound, LIVE)

`GET /coordination/github/status` (probe) + `POST /coordination/github/sync`
(poll PRs/issues/check-runs of `CICC_GH_REPO`, default oldman-088/cicc;
creates `ci_failed` tasks for failed checks on arena/* branches and
`pr_opened` tasks for open PRs). Token (`GH_TOKEN`/`GITHUB_TOKEN`) used
header-only, never logged/returned; circuit-breaker + rate-limit guarded.

## Agent consumption contract (outbound, for Agents 2/3/4)

Register + heartbeat (`/coordination/agents/*`), poll `GET /coordination/tasks`,
then route → deliver → ack → start → progress → complete/fail. Approvals:
only `CICC_COORD_APPROVERS` may approve/reject. Every transition is audited
(`GET /tasks/{id}/events`). Deliveries are recorded in `/tasks/{id}/deliveries`;
"delivered" is only claimed with broker publisher-confirm; otherwise honest
`human_assisted/published`.

---

# Contract v1.0 (M11-02) — stable, backward-compatible; confirmation requested from Agents 2/3/4 via PR #4 comment

All coordination endpoints are under `/api/v1/coordination`, read-gated by
read token, write-gated by write token + per-principal rate limit (429).
Every state transition is audited (`GET /tasks/{id}/events`).

| # | Capability | Method & path | Key fields | Response |
|---|---|---|---|---|
| 1 | Agent register | `POST /agents/register` | `agent`, `capabilities[]`, `meta?` | 201 `{agent, status}` — idempotent |
| 2 | Heartbeat | `POST /agents/{agent}/heartbeat` | `status?`, `active_tasks?`, `meta?` | 200; stale after `CICC_AGENT_STALE_S` (300s) |
| 3 | Deregister | `POST /agents/{agent}/deregister` | — | 200 `{status: offline}`; 404 unknown |
| 4 | List agents | `GET /agents` | — | `{agents: [..., stale]}` |
| 5 | Submit task | `POST /tasks` | `kind`, `payload`, `idempotency_key?`, `priority` 1–10, `depends_on?`, `timeout_s?`, `ttl_s?`, `requires_approval?` | 201 `{task_id, state, duplicate}` |
| 6 | List tasks | `GET /tasks?state=&agent=&kind=` | filters | `{tasks: [..., progress, next_retry_at, routing_explanation]}` |
| 7 | Route/assign | `POST /tasks/{id}/route` | — | `{agent, state, explanation}` (explainable) |
| 8 | Deliver | `POST /tasks/{id}/deliver` | — | 200 `{delivered, via}` — `delivered:true` ONLY with broker publisher-confirm; no broker → `via: human_assisted, delivered:false` (honest); 409 while WAITING_FOR_APPROVAL or deps unmet |
| 9 | Ack | `POST /tasks/{id}/ack` | — | → ACKNOWLEDGED |
| 10 | Start | `POST /tasks/{id}/start` | — | → RUNNING |
| 11 | Progress | `POST /tasks/{id}/progress` | `percent` 0–100, `note?` | 200, audited |
| 12 | Complete | `POST /tasks/{id}/complete` | `result?` | → COMPLETED |
| 13 | Fail | `POST /tasks/{id}/fail` | `reason` | → RETRYING (backoff) or dead-letter→BLOCKED after `CICC_COORD_MAX_ATTEMPTS` |
| 14 | Retry/cancel | `POST /tasks/{id}/retry` \| `/cancel` | — | audited |
| 15 | Approve/reject | `POST /tasks/{id}/approve` \| `/reject` | `decided_by` (+`note`) | 403 non-approver, 409 no pending, 410 expired |
| 16 | Approval state | `GET /tasks/{id}/approval` | — | `{approval: {status, requested_by, decided_by, expires_at}}` |
| 17 | Audit trail | `GET /tasks/{id}/events` | — | `{events: [{at, kind, detail}]}` |
| 18 | Deliveries | `GET /tasks/{id}/deliveries` | — | `{deliveries: [{channel, status, attempt, ...}]}` |
| 19 | DAG | `GET /tasks/dag` | — | `{nodes, edges}` |
| 20 | Metrics | `GET /metrics` | — | honest aggregates (see M10) |
| 21 | Sweep | `POST /sweep` | — | `{expired_tasks, requeued, expired_approvals, stale_agents}` |
| 22 | Webhook (GitHub→us) | `POST /webhook/github` | HMAC headers | 401 bad sig / fail-closed, dedup by delivery |
| 23 | GitHub live | `GET /github/status`, `POST /github/sync` | — | probe/sync vs api.github.com |
| 24 | GitHub events | `GET /events?limit=` | — | ingested webhook events w/ provenance |
| 25 | Routing rules | `GET /rules`, `POST /rules` | `name, match, agent, priority` | explainable rules-first routing |

## Agent 4 dashboard contract (M11-06)
The Coordination dashboard consumes ONLY these verified endpoints:
`/agents`, `/tasks` (+filters), `/tasks/dag`, `/metrics`, `/events`,
`/github/status`, plus ops `/api/v1/overview` (services incl. `rabbitmq`
broker chip). It distinguishes: online vs stale agents; CREATED/QUEUED/
ASSIGNED/DELIVERING/ACKNOWLEDGED/RUNNING/WAITING_FOR_APPROVAL/BLOCKED/FAILED/
RETRYING/COMPLETED/CANCELLED/EXPIRED; broker-confirmed vs human-assisted
deliveries; broker connected vs unavailable; live metrics vs `—` when a
fetch fails. No fabricated data: failed fetches render as unavailable.

## Backward compatibility
- Legacy state aliases accepted on input, normalized to the 14 canonical states.
- `delivered:false + via:human_assisted` semantics unchanged since M7.
- New fields are additive; no endpoint removed since M6.
