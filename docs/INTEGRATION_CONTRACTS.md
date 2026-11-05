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
