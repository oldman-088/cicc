# Task-Event & Traceability Contract (M27)

## Correlation model
- `task_id` — primary identifier (client- or server-generated).
- `idempotency_key` — dedup/correlation key; **persisted on the task row and
  serialized on reads** (`GET /tasks`, `GET /tasks/{id}` → field
  `idempotency_key`, added M27 after Backup Agent 4's finding) and appears in
  events (`created`, `duplicate_idempotency_key`). BFF write path generates
  `bff-<uuid>` server-side when the client omits it.
- `event_id` — webhook-origin correlation (delivery id for GitHub tasks).

## Persisted events (coord_task_events) and where they are exposed
Exposed via `GET /api/v1/coordination/tasks/{id}/events` and global webhook
stream `GET /api/v1/coordination/events` (webhook deliveries only):

| event kind | when | exposed |
|---|---|---|
| `created` | task creation | task events |
| `state:OLD->NEW` | every successful transition | task events |
| `transition_rejected` | illegal/concurrent-losing transition | task events |
| `report:<action>` | ignored report (wrong state) | task events |
| `report:complete_blocked_deps` | deps gate on complete (409) | task events |
| `duplicate_idempotency_key` | duplicate submission replay | task events |
| `approval_approved` / `approval_rejected` / `approval_expired` | approval decisions | task events + `/tasks/{id}/approval` |
| `dead_letter` | max attempts reached | task events |
| `delivery_blocked_deps` | deliver blocked by deps | task events |

## Not currently exposed
- Per-delivery records are exposed via `GET /tasks/{id}/deliveries` (not as
  events). Ops-level agent status transitions go to the ops event log
  (`source=coordination.agents`), readable via `/api/v1/ops/events`.
- No event is exposed for rate-limit rejections (429) — by design (log-only,
  sanitized).

## Lifecycle trace example
create → `created`; route/deliver → `state:*`; ack/start → `state:*`;
progress → `progress` field on task; complete/fail → `state:RUNNING->COMPLETED|FAILED`;
retry → `state:->RETRYING->QUEUED`; approval → `approval_*` + state; terminal
states (COMPLETED/CANCELLED/EXPIRED/FAILED+dead_letter) are final.

All of the above is pinned by tests: `test_m20_contract_consistency.py`
(wire==descriptor), `test_m23_lifecycle.py` (state==latest event),
`test_m24_concurrency.py` / `test_m25_concurrency.py` /
`test_m25_pg_concurrency.py` (concurrent consistency on SQLite and real PG).
