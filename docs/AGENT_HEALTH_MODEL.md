# Agent Health-State Model (M24)

`GET /api/v1/coordination/agents` returns per-agent `status`, `stale`, and
`health`. `health` is the canonical classification:

| health | meaning | rule |
|---|---|---|
| `ACTIVE` | live worker with fresh heartbeat | `last_heartbeat` within `CICC_AGENT_STALE_S` (default 300s) AND `status` not `offline` |
| `STALE` | heartbeat expired | `last_heartbeat` older than `CICC_AGENT_STALE_S` (sweep marks `status=offline`) |
| `UNAVAILABLE` | explicitly offline | `status=offline` with a heartbeat on record |
| `UNKNOWN` | never heartbeated (legacy rows) | `last_heartbeat` is NULL |

## Transition model
```
(register)          -> ACTIVE (status=available, heartbeat=now)
(heartbeat ok)      -> ACTIVE (status updated)
(heartbeat stale)   -> STALE -> sweep -> UNAVAILABLE (status=offline, audited)
(deregister)        -> UNAVAILABLE (audited)
(no heartbeat ever) -> UNKNOWN
```
Every status change is audited to the ops event log (`source=coordination.agents`).

## Boundary (important)
`health` describes **application heartbeat liveness only**. It is NOT evidence
of an active Arena session, and lack of response is NOT proof of unavailability.
Arena session availability is a separate concept and is never inferred here.

## Task-side consistency (M24)
Task state transitions are guarded compare-and-set updates (atomic on SQLite and
PostgreSQL): concurrent transitions on the same task cannot both win; the loser
is rejected and audited (`transition_rejected ... (concurrent)`). Duplicate
concurrent submissions of the same `task_id`/`idempotency_key` produce exactly
one persisted task (UNIQUE constraint + replay handling). Verified under real
threaded execution in `apps/api/tests/test_m24_concurrency.py` (6 tests).
