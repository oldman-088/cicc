"""Durable coordination Task Registry — lifecycle v2 (M7).

States (canonical): CREATED, VALIDATING, QUEUED, WAITING_FOR_APPROVAL,
ASSIGNED, DELIVERING, ACKNOWLEDGED, RUNNING, COMPLETED, FAILED, RETRYING,
BLOCKED, CANCELLED, EXPIRED. Legacy states NEW/DELIVERED/IN_PROGRESS are
accepted on input and normalized via LEGACY_STATE_ALIASES (backward compat).

Every transition is validated against an explicit policy and recorded in
coord_task_events (complete audit history). Tasks support ownership,
dependencies (depends_on), timeouts, TTL expiry, cancellation, idempotency
keys and dead-lettering.
"""
import json
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select, update

from app import models

CANONICAL_STATES = (
    "CREATED", "VALIDATING", "QUEUED", "WAITING_FOR_APPROVAL", "ASSIGNED",
    "DELIVERING", "ACKNOWLEDGED", "RUNNING", "COMPLETED", "FAILED",
    "RETRYING", "BLOCKED", "CANCELLED", "EXPIRED",
)

# explicit transition policy — anything not listed is rejected + audited
ALLOWED_TRANSITIONS = {
    "CREATED": {"VALIDATING", "QUEUED", "WAITING_FOR_APPROVAL", "BLOCKED", "CANCELLED", "FAILED", "EXPIRED"},
    "VALIDATING": {"QUEUED", "WAITING_FOR_APPROVAL", "BLOCKED", "FAILED", "CANCELLED", "EXPIRED"},
    "QUEUED": {"ASSIGNED", "DELIVERING", "ACKNOWLEDGED", "WAITING_FOR_APPROVAL", "FAILED", "RETRYING", "BLOCKED", "CANCELLED", "EXPIRED"},
    "WAITING_FOR_APPROVAL": {"QUEUED", "ASSIGNED", "BLOCKED", "CANCELLED", "EXPIRED", "FAILED"},
    # M28: QUEUED added to ASSIGNED/DELIVERING/ACKNOWLEDGED — delivery-lease
    # recovery (recover_abandoned) re-queues abandoned tasks. Additive only.
    "ASSIGNED": {"DELIVERING", "ACKNOWLEDGED", "BLOCKED", "FAILED", "CANCELLED", "RETRYING", "QUEUED"},
    "DELIVERING": {"ACKNOWLEDGED", "RUNNING", "FAILED", "RETRYING", "CANCELLED", "QUEUED"},
    "ACKNOWLEDGED": {"RUNNING", "FAILED", "BLOCKED", "CANCELLED", "QUEUED"},
    "RUNNING": {"COMPLETED", "FAILED", "WAITING_FOR_APPROVAL", "BLOCKED", "CANCELLED", "EXPIRED"},
    "RETRYING": {"QUEUED", "FAILED", "BLOCKED", "CANCELLED"},
    "COMPLETED": set(),
    "FAILED": {"RETRYING", "QUEUED", "BLOCKED"},
    "BLOCKED": {"QUEUED", "FAILED", "CANCELLED"},
    "CANCELLED": set(),
    "EXPIRED": set(),
}

TERMINAL = {"COMPLETED", "CANCELLED", "EXPIRED"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def normalize_state(state: str | None) -> str | None:
    if not state:
        return None
    up = state.upper()
    return models.LEGACY_STATE_ALIASES.get(up, up if up in CANONICAL_STATES else up)


def _iso(dt) -> str | None:
    return dt.isoformat() if dt else None


def record_event(s, task_id: str, kind: str, detail: str | None = None) -> None:
    s.add(models.CoordinationTaskEvent(task_id=task_id, at=utcnow(), kind=kind, detail=detail))
    s.flush()  # visible to reads even with autoflush=False


def create_task(s, *, task_id: str, event_id: str | None, source: str, kind: str,
                repo: str | None, pr_ref: str | None, branch_ref: str | None,
                title: str | None, payload: dict, priority: int = 5,
                owner: str | None = None, depends_on: list | None = None,
                timeout_s: int | None = None, ttl_s: int | None = None,
                idempotency_key: str | None = None, requires_approval: bool = False) -> models.CoordinationTask:
    """Idempotent on task_id AND on idempotency_key (dedup)."""
    if idempotency_key:
        existing = s.execute(
            select(models.CoordinationTask).where(models.CoordinationTask.idempotency_key == idempotency_key)
        ).scalar_one_or_none()
        if existing is not None:
            record_event(s, existing.task_id, "duplicate_idempotency_key", task_id)
            s.flush()
            return existing
    t = s.execute(select(models.CoordinationTask).where(models.CoordinationTask.task_id == task_id)).scalar_one_or_none()
    if t is not None:
        return t
    now = utcnow()
    t = models.CoordinationTask(
        task_id=task_id, event_id=event_id, source=source, kind=kind, state="CREATED",
        priority=priority, repo=repo, pr_ref=pr_ref, branch_ref=branch_ref,
        title=title, payload=json.dumps(payload), owner=owner,
        depends_on=json.dumps(depends_on) if depends_on else None,
        timeout_s=timeout_s, expires_at=(now + timedelta(seconds=ttl_s)) if ttl_s else None,
        idempotency_key=idempotency_key,
    )
    s.add(t)
    try:
        s.flush()
    except Exception:
        # M24 P0-3: concurrent duplicate submission — the UNIQUE constraint on
        # task_id/idempotency_key wins the race; replay the existing row instead
        # of failing with a 500 IntegrityError
        s.rollback()
        existing = s.execute(select(models.CoordinationTask).where(
            models.CoordinationTask.task_id == task_id)).scalar_one_or_none()
        if existing is None and idempotency_key:
            existing = s.execute(select(models.CoordinationTask).where(
                models.CoordinationTask.idempotency_key == idempotency_key)).scalar_one_or_none()
        if existing is not None:
            record_event(s, existing.task_id, "duplicate_idempotency_key", task_id)
            s.flush()
            return existing
        raise
    record_event(s, task_id, "created", f"kind={kind} repo={repo} pr={pr_ref} requires_approval={requires_approval}")
    if requires_approval:
        transition(s, t, "WAITING_FOR_APPROVAL", "requires approval per policy")
        from . import approvals as _approvals  # local import: approvals imports registry
        _approvals.request_approval(s, t, requested_by=owner or source)
    return t


def transition(s, task: models.CoordinationTask, new_state: str, detail: str | None = None) -> bool:
    """Validated state transition. Legacy aliases normalized. Illegal
    transitions are rejected AND audited (transition_rejected)."""
    new_state = normalize_state(new_state) or new_state
    if new_state not in CANONICAL_STATES and new_state not in models.COORD_TASK_STATES:
        record_event(s, task.task_id, "transition_rejected", f"{task.state} -> {new_state} (unknown state)")
        return False
    cur = normalize_state(task.state) or task.state
    allowed = ALLOWED_TRANSITIONS.get(cur, set()) | ALLOWED_TRANSITIONS.get(task.state, set())
    if new_state not in allowed:
        record_event(s, task.task_id, "transition_rejected", f"{cur} -> {new_state}")
        return False
    old = task.state
    # M24 P0-6: guarded atomic UPDATE (compare-and-set on current state) so two
    # concurrent transitions cannot both win — works on SQLite and PostgreSQL
    values = {"state": new_state, "updated_at": utcnow()}
    if new_state in ("QUEUED", "DELIVERING", "RETRYING"):
        values["attempts"] = (models.CoordinationTask.attempts or 0) + 1
    if new_state == "RETRYING":
        values["next_retry_at"] = utcnow() + timedelta(seconds=backoff_seconds((task.attempts or 0) + 1))
    if new_state == "QUEUED":
        values["next_retry_at"] = None
        # M23: reviving a dead-lettered/retrying task clears the flag, otherwise
        # dead_letter=true would contradict the QUEUED state
        values["dead_letter"] = False
    res = s.execute(
        update(models.CoordinationTask)
        .where(models.CoordinationTask.id == task.id)
        .where(models.CoordinationTask.state.in_([cur, task.state]))
        .values(**values),
        execution_options={"synchronize_session": False},  # we sync locals manually below
    )
    if res.rowcount != 1:
        # lost the race to a concurrent transition — reject + audit
        record_event(s, task.task_id, "transition_rejected", f"{cur} -> {new_state} (concurrent)")
        return False
    task.state = new_state
    task.updated_at = values["updated_at"]
    if "attempts" in values:
        task.attempts = (task.attempts or 0) + 1
    if new_state == "RETRYING":
        task.next_retry_at = values["next_retry_at"]
    if new_state == "QUEUED":
        task.next_retry_at = None
        task.dead_letter = False
    record_event(s, task.task_id, f"state:{old}->{new_state}", detail)
    return True


def deps_ready(s, task: models.CoordinationTask) -> bool:
    """All depends_on tasks must be COMPLETED before this task may leave
    CREATED/VALIDATING for QUEUED."""
    if not task.depends_on:
        return True
    try:
        deps = json.loads(task.depends_on)
    except Exception:
        return False
    if not deps:
        return True
    rows = s.execute(
        select(models.CoordinationTask.task_id, models.CoordinationTask.state).where(
            models.CoordinationTask.task_id.in_(deps)
        )
    ).all()
    by_id = {tid: st for tid, st in rows}
    return all(normalize_state(by_id.get(d)) == "COMPLETED" for d in deps)


def sweep_timeouts(s, now: datetime | None = None) -> list[str]:
    """EXPIRED sweep: tasks past expires_at, or RUNNING past timeout_s.
    Returns task_ids transitioned. Safe to call periodically."""
    now = now or utcnow()
    expired = []
    rows = s.execute(select(models.CoordinationTask).where(
        models.CoordinationTask.expires_at.isnot(None),
        models.CoordinationTask.expires_at <= now,
        ~models.CoordinationTask.state.in_(list(TERMINAL) + ["FAILED"]),
    )).scalars().all()
    for t in rows:
        if transition(s, t, "EXPIRED", "TTL expired"):
            expired.append(t.task_id)
    running = s.execute(select(models.CoordinationTask).where(
        models.CoordinationTask.state == "RUNNING", models.CoordinationTask.timeout_s.isnot(None)
    )).scalars().all()
    for t in running:
        started = t.updated_at  # last transition into RUNNING
        if started and (now - started.replace(tzinfo=timezone.utc)).total_seconds() > (t.timeout_s or 0):
            if transition(s, t, "FAILED", f"timeout after {t.timeout_s}s"):
                expired.append(t.task_id)
    return expired


def backoff_seconds(attempts: int) -> int:
    """Exponential backoff for retries: base * 2^(attempts-1), capped at 1h.
    Base configurable via CICC_COORD_RETRY_BACKOFF_S (default 30)."""
    base = max(0, int(os.getenv("CICC_COORD_RETRY_BACKOFF_S", "30")))
    return min(3600, base * (2 ** max(0, (attempts or 1) - 1)))


def lease_seconds(task) -> int:
    """Delivery/ack lease: per-task timeout_s if set, else CICC_COORD_LEASE_S (default 600)."""
    if task.timeout_s:
        return int(task.timeout_s)
    return max(1, int(os.getenv("CICC_COORD_LEASE_S", "600")))


def recover_abandoned(s, now: datetime | None = None) -> list[str]:
    """M28: delivery-lease recovery. A task in ASSIGNED/DELIVERING/ACKNOWLEDGED
    whose lease elapsed (worker crashed or never acked) is re-queued exactly
    once via the guarded transition; a concurrent ack loses the race (409).
    Returns recovered task_ids."""
    now = now or utcnow()
    recovered = []
    rows = s.execute(select(models.CoordinationTask).where(
        models.CoordinationTask.state.in_(["ASSIGNED", "DELIVERING", "ACKNOWLEDGED"])
    )).scalars().all()
    for t in rows:
        last = t.updated_at
        if last and (now - last.replace(tzinfo=timezone.utc)).total_seconds() > lease_seconds(t):
            if transition(s, t, "QUEUED", f"delivery lease expired after {lease_seconds(t)}s (worker crash/abandon); re-queued"):
                recovered.append(t.task_id)
    return recovered


def requeue_ready(s, now: datetime | None = None) -> list[str]:
    """Sweep: RETRYING tasks whose backoff elapsed go back to QUEUED."""
    now = now or utcnow()
    rows = s.execute(select(models.CoordinationTask).where(
        models.CoordinationTask.state == "RETRYING")).scalars().all()
    requeued = []
    for t in rows:
        if t.next_retry_at is None or t.next_retry_at.replace(tzinfo=timezone.utc) <= now:
            if transition(s, t, "QUEUED", "backoff elapsed, re-queued"):
                requeued.append(t.task_id)
    return requeued


def list_tasks(s, state: str | None = None, agent: str | None = None, kind: str | None = None,
               limit: int = 100, dead_letter: bool | None = None) -> list[dict]:
    q = select(models.CoordinationTask).order_by(models.CoordinationTask.updated_at.desc()).limit(limit)
    if state:
        q = q.where(models.CoordinationTask.state == normalize_state(state))
    if agent:
        q = q.where(models.CoordinationTask.agent == agent)
    if kind:
        q = q.where(models.CoordinationTask.kind == kind)
    if dead_letter is not None:
        q = q.where(models.CoordinationTask.dead_letter == dead_letter)
    out = []
    for t in s.execute(q).scalars().all():
        out.append({
            "id": t.id, "task_id": t.task_id, "event_id": t.event_id, "source": t.source,
            "idempotency_key": t.idempotency_key,  # M27: correlation key visible on reads (Backup Agent 4 finding)
            "kind": t.kind, "agent": t.agent, "state": normalize_state(t.state), "priority": t.priority,
            "repo": t.repo, "pr_ref": t.pr_ref, "branch_ref": t.branch_ref, "title": t.title,
            "attempts": t.attempts, "result": t.result, "owner": t.owner,
            "depends_on": json.loads(t.depends_on) if t.depends_on else [],
            "timeout_s": t.timeout_s, "expires_at": _iso(t.expires_at),
            "dead_letter": bool(t.dead_letter),
            "routing_explanation": json.loads(t.routing_explanation) if t.routing_explanation else None,
            "progress": getattr(t, "progress", 0) or 0,
            "next_retry_at": _iso(getattr(t, "next_retry_at", None)),
            "payload": json.loads(t.payload) if t.payload else None,
            "handoff": t.handoff,
            "created_at": _iso(t.created_at), "updated_at": _iso(t.updated_at),
        })
    return out


def task_events(s, task_id: str, limit: int = 200) -> list[dict]:
    rows = s.execute(
        select(models.CoordinationTaskEvent)
        .where(models.CoordinationTaskEvent.task_id == task_id)
        .order_by(models.CoordinationTaskEvent.at.desc())
        .limit(limit)
    ).scalars().all()
    return [{"at": _iso(r.at), "kind": r.kind, "detail": r.detail} for r in rows]


def task_stats_by_agent(s, agent: str) -> dict:
    """Completion/failure stats used by workload-aware routing."""
    rows = s.execute(
        select(models.CoordinationTask.state, func.count(models.CoordinationTask.id)).where(
            models.CoordinationTask.agent == agent
        ).group_by(models.CoordinationTask.state)
    ).all()
    by_state = {normalize_state(st): n for st, n in rows}
    active = sum(n for st, n in by_state.items() if st in ("QUEUED", "ASSIGNED", "DELIVERING", "ACKNOWLEDGED", "RUNNING", "WAITING_FOR_APPROVAL"))
    return {
        "agent": agent,
        "active_tasks": active,
        "completed": by_state.get("COMPLETED", 0),
        "failed": by_state.get("FAILED", 0),
        "retries": by_state.get("RETRYING", 0),
        "by_state": by_state,
    }


def dag(s, limit: int = 500) -> dict:
    """Dependency DAG over tasks: nodes + edges from depends_on."""
    rows = s.execute(select(models.CoordinationTask).limit(limit)).scalars().all()
    nodes, edges = [], []
    ids = set()
    for t in rows:
        ids.add(t.task_id)
        nodes.append({"task_id": t.task_id, "kind": t.kind, "state": normalize_state(t.state),
                      "agent": t.agent, "priority": t.priority})
        if t.depends_on:
            try:
                deps = json.loads(t.depends_on)
            except Exception:
                deps = []
            for d in deps:
                edges.append({"from": d, "to": t.task_id})
    return {"nodes": nodes, "edges": edges, "known_ids": sorted(ids)}


def progress(s, task_id: str, percent: int, note: str | None = None) -> dict | None:
    """Structured progress report (0..100). Audited as an event."""
    t = s.execute(select(models.CoordinationTask).where(models.CoordinationTask.task_id == task_id)).scalar_one_or_none()
    if t is None:
        return None
    percent = max(0, min(100, int(percent)))
    t.progress = percent
    t.updated_at = utcnow()
    record_event(s, task_id, "progress", f"{percent}%" + (f" {note}" if note else ""))
    s.flush()
    return {"task_id": task_id, "progress": percent, "state": normalize_state(t.state)}


def health(s) -> dict:
    """M28 P1: actionable coordination health. Every component carries an
    explicit status (healthy|degraded|stale|failed|unavailable|not_configured|
    unknown) plus human-readable `reasons` — never a bare generic indicator."""
    from sqlalchemy import func as _func
    now = utcnow()
    components = []
    reasons = []

    def comp(key, status, detail="", comp_reasons=None):
        components.append({"key": key, "status": status, "detail": detail,
                           "reasons": comp_reasons or []})
        for r in (comp_reasons or []):
            reasons.append(f"{key}: {r}")

    # --- agents ---
    agents = s.execute(select(models.CoordinationAgent)).scalars().all()
    active = [a for a in agents if a.last_heartbeat and (now - a.last_heartbeat.replace(tzinfo=timezone.utc)).total_seconds() <= 300]
    stale = [a.agent for a in agents if a.agent not in {x.agent for x in active}]
    comp("agents", "healthy" if agents and not stale else ("degraded" if agents else "not_configured"),
         f"{len(active)} active, {len(stale)} stale/unknown of {len(agents)} registered",
         [f"agent '{a}' has no fresh heartbeat (stale/unavailable)" for a in stale])

    # --- tasks ---
    tasks = s.execute(select(models.CoordinationTask)).scalars().all()
    by_state = {}
    dead = []
    overdue_retry = []
    for t in tasks:
        st = normalize_state(t.state)
        by_state[st] = by_state.get(st, 0) + 1
        if t.dead_letter:
            dead.append(t.task_id)
        if st == "RETRYING" and t.next_retry_at and t.next_retry_at.replace(tzinfo=timezone.utc) <= now:
            overdue_retry.append(t.task_id)
    t_reasons = ([f"dead-lettered task(s): {', '.join(dead[:10])}" for _ in [0] if dead]
                 + [f"retry overdue (backoff elapsed, not re-queued): {', '.join(overdue_retry[:10])}" for _ in [0] if overdue_retry])
    comp("tasks", "degraded" if (dead or overdue_retry) else "healthy",
         f"{len(tasks)} total; by state: {by_state}", t_reasons)

    # --- broker ---
    broker = os.getenv("RABBITMQ_AMQP_URL")
    comp("broker", "not_configured" if not broker else "unknown",
         "RABBITMQ_AMQP_URL not set — human-assisted delivery only" if not broker else "configured; live check not performed here",
         [] if broker else ["no broker configured: deliveries are prepared (human-assisted), NOT broker-delivered"])

    # --- deliveries ---
    deliv = s.execute(select(models.CoordinationDelivery)).scalars().all()
    unconfirmed = [d.task_id for d in deliv if d.status != "confirmed"]
    comp("deliveries", "degraded" if unconfirmed else "healthy",
         f"{len(deliv)} attempts; {sum(1 for d in deliv if d.status == 'confirmed')} confirmed",
         [f"unconfirmed delivery attempt(s) on: {', '.join(unconfirmed[:10])}" for _ in [0] if unconfirmed])

    # --- approvals ---
    appr = s.execute(select(models.CoordinationApproval)).scalars().all()
    pending = [a for a in appr if a.status == "pending"]
    overdue_appr = []
    for a in pending:
        exp = getattr(a, "expires_at", None)
        if exp and exp.replace(tzinfo=timezone.utc) <= now:
            overdue_appr.append(a.task_id)
    comp("approvals", "degraded" if overdue_appr else ("healthy" if pending or appr else "not_configured"),
         f"{len(pending)} pending of {len(appr)} total",
         [f"approval pending past expiry on: {', '.join(overdue_appr[:10])}" for _ in [0] if overdue_appr])

    # --- contract governance health (M30: adoption visibility in health) ---
    from app.coordination import amendments as _amd
    amds = _amd.list_amendments(s)
    by_status = {}
    for a in amds:
        by_status[a["status"]] = by_status.get(a["status"], 0) + 1
    pending_ids = [a["amendment_id"] for a in amds if a["status"] == "pending"]
    comp("contract_governance",
         "degraded" if pending_ids else "healthy",
         f"{len(amds)} amendments; by status: {by_status}; effective version {_amd.effective_version(s)}",
         [f"amendment(s) awaiting owner decision: {', '.join(pending_ids[:10])}" for _ in [0] if pending_ids])

    # --- last attempted / successful operations (M29: evidence-backed recency) ---
    from sqlalchemy import func as _f
    last_webhook = s.execute(select(_f.max(models.GitHubEvent.received_at))).scalar()
    last_sync_ok = s.execute(select(_f.max(models.SyncAttempt.finished_at)).where(
        models.SyncAttempt.status == "success")).scalar()
    last_sync_any = s.execute(select(_f.max(models.SyncAttempt.finished_at))).scalar()
    last_task_event = s.execute(select(_f.max(models.CoordinationTaskEvent.at))).scalar()
    last_ops = {
        "last_webhook_received": _iso(last_webhook),
        "last_github_sync_success": _iso(last_sync_ok),
        "last_github_sync_attempt": _iso(last_sync_any),
        "last_task_event": _iso(last_task_event),
        "checked_at": _iso(now),
        "note": "on-demand check; NOT continuous monitoring (no scheduler running)",
    }
    comp("last_operations", "unknown" if not (last_webhook or last_sync_any or last_task_event) else "healthy",
         "most recent recorded operations", [])

    sev = {"healthy": 0, "not_configured": 1, "unknown": 2, "unavailable": 3, "stale": 3,
           "degraded": 4, "failed": 5}
    overall = max((sev.get(c["status"], 2) for c in components), default=0)
    overall = {v: k for k, v in sev.items()}[overall]
    return {"overall": overall, "components": components, "reasons": reasons,
            "last_operations": last_ops, "at": _iso(now)}


def trace(s, task_id: str) -> dict | None:
    """M28 P1: full correlation trace for one task — identifiers, lifecycle
    events (chronological), delivery attempts, approval decision. Read-only."""
    t = s.execute(select(models.CoordinationTask).where(models.CoordinationTask.task_id == task_id)).scalar_one_or_none()
    if t is None:
        return None
    evs = s.execute(
        select(models.CoordinationTaskEvent).where(models.CoordinationTaskEvent.task_id == task_id)
        .order_by(models.CoordinationTaskEvent.id)
    ).scalars().all()
    dls = s.execute(
        select(models.CoordinationDelivery).where(models.CoordinationDelivery.task_id == task_id)
        .order_by(models.CoordinationDelivery.id)
    ).scalars().all()
    appr = s.execute(
        select(models.CoordinationApproval).where(models.CoordinationApproval.task_id == task_id)
        .order_by(models.CoordinationApproval.id)
    ).scalars().all()
    return {
        "task_id": t.task_id,
        "correlation": {"idempotency_key": t.idempotency_key, "event_id": t.event_id},
        "state": normalize_state(t.state),
        "agent": t.agent,
        "attempts": t.attempts,
        "dead_letter": bool(t.dead_letter),
        "events": [{"id": e.id, "at": _iso(e.at), "kind": e.kind, "detail": e.detail} for e in evs],
        "deliveries": [{"id": d.id, "channel": d.channel, "queue": d.queue, "message_id": d.message_id,
                        "status": d.status, "attempt": d.attempt, "at": _iso(d.at)} for d in dls],
        "approvals": [{"id": a.id, "status": a.status, "requested_by": a.requested_by,
                       "decided_by": a.decided_by, "at": _iso(a.decided_at or a.created_at)} for a in appr],
    }


def metrics(s) -> dict:
    """Aggregate coordination metrics (read-only, honest counts from DB)."""
    from sqlalchemy import func as _func
    tasks = s.execute(select(models.CoordinationTask)).scalars().all()
    by_state, by_kind, by_agent_active = {}, {}, {}
    prog_sum = prog_n = 0
    dead = 0
    for t in tasks:
        st = normalize_state(t.state)
        by_state[st] = by_state.get(st, 0) + 1
        by_kind[t.kind] = by_kind.get(t.kind, 0) + 1
        if st in ("QUEUED", "ASSIGNED", "DELIVERING", "ACKNOWLEDGED", "RUNNING", "WAITING_FOR_APPROVAL"):
            by_agent_active[t.agent or "unassigned"] = by_agent_active.get(t.agent or "unassigned", 0) + 1
            prog_sum += getattr(t, "progress", 0) or 0
            prog_n += 1
        if t.dead_letter:
            dead += 1
    deliv = s.execute(select(models.CoordinationDelivery)).scalars().all()
    by_outcome = {}
    for d in deliv:
        by_outcome[d.status] = by_outcome.get(d.status, 0) + 1
    appr = s.execute(select(models.CoordinationApproval)).scalars().all()
    appr_pending = sum(1 for a in appr if a.status == "pending")
    agents = s.execute(select(models.CoordinationAgent)).scalars().all()
    return {
        "tasks_total": len(tasks),
        "by_state": by_state,
        "by_kind": by_kind,
        "active_by_agent": by_agent_active,
        "avg_progress_active": round(prog_sum / prog_n, 1) if prog_n else 0.0,
        "dead_lettered": dead,
        "deliveries_total": len(deliv),
        "deliveries_by_outcome": by_outcome,
        "approvals_pending": appr_pending,
        "agents_registered": len(agents),
        "agents_online": sum(1 for a in agents if a.status in ("available", "busy")),
    }
