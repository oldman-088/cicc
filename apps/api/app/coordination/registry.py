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

from sqlalchemy import func, select

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
    "ASSIGNED": {"DELIVERING", "ACKNOWLEDGED", "BLOCKED", "FAILED", "CANCELLED", "RETRYING"},
    "DELIVERING": {"ACKNOWLEDGED", "RUNNING", "FAILED", "RETRYING", "CANCELLED"},
    "ACKNOWLEDGED": {"RUNNING", "FAILED", "BLOCKED", "CANCELLED"},
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
    s.flush()
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
    task.state = new_state
    task.updated_at = utcnow()
    if new_state in ("QUEUED", "DELIVERING", "RETRYING"):
        task.attempts = (task.attempts or 0) + 1
    if new_state == "RETRYING":
        task.next_retry_at = utcnow() + timedelta(seconds=backoff_seconds(task.attempts or 1))
    if new_state == "QUEUED":
        task.next_retry_at = None
    if new_state == "FAILED":
        task.dead_letter = task.dead_letter or False
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
               limit: int = 100) -> list[dict]:
    q = select(models.CoordinationTask).order_by(models.CoordinationTask.updated_at.desc()).limit(limit)
    if state:
        q = q.where(models.CoordinationTask.state == normalize_state(state))
    if agent:
        q = q.where(models.CoordinationTask.agent == agent)
    if kind:
        q = q.where(models.CoordinationTask.kind == kind)
    out = []
    for t in s.execute(q).scalars().all():
        out.append({
            "id": t.id, "task_id": t.task_id, "event_id": t.event_id, "source": t.source,
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
