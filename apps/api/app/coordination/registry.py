"""Durable coordination Task Registry (states + audit history).

States: NEW, QUEUED, DELIVERED, IN_PROGRESS, WAITING_FOR_APPROVAL, COMPLETED,
FAILED, RETRYING, BLOCKED. Transitions are validated; every transition is
recorded in coord_task_events (audit history).
"""
from datetime import datetime, timezone

from sqlalchemy import select

from app import models

ALLOWED_TRANSITIONS = {
    "NEW": {"QUEUED", "BLOCKED", "FAILED"},
    "QUEUED": {"DELIVERED", "FAILED", "BLOCKED", "RETRYING"},
    "DELIVERED": {"IN_PROGRESS", "FAILED", "RETRYING"},
    "IN_PROGRESS": {"COMPLETED", "FAILED", "WAITING_FOR_APPROVAL", "BLOCKED"},
    "WAITING_FOR_APPROVAL": {"IN_PROGRESS", "BLOCKED", "FAILED"},
    "RETRYING": {"QUEUED", "FAILED", "BLOCKED"},
    "COMPLETED": set(),
    "FAILED": {"RETRYING", "QUEUED"},
    "BLOCKED": {"QUEUED", "FAILED"},
}

TERMINAL = {"COMPLETED"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt) -> str | None:
    return dt.isoformat() if dt else None


def record_event(s, task_id: str, kind: str, detail: str | None = None) -> None:
    s.add(models.CoordinationTaskEvent(task_id=task_id, at=utcnow(), kind=kind, detail=detail))
    s.flush()  # visible to reads even with autoflush=False


def create_task(s, *, task_id: str, event_id: str | None, source: str, kind: str,
                repo: str | None, pr_ref: str | None, branch_ref: str | None,
                title: str | None, payload: dict, priority: int = 5) -> models.CoordinationTask:
    t = s.execute(select(models.CoordinationTask).where(models.CoordinationTask.task_id == task_id)).scalar_one_or_none()
    if t is not None:
        return t  # idempotent on task_id
    import json

    t = models.CoordinationTask(
        task_id=task_id, event_id=event_id, source=source, kind=kind, state="NEW",
        priority=priority, repo=repo, pr_ref=pr_ref, branch_ref=branch_ref,
        title=title, payload=json.dumps(payload),
    )
    s.add(t)
    s.flush()
    record_event(s, task_id, "created", f"kind={kind} repo={repo} pr={pr_ref}")
    return t


def transition(s, task: models.CoordinationTask, new_state: str, detail: str | None = None) -> bool:
    """Validated state transition. Returns False on illegal transition."""
    if new_state not in models.COORD_TASK_STATES:
        return False
    if new_state not in ALLOWED_TRANSITIONS.get(task.state, set()):
        record_event(s, task.task_id, "transition_rejected", f"{task.state} -> {new_state}")
        return False
    old = task.state
    task.state = new_state
    task.updated_at = utcnow()
    if new_state in ("QUEUED", "DELIVERED", "RETRYING"):
        task.attempts = (task.attempts or 0) + 1
    record_event(s, task.task_id, f"state:{old}->{new_state}", detail)
    return True


def list_tasks(s, state: str | None = None, agent: str | None = None, limit: int = 100) -> list[dict]:
    import json

    q = select(models.CoordinationTask).order_by(models.CoordinationTask.updated_at.desc()).limit(limit)
    if state:
        q = q.where(models.CoordinationTask.state == state)
    if agent:
        q = q.where(models.CoordinationTask.agent == agent)
    out = []
    for t in s.execute(q).scalars().all():
        out.append({
            "id": t.id, "task_id": t.task_id, "event_id": t.event_id, "source": t.source,
            "kind": t.kind, "agent": t.agent, "state": t.state, "priority": t.priority,
            "repo": t.repo, "pr_ref": t.pr_ref, "branch_ref": t.branch_ref, "title": t.title,
            "attempts": t.attempts, "result": t.result,
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
