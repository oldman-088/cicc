"""Approval workflow (M7): WAITING_FOR_APPROVAL enforcement.

- Tasks whose normalized payload has requires_approval=true (or matching an
  approval policy rule) enter WAITING_FOR_APPROVAL at creation.
- Only configured approvers (CICC_COORD_APPROVERS, comma-separated, default
  "owner") may approve/reject via POST /tasks/{id}/approve|reject with a
  Bearer token whose... in non-platform mode the write token gate applies and
  `decided_by` is taken from the request body; with platform auth enabled the
  principal's user id is used.
- Approval records are audited (coord_approvals + task events).
- Approvals expire (CICC_COORD_APPROVAL_TTL_S, default 86400): sweep marks
  the approval expired and the task EXPIRED unless already decided.
- Approved -> QUEUED; rejected -> FAILED (auditable).
Never silently executes: WAITING_FOR_APPROVAL tasks are not deliverable.
"""
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update

from app import models
from . import registry


def approvers() -> set[str]:
    raw = os.getenv("CICC_COORD_APPROVERS", "owner")
    return {a.strip().lower() for a in raw.split(",") if a.strip()}


def approval_ttl_s() -> int:
    try:
        return int(os.getenv("CICC_COORD_APPROVAL_TTL_S", "86400"))
    except ValueError:
        return 86400


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def request_approval(s, task: models.CoordinationTask, requested_by: str | None) -> models.CoordinationApproval:
    """Idempotent: one pending approval per task."""
    existing = s.execute(select(models.CoordinationApproval).where(
        models.CoordinationApproval.task_id == task.task_id,
        models.CoordinationApproval.status == "pending")).scalars().first()
    if existing is not None:
        return existing
    ap = models.CoordinationApproval(
        task_id=task.task_id, status="pending", requested_by=requested_by,
        expires_at=_utcnow() + timedelta(seconds=approval_ttl_s()),
    )
    s.add(ap)
    s.flush()
    registry.record_event(s, task.task_id, "approval_requested", f"by={requested_by}")
    return ap


def decide(s, task_id: str, decision: str, decided_by: str) -> dict | None:
    """decision in {approve, reject}. Returns result dict or None if no task."""
    if decision not in ("approve", "reject"):
        return None
    if decided_by.lower() not in approvers():
        return {"ok": False, "code": 403, "reason": f"'{decided_by}' is not a configured approver"}
    t = s.execute(select(models.CoordinationTask).where(
        models.CoordinationTask.task_id == task_id)).scalar_one_or_none()
    if t is None:
        return None
    ap = s.execute(select(models.CoordinationApproval).where(
        models.CoordinationApproval.task_id == task_id,
        models.CoordinationApproval.status == "pending")).scalar_one_or_none()
    if ap is None:
        return {"ok": False, "code": 409, "reason": "no pending approval for task"}
    now = _utcnow()
    exp = ap.expires_at
    if exp and exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if exp and exp < now:
        ap.status = "expired"
        registry.record_event(s, task_id, "approval_expired", "")
        return {"ok": False, "code": 410, "reason": "approval expired"}
    # M25: guarded compare-and-set on the pending approval — concurrent
    # approve/reject races: exactly one decision wins, the loser gets 409
    new_status = "approved" if decision == "approve" else "rejected"
    res = s.execute(
        update(models.CoordinationApproval)
        .where(models.CoordinationApproval.task_id == task_id)
        .where(models.CoordinationApproval.status == "pending")
        .values(status=new_status, decided_by=decided_by, decided_at=now),
        execution_options={"synchronize_session": False},
    )
    if res.rowcount != 1:
        s.rollback()
        return {"ok": False, "code": 409, "reason": "no pending approval for task (concurrent decision)"}
    ap.status = new_status
    ap.decided_by = decided_by
    ap.decided_at = now
    if decision == "approve":
        registry.transition(s, t, "QUEUED", f"approved by {decided_by}")
        registry.record_event(s, task_id, "approval_approved", f"by={decided_by}")
    else:
        registry.transition(s, t, "FAILED", f"rejected by {decided_by}")
        registry.record_event(s, task_id, "approval_rejected", f"by={decided_by}")
    s.flush()
    return {"ok": True, "task_id": task_id, "approval": ap.status, "state": t.state}


def sweep_expired(s) -> list[str]:
    now = _utcnow()
    out = []
    aps = s.execute(select(models.CoordinationApproval).where(
        models.CoordinationApproval.status == "pending",
        models.CoordinationApproval.expires_at.isnot(None),
    )).scalars().all()
    aps = [ap for ap in aps if (ap.expires_at if ap.expires_at.tzinfo else ap.expires_at.replace(tzinfo=timezone.utc)) <= now]
    for ap in aps:
        ap.status = "expired"
        t = s.execute(select(models.CoordinationTask).where(
            models.CoordinationTask.task_id == ap.task_id)).scalar_one_or_none()
        if t is not None and registry.normalize_state(t.state) == "WAITING_FOR_APPROVAL":
            registry.transition(s, t, "EXPIRED", "approval expired")
        registry.record_event(s, ap.task_id, "approval_expired", "")
        out.append(ap.task_id)
    if out:
        s.flush()
    return out


def task_approval(s, task_id: str) -> dict | None:
    ap = s.execute(select(models.CoordinationApproval).where(
        models.CoordinationApproval.task_id == task_id
    ).order_by(models.CoordinationApproval.id.desc())).scalars().first()
    if ap is None:
        return None
    return {"task_id": ap.task_id, "status": ap.status, "requested_by": ap.requested_by,
            "decided_by": ap.decided_by, "note": ap.note,
            "created_at": ap.created_at.isoformat() if ap.created_at else None,
            "decided_at": ap.decided_at.isoformat() if ap.decided_at else None,
            "expires_at": ap.expires_at.isoformat() if ap.expires_at else None}
