"""M29 P0 — cross-owner contract amendment flow.

Proposals are recorded with explicit ownership and never auto-accepted.
Only configured approvers (CICC_COORD_APPROVERS) may accept/reject, mirroring
the task-approval gate. Each amendment carries a compatibility statement and
linked implementation refs, giving PROPOSED -> ACCEPTED -> IMPLEMENTED ->
MOUNTED -> EXECUTED -> VERIFIED traceability without unilateral changes.
"""
import json
import os
import re
from datetime import datetime, timezone

from sqlalchemy import select

from app import models

_SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{2,63}$")


def approvers() -> set[str]:
    raw = os.getenv("CICC_COORD_APPROVERS", "owner")
    return {a.strip().lower() for a in raw.split(",") if a.strip()}


def _iso(dt):
    return dt.isoformat() if dt else None


def propose(s, *, amendment_id: str, title: str, description: str, proposed_by: str,
            affects: list | None = None, compatibility: dict | None = None,
            target_version: str | None = None) -> dict:
    if not _SLUG.match(amendment_id or ""):
        raise ValueError("amendment_id must match ^[A-Za-z0-9][A-Za-z0-9-]{2,63}$")
    if not title or len(title) > 256:
        raise ValueError("title required (<=256 chars)")
    if not description:
        raise ValueError("description required")
    existing = s.execute(select(models.CoordinationAmendment).where(
        models.CoordinationAmendment.amendment_id == amendment_id)).scalar_one_or_none()
    if existing is not None:
        raise ValueError(f"amendment_id '{amendment_id}' already exists (status={existing.status})")
    row = models.CoordinationAmendment(
        amendment_id=amendment_id, title=title, description=description,
        affects=json.dumps(affects or []), compatibility=json.dumps(compatibility or {}),
        target_version=target_version, proposed_by=proposed_by, status="pending",
    )
    s.add(row)
    s.flush()
    return to_dict(row)


def to_dict(row: models.CoordinationAmendment) -> dict:
    return {
        "amendment_id": row.amendment_id, "title": row.title, "description": row.description,
        "affects": json.loads(row.affects) if row.affects else [],
        "compatibility": json.loads(row.compatibility) if row.compatibility else {},
        "target_version": row.target_version, "proposed_by": row.proposed_by,
        "status": row.status, "decided_by": row.decided_by, "decision_note": row.decision_note,
        "linked_refs": json.loads(row.linked_refs) if row.linked_refs else [],
        "created_at": _iso(row.created_at), "decided_at": _iso(row.decided_at),
    }


def list_amendments(s, status: str | None = None) -> list[dict]:
    q = select(models.CoordinationAmendment).order_by(models.CoordinationAmendment.id.desc())
    if status:
        q = q.where(models.CoordinationAmendment.status == status)
    return [to_dict(r) for r in s.execute(q).scalars().all()]


def get(s, amendment_id: str) -> dict | None:
    row = s.execute(select(models.CoordinationAmendment).where(
        models.CoordinationAmendment.amendment_id == amendment_id)).scalar_one_or_none()
    return to_dict(row) if row else None


def decide(s, amendment_id: str, decision: str, decided_by: str, note: str | None = None,
           linked_refs: list | None = None) -> dict:
    """Guarded CAS on pending amendments — a concurrent/duplicate decision
    loses and gets 409, exactly like task approvals."""
    if decision not in ("accept", "reject"):
        return {"ok": False, "code": 422, "reason": "decision must be 'accept' or 'reject'"}
    if decided_by.lower() not in approvers():
        return {"ok": False, "code": 403, "reason": f"'{decided_by}' is not a configured approver"}
    from sqlalchemy import update
    new_status = "accepted" if decision == "accept" else "rejected"
    res = s.execute(
        update(models.CoordinationAmendment)
        .where(models.CoordinationAmendment.amendment_id == amendment_id)
        .where(models.CoordinationAmendment.status == "pending")
        .values(status=new_status, decided_by=decided_by, decision_note=note,
                linked_refs=json.dumps(linked_refs or []),
                decided_at=datetime.now(timezone.utc))
    )
    if res.rowcount != 1:
        cur = get(s, amendment_id)
        if cur is None:
            return {"ok": False, "code": 404, "reason": "amendment_not_found"}
        return {"ok": False, "code": 409, "reason": f"amendment already {cur['status']}"}
    return {"ok": True, "amendment_id": amendment_id, "status": new_status, "decided_by": decided_by}


def attach_refs(s, amendment_id: str, refs: list) -> dict:
    row = s.execute(select(models.CoordinationAmendment).where(
        models.CoordinationAmendment.amendment_id == amendment_id)).scalar_one_or_none()
    if row is None:
        return {"ok": False, "code": 404, "reason": "amendment_not_found"}
    existing = json.loads(row.linked_refs) if row.linked_refs else []
    merged = existing + [r for r in refs if r not in existing]
    row.linked_refs = json.dumps(merged)
    s.flush()
    return {"ok": True, "amendment_id": amendment_id, "linked_refs": merged}


def effective_version(s, base: str = "1.0") -> str:
    """Highest accepted target_version wins; base contract otherwise."""
    rows = s.execute(select(models.CoordinationAmendment).where(
        models.CoordinationAmendment.status == "accepted")).scalars().all()
    versions = [r.target_version for r in rows if r.target_version]
    if not versions:
        return base
    def key(v):
        return tuple(int(x) if x.isdigit() else 0 for x in v.split("."))
    return max(versions + [base], key=key)
