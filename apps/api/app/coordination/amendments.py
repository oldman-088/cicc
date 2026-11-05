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

STATUSES = ("pending", "accepted", "rejected", "withdrawn", "superseded", "stale")


def _hist(row, frm, to, by, note=None):
    """Append an audit entry to the amendment history (M30)."""
    h = json.loads(row.history) if row.history else []
    h.append({"at": datetime.now(timezone.utc).isoformat(), "from": frm, "to": to, "by": by, "note": note})
    row.history = json.dumps(h)


def stale_after_s() -> int:
    return max(60, int(os.getenv("CICC_AMENDMENT_STALE_S", str(7 * 86400))))


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
        same = (existing.title == title and existing.description == description
                and existing.proposed_by == proposed_by
                and json.loads(existing.affects or "[]") == (affects or []))
        if existing.status == "pending" and same:
            return to_dict(existing), True  # idempotent duplicate submission
        raise ValueError(f"amendment_id '{amendment_id}' already exists (status={existing.status})")
    row = models.CoordinationAmendment(
        amendment_id=amendment_id, title=title, description=description,
        affects=json.dumps(affects or []), compatibility=json.dumps(compatibility or {}),
        target_version=target_version, proposed_by=proposed_by, status="pending",
    )
    s.add(row)
    _hist(row, None, "pending", proposed_by, "proposed")
    s.flush()
    return to_dict(row), False


def to_dict(row: models.CoordinationAmendment) -> dict:
    return {
        "amendment_id": row.amendment_id, "title": row.title, "description": row.description,
        "affects": json.loads(row.affects) if row.affects else [],
        "compatibility": json.loads(row.compatibility) if row.compatibility else {},
        "target_version": row.target_version, "proposed_by": row.proposed_by,
        "status": row.status, "decided_by": row.decided_by, "decision_note": row.decision_note,
        "linked_refs": json.loads(row.linked_refs) if row.linked_refs else [],
        "history": json.loads(row.history) if row.history else [],
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


def validate_compatibility(affects: list, compatibility: dict, descriptor: dict) -> dict:
    """M30: compatibility validation against the live contract descriptor.
    Unknown affected keys are flagged; backward-incompatible proposals require
    an explicit approver note (recorded, never silent)."""
    known = set()
    for k, v in descriptor.items():
        if isinstance(v, dict):
            known.add(k)
            known.update(v.keys())
    unknown = [a for a in (affects or []) if a not in known and not any(a.startswith(p) for p in known)]
    return {
        "backward_compatible": bool(compatibility.get("backward_compatible", True)),
        "unknown_affected_keys": unknown,
        "consumers": "see GET /agents (registered coordination agents)",
        "ok": not unknown,
    }


def decide(s, amendment_id: str, decision: str, decided_by: str, note: str | None = None,
           linked_refs: list | None = None, supersedes: list | None = None,
           descriptor: dict | None = None) -> dict:
    """Guarded CAS on pending amendments — a concurrent/duplicate decision
    loses and gets 409, exactly like task approvals. Records audit history,
    flags self-approval, and can supersede other amendments atomically."""
    if decision not in ("accept", "reject"):
        return {"ok": False, "code": 422, "reason": "decision must be 'accept' or 'reject'"}
    if decided_by.lower() not in approvers():
        return {"ok": False, "code": 403, "reason": f"'{decided_by}' is not a configured approver"}
    row = s.execute(select(models.CoordinationAmendment).where(
        models.CoordinationAmendment.amendment_id == amendment_id)).scalar_one_or_none()
    if row is None:
        return {"ok": False, "code": 404, "reason": "amendment_not_found"}
    if row.status != "pending":
        return {"ok": False, "code": 409, "reason": f"amendment already {row.status}"}
    new_status = "accepted" if decision == "accept" else "rejected"
    # M30: backward-incompatible amendments require an explicit note
    compat = json.loads(row.compatibility) if row.compatibility else {}
    if not compat.get("backward_compatible", True) and not note:
        return {"ok": False, "code": 422,
                "reason": "backward-incompatible amendment requires an explicit decision note"}
    from sqlalchemy import update
    res = s.execute(
        update(models.CoordinationAmendment)
        .where(models.CoordinationAmendment.id == row.id)
        .where(models.CoordinationAmendment.status == "pending")
        .values(status=new_status, decided_by=decided_by, decision_note=note,
                linked_refs=json.dumps(linked_refs or []),
                decided_at=datetime.now(timezone.utc))
    )
    if res.rowcount != 1:
        return {"ok": False, "code": 409, "reason": "amendment already decided (concurrent)"}
    _hist(row, "pending", new_status, decided_by, note)
    superseded = []
    for sid in (supersedes or []):
        srow = s.execute(select(models.CoordinationAmendment).where(
            models.CoordinationAmendment.amendment_id == sid)).scalar_one_or_none()
        if srow and srow.status == "pending":
            srow.status = "superseded"
            srow.decided_by = decided_by
            srow.decided_at = datetime.now(timezone.utc)
            _hist(srow, "pending", "superseded", decided_by, f"superseded by {amendment_id}")
            superseded.append(sid)
    self_approved = (row.proposed_by or "").lower() == decided_by.lower()
    return {"ok": True, "amendment_id": amendment_id, "status": new_status, "decided_by": decided_by,
            "self_approved": self_approved, "superseded": superseded,
            "compatibility": validate_compatibility(
                json.loads(row.affects or "[]"), compat, descriptor or {})}


def withdraw(s, amendment_id: str, by: str) -> dict:
    """M30: proposer-only withdrawal of a still-pending amendment."""
    row = s.execute(select(models.CoordinationAmendment).where(
        models.CoordinationAmendment.amendment_id == amendment_id)).scalar_one_or_none()
    if row is None:
        return {"ok": False, "code": 404, "reason": "amendment_not_found"}
    if row.status != "pending":
        return {"ok": False, "code": 409, "reason": f"amendment already {row.status}"}
    if (row.proposed_by or "").lower() != (by or "").lower():
        return {"ok": False, "code": 403, "reason": "only the proposer may withdraw"}
    row.status = "withdrawn"
    row.decided_by = by
    row.decided_at = datetime.now(timezone.utc)
    _hist(row, "pending", "withdrawn", by)
    return {"ok": True, "amendment_id": amendment_id, "status": "withdrawn"}


def sweep_stale(s, now: datetime | None = None) -> list[str]:
    """M30: pending amendments older than CICC_AMENDMENT_STALE_S become stale."""
    now = now or datetime.now(timezone.utc)
    out = []
    for row in s.execute(select(models.CoordinationAmendment).where(
            models.CoordinationAmendment.status == "pending")).scalars().all():
        created = row.created_at
        if created and (now - created.replace(tzinfo=timezone.utc)).total_seconds() > stale_after_s():
            row.status = "stale"
            _hist(row, "pending", "stale", "sweep", f"pending > {stale_after_s()}s")
            out.append(row.amendment_id)
    return out


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
