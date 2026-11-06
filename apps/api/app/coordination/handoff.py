"""Delivery & handoff v2 (M7): delivery records, publisher confirms,
idempotent message ids, dependency gating, dead-letter on repeated failure.

Rules:
- A task is never reported "delivered" merely because a message was prepared:
  with a real broker we require a publisher confirm (or at least a successful
  publish call) and record it; without a broker the delivery record says
  channel=human_assisted, status=published (payload prepared), and the task
  stays QUEUED — a human must hand it off.
- RabbitMQ distributes tasks; it does NOT launch/control Arena sessions.
- depends_on gate: a task whose dependencies are not all COMPLETED cannot be
  delivered (transition attempt is rejected + audited).
"""
import json
import os
import uuid

from sqlalchemy import select

from app import models
from . import registry


def build_handoff(task: models.CoordinationTask) -> dict:
    payload = {}
    try:
        payload = json.loads(task.payload) if task.payload else {}
    except Exception:
        payload = {}
    return {
        "task_id": task.task_id,
        "agent": task.agent,
        "kind": task.kind,
        "repo": task.repo,
        "pr_ref": task.pr_ref,
        "branch_ref": task.branch_ref,
        "title": task.title,
        "priority": task.priority,
        "instructions": (
            f"Agent {task.agent}: handle {task.kind} in {task.repo}"
            + (f" (PR #{task.pr_ref})" if task.pr_ref else "")
            + ". Work on your OWN feature branch; never push to main; keep your PR open; "
              f"report via POST /api/v1/coordination/tasks/{task.task_id}/complete."
        ),
        "event": payload,
        "boundary": "RabbitMQ/local workers distribute tasks; they do NOT control Arena sessions.",
    }


def _record_delivery(s, task_id: str, channel: str, queue: str | None, message_id: str | None,
                     status: str, attempt: int, error: str | None = None) -> models.CoordinationDelivery:
    d = models.CoordinationDelivery(task_id=task_id, channel=channel, queue=queue,
                                    message_id=message_id, status=status, attempt=attempt, error=error)
    s.add(d)
    s.flush()
    registry.record_event(s, task_id, f"delivery:{status}", f"channel={channel} queue={queue} attempt={attempt}" + (f" error={error}" if error else ""))
    return d


def deliver(s, task: models.CoordinationTask) -> dict:
    """Deliver a task to its assigned agent. Dependency gate first."""
    if not registry.deps_ready(s, task):
        registry.record_event(s, task.task_id, "delivery_blocked_deps", "depends_on not all COMPLETED")
        return {"delivered": False, "via": None, "reason": "dependencies not completed"}
    handoff = build_handoff(task)
    task.handoff = json.dumps(handoff)
    message_id = task.idempotency_key or f"{task.task_id}:{task.attempts + 1}:{uuid.uuid4().hex[:8]}"
    url = os.getenv("RABBITMQ_AMQP_URL")
    if url and task.agent:
        q = f"cicc.agent.{task.agent}"
        try:
            import pika

            params = pika.URLParameters(url)
            params.socket_timeout = 5
            conn = pika.BlockingConnection(params)
            ch = conn.channel()
            ch.queue_declare(queue=q, durable=True)
            ch.confirm_delivery()  # publisher confirms ON
            props = pika.BasicProperties(
                delivery_mode=2, content_type="application/json",
                message_id=message_id, type="cicc-coord-task",
                headers={"x-cicc-task-id": task.task_id, "x-cicc-agent": task.agent},
            )
            ch.basic_publish(exchange="", routing_key=q, body=json.dumps(handoff).encode(), properties=props)
            conn.close()
            d = _record_delivery(s, task.task_id, "rabbitmq", q, message_id, "confirmed", (task.attempts or 0) + 1)
            d.confirmed_at = registry.utcnow()
            registry.transition(s, task, "DELIVERING", f"publisher-confirmed to {q} msg={message_id}")
            return {"delivered": True, "via": "rabbitmq", "queue": q, "message_id": message_id,
                    "confirmed": True, "state": task.state}
        except Exception as e:  # noqa: BLE001 - real failure recorded, fallback
            _record_delivery(s, task.task_id, "rabbitmq", q, message_id, "failed", (task.attempts or 0) + 1,
                             f"{type(e).__name__}: {e}")
            registry.transition(s, task, "RETRYING", f"broker publish failed ({type(e).__name__}); human-assisted fallback")
            d = _record_delivery(s, task.task_id, "human_assisted", None, message_id, "published", (task.attempts or 0) + 1)
            return {"delivered": False, "via": "human_assisted", "handoff": handoff,
                    "state": task.state, "error": type(e).__name__}
    # no broker: prepare copy-ready payload, record honestly, stay QUEUED
    _record_delivery(s, task.task_id, "human_assisted", None, message_id, "published", (task.attempts or 0) + 1)
    # M28: re-assert QUEUED only from QUEUED/BLOCKED (historic no-broker paths);
    # QUEUED is also a lease-recovery target, so deliver() on e.g. ACKNOWLEDGED
    # must not silently re-queue an already-acked task
    if registry.normalize_state(task.state) in ("QUEUED", "BLOCKED"):
        registry.transition(s, task, "QUEUED", "copy-ready handoff payload prepared (no broker configured)")
    return {"delivered": False, "via": "human_assisted", "handoff": handoff, "state": task.state,
            "note": "message prepared, NOT delivered — human/operator handoff required"}


def dead_letter(s, task: models.CoordinationTask, reason: str) -> bool:
    """Move a FAILED task to dead-letter after max attempts (default 3)."""
    max_attempts = int(os.getenv("CICC_COORD_MAX_ATTEMPTS", "3"))
    if (task.attempts or 0) < max_attempts:
        registry.transition(s, task, "RETRYING", f"attempt {task.attempts} failed: {reason}")
        return False
    task.dead_letter = True
    registry.transition(s, task, "BLOCKED", f"dead-lettered after {task.attempts} attempts: {reason}")
    registry.record_event(s, task.task_id, "dead_letter", reason)
    return True


def deliveries(s, task_id: str, limit: int = 100) -> list[dict]:
    rows = s.execute(
        select(models.CoordinationDelivery).where(models.CoordinationDelivery.task_id == task_id)
        .order_by(models.CoordinationDelivery.at.desc()).limit(limit)
    ).scalars().all()
    return [{
        "id": d.id, "task_id": d.task_id, "channel": d.channel, "queue": d.queue,
        "message_id": d.message_id, "status": d.status, "attempt": d.attempt, "error": d.error,
        "at": d.at.isoformat() if d.at else None,
        "confirmed_at": d.confirmed_at.isoformat() if d.confirmed_at else None,
    } for d in rows]


def report(s, task_id: str, action: str, result: str | None = None) -> dict | None:
    """Agent reporting: ack (DELIVERING/ASSIGNED -> ACKNOWLEDGED), start
    (ACKNOWLEDGED -> RUNNING), complete (RUNNING -> COMPLETED), fail
    (any active -> FAILED + dead-letter policy)."""
    t = s.execute(
        select(models.CoordinationTask).where(models.CoordinationTask.task_id == task_id)
    ).scalar_one_or_none()
    if t is None:
        return None
    cur = registry.normalize_state(t.state)
    mapping = {
        "ack": ("ACKNOWLEDGED", {"ASSIGNED", "DELIVERING", "QUEUED"}),
        "start": ("RUNNING", {"ACKNOWLEDGED", "DELIVERING"}),
        "complete": ("COMPLETED", {"RUNNING", "ACKNOWLEDGED"}),
        "fail": ("FAILED", {"RUNNING", "ACKNOWLEDGED", "DELIVERING", "ASSIGNED", "QUEUED"}),
    }
    if action not in mapping:
        return None
    to, from_states = mapping[action]
    applied = cur in from_states
    # M24 P0-6: transition() is a guarded compare-and-set; its return value is
    # authoritative — a concurrent loser must not report applied=True
    if applied and action == "complete" and not registry.deps_ready(s, t):
        # M19 defect fix: dependency gate applies to completion, not only delivery
        registry.record_event(s, task_id, "report:complete_blocked_deps", "depends_on not all COMPLETED")
        s.commit()
        return {"task_id": t.task_id, "state": registry.normalize_state(t.state), "attempts": t.attempts,
                "dead_letter": bool(t.dead_letter), "applied": False}
    if applied:
        applied = registry.transition(s, t, to, result or action)  # authoritative
    if not applied:
        registry.record_event(s, task_id, f"report:{action}", f"ignored in state {cur}")
    if action == "fail" and applied:
        # M28 fix: dead-letter policy only when the fail was actually applied;
        # a rejected duplicate fail must not record a second dead_letter event
        dead_letter(s, t, result or "reported failure")
    if result:
        t.result = result
    s.commit()
    return {"task_id": t.task_id, "state": registry.normalize_state(t.state), "attempts": t.attempts,
            "dead_letter": bool(t.dead_letter), "applied": applied}
