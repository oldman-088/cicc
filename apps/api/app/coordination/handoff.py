"""Agent handoff: delivery via RabbitMQ when a broker is configured (real
AMQP publish to a per-agent queue), otherwise a copy-ready human-assisted
handoff payload. RabbitMQ distributes tasks; it does NOT launch or control
Arena sessions — that boundary is stated in every handoff payload.

Also: ack / complete / fail reporting back into the registry.
"""
import json
import os

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
        "instructions": (
            f"Agent {task.agent}: handle {task.kind} in {task.repo}"
            + (f" (PR #{task.pr_ref})" if task.pr_ref else "")
            + ". Work on your OWN feature branch; never push to main; open/keep your PR; "
              "report completion via POST /api/v1/coordination/tasks/{task_id}/complete."
        ),
        "event": payload,
        "boundary": "RabbitMQ/local workers distribute tasks; they do NOT control Arena sessions.",
    }


def deliver(s, task: models.CoordinationTask) -> dict:
    """Mark QUEUED -> DELIVERED. Publishes to RabbitMQ ONLY when
    RABBITMQ_AMQP_URL is configured (real broker); otherwise produces the
    copy-ready handoff payload and marks QUEUED (human-assisted)."""
    handoff = build_handoff(task)
    task.handoff = json.dumps(handoff)
    url = os.getenv("RABBITMQ_AMQP_URL")
    if url and task.agent:
        try:
            import pika

            params = pika.URLParameters(url)
            params.socket_timeout = 5
            conn = pika.BlockingConnection(params)
            ch = conn.channel()
            q = f"cicc.agent.{task.agent}"
            ch.queue_declare(queue=q, durable=True)
            ch.basic_publish(
                exchange="", routing_key=q,
                body=json.dumps(handoff).encode(),
                properties=pika.BasicProperties(delivery_mode=2, content_type="application/json"),
            )
            conn.close()
            registry.transition(s, task, "DELIVERED", "published to RabbitMQ queue " + q)
            return {"delivered": True, "via": "rabbitmq", "queue": q}
        except Exception as e:  # noqa: BLE001 - fall back to human-assisted
            registry.record_event(s, task.task_id, "delivery_failed", f"{type(e).__name__}: {e}")
            registry.transition(s, task, "RETRYING", "broker publish failed; human-assisted handoff")
            return {"delivered": False, "via": "human_assisted", "error": type(e).__name__}
    registry.transition(s, task, "QUEUED", "copy-ready handoff payload (no broker configured)")
    return {"delivered": False, "via": "human_assisted", "handoff": handoff}


def report(s, task_id: str, action: str, result: str | None = None) -> dict | None:
    """Ack / start / complete / fail reporting from agents."""
    t = s.execute(
        select(models.CoordinationTask).where(models.CoordinationTask.task_id == task_id)
    ).scalar_one_or_none()
    if t is None:
        return None
    mapping = {
        "ack": ("DELIVERED", "IN_PROGRESS", "agent acknowledged"),
        "complete": ("IN_PROGRESS", "COMPLETED", "agent reported completion"),
        "fail": ("IN_PROGRESS", "FAILED", "agent reported failure"),
    }
    if action not in mapping:
        return None
    _from, to, msg = mapping[action]
    if t.state == _from:
        registry.transition(s, t, to, result or msg)
    else:
        registry.record_event(s, t.task_id, f"report:{action}", f"ignored in state {t.state}: {msg}")
    if action == "fail" and t.state != "FAILED":
        registry.transition(s, t, "FAILED", result or msg)
    if result:
        t.result = result
    s.commit()
    return {"task_id": t.task_id, "state": t.state, "attempts": t.attempts}
