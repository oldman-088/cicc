"""Agent registry & lifecycle (M7): registration, heartbeat, status,
deregistration, stale detection, workload + performance stats.

Boundary: a registered agent with fresh heartbeats is a LIVE WORKER, not an
active Arena session. Arena session control is never claimed here.
"""
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from app import models
from . import registry

AGENT_STATUSES = ("available", "busy", "draining", "offline")
STALE_AFTER_S = 300  # env-overridable via CICC_AGENT_STALE_S


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _stale_s() -> int:
    import os

    try:
        return int(os.getenv("CICC_AGENT_STALE_S", str(STALE_AFTER_S)))
    except ValueError:
        return STALE_AFTER_S


def register(s, agent: str, specialization: str | None = None, capabilities: list | None = None,
             version: str | None = None, meta: dict | None = None) -> dict:
    row = s.get(models.CoordinationAgent, agent)
    created = row is None
    if row is None:
        row = models.CoordinationAgent(agent=agent)
        s.add(row)
    if specialization:
        row.specialization = specialization
    if capabilities is not None:
        row.capabilities = json.dumps(capabilities)
    if version:
        row.version = version
    if meta is not None:
        row.meta = json.dumps(meta)
    row.status = "available"
    row.last_heartbeat = _utcnow()
    s.flush()
    return {"agent": agent, "created": created, "status": row.status}


def heartbeat(s, agent: str, status: str | None = None, active_tasks: int | None = None,
              meta: dict | None = None) -> dict | None:
    row = s.get(models.CoordinationAgent, agent)
    if row is None:
        return None
    row.last_heartbeat = _utcnow()
    if status in AGENT_STATUSES:
        row.status = status
    # M22: honor the documented heartbeat fields (INTEGRATION_CONTRACTS.md #2);
    # persist them inside the free-form meta JSON — no schema change
    if active_tasks is not None or meta is not None:
        try:
            m = json.loads(row.meta) if row.meta else {}
        except Exception:
            m = {}
        hb = m.get("heartbeat") if isinstance(m.get("heartbeat"), dict) else {}
        if active_tasks is not None:
            hb["active_tasks"] = active_tasks
        if meta is not None:
            hb["meta"] = meta
        m["heartbeat"] = hb
        row.meta = json.dumps(m)
    s.flush()
    return {"agent": agent, "status": row.status, "last_heartbeat": row.last_heartbeat.isoformat()}


def deregister(s, agent: str) -> bool:
    row = s.get(models.CoordinationAgent, agent)
    if row is None:
        return False
    row.status = "offline"
    row.last_heartbeat = _utcnow()
    s.flush()
    return True


def is_stale(row: models.CoordinationAgent, now: datetime | None = None) -> bool:
    if not row.last_heartbeat:
        return True
    now = now or _utcnow()
    hb = row.last_heartbeat if row.last_heartbeat.tzinfo else row.last_heartbeat.replace(tzinfo=timezone.utc)
    return (now - hb).total_seconds() > _stale_s()


def list_agents(s) -> list[dict]:
    out = []
    for row in s.execute(select(models.CoordinationAgent).order_by(models.CoordinationAgent.agent)).scalars().all():
        stats = registry.task_stats_by_agent(s, row.agent)
        stale = is_stale(row)
        effective = "offline" if stale else row.status
        out.append({
            "agent": row.agent,
            "specialization": row.specialization,
            "capabilities": json.loads(row.capabilities) if row.capabilities else [],
            "status": effective,
            "stale": stale,
            "version": row.version,
            "meta": json.loads(row.meta) if row.meta else {},
            "last_heartbeat": row.last_heartbeat.isoformat() if row.last_heartbeat else None,
            "registered_at": row.registered_at.isoformat() if row.registered_at else None,
            **stats,
        })
    return out


def sweep_stale(s) -> list[str]:
    """Mark agents with stale heartbeats offline. Returns affected agents."""
    now = _utcnow()
    out = []
    for row in s.execute(select(models.CoordinationAgent)).scalars().all():
        if is_stale(row, now) and row.status != "offline":
            row.status = "offline"
            out.append(row.agent)
    if out:
        s.flush()
    return out


def available_agents(s, required_capabilities: list | None = None) -> list[dict]:
    """Agents eligible for routing: not stale, not offline/draining, and (if
    required) holding all required capabilities."""
    agents = list_agents(s)
    req = set(required_capabilities or [])
    out = []
    for a in agents:
        if a["status"] in ("offline", "draining"):
            continue
        caps = set(a["capabilities"])
        if req and not req.issubset(caps):
            continue
        out.append(a)
    return out
