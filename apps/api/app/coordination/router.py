"""Coordination HTTP API (mounted under /api/v1/coordination).

- POST /webhook/github — signed GitHub webhook ingestion (fail-closed).
- GET  /events — ingested GitHub events (provenance preserved).
- GET  /tasks?state&agent — durable task registry.
- GET  /tasks/{task_id}/events — audit history of one task.
- POST /tasks/{task_id}/route — run the routing engine (assign agent).
- POST /tasks/{task_id}/deliver — RabbitMQ publish (real broker only) or
  copy-ready human-assisted handoff payload.
- POST /tasks/{task_id}/ack|complete|fail — agent reporting.
- GET  /rules, POST /rules — routing rules (write-gated).

Reads honor CICC_OPS_READ_TOKEN when set; writes honor CICC_OPS_WRITE_TOKEN
(write token also satisfies read). All under the ops rate limiter.
"""
import json
import os

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from app import models, ops
from app.ratelimit import read_token_dependency, require_write_token, write_rate_limit_dependency
from . import handoff, registry, routing, webhook

# NOTE: the GitHub webhook endpoint is intentionally NOT behind the read-token
# gate — it authenticates via X-Hub-Signature-256 HMAC (fail-closed when the
# secret is unset). All other endpoints carry the read gate explicitly.
router = APIRouter(prefix="/api/v1/coordination", tags=["coordination"])


class RuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    match: dict
    agent: str = Field(min_length=1, max_length=64)
    priority: int = Field(default=100, ge=0, le=10000)
    enabled: bool = True


class ReportIn(BaseModel):
    result: str | None = Field(default=None, max_length=4000)


@router.post("/webhook/github")
async def github_webhook(
    request: Request,
    x_github_event: str | None = Header(default=None),
    x_github_delivery: str | None = Header(default=None),
    x_hub_signature_256: str | None = Header(default=None),
):
    """Signed GitHub webhook. Fail-closed when CICC_GH_WEBHOOK_SECRET is unset."""
    body = await request.body()
    if not x_github_delivery:
        raise HTTPException(status_code=400, detail="missing X-GitHub-Delivery")
    secret = os.getenv("CICC_GH_WEBHOOK_SECRET")
    with ops.SessionLocal() as s:
        result = webhook.ingest(s, x_github_delivery, x_github_event or "unknown", body,
                                x_hub_signature_256, secret)
    if not result.get("ok"):
        raise HTTPException(status_code=result["code"], detail=result["reason"])
    return result


@router.get("/events")
def list_events(_gate: None = Depends(read_token_dependency), limit: int = Query(100, ge=1, le=500)):
    with ops.SessionLocal() as s:
        rows = s.execute(
            select(models.GitHubEvent).order_by(models.GitHubEvent.received_at.desc()).limit(limit)
        ).scalars().all()
        return {"events": [
            {"delivery_id": r.delivery_id, "event": r.event, "action": r.action,
             "repo": r.repo, "sender": r.sender,
             "received_at": r.received_at.isoformat() if r.received_at else None}
            for r in rows
        ]}


@router.get("/tasks")
def list_tasks(_gate: None = Depends(read_token_dependency), state: str | None = Query(None),
               agent: str | None = Query(None), limit: int = Query(100, ge=1, le=500)):
    with ops.SessionLocal() as s:
        return {"tasks": registry.list_tasks(s, state, agent, limit)}


@router.get("/tasks/{task_id}/events")
def get_task_events(task_id: str, _gate: None = Depends(read_token_dependency), limit: int = Query(200, ge=1, le=1000)):
    with ops.SessionLocal() as s:
        return {"task_id": task_id, "events": registry.task_events(s, task_id, limit)}


def _get_task(s, task_id: str):
    t = s.execute(
        select(models.CoordinationTask).where(models.CoordinationTask.task_id == task_id)
    ).scalar_one_or_none()
    if t is None:
        raise HTTPException(status_code=404, detail="task_not_found")
    return t


@router.post("/tasks/{task_id}/route")
def route_task(task_id: str, _gate: None = Depends(read_token_dependency), authorization: str | None = Header(default=None)):
    require_write_token(authorization)
    with ops.SessionLocal() as s:
        t = _get_task(s, task_id)
        agent = routing.route(s, t)
        t.agent = agent
        if agent:
            registry.transition(s, t, "QUEUED", f"routed to {agent}")
        else:
            registry.transition(s, t, "BLOCKED", "no routing rule matched; needs owner assignment")
        s.commit()
        return {"task_id": task_id, "agent": agent, "state": t.state}


@router.post("/tasks/{task_id}/deliver")
def deliver_task(task_id: str, request: Request, _gate: None = Depends(read_token_dependency), authorization: str | None = Header(default=None)):
    require_write_token(authorization)
    write_rate_limit_dependency(request, authorization)
    with ops.SessionLocal() as s:
        t = _get_task(s, task_id)
        if t.state == "NEW":
            t.agent = routing.route(s, t)
            registry.transition(s, t, "QUEUED", "auto-routed before delivery")
        res = handoff.deliver(s, t)
        s.commit()
        return {"task_id": task_id, "state": t.state, **res}


@router.post("/tasks/{task_id}/ack")
def ack_task(task_id: str, _gate: None = Depends(read_token_dependency), authorization: str | None = Header(default=None)):
    require_write_token(authorization)
    with ops.SessionLocal() as s:
        r = handoff.report(s, task_id, "ack")
        if r is None:
            raise HTTPException(status_code=404, detail="task_not_found")
        return r


@router.post("/tasks/{task_id}/complete")
def complete_task(task_id: str, _gate: None = Depends(read_token_dependency), body: ReportIn | None = None, authorization: str | None = Header(default=None)):
    require_write_token(authorization)
    with ops.SessionLocal() as s:
        r = handoff.report(s, task_id, "complete", body.result if body else None)
        if r is None:
            raise HTTPException(status_code=404, detail="task_not_found")
        return r


@router.post("/tasks/{task_id}/fail")
def fail_task(task_id: str, _gate: None = Depends(read_token_dependency), body: ReportIn | None = None, authorization: str | None = Header(default=None)):
    require_write_token(authorization)
    with ops.SessionLocal() as s:
        r = handoff.report(s, task_id, "fail", body.result if body else None)
        if r is None:
            raise HTTPException(status_code=404, detail="task_not_found")
        return r


@router.get("/rules")
def list_rules(_gate: None = Depends(read_token_dependency)):
    with ops.SessionLocal() as s:
        rows = s.execute(select(models.RoutingRule).order_by(models.RoutingRule.priority.asc())).scalars().all()
        return {"rules": [{"id": r.id, "name": r.name, "priority": r.priority, "match": r.match,
                           "agent": r.agent, "enabled": r.enabled} for r in rows]}


@router.post("/rules", status_code=201)
def add_rule(body: RuleIn, request: Request, _gate: None = Depends(read_token_dependency), authorization: str | None = Header(default=None)):
    require_write_token(authorization)
    write_rate_limit_dependency(request, authorization)
    with ops.SessionLocal() as s:
        exists = s.execute(select(models.RoutingRule).where(models.RoutingRule.name == body.name)).scalar_one_or_none()
        if exists:
            raise HTTPException(status_code=409, detail="rule name exists")
        r = models.RoutingRule(priority=body.priority, name=body.name,
                               match=json.dumps(body.match), agent=body.agent, enabled=body.enabled)
        s.add(r)
        s.commit()
        return {"id": r.id, "name": r.name, "agent": r.agent, "enabled": r.enabled}
