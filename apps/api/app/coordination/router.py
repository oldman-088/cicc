"""Coordination HTTP API v2 (M7), mounted under /api/v1/coordination.

Webhook:   POST /webhook/github (HMAC only — GitHub sends no ops read token)
Events:    GET  /events
Tasks:     GET  /tasks?state&agent   GET /tasks/{id}   GET /tasks/{id}/events
           POST /tasks/{id}/route    POST /tasks/{id}/deliver
           POST /tasks/{id}/ack|start|complete|fail
           POST /tasks/{id}/cancel   POST /tasks/{id}/retry
           GET  /tasks/{id}/deliveries   GET /tasks/{id}/approval
           POST /tasks/{id}/approve|reject  (approver-gated)
           POST /sweep                (timeouts/expired approvals/stale agents)
Agents:    GET  /agents   POST /agents/register   POST /agents/{agent}/heartbeat
           POST /agents/{agent}/deregister
Rules:     GET  /rules    POST /rules

Reads honor CICC_OPS_READ_TOKEN when set; writes honor CICC_OPS_WRITE_TOKEN
(write also satisfies read). Webhook is the only endpoint without the read gate.
"""
import json
import os

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from app import models, ops
from app.ratelimit import read_token_dependency, require_write_token, write_rate_limit_dependency
from . import agents as agent_registry
from . import approvals, github_sync, handoff, registry, routing, webhook

router = APIRouter(prefix="/api/v1/coordination", tags=["coordination"])


class RuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    match: dict
    agent: str = Field(min_length=1, max_length=64)
    priority: int = Field(default=100, ge=0, le=10000)
    enabled: bool = True


class ReportIn(BaseModel):
    result: str | None = Field(default=None, max_length=4000)


class TaskIn(BaseModel):
    task_id: str | None = Field(default=None, max_length=200, pattern=r"^[A-Za-z0-9_.:-]+$")
    idempotency_key: str | None = Field(default=None, max_length=300)
    kind: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_]+$")
    priority: int = Field(default=5, ge=1, le=10)
    title: str | None = Field(default=None, max_length=500)
    payload: dict = Field(default_factory=dict)
    repo: str | None = Field(default=None, max_length=200)
    pr_ref: str | None = Field(default=None, max_length=100)
    branch_ref: str | None = Field(default=None, max_length=200)
    owner: str | None = Field(default=None, max_length=200)
    depends_on: list[str] | None = None
    timeout_s: int | None = Field(default=None, ge=1, le=86400 * 30)
    ttl_s: int | None = Field(default=None, ge=1, le=86400 * 365)
    requires_approval: bool = False


class ProgressIn(BaseModel):
    percent: int = Field(ge=0, le=100)
    note: str | None = Field(default=None, max_length=2000)


class DecisionIn(BaseModel):
    decided_by: str = Field(min_length=1, max_length=128)
    note: str | None = Field(default=None, max_length=2000)


class AgentRegisterIn(BaseModel):
    agent: str = Field(min_length=1, max_length=64)
    specialization: str | None = Field(default=None, max_length=128)
    capabilities: list[str] | None = Field(default=None, max_length=64)
    version: str | None = Field(default=None, max_length=64)
    meta: dict | None = None


class AgentHeartbeatIn(BaseModel):
    status: str | None = Field(default=None, pattern="^(available|busy|draining|offline)$")


def _get_task(s, task_id: str):
    t = s.execute(
        select(models.CoordinationTask).where(models.CoordinationTask.task_id == task_id)
    ).scalar_one_or_none()
    if t is None:
        raise HTTPException(status_code=404, detail="task_not_found")
    return t


# ---------------- webhook (signature-only auth) ----------------

@router.post("/webhook/github")
async def github_webhook(
    request: Request,
    x_github_event: str | None = Header(default=None),
    x_github_delivery: str | None = Header(default=None),
    x_hub_signature_256: str | None = Header(default=None),
):
    body = await request.body()
    if not x_github_delivery:
        raise HTTPException(status_code=400, detail="missing X-GitHub-Delivery")
    secrets = webhook.webhook_secrets()
    with ops.SessionLocal() as s:
        result = webhook.ingest(s, x_github_delivery, x_github_event or "unknown", body,
                                x_hub_signature_256, secrets)
    if not result.get("ok"):
        raise HTTPException(status_code=result["code"], detail=result["reason"])
    return result


# ---------------- events ----------------

@router.get("/events")
def list_events(_gate: None = Depends(read_token_dependency), limit: int = Query(100, ge=1, le=500)):
    with ops.SessionLocal() as s:
        rows = s.execute(
            select(models.GitHubEvent).order_by(models.GitHubEvent.received_at.desc()).limit(limit)
        ).scalars().all()
        task_by_event = {t.event_id: t.task_id for t in s.execute(select(models.CoordinationTask)).scalars()}
        return {"events": [
            {"delivery_id": r.delivery_id, "event": r.event, "action": r.action,
             "repo": r.repo, "sender": r.sender, "task_id": task_by_event.get(r.delivery_id),
             "received_at": r.received_at.isoformat() if r.received_at else None}
            for r in rows
        ]}


# ---------------- tasks ----------------

@router.post("/tasks", status_code=201)
def create_task_api(body: TaskIn, request: Request, _gate: None = Depends(read_token_dependency),
                    authorization: str | None = Header(default=None)):
    """Programmatic task creation (integration contract for Agents 2/3/4).
    Idempotent on task_id and idempotency_key. Write-token + rate limited."""
    require_write_token(authorization)
    write_rate_limit_dependency(request, authorization)
    import uuid as _uuid
    task_id = body.task_id or ("api-" + _uuid.uuid4().hex[:12])
    with ops.SessionLocal() as s:
        existing = None
        if body.idempotency_key:
            from sqlalchemy import select as _sel
            existing = s.execute(_sel(models.CoordinationTask).where(
                models.CoordinationTask.idempotency_key == body.idempotency_key)).scalar_one_or_none()
        t = registry.create_task(
            s, task_id=task_id, event_id=None, source="api", kind=body.kind,
            repo=body.repo, pr_ref=body.pr_ref, branch_ref=body.branch_ref,
            title=body.title, payload=body.payload, priority=body.priority,
            owner=body.owner, depends_on=body.depends_on, timeout_s=body.timeout_s,
            ttl_s=body.ttl_s, idempotency_key=body.idempotency_key,
            requires_approval=body.requires_approval)
        s.commit()
        return {"task_id": t.task_id, "state": registry.normalize_state(t.state), "kind": t.kind,
                "duplicate": existing is not None and existing.task_id != task_id}


@router.get("/metrics")
def coordination_metrics(_gate: None = Depends(read_token_dependency)):
    with ops.SessionLocal() as s:
        return registry.metrics(s)


@router.get("/tasks")
def list_tasks(_gate: None = Depends(read_token_dependency), state: str | None = Query(None),
               agent: str | None = Query(None), kind: str | None = Query(None),
               dead_letter: bool | None = Query(None),
               limit: int = Query(100, ge=1, le=500)):
    with ops.SessionLocal() as s:
        return {"tasks": registry.list_tasks(s, state, agent, kind, limit, dead_letter)}


@router.get("/tasks/dag")
def get_dag(_gate: None = Depends(read_token_dependency), limit: int = Query(500, ge=1, le=2000)):
    with ops.SessionLocal() as s:
        return registry.dag(s, limit)


@router.get("/tasks/{task_id}")
def get_task(task_id: str, _gate: None = Depends(read_token_dependency)):
    with ops.SessionLocal() as s:
        _get_task(s, task_id)
        rows = [t for t in registry.list_tasks(s, limit=10000) if t["task_id"] == task_id]
        return rows[0]


@router.get("/tasks/{task_id}/events")
def get_task_events(task_id: str, _gate: None = Depends(read_token_dependency), limit: int = Query(200, ge=1, le=1000)):
    with ops.SessionLocal() as s:
        _get_task(s, task_id)
        return {"task_id": task_id, "events": registry.task_events(s, task_id, limit)}


@router.get("/tasks/{task_id}/deliveries")
def get_task_deliveries(task_id: str, _gate: None = Depends(read_token_dependency), limit: int = Query(100, ge=1, le=500)):
    with ops.SessionLocal() as s:
        _get_task(s, task_id)
        return {"task_id": task_id, "deliveries": handoff.deliveries(s, task_id, limit)}


@router.get("/tasks/{task_id}/approval")
def get_task_approval(task_id: str, _gate: None = Depends(read_token_dependency)):
    with ops.SessionLocal() as s:
        _get_task(s, task_id)
        ap = approvals.task_approval(s, task_id)
        return {"task_id": task_id, "approval": ap}


@router.post("/tasks/{task_id}/route")
def route_task(task_id: str, request: Request, _gate: None = Depends(read_token_dependency), authorization: str | None = Header(default=None)):
    require_write_token(authorization)
    write_rate_limit_dependency(request, authorization)
    with ops.SessionLocal() as s:
        t = _get_task(s, task_id)
        res = routing.route(s, t)
        t.agent = res["agent"]
        t.routing_explanation = json.dumps(res["explanation"])
        if res["agent"]:
            registry.transition(s, t, "QUEUED", f"routed to {res['agent']}: {res['explanation'].get('via')}")
        else:
            registry.transition(s, t, "BLOCKED", "no routing decision: " + "; ".join(res["explanation"]["reasons"]))
        s.commit()
        return {"task_id": task_id, "agent": res["agent"], "state": registry.normalize_state(t.state),
                "explanation": res["explanation"]}


@router.post("/tasks/{task_id}/deliver")
def deliver_task(task_id: str, request: Request, _gate: None = Depends(read_token_dependency),
                 authorization: str | None = Header(default=None)):
    require_write_token(authorization)
    write_rate_limit_dependency(request, authorization)
    with ops.SessionLocal() as s:
        t = _get_task(s, task_id)
        if registry.normalize_state(t.state) == "CREATED":
            res = routing.route(s, t)
            t.agent = res["agent"]
            t.routing_explanation = json.dumps(res["explanation"])
            registry.transition(s, t, "QUEUED", "auto-routed before delivery")
        if registry.normalize_state(t.state) == "WAITING_FOR_APPROVAL":
            raise HTTPException(status_code=409, detail="task is WAITING_FOR_APPROVAL; not deliverable")
        res = handoff.deliver(s, t)
        s.commit()
        if res.get("delivered") is False and res.get("reason") == "dependencies not completed":
            raise HTTPException(status_code=409, detail=res["reason"])
        # note: delivered=False with via=human_assisted is the HONEST no-broker
        # path (payload prepared, not delivered) -> returned 200, not an error
        return {"task_id": task_id, "state": registry.normalize_state(t.state), **res}


@router.post("/tasks/{task_id}/ack")
def ack_task(task_id: str, request: Request, _gate: None = Depends(read_token_dependency), authorization: str | None = Header(default=None)):
    require_write_token(authorization)
    write_rate_limit_dependency(request, authorization)
    with ops.SessionLocal() as s:
        r = handoff.report(s, task_id, "ack")
        if r is None:
            raise HTTPException(status_code=404, detail="task_not_found")
        if not r.get("applied", True):
            s.commit()
            raise HTTPException(status_code=409, detail=f"report:ack ignored in state {r['state']}")
        return r


@router.post("/tasks/{task_id}/start")
def start_task(task_id: str, request: Request, _gate: None = Depends(read_token_dependency), authorization: str | None = Header(default=None)):
    require_write_token(authorization)
    write_rate_limit_dependency(request, authorization)
    with ops.SessionLocal() as s:
        r = handoff.report(s, task_id, "start")
        if r is None:
            raise HTTPException(status_code=404, detail="task_not_found")
        if not r.get("applied", True):
            s.commit()
            raise HTTPException(status_code=409, detail=f"report:start ignored in state {r['state']}")
        return r


@router.post("/tasks/{task_id}/complete")
def complete_task(task_id: str, _gate: None = Depends(read_token_dependency), body: ReportIn | None = None,
                  authorization: str | None = Header(default=None)):
    require_write_token(authorization)
    with ops.SessionLocal() as s:
        r = handoff.report(s, task_id, "complete", body.result if body else None)
        if r is None:
            raise HTTPException(status_code=404, detail="task_not_found")
        if not r.get("applied", True):
            s.commit()
            raise HTTPException(status_code=409, detail=f"report:complete ignored in state {r['state']}")
        return r


@router.post("/tasks/{task_id}/fail")
def fail_task(task_id: str, _gate: None = Depends(read_token_dependency), body: ReportIn | None = None,
              authorization: str | None = Header(default=None)):
    require_write_token(authorization)
    with ops.SessionLocal() as s:
        r = handoff.report(s, task_id, "fail", body.result if body else None)
        if r is None:
            raise HTTPException(status_code=404, detail="task_not_found")
        return r  # fail is allowed from any active state; dead-letter policy applies


@router.post("/tasks/{task_id}/cancel")
def cancel_task(task_id: str, request: Request, _gate: None = Depends(read_token_dependency), authorization: str | None = Header(default=None)):
    require_write_token(authorization)
    write_rate_limit_dependency(request, authorization)
    with ops.SessionLocal() as s:
        t = _get_task(s, task_id)
        ok = registry.transition(s, t, "CANCELLED", "cancelled by operator")
        s.commit()
        if not ok:
            raise HTTPException(status_code=409, detail=f"cannot cancel from state {t.state}")
        return {"task_id": task_id, "state": "CANCELLED"}


@router.post("/tasks/{task_id}/retry")
def retry_task(task_id: str, request: Request, _gate: None = Depends(read_token_dependency), authorization: str | None = Header(default=None)):
    require_write_token(authorization)
    write_rate_limit_dependency(request, authorization)
    with ops.SessionLocal() as s:
        t = _get_task(s, task_id)
        ok = registry.transition(s, t, "RETRYING", "manual retry") and registry.transition(s, t, "QUEUED", "re-queued")
        s.commit()
        if not ok:
            raise HTTPException(status_code=409, detail=f"cannot retry from state {t.state}")
        return {"task_id": task_id, "state": "QUEUED", "attempts": t.attempts}


@router.post("/tasks/{task_id}/approve")
def approve_task(task_id: str, body: DecisionIn, request: Request, _gate: None = Depends(read_token_dependency),
                 authorization: str | None = Header(default=None)):
    require_write_token(authorization)
    write_rate_limit_dependency(request, authorization)
    with ops.SessionLocal() as s:
        r = approvals.decide(s, task_id, "approve", body.decided_by)
        s.commit()
    if r is None:
        raise HTTPException(status_code=404, detail="task_not_found")
    if not r.get("ok"):
        raise HTTPException(status_code=r["code"], detail=r["reason"])
    return r


@router.post("/tasks/{task_id}/reject")
def reject_task(task_id: str, body: DecisionIn, request: Request, _gate: None = Depends(read_token_dependency),
                authorization: str | None = Header(default=None)):
    require_write_token(authorization)
    write_rate_limit_dependency(request, authorization)
    with ops.SessionLocal() as s:
        r = approvals.decide(s, task_id, "reject", body.decided_by)
        s.commit()
    if r is None:
        raise HTTPException(status_code=404, detail="task_not_found")
    if not r.get("ok"):
        raise HTTPException(status_code=r["code"], detail=r["reason"])
    return r


@router.post("/sweep")
def sweep(_gate: None = Depends(read_token_dependency), authorization: str | None = Header(default=None)):
    """Periodic maintenance: expire tasks/approvals, mark stale agents."""
    require_write_token(authorization)
    with ops.SessionLocal() as s:
        expired_tasks = registry.sweep_timeouts(s)
        requeued = registry.requeue_ready(s)
        expired_approvals = approvals.sweep_expired(s)
        stale_agents = agent_registry.sweep_stale(s)
        s.commit()
        return {"expired_tasks": expired_tasks, "requeued": requeued,
                "expired_approvals": expired_approvals, "stale_agents": stale_agents}


# ---------------- agents ----------------

@router.get("/agents")
def list_agents(_gate: None = Depends(read_token_dependency)):
    with ops.SessionLocal() as s:
        return {"agents": agent_registry.list_agents(s)}


@router.post("/agents/register", status_code=201)
def register_agent(body: AgentRegisterIn, request: Request, _gate: None = Depends(read_token_dependency),
                   authorization: str | None = Header(default=None)):
    require_write_token(authorization)
    write_rate_limit_dependency(request, authorization)
    with ops.SessionLocal() as s:
        r = agent_registry.register(s, body.agent, body.specialization, body.capabilities, body.version, body.meta)
        s.commit()
        return r


@router.post("/agents/{agent}/heartbeat")
def agent_heartbeat(agent: str, body: AgentHeartbeatIn, request: Request,
                    _gate: None = Depends(read_token_dependency), authorization: str | None = Header(default=None)):
    require_write_token(authorization)
    write_rate_limit_dependency(request, authorization)
    with ops.SessionLocal() as s:
        r = agent_registry.heartbeat(s, agent, body.status)
        s.commit()
        if r is None:
            raise HTTPException(status_code=404, detail="agent_not_registered")
        return r


@router.post("/agents/{agent}/deregister")
def deregister_agent(agent: str, request: Request, _gate: None = Depends(read_token_dependency), authorization: str | None = Header(default=None)):
    require_write_token(authorization)
    write_rate_limit_dependency(request, authorization)
    with ops.SessionLocal() as s:
        ok = agent_registry.deregister(s, agent)
        s.commit()
        if not ok:
            raise HTTPException(status_code=404, detail="agent_not_registered")
        return {"agent": agent, "status": "offline"}


# ---------------- rules ----------------

@router.get("/rules")
def list_rules(_gate: None = Depends(read_token_dependency)):
    with ops.SessionLocal() as s:
        rows = s.execute(select(models.RoutingRule).order_by(models.RoutingRule.priority.asc())).scalars().all()
        return {"rules": [{"id": r.id, "name": r.name, "priority": r.priority, "match": r.match,
                           "agent": r.agent, "enabled": r.enabled} for r in rows]}


@router.post("/rules", status_code=201)
def add_rule(body: RuleIn, request: Request, _gate: None = Depends(read_token_dependency),
             authorization: str | None = Header(default=None)):
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


# ---------------- progress, DAG, live GitHub sync (M8) ----------------

@router.post("/tasks/{task_id}/progress")
def report_progress(task_id: str, body: ProgressIn, request: Request, _gate: None = Depends(read_token_dependency),
                    authorization: str | None = Header(default=None)):
    require_write_token(authorization)
    write_rate_limit_dependency(request, authorization)
    with ops.SessionLocal() as s:
        r = registry.progress(s, task_id, body.percent, body.note)
        s.commit()
        if r is None:
            raise HTTPException(status_code=404, detail="task_not_found")
        return r


@router.get("/github/status")
def github_status(_gate: None = Depends(read_token_dependency)):
    """LIVE probe of api.github.com (real call, circuit-breaker guarded)."""
    with ops.SessionLocal() as s:
        return github_sync.fetch_repo_status(s)


@router.post("/github/sync")
def github_sync_run(_gate: None = Depends(read_token_dependency), authorization: str | None = Header(default=None)):
    """REAL GitHub API sync: polls repo PRs/issues/check-runs and creates
    coordination tasks (CI failures on arena branches, open PRs)."""
    require_write_token(authorization)
    with ops.SessionLocal() as s:
        return github_sync.sync(s)
