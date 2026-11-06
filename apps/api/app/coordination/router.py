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
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from app import models, ops
from app.ratelimit import read_token_dependency, require_write_token, write_rate_limit_dependency
from . import agents as agent_registry, amendments, domains
from . import approvals, contract, github_sync, handoff, registry, routing, webhook

router = APIRouter(prefix="/api/v1/coordination", tags=["coordination"])


class RuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    match: dict
    agent: str = Field(min_length=1, max_length=64)
    priority: int = Field(default=100, ge=0, le=10000)
    enabled: bool = True


class ReportIn(BaseModel):
    result: str | None = Field(default=None, max_length=4000)
    provenance: dict | None = None  # M35: additive — domain outputs carry provenance (source, produced_at, ...)


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
    active_tasks: int | None = Field(default=None, ge=0, le=100000)
    meta: dict | None = None


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
        s.commit()  # persist event/task AND any replay-detection alert (M16)
    if not result.get("ok"):
        raise HTTPException(status_code=result["code"], detail=result["reason"])
    return result


# ---------------- events ----------------

@router.get("/contract")
def contract_descriptor(_gate: None = Depends(read_token_dependency)):
    """Machine-readable contract self-description (base v1.0, additive,
    read-only). M29: includes effective version + amendment registry summary."""
    with ops.SessionLocal() as s:
        desc = contract.contract_v1()
        desc["version"] = amendments.effective_version(s, desc.get("version", "1.0"))
        desc["amendments"] = {
            "base_version": "1.0",
            "effective_version": desc["version"],
            "statuses": list(amendments.STATUSES),
            **{st: amendments.list_amendments(s, st) for st in amendments.STATUSES},
        }
        return desc


class AmendmentIn(BaseModel):
    amendment_id: str
    title: str
    description: str
    proposed_by: str
    affects: list[str] = []
    compatibility: dict = {}
    target_version: str | None = None


class AmendmentDecisionIn(BaseModel):
    decision: str  # accept | reject
    decided_by: str
    note: str | None = None
    linked_refs: list[str] = []
    supersedes: list[str] = []  # M30: mark other pending amendments superseded


@router.post("/contract/amendments", status_code=201)
def propose_amendment(body: AmendmentIn, _gate: None = Depends(read_token_dependency),
                      authorization: str | None = Header(default=None)):
    """M29: propose a contract amendment (recorded, pending owner review)."""
    require_write_token(authorization)
    with ops.SessionLocal() as s:
        try:
            row, duplicate = amendments.propose(s, amendment_id=body.amendment_id, title=body.title,
                                     description=body.description, proposed_by=body.proposed_by,
                                     affects=body.affects, compatibility=body.compatibility,
                                     target_version=body.target_version)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
        s.commit()
        row["duplicate"] = duplicate  # M30: idempotent re-proposal of identical pending amendment
        return JSONResponse(status_code=200 if duplicate else 201, content=row)


@router.get("/contract/amendments")
def list_amendments_api(status: str | None = Query(None), _gate: None = Depends(read_token_dependency)):
    with ops.SessionLocal() as s:
        return {"amendments": amendments.list_amendments(s, status)}


@router.get("/contract/amendments/{amendment_id}")
def get_amendment_api(amendment_id: str, _gate: None = Depends(read_token_dependency)):
    with ops.SessionLocal() as s:
        row = amendments.get(s, amendment_id)
        if row is None:
            raise HTTPException(status_code=404, detail="amendment_not_found")
        return row


@router.post("/contract/amendments/{amendment_id}/decide")
def decide_amendment_api(amendment_id: str, body: AmendmentDecisionIn,
                         _gate: None = Depends(read_token_dependency),
                         authorization: str | None = Header(default=None)):
    """M29: accept/reject an amendment. Approver-only, guarded CAS (loser 409)."""
    require_write_token(authorization)
    with ops.SessionLocal() as s:
        r = amendments.decide(s, amendment_id, body.decision, body.decided_by,
                              body.note, body.linked_refs, body.supersedes,
                              descriptor=contract.contract_v1())
        s.commit()
    if not r.get("ok"):
        raise HTTPException(status_code=r["code"], detail=r["reason"])
    return r


@router.post("/contract/amendments/{amendment_id}/withdraw")
def withdraw_amendment_api(amendment_id: str, body: dict,
                           _gate: None = Depends(read_token_dependency),
                           authorization: str | None = Header(default=None)):
    """M30: proposer-only withdrawal of a pending amendment."""
    require_write_token(authorization)
    with ops.SessionLocal() as s:
        r = amendments.withdraw(s, amendment_id, body.get("by", ""))
        s.commit()
    if not r.get("ok"):
        raise HTTPException(status_code=r["code"], detail=r["reason"])
    return r


@router.post("/contract/amendments/{amendment_id}/refs")
def attach_amendment_refs(amendment_id: str, body: dict,
                          _gate: None = Depends(read_token_dependency),
                          authorization: str | None = Header(default=None)):
    """M29: attach implementation refs (commits/PRs) for traceability."""
    require_write_token(authorization)
    with ops.SessionLocal() as s:
        r = amendments.attach_refs(s, amendment_id, body.get("refs", []))
        s.commit()
    if not r.get("ok"):
        raise HTTPException(status_code=r["code"], detail=r["reason"])
    return r


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


def _load_persisted_stats(s) -> None:
    """M38: restore domain evidence from coord_domain_stats (restart persistence)."""
    rows = s.execute(select(models.CoordinationDomainStat)).scalars().all()
    domains.load_persisted_stats(list(rows))


def _persist_domain_stats(s) -> None:
    """M37/M38: mirror in-memory domain evidence into coord_domain_stats so health
    survives restarts. Sanitized fields only. Loads persisted rows first so a
    re-mount after a restart does not clobber older evidence with zeros."""
    _load_persisted_stats(s)
    for kind, st in domains.all_statuses().items():
        row = s.execute(select(models.CoordinationDomainStat).where(
            models.CoordinationDomainStat.kind == kind)).scalar_one_or_none()
        if row is None:
            row = models.CoordinationDomainStat(kind=kind)
            s.add(row)
        row.version = st["version"]
        row.source_ref = st["source_ref"]
        row.mounted_at = st["mounted_at"]
        row.validated = 1 if domains.is_mounted(kind) and st["status"] != domains.MOUNTED else 0
        row.invokes = st["invokes"]
        row.successes = st["successes"]
        row.consecutive_failures = st.get("consecutive_failures", 0)
        row.last_stale = 1 if st.get("last_stale") else 0
        row.last_invoke_at = st["last_invoke_at"]
        row.last_status = "ok" if st["status"] == domains.EXECUTION_VERIFIED else (
            None if st["invokes"] == 0 else "error")
        row.last_error = st["last_error"]


@router.get("/domains")
def list_domains(_gate: None = Depends(read_token_dependency)):
    """M35/M37: mounted domain handlers with evidence-based status (honest:
    empty list = no domain API mounted in this deployment)."""
    with ops.SessionLocal() as s:
        _load_persisted_stats(s)
        _persist_domain_stats(s)
        s.commit()
    return {"domains": domains.mounted_domains(), "statuses": domains.all_statuses(),
            "states": list(domains.STATES),
            "note": "empty list = no domain API mounted in this deployment; status is evidence-based (NOT_MOUNTED/MOUNTED/AVAILABLE/EXECUTION_VERIFIED/DEGRADED/FAILED/UNKNOWN)"}


@router.get("/domains/{kind}/status")
def domain_status(kind: str, _gate: None = Depends(read_token_dependency)):
    """M37: evidence-based lifecycle status for one domain + observable stats."""
    with ops.SessionLocal() as s:
        _load_persisted_stats(s)
        _persist_domain_stats(s)
        s.commit()
    st = domains.all_statuses().get(kind)
    if st is None:
        return {"kind": kind, "status": domains.NOT_MOUNTED,
                "evidence": {"invokes": 0, "successes": 0, "note": "no handler registered"}}
    return {"kind": kind, "status": st["status"], "evidence": st}


class MountIn(BaseModel):
    module_path: str = Field(min_length=1, max_length=512)
    attr: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=64)
    source_ref: str = Field(min_length=1, max_length=256)


@router.post("/domains/{kind}/mount", status_code=201)
def mount_domain(kind: str, body: MountIn,
                 _gate: None = Depends(read_token_dependency),
                 authorization: str | None = Header(default=None)):
    """M37: mount a domain handler READ-ONLY from a server-side module path
    (write-token only). Never modifies the domain package; a missing module is
    an honest 409 domain_not_mounted, not a fake mount."""
    require_write_token(authorization)
    try:
        entry = domains.load_handler_from_module(kind, body.module_path, body.attr,
                                                 version=body.version, source_ref=body.source_ref)
    except domains.DomainNotMounted as e:
        raise HTTPException(status_code=409, detail=str(e))
    except domains.DomainInvalid as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"domain_mount_failed ({type(e).__name__})")
    with ops.SessionLocal() as s:
        ops.record_event("info", "coordination.domains",
                         f"domain mounted kind={kind} version={body.version} by=api-write-token", s=s)
        _persist_domain_stats(s)
        s.commit()
    return {"kind": kind, "mounted": True, "status": domains.domain_status(kind), **entry}


@router.post("/domains/{kind}/deregister")
def deregister_domain(kind: str, _gate: None = Depends(read_token_dependency),
                      authorization: str | None = Header(default=None)):
    """M37: handler lifecycle — deregister (write-token only)."""
    require_write_token(authorization)
    removed = domains.unregister_domain(kind)
    with ops.SessionLocal() as s:
        ops.record_event("info", "coordination.domains",
                         f"domain deregistered kind={kind} removed={removed} by=api-write-token", s=s)
        _persist_domain_stats(s)
        s.commit()
    if not removed:
        raise HTTPException(status_code=409, detail=f"domain_not_mounted: {kind}")
    return {"kind": kind, "deregistered": True, "status": domains.NOT_MOUNTED}


@router.post("/domains/{kind}/invoke", status_code=201)
def invoke_domain(kind: str, body: dict, _gate: None = Depends(read_token_dependency),
                  authorization: str | None = Header(default=None)):
    """M35: coordination-side domain consumption. Creates a task of the domain
    kind, invokes the mounted handler (if any), and persists result +
    provenance + trace events. API write-token protected; the browser/BFF write
    path stays limited to POST /tasks (owner-approved route)."""
    require_write_token(authorization)
    payload = body.get("payload") if isinstance(body.get("payload"), dict) else {}
    idempotency_key = body.get("idempotency_key") or None
    task_id = body.get("task_id") or f"dom-{kind}-{uuid.uuid4().hex[:12]}"
    claimed_tenant = body.get("tenant_id")  # M42: recorded as CLAIMED metadata only; enforcement is owner-reserved
    with ops.SessionLocal() as s:
        pre = None
        if idempotency_key:
            from sqlalchemy import select as _sel
            pre = s.execute(_sel(models.CoordinationTask).where(
                models.CoordinationTask.idempotency_key == idempotency_key)).scalar_one_or_none()
        if pre is not None:
            s.commit()
            return JSONResponse(status_code=200, content={"task_id": pre.task_id, "duplicate": True,
                                                           "state": registry.normalize_state(pre.state)})
        t = registry.create_task(s, task_id=task_id, event_id=None, source="domain_gateway",
                                 kind=kind, repo=None, pr_ref=None, branch_ref=None,
                                 title=body.get("title") or f"domain invoke {kind}",
                                 payload=payload, idempotency_key=idempotency_key)
        if not getattr(t, "_created", True):
            # M35: lost the concurrent-create race — replay, never re-execute
            s.commit()
            return JSONResponse(status_code=200, content={"task_id": t.task_id, "duplicate": True,
                                                           "state": registry.normalize_state(t.state)})
        if not domains.is_mounted(kind):
            registry.record_event(s, task_id, "domain_not_mounted", f"kind={kind}")
            s.commit()
            raise HTTPException(status_code=409, detail=f"domain_not_mounted: {kind}")
        try:
            out = domains.invoke(kind, payload, task=t)  # M37: per-attempt timeout + retries, same idempotency key
        except domains.DomainError as e:
            domains.record_outcome(kind, False, str(e))
            registry.record_event(s, task_id, "domain_error", str(e))
            _persist_domain_stats(s)
            s.commit()
            raise HTTPException(status_code=502, detail=str(e))
        except domains.DomainInvalid as e:
            domains.record_outcome(kind, False, str(e))
            registry.record_event(s, task_id, "domain_invalid", str(e))
            _persist_domain_stats(s)
            s.commit()
            raise HTTPException(status_code=422, detail=str(e))
        freshness = domains.analyze_freshness(out["provenance"])  # M42: basis + clock skew
        stale = freshness["stale"]
        domains.record_outcome(kind, True, stale=stale)
        ops.record_event("info", "coordination.domains",
                         f"domain invoke ok kind={kind} task={task_id} stale={stale} by=api-write-token", s=s)
        if claimed_tenant is not None:
            registry.record_event(s, task_id, "claimed_tenant", f"tenant_id={claimed_tenant} (unverified claim)")
        if stale:
            registry.record_event(s, task_id, "domain_stale",
                                  f"basis={freshness['basis']} age_s={freshness['age_s']} "
                                  f"skew_s={freshness['clock_skew_s']} limit={domains.stale_after_s()}s")
        if freshness["clock_skew_s"] > 0:
            registry.record_event(s, task_id, "domain_clock_skew",
                                  f"produced_at in future by {freshness['clock_skew_s']:.1f}s")
        # persist the real domain result with provenance (incl. confidence/freshness if the domain provides them)
        t.result = json.dumps({"result": out["result"], "provenance": out["provenance"], "stale": stale})
        registry.record_event(s, task_id, "domain_result",
                              f"source={out['provenance'].get('source')} produced_at={out['provenance'].get('produced_at')}")
        # M37 fix: walk the legal state chain (QUEUED->ASSIGNED->DELIVERING->
        # ACKNOWLEDGED->RUNNING->COMPLETED); the M35 code jumped QUEUED->COMPLETED,
        # which the state machine rejects (silent no-op left state=QUEUED while
        # the response claimed COMPLETED)
        for st in ("QUEUED", "ASSIGNED", "DELIVERING", "ACKNOWLEDGED", "RUNNING", "COMPLETED"):
            assert registry.transition(s, t, st, "domain gateway"), f"illegal transition to {st}"
        _persist_domain_stats(s)
        s.commit()
        return {"task_id": task_id, "kind": kind, "state": registry.normalize_state(t.state),
                "result": out["result"], "provenance": out["provenance"], "stale": stale,
                "freshness": freshness,
                "idempotency_key": t.idempotency_key}


@router.get("/diagnostics")
def coordination_diagnostics(_gate: None = Depends(read_token_dependency)):
    """M42: operational diagnostics (read-only, no secrets): DB connectivity,
    uptime, app version, mounted domains + evidence-based statuses."""
    from sqlalchemy import text as _text
    db_ok = False
    with ops.SessionLocal() as s:
        try:
            s.execute(_text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        _load_persisted_stats(s)
        _persist_domain_stats(s)
        s.commit()
    from app.main import __version__, _STARTED_TS
    import time as _time
    return {
        "status": "ok" if db_ok else "degraded",
        "db_ok": db_ok,
        "version": __version__,
        "uptime_s": round(_time.time() - _STARTED_TS, 1),
        "mounted_domains": domains.mounted_domains(),
        "domain_statuses": domains.all_statuses(),
        "stale_after_s": domains.stale_after_s(),
        "note": "diagnostics expose no credentials, tokens, or internal error details",
    }


@router.get("/health")
def coordination_health(_gate: None = Depends(read_token_dependency)):
    """M28/M37: actionable health with explicit statuses + reasons (read-only).
    Adds a `domains` component with evidence-based per-domain lifecycle status
    (never healthy merely because a package exists)."""
    with ops.SessionLocal() as s:
        h = registry.health(s)
        _load_persisted_stats(s)
        _persist_domain_stats(s)
        s.commit()
    st = domains.all_statuses()
    if st:
        worst = domains.EXECUTION_VERIFIED
        order = [domains.FAILED, domains.DEGRADED, domains.UNKNOWN, domains.MOUNTED,
                 domains.AVAILABLE, domains.EXECUTION_VERIFIED, domains.NOT_MOUNTED]
        present = [st[k]["status"] for k in st]
        worst = min(present, key=lambda x: order.index(x)) if present else domains.NOT_MOUNTED
        comp_status = "healthy" if worst in (domains.EXECUTION_VERIFIED, domains.AVAILABLE, domains.NOT_MOUNTED) else "degraded"
        h["components"].append({
            "key": "domains", "status": comp_status,
            "detail": f"{len(st)} mounted, worst={worst}; evidence-based states only",
            "domains": st})
    else:
        h["components"].append({
            "key": "domains", "status": "healthy",
            "detail": "no domain handlers mounted (NOT_MOUNTED for all kinds)",
            "domains": {}})
    return h


@router.get("/tasks/{task_id}/trace")
def get_task_trace(task_id: str, _gate: None = Depends(read_token_dependency)):
    """M28: full correlation trace (ids, events, deliveries, approval)."""
    with ops.SessionLocal() as s:
        tr = registry.trace(s, task_id)
        if tr is None:
            raise HTTPException(status_code=404, detail="task_not_found")
        return tr


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
        cur = registry.normalize_state(t.state)
        if cur in ("RETRYING", "BLOCKED"):
            # auto dead-letter policy may already have moved FAILED -> RETRYING/BLOCKED;
            # both allow a direct transition back to QUEUED
            ok = registry.transition(s, t, "QUEUED", "re-queued")
        else:
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
        recovered = registry.recover_abandoned(s)  # M28: delivery-lease recovery
        requeued = registry.requeue_ready(s)
        expired_approvals = approvals.sweep_expired(s)
        stale_agents = agent_registry.sweep_stale(s)
        stale_amendments = amendments.sweep_stale(s)  # M30: stale pending amendments
        s.commit()
        return {"expired_tasks": expired_tasks, "requeued": requeued, "recovered_abandoned": recovered,
                "expired_approvals": expired_approvals, "stale_agents": stale_agents,
                "stale_amendments": stale_amendments}


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
        r = agent_registry.heartbeat(s, agent, body.status, body.active_tasks, body.meta)
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
