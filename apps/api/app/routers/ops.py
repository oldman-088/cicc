"""Operations endpoints: overview, components, metrics (+history),
activity, dependencies, tasks, workers, alerts, broker history, system."""
from fastapi import APIRouter, Depends, Header, HTTPException, Query

from app import ops
from app.ratelimit import rate_limit_dependency, read_token_dependency, require_write_token
from app.schemas import (
    ActivityListResponse,
    AckIn,
    AlertActionResponse,
    AlertsResponse,
    BrokerHistoryResponse,
    ComponentListResponse,
    DependencyResponse,
    HistoryResponse,
    MaintenanceCancelled,
    MaintenanceCreated,
    MaintenanceListResponse,
    MaintenanceWindowIn,
    Metrics,
    OverviewResponse,
    SystemResponse,
    TaskFailuresResponse,
    TaskListResponse,
    TaskRunCreated,
    TaskRunIn,
    TaskStatsResponse,
    WorkerHeartbeatCreated,
    WorkerHeartbeatIn,
    WorkerHistoryResponse,
    WorkersResponse,
)

router = APIRouter(
    prefix="/api/v1/ops",
    tags=["operations"],
    dependencies=[Depends(rate_limit_dependency), Depends(read_token_dependency)],
)


@router.get("/overview", response_model=OverviewResponse)
def get_overview():
    """Full operational overview (short-TTL cached). Failure of any single
    monitored component degrades only that component, never this endpoint."""
    return ops.build_overview_cached()


@router.get("/components", response_model=ComponentListResponse)
def get_components():
    """Component registry with live, truthful statuses."""
    return ops.build_components()


@router.get("/metrics", response_model=Metrics)
def get_metrics():
    """Real counters from the operations database (never synthetic)."""
    return ops.build_metrics()


@router.get("/metrics/history", response_model=HistoryResponse)
def get_metrics_history(hours: int = Query(24, ge=1, le=168)):
    """Historical real metric snapshots for trend visualization."""
    return {"window_hours": hours, "snapshots": ops.build_history(hours)}


@router.get("/activity", response_model=ActivityListResponse)
def get_activity(limit: int = Query(50, ge=1, le=200)):
    """Recent real system events, newest first."""
    return {"events": ops.build_activity(limit)}


@router.get("/dependencies", response_model=DependencyResponse)
def get_dependencies():
    """Service dependency graph with live node statuses."""
    data = ops.build_dependencies()
    edges = [{"from": e["from"], "to": e["to"], "label": e["label"]} for e in data["edges"]]
    return {"nodes": data["nodes"], "edges": edges}


@router.get("/tasks/stats", response_model=TaskStatsResponse)
def get_task_stats(hours: int = Query(24, ge=1, le=168)):
    """Aggregated stats over REAL worker-reported task runs."""
    return ops.build_task_stats(hours)


@router.post("/tasks", response_model=TaskRunCreated, status_code=201)
def post_task_run(payload: TaskRunIn, authorization: str | None = Header(default=None)):
    """Record a worker-reported task run (token-gated when CICC_OPS_WRITE_TOKEN
    is set; otherwise trusted-network/dev only — see contracts doc)."""
    require_write_token(authorization)
    run_id = ops.record_task_run(payload.model_dump())
    ops.record_event("info", "ops", f"task run reported: worker={payload.worker} queue={payload.queue} status={payload.status}")
    return {"id": run_id}


@router.get("/workers", response_model=WorkersResponse)
def get_workers():
    """Worker liveness from REAL heartbeats + per-worker task stats."""
    return ops.build_workers()


@router.post("/workers/heartbeat", response_model=WorkerHeartbeatCreated, status_code=201)
def post_heartbeat(payload: WorkerHeartbeatIn, authorization: str | None = Header(default=None)):
    """Record a worker heartbeat (local worker liveness only)."""
    require_write_token(authorization)
    created = ops.post_heartbeat(payload.worker, payload.details or "")
    return {"worker": payload.worker, "created": created}


@router.get("/alerts", response_model=AlertsResponse)
def get_alerts(
    state: str = Query("active", pattern="^(active|acknowledged|resolved|all)$"),
    limit: int = Query(100, ge=1, le=500),
):
    """Operational alerts derived from real checks. Evaluates rules first."""
    ops.evaluate_alerts()
    return {"alerts": ops.build_alerts(state, limit)}


@router.post("/alerts/{alert_id}/ack", response_model=AlertActionResponse)
def ack_alert(alert_id: int, body: AckIn):
    res = ops.ack_alert(alert_id, body.acked_by)
    if res is None:
        raise HTTPException(status_code=404, detail="alert_not_found")
    if res == "conflict":
        raise HTTPException(status_code=409, detail="alert_already_resolved")
    return res


@router.post("/alerts/{alert_id}/resolve", response_model=AlertActionResponse)
def resolve_alert(alert_id: int):
    res = ops.resolve_alert(alert_id)
    if res is None:
        raise HTTPException(status_code=404, detail="alert_not_found")
    if res == "conflict":
        raise HTTPException(status_code=409, detail="alert_already_resolved")
    return res


@router.get("/broker/history", response_model=BrokerHistoryResponse)
def get_broker_history(hours: int = Query(24, ge=1, le=168)):
    """Real RabbitMQ broker-total snapshots (only recorded when the broker
    check actually succeeded)."""
    return {"window_hours": hours, "snapshots": ops.build_broker_history(hours)}


@router.get("/system", response_model=SystemResponse)
def get_system():
    """REAL process-level resource metrics of this API process."""
    return ops.build_system()


# ---------- milestone 4 endpoints ----------

@router.get("/tasks", response_model=TaskListResponse)
def list_tasks(
    worker: str | None = Query(None, max_length=128),
    queue: str | None = Query(None, max_length=128),
    status: str | None = Query(None, pattern="^(running|success|failed)$"),
    limit: int = Query(100, ge=1, le=500),
):
    """Real task-run history with filters (worker/queue/status)."""
    return {"tasks": ops.build_task_list(worker, queue, status, limit)}


@router.get("/tasks/failures", response_model=TaskFailuresResponse)
def task_failures(hours: int = Query(24, ge=1, le=168), limit: int = Query(20, ge=1, le=100)):
    """Repeated-failure analytics: failed runs grouped by (worker, error)."""
    return ops.build_task_failures(hours, limit)


@router.get("/workers/history", response_model=WorkerHistoryResponse)
def worker_history(worker: str | None = Query(None, max_length=128), hours: int = Query(24, ge=1, le=168)):
    """Worker availability history from real throttled heartbeat samples."""
    return ops.build_worker_history(worker, hours)


@router.get("/maintenance", response_model=MaintenanceListResponse)
def list_maintenance(active: bool = Query(False)):
    """Maintenance windows (active ones suppress matching alerts)."""
    return {"windows": ops.list_windows(active_only=active)}


@router.post("/maintenance", response_model=MaintenanceCreated, status_code=201)
def create_maintenance(payload: MaintenanceWindowIn, authorization: str | None = Header(default=None)):
    require_write_token(authorization)
    wid = ops.create_window(
        payload.label,
        payload.starts_at,
        payload.ends_at,
        payload.component_keys,
        payload.rule,
        payload.created_by,
    )
    return {"id": wid}


@router.post("/maintenance/{window_id}/cancel", response_model=MaintenanceCancelled)
def cancel_maintenance(window_id: int, authorization: str | None = Header(default=None)):
    require_write_token(authorization)
    res = ops.cancel_window(window_id)
    if res is None:
        raise HTTPException(status_code=404, detail="window_not_found")
    if res == "conflict":
        raise HTTPException(status_code=409, detail="window_already_ended")
    return res
