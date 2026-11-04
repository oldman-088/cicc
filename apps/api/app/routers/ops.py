"""Operations endpoints: overview, components, metrics (+history),
activity, dependencies, task stats and worker task-run ingestion."""
import os

from fastapi import APIRouter, Depends, Header, HTTPException, Query

from app import ops
from app.ratelimit import rate_limit_dependency
from app.schemas import (
    ActivityListResponse,
    ComponentListResponse,
    DependencyResponse,
    HistoryResponse,
    Metrics,
    OverviewResponse,
    TaskRunCreated,
    TaskRunIn,
    TaskStatsResponse,
)

router = APIRouter(
    prefix="/api/v1/ops",
    tags=["operations"],
    dependencies=[Depends(rate_limit_dependency)],
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
def post_task_run(
    payload: TaskRunIn,
    authorization: str | None = Header(default=None),
):
    """Record a worker-reported task run.

    If CICC_OPS_WRITE_TOKEN is configured, a matching
    `Authorization: Bearer <token>` header is required. Without the env
    var the endpoint is open — intended for trusted internal networks
    only; production deployments must set the token (see
    docs/MONITORING_CONTRACTS.md).
    """
    token = ops.write_token_required()
    if token:
        expected = f"Bearer {token}"
        if authorization != expected:
            raise HTTPException(status_code=401, detail="invalid or missing write token")
    run_id = ops.record_task_run(payload.model_dump())
    ops.record_event("info", "ops", f"task run reported: worker={payload.worker} queue={payload.queue} status={payload.status}")
    return {"id": run_id}
