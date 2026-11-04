"""Operations endpoints: overview, components, metrics, activity."""
from fastapi import APIRouter, Query

from app import ops
from app.schemas import (
    ActivityListResponse,
    ComponentListResponse,
    Metrics,
    OverviewResponse,
)

router = APIRouter(prefix="/api/v1/ops", tags=["operations"])


@router.get("/overview", response_model=OverviewResponse)
def get_overview():
    """Full operational overview: services, modules, metrics, recent activity."""
    return ops.build_overview()


@router.get("/components", response_model=ComponentListResponse)
def get_components():
    """Component registry with truthful statuses."""
    return ops.build_components()


@router.get("/metrics", response_model=Metrics)
def get_metrics():
    """Real counters from the operations database (never synthetic)."""
    return ops.build_metrics()


@router.get("/activity", response_model=ActivityListResponse)
def get_activity(limit: int = Query(50, ge=1, le=200)):
    """Recent real system events, newest first."""
    return {"events": ops.build_activity(limit)}
