"""Pydantic request/response schemas for the operations API."""
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field


class ComponentInfo(BaseModel):
    key: str
    kind: str
    name: str
    status: str
    detail: str
    last_check_at: Optional[str] = None
    check: Optional[dict] = None


class Metrics(BaseModel):
    entities: int
    vulnerabilities: int
    campaigns: int
    recent_updates_24h: int
    last_successful_sync: Optional[str] = None


class ActivityEvent(BaseModel):
    id: int
    ts: Optional[str] = None
    level: str
    source: str
    message: str


class OverviewResponse(BaseModel):
    generated_at: str
    overall_status: str
    services: list[ComponentInfo]
    modules: list[ComponentInfo]
    metrics: Metrics
    activity: list[ActivityEvent]
    data_source: str
    cached: Optional[bool] = None
    cache_age_s: Optional[float] = None


class ComponentListResponse(BaseModel):
    services: list[ComponentInfo]
    modules: list[ComponentInfo]


class ActivityListResponse(BaseModel):
    events: list[ActivityEvent]


class MetricSnapshotItem(BaseModel):
    ts: Optional[str] = None
    entities: int
    vulnerabilities: int
    campaigns: int
    recent_updates_24h: int


class HistoryResponse(BaseModel):
    window_hours: int
    snapshots: list[MetricSnapshotItem]


class DependencyEdge(BaseModel):
    from_: str = Field(alias="from")
    to: str
    label: str

    model_config = {"populate_by_name": True}


class DependencyResponse(BaseModel):
    nodes: list[ComponentInfo]
    edges: list[DependencyEdge]


class TaskStatsResponse(BaseModel):
    window_hours: int
    completed: int
    failed: int
    pending: int
    avg_duration_ms: Optional[float] = None
    oldest_pending_started: Optional[str] = None


class TaskRunIn(BaseModel):
    """Contract for worker-reported task runs (POST /api/v1/ops/tasks).

    Records task execution only; it is not evidence of Arena session
    control by RabbitMQ.
    """

    worker: str = Field(min_length=1, max_length=128)
    queue: str = Field(min_length=1, max_length=128)
    status: Literal["running", "success", "failed"]
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration_ms: Optional[int] = Field(default=None, ge=0)
    error: Optional[str] = Field(default=None, max_length=500)


class TaskRunCreated(BaseModel):
    id: int


class WorkerHeartbeatIn(BaseModel):
    """Contract for worker heartbeats (POST /api/v1/ops/workers/heartbeat).

    Records local worker process liveness only — never Arena session activity.
    """

    worker: str = Field(min_length=1, max_length=128)
    details: Optional[str] = Field(default=None, max_length=500)


class WorkerHeartbeatCreated(BaseModel):
    worker: str
    created: bool


class WorkerInfo(BaseModel):
    worker: str
    last_seen: Optional[str] = None
    age_s: Optional[float] = None
    stalled: bool
    tasks_24h: int
    failed_24h: int
    details: str = ""


class WorkersResponse(BaseModel):
    stall_threshold_s: float
    workers: list[WorkerInfo]


class AlertItem(BaseModel):
    id: int
    rule: str
    component_key: Optional[str] = None
    severity: str
    status: str
    message: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    resolved_at: Optional[str] = None
    acked_at: Optional[str] = None
    acked_by: Optional[str] = None
    occurrences: int


class AlertsResponse(BaseModel):
    alerts: list[AlertItem]


class AckIn(BaseModel):
    acked_by: Optional[str] = Field(default=None, max_length=128)


class AlertActionResponse(BaseModel):
    id: int
    status: str


class BrokerSnapshotItem(BaseModel):
    ts: Optional[str] = None
    messages_ready: Optional[int] = None
    messages_unacknowledged: Optional[int] = None
    queues: Optional[int] = None
    consumers: Optional[int] = None
    dead_letter_queues: Optional[int] = None


class BrokerHistoryResponse(BaseModel):
    window_hours: int
    snapshots: list[BrokerSnapshotItem]


class SystemResponse(BaseModel):
    process: dict
    python: str
    database: str


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    started_at: str
    uptime_seconds: float
    checks: dict
