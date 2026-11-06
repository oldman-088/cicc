"""Pydantic request/response schemas for the operations API."""
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field, model_validator


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
    tasks_per_min: Optional[float] = None  # processing rate (M6)
    duration_p50_ms: Optional[int] = None
    duration_p95_ms: Optional[int] = None
    duration_max_ms: Optional[int] = None
    retry_rate: Optional[float] = None  # M7: failed-with-retries / failed


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
    attempts: int = Field(default=1, ge=1, le=100)  # retry count (M6)


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
    details: str
    registered: bool = False
    version: Optional[str] = None
    capabilities: list[str] = []
    registered_at: Optional[str] = None


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
    escalated: bool = False
    flapping: bool = False
    owner: Optional[str] = None


class AlertsResponse(BaseModel):
    alerts: list[AlertItem]


class AckIn(BaseModel):
    acked_by: Optional[str] = Field(default=None, max_length=128)
    owner: Optional[str] = Field(default=None, max_length=128)


class AssignIn(BaseModel):
    owner: str = Field(min_length=1, max_length=128)


class AlertActionResponse(BaseModel):
    id: int
    status: str


    owner: Optional[str] = None


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


# ---------- milestone 4: maintenance windows, task history, worker history ----------

class MaintenanceWindowIn(BaseModel):
    label: str = Field(min_length=1, max_length=128)
    starts_at: datetime
    ends_at: datetime
    component_keys: Optional[list[str]] = Field(default=None, max_length=32)
    rule: Optional[str] = Field(default=None, max_length=64)
    created_by: Optional[str] = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def _ends_after_starts(self):
        if self.ends_at <= self.starts_at:
            raise ValueError("ends_at must be after starts_at")
        return self


class MaintenanceWindowItem(BaseModel):
    id: int
    label: str
    starts_at: Optional[str] = None
    ends_at: Optional[str] = None
    component_keys: list[str] = []
    rule: Optional[str] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None


class MaintenanceListResponse(BaseModel):
    windows: list[MaintenanceWindowItem]


class MaintenanceCreated(BaseModel):
    id: int


class MaintenanceCancelled(BaseModel):
    id: int
    ends_at: Optional[str] = None


class TaskRunItem(BaseModel):
    id: int
    worker: str
    queue: str
    status: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_ms: Optional[int] = None
    error: Optional[str] = None
    attempts: int = 1
    created_at: Optional[str] = None


class TaskListResponse(BaseModel):
    tasks: list[TaskRunItem]


class TaskFailureGroup(BaseModel):
    worker: str
    error: str
    count: int
    last_seen: Optional[str] = None


class TaskFailuresResponse(BaseModel):
    window_hours: int
    groups: list[TaskFailureGroup]


class WorkerHistorySample(BaseModel):
    worker: str
    ts: Optional[str] = None


class WorkerHistoryResponse(BaseModel):
    window_hours: int
    worker: Optional[str] = None
    sample_interval_s: int
    samples: list[WorkerHistorySample]


class WorkerRegisterIn(BaseModel):
    """Worker self-registration contract (POST /api/v1/ops/workers/register)."""

    worker: str = Field(min_length=1, max_length=128)
    queue: str = Field(default="default", max_length=128)
    version: Optional[str] = Field(default=None, max_length=64)
    capabilities: Optional[list[str]] = Field(default=None, max_length=32)


class WorkerRegistered(BaseModel):
    worker: str
    created: bool
