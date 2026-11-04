"""Pydantic response schemas for the operations API."""
from typing import Optional

from pydantic import BaseModel


class ComponentInfo(BaseModel):
    key: str
    kind: str
    name: str
    status: str
    detail: str
    last_check_at: Optional[str] = None


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


class ComponentListResponse(BaseModel):
    services: list[ComponentInfo]
    modules: list[ComponentInfo]


class ActivityListResponse(BaseModel):
    events: list[ActivityEvent]


class DatabaseCheck(BaseModel):
    status: str
    detail: str
    latency_ms: Optional[float] = None


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    started_at: str
    uptime_seconds: float
    checks: dict
