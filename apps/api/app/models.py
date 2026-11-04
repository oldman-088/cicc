"""Operational database models.

These tables hold the platform's *own* operational state (component
registry, real events, real counters, real task runs, real metric
snapshots). Intelligence tables (entities, vulnerabilities, campaigns,
sync attempts) stay empty until a real, authorized ingestion source
writes to them. No synthetic rows are seeded.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Text

from app.db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Component(Base):
    """A registered platform component (service or module)."""

    __tablename__ = "components"

    id = Column(Integer, primary_key=True)
    key = Column(String(64), unique=True, nullable=False, index=True)
    kind = Column(String(32), nullable=False)  # "service" | "module"
    name = Column(String(128), nullable=False)
    # ok | degraded | down | not_implemented | not_configured | unknown
    status = Column(String(32), nullable=False)
    detail = Column(Text, default="")
    last_check_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Event(Base):
    """A real system event recorded by the platform itself."""

    __tablename__ = "events"

    id = Column(Integer, primary_key=True)
    ts = Column(DateTime(timezone=True), default=utcnow, index=True)
    level = Column(String(16), nullable=False)  # info | warning | error
    source = Column(String(64), nullable=False)
    message = Column(Text, nullable=False)


class Entity(Base):
    """Generic registered intelligence entity (written by real ingestion only)."""

    __tablename__ = "entities"

    id = Column(Integer, primary_key=True)
    kind = Column(String(64), nullable=False)
    title = Column(String(256), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class Vulnerability(Base):
    """Vulnerability records. Never seeded with fabricated CVEs."""

    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True)
    cve_id = Column(String(32), unique=True, nullable=False)
    summary = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=utcnow)


class Campaign(Base):
    """Tracked campaigns (written by real ingestion only)."""

    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True)
    name = Column(String(256), nullable=False)
    status = Column(String(32), default="active")
    created_at = Column(DateTime(timezone=True), default=utcnow)


class SyncAttempt(Base):
    """Real synchronization attempts against intelligence sources."""

    __tablename__ = "sync_attempts"

    id = Column(Integer, primary_key=True)
    source = Column(String(64), nullable=False)
    started_at = Column(DateTime(timezone=True), default=utcnow)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(32), nullable=False)  # running | success | failed
    records = Column(Integer, default=0)


class TaskRun(Base):
    """A real background task execution, reported by a worker via
    POST /api/v1/ops/tasks (see docs/MONITORING_CONTRACTS.md).

    This records *task execution* only. It does NOT prove that any Arena
    agent session is being controlled by RabbitMQ — that integration is
    not implemented or verified.
    """

    __tablename__ = "task_runs"

    id = Column(Integer, primary_key=True)
    worker = Column(String(128), nullable=False)
    queue = Column(String(128), nullable=False, index=True)
    status = Column(String(32), nullable=False)  # running | success | failed
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    duration_ms = Column(Integer, nullable=True)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)


class MetricSnapshot(Base):
    """Point-in-time operational counters, recorded at most once per
    SNAPSHOT_MIN_INTERVAL seconds from real COUNT queries."""

    __tablename__ = "metric_snapshots"

    id = Column(Integer, primary_key=True)
    ts = Column(DateTime(timezone=True), default=utcnow, index=True)
    entities = Column(Integer, nullable=False)
    vulnerabilities = Column(Integer, nullable=False)
    campaigns = Column(Integer, nullable=False)
    recent_updates_24h = Column(Integer, nullable=False)
