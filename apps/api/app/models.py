"""Operational database models.

These tables hold the platform's *own* operational state (component
registry, real events, real counters, real task runs, real worker
heartbeats, real alerts, real metric/broker snapshots). Intelligence
tables (entities, vulnerabilities, campaigns, sync attempts) stay empty
until a real, authorized ingestion source writes to them. No synthetic
rows are seeded.
"""
from datetime import datetime, timezone

from sqlalchemy import UniqueConstraint,  Boolean, Column, DateTime, Integer, String, Text

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
    worker = Column(String(128), nullable=False, index=True)
    queue = Column(String(128), nullable=False, index=True)
    status = Column(String(32), nullable=False)  # running | success | failed
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    duration_ms = Column(Integer, nullable=True)
    error = Column(Text, nullable=True)
    attempts = Column(Integer, default=1, nullable=False)  # retry count
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)


class WorkerHeartbeat(Base):
    """A real worker heartbeat, reported via POST /api/v1/ops/workers/heartbeat.

    Records local worker process liveness only — never Arena session activity.
    """

    __tablename__ = "worker_heartbeats"

    id = Column(Integer, primary_key=True)
    worker = Column(String(128), unique=True, nullable=False, index=True)
    last_seen = Column(DateTime(timezone=True), default=utcnow, index=True)
    details = Column(Text, default="")
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


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


class BrokerSnapshot(Base):
    """Point-in-time RabbitMQ broker totals from a REAL management-API check
    (recorded only when the broker check succeeds)."""

    __tablename__ = "broker_snapshots"

    id = Column(Integer, primary_key=True)
    ts = Column(DateTime(timezone=True), default=utcnow, index=True)
    messages_ready = Column(Integer, nullable=True)
    messages_unacknowledged = Column(Integer, nullable=True)
    queues = Column(Integer, nullable=True)
    consumers = Column(Integer, nullable=True)
    dead_letter_queues = Column(Integer, nullable=True)


class Alert(Base):
    """An operational alert derived from REAL check results.

    Deduplicated by (rule, component_key): an open alert is updated
    (occurrences+1) instead of duplicated; when the condition clears it is
    marked resolved and kept for history.
    """

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    rule = Column(String(64), nullable=False, index=True)
    component_key = Column(String(64), nullable=True, index=True)
    severity = Column(String(16), nullable=False)  # critical | warning | info
    status = Column(String(16), nullable=False, index=True)  # active | acknowledged | resolved
    message = Column(Text, nullable=False)
    first_seen = Column(DateTime(timezone=True), default=utcnow)
    last_seen = Column(DateTime(timezone=True), default=utcnow)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    acked_at = Column(DateTime(timezone=True), nullable=True)
    acked_by = Column(String(128), nullable=True)
    occurrences = Column(Integer, default=1)
    # M5: escalation (severity bumped after OPS_ALERT_ESCALATE_OCCURRENCES)
    # and flap detection (resolved then re-fired within OPS_ALERT_FLAP_WINDOW_S)
    escalated = Column(Boolean, default=False, nullable=False)
    flapping = Column(Boolean, default=False, nullable=False)
    owner = Column(String(128), nullable=True)  # alert ownership/assignment


class MaintenanceWindow(Base):
    """A scheduled maintenance window. While active, matching alert rules are
    suppressed (not raised) and open matching alerts are not auto-resolved."""

    __tablename__ = "maintenance_windows"

    id = Column(Integer, primary_key=True)
    label = Column(String(128), nullable=False)
    starts_at = Column(DateTime(timezone=True), nullable=False, index=True)
    ends_at = Column(DateTime(timezone=True), nullable=False, index=True)
    # JSON list of component keys; empty = all components
    component_keys = Column(Text, default="[]")
    # optional rule filter; null = all rules
    rule = Column(String(64), nullable=True)
    created_by = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class WorkerHeartbeatHistory(Base):
    """Throttled samples of worker heartbeats for availability history
    (at most one sample per worker per ~60 s)."""

    __tablename__ = "worker_heartbeat_history"

    id = Column(Integer, primary_key=True)
    worker = Column(String(128), nullable=False, index=True)
    ts = Column(DateTime(timezone=True), default=utcnow, index=True)


class Worker(Base):
    """Registered worker identity (M6). Heartbeats update last_seen; the
    broker never controls Arena sessions — this registry tracks WORKERS only."""

    __tablename__ = "workers"

    worker = Column(String(128), primary_key=True)
    queue = Column(String(128), default="default")
    version = Column(String(64), nullable=True)
    capabilities = Column(Text, nullable=True)  # JSON array of strings
    registered_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


# ---- Central Autonomous Coordination (separately reviewable; own tables) ----

# M7 lifecycle v2: legacy states kept as aliases for backward compatibility
# (NEW == CREATED, DELIVERED == DELIVERING, IN_PROGRESS == RUNNING).
COORD_TASK_STATES = (
    "CREATED", "VALIDATING", "QUEUED", "WAITING_FOR_APPROVAL", "ASSIGNED",
    "DELIVERING", "ACKNOWLEDGED", "RUNNING", "COMPLETED", "FAILED",
    "RETRYING", "BLOCKED", "CANCELLED", "EXPIRED",
    # legacy aliases (accepted on read, normalized on write)
    "NEW", "DELIVERED", "IN_PROGRESS",
)
LEGACY_STATE_ALIASES = {"NEW": "CREATED", "DELIVERED": "DELIVERING", "IN_PROGRESS": "RUNNING"}


class CoordinationTask(Base):
    """Durable task registry entry for the coordination system (P4)."""

    __tablename__ = "coord_tasks"

    id = Column(Integer, primary_key=True)
    task_id = Column(String(64), unique=True, index=True)  # e.g. gh-<delivery>-<n>
    event_id = Column(String(128), nullable=True, index=True)  # X-GitHub-Delivery
    source = Column(String(32), default="github")  # provenance
    kind = Column(String(64), index=True)  # pr_opened, issue_comment, ci_failed, manual...
    agent = Column(String(64), nullable=True, index=True)  # assigned agent
    state = Column(String(32), default="NEW", index=True)
    priority = Column(Integer, default=5)
    repo = Column(String(256), nullable=True)
    pr_ref = Column(String(64), nullable=True)
    branch_ref = Column(String(256), nullable=True)
    title = Column(Text, nullable=True)
    payload = Column(Text, nullable=True)  # normalized event JSON (no secrets)
    handoff = Column(Text, nullable=True)  # copy-ready handoff payload
    attempts = Column(Integer, default=0)
    result = Column(Text, nullable=True)
    owner = Column(String(128), nullable=True)            # human owner of the task
    depends_on = Column(Text, nullable=True)               # JSON list of task_ids
    timeout_s = Column(Integer, nullable=True)             # max runtime once RUNNING
    expires_at = Column(DateTime(timezone=True), nullable=True)  # task TTL
    idempotency_key = Column(String(128), nullable=True, index=True)
    dead_letter = Column(Boolean, default=False, nullable=False)
    routing_explanation = Column(Text, nullable=True)      # why this agent was chosen
    progress = Column(Integer, default=0, nullable=False)  # 0..100 structured progress (M8)
    next_retry_at = Column(DateTime, nullable=True)         # backoff until this time (M9)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class CoordinationTaskEvent(Base):
    """Audit history for coordination tasks (state transitions, acks...)."""

    __tablename__ = "coord_task_events"

    id = Column(Integer, primary_key=True)
    task_id = Column(String(64), index=True)
    at = Column(DateTime(timezone=True), default=utcnow)
    kind = Column(String(64))  # created, routed, delivered, acked, completed...
    detail = Column(Text, nullable=True)


class GitHubEvent(Base):
    """Deduplicated GitHub webhook deliveries with provenance (replay-safe)."""

    __tablename__ = "coord_github_events"

    delivery_id = Column(String(128), primary_key=True)  # X-GitHub-Delivery
    event = Column(String(64), index=True)  # X-GitHub-Event
    received_at = Column(DateTime(timezone=True), default=utcnow)
    action = Column(String(64), nullable=True)
    repo = Column(String(256), nullable=True)
    sender = Column(String(128), nullable=True)
    normalized = Column(Text, nullable=True)  # canonical JSON, secrets stripped


class RoutingRule(Base):
    """Configurable routing rules: match JSON -> agent."""

    __tablename__ = "coord_routing_rules"

    id = Column(Integer, primary_key=True)
    priority = Column(Integer, default=100, index=True)
    name = Column(String(128), unique=True)
    match = Column(Text, nullable=False)  # JSON: {"kind": ..., "labels": [...], "path": ...}
    agent = Column(String(64), nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)


class CoordinationAgent(Base):
    """Agent registry entry (M7): identity, specialization, capabilities,
    liveness, workload and performance stats. A registered agent is NOT an
    active Arena session — liveness here means heartbeats, nothing more."""

    __tablename__ = "coord_agents"

    agent = Column(String(64), primary_key=True)
    specialization = Column(String(128), nullable=True)
    capabilities = Column(Text, nullable=True)  # JSON array
    status = Column(String(16), default="unknown", index=True)  # available|busy|offline|draining
    version = Column(String(64), nullable=True)
    last_heartbeat = Column(DateTime(timezone=True), nullable=True)
    registered_at = Column(DateTime(timezone=True), default=utcnow)
    meta = Column(Text, nullable=True)  # JSON free-form (compat metadata)


class CoordinationApproval(Base):
    """Approval workflow record (M7): one row per approval request."""

    __tablename__ = "coord_approvals"

    id = Column(Integer, primary_key=True)
    task_id = Column(String(64), index=True)
    status = Column(String(16), default="pending", index=True)  # pending|approved|rejected|expired
    requested_by = Column(String(128), nullable=True)
    decided_by = Column(String(128), nullable=True)
    note = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    decided_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)


class CoordinationAmendment(Base):
    """M29: cross-owner contract amendment proposal (auditable workflow).
    Lifecycle: pending -> accepted|rejected (decided only by configured
    approvers). Proposals never change the live contract by themselves."""

    __tablename__ = "coord_amendments"

    id = Column(Integer, primary_key=True)
    amendment_id = Column(String(64), unique=True, index=True)  # slug, e.g. AMD-001
    title = Column(String(256))
    description = Column(Text)
    affects = Column(Text, nullable=True)          # JSON list of contract keys affected
    compatibility = Column(Text, nullable=True)    # JSON: {backward_compatible, notes, consumers_checked}
    target_version = Column(String(16), nullable=True)  # e.g. 1.1
    proposed_by = Column(String(128))
    status = Column(String(16), default="pending", index=True)  # pending|accepted|rejected
    decided_by = Column(String(128), nullable=True)
    decision_note = Column(Text, nullable=True)
    linked_refs = Column(Text, nullable=True)      # JSON list: commits/PRs implementing it
    history = Column(Text, nullable=True)          # M30: JSON audit trail of status transitions
    created_at = Column(DateTime(timezone=True), default=utcnow)
    decided_at = Column(DateTime(timezone=True), nullable=True)


class CoordinationAmendmentRef(Base):
    """M32: per-ref rows for amendment traceability. Append-only with a unique
    (amendment_id, ref) constraint, so concurrent decide/attach_refs can never
    overwrite each other's refs (unlike a JSON column)."""

    __tablename__ = "coord_amendment_refs"
    __table_args__ = (UniqueConstraint("amendment_id", "ref", name="uq_amendment_ref"),)

    id = Column(Integer, primary_key=True)
    amendment_id = Column(String(64), index=True)
    ref = Column(String(256))
    added_by = Column(String(128), nullable=True)
    at = Column(DateTime(timezone=True), default=utcnow)


class CoordinationDelivery(Base):
    """Delivery history record (M7): one row per delivery attempt. A task is
    DELIVERING only while a record is unconfirmed; publisher confirms update
    it. Never marks delivered merely because a message was prepared."""

    __tablename__ = "coord_deliveries"

    id = Column(Integer, primary_key=True)
    task_id = Column(String(64), index=True)
    channel = Column(String(16))  # rabbitmq | human_assisted
    queue = Column(String(256), nullable=True)
    message_id = Column(String(128), nullable=True)  # idempotency / dedup id
    status = Column(String(16), index=True)  # published|confirmed|failed
    attempt = Column(Integer, default=1)
    error = Column(Text, nullable=True)
    at = Column(DateTime(timezone=True), default=utcnow)
    confirmed_at = Column(DateTime(timezone=True), nullable=True)
