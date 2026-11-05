"""
Threat Intelligence Domain Observability — operational visibility for the TI subsystem.
Branch: arena/28e50255-cicc (Agent 6 - Full Threat Intelligence Backup Engineer)

This module COMPOSES the existing services rather than duplicating their state:
- `SourceReliabilityService`    -> source health, freshness, reliability tiers
- `CollectionWorker`            -> job state, retries, leases, circuit breakers
- `ConflictResolutionService`   -> ingestion disagreement counts
- `RelationshipAnalysisService` -> contradiction and incompleteness counts (optional)

SCOPE BOUNDARY: this is Threat Intelligence domain observability only. It does not define or
redefine Agent 1's shared system-health contract. `to_agent1_heartbeat_details()` and
`to_agent1_payload()` merely format values for the *proposed* Agent 1 heartbeat; that contract
remains PROPOSED and is not load-bearing here.

HONESTY CONSTRAINTS:
- Nothing here claims a worker process is running. `runtime_status` defaults to
  `caller_invoked_no_daemon` and the caveats repeat it on every snapshot.
- No source is reported as live without evidence-backed verification state carried by
  `SourceReliabilityService`.
"""

import threading
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from apps.threat_intelligence.cisa_kev import EXPERIMENTAL_DEMO_DATA_ONLY
from apps.threat_intelligence.collection_workers import CollectionWorker, JobState
from apps.threat_intelligence.conflict_resolution import ConflictResolutionService
from apps.threat_intelligence.relationship_analysis import RelationshipAnalysisService
from apps.threat_intelligence.source_reliability import (
    FreshnessState,
    ReliabilityTier,
    SourceReliabilityService,
    to_utc,
)

MAX_EVENT_RETENTION = 5_000
MAX_SNAPSHOT_HISTORY = 200

RUNTIME_CALLER_INVOKED = "caller_invoked_no_daemon"


class ObservabilityError(ValueError):
    """Raised when an observability request is invalid."""


class SourceHealth(str, Enum):
    """Roll-up health of one source across collection, freshness and circuit state."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILING = "failing"
    CIRCUIT_OPEN = "circuit_open"
    STALE = "stale"
    NEVER_COLLECTED = "never_collected"
    UNSCORED = "unscored"


class DomainObservabilityEvent(BaseModel):
    """A bounded, structured observability event."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(..., max_length=256)
    kind: str = Field(..., max_length=64)
    severity: str = Field("info", max_length=16, description="debug | info | warning | error")
    source_id: Optional[str] = Field(None, max_length=256)
    message: str = Field(..., max_length=1000)
    data: Dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime = Field(default_factory=datetime.utcnow)


class SourceHealthView(BaseModel):
    """Per-source operational view assembled from the underlying services."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    source_id: str
    health: SourceHealth
    reliability_tier: Optional[str] = None
    reliability_score: Optional[float] = None
    consecutive_failures: int = 0
    total_successes: int = 0
    total_failures: int = 0
    last_successful_at: Optional[str] = Field(None, description="ISO-8601, as recorded by the reliability service")
    last_attempted_at: Optional[str] = Field(None, description="ISO-8601 of the most recent collection attempt")
    freshness_state: Optional[str] = None
    freshness_age_seconds: Optional[int] = None
    stale_after_seconds: Optional[int] = None
    circuit_state: Optional[str] = None
    circuit_opened_at: Optional[str] = None
    verification_mode: str = "fixture_tested"
    pending_jobs: int = 0
    running_jobs: int = 0
    retry_scheduled_jobs: int = 0
    abandoned_jobs: int = 0
    failed_jobs: int = 0
    notes: List[str] = Field(default_factory=list)


class DomainHealthSnapshot(BaseModel):
    """A point-in-time snapshot of Threat Intelligence operational state."""

    model_config = ConfigDict(extra="forbid")

    snapshot_id: str
    tenant_id: str
    generated_at: datetime
    runtime_status: str = RUNTIME_CALLER_INVOKED
    source_count: int = 0
    sources_by_health: Dict[str, int] = Field(default_factory=dict)
    sources_by_tier: Dict[str, int] = Field(default_factory=dict)
    freshness_by_state: Dict[str, int] = Field(default_factory=dict)
    verification_modes: Dict[str, int] = Field(default_factory=dict)
    collection: Dict[str, Any] = Field(default_factory=dict)
    conflicts: Dict[str, Any] = Field(default_factory=dict)
    relationships: Dict[str, Any] = Field(default_factory=dict)
    degraded_sources: List[str] = Field(default_factory=list)
    experimental_label: Optional[str] = Field(EXPERIMENTAL_DEMO_DATA_ONLY)
    caveats: List[str] = Field(default_factory=list)


class ThreatIntelObservabilityService:
    """
    Read-oriented aggregation over the existing TI services.

    In-memory and safe for concurrent readers; starts no thread, process or event loop.
    """

    _SEVERITIES = ("debug", "info", "warning", "error")
    _UNHEALTHY_TIERS = (ReliabilityTier.TIER3_UNPROVEN, ReliabilityTier.TIER4_UNRELIABLE)
    _BAD_FRESHNESS = (FreshnessState.STALE.value, FreshnessState.EXPIRED.value)

    def __init__(
        self,
        tenant_id: str = "default",
        reliability_service: Optional[SourceReliabilityService] = None,
        worker: Optional[CollectionWorker] = None,
        conflict_service: Optional[ConflictResolutionService] = None,
        relationship_service: Optional[RelationshipAnalysisService] = None,
        runtime_status: str = RUNTIME_CALLER_INVOKED,
    ):
        if not tenant_id or not tenant_id.strip():
            raise ObservabilityError("tenant_id is required")
        self.tenant_id = tenant_id.strip()
        self.reliability = reliability_service or SourceReliabilityService()
        self.worker = worker or CollectionWorker()
        self.conflicts = conflict_service or ConflictResolutionService(tenant_id=self.tenant_id)
        self.relationships = relationship_service
        self.runtime_status = runtime_status
        self._lock = threading.RLock()
        self._events: List[DomainObservabilityEvent] = []
        self._snapshots: List[DomainHealthSnapshot] = []
        self._event_counter = 0
        self._snapshot_counter = 0

    # ------------------------------------------------------------------ events

    def emit(
        self,
        kind: str,
        message: str,
        severity: str = "info",
        source_id: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        now: Optional[datetime] = None,
    ) -> DomainObservabilityEvent:
        """Append a bounded structured event. Oldest events are dropped past the retention cap."""
        if not kind or not kind.strip():
            raise ObservabilityError("event kind is required")
        if not message or not message.strip():
            raise ObservabilityError("event message is required")
        if severity not in self._SEVERITIES:
            raise ObservabilityError(
                f"invalid severity {severity!r}: must be one of {list(self._SEVERITIES)}"
            )
        with self._lock:
            self._event_counter += 1
            event = DomainObservabilityEvent(
                event_id=f"OBS-{self._event_counter:08d}",
                kind=kind.strip(),
                severity=severity,
                source_id=source_id,
                message=message.strip()[:1000],
                data=dict(data or {}),
                occurred_at=now or datetime.utcnow(),
            )
            self._events.append(event)
            if len(self._events) > MAX_EVENT_RETENTION:
                del self._events[: len(self._events) - MAX_EVENT_RETENTION]
            return event

    def events(
        self,
        kind: Optional[str] = None,
        severity: Optional[str] = None,
        source_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[DomainObservabilityEvent]:
        limit = max(1, min(int(limit), MAX_EVENT_RETENTION))
        with self._lock:
            items = list(self._events)
        if kind is not None:
            items = [e for e in items if e.kind == kind]
        if severity is not None:
            items = [e for e in items if e.severity == severity]
        if source_id is not None:
            items = [e for e in items if e.source_id == source_id]
        return items[-limit:]

    def event_count(self) -> int:
        with self._lock:
            return len(self._events)

    # ----------------------------------------------------------- source health

    def _job_counts_for_source(self, source_id: str) -> Dict[str, int]:
        counts = {
            "pending": 0,
            "running": 0,
            "retry_scheduled": 0,
            "abandoned": 0,
            "failed": 0,
        }
        for job in self.worker.list_jobs(source_id=source_id):
            if job.state is JobState.PENDING:
                counts["pending"] += 1
            elif job.state in (JobState.LEASED, JobState.RUNNING):
                counts["running"] += 1
            elif job.state is JobState.RETRY_SCHEDULED:
                counts["retry_scheduled"] += 1
            elif job.state is JobState.ABANDONED:
                counts["abandoned"] += 1
            elif job.state is JobState.FAILED:
                counts["failed"] += 1
        return counts

    def source_health(self, source_id: str, now: Optional[datetime] = None) -> SourceHealthView:
        """
        Assemble one source's operational view.

        Precedence is deliberate: an open circuit outranks a hard failure, which outranks a weak
        reliability tier, which outranks staleness - so the most urgent condition surfaces first.
        """
        if not source_id or not source_id.strip():
            raise ObservabilityError("source_id is required")
        moment = to_utc(now or datetime.utcnow())
        source_id = source_id.strip()
        notes: List[str] = []

        record = self.reliability.get(self.tenant_id, source_id)
        breaker_state = self.worker.breaker_for(source_id).snapshot()
        counts = self._job_counts_for_source(source_id)

        view = SourceHealthView(
            tenant_id=self.tenant_id,
            source_id=source_id,
            health=SourceHealth.NEVER_COLLECTED,
            circuit_state=breaker_state.get("state"),
            circuit_opened_at=breaker_state.get("opened_at"),
            pending_jobs=counts["pending"],
            running_jobs=counts["running"],
            retry_scheduled_jobs=counts["retry_scheduled"],
            abandoned_jobs=counts["abandoned"],
            failed_jobs=counts["failed"],
        )

        circuit_open = breaker_state.get("state") == "open"

        if record is None:
            view.health = SourceHealth.CIRCUIT_OPEN if circuit_open else SourceHealth.UNSCORED
            view.notes.append(
                "no reliability record: this source is unscored and is not trusted by default"
            )
            if circuit_open:
                view.notes.append("circuit breaker open despite no reliability record")
            return view

        view.reliability_tier = record.reliability_tier.value
        view.reliability_score = record.reliability_score
        view.consecutive_failures = record.consecutive_failures
        view.total_successes = record.total_successes
        view.total_failures = record.total_failures
        view.last_successful_at = record.last_success_at
        view.last_attempted_at = record.last_collection_at
        view.verification_mode = record.verification_mode
        view.stale_after_seconds = self.reliability.freshness_policy.stale_after_seconds

        # Freshness is RECOMPUTED against the caller's clock rather than read from the record.
        #
        # `record.data_age_seconds` was frozen when the last outcome was recorded, so reporting it
        # verbatim would keep a five-day-old source looking "fresh" forever. Deriving the age from
        # `last_success_at` against `now` is what makes staleness actually observable.
        policy = self.reliability.freshness_policy
        if record.last_success_at is None:
            view.freshness_state = FreshnessState.UNKNOWN.value
            view.freshness_age_seconds = None
            notes.append("no successful collection yet; freshness unknown")
        else:
            age = (to_utc(moment) - datetime.fromisoformat(record.last_success_at)).total_seconds()
            if age < 0:
                view.freshness_state = FreshnessState.UNKNOWN.value
                view.freshness_age_seconds = None
                notes.append("last successful collection is future-dated; freshness unknown")
            else:
                view.freshness_age_seconds = int(age)
                view.freshness_state = policy.classify(age).value

        if circuit_open:
            view.health = SourceHealth.CIRCUIT_OPEN
            notes.append("circuit breaker open: collection suppressed until it half-opens")
        elif record.total_successes == 0 and record.total_failures > 0:
            view.health = SourceHealth.FAILING
            notes.append("source has never produced a successful collection")
        elif record.reliability_tier in self._UNHEALTHY_TIERS:
            view.health = SourceHealth.DEGRADED
            notes.append(f"reliability tier {record.reliability_tier.value}")
        elif view.freshness_state in self._BAD_FRESHNESS:
            view.health = SourceHealth.STALE
            notes.append(f"freshness state {view.freshness_state}")
        elif record.total_successes == 0 and record.total_failures == 0:
            view.health = SourceHealth.NEVER_COLLECTED
            notes.append("source registered but never collected")
        elif not record.is_scored:
            view.health = SourceHealth.UNSCORED
            notes.append("insufficient outcomes to score this source")
        else:
            view.health = SourceHealth.HEALTHY

        if record.verification_mode != "live_verified":
            notes.append(f"verification_mode={record.verification_mode}: not live-verified")

        view.notes = notes
        return view

    def all_source_health(self, now: Optional[datetime] = None) -> List[SourceHealthView]:
        """Health views for every source known to the reliability service or the worker."""
        ids = {r.source_id for r in self.reliability.list_sources(tenant_id=self.tenant_id)}
        for job in self.worker.list_jobs(tenant_id=self.tenant_id):
            ids.add(job.source_id)
        for snapshot in self.worker.breaker_snapshots():
            ids.add(snapshot["source_id"])
        return sorted(
            (self.source_health(sid, now=now) for sid in ids),
            key=lambda v: v.source_id,
        )

    # -------------------------------------------------------------- snapshots

    def snapshot(self, now: Optional[datetime] = None, retain: bool = True) -> DomainHealthSnapshot:
        """
        Build a point-in-time domain health snapshot.

        Retained snapshots are capped so long-running aggregation cannot grow without bound.
        """
        moment = now or datetime.utcnow()
        with self._lock:
            self._snapshot_counter += 1
            snapshot_id = f"SNAP-{self._snapshot_counter:08d}"

        views = self.all_source_health(now=moment)

        by_health: Dict[str, int] = {}
        by_tier: Dict[str, int] = {}
        by_freshness: Dict[str, int] = {}
        by_verification: Dict[str, int] = {}
        degraded: List[str] = []
        for view in views:
            by_health[view.health.value] = by_health.get(view.health.value, 0) + 1
            tier = view.reliability_tier or ReliabilityTier.UNSCORED.value
            by_tier[tier] = by_tier.get(tier, 0) + 1
            fresh = view.freshness_state or FreshnessState.UNKNOWN.value
            by_freshness[fresh] = by_freshness.get(fresh, 0) + 1
            by_verification[view.verification_mode] = by_verification.get(view.verification_mode, 0) + 1
            if view.health is not SourceHealth.HEALTHY:
                degraded.append(view.source_id)

        conflict_stats = self.conflicts.stats()
        relationships: Dict[str, Any] = {}
        if self.relationships is not None:
            relationships = self.relationships.health(now=moment)

        live_verified = by_verification.get("live_verified", 0)
        caveats = [
            "runtime_status=caller_invoked_no_daemon: no worker process or event loop is running",
            "snapshot is derived from in-memory service state; no metrics backend is connected",
        ]
        if live_verified == 0:
            caveats.append("no source is live_verified: all reported data is fixture-tested")

        snapshot = DomainHealthSnapshot(
            snapshot_id=snapshot_id,
            tenant_id=self.tenant_id,
            generated_at=moment,
            runtime_status=self.runtime_status,
            source_count=len(views),
            sources_by_health=by_health,
            sources_by_tier=by_tier,
            freshness_by_state=by_freshness,
            verification_modes=by_verification,
            collection=self.worker.health_snapshot(now=moment),
            conflicts={
                "claim_count": conflict_stats["claim_count"],
                "open_conflict_count": conflict_stats["open_conflict_count"],
                "unresolved_count": conflict_stats["unresolved_count"],
                "withdrawn_claim_count": conflict_stats["withdrawn_claim_count"],
            },
            relationships=relationships,
            degraded_sources=degraded,
            experimental_label=(None if live_verified > 0 else EXPERIMENTAL_DEMO_DATA_ONLY),
            caveats=caveats,
        )

        if retain:
            with self._lock:
                self._snapshots.append(snapshot)
                if len(self._snapshots) > MAX_SNAPSHOT_HISTORY:
                    del self._snapshots[: len(self._snapshots) - MAX_SNAPSHOT_HISTORY]
        return snapshot

    def snapshot_history(self, limit: int = 50) -> List[DomainHealthSnapshot]:
        limit = max(1, min(int(limit), MAX_SNAPSHOT_HISTORY))
        with self._lock:
            return list(self._snapshots[-limit:])

    # -------------------------------------------------------------- ingestion

    def ingestion_report(self, source_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Ingestion and validation counters, taken directly from the worker's own metrics.

        Nothing is estimated or invented here: if the worker has counted nothing, this reports
        zeros rather than plausible-looking numbers.
        """
        metrics = self.worker.metrics
        by_source = dict(metrics.by_source)
        if source_id is not None:
            wanted = source_id.strip()
            by_source = {k: v for k, v in by_source.items() if k == wanted}
        counters = {
            "jobs_created": metrics.jobs_created,
            "attempts_started": metrics.attempts_started,
            "attempts_succeeded": metrics.attempts_succeeded,
            "attempts_failed": metrics.attempts_failed,
            "retries_scheduled": metrics.retries_scheduled,
            "jobs_failed_terminal": metrics.jobs_failed_terminal,
            "jobs_abandoned": metrics.jobs_abandoned,
            "jobs_expired": metrics.jobs_expired,
            "breaker_open_events": metrics.breaker_open_events,
            "breaker_open_rejections": metrics.breaker_open_rejections,
            "leases_expired_reclaimed": metrics.leases_expired_reclaimed,
            "idempotent_duplicates_suppressed": metrics.idempotent_duplicates_suppressed,
        }
        return {
            "tenant_id": self.tenant_id,
            "counters": counters,
            "by_source": by_source,
            "succeeded": metrics.attempts_succeeded,
            "failed": metrics.attempts_failed,
            "retries_scheduled": metrics.retries_scheduled,
            "note": "counters are in-memory and reset when the worker object is discarded",
        }

    # --------------------------------------------------------- agent 1 bridge

    def to_agent1_heartbeat_details(self, now: Optional[datetime] = None) -> str:
        """
        A compact, secret-free status string for the PROPOSED Agent 1 heartbeat `details` field.

        This does not make the Agent 1 contract load-bearing: it only formats a string a host may
        send if and when that contract is accepted and mounted.
        """
        snap = self.snapshot(now=now, retain=False)
        return (
            f"ti_domain sources={snap.source_count} "
            f"degraded={len(snap.degraded_sources)} "
            f"live_verified={snap.verification_modes.get('live_verified', 0)} "
            f"runtime={snap.runtime_status}"
        )

    def to_agent1_payload(self, now: Optional[datetime] = None) -> Dict[str, Any]:
        """Structured payload for the proposed Agent 1 heartbeat, kept free of secrets."""
        snap = self.snapshot(now=now, retain=False)
        state_counts = snap.collection.get("state_counts", {})
        return {
            "status": "online",
            "active_tasks": state_counts.get(JobState.RUNNING.value, 0)
            + state_counts.get(JobState.LEASED.value, 0),
            "meta": {
                "domain": "threat_intelligence",
                "tenant_id": self.tenant_id,
                "source_count": snap.source_count,
                "degraded_sources": snap.degraded_sources,
                "verification_modes": snap.verification_modes,
                "runtime_status": snap.runtime_status,
                "contract_status": "proposed_not_accepted",
            },
        }
