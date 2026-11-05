"""
Threat Intelligence Background Collection & Synchronization Architecture

Repository:  oldman-088/cicc   Branch: arena/28e50255-cicc (Agent 6 backup)

What this module IS
-------------------
A deterministic, in-process model of the collection/synchronization control
plane for Threat Intelligence sources:

* bounded retries with exponential backoff and jitter;
* explicit job lifecycle states including terminal failure states;
* a circuit breaker that stops hammering a source that is already failing;
* observability counters and a structured event log;
* lease-based claiming so two workers cannot process the same job;
* persistence of job state through the Threat Intelligence repository.

What this module IS NOT
-----------------------
* **No worker is running.** There is no thread, no process, no asyncio loop and
  no scheduler daemon started by importing or instantiating anything here.
  ``CollectionWorker.run_pending(now=...)`` executes *synchronously* when a
  caller invokes it. Nothing ticks on its own.
* **No network I/O.** A job's work is whatever callable the caller supplies.
  This module never opens a socket.
* Time is injected. Every time-dependent decision takes an explicit ``now``
  argument, which is what makes retry and backoff behaviour testable without
  sleeping.

Verification state: **fixture_tested**.
"""

from __future__ import annotations

import hashlib
import json
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator

EXPERIMENTAL_DEMO_DATA_ONLY = "EXPERIMENTAL_DEMO_DATA_ONLY"

DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_BASE_DELAY_SECONDS = 30.0
DEFAULT_MAX_DELAY_SECONDS = 3600.0
DEFAULT_BACKOFF_MULTIPLIER = 2.0
DEFAULT_JITTER_RATIO = 0.2
DEFAULT_LEASE_SECONDS = 300
DEFAULT_BREAKER_FAILURE_THRESHOLD = 5
DEFAULT_BREAKER_COOLDOWN_SECONDS = 600.0

_MAX_ERROR_DETAIL_LENGTH = 500


class JobState(str, Enum):
    """Explicit job lifecycle. Terminal states are marked in TERMINAL_STATES."""

    PENDING = "pending"
    LEASED = "leased"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    RETRY_SCHEDULED = "retry_scheduled"
    FAILED = "failed"            # terminal: attempts exhausted
    ABANDONED = "abandoned"      # terminal: breaker open / operator decision
    EXPIRED = "expired"          # terminal: TTL elapsed before success


TERMINAL_STATES = frozenset({
    JobState.SUCCEEDED,
    JobState.FAILED,
    JobState.ABANDONED,
    JobState.EXPIRED,
})

VALID_VERIFICATION_MODES = frozenset({"fixture_tested", "oracle_verified", "live_verified"})


class CollectionWorkerError(Exception):
    """Base error for the collection control plane."""


class UnknownJobError(CollectionWorkerError):
    """Job id does not exist."""


class JobNotLeasableError(CollectionWorkerError):
    """Job cannot be claimed in its current state."""


class LeaseConflictError(CollectionWorkerError):
    """Another worker holds a live lease on this job."""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{moment.astimezone(timezone.utc).microsecond // 1000:03d}Z"


def _truncate_error(exc: BaseException) -> str:
    """
    Bound the stored error detail. Unbounded exception text is both a storage
    problem and a log-injection vector.
    """
    text = f"{type(exc).__name__}: {exc}".replace("\n", " ").replace("\r", " ")
    return text[:_MAX_ERROR_DETAIL_LENGTH]


# ============================================================================
# Configuration
# ============================================================================

class RetryPolicy(BaseModel):
    """Bounded retry configuration for a collection job."""

    model_config = ConfigDict(extra="forbid")

    max_attempts: int = Field(DEFAULT_MAX_ATTEMPTS, ge=1, le=100)
    base_delay_seconds: float = Field(DEFAULT_BASE_DELAY_SECONDS, gt=0)
    max_delay_seconds: float = Field(DEFAULT_MAX_DELAY_SECONDS, gt=0)
    backoff_multiplier: float = Field(DEFAULT_BACKOFF_MULTIPLIER, ge=1.0, le=10.0)
    jitter_ratio: float = Field(DEFAULT_JITTER_RATIO, ge=0.0, le=0.9)
    ttl_seconds: Optional[int] = Field(86400, ge=1)
    lease_seconds: int = Field(DEFAULT_LEASE_SECONDS, ge=1)

    @field_validator("max_delay_seconds")
    @classmethod
    def _max_at_least_base(cls, v: float, info) -> float:
        base = info.data.get("base_delay_seconds")
        if base is not None and v < base:
            raise ValueError("max_delay_seconds must be >= base_delay_seconds")
        return v

    def delay_for_attempt(self, attempt: int, *, rng: Optional[random.Random] = None) -> float:
        """
        Exponential backoff with bounded jitter.

        ``attempt`` is 1-based: the delay applied *after* the Nth failed attempt.
        """
        if attempt < 1:
            raise ValueError("attempt must be >= 1")
        raw = self.base_delay_seconds * (self.backoff_multiplier ** (attempt - 1))
        capped = min(raw, self.max_delay_seconds)
        if self.jitter_ratio <= 0:
            return capped
        generator = rng or random
        spread = capped * self.jitter_ratio
        jittered = capped + generator.uniform(-spread, spread)
        return max(0.0, min(jittered, self.max_delay_seconds))


class CircuitBreakerConfig(BaseModel):
    """Per-source circuit breaker configuration."""

    model_config = ConfigDict(extra="forbid")

    failure_threshold: int = Field(DEFAULT_BREAKER_FAILURE_THRESHOLD, ge=1)
    cooldown_seconds: float = Field(DEFAULT_BREAKER_COOLDOWN_SECONDS, gt=0)
    half_open_probe_limit: int = Field(1, ge=1, le=10)


# ============================================================================
# Job model
# ============================================================================

class CollectionJob(BaseModel):
    """A single unit of collection/synchronization work."""

    model_config = ConfigDict(extra="forbid")

    job_id: str = Field(..., min_length=1)
    tenant_id: str = Field(..., min_length=1)
    source_id: str = Field(..., min_length=1)
    kind: str = Field(..., description="Job kind, e.g. osint_sync, kev_catalog_sync, mitre_sync")
    payload: Dict[str, Any] = Field(default_factory=dict)
    idempotency_key: Optional[str] = Field(None)
    priority: int = Field(5, ge=1, le=10)

    state: JobState = Field(JobState.PENDING)
    attempts: int = Field(0, ge=0)
    max_attempts: int = Field(DEFAULT_MAX_ATTEMPTS, ge=1)
    next_attempt_at: Optional[str] = Field(None)
    lease_owner: Optional[str] = Field(None)
    lease_expires_at: Optional[str] = Field(None)

    created_at: str = Field(...)
    updated_at: str = Field(...)
    scheduled_for: Optional[str] = Field(None)
    expires_at: Optional[str] = Field(None)
    last_error: Optional[str] = Field(None)
    last_error_at: Optional[str] = Field(None)
    result_summary: Optional[Dict[str, Any]] = Field(None)

    verification_mode: str = Field("fixture_tested")
    experimental_label: Optional[str] = Field(EXPERIMENTAL_DEMO_DATA_ONLY)

    @field_validator("kind")
    @classmethod
    def _check_kind(cls, v: str) -> str:
        if not v or " " in v:
            raise ValueError("kind must be a single non-empty token without spaces")
        return v

    @field_validator("verification_mode")
    @classmethod
    def _check_verification(cls, v: str) -> str:
        if v not in VALID_VERIFICATION_MODES:
            raise ValueError(f"verification_mode must be one of {sorted(VALID_VERIFICATION_MODES)}")
        return v

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES


class JobEvent(BaseModel):
    """One structured observability event."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(...)
    job_id: str = Field(...)
    tenant_id: str = Field(...)
    source_id: str = Field(...)
    event_type: str = Field(..., description="created|leased|attempt_started|attempt_failed|"
                                             "attempt_succeeded|retry_scheduled|state_terminal|"
                                             "breaker_opened|breaker_half_open|breaker_closed|"
                                             "lease_expired|job_expired")
    state: JobState
    attempts: int = Field(0, ge=0)
    detail: Optional[str] = Field(None)
    occurred_at: str = Field(...)


class WorkerMetrics(BaseModel):
    """Aggregate observability counters."""

    model_config = ConfigDict(extra="forbid")

    jobs_created: int = Field(0, ge=0)
    attempts_started: int = Field(0, ge=0)
    attempts_succeeded: int = Field(0, ge=0)
    attempts_failed: int = Field(0, ge=0)
    retries_scheduled: int = Field(0, ge=0)
    jobs_failed_terminal: int = Field(0, ge=0)
    jobs_abandoned: int = Field(0, ge=0)
    jobs_expired: int = Field(0, ge=0)
    breaker_open_events: int = Field(0, ge=0)
    breaker_open_rejections: int = Field(0, ge=0)
    leases_expired_reclaimed: int = Field(0, ge=0)
    idempotent_duplicates_suppressed: int = Field(0, ge=0)
    by_source: Dict[str, Dict[str, int]] = Field(default_factory=dict)

    def bump(self, counter: str, source_id: Optional[str] = None, amount: int = 1) -> None:
        current = getattr(self, counter)
        object.__setattr__(self, counter, current + amount)
        if source_id is not None:
            bucket = self.by_source.setdefault(source_id, {})
            bucket[counter] = bucket.get(counter, 0) + amount


# ============================================================================
# Circuit breaker
# ============================================================================

@dataclass
class SourceCircuitBreaker:
    """
    Per-source circuit breaker.

    States: ``closed`` (normal), ``open`` (rejecting), ``half_open`` (probing).
    """

    source_id: str
    config: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)
    consecutive_failures: int = 0
    state: str = "closed"
    opened_at: Optional[datetime] = None
    half_open_probes: int = 0

    def allow_request(self, now: datetime) -> bool:
        if self.state == "closed":
            return True
        if self.state == "open":
            if self.opened_at is None:
                return False
            elapsed = (now - self.opened_at).total_seconds()
            if elapsed >= self.config.cooldown_seconds:
                self.state = "half_open"
                self.half_open_probes = 0
                return True
            return False
        # half_open: allow a bounded number of probes
        return self.half_open_probes < self.config.half_open_probe_limit

    def record_probe(self) -> None:
        if self.state == "half_open":
            self.half_open_probes += 1

    def record_success(self) -> bool:
        """Returns True when this success transitioned the breaker to closed."""
        transitioned = self.state != "closed"
        self.consecutive_failures = 0
        self.state = "closed"
        self.opened_at = None
        self.half_open_probes = 0
        return transitioned

    def record_failure(self, now: datetime) -> bool:
        """Returns True when this failure transitioned the breaker to open."""
        self.consecutive_failures += 1
        if self.state == "half_open":
            self.state = "open"
            self.opened_at = now
            self.half_open_probes = 0
            return True
        if self.consecutive_failures >= self.config.failure_threshold:
            self.state = "open"
            self.opened_at = now
            return True
        return False

    def snapshot(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "state": self.state,
            "consecutive_failures": self.consecutive_failures,
            "opened_at": _iso(self.opened_at) if self.opened_at else None,
            "half_open_probes": self.half_open_probes,
        }


# ============================================================================
# Worker
# ============================================================================

Handler = Callable[[CollectionJob], Dict[str, Any]]


class CollectionWorker:
    """
    Synchronous, lease-based collection worker.

    ``run_pending`` must be called explicitly. Importing this module and
    constructing a worker starts nothing.
    """

    def __init__(
        self,
        *,
        retry_policy: Optional[RetryPolicy] = None,
        breaker_config: Optional[CircuitBreakerConfig] = None,
        worker_id: Optional[str] = None,
        event_retention: int = 1000,
        seed: Optional[int] = None,
    ):
        self.retry_policy = retry_policy or RetryPolicy()
        self.breaker_config = breaker_config or CircuitBreakerConfig()
        self.worker_id = worker_id or f"ti-worker-{uuid.uuid4().hex[:8]}"
        self._jobs: Dict[str, CollectionJob] = {}
        self._idempotency_index: Dict[Tuple[str, str], str] = {}
        self._breakers: Dict[str, SourceCircuitBreaker] = {}
        self._events: List[JobEvent] = []
        self._event_retention = max(50, event_retention)
        self.metrics = WorkerMetrics()
        self._rng = random.Random(seed) if seed is not None else random.Random()

    # ------------------------------------------------------------- breakers

    def breaker_for(self, source_id: str) -> SourceCircuitBreaker:
        breaker = self._breakers.get(source_id)
        if breaker is None:
            breaker = SourceCircuitBreaker(source_id=source_id, config=self.breaker_config)
            self._breakers[source_id] = breaker
        return breaker

    def breaker_snapshots(self) -> List[Dict[str, Any]]:
        return [b.snapshot() for b in self._breakers.values()]

    # -------------------------------------------------------------- events

    def _emit(
        self,
        job: CollectionJob,
        event_type: str,
        *,
        detail: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> JobEvent:
        event = JobEvent(
            event_id=uuid.uuid4().hex,
            job_id=job.job_id,
            tenant_id=job.tenant_id,
            source_id=job.source_id,
            event_type=event_type,
            state=job.state,
            attempts=job.attempts,
            detail=detail,
            occurred_at=_iso(now or utcnow()),
        )
        self._events.append(event)
        if len(self._events) > self._event_retention:
            del self._events[: len(self._events) - self._event_retention]
        return event

    def events(self, *, job_id: Optional[str] = None, source_id: Optional[str] = None,
               event_type: Optional[str] = None) -> List[JobEvent]:
        result = self._events
        if job_id is not None:
            result = [e for e in result if e.job_id == job_id]
        if source_id is not None:
            result = [e for e in result if e.source_id == source_id]
        if event_type is not None:
            result = [e for e in result if e.event_type == event_type]
        return list(result)

    # ----------------------------------------------------------- job intake

    def enqueue(
        self,
        *,
        tenant_id: str,
        source_id: str,
        kind: str,
        payload: Optional[Dict[str, Any]] = None,
        job_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        priority: int = 5,
        max_attempts: Optional[int] = None,
        ttl_seconds: Optional[int] = "policy",
        verification_mode: str = "fixture_tested",
        now: Optional[datetime] = None,
    ) -> CollectionJob:
        """
        Register a job.

        If ``idempotency_key`` was already used for this ``(tenant, source)``,
        the existing job is returned unchanged and the duplicate is counted
        rather than silently creating a second job.
        """
        moment = now or utcnow()
        resolved_id = job_id or f"job-{uuid.uuid4().hex[:12]}"

        if idempotency_key:
            index_key = (tenant_id, idempotency_key)
            existing_id = self._idempotency_index.get(index_key)
            if existing_id is not None and existing_id in self._jobs:
                self.metrics.bump("idempotent_duplicates_suppressed", source_id)
                return self._jobs[existing_id]

        attempts_cap = max_attempts if max_attempts is not None else self.retry_policy.max_attempts
        ttl = (
            self.retry_policy.ttl_seconds if ttl_seconds == "policy"
            else ttl_seconds
        )
        job = CollectionJob(
            job_id=resolved_id,
            tenant_id=tenant_id,
            source_id=source_id,
            kind=kind,
            payload=payload or {},
            idempotency_key=idempotency_key,
            priority=priority,
            max_attempts=attempts_cap,
            state=JobState.PENDING,
            created_at=_iso(moment),
            updated_at=_iso(moment),
            expires_at=_iso(moment + timedelta(seconds=ttl)) if ttl else None,
            verification_mode=verification_mode,
        )
        self._jobs[job.job_id] = job
        if idempotency_key:
            self._idempotency_index[(tenant_id, idempotency_key)] = job.job_id
        self.metrics.bump("jobs_created", source_id)
        self._emit(job, "created", now=moment)
        return job

    def get_job(self, job_id: str) -> CollectionJob:
        job = self._jobs.get(job_id)
        if job is None:
            raise UnknownJobError(f"Unknown job_id: {job_id}")
        return job

    def list_jobs(
        self,
        *,
        tenant_id: Optional[str] = None,
        source_id: Optional[str] = None,
        state: Optional[JobState] = None,
        include_terminal: bool = True,
    ) -> List[CollectionJob]:
        jobs = list(self._jobs.values())
        if tenant_id is not None:
            jobs = [j for j in jobs if j.tenant_id == tenant_id]
        if source_id is not None:
            jobs = [j for j in jobs if j.source_id == source_id]
        if state is not None:
            jobs = [j for j in jobs if j.state == state]
        if not include_terminal:
            jobs = [j for j in jobs if not j.is_terminal]
        # Deterministic ordering: priority desc, then creation order.
        return sorted(jobs, key=lambda j: (-j.priority, j.created_at, j.job_id))

    # --------------------------------------------------------------- leases

    def _reclaim_expired_leases(self, now: datetime) -> int:
        reclaimed = 0
        for job in self._jobs.values():
            if job.state != JobState.LEASED or not job.lease_expires_at:
                continue
            if datetime.fromisoformat(job.lease_expires_at) <= now:
                job.state = JobState.PENDING
                job.lease_owner = None
                job.lease_expires_at = None
                job.updated_at = _iso(now)
                self.metrics.bump("leases_expired_reclaimed", job.source_id)
                self._emit(job, "lease_expired", detail="lease expired before completion", now=now)
                reclaimed += 1
        return reclaimed

    def claim(self, job_id: str, *, owner: Optional[str] = None,
              now: Optional[datetime] = None) -> CollectionJob:
        """
        Take a lease on a job. Raises if the job is not leasable or another
        worker holds a live lease.
        """
        moment = now or utcnow()
        owner_id = owner or self.worker_id
        job = self.get_job(job_id)
        self._reclaim_expired_leases(moment)

        if job.is_terminal:
            raise JobNotLeasableError(f"Job {job_id} is in terminal state {job.state.value}")
        if job.state == JobState.LEASED and job.lease_owner != owner_id:
            raise LeaseConflictError(
                f"Job {job_id} is leased by {job.lease_owner} until {job.lease_expires_at}"
            )
        if job.next_attempt_at and datetime.fromisoformat(job.next_attempt_at) > moment:
            raise JobNotLeasableError(
                f"Job {job_id} is not due until {job.next_attempt_at}"
            )

        breaker = self.breaker_for(job.source_id)
        if not breaker.allow_request(moment):
            self.metrics.bump("breaker_open_rejections", job.source_id)
            job.state = JobState.ABANDONED
            job.updated_at = _iso(moment)
            job.last_error = f"circuit breaker open for source {job.source_id}"
            job.last_error_at = _iso(moment)
            self.metrics.bump("jobs_abandoned", job.source_id)
            self._emit(job, "state_terminal", detail="abandoned: circuit breaker open", now=moment)
            raise JobNotLeasableError(
                f"Job {job_id} abandoned: circuit breaker open for {job.source_id}"
            )
        breaker.record_probe()

        job.state = JobState.LEASED
        job.lease_owner = owner_id
        job.lease_expires_at = _iso(moment + timedelta(seconds=self.retry_policy.lease_seconds))
        job.updated_at = _iso(moment)
        self._emit(job, "leased", detail=f"owner={owner_id}", now=moment)
        return job

    # ------------------------------------------------------------ execution

    def execute(
        self,
        job_id: str,
        handler: Handler,
        *,
        owner: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> CollectionJob:
        """
        Claim and run one job synchronously.

        The handler receives the job and must return a summary dict. Raising
        any exception counts as a failed attempt; the job is retried up to
        ``max_attempts`` with bounded exponential backoff, then fails
        terminally.
        """
        moment = now or utcnow()
        job = self.claim(job_id, owner=owner, now=moment)

        job.state = JobState.RUNNING
        job.attempts += 1
        job.updated_at = _iso(moment)
        self.metrics.bump("attempts_started", job.source_id)
        self._emit(job, "attempt_started", detail=f"attempt {job.attempts}", now=moment)

        breaker = self.breaker_for(job.source_id)
        try:
            summary = handler(job)
        except Exception as exc:  # noqa: BLE001 - deliberate: handler failures are data
            return self._handle_failure(job, exc, breaker, moment)

        if not isinstance(summary, dict):
            return self._handle_failure(
                job,
                TypeError(f"handler must return a dict, got {type(summary).__name__}"),
                breaker,
                moment,
            )

        if breaker.record_success():
            self._emit(job, "breaker_closed", detail="source recovered", now=moment)

        job.state = JobState.SUCCEEDED
        job.result_summary = summary
        job.last_error = None
        job.lease_owner = None
        job.lease_expires_at = None
        job.updated_at = _iso(moment)
        self.metrics.bump("attempts_succeeded", job.source_id)
        self._emit(job, "attempt_succeeded", detail=f"attempt {job.attempts}", now=moment)
        self._emit(job, "state_terminal", detail="succeeded", now=moment)
        return job

    def _handle_failure(
        self,
        job: CollectionJob,
        exc: BaseException,
        breaker: SourceCircuitBreaker,
        moment: datetime,
    ) -> CollectionJob:
        detail = _truncate_error(exc)
        job.last_error = detail
        job.last_error_at = _iso(moment)
        job.lease_owner = None
        job.lease_expires_at = None
        self.metrics.bump("attempts_failed", job.source_id)
        self._emit(job, "attempt_failed", detail=detail, now=moment)

        opened = breaker.record_failure(moment)
        if opened:
            self.metrics.bump("breaker_open_events", job.source_id)
            self._emit(job, "breaker_opened",
                       detail=f"source {job.source_id} exceeded failure threshold", now=moment)

        if job.attempts >= job.max_attempts:
            job.state = JobState.FAILED
            job.updated_at = _iso(moment)
            self.metrics.bump("jobs_failed_terminal", job.source_id)
            self._emit(job, "state_terminal",
                       detail=f"failed: {job.attempts}/{job.max_attempts} attempts exhausted",
                       now=moment)
            return job

        delay = self.retry_policy.delay_for_attempt(job.attempts, rng=self._rng)
        job.state = JobState.RETRY_SCHEDULED
        job.next_attempt_at = _iso(moment + timedelta(seconds=delay))
        job.updated_at = _iso(moment)
        self.metrics.bump("retries_scheduled", job.source_id)
        self._emit(job, "retry_scheduled",
                   detail=f"next attempt in {delay:.1f}s", now=moment)
        return job

    def run_pending(
        self,
        handler: Handler,
        *,
        tenant_id: Optional[str] = None,
        now: Optional[datetime] = None,
        max_jobs: Optional[int] = None,
    ) -> List[CollectionJob]:
        """
        Execute every job that is due right now, in priority order.

        This runs **synchronously** and returns when the due set is exhausted
        (or ``max_jobs`` is reached). Nothing is scheduled for later; a caller
        must invoke this again after the next backoff interval.
        """
        moment = now or utcnow()
        self._reclaim_expired_leases(moment)

        due: List[CollectionJob] = []
        for job in self.list_jobs(tenant_id=tenant_id, include_terminal=False):
            if job.state not in (JobState.PENDING, JobState.RETRY_SCHEDULED, JobState.LEASED):
                continue
            if job.next_attempt_at and datetime.fromisoformat(job.next_attempt_at) > moment:
                continue
            due.append(job)

        executed: List[CollectionJob] = []
        for job in due:
            if max_jobs is not None and len(executed) >= max_jobs:
                break
            try:
                executed.append(self.execute(job.job_id, handler, now=moment))
            except (JobNotLeasableError, LeaseConflictError) as exc:
                # Breaker-open abandonment or a concurrent lease: record and move on.
                self._emit(self.get_job(job.job_id), "attempt_failed",
                           detail=f"not executed: {exc}", now=moment)
        return executed

    # -------------------------------------------------------------- expiry

    def expire_overdue_jobs(self, *, now: Optional[datetime] = None) -> List[CollectionJob]:
        """Move non-terminal jobs past their TTL into the terminal EXPIRED state."""
        moment = now or utcnow()
        expired: List[CollectionJob] = []
        for job in list(self._jobs.values()):
            if job.is_terminal or not job.expires_at:
                continue
            if datetime.fromisoformat(job.expires_at) <= moment:
                job.state = JobState.EXPIRED
                job.updated_at = _iso(moment)
                job.lease_owner = None
                job.lease_expires_at = None
                self.metrics.bump("jobs_expired", job.source_id)
                self._emit(job, "job_expired", detail="ttl elapsed before success", now=moment)
                expired.append(job)
        return expired

    def abandon(self, job_id: str, *, reason: str = "operator_decision",
                now: Optional[datetime] = None) -> CollectionJob:
        """Operator-driven terminal abandonment of a non-terminal job."""
        moment = now or utcnow()
        job = self.get_job(job_id)
        if job.is_terminal:
            raise JobNotLeasableError(f"Job {job_id} is already terminal ({job.state.value})")
        job.state = JobState.ABANDONED
        job.updated_at = _iso(moment)
        job.last_error = f"abandoned: {reason}"[:_MAX_ERROR_DETAIL_LENGTH]
        job.last_error_at = _iso(moment)
        job.lease_owner = None
        job.lease_expires_at = None
        self.metrics.bump("jobs_abandoned", job.source_id)
        self._emit(job, "state_terminal", detail=f"abandoned: {reason}", now=moment)
        return job

    # --------------------------------------------------------- observability

    def health_snapshot(self, *, now: Optional[datetime] = None) -> Dict[str, Any]:
        """Aggregate health view suitable for an operations dashboard."""
        moment = now or utcnow()
        self._reclaim_expired_leases(moment)
        counts: Dict[str, int] = {s.value: 0 for s in JobState}
        for job in self._jobs.values():
            counts[job.state.value] += 1
        return {
            "worker_id": self.worker_id,
            "generated_at": _iso(moment),
            "total_jobs": len(self._jobs),
            "state_counts": counts,
            "terminal_jobs": sum(counts[s.value] for s in TERMINAL_STATES),
            "metrics": self.metrics.model_dump(),
            "breakers": self.breaker_snapshots(),
            "verification_mode": "fixture_tested",
            "experimental_label": EXPERIMENTAL_DEMO_DATA_ONLY,
            "note": "snapshot only - no worker process is running",
        }

    def export_state(self) -> Dict[str, Any]:
        """Serializable snapshot of jobs, breakers and metrics (for persistence)."""
        return {
            "worker_id": self.worker_id,
            "jobs": [j.model_dump(mode="json") for j in self._jobs.values()],
            "breakers": self.breaker_snapshots(),
            "metrics": self.metrics.model_dump(),
            "events": [e.model_dump(mode="json") for e in self._events],
        }

    @staticmethod
    def derive_idempotency_key(tenant_id: str, source_id: str, kind: str,
                               payload: Optional[Dict[str, Any]] = None) -> str:
        """Stable, collision-resistant idempotency key for a logical job."""
        return derive_idempotency_key(tenant_id, source_id, kind, payload)


def json_dumps_canonical(obj: Any) -> str:
    """Canonical JSON serialization: sorted keys, no insignificant whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def derive_idempotency_key(tenant_id: str, source_id: str, kind: str,
                           payload: Optional[Dict[str, Any]] = None) -> str:
    """
    Stable, collision-resistant idempotency key for a logical job.

    Payload key ordering does not affect the result, so two callers describing
    the same logical sync derive the same key.
    """
    material = json_dumps_canonical({
        "tenant_id": tenant_id,
        "source_id": source_id,
        "kind": kind,
        "payload": payload or {},
    })
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]
