"""Health, readiness and operational metrics.

The platform's health dashboard must be able to distinguish three states that
are easy to conflate and expensive to confuse:

``OK``            a real collection succeeded recently;
``DEGRADED``      only cached data is being served, and we can say how old it is;
``UNAVAILABLE``   nothing usable: never collected, or everything expired.

Nothing here probes the network.  A health check that performs I/O is a health
check that fails during an incident, which is exactly when it is needed.  The
report is derived from recorded outcomes (``SourceState``, KEV cache age, EPSS
provider availability), so it is cheap, deterministic and safe to call from a
liveness probe.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Iterable, Mapping, Sequence

from .schema import CollectionStatus, SourceKind, SourceState, utcnow

__all__ = [
    "ComponentHealth",
    "HealthReport",
    "Readiness",
    "SourceHealth",
    "build_health_report",
]


class ComponentHealth(str, Enum):
    OK = "ok"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    NOT_CONFIGURED = "not_configured"

    @property
    def is_serving(self) -> bool:
        return self in (ComponentHealth.OK, ComponentHealth.DEGRADED)


class Readiness(str, Enum):
    """What the subsystem can currently do, in the caller's terms."""

    READY = "ready"  # fresh data from every required source
    DEGRADED = "degraded"  # serving something, but stale or incomplete
    NOT_READY = "not_ready"  # no usable data


@dataclass(frozen=True)
class SourceHealth:
    kind: str
    health: ComponentHealth
    age: timedelta | None
    last_success: datetime | None
    detail: str

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "health": self.health.value,
            "age_seconds": round(self.age.total_seconds(), 1) if self.age else None,
            "last_success": self.last_success.isoformat() if self.last_success else None,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class HealthReport:
    readiness: Readiness
    checked_at: datetime
    sources: tuple[SourceHealth, ...]
    warnings: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "readiness": self.readiness.value,
            "checked_at": self.checked_at.isoformat(),
            "sources": [s.as_dict() for s in self.sources],
            "warnings": list(self.warnings),
        }

    @property
    def http_status(self) -> int:
        """Suggested status for a ``/health`` endpoint."""
        return 200 if self.readiness is not Readiness.NOT_READY else 503


#: How old data may be before it stops counting as fresh, per source.  NVD and
#: KEV publish daily; EPSS publishes daily; OSV updates continuously.
DEFAULT_FRESHNESS: Mapping[str, timedelta] = {
    SourceKind.NVD.value: timedelta(days=2),
    SourceKind.OSV.value: timedelta(days=2),
    "cisa-kev": timedelta(days=3),
    SourceKind.EPSS.value: timedelta(days=2),
}

_UNCONFIGURED_HINT = (
    "no transport or credentials configured: this source has never been collected"
)


def _health_for_state(
    state: SourceState,
    *,
    now: datetime,
    fresh_within: timedelta,
    required: bool,
) -> SourceHealth:
    age = None
    if state.last_success is not None:
        age = now - state.last_success
    if state.status is CollectionStatus.NOT_CONFIGURED:
        return SourceHealth(
            kind=state.kind.value,
            health=ComponentHealth.NOT_CONFIGURED,
            age=age,
            last_success=state.last_success,
            detail=_UNCONFIGURED_HINT,
        )
    if state.status is CollectionStatus.OK:
        if age is not None and age > fresh_within:
            return SourceHealth(
                kind=state.kind.value,
                health=ComponentHealth.DEGRADED,
                age=age,
                last_success=state.last_success,
                detail=f"last success {age.days}d ago: data is stale",
            )
        return SourceHealth(
            kind=state.kind.value,
            health=ComponentHealth.OK,
            age=age,
            last_success=state.last_success,
            detail="collecting normally",
        )
    if state.status is CollectionStatus.PARTIAL:
        return SourceHealth(
            kind=state.kind.value,
            health=ComponentHealth.DEGRADED,
            age=age,
            last_success=state.last_success,
            detail=f"partial collection: {state.error or 'some records failed to parse'}",
        )
    # FAILED
    if state.last_success is not None:
        return SourceHealth(
            kind=state.kind.value,
            health=ComponentHealth.DEGRADED,
            age=age,
            last_success=state.last_success,
            detail=(
                f"collection failed ({state.error or 'unknown error'}); "
                "serving previously collected data"
            ),
        )
    return SourceHealth(
        kind=state.kind.value,
        health=ComponentHealth.UNAVAILABLE,
        age=None,
        last_success=None,
        detail=f"collection failed and no earlier data exists: {state.error or 'unknown error'}"
        + ("" if required else " (source not required)"),
    )


def build_health_report(
    states: Iterable[SourceState],
    *,
    kev_age: timedelta | None = None,
    epss_available: bool = False,
    now: datetime | None = None,
    required_sources: Sequence[str] = (SourceKind.NVD.value, "cisa-kev"),
) -> HealthReport:
    """Derive an honest health report from recorded collection outcomes."""
    now = now or utcnow()
    required = {s.lower() for s in required_sources}
    sources: list[SourceHealth] = []
    warnings: list[str] = []

    seen: set[str] = set()
    for state in states:
        seen.add(state.kind.value)
        fresh = DEFAULT_FRESHNESS.get(state.kind.value, timedelta(days=2))
        sources.append(
            _health_for_state(
                state,
                now=now,
                fresh_within=fresh,
                required=state.kind.value in required,
            )
        )

    if kev_age is not None and "cisa-kev" not in seen:
        fresh = DEFAULT_FRESHNESS["cisa-kev"]
        sources.append(
            SourceHealth(
                kind="cisa-kev",
                health=ComponentHealth.OK if kev_age <= fresh else ComponentHealth.DEGRADED,
                age=kev_age,
                last_success=now - kev_age,
                detail="catalogue cache in use"
                + ("" if kev_age <= fresh else ": catalogue is stale"),
            )
        )
    if not epss_available:
        warnings.append(
            "EPSS provider unavailable: exploitation forecast omitted, not assumed zero"
        )

    serving = [s for s in sources if s.health.is_serving]
    blocking = [
        s for s in sources if s.kind in required and s.health is ComponentHealth.UNAVAILABLE
    ]
    if blocking:
        readiness = Readiness.NOT_READY
        warnings.append(
            "required sources unavailable: " + ", ".join(s.kind for s in blocking)
        )
    elif not serving:
        readiness = Readiness.NOT_READY
    elif any(s.health is not ComponentHealth.OK for s in sources):
        readiness = Readiness.DEGRADED
    else:
        readiness = Readiness.READY

    return HealthReport(
        readiness=readiness,
        checked_at=now,
        sources=tuple(sources),
        warnings=tuple(warnings),
    )


@dataclass
class Metrics:
    """Counters for a metrics endpoint.  In-process, monotonic, cheap."""

    counters: dict[str, int] = field(default_factory=dict)
    gauges: dict[str, float] = field(default_factory=dict)
    started_at: datetime = field(default_factory=utcnow)

    def increment(self, name: str, amount: int = 1) -> None:
        self.counters[name] = self.counters.get(name, 0) + amount

    def gauge(self, name: str, value: float) -> None:
        self.gauges[name] = float(value)

    def record_collection(self, state: SourceState) -> None:
        self.increment(f"collect.{state.kind.value}.attempt")
        self.increment(f"collect.{state.kind.value}.{state.status.value}")
        self.gauge(f"collect.{state.kind.value}.records", state.records)
        if state.last_success is not None:
            self.gauge(
                f"collect.{state.kind.value}.last_success_epoch",
                state.last_success.timestamp(),
            )

    def as_dict(self) -> dict[str, object]:
        return {
            "counters": dict(sorted(self.counters.items())),
            "gauges": {k: round(v, 3) for k, v in sorted(self.gauges.items())},
            "uptime_seconds": round((utcnow() - self.started_at).total_seconds(), 1),
        }


def connector_health(
    kind: SourceKind | str,
    *,
    last_attempt: datetime | None,
    last_success: datetime | None,
    error: str | None = None,
    now: datetime | None = None,
    fresh_within: timedelta = timedelta(days=2),
    required: bool = False,
) -> SourceHealth:
    """Health for a whole-document connector (Debian tracker, Ubuntu USN, GHSA).

    These connectors track ``last_attempt``/``last_success`` directly instead of
    going through a sync checkpoint; this projects those two timestamps onto the
    same :class:`SourceHealth` vocabulary, so "never succeeded" (UNAVAILABLE),
    "failed after good data" (DEGRADED, serving previous data) and "stale but
    healthy" are distinguished exactly as for checkpointed sources.
    """
    moment = now or utcnow()
    if last_attempt is None:
        status = CollectionStatus.NOT_CONFIGURED
    elif last_success is not None and last_success >= last_attempt:
        status = CollectionStatus.OK
    else:
        # the most recent attempt did not succeed (or nothing ever did): FAILED,
        # so _health_for_state can split "failed after good data" (DEGRADED) from
        # "never succeeded" (UNAVAILABLE)
        status = CollectionStatus.FAILED
    state = SourceState(
        kind=kind if isinstance(kind, SourceKind) else SourceKind(str(kind)),
        status=status,
        checked_at=moment,
        last_success=last_success,
        last_attempt=last_attempt,
        error=error,
    )
    return _health_for_state(state, now=moment, fresh_within=fresh_within, required=required)
