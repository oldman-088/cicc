"""Persistent freshness: source synchronization state and observation age.

Two different questions were being answered by one function, and neither answer was
stored:

1. **Is the source synchronising?** Answered by the checkpoint (``completed_at``,
   ``attempted_at``) and turned into a health verdict at read time.
2. **Is this record stale?** Answered by ``compute_freshness`` at read time and never
   persisted.

Both are computed values and both are correctly *not* frozen into a record — freshness
relative to "now" would be wrong the moment it was written. What was missing is the
*inputs*: an operator could not see, from stored state, when a source last succeeded,
when it was last attempted, and therefore whether a stale record means "the feed is
broken" or "the advisory is simply old".

This module stores those inputs and derives the state, so the same facts reach a health
report, a JSON payload and an API response without a layer discarding them in between.

The distinction it exists to make, in the caller's terms:

``never_succeeded``
    The source has never completed a sync. Something is wrong with configuration or
    credentials; retrying will not help. Maps to ``unavailable``.

``failed``
    A previously working source is failing now. Data collected earlier is still being
    served. Maps to ``degraded``, and the age of the last success is the thing to look
    at.

Collapsing those two — which happened when a failure overwrote ``completed_at`` and
again when a projection discarded it — makes a week-old outage look like a fresh,
healthy, empty feed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping

from .schema import (
    CollectionStatus,
    Freshness,
    compute_freshness,
    utcnow,
)

__all__ = [
    "FRESHNESS_SCHEMA",
    "FreshnessState",
    "ObservationFreshness",
    "SourceSynchronisation",
    "describe_freshness",
]

#: Bumped when the persisted shape changes incompatibly.
FRESHNESS_SCHEMA = "cicc.vuln_intel.freshness.v1"


class FreshnessState:
    """Explicit, exhaustive freshness states.

    Listed rather than implied so a consumer can assert on them and a test can prove
    every one is reachable. ``UNKNOWN`` is a state, not a missing value: it means the
    inputs needed to decide are absent, and it must never render as fresh.
    """

    #: Synchronising normally and the data is within its freshness window.
    FRESH = "fresh"
    #: Synchronising, but the newest data is older than the window.
    STALE = "stale"
    #: The source failed at least once and has succeeded before; old data is served.
    FAILED = "failed"
    #: The source has never completed a sync.
    NEVER_SUCCEEDED = "never_succeeded"
    #: No source is configured, so nothing can be assessed.
    NOT_CONFIGURED = "not_configured"
    #: Inputs missing; deliberately distinct from every other state.
    UNKNOWN = "unknown"

    ALL = (
        FRESH,
        STALE,
        FAILED,
        NEVER_SUCCEEDED,
        NOT_CONFIGURED,
        UNKNOWN,
    )


@dataclass(frozen=True)
class SourceSynchronisation:
    """What we know about one source's synchronisation history.

    ``last_success`` and ``last_attempt`` are separate because the Master Prompt lists
    them as separate requirements, and because the gap between them is the signal: a
    source attempted a minute ago and last succeeded a week ago is an outage in
    progress.
    """

    source: str
    last_success: datetime | None = None
    last_attempt: datetime | None = None
    consecutive_failures: int = 0
    last_error: str | None = None
    status: CollectionStatus | None = None

    @property
    def has_ever_succeeded(self) -> bool:
        return self.last_success is not None

    @property
    def is_failing(self) -> bool:
        return self.consecutive_failures > 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "last_success": self.last_success.isoformat() if self.last_success else None,
            "last_attempt": self.last_attempt.isoformat() if self.last_attempt else None,
            "consecutive_failures": self.consecutive_failures,
            "last_error": self.last_error,
            "status": self.status.value if self.status else None,
            "has_ever_succeeded": self.has_ever_succeeded,
        }


@dataclass(frozen=True)
class ObservationFreshness:
    """Persisted freshness metadata for one observation or record.

    ``observed_at`` and ``observed_source`` say which source's success the age is
    measured against, so a record corroborated by a healthy source and a broken one is
    not averaged into a single misleading age.
    """

    observed_at: datetime | None = None
    observed_source: str | None = None
    #: The source's synchronisation state at the time this was recorded. Stored because
    #: the *state* is a fact about the collection, whereas the derived bucket is not.
    source_state: SourceSynchronisation | None = None
    state: str = FreshnessState.UNKNOWN
    detail: str | None = None
    assessed_at: datetime | None = None
    fresh_within: timedelta = timedelta(hours=24)
    stale_after: timedelta = timedelta(days=7)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": FRESHNESS_SCHEMA,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "observed_source": self.observed_source,
            "source_state": self.source_state.as_dict() if self.source_state else None,
            "state": self.state,
            "detail": self.detail,
            "assessed_at": self.assessed_at.isoformat() if self.assessed_at else None,
            "age_seconds": self.age.total_seconds() if self.age else None,
        }

    @property
    def age(self) -> timedelta | None:
        if self.observed_at is None or self.assessed_at is None:
            return None
        return self.assessed_at - self.observed_at

    @property
    def is_serving(self) -> bool:
        """True when a consumer may show this data as current."""
        return self.state in (FreshnessState.FRESH, FreshnessState.STALE, FreshnessState.FAILED)

    @property
    def bucket(self) -> Freshness:
        """The age classification, independent of source health."""
        return compute_freshness(
            self.observed_at,
            now=self.assessed_at,
            fresh_within=self.fresh_within,
            stale_after=self.stale_after,
        )


def describe_freshness(
    *,
    observed_at: datetime | None,
    source_state: SourceSynchronisation | None = None,
    now: datetime | None = None,
    fresh_within: timedelta = timedelta(hours=24),
    stale_after: timedelta = timedelta(days=7),
    configured: bool = True,
) -> ObservationFreshness:
    """Derive the freshness state, and say why.

    Order of precedence matters and is deliberate: a source that has never succeeded is
    reported as ``never_succeeded`` **even if** some observation is recent (it cannot
    be, but a caller could pass a contradictory pair, and configuration truth outranks
    data truth). A failing source outranks a stale bucket, because "the feed is broken"
    is more actionable than "the data is old" — and in that case the data being old is
    a consequence, not a second finding.
    """
    moment = now or utcnow()

    if not configured:
        return ObservationFreshness(
            observed_at=observed_at,
            source_state=source_state,
            state=FreshnessState.NOT_CONFIGURED,
            detail="no source configured: freshness cannot be assessed",
            assessed_at=moment,
            fresh_within=fresh_within,
            stale_after=stale_after,
        )

    if source_state is not None and not source_state.has_ever_succeeded:
        return ObservationFreshness(
            observed_at=observed_at,
            observed_source=source_state.source,
            source_state=source_state,
            state=FreshnessState.NEVER_SUCCEEDED,
            detail=(
                "source has never completed a sync"
                + (f": {source_state.last_error}" if source_state.last_error else "")
            ),
            assessed_at=moment,
            fresh_within=fresh_within,
            stale_after=stale_after,
        )

    if source_state is not None and source_state.is_failing:
        age = (
            moment - source_state.last_success
            if source_state.last_success is not None
            else None
        )
        return ObservationFreshness(
            observed_at=observed_at,
            observed_source=source_state.source,
            source_state=source_state,
            state=FreshnessState.FAILED,
            detail=(
                f"{source_state.consecutive_failures} consecutive failure(s)"
                + (
                    f"; last success {_render_age(age)} ago, serving data collected then"
                    if age is not None
                    else ""
                )
                + (f"; {source_state.last_error}" if source_state.last_error else "")
            ),
            assessed_at=moment,
            fresh_within=fresh_within,
            stale_after=stale_after,
        )

    if observed_at is None:
        return ObservationFreshness(
            observed_at=None,
            observed_source=source_state.source if source_state else None,
            source_state=source_state,
            state=FreshnessState.UNKNOWN,
            detail="no observation timestamp: age cannot be assessed",
            assessed_at=moment,
            fresh_within=fresh_within,
            stale_after=stale_after,
        )

    bucket = compute_freshness(
        observed_at, now=moment, fresh_within=fresh_within, stale_after=stale_after
    )
    state = (
        FreshnessState.FRESH
        if bucket.bucket in ("fresh", "recent")
        else FreshnessState.STALE
    )
    return ObservationFreshness(
        observed_at=observed_at,
        observed_source=source_state.source if source_state else None,
        source_state=source_state,
        state=state,
        detail=f"data {_render_age(bucket.age)} old ({bucket.bucket})",
        assessed_at=moment,
        fresh_within=fresh_within,
        stale_after=stale_after,
    )


def _render_age(age: timedelta | None) -> str:
    if age is None:
        return "unknown"
    seconds = int(age.total_seconds())
    if seconds < 0:
        return "in the future"
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days}d"
    if hours:
        return f"{hours}h"
    return f"{minutes}m"


def source_state_from_checkpoint(
    checkpoint: Mapping[str, Any] | Any, *, source: str | None = None
) -> SourceSynchronisation:
    """Build a :class:`SourceSynchronisation` from a checkpoint payload or object.

    Accepts both so a caller holding a persisted dict and a caller holding a
    ``Checkpoint`` get the same semantics — the point of this milestone is that a value
    preserved in one layer must survive the next one.
    """
    if isinstance(checkpoint, Mapping):
        get = checkpoint.get
        name = source or str(get("source") or "unknown")
        return SourceSynchronisation(
            source=name,
            last_success=_as_datetime(get("completed_at")),
            last_attempt=_as_datetime(get("attempted_at")),
            consecutive_failures=int(get("consecutive_failures") or 0),
            last_error=(str(get("last_error")) if get("last_error") else None),
        )
    return SourceSynchronisation(
        source=source or str(getattr(checkpoint, "source", "unknown")),
        last_success=getattr(checkpoint, "completed_at", None),
        last_attempt=getattr(checkpoint, "attempted_at", None),
        consecutive_failures=int(getattr(checkpoint, "consecutive_failures", 0) or 0),
        last_error=getattr(checkpoint, "last_error", None),
    )


def _as_datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None
