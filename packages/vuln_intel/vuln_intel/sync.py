"""Incremental synchronisation with a checkpoint.

A full NVD mirror is ~250k CVEs and hundreds of pages; re-downloading it to learn
what changed since yesterday is operationally indefensible.  NVD API 2.0 offers
``lastModStartDate``/``lastModEndDate`` for exactly this, bounded to a 120-day
window per request.

Two hard rules shape this module:

* **A checkpoint may only advance over a window that completed.**  If page 7 of
  40 fails, the checkpoint must not move past the last fully synced window —
  otherwise the next run silently skips the CVEs in pages 8-40 and the platform
  believes it has data it never saw.
* **The checkpoint records its own evidence** (window, record count, completion
  time, transport kind), so "last synced" is a fact, not a claim.

The clock is injected.  Time-dependent scheduling that reads the wall clock
directly is untestable and produces the classic daylight-saving/skew bugs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Mapping, Protocol, Sequence

from .errors import ValidationError
from .schema import (
    CollectionStatus,
    NormalizedVulnerability,
    SourceKind,
    SourceState,
    utcnow,
)

__all__ = [
    "MAX_WINDOW",
    "Checkpoint",
    "CheckpointStore",
    "FileCheckpointStore",
    "IncrementalSync",
    "SyncOutcome",
    "SyncWindow",
    "plan_windows",
    "to_source_state",
]

#: NVD rejects a lastMod window wider than 120 consecutive days.
MAX_WINDOW = timedelta(days=120)

#: Default sync step.  One day keeps each window small enough that a failure
#: costs hours of re-fetching, not months.
DEFAULT_WINDOW = timedelta(days=1)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def _aware(moment: datetime, *, field_name: str) -> datetime:
    if moment.tzinfo is None:
        raise ValidationError("timestamps must be timezone-aware", field=field_name)
    return moment.astimezone(timezone.utc)


@dataclass(frozen=True)
class SyncWindow:
    """A half-open ``[start, end)`` modification window."""

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        _aware(self.start, field_name="start")
        _aware(self.end, field_name="end")
        if self.end <= self.start:
            raise ValidationError("sync window end must be after start", field="end")
        if self.end - self.start > MAX_WINDOW:
            raise ValidationError(
                f"sync window exceeds {MAX_WINDOW.days} days", field="end"
            )

    def params(self) -> dict[str, str]:
        """Query parameters in the format NVD documents."""
        return {"lastModStartDate": _iso(self.start), "lastModEndDate": _iso(self.end)}

    def as_dict(self) -> dict[str, str]:
        return {"start": self.start.isoformat(), "end": self.end.isoformat()}


def plan_windows(
    since: datetime,
    until: datetime,
    *,
    step: timedelta = DEFAULT_WINDOW,
) -> list[SyncWindow]:
    """Split ``[since, until]`` into aligned windows, newest-safe ordering.

    Raises if the range is inverted rather than returning an empty plan, because
    an empty plan looks identical to "nothing to do".
    """
    since = _aware(since, field_name="since")
    until = _aware(until, field_name="until")
    if until <= since:
        raise ValidationError("'until' must be after 'since'", field="until")
    if step <= timedelta(0):
        raise ValidationError("step must be positive", field="step")
    if step > MAX_WINDOW:
        step = MAX_WINDOW
    windows: list[SyncWindow] = []
    cursor = since
    while cursor < until:
        boundary = min(cursor + step, until)
        windows.append(SyncWindow(start=cursor, end=boundary))
        cursor = boundary
    return windows


def _as_int(value: object, field_name: str) -> int:
    """Strict integer coercion: a corrupted checkpoint must not silently read 0."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        if value is None:
            return 0
        raise ValidationError(f"checkpoint field {field_name!r} is not an integer", field=field_name)
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(
            f"checkpoint field {field_name!r} is not an integer", field=field_name
        ) from exc


@dataclass(frozen=True)
class Checkpoint:
    """Evidence that a source has been synchronised up to a point in time.

    ``watermark`` is the *end* of the last fully completed window.  A CVE
    modified exactly at the watermark is not lost: the next window starts there
    and NVD's bounds are inclusive on both ends.
    """

    source: str
    watermark: datetime | None = None
    records: int = 0
    completed_at: datetime | None = None
    transport: str = "unknown"
    origin: str = "live"
    consecutive_failures: int = 0
    last_error: str | None = None
    #: Set when a full re-sync is required (schema change, corrupted state).
    invalidated_reason: str | None = None

    def __post_init__(self) -> None:
        if self.watermark is not None:
            _aware(self.watermark, field_name="watermark")
        if self.completed_at is not None:
            _aware(self.completed_at, field_name="completed_at")
        if self.records < 0:
            raise ValidationError("records must be >= 0", field="records")

    def as_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "watermark": self.watermark.isoformat() if self.watermark else None,
            "records": self.records,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "transport": self.transport,
            "origin": self.origin,
            "consecutive_failures": self.consecutive_failures,
            "last_error": self.last_error,
            "invalidated_reason": self.invalidated_reason,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> Checkpoint:
        def moment(key: str) -> datetime | None:
            raw = payload.get(key)
            if not isinstance(raw, str) or not raw:
                return None
            text = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
            return datetime.fromisoformat(text)

        source = payload.get("source")
        if not isinstance(source, str) or not source:
            raise ValidationError("checkpoint requires a source", field="source")
        return cls(
            source=source,
            watermark=moment("watermark"),
            records=_as_int(payload.get("records"), "records"),
            completed_at=moment("completed_at"),
            transport=str(payload.get("transport") or "unknown"),
            origin=str(payload.get("origin") or "live"),
            consecutive_failures=_as_int(
                payload.get("consecutive_failures"), "consecutive_failures"
            ),
            last_error=(str(payload["last_error"]) if payload.get("last_error") else None),
            invalidated_reason=(
                str(payload["invalidated_reason"]) if payload.get("invalidated_reason") else None
            ),
        )


class CheckpointStore(Protocol):
    """Where a checkpoint persists.  Kept minimal so a DB adapter can implement it."""

    def load(self, source: str) -> Checkpoint | None:  # pragma: no cover - protocol
        ...

    def save(self, checkpoint: Checkpoint) -> None:  # pragma: no cover - protocol
        ...


@dataclass
class FileCheckpointStore:
    """JSON checkpoint file.

    Written via a temporary file and ``os.replace`` so a crash mid-write cannot
    leave a truncated checkpoint (which would silently reset the watermark).
    """

    path: Path

    def load(self, source: str) -> Checkpoint | None:
        if not self.path.exists():
            return None
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(payload, Mapping):
            return None
        entry = payload.get(source)
        if not isinstance(entry, Mapping):
            return None
        try:
            return Checkpoint.from_dict(entry)
        except (ValidationError, ValueError, TypeError):
            return None

    def save(self, checkpoint: Checkpoint) -> None:
        existing: dict[str, object] = {}
        if self.path.exists():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    existing = loaded
            except (OSError, json.JSONDecodeError):
                existing = {}
        existing[checkpoint.source] = checkpoint.as_dict()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(existing, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        tmp.replace(self.path)


@dataclass(frozen=True)
class SyncOutcome:
    """Result of a sync run: what was collected and how far the checkpoint moved."""

    source: str
    status: CollectionStatus
    records: tuple[NormalizedVulnerability, ...]
    completed_windows: tuple[SyncWindow, ...]
    failed_window: SyncWindow | None
    checkpoint: Checkpoint
    warnings: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return self.failed_window is None and self.status is not CollectionStatus.FAILED

    @property
    def advanced(self) -> bool:
        return bool(self.completed_windows)

    def as_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "status": self.status.value,
            "records": len(self.records),
            "complete": self.complete,
            "completed_windows": [w.as_dict() for w in self.completed_windows],
            "failed_window": self.failed_window.as_dict() if self.failed_window else None,
            "checkpoint": self.checkpoint.as_dict(),
            "warnings": list(self.warnings),
        }


class WindowFetcher(Protocol):
    """Fetches one page of a modification window."""

    def __call__(  # pragma: no cover - protocol
        self, window: SyncWindow, *, start_index: int, page_size: int
    ) -> tuple[Sequence[NormalizedVulnerability], bool, str | None]:
        """Return ``(records, exhausted, error)`` for one page."""
        ...


@dataclass
class IncrementalSync:
    """Drives paginated window fetching and checkpoint maintenance.

    ``fetch`` is injected so the connector (and tests) decide how a page is
    obtained.  The sync engine owns only the invariants that are easy to get
    wrong: window ordering, page ordering, partial-failure handling and the rule
    that a checkpoint advances only over completed windows.
    """

    source: str
    fetch: WindowFetcher
    store: CheckpointStore
    clock: Callable[[], datetime] = field(default=utcnow)
    page_size: int = 200
    max_pages_per_window: int = 50
    lookback_overlap: timedelta = timedelta(hours=1)

    def __post_init__(self) -> None:
        if not 1 <= self.page_size <= 2000:
            raise ValidationError("page_size must be within 1-2000", field="page_size")

    def _now(self) -> datetime:
        now = self.clock() if callable(self.clock) else utcnow()
        _aware(now, field_name="now")
        return now

    def run(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        step: timedelta = DEFAULT_WINDOW,
        max_windows: int | None = None,
    ) -> SyncOutcome:
        now = self._now()
        checkpoint = self.store.load(self.source) or Checkpoint(source=self.source)
        until = _aware(until, field_name="until") if until else now
        if since is None:
            # Re-read a little before the watermark: NVD's lastModified is written
            # by a batch process and can lag a record's own timestamp, so an
            # overlap costs a few duplicate records and prevents a missed CVE.
            since = (
                checkpoint.watermark - self.lookback_overlap
                if checkpoint.watermark
                else now - DEFAULT_WINDOW
            )
        windows = plan_windows(since, until, step=step)
        if max_windows is not None:
            windows = windows[: max(0, max_windows)]

        collected: list[NormalizedVulnerability] = []
        completed: list[SyncWindow] = []
        warnings: list[str] = []
        failed: SyncWindow | None = None
        failed_error: str | None = None

        for window in windows:
            records, error, exhausted = self._run_window(window)
            if error is not None:
                failed, failed_error = window, error
                warnings.append(f"window {window.start.date()}: {error}; checkpoint held")
                break
            collected.extend(records)
            if not exhausted:
                # The window hit its page cap, so it is *not* fully synced.  Both
                # lists must reflect that: advancing the watermark here would mark
                # records still sitting in unfetched pages as already collected.
                failed, failed_error = window, "page budget exhausted"
                warnings.append(
                    f"window {window.start.date()} exhausted its page budget; "
                    "remaining pages deferred to the next run"
                )
                break
            completed.append(window)

        new_checkpoint = self._advance(
            checkpoint, completed, failed, failed_error, len(collected)
        )
        self.store.save(new_checkpoint)

        if failed is not None and not completed and not collected:
            status = CollectionStatus.FAILED
        elif failed is not None or warnings:
            # Records were collected but coverage is incomplete; PARTIAL states
            # both facts instead of implying a clean run.
            status = CollectionStatus.PARTIAL
        else:
            status = CollectionStatus.OK
        return SyncOutcome(
            source=self.source,
            status=status,
            records=tuple(collected),
            completed_windows=tuple(completed),
            failed_window=failed,
            checkpoint=new_checkpoint,
            warnings=tuple(warnings),
        )

    def _run_window(
        self, window: SyncWindow
    ) -> tuple[list[NormalizedVulnerability], str | None, bool]:
        records: list[NormalizedVulnerability] = []
        seen: set[str] = set()
        for page in range(self.max_pages_per_window):
            batch, exhausted, error = self.fetch(
                window, start_index=page * self.page_size, page_size=self.page_size
            )
            if error is not None:
                return records, error, False
            for record in batch:
                key = str(record.cve)
                # Overlapping windows legitimately return the same CVE twice.
                if key in seen:
                    continue
                seen.add(key)
                records.append(record)
            if exhausted:
                return records, None, True
        return records, None, False

    def _advance(
        self,
        checkpoint: Checkpoint,
        completed: Sequence[SyncWindow],
        failed: SyncWindow | None,
        failed_error: str | None,
        count: int,
    ) -> Checkpoint:
        if not completed:
            detail = (
                f"no window completed; failed at {failed.start.isoformat()}"
                + (f": {failed_error}" if failed_error else "")
                if failed
                else checkpoint.last_error
            )
            return replace(
                checkpoint,
                consecutive_failures=checkpoint.consecutive_failures + 1,
                last_error=detail,
                completed_at=self._now(),
            )
        watermark = completed[-1].end
        if failed is not None and failed.start < watermark:
            # Defensive: a failed window can never lie before the watermark.
            watermark = failed.start
        return replace(
            checkpoint,
            watermark=watermark,
            records=checkpoint.records + count,
            completed_at=self._now(),
            consecutive_failures=0,
            last_error=None,
        )


def to_source_state(
    outcome: SyncOutcome, *, kind: SourceKind, now: datetime | None = None
) -> SourceState:
    """Project a sync outcome onto the schema's collection state.

    This is the join between collection and observability: without it a sync
    run cannot feed the health report, and readiness would silently ignore the
    source that actually collects the data.
    """
    return SourceState(
        kind=kind,
        status=outcome.status,
        checked_at=now or utcnow(),
        last_success=outcome.checkpoint.completed_at if outcome.advanced else None,
        error="; ".join(outcome.warnings[:3]) or None,
        records=len(outcome.records),
    )
