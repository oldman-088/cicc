"""B-11: bounded historical backfill with resume, idempotency and safe abort.

A backfill is a one-shot (or resumed) full import of a source's history, split
into windows.  It reuses the same machinery as incremental sync —
:class:`~vuln_intel.sync.SyncWindow`, :class:`~vuln_intel.sync.Checkpoint`,
:class:`~vuln_intel.sync.CheckpointStore` — because the hard parts (window
planning, atomic checkpoints, last-success vs last-attempted) already exist and
are tested.  What this module adds is the *operator* behaviour:

* **bounded**: an explicit window list; never "everything since the beginning";
* **resumable**: the checkpoint watermark is advanced only over fully completed
  windows, so a restart replays exactly the unfinished tail;
* **idempotent**: records go through the append-only observation log, whose
  (tenant, source, cve, digest) identity collapses replays — duplicates are
  *counted*, never deleted, and never rewrite existing rows;
* **never regressive**: an older observation cannot overwrite a newer one —
  that rule lives in the store and is mirrored here by only ever *appending*;
* **dry-run by default**: ``dry_run=True`` plans and reports without calling
  the fetcher, writing the checkpoint, or appending observations;
* **safe interruption**: ``should_stop`` is polled between windows; the
  checkpoint on disk always reflects only completed windows.

No network, threads or sleeps here: the fetcher is injected, the clock is
injected, and interruption is cooperative.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Sequence

from .errors import MixedOriginError, ValidationError
from .integration.observations import ObservationLog, to_observations
from .schema import NormalizedVulnerability, utcnow
from .sync import Checkpoint, CheckpointStore, SyncWindow, plan_windows

__all__ = [
    "BackfillProgress",
    "BackfillReport",
    "BackfillRunner",
    "BackfillWindowResult",
    "plan_backfill",
    "progress_view",
]


def plan_backfill(
    since: datetime,
    until: datetime,
    *,
    step: timedelta,
) -> list[SyncWindow]:
    """Plan the bounded windows for a backfill (thin wrapper over plan_windows)."""
    return plan_windows(since, until, step=step)


@dataclass(frozen=True)
class BackfillWindowResult:
    """Outcome of one window."""

    window: SyncWindow
    outcome: str  # "done" | "failed" | "skipped" | "planned"
    records: int = 0
    appended: int = 0
    duplicates: int = 0
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "window": self.window.as_dict(),
            "outcome": self.outcome,
            "records": self.records,
            "appended": self.appended,
            "duplicates": self.duplicates,
            "error": self.error,
        }


@dataclass(frozen=True)
class BackfillReport:
    """The operator-facing summary of one backfill run."""

    source: str
    dry_run: bool
    windows_total: int
    windows_done: int
    windows_failed: int
    windows_skipped: int
    records: int
    appended: int
    duplicates: int
    interrupted: bool
    watermark: datetime | None
    results: tuple[BackfillWindowResult, ...] = ()

    @property
    def complete(self) -> bool:
        return (
            not self.dry_run
            and not self.interrupted
            and self.windows_failed == 0
            and self.windows_done + self.windows_skipped == self.windows_total
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "dry_run": self.dry_run,
            "windows_total": self.windows_total,
            "windows_done": self.windows_done,
            "windows_failed": self.windows_failed,
            "windows_skipped": self.windows_skipped,
            "records": self.records,
            "appended": self.appended,
            "duplicates": self.duplicates,
            "interrupted": self.interrupted,
            "complete": self.complete,
            "watermark": self.watermark.isoformat() if self.watermark else None,
            "results": [r.as_dict() for r in self.results],
        }


class BackfillRunner:
    """Run a bounded backfill over injected windows.

    Parameters
    ----------
    source:
        Checkpoint/source name, e.g. ``"nvd"``.
    fetcher:
        ``fetcher(window) -> records``.  Only called when not dry-running.
    checkpoint_store:
        Where resume state lives.  Required; a backfill without a checkpoint
        cannot resume and is refused.
    log:
        Append-only observation log for idempotent dedup.  Required when not
        dry-running; in dry-run nothing is appended.
    tenant_id:
        Tenant scope for the observation log.
    """

    def __init__(
        self,
        *,
        source: str,
        windows: Sequence[SyncWindow],
        fetcher: Callable[[SyncWindow], Sequence[NormalizedVulnerability]],
        checkpoint_store: CheckpointStore,
        log: ObservationLog | None = None,
        tenant_id: str = "default",
        dry_run: bool = True,
        stop_on_error: bool = True,
        should_stop: Callable[[], bool] | None = None,
        now: Callable[[], datetime] = utcnow,
        on_progress: Callable[[BackfillWindowResult], None] | None = None,
    ) -> None:
        if not source:
            raise ValidationError("source is required", field="source")
        if not dry_run and log is None:
            raise ValidationError(
                "an observation log is required for a real (non-dry-run) backfill",
                field="log",
            )
        self.source = source
        self.windows = list(windows)
        self.fetcher = fetcher
        self.checkpoint_store = checkpoint_store
        self.log = log
        self.tenant_id = tenant_id
        self.dry_run = dry_run
        self.stop_on_error = stop_on_error
        self.should_stop = should_stop
        self.now = now
        self.on_progress = on_progress

    def plan(self) -> list[SyncWindow]:
        """Windows still owed, given the persisted checkpoint."""
        checkpoint = self.checkpoint_store.load(self.source)
        watermark = checkpoint.watermark if checkpoint else None
        return [w for w in self.windows if watermark is None or w.end > watermark]

    def run(self) -> BackfillReport:
        checkpoint = self.checkpoint_store.load(self.source)
        watermark = checkpoint.watermark if checkpoint else None
        results: list[BackfillWindowResult] = []
        done = failed = skipped = 0
        records = appended = duplicates = 0
        interrupted = False

        for window in self.windows:
            if watermark is not None and window.end <= watermark:
                skipped += 1
                result = BackfillWindowResult(window, "skipped")
                results.append(result)
                if self.on_progress:
                    self.on_progress(result)
                continue
            if self.should_stop is not None and self.should_stop():
                interrupted = True
                break
            if self.dry_run:
                result = BackfillWindowResult(window, "planned")
                results.append(result)
                if self.on_progress:
                    self.on_progress(result)
                continue

            moment = self.now()
            try:
                produced = list(self.fetcher(window))
            except Exception as exc:
                failed += 1
                result = BackfillWindowResult(
                    window, "failed", error=f"{type(exc).__name__}: {exc}"
                )
                results.append(result)
                if self.on_progress:
                    self.on_progress(result)
                self._save_checkpoint(
                    checkpoint,
                    watermark=watermark,
                    records=checkpoint.records if checkpoint else 0,
                    attempted_at=moment,
                    failed=True,
                    error=result.error,
                )
                if self.stop_on_error:
                    break
                continue

            origins = {r.origin for r in produced}
            if len(origins) > 1:
                raise MixedOriginError(
                    "backfill window produced mixed origins: "
                    + ", ".join(sorted(o.value for o in origins))
                )

            win_appended = win_dupes = 0
            assert self.log is not None
            for record in produced:
                for observation in to_observations(
                    record, tenant_id=self.tenant_id, collected_at=moment
                ):
                    outcome = self.log.append(observation)
                    if outcome.outcome == "appended":
                        win_appended += 1
                    else:
                        win_dupes += 1
            records += len(produced)
            appended += win_appended
            duplicates += win_dupes
            done += 1
            watermark = window.end
            result = BackfillWindowResult(
                window, "done", records=len(produced),
                appended=win_appended, duplicates=win_dupes,
            )
            results.append(result)
            if self.on_progress:
                self.on_progress(result)
            self._save_checkpoint(
                checkpoint,
                watermark=watermark,
                records=(checkpoint.records if checkpoint else 0) + len(produced),
                attempted_at=moment,
                completed_at=moment,
                failed=False,
            )
            checkpoint = self.checkpoint_store.load(self.source)

        final = self.checkpoint_store.load(self.source)
        return BackfillReport(
            source=self.source,
            dry_run=self.dry_run,
            windows_total=len(self.windows),
            windows_done=done,
            windows_failed=failed,
            windows_skipped=skipped,
            records=records,
            appended=appended,
            duplicates=duplicates,
            interrupted=interrupted,
            watermark=final.watermark if final else watermark,
            results=tuple(results),
        )

    def _save_checkpoint(
        self,
        existing: Checkpoint | None,
        *,
        watermark: datetime | None,
        records: int,
        attempted_at: datetime,
        completed_at: datetime | None = None,
        failed: bool,
        error: str | None = None,
    ) -> None:
        base = existing or Checkpoint(source=self.source)
        self.checkpoint_store.save(
            Checkpoint(
                source=self.source,
                watermark=watermark,
                records=records,
                # completed_at is ONLY ever set by a success: it is the
                # "last successful synchronization", kept separate from
                # attempted_at per the Master Prompt §7 rule.
                completed_at=completed_at if completed_at is not None else base.completed_at,
                transport=base.transport,
                origin=base.origin,
                consecutive_failures=(base.consecutive_failures + 1) if failed else 0,
                last_error=error if failed else None,
                attempted_at=attempted_at,
            )
        )


@dataclass(frozen=True)
class BackfillProgress:
    """Operator-facing progress for a backfill run.

    ``eta_seconds`` is ``None`` until at least ``MIN_TIMED_WINDOWS`` windows have
    a measured duration — an ETA from less timing data is a guess, and a guess is
    presented as ``None`` with ``eta_reason`` saying why, never as a number.
    """

    windows_total: int
    windows_done: int
    windows_failed: int
    windows_skipped: int
    records: int
    percent: float
    eta_seconds: float | None
    eta_reason: str | None
    state: str  # "planned" | "running" | "interrupted" | "failed" | "complete"

    def as_dict(self) -> dict[str, Any]:
        return {
            "windows_total": self.windows_total,
            "windows_done": self.windows_done,
            "windows_failed": self.windows_failed,
            "windows_skipped": self.windows_skipped,
            "records": self.records,
            "percent": round(self.percent, 1),
            "eta_seconds": self.eta_seconds,
            "eta_reason": self.eta_reason,
            "state": self.state,
        }


#: Minimum timed windows before an ETA is reported at all.
MIN_TIMED_WINDOWS = 3


def progress_view(
    report: BackfillReport,
    window_durations: Sequence[float] = (),
) -> BackfillProgress:
    """Derive operator progress from a finished/interrupted run's report.

    ``window_durations`` are measured seconds per completed window, in order.
    The ETA is the mean duration times the remaining windows, reported only when
    at least :data:`MIN_TIMED_WINDOWS` windows are timed; otherwise it is None
    with an explicit reason. State is derived from the report flags, keeping
    dry-run, interrupted, failed and complete distinguishable.
    """
    total = report.windows_total
    done = report.windows_done
    remaining = max(0, total - done - report.windows_skipped)
    percent = (100.0 * (done + report.windows_skipped) / total) if total else 100.0
    if report.dry_run:
        state = "planned"
    elif report.interrupted:
        state = "interrupted"
    elif report.windows_failed:
        state = "failed"
    elif report.complete:
        state = "complete"
    else:
        state = "running"
    timed = [d for d in window_durations if d >= 0]
    if remaining == 0:
        eta = None
        reason = "no windows remaining"
    elif len(timed) < MIN_TIMED_WINDOWS:
        eta = None
        reason = (
            f"ETA withheld: {len(timed)} timed window(s), "
            f"need at least {MIN_TIMED_WINDOWS} for a non-misleading estimate"
        )
    else:
        eta = (sum(timed) / len(timed)) * remaining
        reason = f"mean of {len(timed)} timed windows; estimate, not a guarantee"
    return BackfillProgress(
        windows_total=total,
        windows_done=done,
        windows_failed=report.windows_failed,
        windows_skipped=report.windows_skipped,
        records=report.records,
        percent=percent,
        eta_seconds=round(eta, 1) if eta is not None else None,
        eta_reason=reason,
        state=state,
    )
