"""B-11: backfill — bounded, resumable, idempotent, safely interruptible.

Every scenario runs offline: the fetcher is a stub, the clock is fixed, the
checkpoint store is in-memory.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import pytest

from vuln_intel.backfill import BackfillRunner, plan_backfill
from vuln_intel.errors import ValidationError
from vuln_intel.integration.observations import ImmutableObservationLog
from vuln_intel.schema import CveId, NormalizedVulnerability, Origin
from vuln_intel.sync import Checkpoint, SyncWindow

T0 = datetime(2026, 5, 1, 0, 0, tzinfo=timezone.utc)
STEP = timedelta(days=1)


@dataclass
class MemoryCheckpointStore:
    data: dict[str, Checkpoint] = field(default_factory=dict)

    def load(self, source: str) -> Checkpoint | None:
        return self.data.get(source)

    def save(self, checkpoint: Checkpoint) -> None:
        self.data[checkpoint.source] = checkpoint


def _rec(cve: str, origin: Origin = Origin.FIXTURE) -> NormalizedVulnerability:
    return NormalizedVulnerability(
        cve=CveId.parse(cve), origin=origin, sources=("nvd",), summary=cve
    )


def _windows(n: int) -> list[SyncWindow]:
    return plan_backfill(T0, T0 + STEP * n, step=STEP)


def _runner(windows, fetcher, store, log, **kw) -> BackfillRunner:
    kw.setdefault("source", "nvd")
    kw.setdefault("dry_run", False)
    return BackfillRunner(
        windows=windows, fetcher=fetcher, checkpoint_store=store, log=log, **kw
    )


class TestDryRun:
    def test_dry_run_plans_without_fetching_or_writing(self):
        store = MemoryCheckpointStore()
        log = ImmutableObservationLog(allow_fixture=True)
        calls = []

        def fetcher(window):
            calls.append(window)
            return [_rec("CVE-2026-0001")]

        runner = _runner(
            _windows(3), fetcher, store, log, dry_run=True, now=lambda: T0
        )
        report = runner.run()
        assert report.dry_run is True
        assert calls == []  # fetcher never invoked
        assert log.size == 0
        assert store.load("nvd") is None  # no checkpoint written
        assert report.windows_total == 3
        assert report.complete is False
        assert all(r.outcome == "planned" for r in report.results)

    def test_real_run_requires_a_log(self):
        store = MemoryCheckpointStore()
        with pytest.raises(ValidationError, match="observation log"):
            _runner(_windows(1), lambda w: [], store, log=None, dry_run=False)


class TestHappyPathAndIdempotency:
    def test_full_run_advances_watermark_and_appends_once(self):
        store = MemoryCheckpointStore()
        log = ImmutableObservationLog(allow_fixture=True)
        windows = _windows(3)
        fetcher = lambda w: [_rec("CVE-2026-0001"), _rec("CVE-2026-0002")]
        report = _runner(windows, fetcher, store, log, now=lambda: T0).run()
        assert report.complete
        assert report.windows_done == 3 and report.records == 6
        cp = store.load("nvd")
        assert cp.watermark == windows[-1].end
        assert cp.completed_at == T0 and cp.attempted_at == T0
        assert cp.consecutive_failures == 0
        # re-running the same backfill appends nothing: digests dedupe
        report2 = _runner(windows, fetcher, store, log, now=lambda: T0 + STEP).run()
        assert report2.windows_skipped == 3
        assert report2.appended == 0
        # same CVE re-fetched in 3 windows has the same digest: appended once
        assert log.size == 2

    def test_duplicate_batch_counts_duplicates_without_deleting(self):
        store = MemoryCheckpointStore()
        log = ImmutableObservationLog(allow_fixture=True)
        windows = _windows(2)
        fetcher = lambda w: [_rec("CVE-2026-0001")]
        report = _runner(windows, fetcher, store, log, now=lambda: T0).run()
        # window 1 appends the observation, window 2 sees it as duplicate
        assert report.appended == 1
        assert report.duplicates == 1
        assert log.size == 1


class TestResumeAndInterruption:
    def test_resume_skips_completed_windows(self):
        store = MemoryCheckpointStore()
        log = ImmutableObservationLog(allow_fixture=True)
        windows = _windows(4)
        store.save(
            Checkpoint(source="nvd", watermark=windows[1].end, records=2,
                       completed_at=T0, attempted_at=T0)
        )
        seen = []
        fetcher = lambda w: (seen.append(w), [_rec("CVE-2026-0009")])[1]
        report = _runner(windows, fetcher, store, log, now=lambda: T0 + STEP).run()
        assert report.windows_skipped == 2
        assert report.windows_done == 2
        assert [w.end for w in seen] == [windows[2].end, windows[3].end]
        assert store.load("nvd").watermark == windows[3].end

    def test_interruption_preserves_only_completed_windows(self):
        store = MemoryCheckpointStore()
        log = ImmutableObservationLog(allow_fixture=True)
        windows = _windows(4)
        state = {"n": 0}

        def should_stop():
            state["n"] += 1
            return state["n"] > 2  # stop before the 3rd window

        fetcher = lambda w: [_rec("CVE-2026-0001")]
        report = _runner(
            windows, fetcher, store, log, should_stop=should_stop, now=lambda: T0
        ).run()
        assert report.interrupted is True
        assert report.windows_done == 2
        assert store.load("nvd").watermark == windows[1].end
        # resume continues from there
        report2 = _runner(windows, fetcher, store, log, now=lambda: T0 + STEP).run()
        assert report2.complete
        assert store.load("nvd").watermark == windows[3].end


class TestFailureHandling:
    def test_failed_window_records_attempt_not_success_and_stops(self):
        store = MemoryCheckpointStore()
        log = ImmutableObservationLog(allow_fixture=True)
        windows = _windows(3)

        def fetcher(w):
            if w.end == windows[1].end:
                raise RuntimeError("boom")
            return [_rec("CVE-2026-0001")]

        report = _runner(windows, fetcher, store, log, now=lambda: T0).run()
        assert report.windows_done == 1 and report.windows_failed == 1
        assert not report.complete
        cp = store.load("nvd")
        assert cp.watermark == windows[0].end          # success preserved
        assert cp.completed_at == T0                   # last success intact
        assert cp.attempted_at == T0                   # attempt recorded too
        assert cp.consecutive_failures == 1
        assert cp.last_error and "boom" in cp.last_error

    def test_continue_on_error_keeps_going_and_marks_incomplete(self):
        store = MemoryCheckpointStore()
        log = ImmutableObservationLog(allow_fixture=True)
        windows = _windows(3)

        def fetcher(w):
            if w.end == windows[1].end:
                raise RuntimeError("boom")
            return [_rec("CVE-2026-0001")]

        report = _runner(
            windows, fetcher, store, log, stop_on_error=False, now=lambda: T0
        ).run()
        assert report.windows_done == 2 and report.windows_failed == 1
        assert not report.complete
        # the failed middle window did not advance the watermark past it
        assert store.load("nvd").watermark == windows[2].end

    def test_mixed_origins_in_a_window_are_refused(self):
        store = MemoryCheckpointStore()
        log = ImmutableObservationLog(allow_fixture=True)
        fetcher = lambda w: [_rec("CVE-2026-0001", Origin.FIXTURE),
                             _rec("CVE-2026-0002", Origin.LIVE)]
        from vuln_intel.errors import MixedOriginError

        with pytest.raises(MixedOriginError):
            _runner(_windows(1), fetcher, store, log, now=lambda: T0).run()
