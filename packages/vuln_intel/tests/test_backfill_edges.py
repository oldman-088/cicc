"""Backfill edge cases: plan boundaries, watermark regression, interrupted progress."""

from __future__ import annotations

import itertools
from datetime import datetime, timedelta, timezone

import pytest

from vuln_intel.backfill import plan_backfill, progress_view
from vuln_intel.errors import ValidationError

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
DAY = timedelta(days=1)


class TestPlanEdges:
    def test_single_window_when_range_equals_step(self):
        windows = plan_backfill(T0, T0 + DAY, step=DAY)
        assert len(windows) == 1

    def test_inverted_range_refused(self):
        with pytest.raises(ValidationError):
            plan_backfill(T0 + DAY, T0, step=DAY)

    def test_zero_step_refused(self):
        with pytest.raises(ValidationError):
            plan_backfill(T0, T0 + DAY, step=timedelta(0))

    def test_windows_are_contiguous_and_bounded(self):
        windows = plan_backfill(T0, T0 + 3 * DAY, step=DAY)
        assert len(windows) == 3
        assert windows[0].start == T0 and windows[-1].end == T0 + 3 * DAY
        for a, b in itertools.pairwise(windows):
            assert a.end == b.start


class TestProgressEdges:
    def _report(self, done: int, total: int, failed: int = 0, interrupted: bool = False):
        from vuln_intel.backfill import BackfillReport, BackfillWindowResult
        windows = plan_backfill(T0, T0 + total * DAY, step=DAY)
        results = []
        for i in range(done):
            results.append(BackfillWindowResult(window=windows[i], outcome="done", records=1, appended=1))
        for i in range(failed):
            results.append(BackfillWindowResult(window=windows[done + i], outcome="failed",
                                                error="boom"))
        return BackfillReport(
            source="fixture", dry_run=False, windows_total=total,
            windows_done=done, windows_failed=failed, windows_skipped=0,
            records=done, appended=done, duplicates=0, interrupted=interrupted,
            watermark=windows[done - 1].end if done else None, results=tuple(results),
        )

    def test_dry_run_is_planned_not_running(self):
        r = self._report(0, 3)
        from dataclasses import replace
        p = progress_view(replace(r, dry_run=True))
        assert p.state == "planned" and p.percent == 0.0

    def test_eta_withheld_below_three_timed_windows(self):
        p = progress_view(self._report(2, 5), window_durations=(1.0, 2.0))
        assert p.eta_seconds is None and p.eta_reason

    def test_eta_present_with_three_timed_windows(self):
        p = progress_view(self._report(3, 6), window_durations=(1.0, 2.0, 3.0))
        assert p.eta_seconds is not None and p.eta_seconds > 0

    def test_interrupted_state(self):
        p = progress_view(self._report(2, 5, interrupted=True))
        assert p.state == "interrupted" and p.windows_total - p.windows_done == 3

    def test_failed_state(self):
        p = progress_view(self._report(1, 4, failed=1))
        assert p.state == "failed"

    def test_complete_has_no_remaining(self):
        p = progress_view(self._report(4, 4), window_durations=(1.0,) * 4)
        assert p.state == "complete" and p.windows_total == p.windows_done
        assert p.eta_seconds is None and "no windows remaining" in (p.eta_reason or "")
