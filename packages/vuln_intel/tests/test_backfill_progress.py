"""B-11 operator UX: progress states and honest ETA (withheld when unknowable)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from vuln_intel.backfill import BackfillReport, BackfillWindowResult, progress_view
from vuln_intel.sync import SyncWindow

T0 = datetime(2026, 11, 5, tzinfo=timezone.utc)


def _window(i: int) -> SyncWindow:
    return SyncWindow(start=T0 + timedelta(days=i), end=T0 + timedelta(days=i + 1))


def _report(**kw) -> BackfillReport:
    base = dict(
        source="nvd", dry_run=False, windows_total=4, windows_done=2,
        windows_failed=0, windows_skipped=0, records=10, appended=8,
        duplicates=2, interrupted=False, watermark=T0 + timedelta(days=2),
        results=(BackfillWindowResult(_window(0), "done"),),
    )
    base.update(kw)
    return BackfillReport(**base)


class TestProgressView:
    def test_complete_backfill(self):
        p = progress_view(_report(windows_done=4, watermark=T0 + timedelta(days=4)),
                          window_durations=[10.0, 12.0, 11.0, 9.0])
        assert p.state == "complete"
        assert p.percent == 100.0
        assert p.eta_seconds is None and p.eta_reason == "no windows remaining"

    def test_interrupted_and_failed_states_are_distinct(self):
        assert progress_view(_report(interrupted=True)).state == "interrupted"
        assert progress_view(_report(windows_failed=1)).state == "failed"
        assert progress_view(_report(dry_run=True)).state == "planned"

    def test_eta_withheld_below_minimum_timed_windows(self):
        p = progress_view(_report(), window_durations=[10.0, 12.0])
        assert p.eta_seconds is None
        assert "ETA withheld" in p.eta_reason and "need at least 3" in p.eta_reason

    def test_eta_reported_with_enough_timing_and_labelled_estimate(self):
        p = progress_view(_report(), window_durations=[10.0, 12.0, 14.0])  # 2 remaining
        assert p.eta_seconds == 24.0  # mean 12s * 2 remaining
        assert "estimate, not a guarantee" in p.eta_reason
        assert p.percent == 50.0

    def test_no_durations_at_all_still_explains(self):
        p = progress_view(_report(), window_durations=[])
        assert p.eta_seconds is None and "0 timed window(s)" in p.eta_reason

    def test_serialises(self):
        import json

        json.dumps(progress_view(_report(), [5.0, 6.0, 7.0]).as_dict())
