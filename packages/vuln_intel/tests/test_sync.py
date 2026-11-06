"""Incremental synchronisation and checkpoint safety.

The invariant under test: **a checkpoint may only advance over windows that
fully completed.**  Violating it makes the next run skip records permanently and
the platform believe it holds data it never fetched — a silent, unrecoverable
loss of coverage.
"""

from __future__ import annotations

import itertools
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vuln_intel.errors import ValidationError
from vuln_intel.schema import CollectionStatus, CveId, NormalizedVulnerability, Origin
from vuln_intel.sync import (
    MAX_WINDOW,
    Checkpoint,
    FileCheckpointStore,
    IncrementalSync,
    SyncWindow,
    plan_windows,
)

NOW = datetime(2026, 3, 1, tzinfo=timezone.utc)


def record(cve: str) -> NormalizedVulnerability:
    return NormalizedVulnerability(cve=CveId.parse(cve), origin=Origin.LIVE, sources=("nvd",))


class MemoryStore:
    def __init__(self) -> None:
        self.saved: list[Checkpoint] = []

    def load(self, source: str) -> Checkpoint | None:
        for checkpoint in reversed(self.saved):
            if checkpoint.source == source:
                return checkpoint
        return None

    def save(self, checkpoint: Checkpoint) -> None:
        self.saved.append(checkpoint)


class ScriptedFetcher:
    """Serves scripted page results per window, recording every call."""

    def __init__(self, script: list[tuple[list, bool, str | None]]) -> None:
        self.script = list(script)
        self.calls: list[tuple[SyncWindow, int, int]] = []

    def __call__(self, window, *, start_index, page_size):
        self.calls.append((window, start_index, page_size))
        if not self.script:
            return [], True, None
        return self.script.pop(0)


def sync(fetcher, store, **kwargs) -> IncrementalSync:
    kwargs.setdefault("clock", lambda: NOW)
    return IncrementalSync(source="nvd", fetch=fetcher, store=store, **kwargs)


class TestWindowPlanning:
    def test_windows_tile_the_range_without_gaps(self):
        windows = plan_windows(NOW, NOW + timedelta(days=3), step=timedelta(days=1))
        assert len(windows) == 3
        assert windows[0].start == NOW
        assert windows[-1].end == NOW + timedelta(days=3)
        for earlier, later in itertools.pairwise(windows):
            assert earlier.end == later.start

    def test_window_is_half_open_so_boundaries_are_not_lost(self):
        first, second = plan_windows(NOW, NOW + timedelta(days=2), step=timedelta(days=1))
        assert first.end == second.start

    def test_oversized_step_is_clamped_to_the_provider_limit(self):
        windows = plan_windows(NOW, NOW + timedelta(days=400), step=timedelta(days=1000))
        assert all(w.end - w.start <= MAX_WINDOW for w in windows)
        assert len(windows) >= 4

    def test_inverted_range_raises_instead_of_returning_nothing(self):
        with pytest.raises(ValidationError):
            plan_windows(NOW, NOW - timedelta(days=1))

    def test_zero_step_is_rejected(self):
        with pytest.raises(ValidationError):
            plan_windows(NOW, NOW + timedelta(days=1), step=timedelta(0))

    def test_window_carries_provider_parameters(self):
        params = SyncWindow(NOW, NOW + timedelta(days=1)).params()
        assert set(params) == {"lastModStartDate", "lastModEndDate"}
        assert params["lastModStartDate"].startswith("2026-03-01T00:00:00")

    def test_naive_timestamps_are_rejected(self):
        with pytest.raises(ValidationError):
            SyncWindow(datetime(2026, 3, 1), NOW)


class TestIncrementalSync:
    def test_first_run_collects_and_sets_watermark(self):
        store = MemoryStore()
        fetcher = ScriptedFetcher([([record("CVE-2026-0001")], True, None)])
        outcome = sync(fetcher, store).run(step=timedelta(days=1))
        assert outcome.status is CollectionStatus.OK
        assert outcome.complete
        assert len(outcome.records) == 1
        assert outcome.checkpoint.watermark == NOW

    def test_second_run_starts_near_the_watermark_with_overlap(self):
        store = MemoryStore()
        first = ScriptedFetcher([([record("CVE-2026-0001")], True, None)])
        sync(first, store).run(step=timedelta(days=1))

        second = ScriptedFetcher([([], True, None)])
        sync(second, store).run(step=timedelta(days=1))
        start = second.calls[0][0].start
        # One hour of overlap: NVD's lastModified can lag a record's timestamp.
        assert start == NOW - timedelta(hours=1)

    def test_failed_window_does_not_advance_the_checkpoint(self):
        """The critical invariant: a gap must never be marked as synced."""
        store = MemoryStore()
        fetcher = ScriptedFetcher(
            [
                ([record("CVE-2026-0001")], True, None),
                ([], False, "503 from NVD"),
            ]
        )
        outcome = sync(fetcher, store).run(
            since=NOW, until=NOW + timedelta(days=2), step=timedelta(days=1)
        )
        assert outcome.status is CollectionStatus.PARTIAL
        assert not outcome.complete
        assert outcome.checkpoint.watermark == NOW + timedelta(days=1)
        assert outcome.failed_window is not None
        assert outcome.checkpoint.consecutive_failures == 0  # one window did complete

    def test_total_failure_records_the_reason_and_keeps_the_old_watermark(self):
        store = MemoryStore()
        store.save(Checkpoint(source="nvd", watermark=NOW - timedelta(days=5)))
        fetcher = ScriptedFetcher([([], False, "connection refused")])
        outcome = sync(fetcher, store).run(
            since=NOW, until=NOW + timedelta(days=1), step=timedelta(days=1)
        )
        assert outcome.status is CollectionStatus.FAILED
        assert outcome.checkpoint.watermark == NOW - timedelta(days=5)
        assert outcome.checkpoint.consecutive_failures == 1
        assert "connection refused" in (outcome.checkpoint.last_error or "")

    def test_exhausted_page_budget_holds_the_checkpoint(self):
        """A window that hit its page cap is incomplete, not done."""
        store = MemoryStore()
        pages = [([record(f"CVE-2026-{i:04d}")], False, None) for i in range(3)]
        fetcher = ScriptedFetcher(pages)
        outcome = sync(fetcher, store, max_pages_per_window=3).run(
            since=NOW, until=NOW + timedelta(days=1), step=timedelta(days=1)
        )
        assert outcome.status is CollectionStatus.PARTIAL
        assert not outcome.complete
        assert outcome.checkpoint.watermark is None
        assert any("page budget" in w for w in outcome.warnings)

    def test_pages_within_a_window_are_requested_by_index(self):
        store = MemoryStore()
        fetcher = ScriptedFetcher(
            [
                ([record("CVE-2026-0001")], False, None),
                ([record("CVE-2026-0002")], True, None),
            ]
        )
        outcome = sync(fetcher, store, page_size=100).run(
            since=NOW, until=NOW + timedelta(days=1), step=timedelta(days=1)
        )
        assert [call[1] for call in fetcher.calls] == [0, 100]
        assert len(outcome.records) == 2

    def test_duplicate_records_across_overlapping_pages_are_collapsed(self):
        store = MemoryStore()
        fetcher = ScriptedFetcher(
            [
                ([record("CVE-2026-0001")], False, None),
                ([record("CVE-2026-0001")], True, None),
            ]
        )
        outcome = sync(fetcher, store).run(
            since=NOW, until=NOW + timedelta(days=1), step=timedelta(days=1)
        )
        assert len(outcome.records) == 1

    def test_max_windows_bounds_a_run(self):
        store = MemoryStore()
        fetcher = ScriptedFetcher([([], True, None) for _ in range(10)])
        outcome = sync(fetcher, store).run(
            since=NOW,
            until=NOW + timedelta(days=10),
            step=timedelta(days=1),
            max_windows=2,
        )
        assert len(outcome.completed_windows) == 2
        assert len(fetcher.calls) == 2

    def test_record_counts_accumulate_across_runs(self):
        store = MemoryStore()
        sync(ScriptedFetcher([([record("CVE-2026-0001")], True, None)]), store).run(
            since=NOW, until=NOW + timedelta(days=1), step=timedelta(days=1)
        )
        outcome = sync(
            ScriptedFetcher([([record("CVE-2026-0002")], True, None)]), store
        ).run(since=NOW + timedelta(days=1), until=NOW + timedelta(days=2), step=timedelta(days=1))
        assert outcome.checkpoint.records == 2

    def test_outcome_serializes(self):
        store = MemoryStore()
        outcome = sync(ScriptedFetcher([([record("CVE-2026-0001")], True, None)]), store).run(
            since=NOW, until=NOW + timedelta(days=1), step=timedelta(days=1)
        )
        payload = outcome.as_dict()
        assert json.loads(json.dumps(payload))["complete"] is True

    def test_invalid_page_size_is_rejected(self):
        with pytest.raises(ValidationError):
            IncrementalSync(source="nvd", fetch=ScriptedFetcher([]), store=MemoryStore(),
                            page_size=5000)


class TestFileCheckpointStore:
    def test_roundtrip(self, tmp_path: Path):
        store = FileCheckpointStore(tmp_path / "state" / "checkpoints.json")
        saved = Checkpoint(
            source="nvd",
            watermark=NOW,
            records=42,
            completed_at=NOW,
            transport="audited-live",
        )
        store.save(saved)
        loaded = store.load("nvd")
        assert loaded is not None
        assert loaded.watermark == NOW
        assert loaded.records == 42
        assert store.load("osv") is None

    def test_sources_are_stored_independently(self, tmp_path: Path):
        store = FileCheckpointStore(tmp_path / "c.json")
        store.save(Checkpoint(source="nvd", watermark=NOW))
        store.save(Checkpoint(source="osv", watermark=NOW - timedelta(days=1)))
        assert store.load("nvd").watermark == NOW
        assert store.load("osv").watermark == NOW - timedelta(days=1)

    def test_corrupt_file_reads_as_absent_not_as_an_exception(self, tmp_path: Path):
        path = tmp_path / "c.json"
        path.write_text("{not json", encoding="utf-8")
        assert FileCheckpointStore(path).load("nvd") is None

    def test_corrupt_entry_is_ignored(self, tmp_path: Path):
        path = tmp_path / "c.json"
        path.write_text(json.dumps({"nvd": {"records": "many"}}), encoding="utf-8")
        assert FileCheckpointStore(path).load("nvd") is None

    def test_write_is_atomic_leaving_no_temp_file(self, tmp_path: Path):
        path = tmp_path / "c.json"
        FileCheckpointStore(path).save(Checkpoint(source="nvd", watermark=NOW))
        assert path.exists()
        assert not list(tmp_path.glob("*.tmp"))

    def test_naive_watermark_is_rejected(self):
        with pytest.raises(ValidationError):
            Checkpoint(source="nvd", watermark=datetime(2026, 1, 1))

    def test_negative_record_count_is_rejected(self):
        with pytest.raises(ValidationError):
            Checkpoint(source="nvd", records=-1)


class TestSyncToHealth:
    """A completed sync must be able to feed the health report.

    These two subsystems were built separately; without `to_source_state` a sync
    run is invisible to readiness, so the source that actually collects the data
    would be reported as never collected.
    """

    def _outcome(self):
        store = MemoryStore()
        return sync(
            ScriptedFetcher([([record("CVE-2026-0001")], True, None)]), store
        ).run(since=NOW, until=NOW + timedelta(days=1), step=timedelta(days=1))

    def test_successful_sync_projects_to_an_ok_state(self):
        from vuln_intel.schema import CollectionStatus, SourceKind
        from vuln_intel.sync import to_source_state

        state = to_source_state(self._outcome(), kind=SourceKind.NVD, now=NOW)
        assert state.status is CollectionStatus.OK
        assert state.records == 1
        assert state.last_success == NOW

    def test_sync_feeds_a_ready_health_report(self):
        from vuln_intel.health import Readiness, build_health_report
        from vuln_intel.schema import SourceKind
        from vuln_intel.sync import to_source_state

        report = build_health_report(
            [to_source_state(self._outcome(), kind=SourceKind.NVD, now=NOW)],
            kev_age=timedelta(hours=1),
            now=NOW,
        )
        assert report.readiness is Readiness.READY

    def test_failed_sync_projects_to_a_failed_state_with_no_success(self):
        from vuln_intel.schema import CollectionStatus, SourceKind
        from vuln_intel.sync import to_source_state

        outcome = sync(
            ScriptedFetcher([([], False, "connection refused")]), MemoryStore()
        ).run(since=NOW, until=NOW + timedelta(days=1), step=timedelta(days=1))
        state = to_source_state(outcome, kind=SourceKind.NVD, now=NOW)
        assert state.status is CollectionStatus.FAILED
        assert state.last_success is None
        assert "connection refused" in (state.error or "")
