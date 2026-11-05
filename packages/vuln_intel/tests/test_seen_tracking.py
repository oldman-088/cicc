"""First-seen / last-seen semantics, persistence, and duplicate handling.

Master Prompt §7 requires "First seen" and "Last seen" on every record. These tests pin
the four behaviours that make those fields meaningful rather than decorative: first-seen
never moves, last-seen only advances on a *valid* observation, duplicates are not
evidence, and history survives a restart.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vuln_intel.schema import Origin
from vuln_intel.seens import (
    SEEN_SCHEMA,
    InMemorySeenStore,
    JsonSeenStore,
    ObservationStatus,
    SeenRecord,
    SightingTracker,
)

T0 = datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc)


def _tracker(clock=T0, **kwargs) -> SightingTracker:
    kwargs.setdefault("store", InMemorySeenStore())
    return SightingTracker(clock=lambda: clock, **kwargs)


class TestFirstSeenIsMonotonic:
    """The single most important property: history is never rewritten."""

    def test_first_observation_sets_both(self):
        tracker = _tracker()
        assert tracker.record("CVE-2026-0001", source="nvd", observed_at=T0) == (
            ObservationStatus.ADVANCED
        )
        record = tracker.get("CVE-2026-0001")
        assert record is not None
        assert record.first_seen == T0.isoformat()
        assert record.last_seen == T0.isoformat()

    def test_a_later_observation_does_not_move_first_seen(self):
        tracker = _tracker()
        tracker.record("CVE-2026-0001", source="nvd", observed_at=T0)
        later = T0 + timedelta(days=30)
        tracker.record("CVE-2026-0001", source="osv", observed_at=later)
        record = tracker.get("CVE-2026-0001")
        assert record is not None
        assert record.first_seen == T0.isoformat(), "first_seen must never advance"
        assert record.last_seen == later.isoformat()

    def test_a_backdated_observation_does_not_rewrite_first_seen(self):
        """Archive replay or a provider correction must not rewrite history."""
        tracker = _tracker()
        tracker.record("CVE-2026-0001", source="nvd", observed_at=T0)
        older = T0 - timedelta(days=100)
        status = tracker.record("CVE-2026-0001", source="nvd", observed_at=older)
        record = tracker.get("CVE-2026-0001")
        assert record is not None
        assert status == ObservationStatus.STALE
        assert record.first_seen == T0.isoformat()
        assert record.last_seen == T0.isoformat(), "last_seen must not go backwards"
        assert record.backdated_observations == 1, (
            "a back-dated sighting is recorded as such rather than silently dropped"
        )

    def test_the_earliest_of_several_out_of_order_arrivals_wins(self):
        tracker = _tracker()
        tracker.record("CVE-2026-0001", source="nvd", observed_at=T0)
        tracker.record("CVE-2026-0001", source="nvd", observed_at=T0 + timedelta(days=2))
        tracker.record("CVE-2026-0001", source="nvd", observed_at=T0 - timedelta(days=1))
        record = tracker.get("CVE-2026-0001")
        assert record is not None
        # The back-dated one is counted but the established first sighting stands.
        assert record.first_seen == T0.isoformat()


class TestLastSeenAdvancesOnlyOnValidObservation:
    def test_a_duplicate_does_not_advance_last_seen(self):
        """A retry loop must not be able to simulate a live, advancing feed."""
        tracker = _tracker()
        tracker.record("CVE-2026-0001", source="nvd", observed_at=T0)
        for _ in range(5):
            status = tracker.record("CVE-2026-0001", source="nvd", observed_at=T0)
            assert status == ObservationStatus.DUPLICATE
        record = tracker.get("CVE-2026-0001")
        assert record is not None
        assert record.last_seen == T0.isoformat()
        assert record.observations == 1, "duplicates are not observations"

    def test_an_identical_timestamp_from_a_new_source_is_not_a_duplicate(self):
        """Same moment, different source: that is genuine corroboration."""
        tracker = _tracker()
        tracker.record("CVE-2026-0001", source="nvd", observed_at=T0)
        status = tracker.record("CVE-2026-0001", source="osv", observed_at=T0)
        record = tracker.get("CVE-2026-0001")
        assert record is not None
        assert status == ObservationStatus.ADVANCED
        assert record.sources_seen == ("nvd", "osv")
        assert record.observations == 2

    def test_last_seen_tracks_the_newest_observation(self):
        tracker = _tracker()
        tracker.record("CVE-2026-0001", source="nvd", observed_at=T0)
        newest = T0 + timedelta(days=5)
        tracker.record("CVE-2026-0001", source="nvd", observed_at=newest)
        tracker.record("CVE-2026-0001", source="nvd", observed_at=T0 + timedelta(days=2))
        record = tracker.get("CVE-2026-0001")
        assert record is not None
        assert record.last_seen == newest.isoformat()


class TestRefusalsChangeNothing:
    def test_a_fixture_observation_is_refused_by_a_live_tracker(self):
        tracker = _tracker()
        status = tracker.record(
            "CVE-2026-0001", source="nvd", observed_at=T0, origin=Origin.FIXTURE
        )
        assert status == ObservationStatus.REFUSED
        assert tracker.get("CVE-2026-0001") is None
        assert len(tracker.refusals) == 1, "refusals are recorded, not swallowed"
        assert tracker.refusals[0]["reason"] == "origin=fixture"

    def test_a_fixture_tracker_accepts_fixture_data(self):
        tracker = _tracker(allow_fixture=True)
        status = tracker.record(
            "CVE-2026-0001", source="nvd", observed_at=T0, origin=Origin.FIXTURE
        )
        assert status == ObservationStatus.ADVANCED
        record = tracker.get("CVE-2026-0001")
        assert record is not None
        assert record.origin == Origin.FIXTURE.value

    def test_a_naive_timestamp_is_rejected(self):
        tracker = _tracker()
        with pytest.raises(ValueError):
            tracker.record("CVE-2026-0001", source="nvd", observed_at=datetime(2026, 3, 1))


class TestPersistenceAndRestart:
    def test_history_survives_a_restart(self, tmp_path: Path):
        path = tmp_path / "seen.json"
        first = SightingTracker(store=JsonSeenStore(path=path), clock=lambda: T0)
        first.record("CVE-2026-0001", source="nvd", observed_at=T0)
        first.record(
            "CVE-2026-0001", source="osv", observed_at=T0 + timedelta(days=3)
        )

        # A brand-new tracker over the same file: this is the restart.
        second = SightingTracker(
            store=JsonSeenStore(path=path), clock=lambda: T0 + timedelta(days=30)
        )
        record = second.get("CVE-2026-0001")
        assert record is not None
        assert record.first_seen == T0.isoformat()
        assert record.last_seen == (T0 + timedelta(days=3)).isoformat()
        assert record.observations == 2
        assert record.sources_seen == ("nvd", "osv")

    def test_a_restart_does_not_reset_first_seen_on_the_next_observation(
        self, tmp_path: Path
    ):
        path = tmp_path / "seen.json"
        SightingTracker(store=JsonSeenStore(path=path), clock=lambda: T0).record(
            "CVE-2026-0001", source="nvd", observed_at=T0
        )
        later = T0 + timedelta(days=40)
        second = SightingTracker(store=JsonSeenStore(path=path), clock=lambda: later)
        second.record("CVE-2026-0001", source="nvd", observed_at=later)
        record = second.get("CVE-2026-0001")
        assert record is not None
        assert record.first_seen == T0.isoformat()

    def test_an_explicit_reload_matches_a_fresh_instance(self, tmp_path: Path):
        path = tmp_path / "seen.json"
        tracker = SightingTracker(store=JsonSeenStore(path=path), clock=lambda: T0)
        tracker.record("CVE-2026-0001", source="nvd", observed_at=T0)
        tracker.load()
        assert tracker.get("CVE-2026-0001") is not None

    def test_the_file_carries_a_schema_version(self, tmp_path: Path):
        path = tmp_path / "seen.json"
        SightingTracker(store=JsonSeenStore(path=path), clock=lambda: T0).record(
            "CVE-2026-0001", source="nvd", observed_at=T0
        )
        payload = json.loads(path.read_text())
        assert payload["schema"] == SEEN_SCHEMA

    def test_an_unrecognised_schema_is_refused_rather_than_misread(self, tmp_path: Path):
        """Better to lose a cache than to misread time zones into first_seen."""
        path = tmp_path / "seen.json"
        path.write_text(json.dumps({"schema": "something.else.v9", "records": {"x": {}}}))
        assert JsonSeenStore(path=path).load() == {}

    def test_a_corrupt_file_does_not_raise(self, tmp_path: Path):
        path = tmp_path / "seen.json"
        path.write_text("{not json")
        assert JsonSeenStore(path=path).load() == {}

    def test_an_absent_file_is_an_empty_history(self, tmp_path: Path):
        assert JsonSeenStore(path=tmp_path / "missing.json").load() == {}


class TestRecordRoundTrip:
    def test_as_dict_then_from_dict_preserves_every_field(self):
        record = SeenRecord(
            cve="CVE-2026-0001",
            first_seen=T0.isoformat(),
            last_seen=(T0 + timedelta(days=1)).isoformat(),
            observations=4,
            sources_seen=("nvd", "osv"),
            origin="live",
            backdated_observations=2,
        )
        restored = SeenRecord.from_dict(record.as_dict())
        assert restored == record

    def test_a_record_without_timestamps_is_rejected(self):
        with pytest.raises(ValueError):
            SeenRecord.from_dict({"cve": "CVE-2026-0001"})


class TestBatchReporting:
    def test_record_many_returns_a_status_histogram(self):
        """A bare count cannot distinguish 'advanced' from 'all duplicates'."""
        tracker = _tracker()
        counts = tracker.record_many(
            [
                ("CVE-2026-0001", "nvd", T0, Origin.LIVE),
                ("CVE-2026-0001", "nvd", T0, Origin.LIVE),
                ("CVE-2026-0002", "nvd", T0, Origin.LIVE),
                ("CVE-2026-0003", "nvd", T0, Origin.FIXTURE),
            ]
        )
        assert counts[ObservationStatus.ADVANCED] == 2
        assert counts[ObservationStatus.DUPLICATE] == 1
        assert counts[ObservationStatus.REFUSED] == 1

    def test_summary_reports_the_window_of_history(self):
        tracker = _tracker()
        tracker.record("CVE-2026-0001", source="nvd", observed_at=T0)
        tracker.record("CVE-2026-0002", source="nvd", observed_at=T0 + timedelta(days=9))
        summary = tracker.summary()
        assert summary["tracked"] == 2
        assert summary["earliest_first_seen"] == T0.isoformat()
        assert summary["latest_last_seen"] == (T0 + timedelta(days=9)).isoformat()
