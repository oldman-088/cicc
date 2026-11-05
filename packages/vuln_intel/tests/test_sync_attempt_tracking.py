"""Master Prompt §7: "last successful" and "last attempted" sync are separate facts.

The prompt lists them as two distinct connector requirements. ``Checkpoint`` had one
timestamp, ``completed_at``, and the failure path overwrote it with the time of the
*failed* attempt. Since ``to_source_state`` reports ``completed_at`` as
``last_success``, a source that had been failing for a week still looked freshly
synchronised: the reported freshness was the age of the last failure, not of the last
success.

These tests drive the real ``IncrementalSync.run()`` path rather than constructing
``Checkpoint`` values by hand, because the defect lived in ``_advance`` — a test that
builds its own ``replace(...)`` would pass against the broken code and prove nothing.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vuln_intel.errors import ValidationError
from vuln_intel.sync import Checkpoint, IncrementalSync

NOW = datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc)
LATER = NOW + timedelta(days=7)


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


class Fetcher:
    """Serves a single scripted result, then reports exhaustion."""

    def __init__(self, result: tuple[list, bool, str | None]) -> None:
        self.result = result
        self.done = False

    def __call__(self, window, *, start_index, page_size):
        if self.done:
            return [], True, None
        self.done = True
        return self.result


def _record(cve: str):
    from vuln_intel.schema import CveId, NormalizedVulnerability, Origin

    return NormalizedVulnerability(
        cve=CveId.parse(cve), summary="synthetic", origin=Origin.LIVE
    )


def _sync(fetcher, store, clock) -> IncrementalSync:
    return IncrementalSync(source="nvd", fetch=fetcher, store=store, clock=clock)


class TestCheckingThroughTheRealPath:
    def test_a_failed_run_does_not_overwrite_the_last_success(self):
        """The defect. Fails against the pre-fix ``_advance``."""
        store = MemoryStore()
        first = _sync(Fetcher(([_record("CVE-2026-0001")], True, None)), store, lambda: NOW)
        succeeded = first.run(since=NOW - timedelta(days=1), until=NOW)
        assert succeeded.checkpoint.completed_at == NOW

        # A week later, the source is broken.
        second = _sync(Fetcher(([], False, "connection reset")), store, lambda: LATER)
        failed = second.run(since=NOW, until=LATER)

        assert failed.checkpoint.completed_at == NOW, (
            "completed_at must keep recording the last SUCCESSFUL sync; "
            f"got {failed.checkpoint.completed_at}"
        )
        assert failed.checkpoint.attempted_at == LATER, (
            "attempted_at must record the failed attempt"
        )

    def test_the_gap_between_them_is_the_operator_signal(self):
        store = MemoryStore()
        _sync(Fetcher(([_record("CVE-2026-0002")], True, None)), store, lambda: NOW).run(
            since=NOW - timedelta(days=1), until=NOW
        )
        failed = _sync(
            Fetcher(([], False, "timeout")), store, lambda: LATER
        ).run(since=NOW, until=LATER)
        assert failed.checkpoint.attempted_at - failed.checkpoint.completed_at == timedelta(
            days=7
        )

    def test_a_successful_run_sets_both_to_the_same_moment(self):
        store = MemoryStore()
        outcome = _sync(
            Fetcher(([_record("CVE-2026-0003")], True, None)), store, lambda: NOW
        ).run(since=NOW - timedelta(days=1), until=NOW)
        assert outcome.checkpoint.completed_at == outcome.checkpoint.attempted_at == NOW

    def test_repeat_failures_accumulate_without_losing_the_success(self):
        store = MemoryStore()
        _sync(Fetcher(([_record("CVE-2026-0004")], True, None)), store, lambda: NOW).run(
            since=NOW - timedelta(days=1), until=NOW
        )
        for _ in range(3):
            _sync(Fetcher(([], False, "boom")), store, lambda: LATER).run(
                since=NOW, until=LATER
            )
        latest = store.load("nvd")
        assert latest is not None
        assert latest.consecutive_failures == 3
        assert latest.completed_at == NOW


class TestSerialisation:
    def test_attempted_at_round_trips(self):
        checkpoint = Checkpoint(source="nvd", completed_at=NOW, attempted_at=NOW)
        payload = checkpoint.as_dict()
        assert payload["attempted_at"] == NOW.isoformat()
        assert Checkpoint.from_dict(payload).attempted_at == NOW

    def test_naive_timestamps_are_rejected(self):
        with pytest.raises(ValidationError):
            Checkpoint(source="nvd", attempted_at=datetime(2026, 1, 1, 12, 0, 0))


class TestBackwardCompatibility:
    def test_a_checkpoint_written_before_this_field_still_loads(self):
        """Old payloads have no ``attempted_at``; they must not fail to load."""
        legacy = {
            "source": "nvd",
            "watermark": NOW.isoformat(),
            "records": 100,
            "completed_at": NOW.isoformat(),
            "transport": "httpx",
            "origin": "live",
            "consecutive_failures": 0,
            "last_error": None,
            "invalidated_reason": None,
        }
        restored = Checkpoint.from_dict(legacy)
        assert restored.attempted_at == NOW, (
            "an old checkpoint should fall back to completed_at rather than invent a time"
        )

    def test_a_legacy_payload_with_no_timestamps_at_all_loads(self):
        legacy = {
            "source": "nvd",
            "watermark": None,
            "records": 0,
            "completed_at": None,
            "transport": "unknown",
            "origin": "live",
        }
        restored = Checkpoint.from_dict(legacy)
        assert restored.attempted_at is None
        assert restored.completed_at is None
