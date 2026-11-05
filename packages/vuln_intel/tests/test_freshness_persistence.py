"""Persistent freshness: every state reachable, and none of them guessed.

The failure this closes: freshness was computed at read time and never stored, so
nothing downstream could tell "the feed is broken" from "the advisory is simply old".
The states are exhaustive on purpose — a test can assert each one is reachable, and an
unknown input produces ``unknown`` rather than defaulting to fresh.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vuln_intel.freshness import (
    FRESHNESS_SCHEMA,
    FreshnessState,
    SourceSynchronisation,
    describe_freshness,
    source_state_from_checkpoint,
)

NOW = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)


def _healthy(**kwargs) -> SourceSynchronisation:
    kwargs.setdefault("source", "nvd")
    kwargs.setdefault("last_success", NOW - timedelta(hours=1))
    kwargs.setdefault("last_attempt", NOW - timedelta(hours=1))
    return SourceSynchronisation(**kwargs)


class TestEveryStateIsReachable:
    def test_fresh(self):
        state = describe_freshness(
            observed_at=NOW - timedelta(hours=1), source_state=_healthy(), now=NOW
        )
        assert state.state == FreshnessState.FRESH
        assert state.is_serving

    def test_stale(self):
        state = describe_freshness(
            observed_at=NOW - timedelta(days=30), source_state=_healthy(), now=NOW
        )
        assert state.state == FreshnessState.STALE
        assert state.is_serving, "stale data is still served; it is labelled, not hidden"

    def test_failed(self):
        state = describe_freshness(
            observed_at=NOW - timedelta(days=8),
            source_state=SourceSynchronisation(
                source="nvd",
                last_success=NOW - timedelta(days=8),
                last_attempt=NOW,
                consecutive_failures=3,
                last_error="connection reset",
            ),
            now=NOW,
        )
        assert state.state == FreshnessState.FAILED
        assert state.is_serving, "a degraded source still serves previously collected data"
        assert "3 consecutive" in (state.detail or "")

    def test_never_succeeded(self):
        state = describe_freshness(
            observed_at=None,
            source_state=SourceSynchronisation(
                source="nvd", last_attempt=NOW, last_error="401 unauthorised"
            ),
            now=NOW,
        )
        assert state.state == FreshnessState.NEVER_SUCCEEDED
        assert not state.is_serving
        assert "401" in (state.detail or "")

    def test_not_configured(self):
        state = describe_freshness(observed_at=None, configured=False, now=NOW)
        assert state.state == FreshnessState.NOT_CONFIGURED
        assert not state.is_serving

    def test_unknown(self):
        state = describe_freshness(observed_at=None, source_state=_healthy(), now=NOW)
        assert state.state == FreshnessState.UNKNOWN
        assert not state.is_serving, "unknown must never render as fresh"

    def test_the_state_list_is_exhaustive_and_matches_the_class(self):
        assert set(FreshnessState.ALL) == {
            "fresh",
            "stale",
            "failed",
            "never_succeeded",
            "not_configured",
            "unknown",
        }


class TestNeverSucceededIsNotFailed:
    """The distinction the previous milestone's defect made unreachable."""

    def _states(self):
        never = describe_freshness(
            observed_at=None,
            source_state=SourceSynchronisation(
                source="nvd", last_attempt=NOW, last_error="bad credentials"
            ),
            now=NOW,
        )
        broke = describe_freshness(
            observed_at=NOW - timedelta(days=2),
            source_state=SourceSynchronisation(
                source="nvd",
                last_success=NOW - timedelta(days=2),
                last_attempt=NOW,
                consecutive_failures=1,
            ),
            now=NOW,
        )
        return never, broke

    def test_they_are_different_states(self):
        never, broke = self._states()
        assert never.state != broke.state

    def test_only_the_previously_working_source_is_serving(self):
        never, broke = self._states()
        assert broke.is_serving
        assert not never.is_serving

    def test_the_details_give_an_operator_different_actions(self):
        never, broke = self._states()
        assert "never completed" in (never.detail or "")
        assert "serving data collected then" in (broke.detail or "")

    def test_never_succeeded_outranks_a_recent_observation(self):
        """Configuration truth beats data truth: a contradiction must not read as healthy."""
        state = describe_freshness(
            observed_at=NOW,
            source_state=SourceSynchronisation(source="nvd", last_attempt=NOW),
            now=NOW,
        )
        assert state.state == FreshnessState.NEVER_SUCCEEDED


class TestAgeAndBucket:
    def test_the_bucket_is_independent_of_source_health(self):
        state = describe_freshness(
            observed_at=NOW - timedelta(days=30),
            source_state=SourceSynchronisation(
                source="nvd",
                last_success=NOW,
                last_attempt=NOW,
                consecutive_failures=2,
            ),
            now=NOW,
        )
        # State is FAILED because the source is broken; the data is also old.
        assert state.state == FreshnessState.FAILED
        assert state.bucket.is_stale

    def test_age_is_computed_from_the_assessment_moment(self):
        state = describe_freshness(
            observed_at=NOW - timedelta(hours=5), source_state=_healthy(), now=NOW
        )
        assert state.age == timedelta(hours=5)

    def test_a_recent_but_not_new_bucket_still_counts_as_fresh(self):
        state = describe_freshness(
            observed_at=NOW - timedelta(hours=48), source_state=_healthy(), now=NOW
        )
        assert state.bucket.bucket == "recent"
        assert state.state == FreshnessState.FRESH


class TestSerialisation:
    def test_the_payload_carries_the_schema_and_every_input(self):
        state = describe_freshness(
            observed_at=NOW - timedelta(hours=1), source_state=_healthy(), now=NOW
        )
        payload = state.as_dict()
        assert payload["schema"] == FRESHNESS_SCHEMA
        assert payload["state"] == FreshnessState.FRESH
        assert payload["observed_at"] is not None
        assert payload["assessed_at"] is not None
        assert payload["source_state"]["last_success"] is not None
        assert payload["source_state"]["last_attempt"] is not None
        assert payload["age_seconds"] == 3600

    def test_no_timestamp_serialises_as_null_not_zero(self):
        state = describe_freshness(observed_at=None, configured=False, now=NOW)
        assert state.as_dict()["age_seconds"] is None


class TestCheckpointToSourceState:
    def test_it_reads_both_the_success_and_the_attempt(self):
        state = source_state_from_checkpoint(
            {
                "source": "nvd",
                "completed_at": (NOW - timedelta(days=7)).isoformat(),
                "attempted_at": NOW.isoformat(),
                "consecutive_failures": 2,
                "last_error": "timeout",
            }
        )
        assert state.last_success == NOW - timedelta(days=7)
        assert state.last_attempt == NOW
        assert state.consecutive_failures == 2
        assert state.is_failing

    def test_a_dict_and_an_object_agree(self):
        class Fake:
            source = "nvd"
            completed_at = NOW - timedelta(days=1)
            attempted_at = NOW
            consecutive_failures = 0
            last_error = None

        from_obj = source_state_from_checkpoint(Fake())
        from_dict = source_state_from_checkpoint(
            {
                "source": "nvd",
                "completed_at": (NOW - timedelta(days=1)).isoformat(),
                "attempted_at": NOW.isoformat(),
                "consecutive_failures": 0,
            }
        )
        assert from_obj.last_success == from_dict.last_success
        assert from_obj.last_attempt == from_dict.last_attempt

    def test_a_legacy_payload_without_attempted_at_has_no_attempt(self):
        """It must not fall back to completed_at: that would invent an attempt."""
        state = source_state_from_checkpoint(
            {"source": "nvd", "completed_at": NOW.isoformat()}
        )
        assert state.last_attempt is None
        assert state.has_ever_succeeded


class TestRealism:
    def test_a_fresh_value_is_never_reported_for_an_empty_source(self):
        for observed in (None,):
            state = describe_freshness(
                observed_at=observed,
                source_state=SourceSynchronisation(source="nvd"),
                now=NOW,
            )
            assert state.state != FreshnessState.FRESH

    @pytest.mark.parametrize("days", [0, 1, 7, 30, 365])
    def test_no_age_produces_a_duplicate_or_contradictory_state(self, days):
        state = describe_freshness(
            observed_at=NOW - timedelta(days=days), source_state=_healthy(), now=NOW
        )
        assert state.state in (FreshnessState.FRESH, FreshnessState.STALE)
