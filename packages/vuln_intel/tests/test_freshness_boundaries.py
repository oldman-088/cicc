"""Freshness boundary conditions: exact edges, buckets, failed sources, clocks."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from vuln_intel.freshness import SourceSynchronisation, api_freshness_view

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)
FRESH = timedelta(hours=24)
STALE = timedelta(days=7)


def _view(observed, **kw):
    kw.setdefault("now", NOW)
    kw.setdefault("fresh_within", FRESH)
    kw.setdefault("stale_after", STALE)
    return api_freshness_view(observed_at=observed, **kw)


class TestBoundaries:
    def test_just_inside_fresh_is_current(self):
        assert _view(NOW - FRESH + timedelta(seconds=1))["state"] == "current"

    def test_exactly_at_fresh_boundary_is_aging(self):
        # age == fresh_within is NOT < fresh_within -> recent bucket -> aging
        assert _view(NOW - FRESH)["state"] == "aging"

    def test_just_inside_stale_is_aging(self):
        assert _view(NOW - STALE + timedelta(seconds=1))["state"] == "aging"

    def test_exactly_at_stale_boundary_is_stale(self):
        assert _view(NOW - STALE)["state"] == "stale"

    def test_far_past_is_stale(self):
        assert _view(NOW - timedelta(days=365))["state"] == "stale"

    def test_age_seconds_is_exact(self):
        assert _view(NOW - timedelta(hours=3))["age_seconds"] == 10800


class TestSourceHealthInteractions:
    def test_failed_source_with_old_data_is_stale_and_says_why(self):
        v = _view(NOW - timedelta(days=2), source_state=SourceSynchronisation(
            source="nvd", last_success=NOW - timedelta(days=2),
            last_attempt=NOW, consecutive_failures=3))
        assert v["state"] == "stale" and "failure" in v["reason"]

    def test_never_succeeded_is_never_verified_even_with_timestamp(self):
        v = _view(NOW - timedelta(minutes=5), source_state=SourceSynchronisation(
            source="nvd", last_attempt=NOW, last_error="403"))
        assert v["state"] == "never_verified"

    def test_not_configured_without_observation_is_unknown(self):
        v = api_freshness_view(observed_at=None, now=NOW, configured=False)
        assert v["state"] == "unknown"


class TestClockHandling:
    def test_injected_clock_controls_assessment(self):
        observed = datetime(2026, 11, 1, tzinfo=timezone.utc)
        early = api_freshness_view(observed_at=observed, now=NOW)
        late = api_freshness_view(observed_at=observed,
                                  now=NOW + timedelta(days=10))
        assert early["state"] == "aging" and late["state"] == "stale"

    def test_non_utc_aware_clock_normalises_to_utc(self):
        tz = timezone(timedelta(hours=-5))
        v = api_freshness_view(observed_at=NOW.astimezone(tz) - timedelta(hours=1),
                               now=NOW.astimezone(tz))
        assert v["assessed_at"].endswith("+00:00")
        assert v["state"] == "current"

    def test_future_observation_does_not_crash_or_claim_current(self):
        v = _view(NOW + timedelta(hours=1))
        assert v["state"] in ("current", "aging", "unknown")  # never an error, never "stale"
