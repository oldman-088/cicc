"""API freshness view: the five-state vocabulary, determinism, tz-safety, wiring."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vuln_intel.errors import ValidationError
from vuln_intel.freshness import API_FRESHNESS_STATES, SourceSynchronisation, api_freshness_view
from vuln_intel.integration.api import shape_record

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)
NAIVE = datetime(2026, 11, 5, 12, 0)  # no tzinfo


class TestFiveStates:
    def test_vocabulary_is_exactly_the_five_states(self):
        assert set(API_FRESHNESS_STATES) == {
            "unknown", "never_verified", "current", "aging", "stale",
        }

    def test_current(self):
        v = api_freshness_view(observed_at=NOW - timedelta(hours=1), now=NOW)
        assert v["state"] == "current" and v["age_seconds"] == 3600

    def test_aging(self):
        v = api_freshness_view(observed_at=NOW - timedelta(days=2), now=NOW)
        assert v["state"] == "aging"

    def test_stale(self):
        v = api_freshness_view(observed_at=NOW - timedelta(days=30), now=NOW)
        assert v["state"] == "stale"

    def test_unknown_when_no_timestamp(self):
        v = api_freshness_view(observed_at=None, now=NOW)
        assert v["state"] == "unknown" and v["observed_at"] is None

    def test_never_verified_when_source_never_succeeded(self):
        v = api_freshness_view(
            observed_at=None,
            source_state=SourceSynchronisation(source="nvd", last_attempt=NOW,
                                               last_error="boom"),
            now=NOW,
        )
        assert v["state"] == "never_verified"

    def test_failing_source_serving_old_data_is_stale_with_reason(self):
        v = api_freshness_view(
            observed_at=NOW - timedelta(days=2),
            source_state=SourceSynchronisation(
                source="nvd", last_success=NOW - timedelta(days=2),
                last_attempt=NOW, consecutive_failures=2),
            now=NOW,
        )
        assert v["state"] == "stale" and "failure" in v["reason"]


class TestDeterminismAndSafety:
    def test_same_inputs_same_output_across_repeated_calls(self):
        args = dict(observed_at=NOW - timedelta(hours=5), now=NOW)
        assert api_freshness_view(**args) == api_freshness_view(**args)

    def test_naive_datetimes_rejected(self):
        with pytest.raises(ValidationError):
            api_freshness_view(observed_at=NAIVE, now=NOW)
        with pytest.raises(ValidationError):
            api_freshness_view(observed_at=NOW, now=NAIVE)

    def test_utc_normalised(self):
        plus2 = NOW.astimezone(timezone(timedelta(hours=2)))
        v = api_freshness_view(observed_at=plus2 - timedelta(hours=1), now=plus2)
        assert v["assessed_at"].endswith("+00:00")


class TestApiWiring:
    def test_shape_record_serves_freshness_view(self):
        row = {"cve": "CVE-2026-1234", "details": {
            "last_success_at": (NOW - timedelta(hours=2)).isoformat()}}
        shaped = shape_record(row, now=NOW)
        assert shaped["freshness_view"]["state"] == "current"
        assert shaped["freshness_view"]["assessed_at"] == NOW.isoformat()

    def test_shape_record_without_success_is_never_current(self):
        shaped = shape_record({"cve": "CVE-2026-1234", "details": {}}, now=NOW)
        assert shaped["freshness_view"]["state"] == "unknown"  # inputs absent
        assert shaped["freshness_view"]["state"] != "current"
