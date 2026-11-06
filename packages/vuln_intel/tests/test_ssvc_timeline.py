"""B-13 groundwork: SSVC review timelines exist only under an approved policy."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vuln_intel.errors import ValidationError
from vuln_intel.ssvc import SsvcTimelinePolicy, assess_ssvc, next_review

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)


def _assessment():
    return assess_ssvc(
        exploitation="active", automatable="yes", technical_impact="total",
        mission_wellbeing="high", source="kev",
    )


class TestNextReview:
    def test_no_policy_means_no_timeline_not_invented(self):
        assert next_review(_assessment(), assessed_at=NOW) is None
        assert next_review(_assessment(), assessed_at=NOW,
                           policy=SsvcTimelinePolicy()) is None

    def test_unapproved_policy_still_no_timeline(self):
        pol = SsvcTimelinePolicy(review_intervals_days={"act": 1}, approved=False)
        assert next_review(_assessment(), assessed_at=NOW, policy=pol) is None

    def test_approved_policy_gives_date(self):
        pol = SsvcTimelinePolicy(review_intervals_days={"act": 2}, approved=True, name="v1")
        got = next_review(_assessment(), assessed_at=NOW, policy=pol)
        assert got == NOW + timedelta(days=2)

    def test_decision_range_has_no_single_timeline(self):
        pol = SsvcTimelinePolicy(review_intervals_days={"act": 2, "track": 30},
                                 approved=True, name="v1")
        ranged = assess_ssvc(exploitation="active", automatable="yes",
                             technical_impact="total", source="kev")  # no MW
        assert ranged.decision is None
        assert next_review(ranged, assessed_at=NOW, policy=pol) is None

    def test_invalid_policy_rejected(self):
        with pytest.raises(ValidationError):
            SsvcTimelinePolicy(review_intervals_days={"nonsense": 1})
        with pytest.raises(ValidationError):
            SsvcTimelinePolicy(review_intervals_days={"act": -1})
