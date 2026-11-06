"""B-10: source-reliability weighting is injectable, validated, and UNAPPROVED by default.

The default (no policy) reproduces the count-based curve exactly — no behavioural
change without an owner-approved policy.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vuln_intel.confidence import SourceReliabilityPolicy, derive_confidence
from vuln_intel.errors import ValidationError

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)


class TestDefaultsUnchanged:
    def test_no_policy_keeps_count_curve(self):
        one = derive_confidence(sources=["nvd"], policy="p", policy_approved=False)
        two = derive_confidence(sources=["nvd", "osv"], policy="p", policy_approved=False)
        three = derive_confidence(sources=["nvd", "osv", "kev"], policy="p", policy_approved=False)
        assert (one.value, two.value, three.value) == (0.3, 0.7, 1.0)

    def test_empty_policy_object_also_keeps_count_curve(self):
        pol = SourceReliabilityPolicy()
        v = derive_confidence(sources=["nvd", "osv"], policy="p",
                              policy_approved=True, reliability=pol)
        assert v.value == 0.7


class TestWeightedPolicy:
    def test_weights_change_the_value_and_say_so(self):
        pol = SourceReliabilityPolicy(weights={"nvd": 1.0, "osv": 0.2})
        v = derive_confidence(sources=["nvd", "osv"], policy="p",
                              policy_approved=True, reliability=pol,
                              computed_at=NOW)
        # (1.0 + 0.2) / 2 sources = 0.6
        assert v.value == 0.6
        assert any("nvd=1.00" in i for i in v.inputs)
        # unapproved policy -> result marked provisional even if caller said approved
        assert v.is_provisional

    def test_recency_decay_reduces_value_with_age(self):
        pol = SourceReliabilityPolicy(weights={"nvd": 1.0}, recency_decay_per_day=0.1)
        fresh = derive_confidence(sources=["nvd"], policy="p", policy_approved=True,
                                  reliability=pol, computed_at=NOW,
                                  newest_observation=NOW)
        old = derive_confidence(sources=["nvd"], policy="p", policy_approved=True,
                                reliability=pol, computed_at=NOW,
                                newest_observation=NOW - timedelta(days=10))
        assert old.value < fresh.value

    def test_invalid_weights_rejected(self):
        with pytest.raises(ValidationError):
            SourceReliabilityPolicy(weights={"nvd": 1.5})
        with pytest.raises(ValidationError):
            SourceReliabilityPolicy(weights={"nvd": 0.0})
        with pytest.raises(ValidationError):
            SourceReliabilityPolicy(recency_decay_per_day=2.0)

    def test_approved_policy_is_not_provisional(self):
        pol = SourceReliabilityPolicy(weights={"nvd": 1.0}, approved=True, name="owner-approved-v1")
        v = derive_confidence(sources=["nvd"], policy="p", policy_approved=True,
                              reliability=pol, computed_at=NOW)
        assert not v.is_provisional
        assert "owner-approved-v1" in v.policy
