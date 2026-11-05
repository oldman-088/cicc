"""
Unit tests for source reliability, freshness and verification-state handling.

The central invariant under test: a source can never reach `live_verified`
without a specific, attributable `VerificationEvidence` record. Verification
state is evidence-gated, not asserted.
"""

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from apps.threat_intelligence.source_reliability import (
    DEFAULT_RELIABILITY_WINDOW,
    EXPERIMENTAL_DEMO_DATA_ONLY,
    VERIFICATION_RANK,
    FreshnessPolicy,
    FreshnessState,
    ReliabilityTier,
    SourceAvailability,
    SourceOutcome,
    SourceReliabilityError,
    SourceReliabilityRecord,
    SourceReliabilityService,
    VerificationEvidence,
    VerificationPromotionError,
)

T0 = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def svc():
    return SourceReliabilityService(
        freshness_policy=FreshnessPolicy(
            fresh_ttl_seconds=3600, stale_after_seconds=86400, expired_after_seconds=604800
        )
    )


def _record(svc, source_id, successes, failures=0, start=T0):
    svc.register_source(tenant_id="t1", source_id=source_id)
    t = start
    for _ in range(successes):
        svc.record_outcome(tenant_id="t1", source_id=source_id, success=True,
                           latency_ms=100, records_ingested=5, now=t)
        t += timedelta(seconds=1)
    for _ in range(failures):
        svc.record_outcome(tenant_id="t1", source_id=source_id, success=False, now=t)
        t += timedelta(seconds=1)
    return svc.get("t1", source_id)


class TestFreshnessPolicy:
    def test_thresholds_must_be_strictly_ordered(self):
        with pytest.raises(ValidationError):
            FreshnessPolicy(fresh_ttl_seconds=100, stale_after_seconds=50,
                            expired_after_seconds=1000)
        with pytest.raises(ValidationError):
            FreshnessPolicy(fresh_ttl_seconds=100, stale_after_seconds=200,
                            expired_after_seconds=150)

    @pytest.mark.parametrize("age,expected", [
        (0, FreshnessState.FRESH),
        (3599, FreshnessState.FRESH),
        (3601, FreshnessState.AGING),
        (86400, FreshnessState.AGING),
        (86401, FreshnessState.STALE),
        (604800, FreshnessState.STALE),
        (604801, FreshnessState.EXPIRED),
        (None, FreshnessState.UNKNOWN),
        (-5, FreshnessState.UNKNOWN),
    ])
    def test_classification_boundaries(self, age, expected):
        policy = FreshnessPolicy(fresh_ttl_seconds=3600, stale_after_seconds=86400,
                                 expired_after_seconds=604800)
        assert policy.classify(age) is expected

    def test_future_dated_collection_is_unknown_not_fresh(self, svc):
        """A clock skew or bad timestamp must not be reported as fresh data."""
        svc.register_source(tenant_id="t1", source_id="clock-skew")
        svc.record_outcome(tenant_id="t1", source_id="clock-skew", success=True,
                           now=T0 + timedelta(hours=5))
        rec = svc.get("t1", "clock-skew")
        svc._recompute(rec, T0)
        assert rec.freshness_state is FreshnessState.UNKNOWN


class TestReliabilityScoring:
    def test_unscored_source_has_no_fabricated_score(self, svc):
        rec = svc.register_source(tenant_id="t1", source_id="brand-new", now=T0)
        assert rec.reliability_score is None
        assert rec.reliability_tier is ReliabilityTier.UNSCORED
        assert rec.availability is SourceAvailability.UNKNOWN
        assert rec.freshness_state is FreshnessState.UNKNOWN
        assert rec.is_scored is False

    def test_all_success_scores_tier1(self, svc):
        rec = _record(svc, "perfect", successes=10)
        assert rec.reliability_score == 1.0
        assert rec.reliability_tier is ReliabilityTier.TIER1_AUTHORITATIVE
        assert rec.availability is SourceAvailability.HEALTHY

    def test_failure_streak_penalises_beyond_the_raw_ratio(self, svc):
        """8 successes then 4 failures: raw ratio 0.667, but the streak must cut further."""
        rec = _record(svc, "streaky", successes=8, failures=4)
        raw_ratio = 8 / 12
        assert rec.reliability_score < raw_ratio
        assert rec.consecutive_failures == 4

    def test_success_resets_the_failure_streak(self, svc):
        rec = _record(svc, "recovering", successes=5, failures=3)
        streak_before = rec.consecutive_failures
        svc.record_outcome(tenant_id="t1", source_id="recovering", success=True,
                           now=T0 + timedelta(minutes=5))
        rec = svc.get("t1", "recovering")
        assert streak_before == 3
        assert rec.consecutive_failures == 0

    def test_availability_degrades_with_score(self, svc):
        rec = _record(svc, "degraded", successes=5, failures=5)
        assert rec.availability in (SourceAvailability.DEGRADED, SourceAvailability.UNAVAILABLE)

    def test_repeated_failure_marks_source_unavailable(self, svc):
        svc.register_source(tenant_id="t1", source_id="down")
        for i in range(4):
            svc.record_outcome(tenant_id="t1", source_id="down", success=False,
                               now=T0 + timedelta(seconds=i))
        rec = svc.get("t1", "down")
        assert rec.availability is SourceAvailability.UNAVAILABLE

    def test_window_is_bounded(self):
        svc = SourceReliabilityService(reliability_window=5)
        svc.register_source(tenant_id="t1", source_id="bounded")
        for i in range(30):
            svc.record_outcome(tenant_id="t1", source_id="bounded", success=(i % 2 == 0),
                               now=T0 + timedelta(seconds=i))
        rec = svc.get("t1", "bounded")
        assert len(rec.outcomes) <= 5
        assert svc.reliability_window == 5

    def test_window_must_be_positive(self):
        with pytest.raises(ValueError):
            SourceReliabilityService(reliability_window=0)

    def test_tier_boundaries(self):
        assert SourceReliabilityService._tier_for(0.95) is ReliabilityTier.TIER1_AUTHORITATIVE
        assert SourceReliabilityService._tier_for(0.90) is ReliabilityTier.TIER1_AUTHORITATIVE
        assert SourceReliabilityService._tier_for(0.89) is ReliabilityTier.TIER2_RELIABLE
        assert SourceReliabilityService._tier_for(0.70) is ReliabilityTier.TIER2_RELIABLE
        assert SourceReliabilityService._tier_for(0.69) is ReliabilityTier.TIER3_UNPROVEN
        assert SourceReliabilityService._tier_for(0.40) is ReliabilityTier.TIER3_UNPROVEN
        assert SourceReliabilityService._tier_for(0.39) is ReliabilityTier.TIER4_UNRELIABLE

    def test_freshness_is_driven_by_last_success_not_last_attempt(self, svc):
        """A source that keeps failing must not look fresh."""
        svc.register_source(tenant_id="t1", source_id="failing-fresh-look")
        svc.record_outcome(tenant_id="t1", source_id="failing-fresh-look", success=True, now=T0)
        for i in range(1, 4):
            svc.record_outcome(tenant_id="t1", source_id="failing-fresh-look", success=False,
                               now=T0 + timedelta(hours=2 * i))
        rec = svc.get("t1", "failing-fresh-look")
        assert rec.data_age_seconds == pytest.approx(6 * 3600, abs=1)
        assert rec.freshness_state is not FreshnessState.FRESH


class TestVerificationGating:
    """The core honesty invariant."""

    def test_default_state_is_fixture_tested(self, svc):
        rec = svc.register_source(tenant_id="t1", source_id="s", now=T0)
        assert rec.verification_mode == "fixture_tested"
        assert rec.verification_evidence == []
        assert rec.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_cannot_skip_from_fixture_to_live(self, svc):
        svc.register_source(tenant_id="t1", source_id="s", now=T0)
        with pytest.raises(VerificationPromotionError) as exc:
            svc.promote_verification(
                tenant_id="t1", source_id="s", target_mode="live_verified",
                observation_ref="obs-1", performed_by="agent6", method="live_http_fetch", now=T0
            )
        assert "skip verification steps" in str(exc.value)
        assert svc.get("t1", "s").verification_mode == "fixture_tested"

    def test_two_step_promotion_requires_evidence_each_time(self, svc):
        svc.register_source(tenant_id="t1", source_id="s", now=T0)
        svc.promote_verification(
            tenant_id="t1", source_id="s", target_mode="oracle_verified",
            observation_ref="oracle-run-42", performed_by="agent6",
            method="oracle_cross_check", now=T0
        )
        assert svc.get("t1", "s").verification_mode == "oracle_verified"
        svc.promote_verification(
            tenant_id="t1", source_id="s", target_mode="live_verified",
            observation_ref="fetch-2026-11-05", performed_by="agent6",
            method="live_http_fetch", now=T0
        )
        rec = svc.get("t1", "s")
        assert rec.verification_mode == "live_verified"
        assert len(rec.verification_evidence) == 2
        assert {e.target_verification_mode for e in rec.verification_evidence} == {
            "oracle_verified", "live_verified"
        }

    def test_blank_or_placeholder_observation_ref_is_rejected(self, svc):
        svc.register_source(tenant_id="t1", source_id="s", now=T0)
        for bad_ref in ("", "   ", "none", "N/A", "placeholder", "TODO", "tbd"):
            with pytest.raises(ValidationError):
                svc.promote_verification(
                    tenant_id="t1", source_id="s", target_mode="oracle_verified",
                    observation_ref=bad_ref, performed_by="agent6",
                    method="oracle_cross_check", now=T0
                )
        assert svc.get("t1", "s").verification_mode == "fixture_tested"

    def test_unattributable_actor_is_rejected(self, svc):
        svc.register_source(tenant_id="t1", source_id="s", now=T0)
        for bad_actor in ("", "  ", "unknown", "n/a", "anonymous", "self"):
            with pytest.raises(ValidationError):
                svc.promote_verification(
                    tenant_id="t1", source_id="s", target_mode="oracle_verified",
                    observation_ref="obs-1", performed_by=bad_actor,
                    method="oracle_cross_check", now=T0
                )
        assert svc.get("t1", "s").verification_mode == "fixture_tested"

    def test_promoting_to_the_same_mode_is_rejected(self, svc):
        svc.register_source(tenant_id="t1", source_id="s", now=T0)
        with pytest.raises(VerificationPromotionError):
            svc.promote_verification(
                tenant_id="t1", source_id="s", target_mode="fixture_tested",
                observation_ref="obs-1", performed_by="agent6", method="x", now=T0
            )

    def test_unknown_target_mode_is_rejected(self, svc):
        svc.register_source(tenant_id="t1", source_id="s", now=T0)
        with pytest.raises(VerificationPromotionError):
            svc.promote_verification(
                tenant_id="t1", source_id="s", target_mode="verified_by_vibes",
                observation_ref="obs-1", performed_by="agent6", method="x", now=T0
            )

    def test_demotion_needs_no_evidence_and_is_allowed(self, svc):
        svc.register_source(tenant_id="t1", source_id="s", now=T0)
        svc.promote_verification(
            tenant_id="t1", source_id="s", target_mode="oracle_verified",
            observation_ref="obs-1", performed_by="agent6", method="oracle_cross_check", now=T0
        )
        rec = svc.demote_to_fixture(tenant_id="t1", source_id="s", now=T0)
        assert rec.verification_mode == "fixture_tested"
        # Evidence is retained even after demotion: the history is not erased.
        assert len(rec.verification_evidence) == 1

    def test_evidence_records_are_retained_not_overwritten(self, svc):
        svc.register_source(tenant_id="t1", source_id="s", now=T0)
        svc.promote_verification(
            tenant_id="t1", source_id="s", target_mode="oracle_verified",
            observation_ref="obs-1", performed_by="agent6", method="m1", now=T0
        )
        svc.demote_to_fixture(tenant_id="t1", source_id="s", now=T0)
        svc.promote_verification(
            tenant_id="t1", source_id="s", target_mode="oracle_verified",
            observation_ref="obs-2", performed_by="agent6", method="m2",
            now=T0 + timedelta(hours=1)
        )
        rec = svc.get("t1", "s")
        assert len(rec.verification_evidence) == 2
        assert [e.observation_ref for e in rec.verification_evidence] == ["obs-1", "obs-2"]

    def test_evidence_id_is_deterministic_and_unique_per_promotion(self, svc):
        svc.register_source(tenant_id="t1", source_id="s", now=T0)
        svc.promote_verification(
            tenant_id="t1", source_id="s", target_mode="oracle_verified",
            observation_ref="obs-1", performed_by="agent6", method="m", now=T0
        )
        ids = [e.evidence_id for e in svc.get("t1", "s").verification_evidence]
        assert len(set(ids)) == len(ids)
        assert all(len(i) == 16 for i in ids)

    def test_evidence_model_rejects_fixture_target(self):
        with pytest.raises(ValidationError):
            VerificationEvidence(
                evidence_id="e1", target_verification_mode="fixture_tested",
                observation_ref="obs", performed_by="agent6", performed_at="t", method="m"
            )

    def test_outcome_verification_mode_is_validated(self):
        with pytest.raises(ValidationError):
            SourceOutcome(success=True, observed_at="t", verification_mode="guessed")

    def test_record_verification_mode_is_validated(self):
        with pytest.raises(ValidationError):
            SourceReliabilityRecord(
                source_id="s", tenant_id="t1", verification_mode="live_verified_by_flag",
                updated_at="t"
            )

    def test_verification_rank_ordering(self):
        assert VERIFICATION_RANK["fixture_tested"] < VERIFICATION_RANK["oracle_verified"]
        assert VERIFICATION_RANK["oracle_verified"] < VERIFICATION_RANK["live_verified"]


class TestRegistryAndTenancy:
    def test_registration_is_idempotent(self, svc):
        a = svc.register_source(tenant_id="t1", source_id="s", now=T0)
        b = svc.register_source(tenant_id="t1", source_id="s", now=T0 + timedelta(hours=1))
        assert a is b

    def test_sources_are_scoped_per_tenant(self, svc):
        svc.register_source(tenant_id="t1", source_id="s")
        svc.register_source(tenant_id="t2", source_id="s")
        assert svc.get("t1", "s") is not svc.get("t2", "s")
        assert len(svc.list_sources("t1")) == 1
        assert len(svc.list_sources("t2")) == 1
        assert len(svc.list_sources()) == 2

    def test_blank_tenant_or_source_is_rejected(self, svc):
        with pytest.raises(SourceReliabilityError):
            svc.register_source(tenant_id="", source_id="s")
        with pytest.raises(SourceReliabilityError):
            svc.register_source(tenant_id="t1", source_id="")

    def test_unknown_source_returns_none(self, svc):
        assert svc.get("t1", "nope") is None


class TestConfidenceAdjustmentAndReporting:
    def test_unscored_source_is_not_silently_trusted(self, svc):
        svc.register_source(tenant_id="t1", source_id="unscored")
        out = svc.confidence_adjustment("t1", "unscored", 0.9)
        assert out["applied"] is False
        assert out["adjusted_confidence"] == 0.9
        assert out["reason"] == "source_unscored"

    def test_unknown_source_adjustment_is_inert(self, svc):
        out = svc.confidence_adjustment("t1", "nope", 0.9)
        assert out["applied"] is False
        assert out["adjusted_confidence"] == 0.9

    def test_adjustment_reduces_confidence_for_stale_source(self, svc):
        svc.register_source(tenant_id="t1", source_id="stale-src")
        svc.record_outcome(tenant_id="t1", source_id="stale-src", success=True, now=T0)
        rec = svc.get("t1", "stale-src")
        svc._recompute(rec, T0 + timedelta(hours=30))  # stale band
        out = svc.confidence_adjustment("t1", "stale-src", 1.0)
        assert out["applied"] is True
        assert out["freshness_state"] == "stale"
        assert out["adjusted_confidence"] < 1.0

    def test_adjustment_is_bounded_to_unit_interval(self, svc):
        _record(svc, "bounded", successes=10)
        out = svc.confidence_adjustment("t1", "bounded", 1.0)
        assert 0.0 <= out["adjusted_confidence"] <= 1.0

    def test_health_report_counts_every_dimension(self, svc):
        _record(svc, "healthy", successes=10)
        svc.register_source(tenant_id="t1", source_id="unscored")
        svc.promote_verification(
            tenant_id="t1", source_id="healthy", target_mode="oracle_verified",
            observation_ref="obs-1", performed_by="agent6", method="oracle_cross_check", now=T0
        )
        report = svc.health_report(tenant_id="t1", now=T0)
        assert report["total_sources"] == 2
        assert report["by_verification_mode"]["oracle_verified"] == 1
        assert report["by_verification_mode"]["fixture_tested"] == 1
        assert report["live_verified_sources"] == 0
        assert report["by_tier"]["unscored"] == 1
        assert report["experimental_label"] == EXPERIMENTAL_DEMO_DATA_ONLY
        assert len(report["sources"]) == 2

    def test_report_is_tenant_scoped(self, svc):
        _record(svc, "a", successes=3)
        svc.register_source(tenant_id="t2", source_id="b")
        assert svc.health_report(tenant_id="t1", now=T0)["total_sources"] == 1
        assert svc.health_report(tenant_id="t2", now=T0)["total_sources"] == 1

    def test_report_recomputes_freshness_at_report_time(self, svc):
        """A source with no new outcomes must still age in the report."""
        svc.register_source(tenant_id="t1", source_id="aging")
        svc.record_outcome(tenant_id="t1", source_id="aging", success=True, now=T0)
        report = svc.health_report(tenant_id="t1", now=T0 + timedelta(days=10))
        source = next(s for s in report["sources"] if s["source_id"] == "aging")
        assert source["freshness_state"] == "expired"
        assert report["by_freshness"]["expired"] == 1

    def test_default_reliability_window_constant(self):
        assert DEFAULT_RELIABILITY_WINDOW == 50
