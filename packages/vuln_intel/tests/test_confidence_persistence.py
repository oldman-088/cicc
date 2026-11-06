"""Confidence must be persisted, explained, and never silently rewritten.

Confidence was computed inside the ranking call and discarded, so a consumer of the
stored record saw nothing. These tests pin the requirements that make a stored
confidence trustworthy: the value travels with its basis, a provider's assertion is
never confused with our arithmetic, ``None`` is not ``0.0``, and historical values
survive a recomputation.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from vuln_intel.confidence import (
    CONFIDENCE_SCHEMA,
    ConfidenceBasis,
    ConfidenceHistory,
    ConfidenceValue,
    blend,
    derive_confidence,
    deserialise_confidence,
    serialise_confidence,
)

T0 = datetime(2026, 3, 1, tzinfo=timezone.utc)


def _derived(sources, *, approved=False):
    return derive_confidence(
        sources=sources, policy="provisional-default", policy_approved=approved
    )


class TestNoneIsNotZero:
    """The most consequential rule in this module."""

    def test_no_sources_yields_an_absent_value_not_a_low_one(self):
        value = _derived([])
        assert value.value is None
        assert value.basis == ConfidenceBasis.NONE
        assert not value.is_known

    def test_an_absent_value_explains_that_it_is_absence_of_evidence(self):
        value = _derived([])
        assert "absence of evidence" in (value.note or "")

    def test_zero_requires_the_none_basis_and_vice_versa(self):
        with pytest.raises(ValueError):
            ConfidenceValue(value=0.0, basis=ConfidenceBasis.NONE)
        with pytest.raises(ValueError):
            ConfidenceValue(value=None, basis=ConfidenceBasis.CORROBORATION)

    def test_out_of_range_values_are_rejected(self):
        with pytest.raises(ValueError):
            ConfidenceValue(value=1.5, basis=ConfidenceBasis.CORROBORATION)


class TestCorroborationCurve:
    @pytest.mark.parametrize(
        ("sources", "expected"),
        [
            (["nvd"], 0.3),
            (["nvd", "osv"], 0.7),
            (["nvd", "osv", "cisa-kev"], 1.0),
            (["nvd", "osv", "osv"], 0.7),  # duplicates are one source, not two
        ],
    )
    def test_the_curve_matches_the_ranking_policy(self, sources, expected):
        assert _derived(sources).value == expected

    def test_the_inputs_name_the_sources(self):
        value = _derived(["nvd", "osv"])
        assert any("nvd" in i and "osv" in i for i in value.inputs)


class TestBasisDistinguishesProviderFromComputed:
    def test_a_computed_value_is_labelled_corroboration(self):
        assert _derived(["nvd"]).basis == ConfidenceBasis.CORROBORATION

    def test_a_provider_value_keeps_its_own_basis(self):
        provided = ConfidenceValue(
            value=0.9, basis=ConfidenceBasis.SOURCE_PROVIDED, inputs=("vendor advisory",)
        )
        assert provided.basis == ConfidenceBasis.SOURCE_PROVIDED
        assert not provided.is_provisional, (
            "a provider's own number is not our policy's judgement, so it is never "
            "provisional"
        )

    def test_blending_does_not_average(self):
        """Averaging produces a number that is neither claim and is attributable to neither."""
        provided = ConfidenceValue(
            value=0.9, basis=ConfidenceBasis.SOURCE_PROVIDED, inputs=("vendor",)
        )
        computed = _derived(["nvd"])
        merged = blend(provided, computed)
        assert merged.value == 0.9, "the provider's assertion is the reported value"
        assert merged.value != pytest.approx((0.9 + 0.3) / 2)
        assert merged.basis == ConfidenceBasis.MIXED
        assert any("not averaged" in i for i in merged.inputs)

    def test_blending_retains_the_local_estimate_as_context(self):
        provided = ConfidenceValue(
            value=0.9, basis=ConfidenceBasis.SOURCE_PROVIDED, inputs=("vendor",)
        )
        merged = blend(provided, _derived(["nvd", "osv"]))
        assert any("0.70" in i for i in merged.inputs)

    def test_blending_falls_back_when_one_side_is_absent(self):
        provided = ConfidenceValue(
            value=0.9, basis=ConfidenceBasis.SOURCE_PROVIDED, inputs=("vendor",)
        )
        assert blend(provided, _derived([])).value == 0.9
        assert blend(_derived([]), provided).value == 0.9


class TestProvisionalPolicyIsVisible:
    def test_an_unapproved_policy_marks_the_value_provisional(self):
        value = derive_confidence(
            sources=["nvd"],
            policy="provisional-default",
            policy_approved=False,
            computed_at=T0,
        )
        assert value.is_provisional

    def test_an_approved_policy_is_not_provisional(self):
        value = derive_confidence(
            sources=["nvd"], policy="org-v1", policy_approved=True, computed_at=T0
        )
        assert not value.is_provisional

    def test_the_policy_name_travels_with_the_value(self):
        value = derive_confidence(
            sources=["nvd"], policy="org-v1", policy_approved=True
        )
        assert value.policy == "org-v1"


class TestHistoryDoesNotRewriteThePast:
    def test_recomputing_appends_rather_than_overwrites(self):
        history = ConfidenceHistory(cve="CVE-2026-0001")
        history.append(_derived(["nvd"]))
        history.append(_derived(["nvd", "osv"]), reason="OSV now also reports it")
        assert len(history.history) == 2
        assert history.history[0].value == 0.3, "the earlier value remains readable"
        assert history.current is not None
        assert history.current.value == 0.7

    def test_each_supersession_records_its_reason(self):
        history = ConfidenceHistory(cve="CVE-2026-0001")
        history.append(_derived(["nvd"]))
        history.append(_derived(["nvd", "osv"]), reason="second source")
        assert history.superseded_reasons == ["second source"]

    def test_an_unexplained_recomputation_still_says_so(self):
        history = ConfidenceHistory(cve="CVE-2026-0001")
        history.append(_derived(["nvd"]))
        history.append(_derived(["nvd", "osv"]))
        assert history.superseded_reasons == ["recomputed: no reason given by the caller"]

    def test_an_empty_history_has_no_current_value(self):
        assert ConfidenceHistory(cve="CVE-2026-0001").current is None


class TestSerialisation:
    def test_round_trip_preserves_every_field(self):
        value = derive_confidence(
            sources=["nvd", "osv"],
            policy="org-v1",
            policy_approved=True,
            computed_at=T0,
        )
        restored = deserialise_confidence(serialise_confidence(value))
        assert restored == value

    def test_the_payload_carries_a_schema_version(self):
        assert serialise_confidence(_derived(["nvd"]))["schema"] == CONFIDENCE_SCHEMA

    def test_a_null_value_round_trips_as_null(self):
        restored = deserialise_confidence(serialise_confidence(_derived([])))
        assert restored.value is None
        assert restored.basis == ConfidenceBasis.NONE

    def test_a_non_numeric_value_is_rejected(self):
        with pytest.raises(ValueError):
            deserialise_confidence({"value": "high", "basis": "corroboration"})
