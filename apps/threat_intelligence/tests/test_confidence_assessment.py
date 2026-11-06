from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import UUID

import pytest
from pydantic import ValidationError

from apps.threat_intelligence.confidence_assessment import EvidenceRating, calculate_confidence
from apps.threat_intelligence.relationship_analysis import RelationshipConfidence
from test_intelligence_assessment import ev, record


def rating(n, strength='0.5', reliability='1.0', stance='supports'):
    return EvidenceRating(evidence_id=UUID(int=n), strength=strength, source_reliability=reliability,
                          stance=stance, assessor='fixture analyst', rationale_reference='fixture methodology')


def test_explicit_reproducible_calculation_and_provenance():
    date = datetime(2026, 1, 1, tzinfo=timezone.utc)
    r = record(1, evidence=[ev(1, 'fixture-a', date), ev(2, 'fixture-b', date)])
    result = calculate_confidence(r, [rating(1, '0.6', '0.5'), rating(2, '0.4', '1')])
    assert result.calculated_score == Decimal('0.466667') and result.score_status == 'calculated'
    assert result.record_declared_confidence == 'HIGH' and result.record_declared_confirmed is False
    assert result.observations[0].evidence.provenance == 'fixture feed'
    assert result.observations[0].analyst_input.assessor == 'fixture analyst'
    assert result.experimental_label == 'EXPERIMENTAL_DEMO_DATA_ONLY'
    assert calculate_confidence(r, [rating(2, '0.4', '1'), rating(1, '0.6', '0.5')]) == result


def test_no_invented_value_with_missing_zero_or_uncertain_inputs():
    date = datetime(2026, 1, 1, tzinfo=timezone.utc)
    r = record(1, evidence=[ev(1, 'fixture', date)])
    with pytest.raises(ValueError, match='match selected evidence'):
        calculate_confidence(r, [])
    assert calculate_confidence(record(2), []).score_status == 'insufficient_evidence'
    assert calculate_confidence(r, [rating(1, reliability='0')]).score_status == 'zero_weight'
    for stance in ('opposes', 'unknown'):
        result = calculate_confidence(r, [rating(1, stance=stance)])
        assert result.score_status == 'indeterminate_stance' and result.calculated_score is None


def test_opposing_stances_or_explicit_conflicts_remain_unresolved():
    date = datetime(2026,1,1,tzinfo=timezone.utc)
    r = record(1, evidence=[ev(1, 'a', date), ev(2, 'b', date)], conflicts=[{'source': 'fixture', 'claim': 'opposes'}])
    result = calculate_confidence(r, [rating(1), rating(2, stance='opposes')])
    assert result.conflict_status == 'unresolved' and result.calculated_score is None
    assert result.conflict_reasons == ['source_provided_conflict', 'opposing_analyst_stances']
    assert result.explicit_conflicts[0]['conflict']['claim'] == 'opposes'
    assert len(result.observations) == 2


def test_window_and_duplicate_or_unknown_evidence():
    date = datetime(2026,1,1,tzinfo=timezone.utc)
    r = record(1, evidence=[ev(1, 'a', date), ev(2, 'b', date + timedelta(days=1))])
    result = calculate_confidence(r, [rating(2)], start=date+timedelta(days=1))
    assert len(result.observations) == 1 and result.observations[0].evidence.evidence_id.int == 2
    with pytest.raises(ValueError): calculate_confidence(r, [rating(1), rating(1)])
    with pytest.raises(ValueError): calculate_confidence(r, [rating(1), rating(3)])
    with pytest.raises(ValueError, match='duplicate evidence'):
        calculate_confidence(record(2, evidence=[ev(1, 'a', date), ev(1, 'b', date)]), [rating(1)])


def test_input_validation_rejects_invalid_and_ambiguous_ratings():
    for kwargs in ({'strength': 'NaN'}, {'strength':'1.1'}, {'reliability':'-1'}, {'strength':0.5}, {'strength':'0.1234567'}, {'stance':'verified'}):
        with pytest.raises(ValidationError): rating(1, **kwargs)


def test_decimal_calculation_does_not_depend_on_ambient_precision():
    from decimal import localcontext
    date = datetime(2026, 1, 1, tzinfo=timezone.utc)
    r = record(1, evidence=[ev(1, 'fixture-a', date), ev(2, 'fixture-b', date)])
    with localcontext() as ctx:
        ctx.prec = 3
        result = calculate_confidence(r, [rating(1, '0.6', '0.5'), rating(2, '0.4', '1')])
    assert result.calculated_score == Decimal('0.466667')


def test_confidence_boundary_values_and_half_even_rounding():
    date = datetime(2026,1,1,tzinfo=timezone.utc)
    r = record(1, evidence=[ev(1,'a',date), ev(2,'b',date)])
    assert calculate_confidence(r, [rating(1, '0', '1'), rating(2, '1', '1')]).calculated_score == Decimal('0.500000')
    assert calculate_confidence(r, [rating(1, '0', '0'), rating(2, '1', '1')]).calculated_score == Decimal('1.000000')
    assert calculate_confidence(r, [rating(1, '0', '1'), rating(2, '0.000001', '1')]).calculated_score == Decimal('0.000000')
