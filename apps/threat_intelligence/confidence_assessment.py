"""Experimental, explicitly parameterized confidence and conflict assessment.

This pure service is NOT tenant-aware: callers must first authenticate and load
exactly one tenant's stored record. It is not exposed through any HTTP API.
Analyst-provided ratings are inputs, not verified source reliability or facts.
"""
from __future__ import annotations

from decimal import Decimal, ROUND_HALF_EVEN, localcontext
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from .intelligence_assessment import EvidenceObservation, assess_observations
from .relationship_analysis import EXPERIMENTAL_DEMO_DATA_ONLY, RelationshipRecord

BoundedText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]
Rating = Annotated[Decimal, Field(ge=0, le=1, max_digits=7, decimal_places=6, allow_inf_nan=False)]

class EvidenceRating(BaseModel):
    """Explicit analyst input for one existing evidence item."""
    model_config = ConfigDict(extra='forbid', frozen=True)
    evidence_id: UUID
    strength: Rating
    source_reliability: Rating
    stance: Literal['supports', 'opposes', 'unknown']
    assessor: BoundedText
    rationale_reference: BoundedText
    experimental_label: Literal['EXPERIMENTAL_DEMO_DATA_ONLY'] = EXPERIMENTAL_DEMO_DATA_ONLY

    @field_validator('strength', 'source_reliability', mode='before')
    @classmethod
    def no_float(cls, value):
        if isinstance(value, (float, bool)):
            raise ValueError('use an exact decimal string or Decimal')
        return value

class RatedObservation(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    evidence: EvidenceObservation
    analyst_input: EvidenceRating

class ConfidenceResult(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    relationship_id: UUID
    relationship_experimental_label: str
    record_declared_confidence: str
    record_declared_confirmed: bool
    calculated_score: Decimal | None
    score_status: Literal['calculated', 'insufficient_evidence', 'zero_weight', 'unresolved_conflict', 'indeterminate_stance']
    conflict_status: Literal['unresolved', 'none_observed']
    conflict_reasons: list[str]
    explicit_conflicts: list[dict]
    observations: list[RatedObservation]
    formula: str
    experimental_label: Literal['EXPERIMENTAL_DEMO_DATA_ONLY'] = EXPERIMENTAL_DEMO_DATA_ONLY


def calculate_confidence(record: RelationshipRecord, ratings: list[EvidenceRating], *, start=None, end=None) -> ConfidenceResult:
    """Assess a single record using explicit analyst ratings; [start,end) uses collection time.

    Score is sum(strength * source_reliability) / sum(source_reliability),
    rounded to 6 decimal places HALF_EVEN. Scores are withheld for any explicit
    conflict, mixed stances, absent/zero-weight evidence or non-supporting stance.
    This is an experimental assessment, not a probability or verified claim.
    """
    if len(record.evidence) > 1000 or len(ratings) > 1000:
        raise ValueError('at most 1000 evidence observations are supported')
    summary = assess_observations([record], start=start, end=end)
    observations = summary.observations
    if len(observations) > 1000 or len(ratings) > 1000:
        raise ValueError('at most 1000 evidence observations are supported')
    evidence_ids = [item.evidence_id for item in observations]
    rating_ids = [item.evidence_id for item in ratings]
    if len(set(evidence_ids)) != len(evidence_ids):
        raise ValueError('duplicate evidence identifiers in record')
    if len(set(rating_ids)) != len(rating_ids) or set(evidence_ids) != set(rating_ids):
        raise ValueError('ratings must match selected evidence exactly once')
    by_id = {item.evidence_id: item for item in ratings}
    rated = [RatedObservation(evidence=item, analyst_input=by_id[item.evidence_id]) for item in observations]
    stances = {item.analyst_input.stance for item in rated}
    reasons = []
    if summary.conflicts:
        reasons.append('source_provided_conflict')
    if 'supports' in stances and 'opposes' in stances:
        reasons.append('opposing_analyst_stances')
    if reasons:
        status, score = 'unresolved_conflict', None
    elif not rated:
        status, score = 'insufficient_evidence', None
    elif stances != {'supports'}:
        status, score = 'indeterminate_stance', None
    else:
        with localcontext() as ctx:
            ctx.prec = 40
            total = sum((item.analyst_input.source_reliability for item in rated), Decimal(0))
            if total == 0:
                status, score = 'zero_weight', None
            else:
                numerator = sum((item.analyst_input.strength * item.analyst_input.source_reliability for item in rated), Decimal(0))
                score = (numerator / total).quantize(Decimal('0.000001'), rounding=ROUND_HALF_EVEN)
                status = 'calculated'
    return ConfidenceResult(relationship_id=record.relationship_id,
        relationship_experimental_label=record.experimental_label,
        record_declared_confidence=record.confidence.value, record_declared_confirmed=record.confirmed,
        calculated_score=score, score_status=status, conflict_status='unresolved' if reasons else 'none_observed',
        conflict_reasons=reasons, explicit_conflicts=summary.conflicts, observations=rated,
        formula='sum(strength * source_reliability) / sum(source_reliability); round HALF_EVEN to 6 decimals')
