from datetime import datetime, timezone, timedelta
from uuid import UUID

import pytest
from apps.threat_intelligence.intelligence_assessment import assess_observations
from apps.threat_intelligence.relationship_analysis import (
    EntityReference, RelationshipRecord, RelationshipEvidence, RelationshipConfidence,
    RelationshipType, EXPERIMENTAL_DEMO_DATA_ONLY,
)


def record(num, *, confirmed=False, confidence=RelationshipConfidence.HIGH, evidence=None, conflicts=None):
    return RelationshipRecord(relationship_id=UUID(int=num), source_entity=EntityReference(entity_id='a', entity_type='Actor'),
        target_entity=EntityReference(entity_id='b', entity_type='Malware'), relationship_type=RelationshipType.USES,
        confidence=confidence, confirmed=confirmed, evidence=evidence or [], provenance='fixture record',
        conflicting_intelligence=conflicts, experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY)


def ev(num, source, timestamp):
    return RelationshipEvidence(evidence_id=UUID(int=num), source=source, timestamp=timestamp,
        description='fixture evidence', confidence=RelationshipConfidence.LOW, provenance='fixture feed')


def test_assessment_keeps_declared_confidence_and_evidence_distinct():
    date = datetime(2026,1,1,tzinfo=timezone.utc)
    r1 = record(1, confirmed=True, evidence=[ev(1,'source-a',date), ev(2,'source-a',date)])
    r2 = record(2, confirmed=True, confidence=RelationshipConfidence.CONFIRMED)
    result = assess_observations([r1, r2])
    assert result.declared_confirmed_count == 2 and result.confirmed_without_evidence == [r2.relationship_id]
    assert result.evidence_count == 2 and result.distinct_source_count == 1
    assert result.declared_confidence_counts[RelationshipConfidence.CONFIRMED] == 1
    assert result.observations[0].provenance == 'fixture feed'
    assert result.observations[0].experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY
    assert 'not truth' in result.explanation


def test_half_open_temporal_window_and_stable_ties():
    date = datetime(2026,1,1,tzinfo=timezone.utc)
    r1 = record(1, evidence=[ev(2,'same',date), ev(1,'same',date), ev(3,'same',date+timedelta(days=1))])
    report = assess_observations([r1], start=date, end=date+timedelta(days=1))
    assert [e.evidence_id.int for e in report.observations] == [1,2]
    assert report.evidence_count == 2
    assert assess_observations([r1], start=date+timedelta(days=2)).evidence_count == 0


def test_preserves_explicit_conflict_without_resolving_or_mutating_input():
    conflict = {'source':'fixture', 'reason':'contradiction', 'nested': {'claim':'different'}}
    r = record(1, conflicts=[conflict])
    report = assess_observations([r])
    assert report.conflicts[0]['conflict'] == conflict and report.conflicts[0]['relationship_provenance'] == 'fixture record'
    report.conflicts[0]['conflict']['nested']['claim'] = 'changed'
    assert r.conflicting_intelligence[0]['nested']['claim'] == 'different'


def test_reject_naive_dates_invalid_windows_and_duplicate_relationships():
    naive = datetime(2026,1,1)
    aware = naive.replace(tzinfo=timezone.utc)
    with pytest.raises(ValueError, match='timezone-aware'):
        assess_observations([record(1, evidence=[ev(1, 'fixture', naive)])])
    with pytest.raises(ValueError, match='before'):
        assess_observations([], start=aware, end=aware)
    with pytest.raises(ValueError, match='duplicate'):
        assess_observations([record(1), record(1)])


def test_timezone_equivalence_and_empty_assessment():
    utc = datetime(2026,1,1,tzinfo=timezone.utc)
    shifted = utc.astimezone(timezone(timedelta(hours=8)))
    result = assess_observations([record(1, evidence=[ev(1,'fixture',shifted)])], start=utc)
    assert result.observations[0].timestamp == utc
    assert assess_observations([]).relationship_count == 0
