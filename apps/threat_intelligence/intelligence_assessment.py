"""Explainable, offline relationship observation summaries (P2-02/03/04).

Pure functions, not an authorization boundary. The caller MUST supply records
from one authenticated tenant. No score, source independence, truth, or conflict
resolution is inferred from these counts. No live-source integration is implied.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Iterable
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from .relationship_analysis import RelationshipConfidence, RelationshipRecord


class EvidenceObservation(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    relationship_id: UUID
    evidence_id: UUID
    source: str
    timestamp: datetime
    description: str
    confidence: RelationshipConfidence
    provenance: str
    relationship_provenance: str
    experimental_label: str
    relationship_experimental_label: str


class Assessment(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    relationship_count: int
    declared_confidence_counts: dict[RelationshipConfidence, int]
    declared_confirmed_count: int
    confirmed_without_evidence: list[UUID]
    evidence_count: int
    distinct_source_count: int
    observations: list[EvidenceObservation]
    conflicts: list[dict]
    explanation: str


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('timezone-aware timestamps are required')
    return value.astimezone(timezone.utc)


def assess_observations(records: Iterable[RelationshipRecord], *, start: datetime | None = None,
                        end: datetime | None = None) -> Assessment:
    """Summarize caller-scoped stored records; time window is [start, end).

    Counts of declarations/conflicts cover all records; evidence counts and
    timeline cover only evidence in the requested time window. Evidence is not
    assumed independent or verified. Explicit conflict payloads remain intact.
    """
    start = _utc(start) if start is not None else None
    end = _utc(end) if end is not None else None
    if start is not None and end is not None and start >= end:
        raise ValueError('start must be before end')
    items = list(records)
    if len({item.relationship_id for item in items}) != len(items):
        raise ValueError('duplicate relationship identifiers')
    counts = {level: 0 for level in RelationshipConfidence}
    evidence = []
    conflicts = []
    confirmed_without = []
    for record in items:
        counts[record.confidence] += 1
        if record.confirmed and not record.evidence:
            confirmed_without.append(record.relationship_id)
        for value in record.conflicting_intelligence or []:
            conflicts.append({'relationship_id': str(record.relationship_id),
                              'relationship_provenance': record.provenance,
                              'experimental_label': record.experimental_label,
                              'conflict': deepcopy(value)})
        for item in record.evidence:
            timestamp = _utc(item.timestamp)
            if (start is not None and timestamp < start) or (end is not None and timestamp >= end):
                continue
            evidence.append(EvidenceObservation(
                relationship_id=record.relationship_id, evidence_id=item.evidence_id,
                source=item.source, timestamp=timestamp, description=item.description,
                confidence=item.confidence, provenance=item.provenance,
                relationship_provenance=record.provenance, experimental_label=item.experimental_label,
                relationship_experimental_label=record.experimental_label))
    evidence.sort(key=lambda e: (e.timestamp, str(e.relationship_id), str(e.evidence_id)))
    conflicts.sort(key=lambda item: item['relationship_id'])
    return Assessment(relationship_count=len(items), declared_confidence_counts=counts,
        declared_confirmed_count=sum(record.confirmed for record in items),
        confirmed_without_evidence=sorted(confirmed_without, key=str),
        evidence_count=len(evidence), distinct_source_count=len({item.source for item in evidence}),
        observations=evidence, conflicts=conflicts,
        explanation=('Counts describe supplied declarations and observations, not truth, independent corroboration, '
                     'source reliability, a calculated score, or conflict resolution.'))
