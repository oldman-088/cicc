"""Exact, explainable KEV-to-relationship joins on caller-scoped inputs.

Offline analysis only: caller MUST authenticate and fetch exactly one tenant's
relationships first. No API, DB access, truth determination, calibration, source
independence, conflict resolution, or credential boundary is implemented here.
"""
from __future__ import annotations
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict
from .cisa_github_collector import CollectedCatalog, Entry
from .intelligence_assessment import CollectionFreshness, assess_observations, collection_freshness
from .relationship_analysis import RelationshipRecord

class KevMatch(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    relationship: RelationshipRecord
    cve_id: str
    matched_roles: list[Literal['source','target']]
    kev_entry: Entry
    evidence_collection_ages: list[CollectionFreshness]
    conflict_status: Literal['unresolved', 'none_declared']
    explicit_conflicts: list[dict]

class KevCorrelationResult(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    origin: Literal['FETCHED_FROM_GITHUB_CISA_REPO','EXPERIMENTAL_DEMO_DATA_ONLY']
    source_url: str
    github_blob_sha: str
    content_sha256: str
    catalog_released_at: datetime
    catalog_collected_at: datetime
    as_of: datetime
    catalog_age_seconds: float
    catalog_max_age_seconds: float
    catalog_collection_status: Literal['within_window','outside_window','future_collection_time']
    cve_entity_types: list[str]
    matches: list[KevMatch]
    unmatched_relationship_ids: list[UUID]
    explanation: str


def correlate_kev(records: list[RelationshipRecord], collected: CollectedCatalog, *, as_of: datetime,
                  evidence_max_age: timedelta, catalog_max_age: timedelta,
                  cve_entity_types: set[str]) -> KevCorrelationResult:
    """Exact case-sensitive CVE identity match only, with no inference or score."""
    if len(records) > 1000 or sum(len(r.evidence) for r in records) > 5000:
        raise ValueError('input exceeds correlation limits')
    if len({r.relationship_id for r in records}) != len(records):
        raise ValueError('duplicate relationship identifiers')
    if not isinstance(cve_entity_types, set) or not cve_entity_types or len(cve_entity_types) > 16 or any(
        not isinstance(t,str) or not t.strip() or len(t)>256 for t in cve_entity_types):
        raise ValueError('explicit CVE entity types are required')
    if not isinstance(as_of,datetime) or as_of.tzinfo is None or as_of.utcoffset() is None:
        raise ValueError('timezone-aware as_of is required')
    for horizon in (evidence_max_age,catalog_max_age):
        if not isinstance(horizon,timedelta) or horizon.total_seconds() <= 0:
            raise ValueError('positive explicit horizons are required')
    if collected.collected_at.tzinfo is None or collected.collected_at.utcoffset() is None:
        raise ValueError('catalog collection time must be timezone-aware')
    as_of=as_of.astimezone(timezone.utc)
    age=(as_of-collected.collected_at.astimezone(timezone.utc)).total_seconds()
    catalog_state='future_collection_time' if age<0 else ('within_window' if age<=catalog_max_age.total_seconds() else 'outside_window')
    entries={entry.cveID:entry for entry in collected.catalog.vulnerabilities}
    if len(entries) != len(collected.catalog.vulnerabilities) or len(entries) != collected.catalog.count:
        raise ValueError('catalog is incomplete or has duplicate identifiers')
    matches=[]; unmatched=[]
    for record in sorted(records,key=lambda r:str(r.relationship_id)):
        found={}
        for role,ref in (('source',record.source_entity),('target',record.target_entity)):
            if ref.entity_type in cve_entity_types and ref.entity_id in entries:
                found.setdefault(ref.entity_id,[]).append(role)
        if not found:
            unmatched.append(record.relationship_id); continue
        summary=assess_observations([record])
        evidence=[collection_freshness(e,as_of=as_of,max_age=evidence_max_age) for e in summary.observations]
        for cve,roles in sorted(found.items()):
            matches.append(KevMatch(relationship=record.model_copy(deep=True),cve_id=cve,matched_roles=roles,
                kev_entry=entries[cve].model_copy(deep=True),evidence_collection_ages=evidence,
                conflict_status='unresolved' if summary.conflicts else 'none_declared',explicit_conflicts=deepcopy(summary.conflicts)))
    return KevCorrelationResult(origin=collected.origin,source_url=collected.source_url,github_blob_sha=collected.github_blob_sha,
        content_sha256=collected.content_sha256,catalog_released_at=collected.catalog.dateReleased,catalog_collected_at=collected.collected_at,
        as_of=as_of,catalog_age_seconds=age,catalog_max_age_seconds=catalog_max_age.total_seconds(),catalog_collection_status=catalog_state,
        cve_entity_types=sorted(cve_entity_types),matches=matches,unmatched_relationship_ids=unmatched,
        explanation=('Exact identifier joins only. KEV membership does not establish the relationship, source independence, '
                     'exploit activity in the tenant, calibrated confidence, or conflict resolution. Collection age is not event freshness.'))
