"""Experimental relationship HTTP surface. Host dependencies must be supplied explicitly.

This module does not authenticate requests. The host MUST override get_principal
with verified credentials and trusted server-side tenant/permission resolution.
The default fails closed. The in-memory store is for a single-process test only.
"""
from datetime import datetime
from hashlib import sha256
import json
from threading import RLock
from typing import Annotated, Callable, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from .relationship_analysis import (
    EntityReference, RelationshipAnalysisEngine, RelationshipConfidence,
    RelationshipEvidence, RelationshipRecord, RelationshipType,
    EXPERIMENTAL_DEMO_DATA_ONLY,
)

Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]
Label = Literal['EXPERIMENTAL_DEMO_DATA_ONLY']

class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')

class Principal(StrictModel):
    """Trusted host identity, never constructed from caller-supplied tenant headers."""
    subject: Text
    tenant_id: Text
    permissions: frozenset[str]

class EntityInput(StrictModel):
    entity_id: Text
    entity_type: Text
    name: Text | None = None
    experimental_label: Label = EXPERIMENTAL_DEMO_DATA_ONLY

class EvidenceInput(StrictModel):
    source: Text
    timestamp: datetime
    description: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=4096)]
    confidence: RelationshipConfidence
    provenance: Text
    experimental_label: Label = EXPERIMENTAL_DEMO_DATA_ONLY

    @field_validator('timestamp')
    @classmethod
    def timezone_required(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError('timestamp must include a timezone')
        return value

class RelationshipCreate(StrictModel):
    source_entity: EntityInput
    target_entity: EntityInput
    relationship_type: RelationshipType
    confidence: RelationshipConfidence
    evidence: list[EvidenceInput] = Field(default_factory=list, max_length=100)
    provenance: Text
    confirmed: bool = False
    experimental_label: Label = EXPERIMENTAL_DEMO_DATA_ONLY

    @model_validator(mode='after')
    def consistent_confirmation(self):
        if self.confirmed and (not self.evidence or self.confidence == RelationshipConfidence.INFERRED):
            raise ValueError('confirmed relationships require evidence and non-inferred confidence')
        if not self.confirmed and self.confidence == RelationshipConfidence.CONFIRMED:
            raise ValueError('confirmed confidence requires confirmed=true')
        return self

class RelationshipPage(StrictModel):
    items: list[RelationshipRecord]
    total: int
    offset: int
    limit: int
    has_more: bool

class TraversalInput(StrictModel):
    entity_id: Text
    entity_type: Text
    max_depth: int = Field(default=3, ge=0, le=8)
    relationship_types: list[RelationshipType] | None = Field(default=None, max_length=15)
    limit: int = Field(default=100, ge=1, le=500)
    offset: int = Field(default=0, ge=0, le=100000)

class TraversalEdge(StrictModel):
    depth: int
    relationship: RelationshipRecord

class TraversalPage(StrictModel):
    entity_id: str
    entity_type: str
    max_depth: int
    visited_entities: int
    items: list[TraversalEdge]
    total: int
    offset: int
    limit: int
    has_more: bool
    experimental_label: Label = EXPERIMENTAL_DEMO_DATA_ONLY

class InMemoryRelationshipStore:
    """Tenant-separated ephemeral store; not a persistence or production boundary."""
    def __init__(self):
        self.lock = RLock()
        self.engines: dict[str, RelationshipAnalysisEngine] = {}
        self.keys: dict[tuple[str, str], tuple[str, UUID]] = {}
        self.fingerprints: dict[tuple[str, str], UUID] = {}

    def engine(self, tenant: str) -> RelationshipAnalysisEngine:
        return self.engines.setdefault(tenant, RelationshipAnalysisEngine())


def get_principal() -> Principal:
    raise HTTPException(status_code=503, detail='Authentication integration not configured')


def get_store(request: Request) -> InMemoryRelationshipStore:
    store = getattr(request.app.state, 'relationship_store', None)
    if store is None:
        raise HTTPException(status_code=503, detail='Relationship storage not configured')
    return store


def get_audit(request: Request) -> Callable[[dict], None]:
    audit = getattr(request.app.state, 'relationship_audit', None)
    if not callable(audit):
        raise HTTPException(status_code=503, detail='Audit integration not configured')
    return audit


def authorize(principal: Principal, permission: str):
    if permission not in principal.permissions:
        raise HTTPException(status_code=403, detail='Forbidden')


def emit(audit: Callable, principal: Principal, action: str):
    # Only metadata; never pass request bodies, credentials, or evidence text.
    try:
        audit({'subject': principal.subject, 'tenant_id': principal.tenant_id, 'action': action})
    except Exception:
        raise HTTPException(status_code=503, detail='Audit unavailable') from None

router = APIRouter(prefix='/api/v1/threat-intelligence', tags=['Threat Intelligence Relationships'])

@router.post('/relationships', response_model=RelationshipRecord, status_code=201)
def create_relationship(
    data: RelationshipCreate, response: Response,
    idempotency_key: Annotated[str, Header(alias='Idempotency-Key', min_length=1, max_length=128, pattern=r'^[A-Za-z0-9._:-]+$')],
    principal: Principal = Depends(get_principal), store: InMemoryRelationshipStore = Depends(get_store),
    audit: Callable = Depends(get_audit),
):
    authorize(principal, 'threat:write')
    fingerprint = sha256(json.dumps(data.model_dump(mode='json'), sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    emit(audit, principal, 'relationship.create.attempt')
    with store.lock:
        engine = store.engine(principal.tenant_id)
        key = (principal.tenant_id, idempotency_key)
        prior = store.keys.get(key)
        if prior:
            if prior[0] != fingerprint:
                raise HTTPException(status_code=409, detail='Idempotency key conflict')
            response.status_code = 200
            return engine.relationships[prior[1]].model_copy(deep=True)
        duplicate = store.fingerprints.get((principal.tenant_id, fingerprint))
        if duplicate:
            store.keys[key] = (fingerprint, duplicate)
            response.status_code = 200
            return engine.relationships[duplicate].model_copy(deep=True)
        record = engine.create_relationship(
            source_entity=EntityReference(**data.source_entity.model_dump()),
            target_entity=EntityReference(**data.target_entity.model_dump()),
            relationship_type=data.relationship_type, confidence=data.confidence,
            evidence=[RelationshipEvidence(**item.model_dump()) for item in data.evidence],
            provenance=data.provenance, confirmed=data.confirmed,
            experimental_label=data.experimental_label,
        )
        store.keys[key] = (fingerprint, record.relationship_id)
        store.fingerprints[(principal.tenant_id, fingerprint)] = record.relationship_id
        return record.model_copy(deep=True)

@router.get('/relationships', response_model=RelationshipPage)
def list_relationships(
    entity_id: Text | None = None, entity_type: Text | None = None,
    relationship_type: RelationshipType | None = None,
    limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0, le=100000),
    principal: Principal = Depends(get_principal), store: InMemoryRelationshipStore = Depends(get_store),
    audit: Callable = Depends(get_audit),
):
    authorize(principal, 'threat:read')
    if (entity_id is None) != (entity_type is None):
        raise HTTPException(status_code=422, detail='entity_id and entity_type must be supplied together')
    emit(audit, principal, 'relationship.list.attempt')
    with store.lock:
        engine = store.engine(principal.tenant_id)
        records = engine.get_relationships_for_entity(entity_id, entity_type) if entity_id is not None else list(engine.relationships.values())
        if relationship_type is not None:
            records = [r for r in records if r.relationship_type == relationship_type]
        total = len(records)
        return RelationshipPage(items=[r.model_copy(deep=True) for r in records[offset:offset+limit]], total=total, offset=offset, limit=limit, has_more=offset+limit<total)

@router.get('/relationships/{relationship_id}', response_model=RelationshipRecord)
def get_relationship(
    relationship_id: UUID, principal: Principal = Depends(get_principal),
    store: InMemoryRelationshipStore = Depends(get_store), audit: Callable = Depends(get_audit),
):
    authorize(principal, 'threat:read')
    emit(audit, principal, 'relationship.read.attempt')
    with store.lock:
        record = store.engine(principal.tenant_id).relationships.get(relationship_id)
        if record is None:
            raise HTTPException(status_code=404, detail='Relationship not found')
        return record.model_copy(deep=True)

@router.post('/relationship-analysis/traverse', response_model=TraversalPage)
def traverse_relationships(
    data: TraversalInput, principal: Principal = Depends(get_principal),
    store: InMemoryRelationshipStore = Depends(get_store), audit: Callable = Depends(get_audit),
):
    authorize(principal, 'threat:read')
    emit(audit, principal, 'relationship.traverse.attempt')
    with store.lock:
        engine = store.engine(principal.tenant_id)
        if (data.entity_type, data.entity_id) not in engine.entity_index:
            raise HTTPException(status_code=404, detail='Entity not found')
        result = engine.traverse_relationships(data.entity_id, data.entity_type, data.max_depth, data.relationship_types)
        edges = result['traversal_path']
        return TraversalPage(entity_id=data.entity_id, entity_type=data.entity_type, max_depth=data.max_depth,
            visited_entities=result['visited_entities'], total=len(edges), offset=data.offset, limit=data.limit,
            has_more=data.offset+data.limit<len(edges), items=[TraversalEdge(depth=e['depth'], relationship=engine.relationships[UUID(e['relationship_id'])].model_copy(deep=True)) for e in edges[data.offset:data.offset+data.limit]])
