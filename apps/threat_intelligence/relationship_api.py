"""Experimental relationship HTTP surface. Host dependencies must be supplied explicitly.

This module does not authenticate requests. The host MUST override get_principal
with verified credentials and trusted server-side tenant/permission resolution.
The default fails closed. The in-memory store is for a single-process test only.
"""
from datetime import datetime, timezone
from hashlib import sha256
import json
from threading import RLock
from typing import Annotated, Callable, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from .relationship_storage import AuditContext, PostgresRelationshipStore, TraversalLimitExceeded

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
        self.audit_events: list[dict] = []

    def engine(self, tenant: str) -> RelationshipAnalysisEngine:
        return self.engines.setdefault(tenant, RelationshipAnalysisEngine())

    def _audit(self, ctx, operation, outcome, resource_id=None):
        self.audit_events.append({'event_id': uuid4(), 'tenant_id': ctx.tenant_id, 'actor': ctx.actor,
            'operation': operation, 'resource_id': resource_id, 'outcome': outcome,
            'correlation_id': ctx.correlation_id, 'occurred_at': datetime.now(timezone.utc)})

    def create(self, ctx, key, fingerprint, record):
        with self.lock:
            engine = self.engine(ctx.tenant_id)
            key_tuple = (ctx.tenant_id, key)
            previous = self.keys.get(key_tuple)
            if previous and previous[0] != fingerprint:
                self._audit(ctx, 'relationship.create', 'conflict')
                return None, 'conflict'
            duplicate = self.fingerprints.get((ctx.tenant_id, fingerprint))
            if duplicate:
                self._audit(ctx, 'relationship.create', 'replayed', duplicate)
                self.keys[key_tuple] = (fingerprint, duplicate)
                return engine.relationships[duplicate].model_copy(deep=True), 'replayed'
            self._audit(ctx, 'relationship.create', 'created', record.relationship_id)
            engine.relationships[record.relationship_id] = record.model_copy(deep=True)
            engine._index_relationship(engine.relationships[record.relationship_id])
            self.keys[key_tuple] = (fingerprint, record.relationship_id)
            self.fingerprints[(ctx.tenant_id, fingerprint)] = record.relationship_id
            return record.model_copy(deep=True), 'created'

    def get(self, ctx, record_id):
        with self.lock:
            record = self.engine(ctx.tenant_id).relationships.get(record_id)
            self._audit(ctx, 'relationship.read', 'success' if record else 'not_found', record_id)
            return record.model_copy(deep=True) if record else None

    def list(self, ctx, entity_id, entity_type, relationship_type, limit, offset):
        with self.lock:
            engine = self.engine(ctx.tenant_id)
            records = engine.get_relationships_for_entity(entity_id, entity_type) if entity_id is not None else list(engine.relationships.values())
            if relationship_type is not None:
                records = [r for r in records if r.relationship_type == relationship_type]
            self._audit(ctx, 'relationship.list', 'success')
            return [r.model_copy(deep=True) for r in records[offset:offset+limit]], len(records)

    def traverse(self, ctx, entity_id, entity_type, max_depth, relationship_types, limit, offset):
        with self.lock:
            engine = self.engine(ctx.tenant_id)
            if (entity_type, entity_id) not in engine.entity_index:
                self._audit(ctx, 'relationship.traverse', 'not_found')
                return None
            result = engine.traverse_relationships(entity_id, entity_type, max_depth, relationship_types)
            edges = result['traversal_path']
            self._audit(ctx, 'relationship.traverse', 'success')
            return [(e['depth'], engine.relationships[UUID(e['relationship_id'])].model_copy(deep=True))
                    for e in edges[offset:offset+limit]], len(edges), result['visited_entities']


def get_principal() -> Principal:
    raise HTTPException(status_code=503, detail='Authentication integration not configured')


def get_store(request: Request):
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

def context(principal: Principal, response: Response) -> AuditContext:
    correlation_id = uuid4()
    response.headers['X-Correlation-ID'] = str(correlation_id)
    return AuditContext(tenant_id=principal.tenant_id, actor=principal.subject, correlation_id=correlation_id)

@router.post('/relationships', response_model=RelationshipRecord, status_code=201)
def create_relationship(
    data: RelationshipCreate, response: Response,
    idempotency_key: Annotated[str, Header(alias='Idempotency-Key', min_length=1, max_length=128, pattern=r'^[A-Za-z0-9._:-]+$')],
    principal: Principal = Depends(get_principal), store = Depends(get_store),
    audit: Callable = Depends(get_audit),
):
    authorize(principal, 'threat:write')
    ctx = context(principal, response)
    fingerprint = sha256(json.dumps(data.model_dump(mode='json'), sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    emit(audit, principal, 'relationship.create.attempt')
    record = RelationshipRecord(
        source_entity=EntityReference(**data.source_entity.model_dump()),
        target_entity=EntityReference(**data.target_entity.model_dump()),
        relationship_type=data.relationship_type, confidence=data.confidence,
        evidence=[RelationshipEvidence(**item.model_dump()) for item in data.evidence],
        provenance=data.provenance, confirmed=data.confirmed, experimental_label=data.experimental_label)
    record, outcome = store.create(ctx, idempotency_key, fingerprint, record)
    if outcome == 'conflict':
        raise HTTPException(status_code=409, detail='Idempotency key conflict', headers={'X-Correlation-ID': str(ctx.correlation_id)})
    if outcome == 'replayed':
        response.status_code = 200
    return record

@router.get('/relationships', response_model=RelationshipPage)
def list_relationships(
    response: Response, entity_id: Text | None = None, entity_type: Text | None = None,
    relationship_type: RelationshipType | None = None,
    limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0, le=100000),
    principal: Principal = Depends(get_principal), store = Depends(get_store), audit: Callable = Depends(get_audit),
):
    authorize(principal, 'threat:read')
    if (entity_id is None) != (entity_type is None):
        raise HTTPException(status_code=422, detail='entity_id and entity_type must be supplied together')
    ctx = context(principal, response)
    emit(audit, principal, 'relationship.list.attempt')
    records, total = store.list(ctx, entity_id, entity_type, relationship_type, limit, offset)
    return RelationshipPage(items=records, total=total, offset=offset, limit=limit, has_more=offset+limit<total)

@router.get('/relationships/{relationship_id}', response_model=RelationshipRecord)
def get_relationship(
    relationship_id: UUID, response: Response, principal: Principal = Depends(get_principal),
    store = Depends(get_store), audit: Callable = Depends(get_audit),
):
    authorize(principal, 'threat:read')
    ctx = context(principal, response)
    emit(audit, principal, 'relationship.read.attempt')
    record = store.get(ctx, relationship_id)
    if record is None:
        raise HTTPException(status_code=404, detail='Relationship not found', headers={'X-Correlation-ID': str(ctx.correlation_id)})
    return record

@router.post('/relationship-analysis/traverse', response_model=TraversalPage)
def traverse_relationships(
    data: TraversalInput, response: Response, principal: Principal = Depends(get_principal),
    store = Depends(get_store), audit: Callable = Depends(get_audit),
):
    authorize(principal, 'threat:read')
    ctx = context(principal, response)
    emit(audit, principal, 'relationship.traverse.attempt')
    try:
        result = store.traverse(ctx, data.entity_id, data.entity_type, data.max_depth, data.relationship_types, data.limit, data.offset)
    except TraversalLimitExceeded:
        raise HTTPException(status_code=422, detail='Traversal exceeds configured graph limit', headers={'X-Correlation-ID': str(ctx.correlation_id)}) from None
    if result is None:
        raise HTTPException(status_code=404, detail='Entity not found', headers={'X-Correlation-ID': str(ctx.correlation_id)})
    edges, total, visited = result
    return TraversalPage(entity_id=data.entity_id, entity_type=data.entity_type, max_depth=data.max_depth,
        visited_entities=visited, total=total, offset=data.offset, limit=data.limit,
        has_more=data.offset+data.limit<total, items=[TraversalEdge(depth=depth, relationship=record) for depth, record in edges])
