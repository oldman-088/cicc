"""Opt-in experimental API, not production ready. No browser cookie sessions.

TLS must reach ASGI as https. Forwarded headers must only be accepted from a
properly configured trusted proxy; source IP is the ASGI client address. Data
reads and audit events commit together; caller tenant never comes from input.
"""
from uuid import UUID
from datetime import datetime, timezone
from enum import Enum
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import and_, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from .audit import AuditType, record_event
from .accounts import create_user, change_role, disable_user, revoke_user_sessions, change_own_password, PasswordChangeThrottled
from .login_service import LoginStatus, login, logout
from .connectors.cisa_sync import abandon_sync, get_status
from .connectors.nvd_sync import abandon_sync as abandon_nvd_sync, get_status as get_nvd_status
from .connectors.nvd_cve import _cve_id
from .models import CisaSyncAttempt, NvdCatalogRecord, NvdSyncAttempt, Entity, EvidenceReference, ProvenanceEvent, Relationship, SecurityAuditEvent, Investigation, InvestigationEvent, InvestigationEntityLink, InvestigationEvidenceLink, InvestigationNote, User, AuthSession
from .security import Permission, Role, authorize
from .sessions import authenticate_session, authenticate_session_locked, _digest

class CisaAttemptStatus(str, Enum):
    RUNNING = 'running'
    SUCCEEDED = 'succeeded'
    FAILED = 'failed'
    ABANDONED = 'abandoned'

class NvdAttemptStatus(str, Enum):
    RUNNING = 'running'
    SUCCEEDED = 'succeeded'
    NOT_FOUND = 'not_found'
    FAILED = 'failed'
    ABANDONED = 'abandoned'

class LoginInput(BaseModel):
    tenant_id: UUID
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=1024)

class CreateUserInput(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=1024)
    role: Role

class EntityKind(str, Enum):
    INDICATOR = 'indicator'
    VULNERABILITY = 'vulnerability'
    THREAT_ACTOR = 'threat_actor'
    CAMPAIGN = 'campaign'
    ASSET = 'asset'
    INCIDENT = 'incident'
    REPORT = 'report'
    OTHER = 'other'

class CreateEntityInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: EntityKind
    title: str = Field(min_length=1, max_length=500)
    source: str = Field(min_length=1, max_length=500)
    source_reference: str | None = Field(default=None, max_length=2048)
    confidence: int | None = Field(default=None, ge=0, le=100, strict=True)

    @field_validator('title', 'source', 'source_reference')
    @classmethod
    def validate_text(cls, value):
        if value is not None and (not value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value)):
            raise ValueError('Invalid text')
        return value.strip() if value is not None else None

class RelationshipKind(str, Enum):
    ATTRIBUTED_TO = 'ATTRIBUTED_TO'
    USES = 'USES'
    TARGETS = 'TARGETS'
    INDICATES = 'INDICATES'
    ASSOCIATED_WITH = 'ASSOCIATED_WITH'
    EXPLOITS = 'EXPLOITS'
    AFFECTS = 'AFFECTS'
    OBSERVED_IN = 'OBSERVED_IN'
    DERIVED_FROM = 'DERIVED_FROM'
    CORROBORATES = 'CORROBORATES'
    CONTRADICTS = 'CONTRADICTS'
    CONTAINS = 'CONTAINS'
    DEPENDS_ON = 'DEPENDS_ON'
    BELONGS_TO = 'BELONGS_TO'
    RELATED_TO = 'RELATED_TO'

class RelationshipInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    subject_id: UUID
    object_id: UUID
    kind: RelationshipKind
    source: str = Field(min_length=1, max_length=500)
    confidence: int | None = Field(default=None, ge=0, le=100, strict=True)
    evidence_id: UUID | None = None

    @field_validator('source')
    @classmethod
    def validate_source(cls, value):
        if not value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError('Invalid source')
        return value.strip()

class UpdateEntityInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    expected_version: int = Field(ge=1, le=2147483646, strict=True)
    title: str = Field(min_length=1, max_length=500)
    confidence: int | None = Field(ge=0, le=100, strict=True)

    @field_validator('title')
    @classmethod
    def validate_title(cls, value):
        if not value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError('Invalid title')
        return value.strip()

class EvidenceInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    description: str = Field(min_length=1, max_length=2000)
    source: str = Field(min_length=1, max_length=500)
    reference: str | None = Field(default=None, max_length=2048)
    sha256: str | None = Field(default=None, pattern=r'^[0-9a-f]{64}$')

    @field_validator('description', 'source', 'reference')
    @classmethod
    def validate_text(cls, value):
        if value is not None and (not value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value)):
            raise ValueError('Invalid text')
        return value.strip() if value is not None else None

class InvestigationInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    title: str = Field(min_length=1, max_length=500)
    description: str = Field(min_length=1, max_length=4000)

    @field_validator('title', 'description')
    @classmethod
    def validate_text(cls, value):
        if not value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError('Invalid text')
        return value.strip()

class InvestigationUpdateInput(InvestigationInput):
    expected_version: int = Field(ge=1, le=2147483646, strict=True)

class InvestigationStatus(str, Enum):
    OPEN = 'open'
    CLOSED = 'closed'

class InvestigationStatusInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    status: InvestigationStatus
    expected_version: int = Field(ge=1, le=2147483646, strict=True)

class InvestigationEntityInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    entity_id: UUID

class InvestigationEvidenceInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    entity_id: UUID
    evidence_id: UUID

class InvestigationAssignmentInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    assignee_id: UUID | None
    expected_version: int = Field(ge=1, le=2147483646, strict=True)

class InvestigationNoteInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    body: str = Field(min_length=1, max_length=4000)

    @field_validator('body')
    @classmethod
    def validate_body(cls, value):
        if not value.strip() or any((ord(c) < 32 and c not in '\n\t') or ord(c) == 127 for c in value):
            raise ValueError('Invalid note')
        return value.strip()

class ChangePasswordInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=12, max_length=1024)

class ChangeRoleInput(BaseModel):
    role: Role

class RedactedValidationRoute(APIRoute):
    def get_route_handler(self):
        original = super().get_route_handler()
        async def handler(request):
            try:
                return await original(request)
            except RequestValidationError:
                # FastAPI's default validation error may echo submitted credentials.
                return JSONResponse({'detail': 'Invalid request'}, status_code=422,
                                    headers={'Cache-Control': 'no-store'})
        return handler

def entity_output(entity):
    return {'id':str(entity.id), 'kind':entity.kind, 'title':entity.title, 'source':entity.source,
        'source_reference':entity.source_reference, 'confidence':entity.confidence,
        'verification_status':entity.verification_status, 'version':entity.version,
        'created_by':str(entity.created_by) if entity.created_by else None, 'collected_at':entity.collected_at.isoformat()}

def investigation_output(case, active, role):
    return {'id':str(case.id), 'title':case.title, 'description':case.description, 'status':case.status,
        'version':case.version, 'assignee_id':str(case.assignee_id) if case.assignee_id else None,
        'assignee_status':('unassigned' if case.assignee_id is None else 'eligible' if active and role in ('admin','analyst') else 'ineligible'),
        'created_by':str(case.created_by), 'created_at':case.created_at.isoformat()}

def protected_router(factory: sessionmaker, secret: bytes) -> APIRouter:
    if len(secret) < 32:
        raise ValueError('A rate-limit key of at least 32 bytes is required')
    router = APIRouter(prefix='/api/v1/secure', route_class=RedactedValidationRoute)

    def require_tls(request: Request, response: Response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        if request.scope.get('scheme') != 'https':
            raise HTTPException(status_code=400, detail='HTTPS required', headers={'Cache-Control':'no-store'})

    def bearer(authorization: str | None = Header(default=None)) -> str:
        if not authorization:
            raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
        scheme, separator, token = authorization.partition(' ')
        if scheme.lower() != 'bearer' or not separator or not token or ' ' in token:
            raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
        return token

    @router.post('/login', dependencies=[Depends(require_tls)])
    def sign_in(payload: LoginInput, request: Request):
        if not request.client:
            raise HTTPException(status_code=503, detail='Source unavailable')
        try:
            result = login(factory, secret=secret, tenant_id=payload.tenant_id,
                username=payload.username, password=payload.password, source_ip=request.client.host)
        except ValueError:
            raise HTTPException(status_code=400, detail='Invalid request') from None
        if result.status == LoginStatus.THROTTLED:
            raise HTTPException(status_code=429, detail='Too many attempts', headers={'Cache-Control':'no-store'})
        if result.status != LoginStatus.SUCCESS:
            raise HTTPException(status_code=401, detail='Invalid credentials', headers={'Cache-Control':'no-store'})
        return {'access_token': result.token, 'token_type': 'bearer', 'expires_in': 28800}

    @router.post('/logout', dependencies=[Depends(require_tls)])
    def sign_out(token: str = Depends(bearer)):
        if not logout(factory, token):
            raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
        return {'status': 'revoked'}

    @router.get('/entities', dependencies=[Depends(require_tls)])
    def entities(after: UUID | None = None, kind: EntityKind | None = None, q: str | None = Query(default=None, min_length=2, max_length=100), token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            authorize(principal, principal.tenant_id, Permission.READ_INTELLIGENCE)
            if q is not None:
                q = q.strip()
                if len(q) < 2 or any(ord(c) < 32 or ord(c) == 127 for c in q):
                    raise HTTPException(status_code=422, detail='Invalid request', headers={'Cache-Control':'no-store'})
            query = select(Entity).where(Entity.tenant_id == principal.tenant_id)
            if kind is not None: query = query.where(Entity.kind == kind.value)
            if q is not None: query = query.where(Entity.title.icontains(q, autoescape=True))
            if after is not None:
                anchor_query = select(Entity.id).where(Entity.tenant_id == principal.tenant_id, Entity.id == after)
                if kind is not None: anchor_query = anchor_query.where(Entity.kind == kind.value)
                if q is not None: anchor_query = anchor_query.where(Entity.title.icontains(q, autoescape=True))
                if db.scalar(anchor_query) is None:
                    raise HTTPException(status_code=404, detail='Cursor not found', headers={'Cache-Control':'no-store'})
                query = query.where(Entity.id > after)
            items = list(db.scalars(query.order_by(Entity.id).limit(101)))
            record_event(db, principal.tenant_id, AuditType.INTELLIGENCE_READ, principal.user_id)
            # Bounded UUID keyset pagination; traversal is not a consistent snapshot.
            return {'items': [entity_output(x) for x in items[:100]], 'truncated': len(items) > 100,
                    'next_cursor': str(items[99].id) if len(items) > 100 else None}
    @router.post('/entities', status_code=201, dependencies=[Depends(require_tls)])
    def create_entity(payload: CreateEntityInput, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            try:
                authorize(principal, principal.tenant_id, Permission.WRITE_INTELLIGENCE)
            except PermissionError:
                raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
            entity = Entity(tenant_id=principal.tenant_id, created_by=principal.user_id,
                            kind=payload.kind.value, title=payload.title, source=payload.source,
                            source_reference=payload.source_reference, confidence=payload.confidence,
                            verification_status='unverified')
            db.add(entity); db.flush()
            db.add(ProvenanceEvent(tenant_id=principal.tenant_id, entity_id=entity.id, actor_id=principal.user_id,
                event_type='manual_entity_created', details={'source': entity.source, 'source_reference': entity.source_reference,
                'confidence': entity.confidence, 'verification_status': entity.verification_status}))
            record_event(db, principal.tenant_id, AuditType.INTELLIGENCE_CREATED, principal.user_id, target_entity_id=entity.id)
            return {'id': str(entity.id), 'verification_status': entity.verification_status, 'version': entity.version}

    @router.get('/entities/{entity_id}', dependencies=[Depends(require_tls)])
    def get_entity(entity_id: UUID, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            authorize(principal, principal.tenant_id, Permission.READ_INTELLIGENCE)
            entity = db.scalar(select(Entity).where(Entity.tenant_id == principal.tenant_id, Entity.id == entity_id))
            if entity is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            record_event(db, principal.tenant_id, AuditType.INTELLIGENCE_READ, principal.user_id, target_entity_id=entity.id)
            return {**entity_output(entity), 'notice':'Entity metadata is not independently verified; provenance and evidence references may be incomplete.'}

    @router.patch('/entities/{entity_id}', dependencies=[Depends(require_tls)])
    def update_entity(entity_id: UUID, payload: UpdateEntityInput, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            try:
                authorize(principal, principal.tenant_id, Permission.WRITE_INTELLIGENCE)
            except PermissionError:
                raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
            entity = db.scalar(select(Entity).where(Entity.id == entity_id, Entity.tenant_id == principal.tenant_id))
            if entity is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            if entity.version != payload.expected_version:
                raise HTTPException(status_code=409, detail='Version conflict', headers={'Cache-Control':'no-store'})
            before = {'title': entity.title, 'confidence': entity.confidence, 'verification_status': entity.verification_status,
                      'version': entity.version}
            changed = db.execute(update(Entity).where(Entity.id == entity_id, Entity.tenant_id == principal.tenant_id,
                Entity.version == payload.expected_version).values(title=payload.title, confidence=payload.confidence,
                verification_status='unverified', version=Entity.version + 1).execution_options(synchronize_session=False))
            if changed.rowcount != 1:
                raise HTTPException(status_code=409, detail='Version conflict', headers={'Cache-Control':'no-store'})
            after = {'title': payload.title, 'confidence': payload.confidence, 'verification_status': 'unverified',
                     'version': payload.expected_version + 1}
            db.add(ProvenanceEvent(tenant_id=principal.tenant_id, entity_id=entity_id, actor_id=principal.user_id,
                event_type='manual_entity_updated', details={'before': before, 'after': after}))
            record_event(db, principal.tenant_id, AuditType.INTELLIGENCE_UPDATED, principal.user_id, target_entity_id=entity_id)
            return {'id': str(entity_id), 'version': after['version'], 'verification_status': 'unverified'}

    @router.post('/entities/{entity_id}/evidence', status_code=201, dependencies=[Depends(require_tls)])
    def add_evidence(entity_id: UUID, payload: EvidenceInput, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            try:
                authorize(principal, principal.tenant_id, Permission.WRITE_INTELLIGENCE)
            except PermissionError:
                raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
            entity = db.scalar(select(Entity).where(Entity.id == entity_id, Entity.tenant_id == principal.tenant_id))
            if entity is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            item = EvidenceReference(tenant_id=principal.tenant_id, entity_id=entity.id, created_by=principal.user_id,
                                     description=payload.description, source=payload.source, reference=payload.reference, sha256=payload.sha256)
            db.add(item); db.flush()
            db.add(ProvenanceEvent(tenant_id=principal.tenant_id, entity_id=entity.id, actor_id=principal.user_id,
                evidence_id=item.id, event_type='evidence_reference_added', details={'source': item.source,
                'reference': item.reference, 'sha256': item.sha256, 'status': 'analyst_entered_unverified'}))
            record_event(db, principal.tenant_id, AuditType.EVIDENCE_CREATED, principal.user_id, target_entity_id=entity.id, target_evidence_id=item.id)
            return {'id': str(item.id), 'status': 'analyst_entered_unverified'}

    @router.get('/entities/{entity_id}/evidence', dependencies=[Depends(require_tls)])
    def list_evidence(entity_id: UUID, after: UUID | None = None, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            authorize(principal, principal.tenant_id, Permission.READ_INTELLIGENCE)
            entity = db.scalar(select(Entity).where(Entity.id == entity_id, Entity.tenant_id == principal.tenant_id))
            if entity is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            query = select(EvidenceReference).where(EvidenceReference.tenant_id == principal.tenant_id, EvidenceReference.entity_id == entity.id)
            if after is not None:
                anchor = db.scalar(select(EvidenceReference.id).where(EvidenceReference.tenant_id == principal.tenant_id,
                    EvidenceReference.entity_id == entity.id, EvidenceReference.id == after))
                if anchor is None:
                    raise HTTPException(status_code=404, detail='Cursor not found', headers={'Cache-Control':'no-store'})
                query = query.where(EvidenceReference.id > after)
            items = list(db.scalars(query.order_by(EvidenceReference.id).limit(101)))
            record_event(db, principal.tenant_id, AuditType.EVIDENCE_READ, principal.user_id, target_entity_id=entity.id)
            return {'items': [{'id': str(x.id), 'description': x.description, 'source': x.source, 'reference': x.reference,
                               'sha256': x.sha256, 'created_by': str(x.created_by), 'created_at': x.created_at.isoformat(),
                               'status': 'analyst_entered_unverified'} for x in items[:100]], 'truncated': len(items) > 100,
                    'next_cursor': str(items[99].id) if len(items) > 100 else None}

    @router.get('/entities/{entity_id}/evidence/{evidence_id}', dependencies=[Depends(require_tls)])
    def get_evidence(entity_id: UUID, evidence_id: UUID, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            authorize(principal, principal.tenant_id, Permission.READ_INTELLIGENCE)
            item = db.scalar(select(EvidenceReference).where(EvidenceReference.tenant_id == principal.tenant_id,
                EvidenceReference.entity_id == entity_id, EvidenceReference.id == evidence_id))
            if item is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            record_event(db, principal.tenant_id, AuditType.EVIDENCE_READ, principal.user_id,
                target_entity_id=entity_id, target_evidence_id=item.id)
            return {'id':str(item.id), 'description':item.description, 'source':item.source, 'reference':item.reference,
                'sha256':item.sha256, 'created_by':str(item.created_by), 'created_at':item.created_at.isoformat(),
                'status':'analyst_entered_unverified',
                'notice':'This is an analyst-entered reference; no file or hash has been verified.'}

    @router.get('/entities/{entity_id}/provenance', dependencies=[Depends(require_tls)])
    def list_provenance(entity_id: UUID, after: UUID | None = None, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            authorize(principal, principal.tenant_id, Permission.READ_INTELLIGENCE)
            entity = db.scalar(select(Entity).where(Entity.id == entity_id, Entity.tenant_id == principal.tenant_id))
            if entity is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            query = select(ProvenanceEvent).where(ProvenanceEvent.tenant_id == principal.tenant_id, ProvenanceEvent.entity_id == entity.id)
            if after is not None:
                anchor = db.scalar(select(ProvenanceEvent).where(ProvenanceEvent.tenant_id == principal.tenant_id,
                    ProvenanceEvent.entity_id == entity.id, ProvenanceEvent.id == after))
                if anchor is None:
                    raise HTTPException(status_code=404, detail='Cursor not found', headers={'Cache-Control':'no-store'})
                query = query.where(or_(ProvenanceEvent.occurred_at > anchor.occurred_at,
                    and_(ProvenanceEvent.occurred_at == anchor.occurred_at, ProvenanceEvent.id > anchor.id)))
            events = list(db.scalars(query.order_by(ProvenanceEvent.occurred_at, ProvenanceEvent.id).limit(101)))
            record_event(db, principal.tenant_id, AuditType.PROVENANCE_READ, principal.user_id, target_entity_id=entity.id)
            return {'items': [{'id': str(x.id), 'event_type': x.event_type, 'actor_id': str(x.actor_id),
                               'evidence_id': str(x.evidence_id) if x.evidence_id else None,
                               'details': x.details, 'occurred_at': x.occurred_at.isoformat()} for x in events[:100]],
                    'truncated': len(events) > 100,
                    'next_cursor': str(events[99].id) if len(events) > 100 else None,
                    'notice': 'History covers supported operations after provenance tracking was introduced; earlier history may be missing.'}

    @router.post('/relationships', status_code=201, dependencies=[Depends(require_tls)])
    def create_relationship(payload: RelationshipInput, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            try:
                authorize(principal, principal.tenant_id, Permission.WRITE_INTELLIGENCE)
            except PermissionError:
                raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
            if payload.subject_id == payload.object_id:
                raise HTTPException(status_code=422, detail='Self relationships are not supported', headers={'Cache-Control':'no-store'})
            found = set(db.scalars(select(Entity.id).where(Entity.tenant_id == principal.tenant_id,
                Entity.id.in_([payload.subject_id, payload.object_id]))))
            if found != {payload.subject_id, payload.object_id}:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            if payload.evidence_id is not None and db.scalar(select(EvidenceReference.id).where(
                EvidenceReference.tenant_id == principal.tenant_id, EvidenceReference.entity_id == payload.subject_id,
                EvidenceReference.id == payload.evidence_id)) is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            relation = Relationship(tenant_id=principal.tenant_id, subject_id=payload.subject_id,
                object_id=payload.object_id, kind=payload.kind.value, source=payload.source,
                confidence=payload.confidence, evidence_id=payload.evidence_id, created_by=principal.user_id,
                provenance={'method':'manual', 'status':'analyst_assertion_unverified'})
            db.add(relation); db.flush()
            db.add(ProvenanceEvent(tenant_id=principal.tenant_id, entity_id=payload.subject_id, actor_id=principal.user_id,
                evidence_id=payload.evidence_id, event_type='relationship_asserted', details={'relationship_id':str(relation.id),
                'object_id':str(payload.object_id), 'kind':payload.kind.value, 'source':payload.source,
                'confidence':payload.confidence, 'status':'analyst_assertion_unverified'}))
            record_event(db, principal.tenant_id, AuditType.RELATIONSHIP_CREATED, principal.user_id, target_entity_id=payload.subject_id)
            return {'id':str(relation.id), 'status':'analyst_assertion_unverified'}

    @router.get('/entities/{entity_id}/relationships', dependencies=[Depends(require_tls)])
    def list_relationships(entity_id: UUID, after: UUID | None = None, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            authorize(principal, principal.tenant_id, Permission.READ_INTELLIGENCE)
            if db.scalar(select(Entity.id).where(Entity.tenant_id == principal.tenant_id, Entity.id == entity_id)) is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            scope = or_(Relationship.subject_id == entity_id, Relationship.object_id == entity_id)
            query = select(Relationship).where(Relationship.tenant_id == principal.tenant_id, scope)
            if after is not None:
                anchor = db.scalar(select(Relationship).where(Relationship.tenant_id == principal.tenant_id, scope, Relationship.id == after))
                if anchor is None:
                    raise HTTPException(status_code=404, detail='Cursor not found', headers={'Cache-Control':'no-store'})
                query = query.where(or_(Relationship.created_at > anchor.created_at,
                    and_(Relationship.created_at == anchor.created_at, Relationship.id > anchor.id)))
            relations = list(db.scalars(query.order_by(Relationship.created_at, Relationship.id).limit(101)))
            record_event(db, principal.tenant_id, AuditType.RELATIONSHIP_READ, principal.user_id, target_entity_id=entity_id)
            return {'items':[{'id':str(x.id), 'subject_id':str(x.subject_id), 'object_id':str(x.object_id),
                'kind':x.kind, 'source':x.source, 'confidence':x.confidence,
                'created_by':str(x.created_by) if x.created_by else None,
                'evidence_id':str(x.evidence_id) if x.evidence_id else None,
                'created_at':x.created_at.isoformat(), 'provenance':x.provenance} for x in relations[:100]],
                'truncated':len(relations) > 100, 'next_cursor':str(relations[99].id) if len(relations) > 100 else None}

    @router.post('/investigations', status_code=201, dependencies=[Depends(require_tls)])
    def create_investigation(payload: InvestigationInput, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            try:
                authorize(principal, principal.tenant_id, Permission.WRITE_INTELLIGENCE)
            except PermissionError:
                raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
            case = Investigation(tenant_id=principal.tenant_id, created_by=principal.user_id, title=payload.title, description=payload.description)
            db.add(case); db.flush()
            db.add(InvestigationEvent(tenant_id=principal.tenant_id, investigation_id=case.id, actor_id=principal.user_id,
                event_type='created', details={'title':case.title, 'description':case.description, 'status':case.status, 'version':case.version}))
            record_event(db, principal.tenant_id, AuditType.INVESTIGATION_CREATED, principal.user_id, target_investigation_id=case.id)
            return {'id':str(case.id), 'status':case.status, 'version':case.version}

    @router.get('/investigations', dependencies=[Depends(require_tls)])
    def list_investigations(after: UUID | None = None, status: InvestigationStatus | None = None, assignee_id: UUID | None = None, q: str | None = Query(default=None, min_length=2, max_length=100), token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            authorize(principal, principal.tenant_id, Permission.READ_INTELLIGENCE)
            if q is not None:
                q = q.strip()
                if len(q) < 2 or any(ord(c) < 32 or ord(c) == 127 for c in q):
                    raise HTTPException(status_code=422, detail='Invalid request', headers={'Cache-Control':'no-store'})
            query = select(Investigation, User.active, User.role).outerjoin(User,
                and_(User.tenant_id == Investigation.tenant_id, User.id == Investigation.assignee_id))
            query = query.where(Investigation.tenant_id == principal.tenant_id)
            if status is not None: query = query.where(Investigation.status == status.value)
            if assignee_id is not None: query = query.where(Investigation.assignee_id == assignee_id)
            if q is not None: query = query.where(Investigation.title.icontains(q, autoescape=True))
            if after is not None:
                anchor = select(Investigation.id).where(Investigation.tenant_id == principal.tenant_id, Investigation.id == after)
                if status is not None: anchor = anchor.where(Investigation.status == status.value)
                if assignee_id is not None: anchor = anchor.where(Investigation.assignee_id == assignee_id)
                if q is not None: anchor = anchor.where(Investigation.title.icontains(q, autoescape=True))
                if db.scalar(anchor) is None:
                    raise HTTPException(status_code=404, detail='Cursor not found', headers={'Cache-Control':'no-store'})
                query = query.where(Investigation.id > after)
            cases = list(db.execute(query.order_by(Investigation.id).limit(101)))
            record_event(db, principal.tenant_id, AuditType.INVESTIGATION_READ, principal.user_id)
            return {'items':[investigation_output(x, active, role) for x, active, role in cases[:100]],
                'next_cursor':str(cases[99][0].id) if len(cases) > 100 else None,
                'notice':'Assignee eligibility reflects the list query only. Cases have no file storage, verified evidence lifecycle or tamper-resistant history.'}

    @router.get('/investigations/{investigation_id}', dependencies=[Depends(require_tls)])
    def get_investigation(investigation_id: UUID, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            authorize(principal, principal.tenant_id, Permission.READ_INTELLIGENCE)
            row = db.execute(select(Investigation, User.active, User.role).outerjoin(User,
                and_(User.tenant_id == Investigation.tenant_id, User.id == Investigation.assignee_id)).where(
                    Investigation.tenant_id == principal.tenant_id, Investigation.id == investigation_id)).first()
            if row is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            record_event(db, principal.tenant_id, AuditType.INVESTIGATION_READ, principal.user_id, target_investigation_id=investigation_id)
            return {**investigation_output(*row), 'notice':'Eligibility reflects this query only; case history is not tamper-resistant.'}

    @router.get('/investigations/{investigation_id}/report', dependencies=[Depends(require_tls)])
    def investigation_report(investigation_id: UUID, token: str = Depends(bearer)):
        """Bounded analytical summary, not an evidentiary or consistent snapshot."""
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            authorize(principal, principal.tenant_id, Permission.READ_INTELLIGENCE)
            row = db.execute(select(Investigation, User.active, User.role).outerjoin(User,
                and_(User.tenant_id == Investigation.tenant_id, User.id == Investigation.assignee_id)).where(
                    Investigation.tenant_id == principal.tenant_id, Investigation.id == investigation_id)).first()
            if row is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            entity_rows = list(db.execute(select(InvestigationEntityLink, Entity).join(Entity,
                and_(Entity.tenant_id == InvestigationEntityLink.tenant_id, Entity.id == InvestigationEntityLink.entity_id))
                .where(InvestigationEntityLink.tenant_id == principal.tenant_id, InvestigationEntityLink.investigation_id == investigation_id)
                .order_by(InvestigationEntityLink.id).limit(51)))
            evidence_rows = list(db.execute(select(InvestigationEvidenceLink, EvidenceReference).join(EvidenceReference,
                and_(EvidenceReference.tenant_id == InvestigationEvidenceLink.tenant_id,
                     EvidenceReference.entity_id == InvestigationEvidenceLink.entity_id, EvidenceReference.id == InvestigationEvidenceLink.evidence_id))
                .where(InvestigationEvidenceLink.tenant_id == principal.tenant_id, InvestigationEvidenceLink.investigation_id == investigation_id)
                .order_by(InvestigationEvidenceLink.id).limit(51)))
            notes = list(db.scalars(select(InvestigationNote).where(InvestigationNote.tenant_id == principal.tenant_id,
                InvestigationNote.investigation_id == investigation_id).order_by(InvestigationNote.created_at, InvestigationNote.id).limit(51)))
            record_event(db, principal.tenant_id, AuditType.INVESTIGATION_REPORT_READ, principal.user_id, target_investigation_id=investigation_id)
            return {'generated_at':datetime.now(timezone.utc).isoformat(), 'investigation':investigation_output(*row),
                'entities':{'items':[{'link_id':str(link.id), 'entity':entity_output(entity),
                    'association_status':'analyst_association_unverified'} for link,entity in entity_rows[:50]], 'truncated':len(entity_rows)>50},
                'evidence':{'items':[{'link_id':str(link.id), 'entity_id':str(link.entity_id), 'evidence_id':str(evidence.id),
                    'description':evidence.description, 'source':evidence.source, 'reference':evidence.reference,
                    'sha256':evidence.sha256, 'status':'analyst_entered_unverified'} for link,evidence in evidence_rows[:50]],
                    'truncated':len(evidence_rows)>50},
                'notes':{'items':[{'id':str(note.id), 'author_id':str(note.author_id), 'body':note.body,
                    'created_at':note.created_at.isoformat(), 'status':'analyst_entered_unverified'} for note in notes[:50]],
                    'truncated':len(notes)>50},
                'notice':'Bounded report is not a consistent snapshot, complete history, verified evidence, chain of custody, or tamper-resistant record. Associations and notes are analyst assertions; supplied hashes are not verified.'}

    @router.patch('/investigations/{investigation_id}', dependencies=[Depends(require_tls)])
    def update_investigation(investigation_id: UUID, payload: InvestigationUpdateInput, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            try:
                authorize(principal, principal.tenant_id, Permission.WRITE_INTELLIGENCE)
            except PermissionError:
                raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
            case = db.scalar(select(Investigation).where(Investigation.tenant_id == principal.tenant_id,
                Investigation.id == investigation_id).with_for_update().execution_options(populate_existing=True))
            if case is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            if case.status != 'open':
                raise HTTPException(status_code=409, detail='Investigation is closed', headers={'Cache-Control':'no-store'})
            if case.version != payload.expected_version:
                raise HTTPException(status_code=409, detail='Version conflict', headers={'Cache-Control':'no-store'})
            previous = {'title':case.title, 'description':case.description}
            case.title, case.description = payload.title, payload.description
            case.version += 1
            db.add(InvestigationEvent(tenant_id=principal.tenant_id, investigation_id=case.id, actor_id=principal.user_id,
                event_type='details_changed', details={'previous':previous,
                'current':{'title':case.title, 'description':case.description}, 'version':case.version}))
            record_event(db, principal.tenant_id, AuditType.INVESTIGATION_UPDATED, principal.user_id, target_investigation_id=case.id)
            return {'id':str(case.id), 'version':case.version}

    @router.patch('/investigations/{investigation_id}/status', dependencies=[Depends(require_tls)])
    def change_investigation_status(investigation_id: UUID, payload: InvestigationStatusInput, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            try:
                authorize(principal, principal.tenant_id, Permission.WRITE_INTELLIGENCE)
            except PermissionError:
                raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
            case = db.scalar(select(Investigation).where(Investigation.tenant_id == principal.tenant_id, Investigation.id == investigation_id))
            if case is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            if case.version != payload.expected_version:
                raise HTTPException(status_code=409, detail='Version conflict', headers={'Cache-Control':'no-store'})
            previous = case.status
            changed = db.execute(update(Investigation).where(Investigation.tenant_id == principal.tenant_id,
                Investigation.id == investigation_id, Investigation.version == payload.expected_version)
                .values(status=payload.status.value, version=Investigation.version + 1).execution_options(synchronize_session=False))
            if changed.rowcount != 1:
                raise HTTPException(status_code=409, detail='Version conflict', headers={'Cache-Control':'no-store'})
            db.add(InvestigationEvent(tenant_id=principal.tenant_id, investigation_id=investigation_id, actor_id=principal.user_id,
                event_type='status_changed', details={'previous_status':previous, 'status':payload.status.value,
                'previous_version':payload.expected_version, 'version':payload.expected_version + 1}))
            record_event(db, principal.tenant_id, AuditType.INVESTIGATION_UPDATED, principal.user_id, target_investigation_id=investigation_id)
            return {'id':str(investigation_id), 'status':payload.status.value, 'version':payload.expected_version + 1}

    @router.patch('/investigations/{investigation_id}/assignment', dependencies=[Depends(require_tls)])
    def assign_investigation(investigation_id: UUID, payload: InvestigationAssignmentInput, token: str = Depends(bearer)):
        with factory.begin() as db:
            candidate = authenticate_session(db, token)
            if candidate is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            try:
                authorize(candidate, candidate.tenant_id, Permission.MANAGE_USERS)
            except PermissionError:
                raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
            # Lock both users in UUID order before the session lock, matching
            # account administration and preventing mutual-admin lock cycles.
            ids = {candidate.user_id}
            if payload.assignee_id is not None: ids.add(payload.assignee_id)
            users = list(db.scalars(select(User).where(User.tenant_id == candidate.tenant_id, User.id.in_(ids))
                .order_by(User.id).with_for_update().execution_options(populate_existing=True)))
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            try:
                authorize(principal, principal.tenant_id, Permission.MANAGE_USERS)
            except PermissionError:
                raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
            assignee = next((u for u in users if u.id == payload.assignee_id), None) if payload.assignee_id else None
            if payload.assignee_id is not None and (assignee is None or not assignee.active or assignee.role not in ('admin','analyst')):
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            case = db.scalar(select(Investigation).where(Investigation.tenant_id == principal.tenant_id,
                Investigation.id == investigation_id).with_for_update().execution_options(populate_existing=True))
            if case is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            if case.status != 'open':
                raise HTTPException(status_code=409, detail='Investigation is closed', headers={'Cache-Control':'no-store'})
            if case.version != payload.expected_version:
                raise HTTPException(status_code=409, detail='Version conflict', headers={'Cache-Control':'no-store'})
            previous = case.assignee_id
            case.assignee_id = payload.assignee_id
            case.version += 1
            db.add(InvestigationEvent(tenant_id=principal.tenant_id, investigation_id=case.id, actor_id=principal.user_id,
                event_type='assignment_changed', details={'previous_assignee_id':str(previous) if previous else None,
                'assignee_id':str(payload.assignee_id) if payload.assignee_id else None, 'version':case.version}))
            record_event(db, principal.tenant_id, AuditType.INVESTIGATION_ASSIGNED, principal.user_id,
                target_user_id=payload.assignee_id, target_investigation_id=case.id)
            return {'id':str(case.id), 'assignee_id':str(case.assignee_id) if case.assignee_id else None, 'version':case.version}

    @router.post('/investigations/{investigation_id}/entities', status_code=201, dependencies=[Depends(require_tls)])
    def link_investigation_entity(investigation_id: UUID, payload: InvestigationEntityInput, token: str = Depends(bearer)):
        try:
            with factory.begin() as db:
                principal = authenticate_session_locked(db, token)
                if principal is None:
                    raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
                try:
                    authorize(principal, principal.tenant_id, Permission.WRITE_INTELLIGENCE)
                except PermissionError:
                    raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
                case = db.scalar(select(Investigation).where(Investigation.tenant_id == principal.tenant_id,
                    Investigation.id == investigation_id).with_for_update())
                entity = db.scalar(select(Entity.id).where(Entity.tenant_id == principal.tenant_id, Entity.id == payload.entity_id))
                if case is None or entity is None:
                    raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
                if case.status != 'open':
                    raise HTTPException(status_code=409, detail='Investigation is closed', headers={'Cache-Control':'no-store'})
                link = InvestigationEntityLink(tenant_id=principal.tenant_id, investigation_id=case.id,
                    entity_id=entity, created_by=principal.user_id)
                db.add(link); db.flush()
                db.add(InvestigationEvent(tenant_id=principal.tenant_id, investigation_id=case.id, actor_id=principal.user_id,
                    event_type='entity_linked', details={'entity_id':str(entity), 'link_id':str(link.id), 'status':'analyst_association_unverified'}))
                record_event(db, principal.tenant_id, AuditType.INVESTIGATION_ENTITY_LINKED, principal.user_id,
                    target_entity_id=entity, target_investigation_id=case.id)
                return {'id':str(link.id), 'status':'analyst_association_unverified'}
        except IntegrityError:
            raise HTTPException(status_code=409, detail='Link could not be created', headers={'Cache-Control':'no-store'}) from None

    @router.get('/investigations/{investigation_id}/entities', dependencies=[Depends(require_tls)])
    def list_investigation_entities(investigation_id: UUID, after: UUID | None = None, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            authorize(principal, principal.tenant_id, Permission.READ_INTELLIGENCE)
            if db.scalar(select(Investigation.id).where(Investigation.tenant_id == principal.tenant_id, Investigation.id == investigation_id)) is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            query = select(InvestigationEntityLink).where(InvestigationEntityLink.tenant_id == principal.tenant_id,
                InvestigationEntityLink.investigation_id == investigation_id)
            if after is not None:
                anchor = db.scalar(select(InvestigationEntityLink.id).where(InvestigationEntityLink.tenant_id == principal.tenant_id,
                    InvestigationEntityLink.investigation_id == investigation_id, InvestigationEntityLink.id == after))
                if anchor is None:
                    raise HTTPException(status_code=404, detail='Cursor not found', headers={'Cache-Control':'no-store'})
                query = query.where(InvestigationEntityLink.id > after)
            links = list(db.scalars(query.order_by(InvestigationEntityLink.id).limit(101)))
            record_event(db, principal.tenant_id, AuditType.INVESTIGATION_READ, principal.user_id, target_investigation_id=investigation_id)
            return {'items':[{'id':str(x.id), 'entity_id':str(x.entity_id), 'created_by':str(x.created_by),
                'created_at':x.created_at.isoformat(), 'status':'analyst_association_unverified'} for x in links[:100]],
                'next_cursor':str(links[99].id) if len(links)>100 else None,
                'notice':'Analyst associations are not verified evidence; pagination is not a consistent snapshot.'}

    @router.get('/investigations/{investigation_id}/entities/{link_id}', dependencies=[Depends(require_tls)])
    def get_investigation_entity(investigation_id: UUID, link_id: UUID, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            authorize(principal, principal.tenant_id, Permission.READ_INTELLIGENCE)
            link = db.scalar(select(InvestigationEntityLink).where(InvestigationEntityLink.tenant_id == principal.tenant_id,
                InvestigationEntityLink.investigation_id == investigation_id, InvestigationEntityLink.id == link_id))
            if link is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            record_event(db, principal.tenant_id, AuditType.INVESTIGATION_READ, principal.user_id,
                target_investigation_id=investigation_id, target_entity_id=link.entity_id)
            return {'id':str(link.id), 'entity_id':str(link.entity_id), 'created_by':str(link.created_by),
                'created_at':link.created_at.isoformat(), 'status':'analyst_association_unverified',
                'notice':'Analyst association is unverified and is not evidence of involvement.'}

    @router.delete('/investigations/{investigation_id}/entities/{link_id}', dependencies=[Depends(require_tls)])
    def unlink_investigation_entity(investigation_id: UUID, link_id: UUID, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            try:
                authorize(principal, principal.tenant_id, Permission.WRITE_INTELLIGENCE)
            except PermissionError:
                raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
            case = db.scalar(select(Investigation).where(Investigation.tenant_id == principal.tenant_id,
                Investigation.id == investigation_id).with_for_update())
            link = db.scalar(select(InvestigationEntityLink).where(InvestigationEntityLink.tenant_id == principal.tenant_id,
                InvestigationEntityLink.investigation_id == investigation_id, InvestigationEntityLink.id == link_id))
            if case is None or link is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            if case.status != 'open':
                raise HTTPException(status_code=409, detail='Investigation is closed', headers={'Cache-Control':'no-store'})
            entity_id = link.entity_id
            if db.scalar(select(InvestigationEvidenceLink.id).where(InvestigationEvidenceLink.tenant_id == principal.tenant_id,
                InvestigationEvidenceLink.investigation_id == case.id, InvestigationEvidenceLink.entity_id == entity_id).limit(1)) is not None:
                raise HTTPException(status_code=409, detail='Unlink evidence references first', headers={'Cache-Control':'no-store'})
            db.delete(link); db.flush()
            db.add(InvestigationEvent(tenant_id=principal.tenant_id, investigation_id=case.id, actor_id=principal.user_id,
                event_type='entity_unlinked', details={'entity_id':str(entity_id), 'link_id':str(link_id)}))
            record_event(db, principal.tenant_id, AuditType.INVESTIGATION_ENTITY_UNLINKED, principal.user_id,
                target_entity_id=entity_id, target_investigation_id=case.id)
            return {'status':'unlinked'}

    @router.post('/investigations/{investigation_id}/evidence', status_code=201, dependencies=[Depends(require_tls)])
    def link_investigation_evidence(investigation_id: UUID, payload: InvestigationEvidenceInput, token: str = Depends(bearer)):
        try:
            with factory.begin() as db:
                principal = authenticate_session_locked(db, token)
                if principal is None:
                    raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
                try:
                    authorize(principal, principal.tenant_id, Permission.WRITE_INTELLIGENCE)
                except PermissionError:
                    raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
                case = db.scalar(select(Investigation).where(Investigation.tenant_id == principal.tenant_id, Investigation.id == investigation_id).with_for_update())
                entity_link = db.scalar(select(InvestigationEntityLink.id).where(InvestigationEntityLink.tenant_id == principal.tenant_id,
                    InvestigationEntityLink.investigation_id == investigation_id, InvestigationEntityLink.entity_id == payload.entity_id))
                evidence = db.scalar(select(EvidenceReference.id).where(EvidenceReference.tenant_id == principal.tenant_id,
                    EvidenceReference.entity_id == payload.entity_id, EvidenceReference.id == payload.evidence_id))
                if case is None or entity_link is None or evidence is None:
                    raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
                if case.status != 'open':
                    raise HTTPException(status_code=409, detail='Investigation is closed', headers={'Cache-Control':'no-store'})
                link = InvestigationEvidenceLink(tenant_id=principal.tenant_id, investigation_id=case.id,
                    entity_id=payload.entity_id, evidence_id=evidence, created_by=principal.user_id)
                db.add(link); db.flush()
                db.add(InvestigationEvent(tenant_id=principal.tenant_id, investigation_id=case.id, actor_id=principal.user_id,
                    event_type='evidence_linked', details={'entity_id':str(payload.entity_id), 'evidence_id':str(evidence),
                    'link_id':str(link.id), 'status':'analyst_entered_unverified'}))
                record_event(db, principal.tenant_id, AuditType.INVESTIGATION_EVIDENCE_LINKED, principal.user_id,
                    target_entity_id=payload.entity_id, target_investigation_id=case.id, target_evidence_id=evidence)
                return {'id':str(link.id), 'status':'analyst_entered_unverified'}
        except IntegrityError:
            raise HTTPException(status_code=409, detail='Link could not be created', headers={'Cache-Control':'no-store'}) from None

    @router.get('/investigations/{investigation_id}/evidence', dependencies=[Depends(require_tls)])
    def list_investigation_evidence(investigation_id: UUID, after: UUID | None = None, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            authorize(principal, principal.tenant_id, Permission.READ_INTELLIGENCE)
            if db.scalar(select(Investigation.id).where(Investigation.tenant_id == principal.tenant_id, Investigation.id == investigation_id)) is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            query = select(InvestigationEvidenceLink).where(InvestigationEvidenceLink.tenant_id == principal.tenant_id,
                InvestigationEvidenceLink.investigation_id == investigation_id)
            if after is not None:
                anchor = db.scalar(select(InvestigationEvidenceLink.id).where(InvestigationEvidenceLink.tenant_id == principal.tenant_id,
                    InvestigationEvidenceLink.investigation_id == investigation_id, InvestigationEvidenceLink.id == after))
                if anchor is None:
                    raise HTTPException(status_code=404, detail='Cursor not found', headers={'Cache-Control':'no-store'})
                query = query.where(InvestigationEvidenceLink.id > after)
            links = list(db.scalars(query.order_by(InvestigationEvidenceLink.id).limit(101)))
            record_event(db, principal.tenant_id, AuditType.INVESTIGATION_READ, principal.user_id, target_investigation_id=investigation_id)
            return {'items':[{'id':str(x.id), 'entity_id':str(x.entity_id), 'evidence_id':str(x.evidence_id),
                'created_by':str(x.created_by), 'created_at':x.created_at.isoformat(), 'status':'analyst_entered_unverified'} for x in links[:100]],
                'next_cursor':str(links[99].id) if len(links)>100 else None,
                'notice':'References are unverified; no files are retrieved or validated. Pagination is not a snapshot.'}

    @router.get('/investigations/{investigation_id}/evidence/{link_id}', dependencies=[Depends(require_tls)])
    def get_investigation_evidence(investigation_id: UUID, link_id: UUID, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            authorize(principal, principal.tenant_id, Permission.READ_INTELLIGENCE)
            link = db.scalar(select(InvestigationEvidenceLink).where(InvestigationEvidenceLink.tenant_id == principal.tenant_id,
                InvestigationEvidenceLink.investigation_id == investigation_id, InvestigationEvidenceLink.id == link_id))
            if link is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            record_event(db, principal.tenant_id, AuditType.INVESTIGATION_READ, principal.user_id,
                target_investigation_id=investigation_id, target_entity_id=link.entity_id, target_evidence_id=link.evidence_id)
            return {'id':str(link.id), 'entity_id':str(link.entity_id), 'evidence_id':str(link.evidence_id),
                'created_by':str(link.created_by), 'created_at':link.created_at.isoformat(), 'status':'analyst_entered_unverified',
                'notice':'Analyst association is unverified; no file or digest has been validated.'}

    @router.delete('/investigations/{investigation_id}/evidence/{link_id}', dependencies=[Depends(require_tls)])
    def unlink_investigation_evidence(investigation_id: UUID, link_id: UUID, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            try:
                authorize(principal, principal.tenant_id, Permission.WRITE_INTELLIGENCE)
            except PermissionError:
                raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
            case = db.scalar(select(Investigation).where(Investigation.tenant_id == principal.tenant_id, Investigation.id == investigation_id).with_for_update())
            link = db.scalar(select(InvestigationEvidenceLink).where(InvestigationEvidenceLink.tenant_id == principal.tenant_id,
                InvestigationEvidenceLink.investigation_id == investigation_id, InvestigationEvidenceLink.id == link_id))
            if case is None or link is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            if case.status != 'open':
                raise HTTPException(status_code=409, detail='Investigation is closed', headers={'Cache-Control':'no-store'})
            entity_id, evidence_id = link.entity_id, link.evidence_id
            db.delete(link); db.flush()
            db.add(InvestigationEvent(tenant_id=principal.tenant_id, investigation_id=case.id, actor_id=principal.user_id,
                event_type='evidence_unlinked', details={'entity_id':str(entity_id), 'evidence_id':str(evidence_id), 'link_id':str(link_id)}))
            record_event(db, principal.tenant_id, AuditType.INVESTIGATION_EVIDENCE_UNLINKED, principal.user_id,
                target_entity_id=entity_id, target_investigation_id=case.id, target_evidence_id=evidence_id)
            return {'status':'unlinked'}

    @router.post('/investigations/{investigation_id}/notes', status_code=201, dependencies=[Depends(require_tls)])
    def add_investigation_note(investigation_id: UUID, payload: InvestigationNoteInput, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            try:
                authorize(principal, principal.tenant_id, Permission.WRITE_INTELLIGENCE)
            except PermissionError:
                raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
            case = db.scalar(select(Investigation).where(Investigation.tenant_id == principal.tenant_id,
                Investigation.id == investigation_id).with_for_update())
            if case is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            if case.status != 'open':
                raise HTTPException(status_code=409, detail='Investigation is closed', headers={'Cache-Control':'no-store'})
            note = InvestigationNote(tenant_id=principal.tenant_id, investigation_id=case.id,
                author_id=principal.user_id, body=payload.body)
            db.add(note); db.flush()
            db.add(InvestigationEvent(tenant_id=principal.tenant_id, investigation_id=case.id, actor_id=principal.user_id,
                event_type='note_added', details={'note_id':str(note.id), 'status':'analyst_entered_unverified'}))
            record_event(db, principal.tenant_id, AuditType.INVESTIGATION_NOTE_CREATED, principal.user_id, target_investigation_id=case.id, target_note_id=note.id)
            return {'id':str(note.id), 'status':'analyst_entered_unverified'}

    @router.get('/investigations/{investigation_id}/notes', dependencies=[Depends(require_tls)])
    def list_investigation_notes(investigation_id: UUID, after: UUID | None = None, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            authorize(principal, principal.tenant_id, Permission.READ_INTELLIGENCE)
            if db.scalar(select(Investigation.id).where(Investigation.tenant_id == principal.tenant_id, Investigation.id == investigation_id)) is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            query = select(InvestigationNote).where(InvestigationNote.tenant_id == principal.tenant_id,
                InvestigationNote.investigation_id == investigation_id)
            if after is not None:
                anchor = db.scalar(select(InvestigationNote).where(InvestigationNote.tenant_id == principal.tenant_id,
                    InvestigationNote.investigation_id == investigation_id, InvestigationNote.id == after))
                if anchor is None:
                    raise HTTPException(status_code=404, detail='Cursor not found', headers={'Cache-Control':'no-store'})
                query = query.where(or_(InvestigationNote.created_at > anchor.created_at,
                    and_(InvestigationNote.created_at == anchor.created_at, InvestigationNote.id > anchor.id)))
            notes = list(db.scalars(query.order_by(InvestigationNote.created_at, InvestigationNote.id).limit(101)))
            record_event(db, principal.tenant_id, AuditType.INVESTIGATION_READ, principal.user_id, target_investigation_id=investigation_id)
            return {'items':[{'id':str(n.id), 'author_id':str(n.author_id), 'body':n.body,
                'created_at':n.created_at.isoformat(), 'status':'analyst_entered_unverified'} for n in notes[:100]],
                'next_cursor':str(notes[99].id) if len(notes)>100 else None,
                'notice':'Notes are analyst assertions, not verified facts or tamper-resistant; pagination is not a snapshot.'}

    @router.get('/investigations/{investigation_id}/notes/{note_id}', dependencies=[Depends(require_tls)])
    def get_investigation_note(investigation_id: UUID, note_id: UUID, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            authorize(principal, principal.tenant_id, Permission.READ_INTELLIGENCE)
            note = db.scalar(select(InvestigationNote).where(InvestigationNote.tenant_id == principal.tenant_id,
                InvestigationNote.investigation_id == investigation_id, InvestigationNote.id == note_id))
            if note is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            record_event(db, principal.tenant_id, AuditType.INVESTIGATION_READ, principal.user_id,
                target_investigation_id=investigation_id, target_note_id=note.id)
            return {'id':str(note.id), 'author_id':str(note.author_id), 'body':note.body,
                'created_at':note.created_at.isoformat(), 'status':'analyst_entered_unverified',
                'notice':'Analyst assertion, not verified or tamper-resistant.'}

    @router.get('/investigations/{investigation_id}/events', dependencies=[Depends(require_tls)])
    def list_investigation_events(investigation_id: UUID, after: UUID | None = None, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            authorize(principal, principal.tenant_id, Permission.READ_INTELLIGENCE)
            if db.scalar(select(Investigation.id).where(Investigation.tenant_id == principal.tenant_id, Investigation.id == investigation_id)) is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            query = select(InvestigationEvent).where(InvestigationEvent.tenant_id == principal.tenant_id, InvestigationEvent.investigation_id == investigation_id)
            if after is not None:
                anchor = db.scalar(select(InvestigationEvent).where(InvestigationEvent.tenant_id == principal.tenant_id,
                    InvestigationEvent.investigation_id == investigation_id, InvestigationEvent.id == after))
                if anchor is None:
                    raise HTTPException(status_code=404, detail='Cursor not found', headers={'Cache-Control':'no-store'})
                query = query.where(or_(InvestigationEvent.occurred_at > anchor.occurred_at,
                    and_(InvestigationEvent.occurred_at == anchor.occurred_at, InvestigationEvent.id > anchor.id)))
            events = list(db.scalars(query.order_by(InvestigationEvent.occurred_at, InvestigationEvent.id).limit(101)))
            record_event(db, principal.tenant_id, AuditType.INVESTIGATION_READ, principal.user_id, target_investigation_id=investigation_id)
            return {'items':[{'id':str(e.id), 'actor_id':str(e.actor_id), 'event_type':e.event_type,
                'details':e.details, 'occurred_at':e.occurred_at.isoformat()} for e in events[:100]],
                'next_cursor':str(events[99].id) if len(events) > 100 else None,
                'notice':'History is not tamper-resistant; traversal is not a consistent snapshot.'}

    @router.get('/investigations/{investigation_id}/events/{event_id}', dependencies=[Depends(require_tls)])
    def get_investigation_event(investigation_id: UUID, event_id: UUID, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            authorize(principal, principal.tenant_id, Permission.READ_INTELLIGENCE)
            event = db.scalar(select(InvestigationEvent).where(InvestigationEvent.tenant_id == principal.tenant_id,
                InvestigationEvent.investigation_id == investigation_id, InvestigationEvent.id == event_id))
            if event is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            # Audit currently targets the investigation, not the individual event.
            record_event(db, principal.tenant_id, AuditType.INVESTIGATION_EVENT_READ, principal.user_id, target_investigation_id=investigation_id)
            return {'id':str(event.id), 'actor_id':str(event.actor_id), 'event_type':event.event_type,
                'details':event.details, 'occurred_at':event.occurred_at.isoformat(),
                'notice':'History is not tamper-resistant; recorded assertions may be unverified.'}

    @router.get('/audit', dependencies=[Depends(require_tls)])
    def audit_events(before: UUID | None = None, investigation_id: UUID | None = None, entity_id: UUID | None = None, evidence_id: UUID | None = None, user_id: UUID | None = None, event_type: AuditType | None = None, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            try:
                authorize(principal, principal.tenant_id, Permission.MANAGE_USERS)
            except PermissionError:
                raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
            query = select(SecurityAuditEvent).where(SecurityAuditEvent.tenant_id == principal.tenant_id)
            if investigation_id is not None: query = query.where(SecurityAuditEvent.target_investigation_id == investigation_id)
            if user_id is not None: query = query.where(SecurityAuditEvent.target_user_id == user_id)
            if entity_id is not None: query = query.where(SecurityAuditEvent.target_entity_id == entity_id)
            if evidence_id is not None: query = query.where(SecurityAuditEvent.target_evidence_id == evidence_id)
            if event_type is not None: query = query.where(SecurityAuditEvent.event_type == event_type.value)
            if before is not None:
                anchor = db.scalar(query.where(SecurityAuditEvent.id == before))
                if anchor is None:
                    raise HTTPException(status_code=404, detail='Cursor not found', headers={'Cache-Control':'no-store'})
                query = query.where(or_(SecurityAuditEvent.occurred_at < anchor.occurred_at,
                    and_(SecurityAuditEvent.occurred_at == anchor.occurred_at, SecurityAuditEvent.id < anchor.id)))
            events = list(db.scalars(query.order_by(SecurityAuditEvent.occurred_at.desc(), SecurityAuditEvent.id.desc()).limit(101)))
            record_event(db, principal.tenant_id, AuditType.AUDIT_READ, principal.user_id)
            return {'items': [{'id': str(e.id), 'event_type': e.event_type,
                               'actor_id': str(e.actor_id) if e.actor_id else None,
                               'target_user_id': str(e.target_user_id) if e.target_user_id else None,
                               'target_entity_id': str(e.target_entity_id) if e.target_entity_id else None,
                               'target_evidence_id': str(e.target_evidence_id) if e.target_evidence_id else None,
                               'target_investigation_id': str(e.target_investigation_id) if e.target_investigation_id else None,
                               'target_note_id': str(e.target_note_id) if e.target_note_id else None,
                               'target_session_id': str(e.target_session_id) if e.target_session_id else None,
                               'previous_role': e.previous_role, 'new_role': e.new_role,
                               'occurred_at': e.occurred_at.isoformat()} for e in events[:100]],
                    'limit': 100, 'next_cursor': str(events[99].id) if len(events) > 100 else None,
                    'notice': 'Audit storage is not tamper-resistant; concurrent changes may not appear during traversal.'}

    def require_active_token(token: str):
        # Authenticate before expensive password hashing; account services recheck
        # authorization in the mutation transaction to avoid relying on this check alone.
        with factory() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            try:
                authorize(principal, principal.tenant_id, Permission.MANAGE_USERS)
            except PermissionError:
                raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None

    @router.get('/sources/nvd/cves/{cve_id}', dependencies=[Depends(require_tls)])
    def nvd_observation(cve_id: str, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            authorize(principal, principal.tenant_id, Permission.READ_INTELLIGENCE)
            try:
                _cve_id(cve_id)
            except ValueError:
                raise HTTPException(status_code=422, detail='Invalid request', headers={'Cache-Control':'no-store'}) from None
            observation = db.scalar(select(NvdCatalogRecord).where(
                NvdCatalogRecord.tenant_id == principal.tenant_id, NvdCatalogRecord.cve_id == cve_id))
            if observation is None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            record_event(db, principal.tenant_id, AuditType.NVD_RECORD_READ, principal.user_id, target_entity_id=observation.entity_id)
            # SQLite removes timezone metadata from stored UTC values.
            def utc_iso(value):
                return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)).isoformat()
            return {'entity_id': str(observation.entity_id), 'observation': observation.details,
                'first_collected_at': utc_iso(observation.first_collected_at),
                'last_collected_at': utc_iso(observation.last_collected_at), 'verification_status': 'unverified',
                'notice': 'Source observation is not independently verified; imported timestamps do not indicate live source health.'}

    @router.get('/sources/nvd/attempts', dependencies=[Depends(require_tls)])
    def nvd_attempts(before: UUID | None = None, status: NvdAttemptStatus | None = None,
                     cve_id: str | None = Query(default=None, min_length=1, max_length=32),
                     token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            try:
                authorize(principal, principal.tenant_id, Permission.MANAGE_USERS)
            except PermissionError:
                raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
            if cve_id is not None:
                try:
                    _cve_id(cve_id)
                except ValueError:
                    raise HTTPException(status_code=422, detail='Invalid request', headers={'Cache-Control':'no-store'}) from None
            query = select(NvdSyncAttempt).where(NvdSyncAttempt.tenant_id == principal.tenant_id)
            if status is not None: query = query.where(NvdSyncAttempt.status == status.value)
            if cve_id is not None: query = query.where(NvdSyncAttempt.cve_id == cve_id)
            if before is not None:
                anchor = db.scalar(query.where(NvdSyncAttempt.id == before))
                if anchor is None:
                    raise HTTPException(status_code=404, detail='Cursor not found', headers={'Cache-Control':'no-store'})
                query = query.where(or_(NvdSyncAttempt.started_at < anchor.started_at,
                    and_(NvdSyncAttempt.started_at == anchor.started_at, NvdSyncAttempt.id < anchor.id)))
            attempts = list(db.scalars(query.order_by(NvdSyncAttempt.started_at.desc(), NvdSyncAttempt.id.desc()).limit(101)))
            record_event(db, principal.tenant_id, AuditType.NVD_ATTEMPTS_READ, principal.user_id)
            def utc_iso(value):
                return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)).isoformat()
            return {'items': [{'id': str(x.id), 'actor_id': str(x.actor_id), 'cve_id': x.cve_id,
                'status': x.status, 'started_at': utc_iso(x.started_at),
                'finished_at': utc_iso(x.finished_at) if x.finished_at else None, 'error_code': x.error_code}
                for x in attempts[:100]], 'limit': 100,
                'next_cursor': str(attempts[99].id) if len(attempts) > 100 else None,
                'notice': 'Attempt history is not a consistent snapshot or evidence of live source health.'}

    @router.get('/sources/nvd/status', dependencies=[Depends(require_tls)])
    def nvd_status(token: str = Depends(bearer)):
        require_active_token(token)
        try:
            status = get_nvd_status(factory, admin_token=token)
        except PermissionError:
            raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
        return {'source': 'NIST National Vulnerability Database', 'integration': 'experimental_not_live_verified', **status,
                'notice': 'Attempt status reflects a single lookup, not live source health or absence of vulnerability.'}

    @router.post('/sources/nvd/attempts/{attempt_id}/abandon', dependencies=[Depends(require_tls)])
    def abandon_nvd_attempt(attempt_id: UUID, token: str = Depends(bearer)):
        require_active_token(token)
        try:
            abandoned = abandon_nvd_sync(factory, admin_token=token, attempt_id=attempt_id)
        except PermissionError:
            raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
        if not abandoned:
            raise HTTPException(status_code=404, detail='Active attempt not found', headers={'Cache-Control':'no-store'})
        return {'status':'abandoned', 'notice':'The worker may still run, but its result cannot be imported.'}

    @router.get('/sources/cisa-kev/attempts', dependencies=[Depends(require_tls)])
    def cisa_attempts(before: UUID | None = None, status: CisaAttemptStatus | None = None, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            try:
                authorize(principal, principal.tenant_id, Permission.MANAGE_USERS)
            except PermissionError:
                raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
            query = select(CisaSyncAttempt).where(CisaSyncAttempt.tenant_id == principal.tenant_id)
            if status is not None: query = query.where(CisaSyncAttempt.status == status.value)
            if before is not None:
                anchor = db.scalar(query.where(CisaSyncAttempt.id == before))
                if anchor is None:
                    raise HTTPException(status_code=404, detail='Cursor not found', headers={'Cache-Control':'no-store'})
                query = query.where(or_(CisaSyncAttempt.started_at < anchor.started_at,
                    and_(CisaSyncAttempt.started_at == anchor.started_at, CisaSyncAttempt.id < anchor.id)))
            attempts = list(db.scalars(query.order_by(CisaSyncAttempt.started_at.desc(), CisaSyncAttempt.id.desc()).limit(101)))
            record_event(db, principal.tenant_id, AuditType.CISA_ATTEMPTS_READ, principal.user_id)
            def utc_iso(value):
                return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)).isoformat()
            return {'items': [{'id': str(x.id), 'actor_id': str(x.actor_id), 'status': x.status,
                'started_at': utc_iso(x.started_at), 'finished_at': utc_iso(x.finished_at) if x.finished_at else None,
                'error_code': x.error_code} for x in attempts[:100]], 'limit': 100,
                'next_cursor': str(attempts[99].id) if len(attempts) > 100 else None,
                'notice': 'Attempt history is not a consistent snapshot or evidence of live source health.'}

    @router.get('/sources/cisa-kev/status', dependencies=[Depends(require_tls)])
    def cisa_status(token: str = Depends(bearer)):
        require_active_token(token)
        try:
            status = get_status(factory, admin_token=token)
        except PermissionError:
            raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
        return {'source':'CISA KEV', 'integration':'experimental_not_live_verified', **status,
                'notice':'No live source verification or scheduler is configured; timestamps reflect recorded attempts and imports only.'}

    @router.post('/sources/cisa-kev/attempts/{attempt_id}/abandon', dependencies=[Depends(require_tls)])
    def abandon_cisa_attempt(attempt_id: UUID, token: str = Depends(bearer)):
        require_active_token(token)
        try:
            abandoned = abandon_sync(factory, admin_token=token, attempt_id=attempt_id)
        except PermissionError:
            raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
        if not abandoned:
            raise HTTPException(status_code=404, detail='Active attempt not found', headers={'Cache-Control':'no-store'})
        return {'status':'abandoned', 'notice':'The worker may still run, but its result cannot be imported.'}

    @router.get('/users', dependencies=[Depends(require_tls)])
    def list_users(after: UUID | None = None, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            try:
                authorize(principal, principal.tenant_id, Permission.MANAGE_USERS)
            except PermissionError:
                raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
            query = select(User).where(User.tenant_id == principal.tenant_id)
            if after is not None:
                if db.scalar(select(User.id).where(User.tenant_id == principal.tenant_id, User.id == after)) is None:
                    raise HTTPException(status_code=404, detail='Cursor not found', headers={'Cache-Control':'no-store'})
                query = query.where(User.id > after)
            users = list(db.scalars(query.order_by(User.id).limit(101)))
            record_event(db, principal.tenant_id, AuditType.USER_DIRECTORY_READ, principal.user_id)
            return {'items':[{'id':str(user.id), 'username':user.username, 'role':user.role, 'active':user.active} for user in users[:100]],
                    'next_cursor':str(users[99].id) if len(users)>100 else None,
                    'notice':'Results are tenant-scoped; pagination is not a consistent snapshot.'}

    @router.post('/users', status_code=201, dependencies=[Depends(require_tls)])
    def add_user(payload: CreateUserInput, token: str = Depends(bearer)):
        require_active_token(token)
        try:
            user_id = create_user(factory, admin_token=token, username=payload.username, password=payload.password, role=payload.role)
        except PermissionError:
            raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
        except ValueError:
            raise HTTPException(status_code=422, detail='Invalid request', headers={'Cache-Control':'no-store'}) from None
        except IntegrityError:
            raise HTTPException(status_code=409, detail='Account could not be created', headers={'Cache-Control':'no-store'}) from None
        return {'id': str(user_id)}

    @router.patch('/users/{user_id}/role', dependencies=[Depends(require_tls)])
    def set_role(user_id: UUID, payload: ChangeRoleInput, token: str = Depends(bearer)):
        require_active_token(token)
        try:
            change_role(factory, admin_token=token, user_id=user_id, role=payload.role)
        except PermissionError:
            raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
        return {'status': 'updated'}

    @router.post('/users/{user_id}/disable', dependencies=[Depends(require_tls)])
    def deactivate_user(user_id: UUID, token: str = Depends(bearer)):
        require_active_token(token)
        try:
            disable_user(factory, admin_token=token, user_id=user_id)
        except PermissionError:
            raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
        return {'status': 'disabled'}

    @router.get('/sessions', dependencies=[Depends(require_tls)])
    def list_own_sessions(after: UUID | None = None, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            # The session digest is only used for comparison, never returned.
            current_id = db.scalar(select(AuthSession.id).where(AuthSession.tenant_id == principal.tenant_id,
                AuthSession.user_id == principal.user_id, AuthSession.token_digest == _digest(token)))
            query = select(AuthSession).where(AuthSession.tenant_id == principal.tenant_id, AuthSession.user_id == principal.user_id)
            if after is not None:
                anchor = db.scalar(select(AuthSession.id).where(AuthSession.tenant_id == principal.tenant_id,
                    AuthSession.user_id == principal.user_id, AuthSession.id == after))
                if anchor is None:
                    raise HTTPException(status_code=404, detail='Cursor not found', headers={'Cache-Control':'no-store'})
                query = query.where(AuthSession.id > after)
            rows = list(db.scalars(query.order_by(AuthSession.id).limit(101)))
            record_event(db, principal.tenant_id, AuditType.SESSION_LIST_READ, principal.user_id, principal.user_id)
            return {'items':[{'id':str(row.id), 'created_at':row.created_at.isoformat(), 'expires_at':row.expires_at.isoformat(),
                'revoked_at':row.revoked_at.isoformat() if row.revoked_at else None, 'current':row.id == current_id} for row in rows[:100]],
                'next_cursor':str(rows[99].id) if len(rows)>100 else None,
                'notice':'Session metadata is retained until cleanup; pagination is not a snapshot.'}

    @router.delete('/sessions/{session_id}', dependencies=[Depends(require_tls)])
    def revoke_own_session(session_id: UUID, token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            session = db.scalar(select(AuthSession).where(AuthSession.tenant_id == principal.tenant_id,
                AuthSession.user_id == principal.user_id, AuthSession.id == session_id).with_for_update())
            if session is None or session.revoked_at is not None:
                raise HTTPException(status_code=404, detail='Not found', headers={'Cache-Control':'no-store'})
            session.revoked_at = datetime.now(timezone.utc)
            record_event(db, principal.tenant_id, AuditType.SESSION_SINGLE_REVOKED, principal.user_id,
                         principal.user_id, target_session_id=session.id)
            return {'status':'revoked'}

    @router.get('/me', dependencies=[Depends(require_tls)])
    def current_user(token: str = Depends(bearer)):
        with factory.begin() as db:
            principal = authenticate_session_locked(db, token)
            if principal is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            user = db.scalar(select(User).where(User.tenant_id == principal.tenant_id, User.id == principal.user_id))
            if user is None:
                raise HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate':'Bearer', 'Cache-Control':'no-store'})
            record_event(db, principal.tenant_id, AuditType.USER_SELF_READ, principal.user_id, principal.user_id)
            return {'id':str(principal.user_id), 'tenant_id':str(principal.tenant_id), 'username':user.username, 'role':principal.role.value}

    @router.post('/password', dependencies=[Depends(require_tls)])
    def change_password(payload: ChangePasswordInput, token: str = Depends(bearer)):
        require_active_token(token)
        try:
            change_own_password(factory, token=token, secret=secret, current_password=payload.current_password, new_password=payload.new_password)
        except PermissionError:
            raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
        except PasswordChangeThrottled:
            raise HTTPException(status_code=429, detail='Too many attempts', headers={'Cache-Control':'no-store'}) from None
        except ValueError:
            raise HTTPException(status_code=422, detail='Invalid request', headers={'Cache-Control':'no-store'}) from None
        return {'status':'password changed', 'notice':'All existing sessions were revoked; sign in again.'}

    @router.post('/users/{user_id}/revoke-sessions', dependencies=[Depends(require_tls)])
    def revoke_account_sessions(user_id: UUID, token: str = Depends(bearer)):
        require_active_token(token)
        try:
            count = revoke_user_sessions(factory, admin_token=token, user_id=user_id)
        except PermissionError:
            raise HTTPException(status_code=403, detail='Access denied', headers={'Cache-Control':'no-store'}) from None
        return {'status':'revoked', 'count':count,
                'notice':'Existing sessions revoked; the account remains active and can log in again.'}

    return router
