"""Experimental tenant-scoped database schema; not yet production validated."""
from datetime import datetime, timezone
from uuid import UUID, uuid4
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint, Index, JSON, String, UniqueConstraint, Uuid, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

class Base(DeclarativeBase):
    pass

json_type = JSON().with_variant(JSONB(), "postgresql")

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False)

class Entity(Base):
    __tablename__ = "intelligence_entities"
    __table_args__ = (UniqueConstraint("tenant_id", "id"),
        Index('ix_entity_tenant_kind_id', 'tenant_id', 'kind', 'id'),
        CheckConstraint('confidence IS NULL OR (confidence >= 0 AND confidence <= 100)', name='ck_entity_confidence'),
        ForeignKeyConstraint(['tenant_id', 'created_by'], ['users.tenant_id', 'users.id']))
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    source: Mapped[str] = mapped_column(String(500), nullable=False)
    source_reference: Mapped[str | None] = mapped_column(String(2048))
    properties: Mapped[dict] = mapped_column(json_type, default=dict, nullable=False)
    confidence: Mapped[int | None] = mapped_column(nullable=True)
    version: Mapped[int] = mapped_column(default=1, server_default='1', nullable=False)
    verification_status: Mapped[str] = mapped_column(String(32), default='unverified', server_default='unverified', nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(Uuid, nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

class Relationship(Base):
    __tablename__ = "intelligence_relationships"
    __table_args__ = (
        Index('ix_rel_tenant_subject_time_id', 'tenant_id', 'subject_id', 'created_at', 'id'),
        Index('ix_rel_tenant_object_time_id', 'tenant_id', 'object_id', 'created_at', 'id'),
        ForeignKeyConstraint(["tenant_id", "subject_id"], ["intelligence_entities.tenant_id", "intelligence_entities.id"]),
        ForeignKeyConstraint(["tenant_id", "object_id"], ["intelligence_entities.tenant_id", "intelligence_entities.id"]),
        ForeignKeyConstraint(['tenant_id', 'created_by'], ['users.tenant_id', 'users.id']),
        ForeignKeyConstraint(['tenant_id', 'subject_id', 'evidence_id'], ['evidence_references.tenant_id', 'evidence_references.entity_id', 'evidence_references.id']),
        CheckConstraint('confidence IS NULL OR (confidence >= 0 AND confidence <= 100)', name='ck_relationship_confidence'),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)
    subject_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    object_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(String(500), nullable=False)
    created_by: Mapped[UUID | None] = mapped_column(Uuid, nullable=True)
    evidence_id: Mapped[UUID | None] = mapped_column(Uuid, nullable=True)
    confidence: Mapped[int | None] = mapped_column(nullable=True)
    provenance: Mapped[dict] = mapped_column(json_type, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

class User(Base):
    """Local identity foundation. Account provisioning is intentionally not exposed."""
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint('tenant_id', 'id'), UniqueConstraint('tenant_id', 'username'))
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey('tenants.id'), nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    active: Mapped[bool] = mapped_column(default=True, nullable=False)

class AuthSession(Base):
    __tablename__ = 'auth_sessions'
    __table_args__ = (
        Index('ix_auth_sessions_expires_id', 'expires_at', 'id'),
        ForeignKeyConstraint(['tenant_id', 'user_id'], ['users.tenant_id', 'users.id']),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey('tenants.id'), nullable=False, index=True)
    user_id: Mapped[UUID] = mapped_column(Uuid, nullable=False, index=True)
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class SecurityAuditEvent(Base):
    """Minimal tenant-scoped audit event, never stores request bodies or credentials."""
    __tablename__ = 'security_audit_events'
    __table_args__ = (Index('ix_audit_tenant_time_id', 'tenant_id', 'occurred_at', 'id'),
                      Index('ix_audit_tenant_case_time_id', 'tenant_id', 'target_investigation_id', 'occurred_at', 'id'),
                      Index('ix_audit_tenant_evidence_time_id', 'tenant_id', 'target_evidence_id', 'occurred_at', 'id'),
                      Index('ix_audit_tenant_entity_time_id', 'tenant_id', 'target_entity_id', 'occurred_at', 'id'),
                      Index('ix_audit_tenant_user_time_id', 'tenant_id', 'target_user_id', 'occurred_at', 'id'),
                      ForeignKeyConstraint(['tenant_id', 'actor_id'], ['users.tenant_id', 'users.id']),
                      ForeignKeyConstraint(['tenant_id', 'target_user_id'], ['users.tenant_id', 'users.id']),
                      ForeignKeyConstraint(['tenant_id', 'target_entity_id'], ['intelligence_entities.tenant_id', 'intelligence_entities.id']),
                      ForeignKeyConstraint(['tenant_id', 'target_entity_id', 'target_evidence_id'], ['evidence_references.tenant_id', 'evidence_references.entity_id', 'evidence_references.id'], name='fk_audit_evidence_scope'),
                      ForeignKeyConstraint(['tenant_id', 'target_investigation_id'], ['investigations.tenant_id', 'investigations.id']),
                      ForeignKeyConstraint(['tenant_id', 'target_investigation_id', 'target_note_id'], ['investigation_notes.tenant_id', 'investigation_notes.investigation_id', 'investigation_notes.id']),
                      CheckConstraint('target_note_id IS NULL OR target_investigation_id IS NOT NULL', name='ck_audit_note_has_case'),
                      CheckConstraint('target_session_id IS NULL OR target_user_id IS NOT NULL', name='ck_audit_session_has_user'),
                      CheckConstraint('target_evidence_id IS NULL OR target_entity_id IS NOT NULL', name='ck_audit_evidence_has_entity'))
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey('tenants.id'), nullable=False, index=True)
    actor_id: Mapped[UUID | None] = mapped_column(Uuid, nullable=True)
    target_user_id: Mapped[UUID | None] = mapped_column(Uuid, nullable=True)
    target_entity_id: Mapped[UUID | None] = mapped_column(Uuid, nullable=True)
    target_evidence_id: Mapped[UUID | None] = mapped_column(Uuid, nullable=True)
    target_investigation_id: Mapped[UUID | None] = mapped_column(Uuid, nullable=True)
    target_note_id: Mapped[UUID | None] = mapped_column(Uuid, nullable=True)
    # Snapshot identifier: intentionally no FK, so session cleanup can retain audit.
    target_session_id: Mapped[UUID | None] = mapped_column(Uuid, nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    new_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

class RateLimitBucket(Base):
    """Fixed window counter; identifier is a keyed digest, not a username or IP."""
    __tablename__ = 'rate_limit_buckets'
    __table_args__ = (Index('ix_rate_limit_window_start', 'window_start'),)
    key_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    window_start: Mapped[int] = mapped_column(primary_key=True)
    attempts: Mapped[int] = mapped_column(nullable=False)

class EvidenceReference(Base):
    """An analyst-entered reference, not an uploaded file or verified evidence."""
    __tablename__ = 'evidence_references'
    __table_args__ = (
        UniqueConstraint('tenant_id', 'entity_id', 'id'),
        ForeignKeyConstraint(['tenant_id', 'entity_id'], ['intelligence_entities.tenant_id', 'intelligence_entities.id']),
        ForeignKeyConstraint(['tenant_id', 'created_by'], ['users.tenant_id', 'users.id']),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey('tenants.id'), nullable=False, index=True)
    entity_id: Mapped[UUID] = mapped_column(Uuid, nullable=False, index=True)
    created_by: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    description: Mapped[str] = mapped_column(String(2000), nullable=False)
    source: Mapped[str] = mapped_column(String(500), nullable=False)
    reference: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

class ProvenanceEvent(Base):
    """Immutable through the API; database-level tamper protection is not implemented."""
    __tablename__ = 'provenance_events'
    __table_args__ = (
        Index('ix_provenance_tenant_entity_time_id', 'tenant_id', 'entity_id', 'occurred_at', 'id'),
        ForeignKeyConstraint(['tenant_id', 'entity_id'], ['intelligence_entities.tenant_id', 'intelligence_entities.id']),
        ForeignKeyConstraint(['tenant_id', 'actor_id'], ['users.tenant_id', 'users.id']),
        ForeignKeyConstraint(['tenant_id', 'entity_id', 'evidence_id'], ['evidence_references.tenant_id', 'evidence_references.entity_id', 'evidence_references.id']),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey('tenants.id'), nullable=False, index=True)
    entity_id: Mapped[UUID] = mapped_column(Uuid, nullable=False, index=True)
    actor_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    evidence_id: Mapped[UUID | None] = mapped_column(Uuid, nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    details: Mapped[dict] = mapped_column(json_type, nullable=False, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

class CisaCatalogState(Base):
    """Last successfully imported KEV catalog, not connector health."""
    __tablename__ = 'cisa_catalog_states'
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey('tenants.id'), primary_key=True)
    catalog_version: Mapped[str] = mapped_column(String(100), nullable=False)
    released_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

class CisaCatalogRecord(Base):
    """The latest successfully imported source observation for one CVE."""
    __tablename__ = 'cisa_catalog_records'
    __table_args__ = (
        UniqueConstraint('tenant_id', 'cve_id'),
        ForeignKeyConstraint(['tenant_id', 'entity_id'], ['intelligence_entities.tenant_id', 'intelligence_entities.id']),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey('tenants.id'), nullable=False, index=True)
    entity_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False)
    details: Mapped[dict] = mapped_column(json_type, nullable=False)
    first_collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

class NvdCatalogRecord(Base):
    """Latest imported NVD observation; separate from analyst-editable fields."""
    __tablename__ = 'nvd_catalog_records'
    __table_args__ = (
        UniqueConstraint('tenant_id', 'cve_id'),
        ForeignKeyConstraint(['tenant_id', 'entity_id'], ['intelligence_entities.tenant_id', 'intelligence_entities.id']),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey('tenants.id'), nullable=False, index=True)
    entity_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False)
    details: Mapped[dict] = mapped_column(json_type, nullable=False)
    first_collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

class NvdSyncAttempt(Base):
    """One manually requested CVE lookup, not a source-health indicator."""
    __tablename__ = 'nvd_sync_attempts'
    __table_args__ = (
        ForeignKeyConstraint(['tenant_id', 'actor_id'], ['users.tenant_id', 'users.id']),
        CheckConstraint("status IN ('running', 'succeeded', 'not_found', 'failed', 'abandoned')", name='ck_nvd_sync_status'),
        Index('uq_nvd_sync_running_tenant', 'tenant_id', unique=True, postgresql_where=text("status = 'running'"), sqlite_where=text("status = 'running'")),
        Index('ix_nvd_sync_tenant_started_id', 'tenant_id', 'started_at', 'id'),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey('tenants.id'), nullable=False, index=True)
    actor_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(32), nullable=True)

class CisaSyncAttempt(Base):
    """Operational history, including attempts that did not import a snapshot."""
    __tablename__ = 'cisa_sync_attempts'
    __table_args__ = (
        ForeignKeyConstraint(['tenant_id', 'actor_id'], ['users.tenant_id', 'users.id']),
        CheckConstraint("status IN ('running', 'succeeded', 'failed', 'abandoned')", name='ck_cisa_sync_status'),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey('tenants.id'), nullable=False, index=True)
    actor_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(32), nullable=True)

class Investigation(Base):
    """Experimental case foundation; no evidence storage or chain of custody."""
    __tablename__ = 'investigations'
    __table_args__ = (
        UniqueConstraint('tenant_id', 'id'),
        ForeignKeyConstraint(['tenant_id', 'created_by'], ['users.tenant_id', 'users.id']),
        ForeignKeyConstraint(['tenant_id', 'assignee_id'], ['users.tenant_id', 'users.id']),
        CheckConstraint("status IN ('open', 'closed')", name='ck_investigation_status'),
        CheckConstraint('version >= 1', name='ck_investigation_version'),
        Index('ix_investigations_tenant_id_id', 'tenant_id', 'id'),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey('tenants.id'), nullable=False)
    created_by: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(String(4000), nullable=False)
    assignee_id: Mapped[UUID | None] = mapped_column(Uuid, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default='open', server_default='open', nullable=False)
    version: Mapped[int] = mapped_column(default=1, server_default='1', nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

class InvestigationEvent(Base):
    """Case history, not tamper-resistant and not a substitute for audit retention."""
    __tablename__ = 'investigation_events'
    __table_args__ = (
        ForeignKeyConstraint(['tenant_id', 'investigation_id'], ['investigations.tenant_id', 'investigations.id']),
        ForeignKeyConstraint(['tenant_id', 'actor_id'], ['users.tenant_id', 'users.id']),
        Index('ix_investigation_events_scope_time_id', 'tenant_id', 'investigation_id', 'occurred_at', 'id'),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey('tenants.id'), nullable=False)
    investigation_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    actor_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    details: Mapped[dict] = mapped_column(json_type, default=dict, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

class InvestigationEntityLink(Base):
    """Analyst-selected association, not verified evidence of involvement."""
    __tablename__ = 'investigation_entity_links'
    __table_args__ = (
        ForeignKeyConstraint(['tenant_id','investigation_id'], ['investigations.tenant_id','investigations.id']),
        ForeignKeyConstraint(['tenant_id','entity_id'], ['intelligence_entities.tenant_id','intelligence_entities.id']),
        ForeignKeyConstraint(['tenant_id','created_by'], ['users.tenant_id','users.id']),
        UniqueConstraint('tenant_id','investigation_id','entity_id', name='uq_investigation_entity_link'),
        Index('ix_investigation_link_scope_id', 'tenant_id','investigation_id','id'),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey('tenants.id'), nullable=False)
    investigation_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    entity_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    created_by: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

class InvestigationEvidenceLink(Base):
    """Association to an unverified reference, not file custody or validation."""
    __tablename__ = 'investigation_evidence_links'
    __table_args__ = (
        ForeignKeyConstraint(['tenant_id','investigation_id','entity_id'], ['investigation_entity_links.tenant_id','investigation_entity_links.investigation_id','investigation_entity_links.entity_id']),
        ForeignKeyConstraint(['tenant_id','entity_id','evidence_id'], ['evidence_references.tenant_id','evidence_references.entity_id','evidence_references.id']),
        ForeignKeyConstraint(['tenant_id','created_by'], ['users.tenant_id','users.id']),
        UniqueConstraint('tenant_id','investigation_id','evidence_id', name='uq_investigation_evidence_link'),
        Index('ix_investigation_evidence_scope_id', 'tenant_id','investigation_id','id'),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey('tenants.id'), nullable=False)
    investigation_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    entity_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    evidence_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    created_by: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

class InvestigationNote(Base):
    """Analyst-authored note; immutable through API, not tamper-resistant."""
    __tablename__ = 'investigation_notes'
    __table_args__ = (
        UniqueConstraint('tenant_id','investigation_id','id', name='uq_investigation_note_scope'),
        ForeignKeyConstraint(['tenant_id','investigation_id'], ['investigations.tenant_id','investigations.id']),
        ForeignKeyConstraint(['tenant_id','author_id'], ['users.tenant_id','users.id']),
        Index('ix_investigation_notes_scope_time_id', 'tenant_id','investigation_id','created_at','id'),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey('tenants.id'), nullable=False)
    investigation_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    author_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    body: Mapped[str] = mapped_column(String(4000), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
