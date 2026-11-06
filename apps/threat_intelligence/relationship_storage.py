"""PostgreSQL persistence for the experimental relationship API.

No connections, migrations or tables are created at import time. The caller owns
engine lifecycle, schema deployment and authenticated principal resolution.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import (BigInteger, Column, DateTime, ForeignKeyConstraint,
                        Identity, Index, MetaData, String, Table,
                        UniqueConstraint, and_, func, or_, select, text, tuple_)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID, insert
from sqlalchemy.engine import Engine

from .relationship_analysis import RelationshipRecord, RelationshipType

metadata = MetaData()
entity = Table('ti_relationship_entity', metadata,
    Column('tenant_id', String(256), primary_key=True),
    Column('entity_type', String(256), primary_key=True),
    Column('entity_id', String(256), primary_key=True))
relationship = Table('ti_relationship_record', metadata,
    Column('sequence', BigInteger, Identity(), primary_key=True),
    Column('tenant_id', String(256), nullable=False),
    Column('relationship_id', PGUUID(as_uuid=True), nullable=False),
    Column('source_type', String(256), nullable=False), Column('source_id', String(256), nullable=False),
    Column('target_type', String(256), nullable=False), Column('target_id', String(256), nullable=False),
    Column('relationship_type', String(32), nullable=False),
    Column('fingerprint', String(64), nullable=False),
    Column('record', JSONB, nullable=False),
    UniqueConstraint('tenant_id', 'relationship_id', name='uq_ti_relationship_identity'),
    UniqueConstraint('tenant_id', 'fingerprint', name='uq_ti_relationship_fingerprint'),
    UniqueConstraint('tenant_id', 'relationship_id', 'fingerprint', name='uq_ti_relationship_identity_fingerprint'),
    ForeignKeyConstraint(['tenant_id','source_type','source_id'], ['ti_relationship_entity.tenant_id','ti_relationship_entity.entity_type','ti_relationship_entity.entity_id']),
    ForeignKeyConstraint(['tenant_id','target_type','target_id'], ['ti_relationship_entity.tenant_id','ti_relationship_entity.entity_type','ti_relationship_entity.entity_id']))
Index('ix_ti_rel_source', relationship.c.tenant_id, relationship.c.source_type, relationship.c.source_id, relationship.c.sequence)
Index('ix_ti_rel_target', relationship.c.tenant_id, relationship.c.target_type, relationship.c.target_id, relationship.c.sequence)
Index('ix_ti_rel_type', relationship.c.tenant_id, relationship.c.relationship_type, relationship.c.sequence)
idempotency = Table('ti_relationship_idempotency', metadata,
    Column('tenant_id', String(256), primary_key=True), Column('key', String(128), primary_key=True),
    Column('fingerprint', String(64), nullable=False), Column('relationship_id', PGUUID(as_uuid=True), nullable=False),
    ForeignKeyConstraint(['tenant_id','relationship_id','fingerprint'], ['ti_relationship_record.tenant_id','ti_relationship_record.relationship_id','ti_relationship_record.fingerprint']))
audit_event = Table('ti_relationship_audit', metadata,
    Column('event_id', PGUUID(as_uuid=True), primary_key=True),
    Column('tenant_id', String(256), nullable=False), Column('actor', String(256), nullable=False),
    Column('operation', String(64), nullable=False), Column('resource_id', PGUUID(as_uuid=True)),
    Column('outcome', String(32), nullable=False), Column('correlation_id', PGUUID(as_uuid=True), nullable=False),
    Column('occurred_at', DateTime(timezone=True), nullable=False))
Index('ix_ti_audit_tenant_time', audit_event.c.tenant_id, audit_event.c.occurred_at)

@dataclass(frozen=True)
class AuditContext:
    tenant_id: str
    actor: str
    correlation_id: UUID

class TraversalLimitExceeded(Exception):
    pass

class PostgresRelationshipStore:
    """Tenant-scoped transactional repository; only use on PostgreSQL.

    Every operation writes a metadata-only audit event in the same transaction.
    A failed audit insert rolls the transaction back. Credentials and free-form
    intelligence payloads are deliberately excluded from audit events.
    """
    def __init__(self, engine: Engine, *, max_traversal_edges: int = 10000, enforce_rls: bool = True, tenant_binding: str = "transaction_guc"):
        if engine.dialect.name != 'postgresql':
            raise ValueError('PostgreSQL is required')
        if max_traversal_edges < 1:
            raise ValueError('max_traversal_edges must be positive')
        if tenant_binding not in ('transaction_guc', 'session_role') or (tenant_binding == 'session_role' and not enforce_rls):
            raise ValueError('invalid tenant binding configuration')
        self.db = engine
        self.max_traversal_edges = max_traversal_edges
        self.enforce_rls = enforce_rls
        self.tenant_binding = tenant_binding

    @contextmanager
    def _transaction(self, ctx: AuditContext, *, snapshot: bool = False):
        with self.db.begin() as conn:
            if snapshot:
                conn.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"))
            if self.enforce_rls:
                # Fail closed on bypass roles and missing/disabled/FORCE RLS tables.
                # This does not verify policy text or the role membership graph.
                safe_role = conn.execute(text("SELECT bool_and(NOT rolsuper AND NOT rolbypassrls) FROM pg_roles WHERE rolname IN (current_user, session_user)")).scalar_one()
                protected = conn.execute(text("""SELECT count(*) FROM pg_class
                    WHERE oid IN (to_regclass('ti_relationship_entity'), to_regclass('ti_relationship_record'),
                                  to_regclass('ti_relationship_idempotency'), to_regclass('ti_relationship_audit'))
                      AND relrowsecurity AND relforcerowsecurity""")).scalar_one()
                if not safe_role or protected != 4:
                    raise RuntimeError("RLS database role or policies are not safely configured")
                if self.tenant_binding == 'session_role':
                    # Exact policy allowlist: refuse missing, changed or extra permissive
                    # policies. Function ownership/body and privileges still require host review.
                    policies = conn.execute(text("""SELECT p.polname, p.polcmd, p.polpermissive,
                        p.polroles, pg_get_expr(p.polqual, p.polrelid), pg_get_expr(p.polwithcheck, p.polrelid)
                        FROM pg_policy p WHERE p.polrelid IN (to_regclass('ti_relationship_entity'),
                        to_regclass('ti_relationship_record'), to_regclass('ti_relationship_idempotency'),
                        to_regclass('ti_relationship_audit'))""")).all()
                    names = {'ti_entity_tenant', 'ti_record_tenant', 'ti_idempotency_tenant', 'ti_audit_tenant'}
                    expression = '((tenant_id)::text = ti_security.authenticated_tenant())'
                    if len(policies) != 4 or {p[0] for p in policies} != names or any(
                        p[1] != '*' or not p[2] or p[3] != [0] or p[4] != expression or p[5] != expression
                        for p in policies
                    ):
                        raise RuntimeError("Role-bound RLS policies do not match the proposal")
                    # The RLS proposal derives the tenant from PostgreSQL session_user,
                    # not a caller-controlled variable; require the app identity to match.
                    bound = conn.execute(text("SELECT ti_security.authenticated_tenant()")).scalar_one_or_none()
                    if not bound or bound != ctx.tenant_id:
                        raise RuntimeError("Database login is not bound to the authenticated tenant")
                else:
                    # A GUC is mutable by arbitrary SQL; this legacy mode is not an auth boundary.
                    inherited = conn.execute(text("SELECT current_setting('cicc.tenant_id', true)")).scalar_one()
                    if inherited:
                        raise RuntimeError("Unexpected pre-existing database tenant context")
                    conn.execute(text("SELECT set_config('cicc.tenant_id', :tenant, true)"), {"tenant": ctx.tenant_id})
            yield conn

    @staticmethod
    def _audit(conn, ctx, operation, outcome, resource_id=None):
        conn.execute(audit_event.insert().values(event_id=uuid4(), tenant_id=ctx.tenant_id,
            actor=ctx.actor, operation=operation, resource_id=resource_id, outcome=outcome,
            correlation_id=ctx.correlation_id, occurred_at=datetime.now(timezone.utc)))

    def create(self, ctx: AuditContext, key: str, fingerprint: str, record: RelationshipRecord):
        with self._transaction(ctx) as conn:
            # Serialize per-tenant creation across processes, including missing keys.
            conn.execute(text('SELECT pg_advisory_xact_lock(hashtextextended(:tenant, 0))'), {'tenant': ctx.tenant_id})
            previous = conn.execute(select(idempotency.c.fingerprint, idempotency.c.relationship_id).where(
                idempotency.c.tenant_id == ctx.tenant_id, idempotency.c.key == key)).first()
            if previous and previous.fingerprint != fingerprint:
                self._audit(conn, ctx, 'relationship.create', 'conflict')
                return None, 'conflict'
            found = conn.execute(select(relationship.c.relationship_id, relationship.c.record).where(
                relationship.c.tenant_id == ctx.tenant_id,
                relationship.c.fingerprint == fingerprint)).first()
            if found:
                if not previous:
                    conn.execute(idempotency.insert().values(tenant_id=ctx.tenant_id, key=key,
                        fingerprint=fingerprint, relationship_id=found.relationship_id))
                self._audit(conn, ctx, 'relationship.create', 'replayed', found.relationship_id)
                return RelationshipRecord.model_validate(found.record), 'replayed'
            if previous:
                raise RuntimeError('idempotency record has no matching relationship')
            for ref in (record.source_entity, record.target_entity):
                conn.execute(insert(entity).values(tenant_id=ctx.tenant_id, entity_type=ref.entity_type,
                    entity_id=ref.entity_id).on_conflict_do_nothing())
            conn.execute(relationship.insert().values(tenant_id=ctx.tenant_id,
                relationship_id=record.relationship_id, source_type=record.source_entity.entity_type,
                source_id=record.source_entity.entity_id, target_type=record.target_entity.entity_type,
                target_id=record.target_entity.entity_id, relationship_type=record.relationship_type.value,
                fingerprint=fingerprint, record=record.model_dump(mode='json')))
            conn.execute(idempotency.insert().values(tenant_id=ctx.tenant_id, key=key,
                fingerprint=fingerprint, relationship_id=record.relationship_id))
            self._audit(conn, ctx, 'relationship.create', 'created', record.relationship_id)
            return record, 'created'

    def get(self, ctx: AuditContext, record_id: UUID):
        with self._transaction(ctx) as conn:
            payload = conn.execute(select(relationship.c.record).where(relationship.c.tenant_id == ctx.tenant_id,
                relationship.c.relationship_id == record_id)).scalar_one_or_none()
            self._audit(conn, ctx, 'relationship.read', 'success' if payload else 'not_found', record_id)
            return RelationshipRecord.model_validate(payload) if payload else None

    def list(self, ctx: AuditContext, entity_id, entity_type, relationship_type, limit, offset):
        with self._transaction(ctx, snapshot=True) as conn:
            clauses = [relationship.c.tenant_id == ctx.tenant_id]
            if entity_id is not None:
                clauses.append(or_(and_(relationship.c.source_type == entity_type, relationship.c.source_id == entity_id),
                                   and_(relationship.c.target_type == entity_type, relationship.c.target_id == entity_id)))
            if relationship_type is not None:
                clauses.append(relationship.c.relationship_type == relationship_type.value)
            total = conn.execute(select(func.count()).select_from(relationship).where(*clauses)).scalar_one()
            rows = conn.execute(select(relationship.c.record).where(*clauses).order_by(relationship.c.sequence).limit(limit).offset(offset)).scalars().all()
            self._audit(conn, ctx, 'relationship.list', 'success')
            return [RelationshipRecord.model_validate(row) for row in rows], total

    def traverse(self, ctx: AuditContext, entity_id: str, entity_type: str, max_depth: int,
                 relationship_types: Optional[list[RelationshipType]], limit: int, offset: int):
        with self._transaction(ctx, snapshot=True) as conn:
            # All graph queries in a traversal see one consistent snapshot.
            exists = conn.execute(select(entity.c.entity_id).where(entity.c.tenant_id == ctx.tenant_id,
                entity.c.entity_type == entity_type, entity.c.entity_id == entity_id)).first()
            if not exists:
                self._audit(conn, ctx, 'relationship.traverse', 'not_found')
                return None
            visited = {(entity_type, entity_id)}
            frontier = set(visited)
            seen = set()
            edges = []
            for depth in range(1, max_depth + 1):
                if not frontier or relationship_types == []:
                    break
                clauses = [relationship.c.tenant_id == ctx.tenant_id,
                    or_(tuple_(relationship.c.source_type, relationship.c.source_id).in_(frontier),
                        tuple_(relationship.c.target_type, relationship.c.target_id).in_(frontier))]
                if relationship_types is not None:
                    clauses.append(relationship.c.relationship_type.in_([v.value for v in relationship_types]))
                rows = conn.execute(select(relationship).where(*clauses).order_by(relationship.c.sequence).limit(self.max_traversal_edges + 1)).mappings().all()
                if len(rows) > self.max_traversal_edges:
                    raise TraversalLimitExceeded()
                next_frontier = set()
                for row in rows:
                    rid = row['relationship_id']
                    if rid not in seen:
                        seen.add(rid)
                        if len(seen) > self.max_traversal_edges:
                            raise TraversalLimitExceeded()
                        edges.append((depth, RelationshipRecord.model_validate(row['record'])))
                    source = (row['source_type'], row['source_id'])
                    target = (row['target_type'], row['target_id'])
                    if source in frontier and target not in visited:
                        next_frontier.add(target)
                    if target in frontier and source not in visited:
                        next_frontier.add(source)
                visited.update(next_frontier)
                frontier = next_frontier
            self._audit(conn, ctx, 'relationship.traverse', 'success')
            return edges[offset:offset+limit], len(edges), len(visited)


class TrustedReadsUnavailable(Exception):
    """Trusted audited read entry points have not been implemented."""


class TrustedWritePostgresRelationshipStore(PostgresRelationshipStore):
    """Experimental controlled create/get adapter with DB-derived audit identity.

    Explicitly refuses list and traversal until audited entry points are available.
    The host must provision per-actor authenticated login roles, reviewed function
    ownership and restricted table privileges; nothing is provisioned here.
    """
    def __init__(self, engine: Engine):
        super().__init__(engine, tenant_binding='session_role')

    def create(self, ctx: AuditContext, key: str, fingerprint: str, record: RelationshipRecord):
        import json
        with self._transaction(ctx) as conn:
            actor = conn.execute(text('SELECT ti_security.authenticated_actor()')).scalar_one_or_none()
            if not actor or actor != ctx.actor:
                raise RuntimeError('Database login is not bound to the authenticated actor')
            result = conn.execute(text('SELECT ti_security.trusted_create_relationship(:key, CAST(:record AS jsonb))'),
                {'key': key, 'record': json.dumps(record.model_dump(mode='json'))}).scalar_one()
            # Verify the identity observed by the write statement itself, even if
            # an administrator changed mappings after the earlier check.
            if result['tenant'] != ctx.tenant_id or result['actor'] != ctx.actor:
                raise RuntimeError('Database identity changed during the operation')
            parsed = RelationshipRecord.model_validate(result['record']) if result['record'] else None
            return parsed, result['outcome'], UUID(result['correlation_id'])

    def get(self, ctx: AuditContext, record_id: UUID):
        with self._transaction(ctx) as conn:
            actor = conn.execute(text('SELECT ti_security.authenticated_actor()')).scalar_one_or_none()
            if not actor or actor != ctx.actor:
                raise RuntimeError('Database login is not bound to the authenticated actor')
            result = conn.execute(text('SELECT ti_security.trusted_get_relationship(:rid)'), {'rid': record_id}).scalar_one()
            if result['tenant'] != ctx.tenant_id or result['actor'] != ctx.actor:
                raise RuntimeError('Database identity changed during the operation')
            parsed = RelationshipRecord.model_validate(result['record']) if result['record'] else None
            return parsed, UUID(result['correlation_id'])

    def list(self, *args, **kwargs):
        raise TrustedReadsUnavailable()

    def traverse(self, *args, **kwargs):
        raise TrustedReadsUnavailable()
