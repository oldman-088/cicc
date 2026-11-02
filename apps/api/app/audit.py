"""Narrow audit API: no arbitrary metadata or secrets. Caller owns transactions.

Database permissions, tamper resistance and retention are not yet implemented.
"""
from enum import Enum
from uuid import UUID
from sqlalchemy import select
from sqlalchemy.orm import Session
from .models import SecurityAuditEvent
from .security import Permission, Principal, Role, authorize

class AuditType(str, Enum):
    LOGIN_SUCCEEDED = 'login_succeeded'
    LOGIN_FAILED = 'login_failed'
    LOGIN_THROTTLED = 'login_throttled'
    SESSION_REVOKED = 'session_revoked'
    SESSION_LIST_READ = 'session_list_read'
    SESSION_SINGLE_REVOKED = 'session_single_revoked'
    TENANT_BOOTSTRAPPED = 'tenant_bootstrapped'
    USER_CREATED = 'user_created'
    USER_SELF_READ = 'user_self_read'
    USER_DIRECTORY_READ = 'user_directory_read'
    USER_ROLE_CHANGED = 'user_role_changed'
    USER_DISABLED = 'user_disabled'
    USER_SESSIONS_REVOKED = 'user_sessions_revoked'
    USER_PASSWORD_CHANGED = 'user_password_changed'
    USER_PASSWORD_CHANGE_FAILED = 'user_password_change_failed'
    USER_PASSWORD_CHANGE_THROTTLED = 'user_password_change_throttled'
    INTELLIGENCE_READ = 'intelligence_read'
    INTELLIGENCE_CREATED = 'intelligence_created'
    INTELLIGENCE_UPDATED = 'intelligence_updated'
    EVIDENCE_CREATED = 'evidence_created'
    EVIDENCE_READ = 'evidence_read'
    PROVENANCE_READ = 'provenance_read'
    RELATIONSHIP_CREATED = 'relationship_created'
    RELATIONSHIP_READ = 'relationship_read'
    CISA_CATALOG_IMPORTED = 'cisa_catalog_imported'
    NVD_RECORD_IMPORTED = 'nvd_record_imported'
    CISA_SYNC_STARTED = 'cisa_sync_started'
    CISA_SYNC_SUCCEEDED = 'cisa_sync_succeeded'
    CISA_SYNC_FAILED = 'cisa_sync_failed'
    CISA_SYNC_ABANDONED = 'cisa_sync_abandoned'
    CISA_STATUS_READ = 'cisa_status_read'
    AUDIT_READ = 'audit_read'
    INVESTIGATION_CREATED = 'investigation_created'
    INVESTIGATION_READ = 'investigation_read'
    INVESTIGATION_UPDATED = 'investigation_updated'
    INVESTIGATION_ASSIGNED = 'investigation_assigned'
    INVESTIGATION_NOTE_CREATED = 'investigation_note_created'
    INVESTIGATION_ENTITY_LINKED = 'investigation_entity_linked'
    INVESTIGATION_ENTITY_UNLINKED = 'investigation_entity_unlinked'
    INVESTIGATION_EVIDENCE_LINKED = 'investigation_evidence_linked'
    INVESTIGATION_EVIDENCE_UNLINKED = 'investigation_evidence_unlinked'

def record_event(db: Session, tenant_id: UUID, event_type: AuditType, actor_id: UUID | None = None, target_user_id: UUID | None = None, previous_role: Role | None = None, new_role: Role | None = None, target_entity_id: UUID | None = None, target_investigation_id: UUID | None = None, target_note_id: UUID | None = None, target_session_id: UUID | None = None, target_evidence_id: UUID | None = None) -> None:
    if not isinstance(event_type, AuditType):
        raise ValueError('Unknown audit event')
    if previous_role is not None and not isinstance(previous_role, Role):
        raise ValueError('Invalid prior role')
    if new_role is not None and not isinstance(new_role, Role):
        raise ValueError('Invalid new role')
    if (previous_role is not None or new_role is not None) and event_type != AuditType.USER_ROLE_CHANGED:
        raise ValueError('Role details only apply to role changes')
    if target_session_id is not None and (event_type != AuditType.SESSION_SINGLE_REVOKED or target_user_id is None):
        raise ValueError('Session target requires a user and a single-session revocation')
    db.add(SecurityAuditEvent(tenant_id=tenant_id, actor_id=actor_id, event_type=event_type.value, target_user_id=target_user_id, target_entity_id=target_entity_id,
                              previous_role=previous_role.value if previous_role else None, new_role=new_role.value if new_role else None, target_investigation_id=target_investigation_id, target_note_id=target_note_id, target_session_id=target_session_id, target_evidence_id=target_evidence_id))
    db.flush()

def list_events(db: Session, principal: Principal, tenant_id: UUID, limit: int = 100):
    authorize(principal, tenant_id, Permission.MANAGE_USERS)
    if not 1 <= limit <= 100:
        raise ValueError('Invalid limit')
    return list(db.scalars(select(SecurityAuditEvent).where(SecurityAuditEvent.tenant_id == tenant_id)
                           .order_by(SecurityAuditEvent.occurred_at.desc(), SecurityAuditEvent.id.desc()).limit(limit)))
