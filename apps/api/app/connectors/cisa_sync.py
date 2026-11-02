"""Internal, manually invoked sync coordinator, not a network endpoint or scheduler.

The actor must hold an admin session. Fetching occurs outside a DB transaction;
import and successful completion are atomic. A crash leaves a visible running
attempt, never a fabricated success. Abandoning requires an explicit admin action.
PostgreSQL tenant locks serialize state changes; SQLite concurrency is unsupported.
"""
from datetime import datetime, timezone
from uuid import UUID
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker
from .cisa_kev import ConnectorError, fetch_snapshot
from .cisa_import import import_snapshot
from ..audit import AuditType, record_event
from ..models import CisaCatalogState, CisaSyncAttempt, Tenant
from ..security import Permission, authorize
from ..sessions import authenticate_session, authenticate_session_locked

class SyncBusy(Exception):
    pass

def _admin_and_tenant(db, token):
    principal = authenticate_session(db, token)
    if principal is None:
        raise PermissionError('Access denied')
    authorize(principal, principal.tenant_id, Permission.MANAGE_USERS)
    # PostgreSQL FOR NO KEY UPDATE serializes source work but permits FK KEY SHARE.
    tenant = db.scalar(select(Tenant).where(Tenant.id == principal.tenant_id).with_for_update(key_share=True))
    refreshed = authenticate_session_locked(db, token)
    if tenant is None or refreshed is None or refreshed.user_id != principal.user_id:
        raise PermissionError('Access denied')
    authorize(refreshed, tenant.id, Permission.MANAGE_USERS)
    return refreshed

def begin_sync(factory: sessionmaker, *, admin_token: str) -> UUID:
    with factory.begin() as db:
        principal = _admin_and_tenant(db, admin_token)
        running = db.scalar(select(CisaSyncAttempt.id).where(CisaSyncAttempt.tenant_id == principal.tenant_id, CisaSyncAttempt.status == 'running'))
        if running is not None:
            raise SyncBusy('A sync is already running')
        attempt = CisaSyncAttempt(tenant_id=principal.tenant_id, actor_id=principal.user_id, status='running', started_at=datetime.now(timezone.utc))
        db.add(attempt); db.flush()
        record_event(db, principal.tenant_id, AuditType.CISA_SYNC_STARTED, principal.user_id)
        return attempt.id

def _fail(factory: sessionmaker, attempt_id: UUID, tenant_id: UUID, actor_id: UUID, code: str) -> bool:
    if code not in ('fetch_failed', 'import_failed'):
        raise ValueError('Invalid failure code')
    with factory.begin() as db:
        db.scalar(select(Tenant).where(Tenant.id == tenant_id).with_for_update(key_share=True))
        attempt = db.scalar(select(CisaSyncAttempt).where(CisaSyncAttempt.id == attempt_id,
            CisaSyncAttempt.tenant_id == tenant_id, CisaSyncAttempt.actor_id == actor_id).with_for_update())
        # Explicitly abandoned attempts cannot be overwritten by a late worker.
        if attempt is None or attempt.status != 'running':
            return False
        attempt.status = 'failed'; attempt.error_code = code; attempt.finished_at = datetime.now(timezone.utc)
        record_event(db, tenant_id, AuditType.CISA_SYNC_FAILED, actor_id)
        return True

def synchronize(factory: sessionmaker, *, admin_token: str, fetch=fetch_snapshot) -> dict:
    attempt_id = begin_sync(factory, admin_token=admin_token)
    with factory() as db:
        attempt = db.get(CisaSyncAttempt, attempt_id)
        tenant_id, actor_id = attempt.tenant_id, attempt.actor_id
    try:
        snapshot = fetch()
    except ConnectorError:
        marked = _fail(factory, attempt_id, tenant_id, actor_id, 'fetch_failed')
        return {'attempt_id':str(attempt_id), 'status':'failed' if marked else 'inactive',
                'error_code':'fetch_failed' if marked else None}
    except Exception:
        _fail(factory, attempt_id, tenant_id, actor_id, 'fetch_failed')
        raise
    try:
        result = import_snapshot(factory, admin_token=admin_token, snapshot=snapshot, attempt_id=attempt_id)
    except Exception:
        _fail(factory, attempt_id, tenant_id, actor_id, 'import_failed')
        raise
    return {'attempt_id':str(attempt_id), 'status':'succeeded', **result}

def abandon_sync(factory: sessionmaker, *, admin_token: str, attempt_id: UUID) -> bool:
    """Operator assertion that the worker is no longer wanted; no automatic lease."""
    with factory.begin() as db:
        principal = _admin_and_tenant(db, admin_token)
        attempt = db.scalar(select(CisaSyncAttempt).where(CisaSyncAttempt.id == attempt_id,
            CisaSyncAttempt.tenant_id == principal.tenant_id).with_for_update())
        if attempt is None or attempt.status != 'running':
            return False
        attempt.status = 'abandoned'; attempt.finished_at = datetime.now(timezone.utc)
        record_event(db, principal.tenant_id, AuditType.CISA_SYNC_ABANDONED, principal.user_id)
        return True

def get_status(factory: sessionmaker, *, admin_token: str) -> dict:
    with factory.begin() as db:
        principal = _admin_and_tenant(db, admin_token)
        last = db.scalar(select(CisaSyncAttempt).where(CisaSyncAttempt.tenant_id == principal.tenant_id)
                         .order_by(CisaSyncAttempt.started_at.desc(), CisaSyncAttempt.id.desc()).limit(1))
        state = db.get(CisaCatalogState, principal.tenant_id)
        record_event(db, principal.tenant_id, AuditType.CISA_STATUS_READ, principal.user_id)
        return {'last_attempt': None if last is None else {'id':str(last.id), 'status':last.status, 'started_at':last.started_at.isoformat(),
            'finished_at':last.finished_at.isoformat() if last.finished_at else None, 'error_code':last.error_code},
            'last_imported_snapshot_collected_at':state.collected_at.isoformat() if state else None,
            'catalog_released_at':state.released_at.isoformat() if state else None}
