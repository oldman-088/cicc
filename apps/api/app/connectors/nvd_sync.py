"""Explicit internal NVD lookup coordinator; no scheduler or public start API.

Network calls occur outside transactions. PostgreSQL tenant locks serialize
starts; SQLite is not concurrency-safe. A crash can leave a running attempt;
admin abandonment is explicit and never interrupts an in-flight network call.
"""
from datetime import datetime, timezone
from uuid import UUID
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker
from .nvd_cve import NvdError, _cve_id, fetch_cve
from .nvd_import import import_record
from ..audit import AuditType, record_event
from ..models import NvdSyncAttempt, Tenant
from ..security import Permission, authorize
from ..sessions import authenticate_session, authenticate_session_locked


class SyncBusy(Exception):
    pass


def _admin_and_tenant(db, token):
    principal = authenticate_session(db, token)
    if principal is None:
        raise PermissionError('Access denied')
    authorize(principal, principal.tenant_id, Permission.MANAGE_USERS)
    tenant = db.scalar(select(Tenant).where(Tenant.id == principal.tenant_id).with_for_update(key_share=True))
    refreshed = authenticate_session_locked(db, token)
    if tenant is None or refreshed is None or refreshed.user_id != principal.user_id:
        raise PermissionError('Access denied')
    authorize(refreshed, tenant.id, Permission.MANAGE_USERS)
    return refreshed


def begin_sync(factory: sessionmaker, *, admin_token: str, cve_id: str) -> UUID:
    _cve_id(cve_id)
    with factory.begin() as db:
        principal = _admin_and_tenant(db, admin_token)
        if db.scalar(select(NvdSyncAttempt.id).where(NvdSyncAttempt.tenant_id == principal.tenant_id,
                                                     NvdSyncAttempt.status == 'running')) is not None:
            raise SyncBusy('A sync is already running')
        attempt = NvdSyncAttempt(tenant_id=principal.tenant_id, actor_id=principal.user_id, cve_id=cve_id,
                                 status='running', started_at=datetime.now(timezone.utc))
        db.add(attempt); db.flush()
        record_event(db, principal.tenant_id, AuditType.NVD_SYNC_STARTED, principal.user_id)
        return attempt.id


def _fail(factory: sessionmaker, attempt_id: UUID, tenant_id: UUID, actor_id: UUID, code: str) -> bool:
    if code not in ('fetch_failed', 'import_failed'):
        raise ValueError('Invalid failure code')
    with factory.begin() as db:
        db.scalar(select(Tenant).where(Tenant.id == tenant_id).with_for_update(key_share=True))
        attempt = db.scalar(select(NvdSyncAttempt).where(NvdSyncAttempt.id == attempt_id,
            NvdSyncAttempt.tenant_id == tenant_id, NvdSyncAttempt.actor_id == actor_id).with_for_update())
        if attempt is None or attempt.status != 'running':
            return False
        attempt.status = 'failed'; attempt.error_code = code; attempt.finished_at = datetime.now(timezone.utc)
        record_event(db, tenant_id, AuditType.NVD_SYNC_FAILED, actor_id)
        return True


def _not_found(factory: sessionmaker, *, admin_token: str, attempt_id: UUID) -> bool:
    with factory.begin() as db:
        principal = _admin_and_tenant(db, admin_token)
        attempt = db.scalar(select(NvdSyncAttempt).where(NvdSyncAttempt.id == attempt_id,
            NvdSyncAttempt.tenant_id == principal.tenant_id, NvdSyncAttempt.actor_id == principal.user_id).with_for_update())
        if attempt is None or attempt.status != 'running':
            return False
        attempt.status = 'not_found'; attempt.finished_at = datetime.now(timezone.utc)
        record_event(db, principal.tenant_id, AuditType.NVD_SYNC_NOT_FOUND, principal.user_id)
        return True


def synchronize(factory: sessionmaker, *, admin_token: str, cve_id: str, fetch=fetch_cve) -> dict:
    attempt_id = begin_sync(factory, admin_token=admin_token, cve_id=cve_id)
    with factory() as db:
        attempt = db.get(NvdSyncAttempt, attempt_id)
        tenant_id, actor_id = attempt.tenant_id, attempt.actor_id
    try:
        observation = fetch(cve_id)
    except NvdError:
        marked = _fail(factory, attempt_id, tenant_id, actor_id, 'fetch_failed')
        return {'attempt_id':str(attempt_id), 'status':'failed' if marked else 'inactive', 'error_code':'fetch_failed' if marked else None}
    except Exception:
        _fail(factory, attempt_id, tenant_id, actor_id, 'fetch_failed')
        raise
    try:
        if observation is None:
            completed = _not_found(factory, admin_token=admin_token, attempt_id=attempt_id)
            return {'attempt_id':str(attempt_id), 'status':'not_found' if completed else 'inactive'}
        result = import_record(factory, admin_token=admin_token, record=observation, attempt_id=attempt_id)
    except Exception:
        _fail(factory, attempt_id, tenant_id, actor_id, 'import_failed')
        raise
    return {'attempt_id':str(attempt_id), 'status':'succeeded', **result}


def abandon_sync(factory: sessionmaker, *, admin_token: str, attempt_id: UUID) -> bool:
    with factory.begin() as db:
        principal = _admin_and_tenant(db, admin_token)
        attempt = db.scalar(select(NvdSyncAttempt).where(NvdSyncAttempt.id == attempt_id,
            NvdSyncAttempt.tenant_id == principal.tenant_id).with_for_update())
        if attempt is None or attempt.status != 'running':
            return False
        attempt.status = 'abandoned'; attempt.finished_at = datetime.now(timezone.utc)
        record_event(db, principal.tenant_id, AuditType.NVD_SYNC_ABANDONED, principal.user_id)
        return True


def get_status(factory: sessionmaker, *, admin_token: str) -> dict:
    with factory.begin() as db:
        principal = _admin_and_tenant(db, admin_token)
        last = db.scalar(select(NvdSyncAttempt).where(NvdSyncAttempt.tenant_id == principal.tenant_id)
                         .order_by(NvdSyncAttempt.started_at.desc(), NvdSyncAttempt.id.desc()).limit(1))
        record_event(db, principal.tenant_id, AuditType.NVD_STATUS_READ, principal.user_id)
        return {'last_attempt': None if last is None else {'id':str(last.id), 'cve_id':last.cve_id, 'status':last.status,
            'started_at':last.started_at.isoformat(), 'finished_at':last.finished_at.isoformat() if last.finished_at else None,
            'error_code':last.error_code}}
