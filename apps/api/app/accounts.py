"""Tenant-bound account administration for the experimental API.

Requires an existing authenticated administrator session. Bootstrap is an offline operation.
All mutations and their audit events commit together; errors fail closed.
"""
import re
from datetime import datetime, timezone
from uuid import UUID
from sqlalchemy import select, update
from sqlalchemy.orm import sessionmaker
from .audit import AuditType, record_event
from .models import AuthSession, User
from .security import Permission, Role, authorize, hash_password, verify_password
from .sessions import authenticate_session, authenticate_session_locked
from .rate_limit import consume

_USERNAME = re.compile(r'^[a-z0-9][a-z0-9._-]{2,63}$')

def _admin(db, token):
    principal = authenticate_session_locked(db, token)
    if principal is None:
        raise PermissionError('Access denied')
    authorize(principal, principal.tenant_id, Permission.MANAGE_USERS)
    return principal

def create_user(factory: sessionmaker, *, admin_token: str, username: str, password: str, role: Role) -> UUID:
    if not _USERNAME.fullmatch(username) or not isinstance(role, Role):
        raise ValueError('Invalid account input')
    if not 12 <= len(password) <= 1024:
        raise ValueError('Invalid account input')
    # Avoid unauthenticated Argon2 work; this check is only a preflight and is
    # repeated under locks after hashing, since privileges can change meanwhile.
    with factory() as db:
        candidate = authenticate_session(db, admin_token)
        if candidate is None:
            raise PermissionError('Access denied')
        authorize(candidate, candidate.tenant_id, Permission.MANAGE_USERS)
    encoded = hash_password(password)
    with factory.begin() as db:
        principal = _admin(db, admin_token)
        user = User(tenant_id=principal.tenant_id, username=username, password_hash=encoded, role=role.value, active=True)
        db.add(user)
        db.flush()  # Database unique constraint resolves concurrent duplicates.
        record_event(db, principal.tenant_id, AuditType.USER_CREATED, principal.user_id, user.id)
        return user.id

def _lock_actor_and_target(db, token, user_id):
    """Lock both user rows in UUID order before checking admin authorization.

    This prevents two admins managing each other from locking in opposite order.
    The first authentication is only a hint and is rechecked under lock by _admin.
    """
    principal = authenticate_session(db, token)
    if principal is None or principal.user_id == user_id:
        raise PermissionError('Access denied')
    authorize(principal, principal.tenant_id, Permission.MANAGE_USERS)
    rows = list(db.scalars(select(User).where(User.tenant_id == principal.tenant_id,
        User.id.in_([principal.user_id, user_id])).order_by(User.id).with_for_update()
        .execution_options(populate_existing=True)))
    if len(rows) != 2:
        raise PermissionError('Access denied')

def _target(db, principal, user_id):
    user = db.scalar(select(User).where(User.id == user_id, User.tenant_id == principal.tenant_id).with_for_update())
    if not user or user.id == principal.user_id:
        # No cross-tenant existence disclosure or self-lockout through this service.
        raise PermissionError('Access denied')
    return user

def change_role(factory: sessionmaker, *, admin_token: str, user_id: UUID, role: Role) -> None:
    if not isinstance(role, Role):
        raise ValueError('Invalid role')
    with factory.begin() as db:
        _lock_actor_and_target(db, admin_token, user_id)
        principal = _admin(db, admin_token)
        user = _target(db, principal, user_id)
        previous = Role(user.role)
        user.role = role.value
        record_event(db, principal.tenant_id, AuditType.USER_ROLE_CHANGED, principal.user_id, user.id, previous_role=previous, new_role=role)

def disable_user(factory: sessionmaker, *, admin_token: str, user_id: UUID) -> None:
    with factory.begin() as db:
        _lock_actor_and_target(db, admin_token, user_id)
        principal = _admin(db, admin_token)
        user = _target(db, principal, user_id)
        user.active = False
        # Prevent old sessions being revived if the account is later re-enabled.
        db.execute(update(AuthSession).where(AuthSession.tenant_id == principal.tenant_id,
            AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None)).values(revoked_at=datetime.now(timezone.utc)))
        record_event(db, principal.tenant_id, AuditType.USER_DISABLED, principal.user_id, user.id)


def revoke_user_sessions(factory: sessionmaker, *, admin_token: str, user_id: UUID) -> int:
    """Revoke existing sessions for another same-tenant account, with audit.

    This does not disable the account, change its password or prevent a later login.
    The target user lock serializes with session issuance on PostgreSQL.
    """
    with factory.begin() as db:
        _lock_actor_and_target(db, admin_token, user_id)
        principal = _admin(db, admin_token)
        user = _target(db, principal, user_id)
        result = db.execute(update(AuthSession).where(AuthSession.tenant_id == principal.tenant_id,
            AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None)).values(revoked_at=datetime.now(timezone.utc)))
        record_event(db, principal.tenant_id, AuditType.USER_SESSIONS_REVOKED, principal.user_id, user.id)
        return result.rowcount


class PasswordChangeThrottled(Exception):
    pass


def change_own_password(factory: sessionmaker, *, token: str, secret: bytes, current_password: str, new_password: str) -> None:
    """Change credentials and revoke all sessions, including the caller's.

    Verify and hash outside locked transactions, then recheck session, account,
    and the observed hash while locked. No password or hash is added to audit.
    """
    if not 1 <= len(current_password) <= 1024 or not 12 <= len(new_password) <= 1024:
        raise ValueError('Invalid password input')
    with factory() as db:
        candidate = authenticate_session(db, token)
        if candidate is None:
            raise PermissionError('Access denied')
        user = db.scalar(select(User).where(User.tenant_id == candidate.tenant_id, User.id == candidate.user_id))
        if user is None:
            raise PermissionError('Access denied')
        observed_hash = user.password_hash
    # Persist a per-account attempt before expensive verification, regardless of
    # outcome. This is not a replacement for ingress/global abuse controls.
    with factory.begin() as db:
        allowed = consume(db, secret=secret, scope='password-change', identifier=f'{candidate.tenant_id}:{candidate.user_id}', limit=5, window_seconds=60)
        if not allowed:
            record_event(db, candidate.tenant_id, AuditType.USER_PASSWORD_CHANGE_THROTTLED, candidate.user_id, candidate.user_id)
    if not allowed:
        raise PasswordChangeThrottled()
    if not verify_password(current_password, observed_hash):
        with factory.begin() as db:
            record_event(db, candidate.tenant_id, AuditType.USER_PASSWORD_CHANGE_FAILED, candidate.user_id, candidate.user_id)
        raise PermissionError('Access denied')
    encoded = hash_password(new_password)
    with factory.begin() as db:
        principal = authenticate_session_locked(db, token)
        if principal is None or principal.user_id != candidate.user_id or principal.tenant_id != candidate.tenant_id:
            raise PermissionError('Access denied')
        user = db.scalar(select(User).where(User.tenant_id == principal.tenant_id, User.id == principal.user_id)
                         .with_for_update().execution_options(populate_existing=True))
        if user is None or user.password_hash != observed_hash:
            raise PermissionError('Access denied')
        user.password_hash = encoded
        db.execute(update(AuthSession).where(AuthSession.tenant_id == principal.tenant_id,
            AuthSession.user_id == principal.user_id, AuthSession.revoked_at.is_(None)).values(revoked_at=datetime.now(timezone.utc)))
        record_event(db, principal.tenant_id, AuditType.USER_PASSWORD_CHANGED, principal.user_id, principal.user_id)
