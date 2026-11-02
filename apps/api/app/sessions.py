"""Local session primitives, not exposed as an API until rate limits and audit exist.

The caller owns the database transaction. Never log or persist raw bearer tokens.
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID
from sqlalchemy import select
from sqlalchemy.orm import Session
from .models import AuthSession, User
from .security import Principal, Role, verify_password

SESSION_LIFETIME = timedelta(hours=8)
# Equalize the expensive password check for missing or disabled accounts. This is a
# non-secret hash of a random, unusable value, generated once at process startup.
from .security import hash_password
_DUMMY_HASH = hash_password(secrets.token_urlsafe(32))

def _now():
    return datetime.now(timezone.utc)

def _digest(token: str) -> str:
    return hashlib.sha256(token.encode('ascii')).hexdigest()

def issue_session(db: Session, tenant_id: UUID, username: str, password: str) -> str | None:
    """Return an opaque token only on success; caller commits the transaction.

    The caller MUST rate-limit and audit every attempt before exposing this function.
    """
    user = db.scalar(select(User).where(User.tenant_id == tenant_id, User.username == username).with_for_update())
    valid = verify_password(password, user.password_hash if user and user.active else _DUMMY_HASH)
    if not user or not user.active or not valid:
        return None
    try:
        Role(user.role)
    except ValueError:
        return None
    token = secrets.token_urlsafe(32)
    now = _now()
    db.add(AuthSession(tenant_id=user.tenant_id, user_id=user.id, token_digest=_digest(token),
                       created_at=now, expires_at=now + SESSION_LIFETIME))
    db.flush()
    return token

def authenticate_session(db: Session, token: str) -> Principal | None:
    if not token or len(token) > 128 or not token.isascii():
        return None
    now = _now()
    result = db.execute(select(AuthSession, User).join(
        User, (AuthSession.user_id == User.id) & (AuthSession.tenant_id == User.tenant_id)
    ).where(AuthSession.token_digest == _digest(token), AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > now, User.active.is_(True))).first()
    if not result:
        return None
    _, user = result
    try:
        return Principal(user.id, user.tenant_id, Role(user.role))
    except ValueError:
        return None

def authenticate_session_locked(db: Session, token: str) -> Principal | None:
    """Serialize a protected transaction with account changes and logout.

    PostgreSQL locks user then session until transaction end. Re-read both after
    any lock wait; the initial lookup is only used to identify the lock target.
    SQLite ignores row locks and is unsuitable for concurrent deployment.
    """
    candidate = authenticate_session(db, token)
    if candidate is None:
        return None
    user = db.scalar(select(User).where(User.id == candidate.user_id,
        User.tenant_id == candidate.tenant_id).with_for_update().execution_options(populate_existing=True))
    if user is None or not user.active:
        return None
    session = db.scalar(select(AuthSession).where(AuthSession.tenant_id == user.tenant_id,
        AuthSession.user_id == user.id, AuthSession.token_digest == _digest(token))
        .with_for_update().execution_options(populate_existing=True))
    if session is None or session.revoked_at is not None:
        return None
    # SQLite stores timestamps without timezone information.
    expires = session.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires <= _now():
        return None
    try:
        return Principal(user.id, user.tenant_id, Role(user.role))
    except ValueError:
        return None

def revoke_session(db: Session, token: str) -> bool:
    if not token or len(token) > 128 or not token.isascii():
        return False
    session = db.scalar(select(AuthSession).where(AuthSession.token_digest == _digest(token)))
    if not session or session.revoked_at is not None:
        return False
    session.revoked_at = _now()
    db.flush()
    return True


def cleanup_expired_sessions_batch(db: Session, *, batch_size: int = 1000, now: datetime | None = None) -> int:
    """Delete one batch expired for over 24 hours; caller owns transaction.

    Requires a synchronized clock and operator-managed concurrency. Audit events
    are not deleted. Revoked but not sufficiently expired sessions are retained.
    """
    from sqlalchemy import delete
    if not 1 <= batch_size <= 10000:
        raise ValueError('Invalid batch size')
    current = _now() if now is None else now
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError('A timezone-aware time is required')
    cutoff = current - timedelta(hours=24)
    candidates = select(AuthSession.id).where(AuthSession.expires_at < cutoff).order_by(
        AuthSession.expires_at, AuthSession.id).limit(batch_size)
    result = db.execute(delete(AuthSession).where(AuthSession.id.in_(candidates))
        .execution_options(synchronize_session=False))
    return result.rowcount
