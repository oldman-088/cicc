"""Atomic fixed-window counters for SQLite and PostgreSQL, not a complete login defense.

Caller must commit *all* attempts including rejected logins; rollback loses the count.
Use independent account, source and global limits at the service boundary. The experimental login service uses these counters; cleanup remains manual.
"""
import hashlib
import hmac
import time
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy import case
from sqlalchemy.orm import Session
from .models import RateLimitBucket

def consume(db: Session, *, secret: bytes, scope: str, identifier: str, limit: int, window_seconds: int, now: int | None = None) -> bool:
    if len(secret) < 32 or not scope or len(scope) > 64 or not identifier or len(identifier) > 512 or not 1 <= limit <= 10000 or not 1 <= window_seconds <= 86400:
        raise ValueError('Invalid rate limit configuration')
    # Length prefix prevents ambiguous concatenation across scopes.
    message = f'{len(scope)}:{scope}{identifier}'.encode('utf-8')
    digest = hmac.new(secret, message, hashlib.sha256).hexdigest()
    timestamp = int(time.time()) if now is None else now
    if timestamp < 0:
        raise ValueError('Invalid time')
    start = timestamp - timestamp % window_seconds
    dialect = db.get_bind().dialect.name
    if dialect == 'postgresql':
        insert = pg_insert(RateLimitBucket)
    elif dialect == 'sqlite':
        insert = sqlite_insert(RateLimitBucket)
    else:
        raise RuntimeError('Unsupported database for atomic rate limiting')
    statement = insert.values(key_digest=digest, window_start=start, attempts=1)
    statement = statement.on_conflict_do_update(
        index_elements=['key_digest', 'window_start'],
        set_={'attempts': case((RateLimitBucket.attempts <= limit, RateLimitBucket.attempts + 1), else_=RateLimitBucket.attempts)},
    ).returning(RateLimitBucket.attempts)
    attempts = db.execute(statement).scalar_one()
    return attempts <= limit

def cleanup_expired(db: Session, *, now: int | None = None) -> int:
    """Delete windows that cannot still be active under the supported max window.

    The caller must explicitly run and commit this maintenance operation. It must
    use a synchronized UTC clock; no scheduler is provided. We retain at least
    one maximum (24 hour) window, irrespective of a bucket's individual policy.
    """
    from sqlalchemy import delete
    timestamp = int(time.time()) if now is None else now
    if timestamp < 0:
        raise ValueError('Invalid time')
    result = db.execute(delete(RateLimitBucket).where(RateLimitBucket.window_start < timestamp - 86400))
    return result.rowcount


def cleanup_expired_batch(db: Session, *, batch_size: int = 1000, now: int | None = None) -> int:
    """Delete one bounded batch, retaining every possibly active window.

    The caller owns the transaction. Operators must use a synchronized clock and
    avoid concurrent batches; no scheduler or operator audit is implemented.
    """
    from sqlalchemy import delete, select, tuple_
    if not 1 <= batch_size <= 10000:
        raise ValueError('Invalid batch size')
    timestamp = int(time.time()) if now is None else now
    if timestamp < 0:
        raise ValueError('Invalid time')
    candidates = select(RateLimitBucket.key_digest, RateLimitBucket.window_start).where(
        RateLimitBucket.window_start < timestamp - 86400).order_by(
        RateLimitBucket.window_start, RateLimitBucket.key_digest).limit(batch_size)
    result = db.execute(delete(RateLimitBucket).where(tuple_(RateLimitBucket.key_digest,
        RateLimitBucket.window_start).in_(candidates)).execution_options(synchronize_session=False))
    return result.rowcount
