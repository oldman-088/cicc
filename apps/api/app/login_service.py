"""Internal login orchestration, intentionally not mounted as an HTTP endpoint.

Callers must derive the source address from a trusted transport, not arbitrary
forwarded headers. Global, source and tenant/account counters are committed
before password verification, including for failed attempts. Session issuance and
its audit event commit together. Database or audit errors propagate (fail closed).
"""
from dataclasses import dataclass
from enum import Enum
from ipaddress import ip_address
from uuid import UUID
from sqlalchemy.orm import sessionmaker
from .audit import AuditType, record_event
from .models import Tenant
from .rate_limit import consume
from .sessions import authenticate_session, authenticate_session_locked, issue_session, revoke_session

@dataclass(frozen=True)
class LoginPolicy:
    account_limit: int = 5
    source_limit: int = 30
    global_limit: int = 1000
    window_seconds: int = 60

class LoginStatus(str, Enum):
    SUCCESS = 'success'
    DENIED = 'denied'
    THROTTLED = 'throttled'

@dataclass(frozen=True)
class LoginResult:
    status: LoginStatus
    token: str | None = None

def login(factory: sessionmaker, *, secret: bytes, tenant_id: UUID, username: str,
          password: str, source_ip: str, policy: LoginPolicy = LoginPolicy()) -> LoginResult:
    if not username or len(username) > 255 or len(password) > 1024:
        raise ValueError('Invalid login input')
    # Canonicalize IPv4/IPv6; do not infer addresses from untrusted headers.
    source = str(ip_address(source_ip))
    # Lock buckets in consistent global -> source -> account order to reduce deadlocks.
    with factory.begin() as db:
        global_ok = consume(db, secret=secret, scope='global', identifier='login', limit=policy.global_limit, window_seconds=policy.window_seconds)
        # Once a broader limit rejects the request, do not allocate narrower
        # buckets for attacker-chosen sources/accounts. No login can succeed.
        source_ok = global_ok and consume(db, secret=secret, scope='source', identifier=source, limit=policy.source_limit, window_seconds=policy.window_seconds)
        account_ok = source_ok and consume(db, secret=secret, scope='account', identifier=f'{tenant_id}:{username}', limit=policy.account_limit, window_seconds=policy.window_seconds)
    allowed = bool(account_ok)
    with factory.begin() as db:
        tenant_exists = db.get(Tenant, tenant_id) is not None
        if not allowed:
            if tenant_exists:
                record_event(db, tenant_id, AuditType.LOGIN_THROTTLED)
            return LoginResult(LoginStatus.THROTTLED)
        # Perform the dummy hash path for a missing tenant too.
        token = issue_session(db, tenant_id, username, password)
        if token is None:
            if tenant_exists:
                record_event(db, tenant_id, AuditType.LOGIN_FAILED)
            return LoginResult(LoginStatus.DENIED)
        principal = authenticate_session(db, token)
        if principal is None:
            raise RuntimeError('Issued session could not be verified')
        record_event(db, tenant_id, AuditType.LOGIN_SUCCEEDED, principal.user_id)
        return LoginResult(LoginStatus.SUCCESS, token)

def logout(factory: sessionmaker, token: str) -> bool:
    """Revoke and audit atomically. Invalid tokens do not disclose session details."""
    with factory.begin() as db:
        principal = authenticate_session_locked(db, token)
        if principal is None or not revoke_session(db, token):
            return False
        record_event(db, principal.tenant_id, AuditType.SESSION_REVOKED, principal.user_id)
        return True
