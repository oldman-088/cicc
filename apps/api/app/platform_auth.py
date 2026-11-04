"""Optional adapter for the VERIFIED platform session contract.

Contract source (read-only inspection of branch arena/da631853-cicc,
apps/api/app/{sessions,security,login_service}.py, 2026-11-04):
  - Clients send an opaque bearer token (secrets.token_urlsafe(32)).
  - The server stores ONLY sha256(token) in `auth_sessions.token_digest`
    (unique), joined to `users` on (tenant_id, user_id); sessions expire
    (8h) and can be revoked; raw tokens are never logged or persisted.
  - `users` carries tenant_id + role (admin|analyst|viewer) + active flag.
  - Authorization fails closed on cross-tenant or unknown role/permission.

This adapter is INERT unless BOTH are set:
  CICC_OPS_USE_PLATFORM_AUTH=1   and   CICC_PLATFORM_DB_URL=<platform DB>
It opens its own read-only connection to the platform DB and verifies the
bearer digest. Any error -> fail closed (None). Raw tokens are never logged.

Tenant scoping of ops-owned data is deliberately NOT implemented here; see
docs/TENANT_ISOLATION_PLAN.md (requires a shared-contract decision).
"""
import hashlib
import os
from datetime import datetime, timezone

_engine = None


def platform_auth_enabled() -> bool:
    return os.getenv("CICC_OPS_USE_PLATFORM_AUTH") == "1" and bool(os.getenv("CICC_PLATFORM_DB_URL"))


def _get_engine():
    global _engine
    if _engine is None:
        from sqlalchemy import create_engine

        _engine = create_engine(os.environ["CICC_PLATFORM_DB_URL"], pool_pre_ping=True)
    return _engine


def _parse_dt(v):
    if v is None:
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(str(v))
    except ValueError:
        return None


def resolve_principal(authorization: str | None) -> dict | None:
    """Verify a platform bearer token; return {user_id, tenant_id, role} or None.
    Fail closed on every error path. Never logs the raw token."""
    if not platform_auth_enabled() or not authorization:
        return None
    if not authorization.startswith("Bearer "):
        return None
    token = authorization[len("Bearer "):].strip()
    if not token or len(token) > 128 or not token.isascii():
        return None
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    try:
        from sqlalchemy import text

        with _get_engine().connect() as conn:
            row = conn.execute(
                text(
                    "SELECT s.user_id AS user_id, s.tenant_id AS tenant_id, "
                    "s.revoked_at AS revoked_at, s.expires_at AS expires_at, "
                    "u.role AS role, u.active AS active "
                    "FROM auth_sessions s JOIN users u "
                    "ON u.id = s.user_id AND u.tenant_id = s.tenant_id "
                    "WHERE s.token_digest = :d LIMIT 1"
                ),
                {"d": digest},
            ).first()
    except Exception:
        return None  # fail closed: platform DB unreachable/unreadable
    if row is None:
        return None
    revoked = _parse_dt(row.revoked_at)
    expires = _parse_dt(row.expires_at)
    now = datetime.now(timezone.utc)
    if revoked is not None or expires is None or expires <= now:
        return None
    if not row.active:
        return None
    role = (row.role or "").lower()
    if role not in ("admin", "analyst", "viewer"):
        return None  # unknown role fails closed, per platform authorize()
    return {"user_id": str(row.user_id), "tenant_id": str(row.tenant_id), "role": role}


def _roles(env_name: str, default: str) -> set[str]:
    return {r.strip().lower() for r in os.getenv(env_name, default).split(",") if r.strip()}


def read_allowed(principal: dict | None) -> bool:
    """Ops reads require a valid platform session whose role is allow-listed."""
    if principal is None:
        return False
    return principal["role"] in _roles("CICC_OPS_READ_ROLES", "admin,analyst,viewer")


def write_allowed(principal: dict | None) -> bool:
    """Ops writes require a valid platform session with a write-capable role."""
    if principal is None:
        return False
    return principal["role"] in _roles("CICC_OPS_WRITE_ROLES", "admin")
