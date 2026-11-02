"""Security primitives; these do not provide authentication endpoints or sessions."""
from dataclasses import dataclass
from enum import Enum
from uuid import UUID

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

# Argon2id parameters are encoded with each hash, permitting later upgrades.
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

class Permission(str, Enum):
    READ_INTELLIGENCE = "intelligence:read"
    WRITE_INTELLIGENCE = "intelligence:write"
    MANAGE_USERS = "users:manage"

ROLE_PERMISSIONS = {
    Role.ADMIN: frozenset(Permission),
    Role.ANALYST: frozenset({Permission.READ_INTELLIGENCE, Permission.WRITE_INTELLIGENCE}),
    Role.VIEWER: frozenset({Permission.READ_INTELLIGENCE}),
}

@dataclass(frozen=True)
class Principal:
    user_id: UUID
    tenant_id: UUID
    role: Role

def authorize(principal: Principal, tenant_id: UUID, permission: Permission) -> None:
    """Fail closed on a different tenant or an unknown role/permission."""
    if principal.tenant_id != tenant_id or permission not in ROLE_PERMISSIONS.get(principal.role, frozenset()):
        raise PermissionError("Access denied")

def hash_password(password: str) -> str:
    if len(password) < 12 or len(password) > 1024:
        raise ValueError("Password must be between 12 and 1024 characters")
    return _hasher.hash(password)

def verify_password(password: str, encoded: str) -> bool:
    if len(password) > 1024:
        return False
    try:
        return _hasher.verify(encoded, password)
    except (VerificationError, InvalidHashError):
        return False
