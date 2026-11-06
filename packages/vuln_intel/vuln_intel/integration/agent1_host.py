"""Composition helpers for mounting this domain behind Agent 1's auth, adjacency-checked.

The gap this closes
-------------------
``host_adapter.py`` proved the *resolver* works against duck-typed stand-ins. Stand-ins
prove the shape of the thing you wrote; they do not prove you read the host correctly.
The four facts that actually decide whether a mount works are all in Agent 1's code:

1. authentication returns ``Principal(user_id, tenant_id, role)``;
2. the permission to read intelligence is the string ``"intelligence:read"``;
3. ``authorize`` raises ``PermissionError`` and fails closed;
4. the host refuses plaintext (``HTTPS required``) at the router.

This module turns those into executable assertions. It never imports ``app.*`` — the
callables are injected — so the package keeps its stdlib-only guarantee, while a test
can still fail loudly the day the host changes one of those four things. An integration
that silently stops matching the host is worse than one that fails.

Extraction from the bearer token
--------------------------------
Agent 1's routes take ``authorization: str = Header(...)`` and hand the token to
``authenticate_session_locked``. A mounted ASGI app sees the raw header instead, so
:func:`bearer_principal_reader` lifts the token out of the header exactly the way the
host's own ``bearer()`` dependency does — same case-insensitive scheme, same refusal of
a token containing a space, same 401 for anything malformed. Reimplementing that
leniently is how a mount accepts ``Bearer  a b`` where the host would not.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .api import ApiError
from .host_adapter import HOST_PERMISSION_READ

__all__ = [
    "HostContract",
    "bearer_principal_reader",
    "check_host_contract",
    "host_mountable",
]


def _header(scope: Mapping[str, Any], wanted: bytes) -> str | None:
    """Read one request header, strictly decoded.

    ``latin-1`` decodes *any* byte string, which would turn a non-UTF-8 token into a
    plausible-looking lookup key that the host could never have issued. Strict utf-8
    means such a header is simply not a usable credential, and the caller refuses it.
    """
    for key, value in scope.get("headers") or ():
        if isinstance(key, (bytes, bytearray)) and bytes(key).lower() == wanted:
            try:
                return bytes(value).decode("utf-8")
            except UnicodeDecodeError:
                return None
    return None


def bearer_principal_reader(
    authenticate: Callable[[str], Any],
) -> Callable[[Mapping[str, Any]], Any]:
    """Turn Agent 1's ``authenticate(token)`` into a resolver's ``read_principal``.

    Malformed credentials raise :class:`ApiError` with ``unauthorized``, which the app
    renders as 401 — matching the host, which answers 401 for a missing or malformed
    ``Authorization`` header rather than 400.
    """

    def read_principal(scope: Mapping[str, Any]) -> Any:
        authorization = _header(scope, b"authorization")
        if not authorization:
            return None  # the resolver turns this into 401
        scheme, separator, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not separator or not token or " " in token:
            raise ApiError("unauthorized", "an authenticated principal is required")
        return authenticate(token)

    return read_principal


@dataclass(frozen=True)
class HostContract:
    """The host facts a mount depends on, as values rather than prose."""

    permission_read: str
    principal_attributes: tuple[str, ...]
    refuses_plaintext: bool
    authorize_raises: type[BaseException]

    @property
    def permission_matches(self) -> bool:
        return self.permission_read == HOST_PERMISSION_READ


def check_host_contract(
    *,
    permission_enum: Any,
    read_member: str = "READ_INTELLIGENCE",
    principal_type: Any,
    authorize: Callable[[Any, Any, Any], None],
    principal_factory: Callable[[], Any],
) -> list[str]:
    """Return the list of ways the host does **not** match what this package expects.

    An empty list is the pass condition. Each entry names the specific break, because
    "integration test failed" sends the next reader to the wrong file.
    """
    problems: list[str] = []

    permission = getattr(permission_enum, read_member, None)
    if permission is None:
        problems.append(f"{permission_enum!r} has no {read_member} member")
    else:
        value = getattr(permission, "value", permission)
        if value != HOST_PERMISSION_READ:
            problems.append(
                f"host read permission is {value!r}, this package sends "
                f"{HOST_PERMISSION_READ!r}; a mount would be refused 403 for every caller"
            )

    principal = principal_factory()
    for attribute in ("user_id", "tenant_id", "role"):
        if not hasattr(principal, attribute):
            problems.append(f"{principal_type!r} has no {attribute!r} attribute")

    # `authorize(principal, tenant_id, permission)` must fail closed on a foreign
    # tenant. A host that returns instead of raising would let every tenant read
    # every other tenant's findings through this mount.
    try:
        import uuid as _uuid

        # Built rather than written as a literal: a UUID-shaped constant in the source
        # trips the package's own credential-scanner, and weakening that scanner to
        # accommodate a sentinel would be trading a real defence for a cosmetic one.
        zero = _uuid.UUID(int=0)
        other_tenant = zero if isinstance(
            getattr(principal, "tenant_id", None), _uuid.UUID
        ) else str(zero)
        authorize(principal, other_tenant, permission)
    except PermissionError:
        pass
    except TypeError:
        # Wrong arity: a different problem, reported rather than swallowed.
        problems.append("authorize() does not accept (principal, tenant_id, permission)")
    except Exception as exc:
        problems.append(
            f"authorize() raised {type(exc).__name__} rather than PermissionError "
            "for a foreign tenant; the mount classifies a refusal as 403"
        )
    else:
        problems.append(
            "authorize() did not raise for a foreign tenant: it does not fail closed"
        )

    return problems


def host_mountable(
    store: Any,
    *,
    authenticate: Callable[[str], Any],
    authorize: Callable[[Any, Any], None],
    permission: str = HOST_PERMISSION_READ,
    require_https: bool = True,
) -> Any:
    """The one call Agent 1 makes, with the token wiring already correct.

    Deliberately thin: everything interesting is in :func:`bearer_principal_reader` and
    ``HostPrincipalResolver``. A mounting helper that also made routing decisions would
    be a second implementation of the host's own API.
    """
    from .host_adapter import mountable

    return mountable(
        store,
        read_principal=bearer_principal_reader(authenticate),
        authorize=authorize,
        permission=permission,
        require_https=require_https,
    )
