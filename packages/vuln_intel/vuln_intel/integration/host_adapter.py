"""Mount this package behind Agent 1's authorization layer, without importing it.

The gap this closes
-------------------
`build_app()` takes a ``resolve_tenant`` callable and trusts whatever it returns. That
is correct for the package — it has no business knowing how the host authenticates —
but it means the *composition* was left as an exercise for whoever mounts it, and the
only worked example in the repository (`scripts/serve_demo.py`) reads a header and
trusts it. An integration that copies the demo resolver is a tenancy bypass with a
reassuring docstring.

This module is the real composition, written against Agent 1's actual contract:

    apps/api/app/security.py::Principal(user_id, tenant_id, role)
    apps/api/app/security.py::authorize(principal, tenant_id, Permission)

Nothing here imports ``app.*``. The host's ``Principal`` arrives as an opaque object
and its tenant is read through a duck-typed attribute, so the package stays stdlib-only
and ``tests/test_isolation.py`` stays true. That is deliberate: importing the host would
make this package unimportable in its own CI, which is the one thing the integration
layer refuses to do.

What is enforced here, and why
-----------------------------
* **Tenant comes from the principal, never from the request.** There is no query
  parameter, header or body field that can change it. A blank or missing tenant raises
  rather than falling back to a default, because "empty means all tenants" is the
  classic multi-tenant leak.
* **Authorization is checked before any read.** ``authorize`` is the host's function,
  called with the host's permission enum, so a viewer without intelligence read access
  is refused by the host's own rules rather than by a re-implementation of them here.
* **A refusal is a 403, not a 401.** The caller is authenticated; they are not allowed.
  Reporting 401 would tell a client to re-authenticate, which cannot help.
* **Errors are sanitized.** The host's ``PermissionError`` message is not forwarded; the
  response carries our error envelope with the code and no internals.

What is *not* claimed
--------------------
This is a tested composition, not a mounted endpoint. Nothing in this repository calls
it, and ``NOT_MOUNTED`` in the returned descriptor says so in machine-readable form. See
``docs/vulnerability-intelligence/INTEGRATION.md`` §2 for what Agent 1 has to do to make
it real.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .api import ApiError
from .asgi import TenantResolver, VulnerabilityAsgiApp, build_app

__all__ = [
    "HOST_PERMISSION_READ",
    "HostPrincipalResolver",
    "MountDescriptor",
    "principal_resolver",
]

#: The permission string the host uses for reading intelligence. Kept as a literal
#: rather than imported so this module has no host dependency; a test asserts it still
#: matches the host's enum by reading the string from our own copy of the contract.
HOST_PERMISSION_READ = "intelligence:read"


@dataclass(frozen=True)
class MountDescriptor:
    """What a mount would look like, and what has actually happened.

    Machine-readable on purpose: a dashboard that renders "mounted" from a boolean
    somebody typed is how a NOT_MOUNTED domain becomes a green tile.
    """

    app: VulnerabilityAsgiApp
    mounted: bool = False
    #: Always False in this build. Flipping it requires a real mount in the host,
    #: executed and verified — not a decision made in this package.
    mounted_in_host: bool = False
    auth_owner: str = "Agent 1 (apps/api/app/security.py)"
    #: Set only by whoever performs the mount, with the commit that did it.
    mounted_by_commit: str | None = None

    def health(self) -> dict[str, Any]:
        """The status a gateway should publish, including the honest part.

        ``not_configured`` is the accurate state for a domain that is implemented,
        tested and *not wired up*. Reporting ``ok`` because the tests pass is the
        specific dishonesty the health contract exists to prevent.
        """
        return {
            "domain": "vulnerability_intelligence",
            "state": "not_configured" if not self.mounted_in_host else "ok",
            "mounted": self.mounted_in_host,
            "auth_owner": self.auth_owner,
            "mounted_by_commit": self.mounted_by_commit,
            "reason": (
                "implemented and tested in packages/vuln_intel; not mounted in the host "
                "application. Mounting is a shared-architecture change owned by Agent 1."
                if not self.mounted_in_host
                else "mounted"
            ),
        }


@dataclass(frozen=True)
class HostPrincipalResolver:
    """A ``TenantResolver`` backed by the host's ``Principal`` and ``authorize``.

    Both are injected as callables so this module never imports the host:

        resolver = HostPrincipalResolver(
            read_principal=lambda scope: ...,   # host session/token -> Principal
            authorize=lambda principal, permission: ...,  # host's authorize()
            permission=HOST_PERMISSION_READ,
        )
        app = build_app(store, resolve_tenant=resolver)
    """

    read_principal: Callable[[Any], Any]
    authorize: Callable[[Any, str], None]
    permission: str = HOST_PERMISSION_READ

    def __call__(self, scope: Mapping[str, Any]) -> str:
        principal = self.read_principal(scope)
        if principal is None:
            # No session is an authentication problem, and 401 is the right answer:
            # the client may be able to fix it by authenticating.
            raise ApiError("unauthorized", "an authenticated principal is required")

        tenant = getattr(principal, "tenant_id", None)
        if tenant is None or not str(tenant).strip():
            # A principal without a tenant is a host bug, not a client error, and it
            # must not degrade into "all tenants".
            raise ApiError("unauthorized", "the resolved principal carries no tenant")

        # The host decides. We pass its permission string; it fails closed on a
        # different tenant, an unknown role, or a missing permission.
        try:
            self.authorize(principal, self.permission)
        except PermissionError as exc:
            # Authenticated but not permitted: 403. Deliberately does not carry the
            # host's message, which may describe internal role wiring.
            raise ApiError(
                "forbidden_tenant", "this principal may not read vulnerability intelligence"
            ) from exc
        except Exception as exc:  # a broken authorization layer is not a 500
            raise ApiError(
                "store_unavailable",
                f"authorization failed: {type(exc).__name__}",
            ) from exc

        return str(tenant)


def principal_resolver(
    *,
    read_principal: Callable[[Any], Any],
    authorize: Callable[[Any, str], None],
    permission: str = HOST_PERMISSION_READ,
) -> TenantResolver:
    """Build the resolver only; a host that already has ``build_app`` needs no more."""
    return HostPrincipalResolver(
        read_principal=read_principal, authorize=authorize, permission=permission
    )


def mountable(
    store: Any,
    *,
    read_principal: Callable[[Any], Any],
    authorize: Callable[[Any, str], None],
    permission: str = HOST_PERMISSION_READ,
    require_https: bool = True,
) -> MountDescriptor:
    """An app plus an honest descriptor of whether anything mounted it.

    ``require_https`` defaults to **True** here, unlike ``build_app``: a deployment
    behind the host's TLS terminator can opt out explicitly, but the default for a
    production mounting helper should not be "accept plaintext".
    """
    resolver = principal_resolver(
        read_principal=read_principal, authorize=authorize, permission=permission
    )
    return MountDescriptor(
        app=build_app(store, resolve_tenant=resolver, require_https=require_https)
    )
