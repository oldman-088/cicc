"""Mounting this package behind Agent 1's authorization layer.

The composition was previously left as an exercise, and the only worked example reads
a header and trusts it. These tests exercise the real one, against a stand-in for the
host's `Principal` / `authorize` contract (`apps/api/app/security.py`), which is
duck-typed on purpose: importing the host into this package would make it unimportable
in its own CI.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from vuln_intel.integration import (
    HOST_PERMISSION_READ,
    InMemoryVulnerabilityStore,
    mountable,
)

TENANT_A = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
TENANT_B = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
USER = uuid.UUID("11111111-1111-1111-1111-111111111111")


@dataclass(frozen=True)
class Principal:
    """A stand-in for `apps/api/app/security.py::Principal`."""

    user_id: uuid.UUID
    tenant_id: uuid.UUID | None
    role: str = "analyst"


@dataclass
class Host:
    """A stand-in for the host's authorization layer, including its rules."""

    principal: Principal | None = None
    raise_instead: Exception | None = None
    calls: list[tuple[uuid.UUID, str]] = field(default_factory=list)

    def read_principal(self, scope):
        return self.principal

    def authorize(self, principal, permission):
        self.calls.append((principal.tenant_id, permission))
        if self.raise_instead is not None:
            raise self.raise_instead
        if permission != HOST_PERMISSION_READ:
            raise PermissionError("Access denied")


def _store():
    return InMemoryVulnerabilityStore(allow_fixture=True)


def _scope(*, method="GET", path="/v1/vulnerabilities", scheme="https", query=""):
    return {
        "type": "http",
        "method": method,
        "path": path,
        "scheme": scheme,
        "query_string": query.encode(),
        "headers": [],
    }


class TestTheTenantComesFromThePrincipal:
    def test_the_resolved_tenant_is_the_principals(self):
        host = Host(principal=Principal(USER, TENANT_A))
        descriptor = mountable(
            _store(), read_principal=host.read_principal, authorize=host.authorize
        )
        response = descriptor.app.handle(_scope())
        assert response.status == 200
        assert host.calls == [(TENANT_A, HOST_PERMISSION_READ)]

    def test_a_request_cannot_choose_its_own_tenant(self):
        """No header, query parameter or path segment may override the principal."""
        host = Host(principal=Principal(USER, TENANT_A))
        descriptor = mountable(
            _store(), read_principal=host.read_principal, authorize=host.authorize
        )
        scope = _scope()
        scope["headers"] = [(b"x-tenant-id", str(TENANT_B).encode())]
        response = descriptor.app.handle(scope)
        assert response.status == 200
        # The store was asked for tenant A. The header changed nothing.
        assert host.calls[0][0] == TENANT_A

    def test_a_principal_with_no_tenant_is_refused_not_defaulted(self):
        """"Empty means all tenants" is the classic multi-tenant leak."""
        host = Host(principal=Principal(USER, None))
        descriptor = mountable(
            _store(), read_principal=host.read_principal, authorize=host.authorize
        )
        assert descriptor.app.handle(_scope()).status == 401

    def test_a_blank_tenant_is_refused(self):
        host = Host(principal=Principal(USER, "   "))
        descriptor = mountable(
            _store(), read_principal=host.read_principal, authorize=host.authorize
        )
        assert descriptor.app.handle(_scope()).status == 401


class TestAuthenticationVersusAuthorization:
    def test_no_session_is_401(self):
        host = Host(principal=None)
        descriptor = mountable(
            _store(), read_principal=host.read_principal, authorize=host.authorize
        )
        response = descriptor.app.handle(_scope())
        assert response.status == 401
        assert response.body["error"]["code"] == "unauthorized"

    def test_a_permission_refusal_is_403_not_401(self):
        """The caller is authenticated; telling them to re-authenticate cannot help."""
        host = Host(principal=Principal(USER, TENANT_A), raise_instead=PermissionError("no"))
        descriptor = mountable(
            _store(), read_principal=host.read_principal, authorize=host.authorize
        )
        response = descriptor.app.handle(_scope())
        assert response.status == 403
        assert response.body["error"]["code"] == "forbidden_tenant"

    def test_the_hosts_permission_error_message_is_not_forwarded(self):
        host = Host(
            principal=Principal(USER, TENANT_A),
            raise_instead=PermissionError("role viewer lacks intelligence:read for tenant aaaa"),
        )
        descriptor = mountable(
            _store(), read_principal=host.read_principal, authorize=host.authorize
        )
        body = str(descriptor.app.handle(_scope()).body)
        assert "viewer" not in body and "lacks" not in body

    def test_a_broken_authorization_layer_is_a_503_not_a_500(self):
        host = Host(
            principal=Principal(USER, TENANT_A), raise_instead=RuntimeError("auth service down")
        )
        descriptor = mountable(
            _store(), read_principal=host.read_principal, authorize=host.authorize
        )
        response = descriptor.app.handle(_scope())
        assert response.status == 503
        assert "RuntimeError" in response.body["error"]["message"]

    def test_authorization_is_not_reached_without_a_principal(self):
        """Checked before the read: an unauthorized request never touches the store."""
        host = Host(principal=None)
        descriptor = mountable(
            _store(), read_principal=host.read_principal, authorize=host.authorize
        )
        descriptor.app.handle(_scope())
        assert host.calls == []


class TestTransportAssumptions:
    def test_https_is_required_by_default(self):
        """`build_app` defaults to False; a production mounting helper must not."""
        host = Host(principal=Principal(USER, TENANT_A))
        descriptor = mountable(
            _store(), read_principal=host.read_principal, authorize=host.authorize
        )
        assert descriptor.app.handle(_scope(scheme="http")).status == 401

    def test_a_tls_terminator_can_be_declared_explicitly(self):
        host = Host(principal=Principal(USER, TENANT_A))
        descriptor = mountable(
            _store(), read_principal=host.read_principal, authorize=host.authorize,
            require_https=False,
        )
        assert descriptor.app.handle(_scope(scheme="http")).status == 200

    def test_forwarded_proto_is_honoured(self):
        host = Host(principal=Principal(USER, TENANT_A))
        descriptor = mountable(
            _store(), read_principal=host.read_principal, authorize=host.authorize
        )
        scope = _scope(scheme="http")
        scope["headers"] = [(b"x-forwarded-proto", b"https")]
        assert descriptor.app.handle(scope).status == 200


class TestTheDescriptorDoesNotLieAboutBeingMounted:
    """A domain that is implemented, tested and unwired must not report health."""

    def test_it_reports_not_configured(self):
        host = Host(principal=Principal(USER, TENANT_A))
        health = mountable(
            _store(), read_principal=host.read_principal, authorize=host.authorize
        ).health()
        assert health["state"] == "not_configured"
        assert health["mounted"] is False
        assert "not mounted" in health["reason"]

    def test_it_never_claims_a_mount_unless_one_was_recorded(self):
        host = Host(principal=Principal(USER, TENANT_A))
        descriptor = mountable(
            _store(), read_principal=host.read_principal, authorize=host.authorize
        )
        assert descriptor.mounted_in_host is False
        assert descriptor.mounted_by_commit is None

    def test_the_permission_string_matches_the_hosts_enum(self):
        """Pinned as a literal because importing the host would break our own CI.

        If Agent 1 renames the permission, this test is where it surfaces rather than
        in a production 403 nobody expected.
        """
        assert HOST_PERMISSION_READ == "intelligence:read"


class TestIsolationStillHolds:
    def test_the_adapter_imports_no_host_module(self):
        import ast
        import pathlib

        source = pathlib.Path(
            str(__import__("vuln_intel.integration.host_adapter", fromlist=["x"]).__file__)
        ).read_text()
        imported = {
            node.module
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.ImportFrom) and node.module
        }
        assert not any(module.startswith("app") for module in imported), imported
        assert all(not module.startswith("sqlalchemy") for module in imported), imported
        assert all(not module.startswith("fastapi") for module in imported), imported
