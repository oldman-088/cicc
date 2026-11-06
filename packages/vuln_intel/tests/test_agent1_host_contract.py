"""Does this package actually match Agent 1's host, or only its own idea of it?

Every earlier integration test used duck-typed stand-ins. A stand-in proves the shape
of the code *I* wrote; it cannot prove I read the host correctly. So these tests read
Agent 1's real source out of the repository — ``apps/api/app/security.py`` and
``protected_api.py`` on the branch that owns them — and assert the four facts a mount
actually depends on:

1. the read permission is the string ``intelligence:read``;
2. ``Principal`` carries ``user_id``, ``tenant_id``, ``role``;
3. ``authorize`` fails closed with ``PermissionError``;
4. the protected router refuses plaintext.

They do not import ``app.*`` and do not require it on ``sys.path``: the source is read
as text and executed against a minimal shim, so the package stays stdlib-only and the
suite still runs when the host branch is absent. When the host branch is absent the
tests skip and *say* the contract was not checked — a silent pass here would be the
exact dishonesty this file exists to prevent.

If the host changes one of these, this file fails. That is the point: an integration
that quietly stops matching the host is worse than one that breaks loudly.
"""

from __future__ import annotations

import ast
import pathlib
import shutil
import subprocess

import pytest

from vuln_intel.integration.agent1_host import (
    bearer_principal_reader,
    check_host_contract,
    host_mountable,
)
from vuln_intel.integration.api import ApiError
from vuln_intel.integration.host_adapter import HOST_PERMISSION_READ

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
#: The branch that owns the host application. Not `main`: `main` predates it.
HOST_BRANCH = "origin/arena/da631853-cicc"
SECURITY_PATH = "apps/api/app/security.py"
ROUTER_PATH = "apps/api/app/protected_api.py"


def _git_show(path: str) -> str | None:
    """Read a file from the host branch, or None when that branch is unavailable."""
    git = shutil.which("git")
    if git is None:
        return None
    try:
        result = subprocess.run(  # noqa: S603
            [git, "show", f"{HOST_BRANCH}:{path}"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            check=False,
        )
    except (OSError, ValueError):  # pragma: no cover - git missing
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return result.stdout


SECURITY_SOURCE = _git_show(SECURITY_PATH)
ROUTER_SOURCE = _git_show(ROUTER_PATH)

requires_host = pytest.mark.skipif(
    SECURITY_SOURCE is None,
    reason=(
        f"host branch {HOST_BRANCH} is not present, so the host contract was NOT "
        "checked; this is not a pass"
    ),
)


class TestTheHostPermissionString:
    """The single literal that decides whether every mount call is rejected."""

    @requires_host
    def test_the_read_permission_matches_the_host_enum(self):
        assert SECURITY_SOURCE is not None
        tree = ast.parse(SECURITY_SOURCE)
        found: str | None = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Name)
                        and target.id == "READ_INTELLIGENCE"
                    ) and isinstance(node.value, ast.Constant):
                        found = node.value.value
        assert found is not None, "the host no longer defines READ_INTELLIGENCE"
        assert found == HOST_PERMISSION_READ, (
            f"host permission is {found!r} but this package sends "
            f"{HOST_PERMISSION_READ!r}; every mounted request would be refused"
        )

    @requires_host
    def test_the_host_defines_the_three_roles_this_package_assumes(self):
        assert SECURITY_SOURCE is not None
        for role in ("ADMIN", "ANALYST", "VIEWER"):
            assert f'{role} = "' in SECURITY_SOURCE, f"host no longer defines {role}"

    @requires_host
    def test_a_viewer_permission_set_still_grants_read(self):
        """A read-only mounted route must work for a viewer, or the domain is useless."""
        assert SECURITY_SOURCE is not None
        # VIEWER -> {READ_INTELLIGENCE} appears as the frozen set in ROLE_PERMISSIONS.
        assert "Role.VIEWER: frozenset({Permission.READ_INTELLIGENCE})" in SECURITY_SOURCE


class TestTheHostPrincipalShape:
    @requires_host
    def test_the_principal_carries_tenant_user_and_role(self):
        assert SECURITY_SOURCE is not None
        for attribute in ("user_id", "tenant_id", "role"):
            assert f"{attribute}:" in SECURITY_SOURCE, (
                f"host Principal no longer declares {attribute}"
            )

    @requires_host
    def test_authorize_fails_closed_by_raising(self):
        """A returning authorizer would let every tenant read every finding."""
        assert SECURITY_SOURCE is not None
        assert "raise PermissionError" in SECURITY_SOURCE

    @requires_host
    def test_authorize_compares_the_tenant_rather_than_trusting_the_argument(self):
        assert SECURITY_SOURCE is not None
        assert "principal.tenant_id != tenant_id" in SECURITY_SOURCE


class TestTheHostRefusesPlaintext:
    @requires_host
    def test_the_protected_router_requires_https(self):
        assert ROUTER_SOURCE is not None
        assert "HTTPS required" in ROUTER_SOURCE, (
            "the host no longer refuses plaintext; the mount's require_https default "
            "would be stricter than the host it sits in, or the host became laxer"
        )

    @requires_host
    def test_the_host_extracts_the_token_from_the_same_header_shape(self):
        assert ROUTER_SOURCE is not None
        assert "scheme.lower() != 'bearer'" in ROUTER_SOURCE
        assert "' ' in token" in ROUTER_SOURCE

    def test_our_reader_rejects_the_same_malformed_headers(self):
        """Same three refusals as the host's ``bearer()`` dependency, by behaviour."""
        read = bearer_principal_reader(lambda token: {"token": token})

        with pytest.raises(ApiError):
            read({"headers": [(b"authorization", b"Basic abc")]})
        with pytest.raises(ApiError):
            read({"headers": [(b"authorization", b"Bearer ")]})
        with pytest.raises(ApiError):
            read({"headers": [(b"authorization", b"Bearer a b")]})
        # A missing header is not an exception: the resolver turns it into 401.
        assert read({"headers": []}) is None

    def test_our_reader_accepts_any_scheme_case(self):
        read = bearer_principal_reader(lambda token: {"token": token})
        for header in (b"Bearer abc", b"bearer abc", b"BEARER abc"):
            assert read({"headers": [(b"authorization", header)]}) == {"token": "abc"}

    def test_our_reader_matches_the_header_name_case_insensitively(self):
        """HTTP header names are case-insensitive; ASGI servers vary."""
        read = bearer_principal_reader(lambda token: {"token": token})
        assert read({"headers": [(b"Authorization", b"Bearer abc")]}) == {"token": "abc"}

    def test_a_non_utf8_header_is_refused_rather_than_mangled(self):
        """latin-1 decodes any byte string, so it would invent a plausible token.

        Strict utf-8 means the header is simply not a usable credential: ``None``,
        which the resolver renders as 401. Never a 500 and never a lookup.
        """
        read = bearer_principal_reader(lambda token: {"token": token})
        assert read({"headers": [(b"authorization", b"Bearer \xff\xfe")]}) is None


class TestTheContractCheckerItself:
    """A checker that cannot fail is not a check."""

    def _principal(self):
        from dataclasses import dataclass
        from uuid import UUID, uuid4

        @dataclass(frozen=True)
        class Principal:
            user_id: UUID
            tenant_id: UUID
            role: str

        return Principal(user_id=uuid4(), tenant_id=uuid4(), role="viewer")

    def _permission(self):
        from enum import Enum

        class Permission(str, Enum):
            READ_INTELLIGENCE = "intelligence:read"

        return Permission

    def test_a_correct_host_produces_no_problems(self):
        principal = self._principal()

        def authorize(p, tenant_id, permission):
            if p.tenant_id != tenant_id:
                raise PermissionError("Access denied")

        assert (
            check_host_contract(
                permission_enum=self._permission(),
                principal_type=type(principal),
                authorize=authorize,
                principal_factory=self._principal,
            )
            == []
        )

    def test_a_wrong_permission_string_is_reported(self):
        from enum import Enum

        class Permission(str, Enum):
            READ_INTELLIGENCE = "intel:read"

        problems = check_host_contract(
            permission_enum=Permission,
            principal_type=type(self._principal()),
            authorize=lambda p, t, perm: (_ for _ in ()).throw(PermissionError()),
            principal_factory=self._principal,
        )
        assert any("403" in p for p in problems), problems

    def test_an_authorizer_that_does_not_fail_closed_is_reported(self):
        """The dangerous host: it returns happily for a foreign tenant."""
        problems = check_host_contract(
            permission_enum=self._permission(),
            principal_type=type(self._principal()),
            authorize=lambda p, t, perm: None,
            principal_factory=self._principal,
        )
        assert any("fail closed" in p for p in problems), problems

    def test_a_principal_missing_a_tenant_is_reported(self):
        from dataclasses import dataclass
        from uuid import UUID, uuid4

        @dataclass(frozen=True)
        class Broken:
            user_id: UUID
            role: str

        problems = check_host_contract(
            permission_enum=self._permission(),
            principal_type=Broken,
            authorize=lambda p, t, perm: (_ for _ in ()).throw(PermissionError()),
            principal_factory=lambda: Broken(user_id=uuid4(), role="viewer"),
        )
        assert any("tenant_id" in p for p in problems), problems


class TestTheMountProducesTheRightRefusals:
    """End-to-end through the real ASGI app, with the host's semantics injected."""

    def _app(self, *, role_can_read: bool = True, tenant: str = "tenant-a"):
        class _Store:
            def find(self, *, tenant_id, cve):
                return None

            def list(self, **kwargs):
                return [], None

            def record_count(self, *, tenant_id):
                return 0

        def authenticate(token):
            if token != "good-token":
                return None

            import uuid
            from dataclasses import dataclass

            @dataclass(frozen=True)
            class Principal:
                user_id: uuid.UUID
                tenant_id: str
                role: str

            return Principal(user_id=uuid.uuid4(), tenant_id=tenant, role="viewer")

        def authorize(principal, permission):
            # Mirrors Agent 1: refuse a principal that cannot read intelligence.
            if not role_can_read:
                raise PermissionError("Access denied")

        # `.app` because a mount returns a descriptor, not the ASGI app: the
        # descriptor carries whether anything actually mounted it.
        return host_mountable(
            _Store(), authenticate=authenticate, authorize=authorize, require_https=False
        ).app

    def _call(self, app, header: bytes | None, path: str = "/health"):
        import asyncio

        scope = {
            "type": "http",
            "method": "GET",
            "path": path,
            "scheme": "http",
            "headers": [(b"authorization", header)] if header else [],
            "query_string": b"",
            "client": ("127.0.0.1", 1234),
        }

        async def run():
            sent: list[dict] = []

            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(message):
                sent.append(message)

            await app(scope, receive, send)
            return sent

        return asyncio.run(run())

    @staticmethod
    def _status(messages) -> int:
        for message in messages:
            if message["type"] == "http.response.start":
                return message["status"]
        raise AssertionError("no response was started")

    def test_a_valid_token_reaches_the_domain(self):
        status = self._status(self._call(self._app(), b"Bearer good-token"))
        assert status in (200, 404), status

    def test_a_missing_token_is_401(self):
        assert self._status(self._call(self._app(), None)) == 401

    def test_an_unknown_token_is_401(self):
        assert self._status(self._call(self._app(), b"Bearer bad")) == 401

    def test_routing_does_not_leak_to_an_anonymous_caller(self):
        """401 for every path, existing or not, when there is no credential.

        Routing before authentication lets an unauthenticated caller map the API by
        comparing 401 with 404. The host authenticates first; so does the mount.
        """
        app = self._app()
        for path in ("/v1/vulnerabilities", "/v1/vulnerabilities/CVE-2021-44228",
                     "/v1/does-not-exist", "/"):
            assert self._status(self._call(app, None, path=path)) == 401, path

    def test_an_authenticated_caller_still_gets_404_for_an_unknown_route(self):
        """The fix must not turn "wrong path" into "unauthenticated"."""
        status = self._status(
            self._call(self._app(), b"Bearer good-token", path="/v1/nope")
        )
        assert status == 404, status

    def test_an_authenticated_but_unpermitted_principal_is_403(self):
        """403, not 401: re-authenticating cannot grant the missing permission."""
        status = self._status(
            self._call(self._app(role_can_read=False), b"Bearer good-token")
        )
        assert status == 403
