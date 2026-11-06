"""The first actual-host acceptance test for SBOM import.

This is **not** a synthetic-host test. It runs the host's own modules — extracted
read-only from `origin/arena/da631853-cicc` into a temporary directory — against a real
PostgreSQL server started by `pgserver`, and feeds a verified `Principal` into the
import handler.

The chain exercised, end to end, with nothing faked:

1. `create_tenant_with_admin` creates two tenants in real PostgreSQL;
2. `issue_session` mints a real session token, stored as a digest;
3. `authenticate_session` reads that row back and resolves a `Principal`;
4. `authorize` (the host's own function) allows the principal's own tenant and **denies
   another tenant** — tenant isolation measured, not assumed;
5. the resolved `tenant_id` is passed to `handle_sbom_import` as an argument while the
   document tries to claim the other tenant, and the claim is ignored;
6. the handler persists nothing, verified by inspecting `pg_tables` afterwards.

Why it skips rather than fails when prerequisites are absent
-----------------------------------------------------------
The host branch has to be fetchable and `fastapi`/`argon2-cffi`/`pgserver` installed.
When any is missing the test cannot run, and a skip is the honest outcome — but each
skip states which prerequisite is missing, and the dedicated CI job fails on any skip in
its PostgreSQL set so this cannot silently stop running.

It is reported separately from the general suite for the same reason.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

import pytest

HOST_BRANCH = "origin/arena/da631853-cicc"
def _repo_root() -> pathlib.Path:
    """Walk up to the directory holding `.git`, so the path depth is not hard-coded.

    A fixed `parents[N]` was wrong here first time and made every test skip while
    looking like it had run. Skipping silently is the failure mode this file exists to
    avoid, so the lookup is explicit.
    """
    for candidate in pathlib.Path(__file__).resolve().parents:
        if (candidate / ".git").exists():
            return candidate
    raise RuntimeError("no .git directory above this test file")


REPO_ROOT = _repo_root()


def _have(module: str) -> bool:
    import importlib.util

    return importlib.util.find_spec(module) is not None


def _host_tree() -> pathlib.Path | None:
    """Extract the host's `apps/api` read-only, or None if the branch is unavailable."""
    # Resolve the executables by absolute path, as test_agent1_host_contract.py does:
    # a bare "git" lets PATH decide what runs, which bandit's S607 is right to flag.
    git = shutil.which("git")
    tar = shutil.which("tar")
    if git is None or tar is None:
        return None
    check = subprocess.run(  # noqa: S603 - absolute path, fixed argv, no shell
        [git, "rev-parse", "--verify", HOST_BRANCH],
        cwd=str(REPO_ROOT), capture_output=True, text=True, check=False,
    )
    if check.returncode != 0:
        return None
    target = pathlib.Path(tempfile.mkdtemp(prefix="hostacc-"))
    archive = subprocess.run(  # noqa: S603 - absolute path, fixed argv, no shell
        [git, "archive", HOST_BRANCH, "apps/api"],
        cwd=str(REPO_ROOT), capture_output=True, check=False,
    )
    if archive.returncode != 0:
        shutil.rmtree(target, ignore_errors=True)
        return None
    untar = subprocess.run(  # noqa: S603 - absolute path, fixed argv, no shell
        [tar, "-x", "-C", str(target)], input=archive.stdout, capture_output=True,
        check=False,
    )
    if untar.returncode != 0:
        shutil.rmtree(target, ignore_errors=True)
        return None
    return target


@pytest.fixture(scope="module")
def host_tree():
    missing = [m for m in ("fastapi", "argon2", "sqlalchemy", "pgserver", "psycopg")
               if not _have(m)]
    if missing:
        pytest.skip(
            "HOST ACCEPTANCE DID NOT RUN: missing prerequisite(s) "
            f"{', '.join(missing)}. Install them in the PostgreSQL CI job; this test "
            "needs a real server and the host's own auth stack, not mocks."
        )
    tree = _host_tree()
    if tree is None:
        pytest.skip(
            f"HOST ACCEPTANCE DID NOT RUN: branch {HOST_BRANCH} is not fetched. "
            "Run `git fetch origin 'refs/heads/*:refs/remotes/origin/*'`."
        )
    yield tree
    shutil.rmtree(tree, ignore_errors=True)


@pytest.fixture(scope="module")
def host_app(host_tree):
    """Boot a real PostgreSQL, create the host schema, and import the host's modules."""
    sys.path.insert(0, str(host_tree / "apps" / "api"))
    try:
        import pgserver
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        data_dir = tempfile.mkdtemp(prefix="pgacc-")
        server = pgserver.get_server(data_dir, cleanup_mode="delete")
        url = server.get_uri()
        engine = create_engine(url, hide_parameters=True)
        assert engine.dialect.name == "postgresql", (
            f"expected a real PostgreSQL server, got {engine.dialect.name}"
        )
        from app.models import Base

        Base.metadata.create_all(engine)
        factory = sessionmaker(engine, expire_on_commit=False)
        yield {"engine": engine, "factory": factory, "url": url}
        engine.dispose()
    finally:
        sys.path.pop(0)


class TestActualHostAcceptance:
    """Each test states what it proves; none of them use a fake host."""

    def test_a_principal_resolves_from_a_real_database_row(self, host_app):
        """Proof the host's session table, digest and lookup all ran for real."""
        from app.bootstrap import create_tenant_with_admin
        from app.sessions import authenticate_session, issue_session

        factory = host_app["factory"]
        tenant, user = create_tenant_with_admin(
            factory, tenant_name="Acceptance A", username="acc-admin",
            password="correct-horse-battery",
        )
        with factory.begin() as db:
            token = issue_session(db, tenant, "acc-admin", "correct-horse-battery")
        assert token, "the host issued no session token"

        with factory.begin() as db:
            principal = authenticate_session(db, token)
        assert principal is not None, "a freshly issued token did not authenticate"
        assert principal.tenant_id == tenant
        assert principal.user_id == user

    def test_another_tenants_data_is_denied_by_the_hosts_own_authorizer(self, host_app):
        """Tenant isolation measured through `authorize`, not assumed from schema."""
        from app.bootstrap import create_tenant_with_admin
        from app.security import Permission, authorize

        factory = host_app["factory"]
        tenant_a, _ = create_tenant_with_admin(
            factory, tenant_name="Acceptance Tenant A", username="adm-a",
            password="correct-horse-battery",
        )
        tenant_b, _ = create_tenant_with_admin(
            factory, tenant_name="Acceptance Tenant B", username="adm-b",
            password="correct-horse-battery",
        )
        from app.sessions import authenticate_session, issue_session

        with factory.begin() as db:
            token = issue_session(db, tenant_a, "adm-a", "correct-horse-battery")
        with factory.begin() as db:
            principal = authenticate_session(db, token)
        assert principal is not None

        authorize(principal, tenant_a, Permission.WRITE_INTELLIGENCE)
        with pytest.raises(PermissionError):
            authorize(principal, tenant_b, Permission.WRITE_INTELLIGENCE)

    def test_an_import_uses_the_principals_tenant_and_ignores_the_documents(
        self, host_app
    ):
        """The property the whole contract exists for.

        The document explicitly claims another tenant. The handler is given the
        tenant resolved from the authenticated principal and must use only that.
        """
        from app.bootstrap import create_tenant_with_admin
        from app.sessions import authenticate_session, issue_session

        from vuln_intel.integration.sbom_handler import (
            SbomImportRequest,
            handle_sbom_import,
        )

        factory = host_app["factory"]
        tenant_a, _ = create_tenant_with_admin(
            factory, tenant_name="Import Tenant A", username="imp-a",
            password="correct-horse-battery",
        )
        tenant_b, _ = create_tenant_with_admin(
            factory, tenant_name="Import Tenant B", username="imp-b",
            password="correct-horse-battery",
        )
        with factory.begin() as db:
            token = issue_session(db, tenant_a, "imp-a", "correct-horse-battery")
        with factory.begin() as db:
            principal = authenticate_session(db, token)
        assert principal is not None

        document = json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                # The attack: name someone else's tenant in the payload.
                "tenant_id": str(tenant_b),
                "components": [
                    {
                        "bom-ref": "r1",
                        "name": "log4j-core",
                        "version": "2.14.1",
                        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                    }
                ],
            }
        ).encode()

        response = handle_sbom_import(
            SbomImportRequest(
                body=document,
                tenant_id=str(principal.tenant_id),
                actor_id=str(principal.user_id),
                origin="live",
            )
        )
        assert response.status == 200
        assert response.body["tenant_id"] == str(principal.tenant_id)
        assert response.body["tenant_id"] != str(tenant_b)
        assert str(tenant_b) not in json.dumps(response.body)
        assert response.body["result"]["components"] == 1
        assert len(response.body["result"]["source_sha256"]) == 64

    def test_the_handler_persists_nothing(self, host_app):
        """A contract test, not an import: no table may gain rows.

        Counted with `count(*)`, not `pg_stat_user_tables.n_live_tup`. The first version
        of this test used the statistics view and was **flaky**: `n_live_tup` is an
        estimate maintained asynchronously by the stats collector, so rows created by
        earlier tests in this module appeared between the "before" and "after" reads and
        the test failed while the handler had written nothing. An exact count has no such
        lag. A test that fails for its own reason is worse than no test: it teaches
        whoever sees it to distrust the suite.
        """
        from sqlalchemy import text

        from vuln_intel.integration.sbom_handler import (
            SbomImportRequest,
            handle_sbom_import,
        )

        engine = host_app["engine"]

        def counts() -> dict[str, int]:
            with engine.begin() as conn:
                tables = [
                    row[0]
                    for row in conn.execute(
                        text(
                            "select tablename from pg_tables "
                            "where schemaname = 'public' order by tablename"
                        )
                    ).all()
                ]
                return {
                    table: conn.execute(
                        text(f'select count(*) from "{table}"')  # noqa: S608 - table name from pg_tables
                    ).scalar_one()
                    for table in tables
                }

        before = counts()
        assert before, "the host schema created no tables; the test would be vacuous"

        document = json.dumps(
            {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
        ).encode()
        response = handle_sbom_import(
            SbomImportRequest(
                body=document,
                tenant_id="00000000-0000-0000-0000-00000000000a",
                origin="live",
            )
        )
        assert response.status == 200

        after = counts()
        assert after == before, "the handler changed persisted row counts"
        # And no inventory store appeared, which is the stronger claim.
        assert not [
            t for t in after if "sbom" in t.lower() or "inventory" in t.lower()
        ], "the handler created an inventory table; it must not own persistence"


class TestTheHostBlocksALargeImport:
    """A measured host constraint, not a guess.

    The host's `ExperimentalBodyLimit` applies a 16 KiB ceiling to every path under
    `/api/v1/secure`, and its default is what `main.py` mounts. A real CycloneDX
    document with a few hundred components exceeds that, so an SBOM route under that
    prefix would reject ordinary inventories before my parser ever saw them.

    Measured against the host's own guard, extracted from their branch.
    """

    HOST_BODY_LIMIT = 16384

    def test_a_typical_sbom_exceeds_the_hosts_body_limit(self):
        components = [
            {
                "bom-ref": f"pkg:npm/c{i}@1.0.0",
                "name": f"c{i}",
                "version": "1.0.0",
                "purl": f"pkg:npm/c{i}@1.0.0",
            }
            for i in range(400)
        ]
        document = json.dumps(
            {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components}
        ).encode()
        assert len(document) > self.HOST_BODY_LIMIT, (
            "if a 400-component SBOM fits in the host's limit, re-measure the blocker"
        )
        # And my own ceiling would accept it, which is the mismatch that matters.
        from vuln_intel.sbom import MAX_DOCUMENT_BYTES

        assert len(document) < MAX_DOCUMENT_BYTES

    def test_the_host_guard_really_rejects_it(self, host_tree):
        """Executed against the host's middleware, not inferred from its constant."""
        if not _have("fastapi"):
            pytest.skip("HOST GUARD NOT EXERCISED: fastapi is not installed")
        sys.path.insert(0, str(host_tree / "apps" / "api"))
        try:
            from app.request_limits import ExperimentalBodyLimit
            from fastapi import FastAPI
            from fastapi.testclient import TestClient

            app = FastAPI()
            app.add_middleware(ExperimentalBodyLimit)

            @app.post("/api/v1/secure/sbom")
            def _accept():
                return {"ok": True}

            client = TestClient(app)
            body = b'{"bomFormat":"CycloneDX","specVersion":"1.5","components":[' + (
                b",".join(
                    b'{"bom-ref":"r%d","name":"c","version":"1","purl":"pkg:npm/c@1"}' % i
                    for i in range(400)
                )
            ) + b"]}"
            assert len(body) > 16384
            response = client.post(
                "/api/v1/secure/sbom", content=body,
                headers={"content-type": "application/json"},
            )
            assert response.status_code == 413, (
                "the host guard did not reject a 20+ KiB body; the blocker in "
                "SBOM_HOST_CONTRACT_M52.md needs re-measuring"
            )
        finally:
            sys.path.pop(0)
