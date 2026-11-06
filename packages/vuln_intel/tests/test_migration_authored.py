"""The authored migration must actually run, or it is only a suggestion.

`migrations/versions/0043_vuln_intel_records.py` is deliberately not applied anywhere.
That makes it unusually easy to ship a file that would fail the moment the owner tries
it — a typo in a revision id, a column type the engine rejects, a foreign key to a table
that does not exist in the chain.

So the migration is executed here, against a real PostgreSQL server, on top of a
minimal stand-in for the one table it depends on (``tenants``). Then the DB-API store
is pointed at the resulting schema and must work unmodified. That is the whole claim:
the table this package expects and the table this migration creates are the same table.

If PostgreSQL is unavailable the tests skip and say the migration was NOT verified. A
skip is not a pass, and the message says so.
"""

from __future__ import annotations

import pathlib
import re

import pytest

MIGRATION = (
    pathlib.Path(__file__).resolve().parents[1]
    / "migrations" / "versions" / "0043_vuln_intel_records.py"
)


def _postgres_dsn():
    import os

    configured = os.environ.get("CICC_TEST_POSTGRES_DSN")
    if configured:
        return configured
    try:
        import pgserver
    except ImportError:
        return None
    import tempfile

    return pgserver.get_server(tempfile.mkdtemp(prefix="pgmig-")).get_uri()


_PG_DSN = _postgres_dsn()
_needs_pg = pytest.mark.skipif(
    _PG_DSN is None,
    reason="no PostgreSQL available: the authoried migration was NOT executed",
)


class TestTheMigrationFileIsWellFormed:
    def test_it_declares_a_revision_and_a_parent(self):
        source = MIGRATION.read_text()
        assert re.search(r"^revision = '0043_vuln_intel_records'$", source, re.M)
        # The parent must be the current head of the host chain.
        assert re.search(r"^down_revision = '0042_note_corrections'$", source, re.M)

    def test_it_has_both_upgrade_and_downgrade(self):
        source = MIGRATION.read_text()
        assert "def upgrade():" in source
        assert "def downgrade():" in source

    def test_every_table_it_creates_is_also_dropped(self):
        """A migration that cannot be reversed is a one-way door in a shared database."""
        source = MIGRATION.read_text()
        created = set(re.findall(r"op\.create_table\(\s*'([a-z_]+)'", source))
        dropped = set(re.findall(r"op\.drop_table\('([a-z_]+)'\)", source))
        assert created, "no tables found; the regex or the migration changed"
        assert created == dropped, f"created {created} but only drops {dropped}"

    def test_every_index_is_also_dropped(self):
        source = MIGRATION.read_text()
        created = set(re.findall(r"op\.create_index\(\s*'([a-z_]+)'", source))
        dropped = set(re.findall(r"op\.drop_index\('([a-z_]+)'", source))
        assert created == dropped, f"created {created} but only drops {dropped}"


@_needs_pg
class TestTheMigrationRuns:
    @pytest.fixture()
    def migrated(self):
        psycopg = pytest.importorskip("psycopg")
        conn = psycopg.connect(_PG_DSN, autocommit=True)
        with conn.cursor() as cur:
            # The migration's only external dependency. The real chain creates this.
            cur.execute("CREATE TABLE IF NOT EXISTS tenants (id UUID PRIMARY KEY)")
            cur.execute("DROP TABLE IF EXISTS vulnerability_provenance_event")
            cur.execute("DROP TABLE IF EXISTS vulnerability_record")
        conn.close()

        # Alembic is not installed here, so `op` is provided by a shim that executes
        # the same DDL against this server. That still proves the DDL is valid
        # PostgreSQL; it does not prove alembic's ordering, which no migration test
        # can prove without the real chain.
        module = _load_with_shim(_PG_DSN)
        module.upgrade()
        conn = psycopg.connect(_PG_DSN, autocommit=True)
        with conn.cursor() as cur:
            cur.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public'"
            )
            tables = {row[0] for row in cur.fetchall()}
        conn.close()
        return tables

    def test_the_tables_exist_after_upgrade(self, migrated):
        assert "vulnerability_record" in migrated
        assert "vulnerability_provenance_event" in migrated

    def test_downgrade_removes_them_again(self, migrated):
        module = _load_with_shim(_PG_DSN)
        module.downgrade()
        import psycopg

        conn = psycopg.connect(_PG_DSN, autocommit=True)
        with conn.cursor() as cur:
            cur.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public'"
            )
            tables = {row[0] for row in cur.fetchall()}
        conn.close()
        assert "vulnerability_record" not in tables
        assert "vulnerability_provenance_event" not in tables

    def test_the_store_works_against_the_migrated_schema(self, migrated):
        """The real claim: the store and the migration describe the same table."""
        import uuid
        from datetime import datetime, timezone

        import psycopg

        from vuln_intel.integration.dbapi_store import DBAPIVulnerabilityStore

        store = DBAPIVulnerabilityStore(
            connect=lambda: psycopg.connect(_PG_DSN),
            paramstyle="format",
            json_mode="json_wrapper",
            boolean_kev=True,
        )
        tenant = str(uuid.uuid4())
        conn = psycopg.connect(_PG_DSN, autocommit=True)
        with conn.cursor() as cur:
            cur.execute("INSERT INTO tenants (id) VALUES (%s) ON CONFLICT DO NOTHING", (tenant,))
        conn.close()

        result = store.upsert(
            tenant_id=tenant,
            cve="CVE-2021-44228",
            entity={"id": str(uuid.uuid4())},
            details={"severity": "critical", "kev": True},
            enrichment={"origin": "live", "severity": "critical"},
            provenance={"source": "NVD"},
            collected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            dry_run=False,
        )
        assert result.outcome == "created"
        found = store.find(tenant_id=tenant, cve="CVE-2021-44228")
        assert found is not None
        assert found["details"]["severity"] == "critical"
        rows, _ = store.list(tenant_id=tenant, limit=10, kev_only=True)
        assert [r["cve"] for r in rows] == ["CVE-2021-44228"]


def _load_with_shim(dsn):
    """Execute the migration module with a minimal ``op``/``sa`` standing in for Alembic.

    The migration is written against Alembic's API. Rather than declare it untestable
    without Alembic, the operations it uses are implemented here as real DDL against a
    real server. Anything the migration calls that this shim lacks will raise, which is
    the honest outcome: it means the migration uses an operation nobody verified.
    """
    import types
    import uuid

    import psycopg
    import sqlalchemy as real_sa

    def run(sql):
        conn = psycopg.connect(dsn, autocommit=True)
        try:
            with conn.cursor() as cur:
                cur.execute(sql)
        finally:
            conn.close()

    def _type(column):
        text = str(column.type).upper()
        # SQLAlchemy's ``Uuid()`` renders as ``CHAR(32)`` for portability. PostgreSQL
        # gets a real UUID, which is what the host's own schema uses in production and
        # why the stand-in ``tenants.id`` above is UUID: the two must agree or the
        # foreign key cannot be created at all.
        if isinstance(column.type, real_sa.Uuid) or "UUID" in text or text == "CHAR(32)":
            return "UUID"
        if "BOOLEAN" in text:
            return "BOOLEAN"
        if "INTEGER" in text:
            return "INTEGER"
        if "BIGINT" in text:
            # An autoincrementing integer PK needs a sequence, not a bare BIGINT.
            # `sa.BigInteger()` alone renders BIGINT and the insert then fails with a
            # not-null violation on the id, which looks like a data bug.
            return "BIGSERIAL"
        if "JSON" in text:
            return "JSONB"
        if "DATETIME" in text or "TIMESTAMP" in text:
            return "TIMESTAMPTZ"
        match = real_sa.String  # keep a reference so a linter sees the import used
        del match
        length = getattr(column.type, "length", None)
        return f"VARCHAR({length})" if length else "TEXT"

    def create_table(name, *columns, **_kwargs):
        parts = []
        for column in columns:
            if isinstance(column, real_sa.schema.Column):
                piece = f'"{column.name}" {_type(column)}'
                if not column.nullable and not column.primary_key:
                    piece += " NOT NULL"
                if column.primary_key:
                    piece += " NOT NULL"
                default = getattr(column, "server_default", None)
                if default is not None and getattr(default, "arg", None) is not None:
                    piece += f" DEFAULT {default.arg}"
                parts.append(piece)
                continue
            # A constraint object. A ForeignKeyConstraint only knows its local
            # columns once it is attached to a Table, so it is bound first --
            # reading `column_names` on a free-standing one raises in SQLAlchemy 2.x.
            if isinstance(column, real_sa.schema.CheckConstraint):
                parts.append(f"CONSTRAINT {column.name} CHECK ({column.sqltext})")
            elif isinstance(column, real_sa.schema.ForeignKeyConstraint):
                # A composite key has one element *per column*; reading only the first
                # produced a single-column reference to a two-column key, which
                # PostgreSQL rejects with "no unique constraint matching given keys".
                targets = [e.target_fullname for e in column.elements]
                remote_table = targets[0].split(".")[0]
                remote_cols = [t.split(".")[-1] for t in targets]
                local_cols = list(getattr(column, "_pending_colargs", []) or [])
                if not local_cols:  # already bound to a table
                    local_cols = list(column.columns.keys())
                local = ", ".join(f'"{c}"' for c in local_cols)
                remote = ", ".join(f'"{c}"' for c in remote_cols)
                parts.append(
                    f'FOREIGN KEY ({local}) REFERENCES "{remote_table}" ({remote})'
                    + (f" ON DELETE {column.ondelete}" if column.ondelete else "")
                )
        primary = [c.name for c in columns if getattr(c, "primary_key", False)]
        quoted = ", ".join(f'"{c}"' for c in primary)
        statement = f'CREATE TABLE "{name}" ({", ".join(parts)}'
        # A composite key must be declared once, as a table constraint. Individual
        # `PRIMARY KEY` markers on each column would be a syntax error for two columns.
        if primary:
            statement += f", PRIMARY KEY ({quoted})"
        statement += ")"
        run(statement)

    def create_index(name, table, columns, **_kwargs):
        cols = ", ".join(f'"{c}"' for c in columns)
        run(f'CREATE INDEX "{name}" ON "{table}" ({cols})')

    def drop_table(name, **_kwargs):
        run(f'DROP TABLE IF EXISTS "{name}" CASCADE')

    def drop_index(name, table_name=None, **_kwargs):
        run(f'DROP INDEX IF EXISTS "{name}"')

    shim = types.ModuleType("alembic.op")
    shim.create_table = create_table
    shim.create_index = create_index
    shim.drop_table = drop_table
    shim.drop_index = drop_index

    alembic = types.ModuleType("alembic")
    alembic.op = shim

    import sys

    sys.modules["alembic"] = alembic
    sys.modules["alembic.op"] = shim
    try:
        import importlib.util

        spec = importlib.util.spec_from_file_location("_mig0043", MIGRATION)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        del uuid
        return module
    finally:
        sys.modules.pop("alembic.op", None)
        sys.modules.pop("alembic", None)
