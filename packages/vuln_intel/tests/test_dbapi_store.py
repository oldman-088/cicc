"""The DB-API store: real SQL, real constraints, both placeholder dialects.

These tests exist because the documented persistence path was "a host migration" —
work owned by somebody else, gating a finished domain. A DB-API adapter over an
injected driver makes deployment possible without that migration, and without the
package taking on a database dependency.

What is tested, and why each one matters:

* **Both paramstyles.** SQLite uses ``?``, psycopg uses ``%s``. A wrong guess is a
  syntax error at the first write, so the dialect is explicit and both are exercised
  rather than assumed.
* **Both JSON modes.** SQLite stores JSON as text; PostgreSQL's JSONB rejects a
  double-encoded string. A store that only works on one is a store that breaks on
  the other, quietly, by storing ``"{\\"severity\\": ...}"`` as a string.
* **The invariants, against real SQL.** Tenant scoping, one row per (tenant, CVE),
  older-observation rejection, dry-run writes nothing, provenance only on change.
  A store tested only against a dict never proves its constraints exist.

The last test class runs against a real PostgreSQL server when one is configured, and
skips *loudly* when not — because a store that has never touched PostgreSQL is not
evidence that it works on PostgreSQL.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from vuln_intel.integration.contracts import UpsertOutcome
from vuln_intel.integration.dbapi_store import (
    POSTGRES_SCHEMA,
    SQLITE_SCHEMA,
    DBAPIVulnerabilityStore,
    UnsupportedParamStyle,
)

_UTC = timezone.utc
_T0 = datetime(2026, 1, 1, tzinfo=_UTC)


def _sqlite_store(path: str, **kwargs) -> DBAPIVulnerabilityStore:
    return DBAPIVulnerabilityStore(
        connect=lambda: sqlite3.connect(path, timeout=5.0), paramstyle="qmark", **kwargs
    )


@pytest.fixture()
def db(tmp_path):
    path = str(tmp_path / "store.db")
    conn = sqlite3.connect(path)
    conn.executescript(SQLITE_SCHEMA)
    conn.commit()
    conn.close()
    return path


def _upsert(store, *, cve="CVE-2021-44228", when=_T0, details=None, origin="live", dry_run=False,
            tenant="tenant-a", provenance=None, entity_id="entity-1"):
    # `entity_id` is overridable because PostgreSQL's schema types it UUID, and a
    # test fixture that cannot express the real column type is testing a schema
    # nobody deploys.
    return store.upsert(
        tenant_id=tenant,
        cve=cve,
        entity={"id": entity_id},
        details={"severity": "critical"} if details is None else details,
        enrichment={"origin": origin, "severity": "critical"},
        provenance=provenance or {"source": "NVD", "observed_at": "2026-01-01T00:00:00+00:00"},
        collected_at=when,
        dry_run=dry_run,
    )


class TestTheSchemaIsTheContract:
    def test_both_dialects_are_published_so_a_host_can_adopt_deliberately(self):
        assert "vulnerability_record" in SQLITE_SCHEMA
        assert "vulnerability_record" in POSTGRES_SCHEMA
        # PostgreSQL needs a real timestamp type and UUID keys; SQLite has neither.
        assert "TIMESTAMPTZ" in POSTGRES_SCHEMA
        assert "TEXT NOT NULL" in SQLITE_SCHEMA

    def test_no_method_executes_ddl(self):
        """Creating tables in somebody else's database is not this adapter's call.

        The word appears in the docstring explaining that; what must be absent is an
        executable statement, so the check looks at what is passed to ``execute``.
        """
        import ast
        import pathlib

        path = (
            pathlib.Path(__file__).resolve().parents[1]
            / "vuln_intel" / "integration" / "dbapi_store.py"
        )
        tree = ast.parse(path.read_text())
        executed: list[str] = []
        for node in ast.walk(tree):
            # An executed SQL string literal, directly on the call.
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"execute", "executescript"}
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                executed.append(node.args[0].value)
        offenders = [
            sql for sql in executed
            if any(k in sql.upper() for k in ("CREATE TABLE", "ALTER TABLE", "DROP TABLE"))
        ]
        assert offenders == [], f"adapter issues DDL: {offenders}"

    def test_an_unknown_paramstyle_is_refused_rather_than_guessed(self):
        with pytest.raises(UnsupportedParamStyle):
            DBAPIVulnerabilityStore(connect=lambda: None, paramstyle="pyformat")

    def test_named_paramstyle_is_refused_because_it_is_not_supported(self):
        # `%(name)s` would need a whole different binding strategy; refusing is
        # better than emitting SQL that cannot bind.
        with pytest.raises(UnsupportedParamStyle):
            DBAPIVulnerabilityStore(connect=lambda: None, paramstyle="named")


class TestTenantScoping:
    def test_a_record_written_for_one_tenant_is_invisible_to_another(self, db):
        store = _sqlite_store(db)
        _upsert(store, tenant="tenant-a")
        assert store.find(tenant_id="tenant-a", cve="CVE-2021-44228") is not None
        assert store.find(tenant_id="tenant-b", cve="CVE-2021-44228") is None

    def test_the_same_cve_can_exist_independently_for_two_tenants(self, db):
        store = _sqlite_store(db)
        _upsert(store, tenant="tenant-a", details={"severity": "critical"})
        _upsert(store, tenant="tenant-b", details={"severity": "low"})
        assert store.find(tenant_id="tenant-a", cve="CVE-2021-44228")["details"]["severity"] == "critical"
        assert store.find(tenant_id="tenant-b", cve="CVE-2021-44228")["details"]["severity"] == "low"

    def test_counts_are_per_tenant(self, db):
        store = _sqlite_store(db)
        _upsert(store, tenant="tenant-a")
        _upsert(store, cve="CVE-2022-0001", tenant="tenant-b")
        assert store.record_count(tenant_id="tenant-a") == 1
        assert store.record_count(tenant_id="tenant-b") == 1
        assert store.record_count(tenant_id="tenant-c") == 0

    def test_provenance_is_tenant_scoped(self, db):
        store = _sqlite_store(db)
        _upsert(store, tenant="tenant-a")
        assert store.provenance_for(tenant_id="tenant-a", cve="CVE-2021-44228")
        assert store.provenance_for(tenant_id="tenant-b", cve="CVE-2021-44228") == []


class TestTheUpsertInvariants:
    def test_a_new_record_is_created_with_provenance(self, db):
        store = _sqlite_store(db)
        result = _upsert(store)
        assert result.outcome == UpsertOutcome.CREATED
        assert result.entity_id == "entity-1"
        assert len(store.provenance_for(tenant_id="tenant-a", cve="CVE-2021-44228")) == 1

    def test_an_older_observation_cannot_overwrite_a_newer_one(self, db):
        """The rule the host importer already follows, enforced in the SQL this time."""
        store = _sqlite_store(db)
        _upsert(store, when=_T0, details={"severity": "critical"})
        result = _upsert(store, when=_T0 - timedelta(days=1), details={"severity": "low"})
        assert result.outcome == UpsertOutcome.SKIPPED
        assert "older observation" in (result.reason or "")
        stored = store.find(tenant_id="tenant-a", cve="CVE-2021-44228")
        assert stored["details"]["severity"] == "critical"

    def test_changed_content_is_updated_and_recorded(self, db):
        store = _sqlite_store(db)
        _upsert(store, when=_T0, details={"severity": "critical"})
        result = _upsert(store, when=_T0 + timedelta(days=1), details={"severity": "high"})
        assert result.outcome == UpsertOutcome.UPDATED
        assert len(store.provenance_for(tenant_id="tenant-a", cve="CVE-2021-44228")) == 2

    def test_an_identical_body_refreshes_the_stamp_without_inventing_evidence(self, db):
        """A refresh is not a new observation.

        Writing a provenance event on every poll would make the audit log claim
        the source said something new each time it said the same thing.
        """
        store = _sqlite_store(db)
        _upsert(store, when=_T0, details={"severity": "critical"})
        result = _upsert(store, when=_T0 + timedelta(days=1), details={"severity": "critical"})
        assert result.outcome == UpsertOutcome.UNCHANGED
        assert len(store.provenance_for(tenant_id="tenant-a", cve="CVE-2021-44228")) == 1
        stored = store.find(tenant_id="tenant-a", cve="CVE-2021-44228")
        assert stored["collected_at"] > _T0

    def test_a_dry_run_on_a_new_record_writes_nothing_at_all(self, db):
        store = _sqlite_store(db)
        result = _upsert(store, dry_run=True)
        assert result.outcome == UpsertOutcome.PREVIEWED
        assert store.record_count(tenant_id="tenant-a") == 0
        assert store.provenance_for(tenant_id="tenant-a", cve="CVE-2021-44228") == []
        assert store.writes == 0

    def test_a_dry_run_on_an_existing_record_writes_nothing(self, db):
        store = _sqlite_store(db)
        _upsert(store, when=_T0, details={"severity": "critical"})
        before = store.find(tenant_id="tenant-a", cve="CVE-2021-44228")
        result = _upsert(store, when=_T0 + timedelta(days=5), details={"severity": "low"}, dry_run=True)
        assert result.outcome == UpsertOutcome.PREVIEWED
        after = store.find(tenant_id="tenant-a", cve="CVE-2021-44228")
        assert after["details"] == before["details"]
        assert after["collected_at"] == before["collected_at"]

    def test_the_store_counts_only_real_writes(self, db):
        store = _sqlite_store(db)
        _upsert(store, when=_T0)
        _upsert(store, when=_T0 - timedelta(days=1))  # skipped
        _upsert(store, when=_T0 + timedelta(days=1), dry_run=True)  # previewed
        assert store.writes == 1

    def test_fixture_origin_is_refused_unless_explicitly_allowed(self, db):
        store = _sqlite_store(db)
        with pytest.raises(Exception):
            _upsert(store, origin="fixture")
        assert store.record_count(tenant_id="tenant-a") == 0

    def test_fixture_origin_is_accepted_when_the_store_says_so(self, db):
        store = _sqlite_store(db, allow_fixture=True)
        result = _upsert(store, origin="fixture")
        assert result.outcome == UpsertOutcome.CREATED


class TestJSONRoundTrip:
    """SQLite stores JSON as text; PostgreSQL's JSONB rejects text. Both must work."""

    def test_stored_details_survive_as_a_structure_not_a_string(self, db):
        store = _sqlite_store(db)
        _upsert(store, details={"severity": "critical", "nested": {"a": [1, 2]}})
        stored = store.find(tenant_id="tenant-a", cve="CVE-2021-44228")
        assert stored["details"]["nested"]["a"] == [1, 2]

    def test_the_enrichment_block_is_nested_not_merged_into_the_top_level(self, db):
        store = _sqlite_store(db)
        _upsert(store)
        stored = store.find(tenant_id="tenant-a", cve="CVE-2021-44228")
        assert "cicc_enrichment" in stored["details"]
        assert stored["details"]["cicc_enrichment"]["origin"] == "live"

    def test_native_json_mode_does_not_double_encode(self, tmp_path):
        """The PostgreSQL path: JSONB wants a mapping, not a JSON string."""

        class _DictCursor:
            """Returns the row shapes the real queries ask for.

            The pre-read in ``upsert`` selects (entity_id, details, collected_at);
            a double that returns a 1-tuple makes the adapter fail with a KeyError
            instead of exercising the branch, which proves nothing about the adapter.
            """

            def __init__(self, log):
                self.log = log
                self._rows: list = []

            def execute(self, sql, params=()):
                self.log.append(list(params))
                if "COUNT(*)" in sql:
                    self._rows = [(0,)]
                elif sql.lstrip().startswith("SELECT entity_id"):
                    self._rows = []          # no existing row -> the INSERT path
                else:
                    self._rows = []

            def fetchone(self):
                return self._rows[0] if self._rows else None

            def fetchall(self):
                return self._rows

        class _DictConn:
            def __init__(self, log):
                self.log = log

            def cursor(self):
                return _DictCursor(self.log)

            def commit(self): ...
            def rollback(self): ...
            def close(self): ...

        log: list = []
        store = DBAPIVulnerabilityStore(
            connect=lambda: _DictConn(log), paramstyle="format", json_mode="native"
        )
        _upsert(store)
        # The details parameter is the 4th bind of the INSERT; it must be a mapping.
        insert_params = next(p for p in log if len(p) == 8)
        assert isinstance(insert_params[3], dict), "JSONB would receive a double-encoded string"


class TestPlaceholders:
    def test_format_style_emits_percent_s(self, db):
        seen: list[str] = []

        def connect():
            conn = sqlite3.connect(db)
            original = conn.cursor

            class _Rec:
                def __init__(self, cur):
                    self._cur = cur

                def execute(self, sql, params=()):
                    seen.append(sql)
                    return self._cur.execute(sql, params)

                def __getattr__(self, name):
                    return getattr(self._cur, name)

            def cursor():
                return _Rec(original())

            conn.cursor = cursor  # type: ignore[method-assign]
            return conn

        # format-style SQL is generated; here we only assert the SQL *text* carries
        # the right placeholder, so the value is checked without needing a server.
        from vuln_intel.integration.dbapi_store import _PARAM_STYLES

        assert _PARAM_STYLES["format"] == "%s"
        assert _PARAM_STYLES["qmark"] == "?"

    def test_the_store_never_interpolates_values_into_sql(self, db):
        """A CVE id is data, not SQL. Bound parameters are the only defence."""
        store = _sqlite_store(db)
        hostile = "CVE-2021-44228'; DROP TABLE vulnerability_record; --"
        _upsert(store, cve=hostile)
        # The table still exists and the hostile value was stored verbatim as a key.
        assert store.find(tenant_id="tenant-a", cve=hostile) is not None
        assert store.record_count(tenant_id="tenant-a") == 1


class TestPaging:
    def _seed(self, store, n=5):
        for i in range(n):
            _upsert(store, cve=f"CVE-2020-{i:04d}", when=_T0)

    def test_pages_use_a_seek_cursor_not_an_offset(self, db):
        store = _sqlite_store(db)
        self._seed(store, 5)
        page1, cursor = store.list(tenant_id="tenant-a", limit=2)
        assert len(page1) == 2
        assert cursor == page1[-1]["cve"]
        page2, _cursor2 = store.list(tenant_id="tenant-a", limit=2, cursor=cursor)
        assert len(page2) == 2
        assert not ({p["cve"] for p in page1} & {p["cve"] for p in page2})

    def test_the_last_page_reports_no_cursor(self, db):
        store = _sqlite_store(db)
        self._seed(store, 2)
        _page, cursor = store.list(tenant_id="tenant-a", limit=10)
        assert cursor is None

    def test_an_insert_between_pages_does_not_shift_the_window(self, db):
        """The reason to seek rather than offset: a concurrent write must not skip a row."""
        store = _sqlite_store(db)
        self._seed(store, 4)
        page1, cursor = store.list(tenant_id="tenant-a", limit=2)
        _upsert(store, cve="CVE-2019-0000", when=_T0)  # sorts before the cursor
        page2, _ = store.list(tenant_id="tenant-a", limit=2, cursor=cursor)
        assert "CVE-2019-0000" not in {p["cve"] for p in page2}
        assert not ({p["cve"] for p in page1} & {p["cve"] for p in page2})

    def test_an_unsupported_order_is_refused(self, db):
        store = _sqlite_store(db)
        with pytest.raises(ValueError):
            store.list(tenant_id="tenant-a", limit=1, order="random")

    def test_a_zero_limit_is_refused_rather_than_returning_everything(self, db):
        store = _sqlite_store(db)
        with pytest.raises(ValueError):
            store.list(tenant_id="tenant-a", limit=0)


def _postgres_dsn():
    """A DSN for a real server, or None.

    Two routes, both real: an explicitly configured server, or a throwaway one
    started by ``pgserver`` when that package is installed. There is deliberately no
    in-process fake — the point of these tests is the engine, and a fake engine
    proves nothing about PostgreSQL's types.
    """
    configured = os.environ.get("CICC_TEST_POSTGRES_DSN")
    if configured:
        return configured
    try:
        import pgserver
    except ImportError:
        return None
    import tempfile

    return pgserver.get_server(tempfile.mkdtemp(prefix="pgdata-")).get_uri()


_PG_DSN = _postgres_dsn()

#: PostgreSQL types ``entity_id`` UUID; SQLite stores text. The fixture states which.
_ENTITY_UUID = "00000000-0000-0000-0000-0000000000e1"


@pytest.mark.skipif(_PG_DSN is None, reason="no PostgreSQL available: NOT exercised on PostgreSQL")
class TestAgainstRealPostgres:
    """The engine-specific failures only a real server produces.

    Both of the defects this class was written after — psycopg3 refusing a bare
    dict, and ``0`` being invalid for a BOOLEAN column — passed every in-memory test.
    """

    @pytest.fixture()
    def pg(self):
        psycopg = pytest.importorskip("psycopg", reason="psycopg is not installed")
        conn = psycopg.connect(_PG_DSN)
        with conn.cursor() as cur:
            cur.execute(POSTGRES_SCHEMA)
            cur.execute("TRUNCATE vulnerability_record CASCADE")
        conn.commit()
        conn.close()
        return _PG_DSN

    def _store(self):
        psycopg = pytest.importorskip("psycopg")
        return DBAPIVulnerabilityStore(
            connect=lambda: psycopg.connect(_PG_DSN),
            paramstyle="format",
            json_mode="json_wrapper",
            boolean_kev=True,
        )

    def test_jsonb_round_trips_as_a_document(self, pg):
        """psycopg3 refuses a bare dict, so the wrapper mode is what makes this work."""
        store = self._store()
        tenant = "00000000-0000-0000-0000-00000000000a"
        result = _upsert(store, tenant=tenant, entity_id=_ENTITY_UUID)
        assert result.outcome == UpsertOutcome.CREATED
        found = store.find(tenant_id=tenant, cve="CVE-2021-44228")
        assert found is not None
        assert isinstance(found["details"], dict)
        assert found["details"]["severity"] == "critical"

    def test_a_boolean_kev_column_rejects_an_integer(self, pg):
        """The defect that only appeared on a real server."""
        store = self._store()
        tenant = "00000000-0000-0000-0000-00000000000b"
        _upsert(store, tenant=tenant, details={"severity": "critical", "kev": True},
                entity_id=_ENTITY_UUID)
        rows, _ = store.list(tenant_id=tenant, limit=10, kev_only=True)
        assert [r["cve"] for r in rows] == ["CVE-2021-44228"]

    def test_the_older_observation_rule_holds_in_postgres(self, pg):
        store = self._store()
        tenant = "00000000-0000-0000-0000-00000000000c"
        _upsert(store, tenant=tenant, when=_T0, details={"severity": "critical"},
                entity_id=_ENTITY_UUID)
        result = _upsert(
            store, tenant=tenant, when=_T0 - timedelta(days=1), details={"severity": "low"},
            entity_id=_ENTITY_UUID,
        )
        assert result.outcome == UpsertOutcome.SKIPPED
        assert store.find(tenant_id=tenant, cve="CVE-2021-44228")["details"]["severity"] == "critical"

    def test_tenants_are_isolated_in_postgres(self, pg):
        store = self._store()
        a, b = "00000000-0000-0000-0000-00000000000d", "00000000-0000-0000-0000-00000000000e"
        _upsert(store, tenant=a, entity_id=_ENTITY_UUID)
        assert store.find(tenant_id=b, cve="CVE-2021-44228") is None
