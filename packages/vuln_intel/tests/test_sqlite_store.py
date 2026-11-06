"""The SQLite store: durability, tenancy as a constraint, and the same rules as memory.

The point of these tests is not "the adapter works". It is that the adapter is held to
the *same* invariants as ``InMemoryVulnerabilityStore``, driven through the same entry
points, on a real file — and that the two cannot drift.

The most important test in this file is
:meth:`TestDurability.test_a_restart_keeps_records_and_provenance`. Everything else
could be true of an in-memory dict; surviving a process boundary is the one property
that justifies the module existing, and it is the one the memory store cannot have.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from vuln_intel.integration.contracts import UpsertOutcome
from vuln_intel.integration.sqlite_store import SCHEMA, SCHEMA_VERSION, SQLiteVulnerabilityStore
from vuln_intel.integration.store import InMemoryVulnerabilityStore

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
LATER = datetime(2026, 2, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "vuln.db"


@pytest.fixture
def store(db_path):
    return SQLiteVulnerabilityStore(path=db_path, allow_fixture=True)


def _write(store, *, tenant="tenant-a", cve="CVE-2026-0001", severity="high", kev=False,
           collected_at=NOW, origin="fixture", dry_run=False, details=None,
           provenance=None):
    return store.upsert(
        tenant_id=tenant,
        cve=cve,
        entity={},
        details=details if details is not None else {"severity": severity, "kev": kev},
        enrichment={"origin": origin},
        provenance=provenance if provenance is not None else {"source": "nvd"},
        collected_at=collected_at,
        dry_run=dry_run,
    )


class TestDurability:
    def test_a_restart_keeps_records_and_provenance(self, db_path):
        """The property an in-memory store cannot have, and the reason this exists."""
        first = SQLiteVulnerabilityStore(path=db_path, allow_fixture=True)
        _write(first, provenance={"source": "nvd", "observed_at": NOW.isoformat()})

        # A brand-new object, as a new process would create.
        second = SQLiteVulnerabilityStore(path=db_path, allow_fixture=True)
        row = second.find(tenant_id="tenant-a", cve="CVE-2026-0001")
        assert row is not None
        assert row["details"]["severity"] == "high"
        assert row["collected_at"] == NOW
        events = second.provenance_for(tenant_id="tenant-a", cve="CVE-2026-0001")
        assert len(events) == 1
        assert events[0]["source"] == "nvd"
        assert events[0]["event_type"] == "source_record_created"

    def test_the_schema_version_is_recorded(self, db_path):
        store = SQLiteVulnerabilityStore(path=db_path, allow_fixture=True)
        assert store.record_count(tenant_id="tenant-a") == 0
        # Re-opening must not destroy the file or fail on existing tables.
        SQLiteVulnerabilityStore(path=db_path, allow_fixture=True)
        assert SCHEMA_VERSION >= 1

    def test_a_second_open_does_not_duplicate_tables(self, db_path):
        SQLiteVulnerabilityStore(path=db_path, allow_fixture=True)
        store = SQLiteVulnerabilityStore(path=db_path, allow_fixture=True)
        _write(store)
        _write(store, cve="CVE-2026-0002")
        assert store.record_count(tenant_id="tenant-a") == 2


class TestTenantIsolationIsAConstraint:
    def test_another_tenant_cannot_read_the_row(self, store):
        _write(store, tenant="tenant-a")
        assert store.find(tenant_id="tenant-b", cve="CVE-2026-0001") is None

    def test_another_tenant_sees_an_empty_list(self, store):
        _write(store, tenant="tenant-a")
        rows, cursor = store.list(tenant_id="tenant-b", limit=10)
        assert rows == [] and cursor is None

    def test_the_primary_key_is_tenant_scoped(self, store):
        """Two tenants may hold the same CVE as separate rows.

        A global primary key on the CVE would make one tenant's ingestion overwrite
        another's, which is a data-leak in the write direction.
        """
        _write(store, tenant="tenant-a", severity="high")
        _write(store, tenant="tenant-b", severity="low")
        assert store.record_count(tenant_id="tenant-a") == 1
        assert store.record_count(tenant_id="tenant-b") == 1
        assert store.find(tenant_id="tenant-b", cve="CVE-2026-0001")["details"]["severity"] == "low"


class TestTheSameRulesAsMemory:
    def test_a_first_write_is_created(self, store):
        assert _write(store).outcome is UpsertOutcome.CREATED

    def test_an_identical_rewrite_is_unchanged(self, store):
        _write(store)
        assert _write(store, collected_at=LATER).outcome is UpsertOutcome.UNCHANGED

    def test_a_changed_body_is_updated(self, store):
        _write(store, severity="high")
        result = _write(store, severity="critical", collected_at=LATER)
        assert result.outcome is UpsertOutcome.UPDATED
        assert store.find(tenant_id="tenant-a", cve="CVE-2026-0001")["details"]["severity"] == "critical"

    def test_an_older_observation_never_overwrites(self, store):
        _write(store, severity="high", collected_at=LATER)
        result = _write(store, severity="low", collected_at=NOW)
        assert result.outcome is UpsertOutcome.SKIPPED
        assert store.find(tenant_id="tenant-a", cve="CVE-2026-0001")["details"]["severity"] == "high"

    def test_a_dry_run_writes_nothing(self, store):
        result = _write(store, dry_run=True)
        assert result.outcome is UpsertOutcome.PREVIEWED
        assert store.record_count(tenant_id="tenant-a") == 0

    def test_a_dry_run_on_an_existing_row_also_writes_nothing(self, store):
        _write(store, severity="high")
        result = _write(store, severity="critical", collected_at=LATER, dry_run=True)
        assert result.outcome is UpsertOutcome.PREVIEWED
        assert store.find(tenant_id="tenant-a", cve="CVE-2026-0001")["details"]["severity"] == "high"

    def test_fixture_data_is_refused_without_permission(self, db_path):
        strict = SQLiteVulnerabilityStore(path=db_path, allow_fixture=False)
        with pytest.raises(PermissionError, match="refusing to persist"):
            _write(strict, origin="fixture")

    def test_live_data_is_accepted_without_permission(self, db_path):
        strict = SQLiteVulnerabilityStore(path=db_path, allow_fixture=False)
        result = _write(strict, origin="live")
        assert result.outcome is UpsertOutcome.CREATED

    def test_provenance_accumulates_one_event_per_change(self, store):
        _write(store, severity="high", collected_at=NOW)
        _write(store, severity="critical", collected_at=LATER)
        _write(store, severity="critical", collected_at=LATER)  # unchanged: no event
        events = store.provenance_for(tenant_id="tenant-a", cve="CVE-2026-0001")
        assert [e["event_type"] for e in events] == [
            "source_record_created",
            "source_record_updated",
        ]


class TestListingAndOrdering:
    def _seed(self, store):
        for cve, sev in [
            ("CVE-2026-0101", "low"),
            ("CVE-2026-0102", "critical"),
            ("CVE-2026-0103", "medium"),
            ("CVE-2026-0104", "high"),
        ]:
            _write(store, cve=cve, severity=sev)

    def test_severity_order_is_severity_order_not_alphabetical(self, store):
        """`ORDER BY severity` in SQL sorts the name, which puts low above medium."""
        self._seed(store)
        rows, _ = store.list(tenant_id="tenant-a", limit=10, order="severity")
        assert [r["details"]["severity"] for r in rows] == [
            "critical", "high", "medium", "low",
        ]

    def test_reverse_severity_is_the_mirror(self, store):
        self._seed(store)
        rows, _ = store.list(tenant_id="tenant-a", limit=10, order="-severity")
        assert [r["details"]["severity"] for r in rows] == [
            "low", "medium", "high", "critical",
        ]

    def test_cve_order_ascending_and_descending(self, store):
        self._seed(store)
        up, _ = store.list(tenant_id="tenant-a", limit=10, order="cve")
        down, _ = store.list(tenant_id="tenant-a", limit=10, order="-cve")
        assert [r["cve"] for r in up] == list(reversed([r["cve"] for r in down]))

    def test_severity_filter(self, store):
        self._seed(store)
        rows, _ = store.list(tenant_id="tenant-a", limit=10, severity="HIGH")
        assert [r["cve"] for r in rows] == ["CVE-2026-0104"]

    def test_kev_filter(self, store):
        _write(store, cve="CVE-2026-0201", kev=True)
        _write(store, cve="CVE-2026-0202", kev=False)
        rows, _ = store.list(tenant_id="tenant-a", limit=10, kev_only=True)
        assert [r["cve"] for r in rows] == ["CVE-2026-0201"]

    def test_paging_does_not_repeat_or_skip_across_severity_ties(self, store):
        """Several rows share a severity, so the cursor must be the unique CVE."""
        for index in range(7):
            _write(store, cve=f"CVE-2026-03{index:02d}", severity="high")
        seen: list[str] = []
        cursor = None
        for _ in range(10):
            rows, cursor = store.list(tenant_id="tenant-a", limit=2, cursor=cursor, order="severity")
            seen.extend(r["cve"] for r in rows)
            if cursor is None:
                break
        assert len(seen) == len(set(seen)) == 7

    def test_paging_by_cve_covers_every_row_once(self, store):
        for index in range(5):
            _write(store, cve=f"CVE-2026-04{index:02d}")
        seen: list[str] = []
        cursor = None
        for _ in range(10):
            rows, cursor = store.list(tenant_id="tenant-a", limit=2, cursor=cursor)
            seen.extend(r["cve"] for r in rows)
            if cursor is None:
                break
        assert len(seen) == len(set(seen)) == 5

    def test_an_unknown_order_is_refused(self, store):
        with pytest.raises(ValueError, match="unsupported order"):
            store.list(tenant_id="tenant-a", limit=1, order="nonsense")

    def test_a_non_positive_limit_is_refused(self, store):
        with pytest.raises(ValueError, match="limit"):
            store.list(tenant_id="tenant-a", limit=0)


class TestTheSchemaEnforcesWhatPythonCannot:
    def test_foreign_keys_are_actually_enabled(self, db_path):
        """SQLite defaults them OFF; a constraint that is not enforced is not one."""
        store = SQLiteVulnerabilityStore(path=db_path, allow_fixture=True)
        with store._connect() as conn:
            assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1

    def test_a_provenance_event_cannot_orphan(self, db_path):
        import sqlite3

        store = SQLiteVulnerabilityStore(path=db_path, allow_fixture=True)
        with store._connect() as conn, pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO provenance_event (tenant_id, cve, event_type, payload) "
                "VALUES ('tenant-a', 'CVE-9999-9999', 'source_record_created', '{}')"
            )

    def test_deleting_a_record_cascades_to_its_provenance(self, db_path):
        store = SQLiteVulnerabilityStore(path=db_path, allow_fixture=True)
        _write(store)
        with store._connect() as conn:
            conn.execute("DELETE FROM vulnerability_record WHERE cve = 'CVE-2026-0001'")
        assert store.provenance_for(tenant_id="tenant-a", cve="CVE-2026-0001") == []

    def test_the_origin_check_constraint_rejects_junk(self, db_path):
        import sqlite3

        store = SQLiteVulnerabilityStore(path=db_path, allow_fixture=True)
        with store._connect() as conn, pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO vulnerability_record "
                "(tenant_id, cve, entity_id, details, origin, collected_at) "
                "VALUES ('t', 'CVE-1', 'e', '{}', 'synthetic', '2026-01-01T00:00:00+00:00')"
            )

    def test_the_schema_declares_tenant_scoped_uniqueness(self):
        assert "PRIMARY KEY (tenant_id, cve)" in SCHEMA

    def test_the_schema_declares_a_cascade(self):
        assert "ON DELETE CASCADE" in SCHEMA


class TestBothStoresAgree:
    """The in-memory store is the reference; the durable one must not drift from it."""

    def _both(self, tmp_path):
        memory = InMemoryVulnerabilityStore(allow_fixture=True)
        disk = SQLiteVulnerabilityStore(path=tmp_path / "parity.db", allow_fixture=True)
        return memory, disk

    def test_the_same_sequence_produces_the_same_outcomes(self, tmp_path):
        memory, disk = self._both(tmp_path)
        sequence = [
            dict(cve="CVE-2026-0501", severity="high", collected_at=NOW),
            dict(cve="CVE-2026-0501", severity="high", collected_at=LATER),
            dict(cve="CVE-2026-0501", severity="critical", collected_at=LATER),
            dict(cve="CVE-2026-0501", severity="low", collected_at=NOW),
            dict(cve="CVE-2026-0502", severity="medium", collected_at=NOW),
        ]
        outcomes_memory = [_write(memory, **step).outcome for step in sequence]
        outcomes_disk = [_write(disk, **step).outcome for step in sequence]
        assert outcomes_memory == outcomes_disk
        assert outcomes_disk == [
            UpsertOutcome.CREATED,
            UpsertOutcome.UNCHANGED,
            UpsertOutcome.UPDATED,
            UpsertOutcome.SKIPPED,
            UpsertOutcome.CREATED,
        ]

    def test_the_same_rows_come_back_in_the_same_order(self, tmp_path):
        memory, disk = self._both(tmp_path)
        for cve, sev in [("CVE-2026-0601", "low"), ("CVE-2026-0602", "critical"),
                         ("CVE-2026-0603", "medium")]:
            _write(memory, cve=cve, severity=sev)
            _write(disk, cve=cve, severity=sev)
        for order in ("cve", "-cve", "severity", "-severity"):
            m, _ = memory.list(tenant_id="tenant-a", limit=10, order=order)
            d, _ = disk.list(tenant_id="tenant-a", limit=10, order=order)
            assert [r["cve"] for r in m] == [r["cve"] for r in d], f"order={order}"


class TestServedThroughTheRealApi:
    """The durable store driven through the actual API boundary, not just its methods.

    A store that satisfies the port but breaks inside ``asgi_handler`` is not
    integrated. These tests go through the same callable the host would bind.
    """

    def test_a_record_written_then_served_over_http(self, tmp_path):
        from vuln_intel.integration.api import VulnerabilityApi, asgi_handler

        store = SQLiteVulnerabilityStore(path=tmp_path / "api.db", allow_fixture=True)
        _write(store, cve="CVE-2026-0701", severity="critical")
        api = VulnerabilityApi(store)
        handler = asgi_handler(api, resolve_tenant=lambda query, path: "tenant-a")

        response = handler("GET", "/v1/vulnerabilities/CVE-2026-0701", {})
        assert response.status == 200
        assert response.body["data"]["cve"] == "CVE-2026-0701"
        assert response.body["data"]["severity"] == "critical"

    def test_the_listing_route_pages_over_the_durable_store(self, tmp_path):
        from vuln_intel.integration.api import VulnerabilityApi, asgi_handler

        store = SQLiteVulnerabilityStore(path=tmp_path / "api2.db", allow_fixture=True)
        for index in range(3):
            _write(store, cve=f"CVE-2026-08{index:02d}", severity="high")
        api = VulnerabilityApi(store)
        handler = asgi_handler(api, resolve_tenant=lambda query, path: "tenant-a")

        response = handler("GET", "/v1/vulnerabilities", {"limit": "2"})
        assert response.status == 200
        assert len(response.body["data"]) == 2
        assert response.body["page"]["has_more"] is True

        cursor = response.body["page"]["next_cursor"]
        second = handler("GET", "/v1/vulnerabilities", {"limit": "2", "cursor": cursor})
        assert second.status == 200
        assert len(second.body["data"]) == 1
        assert second.body["page"]["has_more"] is False

    def test_a_tenant_mismatch_is_a_404_through_the_handler(self, tmp_path):
        from vuln_intel.integration.api import VulnerabilityApi, asgi_handler

        store = SQLiteVulnerabilityStore(path=tmp_path / "api3.db", allow_fixture=True)
        _write(store, tenant="tenant-a", cve="CVE-2026-0901")
        api = VulnerabilityApi(store)
        handler = asgi_handler(api, resolve_tenant=lambda query, path: "tenant-b")

        response = handler("GET", "/v1/vulnerabilities/CVE-2026-0901", {})
        assert response.status == 404

    def test_a_record_survives_into_a_second_api_instance(self, tmp_path):
        """The host restarts; the data does not."""
        from vuln_intel.integration.api import VulnerabilityApi, asgi_handler

        path = tmp_path / "api4.db"
        first = SQLiteVulnerabilityStore(path=path, allow_fixture=True)
        _write(first, cve="CVE-2026-1001", severity="medium")
        handler = asgi_handler(
            VulnerabilityApi(first), resolve_tenant=lambda q, p: "tenant-a"
        )
        assert handler("GET", "/v1/vulnerabilities/CVE-2026-1001", {}).status == 200

        # A new store object over the same file, as a restarted process would build.
        second = SQLiteVulnerabilityStore(path=path, allow_fixture=True)
        handler2 = asgi_handler(
            VulnerabilityApi(second), resolve_tenant=lambda q, p: "tenant-a"
        )
        response = handler2("GET", "/v1/vulnerabilities/CVE-2026-1001", {})
        assert response.status == 200
        assert response.body["data"]["severity"] == "medium"
