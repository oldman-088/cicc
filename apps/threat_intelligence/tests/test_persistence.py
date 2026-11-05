"""
Unit tests for the Threat Intelligence persistence layer.

Covers:
- Append-only enforcement (SQL triggers actually reject UPDATE/DELETE)
- Tenant isolation
- Provenance preservation and observation history
- Cursor pagination
- Parameterized SQL / identifier safety
- Explicit failure for unsupported URL schemes
"""

import os
import sqlite3
import tempfile

import pytest
from pydantic import ValidationError

from apps.threat_intelligence.persistence import (
    APPEND_ONLY_TABLES,
    EXPERIMENTAL_DEMO_DATA_ONLY,
    AppendOnlyViolationError,
    AuditRecord,
    ConflictRecord,
    EntityPage,
    PersistenceError,
    SQLiteThreatIntelRepository,
    StoredEntityRecord,
    StoredObservation,
    TenantIsolationError,
    repository_from_url,
    utcnow_iso,
)


@pytest.fixture
def repo():
    r = SQLiteThreatIntelRepository(":memory:")
    yield r
    r.close()


def _entity(tenant="t1", entity_id="IOC-1", **kwargs):
    now = utcnow_iso()
    base = dict(
        tenant_id=tenant,
        entity_type="indicator",
        entity_id=entity_id,
        display_name="192.0.2.10",
        payload={"provenance": "fixture_pipeline"},
        sources=["source-a"],
        corroboration_count=1,
        confidence=0.8,
        first_seen_at=now,
        last_seen_at=now,
        updated_at=now,
    )
    base.update(kwargs)
    return StoredEntityRecord(**base)


def _observation(tenant="t1", entity_id="IOC-1", source="source-a", **kwargs):
    now = utcnow_iso()
    base = dict(
        tenant_id=tenant,
        entity_type="indicator",
        entity_id=entity_id,
        source_id=source,
        observed_value="192.0.2.10",
        confidence=0.8,
        verification_mode="fixture_tested",
        provenance="fixture_pipeline",
        observed_at=now,
        recorded_at=now,
    )
    base.update(kwargs)
    return StoredObservation(**base)


class TestAppendOnlyEnforcement:
    """History tables must physically reject mutation."""

    def test_observations_reject_delete_and_update(self, repo):
        repo.append_observation(_observation())
        with pytest.raises(sqlite3.IntegrityError):
            repo._conn.execute("DELETE FROM ti_observations WHERE tenant_id = 't1'")
        with pytest.raises(sqlite3.IntegrityError):
            repo._conn.execute("UPDATE ti_observations SET observed_value = 'x' WHERE tenant_id = 't1'")
        assert len(repo.list_observations("t1", "indicator", "IOC-1")) == 1

    def test_history_rejects_delete_and_update(self, repo):
        repo.upsert_entity(_entity(), actor="tester")
        with pytest.raises(sqlite3.IntegrityError):
            repo._conn.execute("DELETE FROM ti_entity_history WHERE tenant_id = 't1'")
        with pytest.raises(sqlite3.IntegrityError):
            repo._conn.execute("UPDATE ti_entity_history SET change_type = 'x' WHERE tenant_id = 't1'")

    def test_conflicts_reject_delete_and_update(self, repo):
        repo.append_conflict(ConflictRecord(
            tenant_id="t1", entity_type="indicator", entity_id="IOC-1",
            field_name="confidence", kept_value="0.9", discarded_values=[0.4],
            resolution_policy="highest_confidence_wins", source="source-a",
            detected_at=utcnow_iso(),
        ))
        with pytest.raises(sqlite3.IntegrityError):
            repo._conn.execute("DELETE FROM ti_conflicts WHERE tenant_id = 't1'")

    def test_audit_log_rejects_delete_and_update(self, repo):
        repo.audit(AuditRecord(
            tenant_id="t1", action="test_action", actor="tester", logged_at=utcnow_iso()
        ))
        with pytest.raises(sqlite3.IntegrityError):
            repo._conn.execute("DELETE FROM ti_audit_log WHERE tenant_id = 't1'")
        with pytest.raises(sqlite3.IntegrityError):
            repo._conn.execute("UPDATE ti_audit_log SET action = 'x' WHERE tenant_id = 't1'")

    def test_self_check_covers_every_append_only_table(self, repo):
        """Construction-time self-check must cover the declared append-only set."""
        for table in APPEND_ONLY_TABLES:
            triggers = repo._conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ?",
                (table,),
            ).fetchall()
            names = {t["name"] for t in triggers}
            assert f"{table}_no_update" in names
            assert f"{table}_no_delete" in names

    def test_observation_ids_start_at_one_after_self_check(self, repo):
        """The construction self-check must not leave a gap in the id sequence."""
        obs = repo.append_observation(_observation())
        assert obs.observation_id == 1

    def test_self_check_fails_loudly_if_triggers_missing(self):
        """If a SQLite build silently ignored the triggers, construction must raise."""

        class NoTriggers(SQLiteThreatIntelRepository):
            def _verify_append_only_enforcement(self):  # pragma: no cover - exercised below
                return None

        r = NoTriggers(":memory:", verify_append_only=False)
        r._conn.executescript("DROP TRIGGER IF EXISTS ti_observations_no_delete;")
        r._conn.executescript("DROP TRIGGER IF EXISTS ti_observations_no_update;")
        r._conn.execute(
            "INSERT INTO ti_observations (tenant_id, entity_type, entity_id, source_id,"
            " observed_value, confidence, verification_mode, provenance, observed_at, recorded_at)"
            " VALUES ('t','indicator','i','s','v',0.5,'fixture_tested','p',?,?)",
            (utcnow_iso(), utcnow_iso()),
        )
        with pytest.raises(AppendOnlyViolationError):
            SQLiteThreatIntelRepository._verify_append_only_enforcement(r)
        r.close()


class TestTenantIsolation:
    """No query path may cross tenant boundaries."""

    def test_reads_are_scoped_to_tenant(self, repo):
        repo.upsert_entity(_entity(tenant="t1", entity_id="IOC-1"))
        repo.upsert_entity(_entity(tenant="t2", entity_id="IOC-1"))
        assert repo.get_entity("t1", "indicator", "IOC-1").tenant_id == "t1"
        assert repo.get_entity("t3", "indicator", "IOC-1") is None
        assert repo.list_entities("t1").total_count == 1
        assert repo.list_entities("t2").total_count == 1
        assert repo.list_entities("t3").total_count == 0

    def test_empty_tenant_id_is_rejected(self, repo):
        with pytest.raises(TenantIsolationError):
            repo.get_entity("", "indicator", "IOC-1")
        with pytest.raises(TenantIsolationError):
            repo.list_entities(None)

    def test_observations_and_audit_are_tenant_scoped(self, repo):
        repo.append_observation(_observation(tenant="t1"))
        repo.append_observation(_observation(tenant="t2"))
        assert len(repo.list_observations("t1", "indicator", "IOC-1")) == 1
        assert len(repo.list_observations("t2", "indicator", "IOC-1")) == 1

        # append_observation writes one automatic audit entry per tenant.
        t1_before = len(repo.list_audit("t1"))
        t2_before = len(repo.list_audit("t2"))
        assert t1_before == 1 and t2_before == 1

        repo.audit(AuditRecord(
            tenant_id="t1", action="tenant_scoped_probe", actor="x", logged_at=utcnow_iso()
        ))
        t1_after = repo.list_audit("t1")
        t2_after = repo.list_audit("t2")
        assert len(t1_after) == t1_before + 1
        assert len(t2_after) == t2_before, "an audit write for t1 leaked into t2"
        assert "tenant_scoped_probe" in {a.action for a in t1_after}
        assert "tenant_scoped_probe" not in {a.action for a in t2_after}
        # A tenant that never wrote anything sees nothing.
        assert repo.list_audit("t3") == []


class TestProvenanceAndHistory:
    """Provenance must survive writes; history must accumulate."""

    def test_entity_upsert_records_created_then_updated(self, repo):
        repo.upsert_entity(_entity(), actor="tester")
        repo.upsert_entity(_entity(confidence=0.9, corroboration_count=2, sources=["source-a", "source-b"]),
                           actor="tester")
        history = repo.list_history("t1", "indicator", "IOC-1")
        assert [h.change_type for h in history] == ["created", "updated"]
        assert history[0].previous is None
        assert history[1].previous is not None
        assert history[1].previous["confidence"] == 0.8
        assert history[1].new["confidence"] == 0.9

    def test_verification_promotion_is_a_distinct_change_type(self, repo):
        repo.upsert_entity(_entity(), actor="tester")
        repo.upsert_entity(_entity(verification_mode="live_verified"), actor="tester")
        history = repo.list_history("t1", "indicator", "IOC-1")
        assert history[-1].change_type == "verification_promoted"

    def test_first_seen_at_is_never_overwritten(self, repo):
        first = _entity()
        repo.upsert_entity(first, actor="tester")
        stored = repo.get_entity("t1", "indicator", "IOC-1")
        later = _entity()
        repo.upsert_entity(later.model_copy(update={"first_seen_at": "1999-01-01T00:00:00.000Z"}),
                           actor="tester")
        assert repo.get_entity("t1", "indicator", "IOC-1").first_seen_at == stored.first_seen_at

    def test_observation_history_is_ordered_and_complete(self, repo):
        for src in ("source-a", "source-b", "source-a"):
            repo.append_observation(_observation(source=src))
        obs = repo.list_observations("t1", "indicator", "IOC-1")
        assert [o.source_id for o in obs] == ["source-a", "source-b", "source-a"]
        assert all(o.observation_id is not None for o in obs)
        # Agent 3 M5 invariant: observations >= distinct sources
        assert len(obs) >= len({o.source_id for o in obs})

    def test_conflict_records_preserve_kept_and_discarded_values(self, repo):
        c = repo.append_conflict(ConflictRecord(
            tenant_id="t1", entity_type="indicator", entity_id="IOC-1",
            field_name="confidence", kept_value="0.95", discarded_values=[0.45, 0.30],
            resolution_policy="highest_confidence_wins", source="source-low",
            detected_at=utcnow_iso(),
        ))
        assert c.conflict_id is not None
        stored = repo.list_conflicts("t1", "indicator", "IOC-1")
        assert len(stored) == 1
        assert stored[0].kept_value == "0.95"
        assert stored[0].discarded_values == [0.45, 0.30]
        # Conflict also lands in entity history
        assert any(h.change_type == "conflict_recorded"
                   for h in repo.list_history("t1", "indicator", "IOC-1"))

    def test_experimental_label_is_enforced(self, repo):
        with pytest.raises(ValidationError):
            _entity(experimental_label="SOMETHING_ELSE")

    def test_unknown_entity_type_and_verification_mode_rejected(self):
        now = utcnow_iso()
        with pytest.raises(ValidationError):
            _entity(entity_type="not_a_type")
        with pytest.raises(ValidationError):
            _observation(verification_mode="guessed")

    def test_records_default_to_experimental_label(self, repo):
        stored = repo.upsert_entity(_entity(), actor="tester")
        assert stored.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY


class TestCursorPagination:
    def test_pagination_walks_all_entities_exactly_once(self, repo):
        for i in range(25):
            repo.upsert_entity(_entity(entity_id=f"IOC-{i:03d}"), actor="tester")
        seen, cursor = [], None
        while True:
            page = repo.list_entities("t1", limit=10, cursor=cursor)
            assert isinstance(page, EntityPage)
            seen.extend(e.entity_id for e in page.items)
            if page.next_cursor is None:
                break
            cursor = page.next_cursor
        assert len(seen) == 25
        assert len(set(seen)) == 25

    def test_malformed_cursor_is_rejected(self, repo):
        with pytest.raises(PersistenceError):
            repo.list_entities("t1", cursor="offXYZ")
        with pytest.raises(PersistenceError):
            repo.list_entities("t1", cursor="garbage")
        with pytest.raises(PersistenceError):
            repo.list_entities("t1", cursor="off-5")

    def test_limit_bounds_are_enforced(self, repo):
        with pytest.raises(PersistenceError):
            repo.list_entities("t1", limit=0)
        with pytest.raises(PersistenceError):
            repo.list_entities("t1", limit=5000)

    def test_entity_type_filter(self, repo):
        repo.upsert_entity(_entity(entity_id="IOC-1"))
        repo.upsert_entity(_entity(entity_type="campaign", entity_id="CAMP-1"))
        page = repo.list_entities("t1", entity_type="campaign")
        assert page.total_count == 1
        assert page.items[0].entity_id == "CAMP-1"


class TestSqlSafety:
    """No caller string may reach SQL as an identifier or literal fragment."""

    def test_quote_and_comment_injection_in_values_is_inert(self, repo):
        evil = _entity(entity_id="IOC-1'; DROP TABLE ti_entities; --")
        repo.upsert_entity(evil, actor="tester")
        assert repo.get_entity("t1", "indicator", evil.entity_id) is not None
        # Table still exists and is queryable
        assert repo.list_entities("t1").total_count == 1

    def test_unsafe_identifier_helper_rejects_injection(self):
        with pytest.raises(PersistenceError):
            SQLiteThreatIntelRepository._safe_identifier("ti_entities; DROP TABLE x")
        assert SQLiteThreatIntelRepository._safe_identifier("ti_entities") == "ti_entities"

    def test_audit_entries_written_for_entity_writes(self, repo):
        repo.upsert_entity(_entity(), actor="tester")
        actions = {a.action for a in repo.list_audit("t1", "indicator", "IOC-1")}
        assert "entity_created" in actions


class TestFileBackedAndUrlFactory:
    def test_file_backed_repository_persists_across_connections(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "nested", "ti.db")
            r1 = SQLiteThreatIntelRepository(path)
            r1.upsert_entity(_entity(), actor="tester")
            r1.append_observation(_observation())
            r1.close()

            r2 = SQLiteThreatIntelRepository(path)
            assert r2.get_entity("t1", "indicator", "IOC-1") is not None
            assert len(r2.list_observations("t1", "indicator", "IOC-1")) == 1
            r2.close()

    def test_url_factory_memory_and_file(self):
        r = repository_from_url("sqlite://:memory:")
        assert isinstance(r, SQLiteThreatIntelRepository)
        r.close()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ti.db")
            r = repository_from_url(f"sqlite:///{path}")
            r.close()

    def test_url_factory_rejects_unsupported_schemes(self):
        with pytest.raises(PersistenceError):
            repository_from_url("postgresql://user:pass@host/db")
        with pytest.raises(PersistenceError):
            repository_from_url("sqlite://")
        with pytest.raises(PersistenceError):
            repository_from_url("sqlite:///relative/path.db")

    def test_context_manager_closes_connection(self):
        with SQLiteThreatIntelRepository(":memory:") as r:
            r.upsert_entity(_entity(), actor="tester")
        with pytest.raises(sqlite3.ProgrammingError):
            r._conn.execute("SELECT 1")
