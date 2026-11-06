"""Two sources, one instant, two answers — what the system does about it.

This is the divergence that would have caused a real incident. The host importer
(`apps/api/app/connectors/nvd_import.py`) refuses a same-timestamp disagreement:

    if incoming < current or (incoming == current and existing.details != details):
        raise ValueError('Older or conflicting observation cannot overwrite a newer
                          observation')

This package treated the same case as a routine update, so the last writer won and
the disagreement vanished — no error, no provenance event, no trace. Two writers for
the same facts with different conflict rules is precisely the duplicate-source risk
described in `docs/vulnerability-intelligence/SOURCE_DIVERGENCE.md`.

The rule now enforced in all three stores:

    older  -> SKIPPED     (a stale observation cannot overwrite a newer one)
    equal, same body -> UNCHANGED (a refresh; no new evidence)
    equal, different body -> CONFLICTED (a contradiction; refuse and name it)

`CONFLICTED` is deliberately not an exception, unlike the host: a batch importer must
carry on with the other records and report the one it refused. It is also
deliberately not counted as `failed`, because a source contradicting itself is not an
outage, and conflating the two would hide which one happened.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from vuln_intel.integration.contracts import ImportReport, RecordOutcome, UpsertOutcome
from vuln_intel.integration.dbapi_store import SQLITE_SCHEMA, DBAPIVulnerabilityStore
from vuln_intel.integration.sqlite_store import SQLiteVulnerabilityStore
from vuln_intel.integration.store import InMemoryVulnerabilityStore

_UTC = timezone.utc
_T0 = datetime(2026, 1, 1, tzinfo=_UTC)
_LATER = _T0 + timedelta(hours=1)


def _provenance(store, cve: str):
    """Read provenance the way this particular store exposes it."""
    if hasattr(store, "provenance_for"):
        return store.provenance_for(tenant_id="tenant-a", cve=cve)
    return [e for e in store.provenance_events if e.get("cve") == cve]


def _fixture_record(cve: str, *, summary: str = "a claim"):
    """A real NormalizedVulnerability, so the service path is exercised for real."""
    from vuln_intel.schema import CveId, NormalizedVulnerability, Origin

    return NormalizedVulnerability(
        cve=CveId.parse(cve), origin=Origin.FIXTURE, summary=summary, sources=("nvd",)
    )


def _upsert(store, *, details, when=_T0, cve="CVE-2021-44228", tenant="tenant-a",
            provenance=None):
    return store.upsert(
        tenant_id=tenant,
        cve=cve,
        entity={"id": "entity-1"},
        details=details,
        enrichment={"origin": "fixture"},
        provenance=provenance or {"source": "NVD", "observed_at": when.isoformat()},
        collected_at=when,
        dry_run=False,
    )


@pytest.fixture(params=["memory", "sqlite", "dbapi"])
def store(request, tmp_path):
    """All three implementations, because they must not disagree about this."""
    if request.param == "memory":
        return InMemoryVulnerabilityStore(allow_fixture=True)
    if request.param == "sqlite":
        return SQLiteVulnerabilityStore(path=tmp_path / "c.db", allow_fixture=True)
    path = str(tmp_path / "c-dbapi.db")
    conn = sqlite3.connect(path)
    conn.executescript(SQLITE_SCHEMA)
    conn.commit()
    conn.close()
    return DBAPIVulnerabilityStore(
        connect=lambda: sqlite3.connect(path), paramstyle="qmark", allow_fixture=True
    )


class TestTheThreeCasesAreDistinguished:
    def test_a_same_instant_disagreement_is_refused(self, store):
        _upsert(store, details={"severity": "critical"})
        result = _upsert(store, details={"severity": "low"})
        assert result.outcome == UpsertOutcome.CONFLICTED
        assert "conflicting observation" in (result.reason or "")

    def test_the_first_source_is_not_overwritten(self, store):
        _upsert(store, details={"severity": "critical"})
        _upsert(store, details={"severity": "low"})
        stored = store.find(tenant_id="tenant-a", cve="CVE-2021-44228")
        assert stored["details"]["severity"] == "critical"

    def test_the_refusal_records_no_provenance_event(self, store):
        """A refused write is not evidence that anything was observed."""
        _upsert(store, details={"severity": "critical"})
        _upsert(store, details={"severity": "low"})
        assert len(_provenance(store, "CVE-2021-44228")) == 1

    def test_a_same_instant_with_identical_content_is_only_a_refresh(self, store):
        _upsert(store, details={"severity": "critical"})
        result = _upsert(store, details={"severity": "critical"})
        assert result.outcome == UpsertOutcome.UNCHANGED

    def test_a_strictly_newer_observation_still_updates(self, store):
        _upsert(store, details={"severity": "critical"})
        result = _upsert(store, details={"severity": "low"}, when=_LATER)
        assert result.outcome == UpsertOutcome.UPDATED
        assert store.find(tenant_id="tenant-a", cve="CVE-2021-44228")["details"][
            "severity"
        ] == "low"

    def test_an_older_observation_is_still_skipped_not_conflicted(self, store):
        """The distinction matters: stale is routine, contradiction is not."""
        _upsert(store, details={"severity": "critical"}, when=_LATER)
        result = _upsert(store, details={"severity": "low"}, when=_T0)
        assert result.outcome == UpsertOutcome.SKIPPED
        assert result.outcome != UpsertOutcome.CONFLICTED

    def test_a_conflict_on_one_cve_does_not_stop_the_others(self, store):
        _upsert(store, details={"severity": "critical"})
        _upsert(store, details={"severity": "low"})
        other = _upsert(store, details={"severity": "medium"}, cve="CVE-2021-0001")
        assert other.outcome == UpsertOutcome.CREATED

    def test_a_conflict_is_visible_in_the_stored_record(self, store):
        """The refusal is not silent: the record still says what it said, and why."""
        _upsert(store, details={"severity": "critical"})
        result = _upsert(store, details={"severity": "low"})
        stored = store.find(tenant_id="tenant-a", cve="CVE-2021-44228")
        assert stored["details"]["severity"] == "critical"
        assert result.outcome == "conflicted"


class TestTheReportCountsConflictsSeparately:
    def _report(self, outcomes):
        return ImportReport(
            tenant_id="tenant-a",
            dry_run=False,
            origin="fixture",
            outcomes=[
                RecordOutcome(cve=f"CVE-2021-{i:04d}", outcome=outcome)
                for i, outcome in enumerate(outcomes)
            ],
        )

    def test_a_conflict_is_counted(self):
        report = self._report([UpsertOutcome.CREATED, UpsertOutcome.CONFLICTED])
        assert report.conflicted == 1

    def test_a_conflict_is_not_counted_as_a_failure(self):
        """A source contradicting itself is not an outage."""
        report = self._report([UpsertOutcome.CONFLICTED])
        assert report.failed == 0
        assert report.conflicted == 1

    def test_a_conflict_is_not_counted_as_an_update(self):
        report = self._report([UpsertOutcome.CONFLICTED])
        assert report.updated == 0

    def test_conflicts_do_not_break_the_other_totals(self):
        report = self._report(
            [
                UpsertOutcome.CREATED,
                UpsertOutcome.UPDATED,
                UpsertOutcome.UNCHANGED,
                UpsertOutcome.SKIPPED,
                UpsertOutcome.PREVIEWED,
                UpsertOutcome.CONFLICTED,
            ]
        )
        assert (report.created, report.updated, report.unchanged) == (1, 1, 1)
        assert report.previewed == 1
        assert report.conflicted == 1
        # skipped is counted as failed; the conflict is not.
        assert report.failed == 1


class TestTheRefusalCarriesItsEvidence:
    """A refusal that says only "no" cannot be investigated.

    The conflict detail exists so an operator can answer three questions without
    guessing: which source was kept, which was refused, and what differed.
    """

    def test_the_detail_is_populated_only_for_conflicts(self, store):
        _upsert(store, details={"severity": "critical"})
        updated = _upsert(store, details={"severity": "low"}, when=_LATER)
        assert updated.conflict is None
        assert updated.conflicted is False

        conflicted = _upsert(store, details={"severity": "high"}, when=_LATER)
        assert conflicted.outcome == UpsertOutcome.CONFLICTED
        assert conflicted.conflict is not None
        assert conflicted.conflicted is True

    def test_it_names_the_field_that_differed(self, store):
        _upsert(store, details={"severity": "critical", "cvss": 10.0})
        result = _upsert(store, details={"severity": "low", "cvss": 10.0})
        assert "severity" in result.conflict.differing_fields
        # Unchanged fields are not listed: a conflict report that names every field
        # is no more useful than one that names none.
        assert "cvss" not in result.conflict.differing_fields

    def test_it_names_nested_differences_by_path(self, store):
        _upsert(store, details={"cvss": {"score": 10.0, "vector": "AV:N"}})
        result = _upsert(store, details={"cvss": {"score": 9.0, "vector": "AV:N"}})
        assert "cvss.score" in result.conflict.differing_fields
        assert "cvss.vector" not in result.conflict.differing_fields

    def test_it_preserves_both_source_identities(self, store):
        _upsert(store, details={"severity": "critical"},
                provenance={"source": "NVD", "observed_at": _T0.isoformat()})
        result = _upsert(store, details={"severity": "low"},
                         provenance={"source": "OSV", "observed_at": _T0.isoformat()})
        assert result.conflict.existing_source == "NVD"
        assert result.conflict.incoming_source == "OSV"

    def test_it_preserves_the_shared_instant(self, store):
        _upsert(store, details={"severity": "critical"})
        result = _upsert(store, details={"severity": "low"})
        assert result.conflict.instant == _T0.isoformat()

    def test_the_digests_differ_and_are_stable(self, store):
        _upsert(store, details={"severity": "critical"})
        first = _upsert(store, details={"severity": "low"})
        assert first.conflict.existing_digest != first.conflict.incoming_digest
        # Re-importing the same contradiction must describe it identically.
        again = _upsert(store, details={"severity": "low"})
        assert again.conflict.as_dict() == first.conflict.as_dict()

    def test_the_detail_survives_as_json(self, store):
        """The report is a machine-readable artifact; it must serialise."""
        import json
        _upsert(store, details={"severity": "critical"})
        result = _upsert(store, details={"severity": "low"})
        text = json.dumps(result.as_dict(), sort_keys=True)
        assert json.loads(text)["conflict"]["instant"] == _T0.isoformat()


class TestRepeatedConflictsAreDeterministic:
    def test_the_same_conflict_repeated_many_times_never_varies(self, store):
        _upsert(store, details={"severity": "critical"})
        outcomes = [_upsert(store, details={"severity": "low"}) for _ in range(5)]
        assert {o.outcome for o in outcomes} == {UpsertOutcome.CONFLICTED}
        # Byte-identical descriptions each time: no accumulating state, no drift.
        descriptions = {o.conflict.existing_digest for o in outcomes}
        assert len(descriptions) == 1

    def test_a_conflict_never_mutates_the_stored_body_even_under_repetition(self, store):
        _upsert(store, details={"severity": "critical", "cvss": 10.0})
        for _ in range(5):
            _upsert(store, details={"severity": "low", "cvss": 1.0})
        stored = store.find(tenant_id="tenant-a", cve="CVE-2021-44228")
        assert stored["details"]["severity"] == "critical"
        assert stored["details"]["cvss"] == 10.0
        assert len(_provenance(store, "CVE-2021-44228")) == 1

    def test_a_conflict_then_a_newer_observation_still_wins(self, store):
        """Refusing the contradiction must not wedge the record."""
        _upsert(store, details={"severity": "critical"})
        _upsert(store, details={"severity": "low"})
        later = _T0 + timedelta(hours=2)
        result = _upsert(store, details={"severity": "low"}, when=later)
        assert result.outcome == UpsertOutcome.UPDATED


class TestBatchContinuesPastAConflict:
    def test_records_before_and_after_the_conflict_are_still_processed(self, store):
        _upsert(store, details={"severity": "critical"}, cve="CVE-2021-0002")
        conflicted = _upsert(store, details={"severity": "low"}, cve="CVE-2021-0002")
        later = [_upsert(store, details={"severity": "high"}, cve=f"CVE-2021-{i:04d}")
                 for i in (1, 3, 4)]
        assert conflicted.outcome == UpsertOutcome.CONFLICTED
        assert [o.outcome for o in later] == [UpsertOutcome.CREATED] * 3

    def test_the_service_reports_the_conflict_and_keeps_going(self):
        """Through the real service, because the stores are not the entry point."""
        from vuln_intel.integration.service import IngestionPolicy, IngestionService

        store = InMemoryVulnerabilityStore(allow_fixture=True)
        # dry_run defaults to True (safe by default), so it must be turned off
        # explicitly for a write to happen at all.
        service = IngestionService(
            store=store, policy=IngestionPolicy(allow_fixture=True, dry_run=False)
        )
        records = [_fixture_record(cve) for cve in
                   ("CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0003")]
        first = service.import_records(records, tenant_id="tenant-a", collected_at=_T0)
        assert first.created == 3

        # Same instant, one record contradicted, others identical.
        changed = _fixture_record("CVE-2021-0002", summary="a different claim entirely")
        second = service.import_records(
            [_fixture_record("CVE-2021-0001"), changed, _fixture_record("CVE-2021-0003")],
            tenant_id="tenant-a", collected_at=_T0,
        )
        outcome_by_cve = {o.cve: o.outcome for o in second.outcomes}
        assert outcome_by_cve["CVE-2021-0002"] == UpsertOutcome.CONFLICTED
        # The unrelated records were still processed, not abandoned.
        assert outcome_by_cve["CVE-2021-0001"] == UpsertOutcome.UNCHANGED
        assert outcome_by_cve["CVE-2021-0003"] == UpsertOutcome.UNCHANGED
        assert second.conflicted == 1
        assert second.failed == 0
        assert second.conflicts[0].cve == "CVE-2021-0002"

    def test_the_report_serialises_the_conflict_separately_from_failures(self):
        from vuln_intel.integration.contracts import ConflictDetail

        report = ImportReport(tenant_id="t", dry_run=False, origin="fixture")
        report.outcomes.append(
            RecordOutcome(
                cve="CVE-2021-0002",
                outcome=UpsertOutcome.CONFLICTED,
                conflict=ConflictDetail(
                    instant=_T0.isoformat(),
                    existing_source="NVD",
                    incoming_source="OSV",
                    differing_fields=("severity",),
                    existing_digest="aaaa",
                    incoming_digest="bbbb",
                ),
            )
        )
        body = report.as_dict()
        assert body["conflicted"] == 1
        assert body["failed"] == 0
        assert body["conflicts"][0]["conflict"]["differing_fields"] == ["severity"]


class TestEveryAdapterAgreesOnTheConflict:
    """Same evidence, same instant, same refusal — byte-identical across adapters.

    The parity test in ``test_sqlite_store.py`` covers outcomes. This covers the
    *description*, which is the part a consumer reads: if two adapters named different
    fields or different sources for the same contradiction, an operator comparing two
    reports would think they had two problems.
    """

    @staticmethod
    def _dbapi(tmp_path):
        import sqlite3

        from vuln_intel.integration.dbapi_store import (
            SQLITE_SCHEMA,
            DBAPIVulnerabilityStore,
        )

        path = str(tmp_path / "parity-conflict.db")
        conn = sqlite3.connect(path)
        conn.executescript(SQLITE_SCHEMA)
        conn.commit()
        conn.close()
        return DBAPIVulnerabilityStore(
            connect=lambda: sqlite3.connect(path), paramstyle="qmark", allow_fixture=True
        )

    def _three(self, tmp_path):
        return (
            InMemoryVulnerabilityStore(allow_fixture=True),
            SQLiteVulnerabilityStore(path=tmp_path / "c.db", allow_fixture=True),
            self._dbapi(tmp_path),
        )

    def test_all_three_describe_the_conflict_identically(self, tmp_path):
        details = []
        for store in self._three(tmp_path):
            _upsert(store, details={"severity": "critical", "cvss": {"score": 10.0}},
                    provenance={"source": "NVD", "observed_at": _T0.isoformat()})
            result = _upsert(store, details={"severity": "low", "cvss": {"score": 10.0}},
                             provenance={"source": "OSV", "observed_at": _T0.isoformat()})
            assert result.outcome == UpsertOutcome.CONFLICTED
            details.append(result.conflict.as_dict())
        assert details[0] == details[1] == details[2]

    def test_all_three_leave_the_same_persisted_state(self, tmp_path):
        states = []
        for store in self._three(tmp_path):
            _upsert(store, details={"severity": "critical"})
            _upsert(store, details={"severity": "low"})
            found = store.find(tenant_id="tenant-a", cve="CVE-2021-44228")
            states.append((found["details"], len(_provenance(store, "CVE-2021-44228"))))
        assert states[0] == states[1] == states[2]
