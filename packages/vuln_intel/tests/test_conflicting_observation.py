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


def _upsert(store, *, details, when=_T0, cve="CVE-2021-44228", tenant="tenant-a"):
    return store.upsert(
        tenant_id=tenant,
        cve=cve,
        entity={"id": "entity-1"},
        details=details,
        enrichment={"origin": "fixture"},
        provenance={"source": "NVD", "observed_at": when.isoformat()},
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
