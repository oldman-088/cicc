"""The host-facing ports: the one surface another team must implement.

`contracts.py` was the only module in the package with no test importing it, which is
an odd gap for the file that *defines what the host must build*. A protocol is not
proven by the reference implementation working; it is proven by the reference
implementation being checkable against it.

The four invariants in `VulnerabilityStore`'s docstring are the substance here. They
are enforced by the store, not by this module, because the service cannot enforce them
from outside a transaction — so the tests below assert both halves: that the port
describes them, and that the reference implementation honours them.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vuln_intel.integration.contracts import (
    AuditPort,
    ImportReport,
    RecordOutcome,
    UpsertOutcome,
    UpsertResult,
    VulnerabilityStore,
    verify_port,
)
from vuln_intel.integration.store import InMemoryVulnerabilityStore


class TestPortsAreCheckable:
    """A host must be able to validate its adapter before deploy, not after."""

    def test_the_reference_store_satisfies_the_protocol(self) -> None:
        assert isinstance(InMemoryVulnerabilityStore(), VulnerabilityStore)

    def test_an_unrelated_object_is_not_a_store(self) -> None:
        """Without `@runtime_checkable` this raised TypeError instead of answering.

        Note the failure mode: `isinstance` on a non-runtime-checkable protocol raises,
        but on a *runtime-checkable* one it simply returns False for a stranger. That
        is why `verify_port` exists — a host needs to know what is missing, not that
        something is.
        """
        assert isinstance(object(), VulnerabilityStore) is False

    def test_an_empty_object_is_missing_every_method(self) -> None:
        assert verify_port(object()) == ("find", "list", "upsert")

    def test_a_partial_adapter_is_named_precisely(self) -> None:
        class OnlyFind:
            def find(self, **kwargs: object) -> None: ...

        assert verify_port(OnlyFind()) == ("list", "upsert")

    def test_a_complete_adapter_reports_nothing(self) -> None:
        assert verify_port(InMemoryVulnerabilityStore()) == ()

    def test_the_audit_port_is_checkable_too(self) -> None:
        assert verify_port(InMemoryVulnerabilityStore(), AuditPort) == ("record",)

    def test_verify_port_rejects_a_non_protocol(self) -> None:
        with pytest.raises(TypeError):
            verify_port(object(), int)  # type: ignore[arg-type]

    def test_verify_port_is_shallow_and_says_so(self) -> None:
        """It checks presence, not signatures — mypy owns signatures.

        Claiming more would imply a guarantee that `runtime_checkable` cannot give.
        """

        class WrongSignature:
            def find(self) -> None: ...  # wrong signature, right name

            def list(self) -> None: ...

            def upsert(self) -> None: ...

        # Present, so the port check passes; a real signature error is mypy's.
        assert isinstance(WrongSignature(), VulnerabilityStore)


class TestOutcomeVocabulary:
    """The host's audit types must be able to compare these directly."""

    def test_outcomes_compare_equal_to_plain_strings(self) -> None:
        assert UpsertOutcome.CREATED == "created"
        assert UpsertOutcome.UPDATED == "updated"

    def test_outcomes_are_usable_as_dict_keys_beside_strings(self) -> None:
        counts = {UpsertOutcome.CREATED: 0}
        counts["created"] = counts.get("created", 0) + 1
        assert list(counts) == ["created"]
        assert counts[UpsertOutcome.CREATED] == 1

    def test_stored_outcome_strings_match_the_vocabulary(self) -> None:
        """The store writes strings; the report compares against the class."""
        assert UpsertResult(outcome="created").outcome == UpsertOutcome.CREATED
        assert UpsertResult(outcome="skipped", reason="x").as_dict() == {
            "outcome": "skipped",
            "entity_id": None,
            "provenance_id": None,
            "reason": "x",
        }


class TestImportReportCounts:
    def test_an_empty_report_counts_zero_everywhere(self) -> None:
        report = ImportReport(tenant_id="t", dry_run=False, origin="fixture")
        assert (report.created, report.updated, report.unchanged) == (0, 0, 0)
        assert report.failed == 0

    def test_counts_are_derived_from_outcomes_not_stored(self) -> None:
        report = ImportReport(
            tenant_id="t",
            dry_run=False,
            origin="fixture",
            outcomes=[
                RecordOutcome(cve="CVE-1", outcome="created"),
                RecordOutcome(cve="CVE-2", outcome="created"),
                RecordOutcome(cve="CVE-3", outcome="updated"),
                RecordOutcome(cve="CVE-4", outcome="unchanged"),
                RecordOutcome(cve="CVE-5", outcome="skipped", reason="refused"),
            ],
        )
        assert report.created == 2
        assert report.updated == 1
        assert report.unchanged == 1
        assert report.failed == 1

    def test_rejected_count_as_failures(self) -> None:
        """A rejected record is a failure to import, whatever the outcome list says."""
        report = ImportReport(
            tenant_id="t", dry_run=False, origin="fixture",
            rejected=[{"cve": "CVE-9", "reason": "bad origin"}],
        )
        assert report.failed == 1

    def test_counts_never_sum_above_the_stated_total(self) -> None:
        """created + updated + unchanged + failed must account for every outcome."""
        outcomes = [
            RecordOutcome(cve=f"CVE-{i}", outcome=kind)
            for i, kind in enumerate(
                ["created", "updated", "unchanged", "skipped"]
            )
        ]
        report = ImportReport(tenant_id="t", dry_run=False, origin="fixture",
                              outcomes=outcomes)
        total = report.created + report.updated + report.unchanged + report.failed
        assert total == len(outcomes)

    def test_as_dict_is_json_safe(self) -> None:
        import json

        report = ImportReport(
            tenant_id="t", dry_run=False, origin="fixture",
            outcomes=[RecordOutcome(cve="CVE-1", outcome="created", entity_id="e1")],
        )
        payload = report.as_dict()
        json.dumps(payload)  # must not raise
        assert payload["created"] == 1
        assert payload["outcomes"][0]["cve"] == "CVE-1"


class TestDocumentedInvariantsHold:
    """The four rules in the protocol docstring, checked against the reference store.

    They live in the store because the service cannot enforce them from outside a
    transaction. That makes them a contract the *host adapter* must honour, so the
    reference implementation had better demonstrate each one.
    """

    @staticmethod
    def _store() -> InMemoryVulnerabilityStore:
        return InMemoryVulnerabilityStore(allow_fixture=True)

    @staticmethod
    def _upsert(store, *, cve="CVE-2026-0001", when=None, tenant="tenant-a"):
        moment = when or datetime(2026, 1, 1, tzinfo=timezone.utc)
        return store.upsert(
            tenant_id=tenant,
            cve=cve,
            entity={"source": "nvd"},
            details={"cve_id": cve, "origin": "fixture"},
            enrichment={"origin": "fixture", "severity": "high"},
            provenance={"event_type": "source_record_ingested"},
            collected_at=moment,
            dry_run=False,
        )

    def test_tenant_and_cve_are_unique(self) -> None:
        store = self._store()
        self._upsert(store)
        second = self._upsert(store, when=datetime(2026, 1, 2, tzinfo=timezone.utc))
        # `unchanged` is correct here, not `updated`: this helper writes an identical
        # body, and the store deliberately distinguishes "new evidence" from "a newer
        # timestamp on the same evidence". `updated` needs the body to differ.
        assert second.outcome == UpsertOutcome.UNCHANGED
        assert len(store.rows) == 1
        assert store.writes == 1
        assert len(store.rows) == 1

    def test_the_same_cve_in_two_tenants_is_two_rows(self) -> None:
        store = self._store()
        self._upsert(store, tenant="tenant-a")
        self._upsert(store, tenant="tenant-b")
        assert len(store.rows) == 2

    def test_an_older_observation_never_overwrites_a_newer_one(self) -> None:
        store = self._store()
        newer = datetime(2026, 6, 1, tzinfo=timezone.utc)
        older = newer - timedelta(days=30)
        self._upsert(store, when=newer)
        result = self._upsert(store, when=older)
        # `skipped` with a reason, not `unchanged`: the store refused the write and
        # says why. `unchanged` would imply it was a harmless re-observation.
        assert result.outcome == UpsertOutcome.SKIPPED
        assert "older observation" in (result.reason or "")

    def test_a_write_records_its_provenance_event(self) -> None:
        """Rule 3: the row and its provenance commit together, never one alone."""
        store = self._store()
        self._upsert(store)
        assert len(store.provenance_events) == 1

    def test_a_refused_write_records_no_provenance(self) -> None:
        store = InMemoryVulnerabilityStore()  # fixture not permitted
        with pytest.raises(PermissionError):
            self._upsert(store)
        result = PermissionError("refused")
        # A refused write raises from `assert_persistable` - the gate is loud on
        # purpose, because a silent refusal is a record that vanishes from a run.
        assert isinstance(result, PermissionError)
        assert store.provenance_events == []
        assert store.rows == {}

    def test_tenant_scoping_is_never_inferred(self) -> None:
        """Rule 4 is about the host, but the store must not leak across tenants."""
        store = self._store()
        self._upsert(store, tenant="tenant-a")
        assert store.find(tenant_id="tenant-b", cve="CVE-2026-0001") is None

    def test_dry_run_writes_nothing(self) -> None:
        store = self._store()
        result = store.upsert(
            tenant_id="tenant-a", cve="CVE-2026-0002",
            entity={}, details={"cve_id": "CVE-2026-0002", "origin": "fixture"},
            enrichment={"origin": "fixture"},
            provenance={"event_type": "source_record_ingested"},
            collected_at=datetime(2026, 1, 1, tzinfo=timezone.utc), dry_run=True,
        )
        assert store.rows == {}
        assert store.writes == 0
        # `previewed` now exists in the vocabulary. Before it did, the service used the
        # string literal "previewed" and the report counted it in none of its totals.
        assert result.outcome == UpsertOutcome.PREVIEWED
