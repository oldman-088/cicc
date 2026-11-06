"""Integration layer: mapping fidelity, origin gates, dry run and audit coupling."""

from __future__ import annotations

from datetime import timedelta

import pytest

from vuln_intel.errors import MixedOriginError
from vuln_intel.integration import (
    ENRICHMENT_KEY,
    ENTITY_KIND,
    IngestionPolicy,
    IngestionService,
    InMemoryVulnerabilityStore,
    RecordingAudit,
    RefusingStore,
    UpsertOutcome,
    assert_persistable,
    to_entity_payload,
    to_source_details,
    to_store_payload,
)
from vuln_intel.schema import (
    AffectedPackage,
    CveId,
    CvssScore,
    NormalizedVulnerability,
    Origin,
    ProvenanceRecord,
    Reference,
    Severity,
)

from .conftest import FIXED_NOW


def live_record(cve: str = "CVE-2026-0001", **overrides) -> NormalizedVulnerability:
    base = dict(
        cve=CveId.parse(cve),
        origin=Origin.LIVE,
        sources=("nvd", "osv"),
        severity=Severity.CRITICAL,
        summary="Synthetic test summary",
        details="Synthetic test detail body",
        published=FIXED_NOW - timedelta(days=3),
        modified=FIXED_NOW - timedelta(days=1),
        cvss=(CvssScore("3.1", 9.8, Severity.CRITICAL, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", source="nvd"),),
        cwe=("CWE-78",),
        references=(Reference(url="https://example.invalid/a", kind="patch", source="nvd"),),
        affected=(AffectedPackage(ecosystem="npm", name="demo-pkg", introduced="0", fixed="1.2.3"),),
        kev=True,
        epss_score=0.42,
        epss_percentile=0.97,
        epss_model_date="2026-01-01",
        provenance=(
            ProvenanceRecord(
                source="nvd",
                source_ref="2026-01-02T03:04:05.000",
                fetched_at=FIXED_NOW,
                transport="live",
                url="https://services.nvd.nist.gov/rest/json/cves/2.0",
            ),
        ),
    )
    base.update(overrides)
    return NormalizedVulnerability(**base)


# -- mapping -----------------------------------------------------------------
def test_entity_payload_matches_host_contract() -> None:
    entity = to_entity_payload(live_record())
    # Mirrors NvdImport's Entity(kind='vulnerability', title=<cve>, ...).
    assert entity["kind"] == ENTITY_KIND == "vulnerability"
    assert entity["title"] == "CVE-2026-0001"
    assert entity["properties"]["cve_id"] == "CVE-2026-0001"
    assert entity["source"] == "NVD"
    # Confidence is never invented; the record stays unverified.
    assert entity["confidence"] is None
    assert entity["verification_status"] == "unverified"


def test_source_details_preserve_source_fields_and_add_enrichment() -> None:
    details = to_source_details(live_record())
    # Source-shaped fields an existing NVD reader understands:
    assert details["cve_id"] == "CVE-2026-0001"
    assert details["descriptions"][0]["text"] == "Synthetic test detail body"
    assert details["cvss"][0]["base_score"] == 9.8
    assert details["kev"] is True
    # Package-owned enrichment sits beside them, never replacing them:
    enrichment = details[ENRICHMENT_KEY]
    assert enrichment["schema"] == "cicc.vuln_intel.v1"
    assert enrichment["origin"] == "live"
    assert enrichment["corroborated"] is True
    assert enrichment["epss"]["available"] is True


def test_enrichment_marks_missing_epss_as_unavailable_not_zero() -> None:
    details = to_source_details(live_record(epss_score=None, epss_percentile=None))
    assert details[ENRICHMENT_KEY]["epss"]["available"] is False
    assert details[ENRICHMENT_KEY]["epss"]["score"] is None


def test_kev_unknown_is_preserved_as_null() -> None:
    details = to_source_details(live_record(kev=None))
    assert details["kev"] is None
    assert details[ENRICHMENT_KEY]["kev"] is None


def test_provenance_block_is_complete_and_aware() -> None:
    payload = to_store_payload(live_record(), tenant_id="tenant-a")
    provenance = payload["provenance"]
    assert provenance["event_type"] == "source_record_created"
    assert provenance["details"]["source"] == "nvd"
    assert provenance["details"]["origin"] == "live"
    assert provenance["occurred_at"].tzinfo is not None


def test_provenance_event_type_is_one_the_package_itself_uses() -> None:
    """The bug this pins: `to_provenance` emitted a value nothing else had.

    It said ``source_record_ingested`` while :func:`event_types` — which both bundled
    stores call to *override* the field — only ever emits ``source_record_created`` /
    ``source_record_updated``. The override hid the mismatch from every store test, so
    a host that inserted the provenance block verbatim would have written an event type
    absent from its own vocabulary and from ours. A payload that names an event type
    must name one this package can produce.
    """
    from vuln_intel.integration.mapping import event_types

    created, _ = event_types(created=True)
    updated, _ = event_types(created=False)
    emitted = to_store_payload(live_record(), tenant_id="tenant-a")["provenance"]["event_type"]
    assert emitted in {created, updated}


def test_both_stores_emit_the_same_event_type_for_the_same_outcome() -> None:
    """The in-memory and SQL stores must not disagree about vocabulary."""
    import tempfile
    from pathlib import Path

    from vuln_intel.integration.sqlite_store import SQLiteVulnerabilityStore

    payload = to_store_payload(live_record(), tenant_id="tenant-a")
    memory = InMemoryVulnerabilityStore(allow_fixture=True)
    with tempfile.TemporaryDirectory() as tmp:
        disk = SQLiteVulnerabilityStore(path=Path(tmp) / "t.db", allow_fixture=True)
        for store in (memory, disk):
            store.upsert(
                tenant_id="tenant-a",
                cve="CVE-2026-0001",
                entity=payload["entity"],
                details=payload["details"],
                enrichment=payload["enrichment"],
                provenance=payload["provenance"],
                collected_at=FIXED_NOW,
                dry_run=False,
            )
        assert memory.provenance_events[0]["event_type"] == disk.provenance_for(
            tenant_id="tenant-a", cve="CVE-2026-0001"
        )[0]["event_type"]


def test_provenance_requires_timezone_aware_timestamps() -> None:
    from datetime import datetime

    from vuln_intel.errors import ValidationError

    # Rejected at construction time, before any payload is built.
    with pytest.raises(ValidationError):
        ProvenanceRecord(
            source="nvd", source_ref=None, fetched_at=datetime(2026, 1, 1)
        )

    # And a naive ``collected_at`` cannot reach a payload either.
    with pytest.raises(ValueError):
        to_store_payload(live_record(), tenant_id="tenant-a", collected_at=datetime(2026, 1, 1))


# -- origin gate -------------------------------------------------------------
def test_fixture_records_are_refused_by_the_store() -> None:
    store = InMemoryVulnerabilityStore(allow_fixture=False)
    with pytest.raises(PermissionError):
        store.upsert(
            tenant_id="tenant-a",
            cve="CVE-2026-0001",
            entity={},
            details={},
            enrichment={"origin": "fixture"},
            provenance={},
            collected_at=FIXED_NOW,
            dry_run=False,
        )


def test_assert_persistable_allows_live_only_by_default() -> None:
    assert_persistable({"origin": "live"}, allow_fixture=False)
    for origin in ("fixture", "demo"):
        with pytest.raises(PermissionError):
            assert_persistable({"origin": origin}, allow_fixture=False)
        assert_persistable({"origin": origin}, allow_fixture=True)


def test_service_skips_fixture_records_without_writing() -> None:
    store = InMemoryVulnerabilityStore(allow_fixture=False)
    service = IngestionService(
        store=store, policy=IngestionPolicy(dry_run=False, allow_fixture=False)
    )
    report = service.import_records(
        [live_record(origin=Origin.FIXTURE)], tenant_id="tenant-a"
    )
    assert report.failed == 1
    assert report.outcomes[0].outcome == UpsertOutcome.SKIPPED
    assert "fixture" in (report.outcomes[0].reason or "")
    assert store.writes == 0


def test_service_rejects_a_mixed_origin_batch() -> None:
    service = IngestionService(store=InMemoryVulnerabilityStore(), policy=IngestionPolicy())
    with pytest.raises(MixedOriginError):
        service.import_records(
            [live_record(), live_record("CVE-2026-0002", origin=Origin.DEMO)],
            tenant_id="tenant-a",
        )


# -- dry run -----------------------------------------------------------------
def test_dry_run_is_the_default_and_writes_nothing() -> None:
    store = InMemoryVulnerabilityStore(allow_fixture=False)
    service = IngestionService(store=store)  # default policy: dry_run=True
    report = service.import_records([live_record()], tenant_id="tenant-a")
    assert report.dry_run is True
    assert store.writes == 0
    assert report.payloads and report.payloads[0]["cve"] == "CVE-2026-0001"
    assert report.outcomes[0].outcome == "previewed"


def test_write_without_a_store_is_reported_not_faked() -> None:
    service = IngestionService(store=None, policy=IngestionPolicy(dry_run=False))
    report = service.import_records([live_record()], tenant_id="tenant-a")
    assert report.outcomes[0].outcome == UpsertOutcome.SKIPPED
    assert "no store configured" in (report.outcomes[0].reason or "")


def test_refusing_store_denies_writes_explicitly() -> None:
    service = IngestionService(
        store=RefusingStore(), policy=IngestionPolicy(dry_run=False)
    )
    report = service.import_records([live_record()], tenant_id="tenant-a")
    assert report.failed == 1
    assert "not approved" in (report.outcomes[0].reason or "")


# -- write path --------------------------------------------------------------
def test_first_import_creates_then_second_is_unchanged() -> None:
    store = InMemoryVulnerabilityStore(allow_fixture=False)
    audit = RecordingAudit()
    service = IngestionService(
        store=store, audit=audit, policy=IngestionPolicy(dry_run=False)
    )
    first = service.import_records([live_record()], tenant_id="tenant-a", actor_id="user-1")
    assert first.outcomes[0].outcome == UpsertOutcome.CREATED
    assert len(audit.events) == 1
    assert audit.events[0]["action"] == "nvd_record_imported"
    assert audit.events[0]["target_entity_id"]

    second = service.import_records([live_record()], tenant_id="tenant-a", actor_id="user-1")
    assert second.outcomes[0].outcome == UpsertOutcome.UNCHANGED
    assert len(audit.events) == 1  # no audit event for a no-op


def test_changed_record_produces_an_update_and_new_provenance() -> None:
    store = InMemoryVulnerabilityStore(allow_fixture=False)
    service = IngestionService(store=store, policy=IngestionPolicy(dry_run=False))
    service.import_records([live_record()], tenant_id="tenant-a", collected_at=FIXED_NOW)
    later = FIXED_NOW + timedelta(hours=1)
    report = service.import_records(
        [live_record(kev=False)], tenant_id="tenant-a", collected_at=later
    )
    assert report.outcomes[0].outcome == UpsertOutcome.UPDATED
    assert len(store.provenance_events) == 2


def test_older_observation_never_overwrites_newer() -> None:
    store = InMemoryVulnerabilityStore(allow_fixture=False)
    service = IngestionService(store=store, policy=IngestionPolicy(dry_run=False))
    service.import_records([live_record()], tenant_id="tenant-a", collected_at=FIXED_NOW)
    report = service.import_records(
        [live_record(kev=False)],
        tenant_id="tenant-a",
        collected_at=FIXED_NOW - timedelta(days=1),
    )
    assert report.outcomes[0].outcome == UpsertOutcome.SKIPPED
    assert "older observation" in (report.outcomes[0].reason or "")


def test_tenants_are_isolated() -> None:
    store = InMemoryVulnerabilityStore(allow_fixture=False)
    service = IngestionService(store=store, policy=IngestionPolicy(dry_run=False))
    service.import_records([live_record()], tenant_id="tenant-a")
    service.import_records([live_record()], tenant_id="tenant-b")
    assert store.find(tenant_id="tenant-a", cve="CVE-2026-0001") is not None
    assert store.find(tenant_id="tenant-b", cve="CVE-2026-0001") is not None
    assert store.find(tenant_id="tenant-c", cve="CVE-2026-0001") is None


def test_audit_failure_is_surfaced_not_swallowed() -> None:
    store = InMemoryVulnerabilityStore(allow_fixture=False)
    service = IngestionService(
        store=store,
        audit=RecordingAudit(fail=True),
        policy=IngestionPolicy(dry_run=False, stop_on_audit_failure=True),
    )
    report = service.import_records([live_record()], tenant_id="tenant-a")
    assert report.outcomes[0].outcome == UpsertOutcome.SKIPPED
    assert "audit failed" in (report.outcomes[0].reason or "")


def test_store_error_is_reported_per_record() -> None:
    class Boom:
        def find(self, **kwargs):
            return None

        def upsert(self, **kwargs):
            raise RuntimeError("db down")

    service = IngestionService(store=Boom(), policy=IngestionPolicy(dry_run=False))
    report = service.import_records([live_record()], tenant_id="tenant-a")
    assert report.failed == 1
    assert "store rejected" in (report.outcomes[0].reason or "")


def test_report_is_json_shaped() -> None:
    service = IngestionService(store=InMemoryVulnerabilityStore())
    payload = service.import_records([live_record()], tenant_id="tenant-a").as_dict()
    assert payload["created"] == 0 and payload["dry_run"] is True
    assert isinstance(payload["payloads"], list)
    assert payload["payloads"][0]["entity"]["title"] == "CVE-2026-0001"


def test_import_requires_a_tenant() -> None:
    service = IngestionService(store=InMemoryVulnerabilityStore())
    with pytest.raises(ValueError):
        service.import_records([live_record()], tenant_id="")


def test_naive_collected_at_is_rejected() -> None:
    from datetime import datetime

    service = IngestionService(store=InMemoryVulnerabilityStore())
    with pytest.raises(ValueError):
        service.import_records(
            [live_record()], tenant_id="tenant-a", collected_at=datetime(2026, 1, 1)
        )


# -- review artifact ---------------------------------------------------------
def test_preview_artifact_satisfies_separation_rules() -> None:
    """The generated preview must never carry fixture data into a store payload."""
    from vuln_intel.integration import preview

    payload = preview.build()
    assert preview.validate(payload) == []
    origins = {item["origin"] for item in payload["store_payload_preview"]["payloads"]}
    assert origins == {"live"}
    gate = payload["origin_gate_check"]["fixture_import"]
    assert gate["failed"] == len(gate["outcomes"]) >= 1
    # And the artifact states plainly that live connectivity was not verified.
    assert "NOT verified" in payload["notice"]
    assert payload["network_requests"] == {"nvd": 1, "osv": 1}
