"""A value preserved in one layer must survive the next one.

This file exists because of a specific, repeated defect. Twice in the previous
milestone a fact was correctly preserved at a lower layer and discarded at an upper
one, and both times the suite was green:

* the checkpoint learned to keep ``completed_at`` across a failure, but
  ``to_source_state`` reported it only when the run advanced, so it was thrown away;
* ``shape_record`` read ``freshness`` and ``policy`` out of the enrichment block, and
  **nothing ever wrote them there**, so both were permanently ``null`` through the API.

Neither was caught by testing a layer in isolation. Both were caught by asking what
consumes the value. So every test here follows one value from its source of truth to
the outermost representation a consumer actually reads, and asserts it is still there.

The rule these tests encode: for each value, if the bottom layer has it, the top layer
must have it — and if the bottom layer does not have it, the top layer must say so
rather than substituting a default.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from vuln_intel.confidence import ConfidenceBasis, derive_confidence
from vuln_intel.freshness import FreshnessState, SourceSynchronisation, describe_freshness
from vuln_intel.integration.api import shape_record
from vuln_intel.integration.mapping import to_enrichment, to_store_payload
from vuln_intel.integration.store import InMemoryVulnerabilityStore
from vuln_intel.schema import (
    CollectionStatus,
    CveId,
    NormalizedVulnerability,
    Origin,
    SourceKind,
    SourceState,
)
from vuln_intel.seens import InMemorySeenStore, SightingTracker

NOW = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)


def _record(**kwargs) -> NormalizedVulnerability:
    kwargs.setdefault("cve", CveId.parse("CVE-2026-4242"))
    kwargs.setdefault("summary", "synthetic")
    kwargs.setdefault("origin", Origin.LIVE)
    kwargs.setdefault("sources", ("nvd", "osv"))
    kwargs.setdefault("modified", NOW - timedelta(days=1))
    return NormalizedVulnerability(**kwargs)


def _row(record, *, confidence=None, freshness=None, seen=None) -> dict:
    payload = to_store_payload(
        record,
        tenant_id="t1",
        collected_at=NOW,
        confidence=confidence,
        freshness=freshness,
        seen=seen,
    )
    return {
        "cve": str(record.cve),
        "entity_id": "entity-1",
        "origin": record.origin.value,
        "collected_at": NOW,
        "details": payload["details"],
        "confidence": payload["entity"]["confidence"],
    }


class TestConfidenceReachesTheApi:
    def test_a_computed_confidence_is_stored_and_served(self):
        """The defect: confidence existed only inside the ranking call."""
        record = _record()
        confidence = derive_confidence(
            sources=record.sources, policy="provisional-default", policy_approved=False
        )

        # layer 1: the value exists
        assert confidence.value == 0.7

        # layer 2: it reaches the stored payload
        payload = to_store_payload(record, tenant_id="t1", confidence=confidence)
        assert payload["enrichment"]["confidence"]["value"] == 0.7

        # layer 3: it survives the round trip through the API shaper
        shaped = shape_record(_row(record, confidence=confidence))
        assert shaped["confidence"] is not None
        assert shaped["confidence"]["value"] == 0.7

    def test_the_api_payload_carries_the_basis_and_the_inputs(self):
        """A bare float cannot be distinguished from a provider's assertion."""
        record = _record()
        confidence = derive_confidence(
            sources=record.sources, policy="provisional-default", policy_approved=False
        )
        shaped = shape_record(_row(record, confidence=confidence))
        assert shaped["confidence"]["basis"] == ConfidenceBasis.CORROBORATION
        assert shaped["confidence"]["inputs"]
        assert shaped["confidence"]["policy"] == "provisional-default"
        assert shaped["confidence"]["policy_approved"] is False

    def test_absent_confidence_is_served_as_null_not_zero(self):
        shaped = shape_record(_row(_record()))
        assert shaped["confidence"] is None, (
            "no confidence must not be rendered as 0.0; a zero asserts certainty"
        )

    def test_a_provider_confidence_reaches_the_host_column_and_a_computed_one_does_not(
        self,
    ):
        """The host column is read as a provider assertion, so ours must not go in it."""
        record = _record()
        provided = derive_confidence(
            sources=record.sources, policy="p", policy_approved=True
        )
        payload = to_store_payload(record, tenant_id="t1", confidence=provided)
        assert payload["entity"]["confidence"] is None, (
            "a corroboration estimate must never be written to Entity.confidence"
        )

        from vuln_intel.confidence import ConfidenceValue

        source_provided = ConfidenceValue(
            value=0.9, basis=ConfidenceBasis.SOURCE_PROVIDED, inputs=("vendor advisory",)
        )
        payload = to_store_payload(record, tenant_id="t1", confidence=source_provided)
        assert payload["entity"]["confidence"] == 90, "0-1 locally, 0-100 in the host column"


class TestFreshnessReachesTheApi:
    def test_the_state_is_stored_and_served(self):
        """The defect: shape_record read freshness and nothing wrote it."""
        record = _record()
        freshness = describe_freshness(
            observed_at=NOW - timedelta(days=30),
            source_state=SourceSynchronisation(
                source="nvd", last_success=NOW, last_attempt=NOW
            ),
            now=NOW,
        )
        payload = to_store_payload(record, tenant_id="t1", freshness=freshness)
        assert payload["enrichment"]["freshness"]["state"] == FreshnessState.STALE

        shaped = shape_record(_row(record, freshness=freshness))
        assert shaped["freshness"] is not None, (
            "freshness was stored but the API served null: this is the exact defect"
        )
        assert shaped["freshness"]["state"] == FreshnessState.STALE

    def test_the_api_exposes_the_inputs_not_just_the_verdict(self):
        """A bucket without its inputs cannot be audited."""
        record = _record()
        freshness = describe_freshness(
            observed_at=NOW - timedelta(hours=1),
            source_state=SourceSynchronisation(
                source="nvd",
                last_success=NOW - timedelta(hours=1),
                last_attempt=NOW - timedelta(hours=1),
            ),
            now=NOW,
        )
        shaped = shape_record(_row(record, freshness=freshness))
        assert shaped["freshness"]["observed_at"] is not None
        assert shaped["freshness"]["assessed_at"] is not None
        assert shaped["freshness"]["source_state"]["last_success"] is not None

    def test_never_succeeded_and_failed_are_distinguishable_through_the_api(self):
        record = _record()
        never = describe_freshness(
            observed_at=None,
            source_state=SourceSynchronisation(
                source="nvd", last_attempt=NOW, last_error="bad credentials"
            ),
            now=NOW,
        )
        broke = describe_freshness(
            observed_at=NOW - timedelta(days=2),
            source_state=SourceSynchronisation(
                source="nvd",
                last_success=NOW - timedelta(days=2),
                last_attempt=NOW,
                consecutive_failures=2,
            ),
            now=NOW,
        )
        never_shaped = shape_record(_row(record, freshness=never))
        broke_shaped = shape_record(_row(record, freshness=broke))
        assert never_shaped["freshness"]["state"] == FreshnessState.NEVER_SUCCEEDED
        assert broke_shaped["freshness"]["state"] == FreshnessState.FAILED
        assert never_shaped["freshness"]["state"] != broke_shaped["freshness"]["state"]

    def test_freshness_absent_is_null_not_fresh(self):
        shaped = shape_record(_row(_record()))
        assert shaped["freshness"] is None


class TestSeenReachesTheStoredPayload:
    def test_first_and_last_seen_survive_into_the_enrichment_block(self):
        tracker = SightingTracker(store=InMemorySeenStore(), clock=lambda: NOW)
        tracker.record("CVE-2026-4242", source="nvd", observed_at=NOW - timedelta(days=9))
        tracker.record("CVE-2026-4242", source="osv", observed_at=NOW)
        seen = tracker.get("CVE-2026-4242")
        assert seen is not None

        enrichment = to_enrichment(_record(), seen=seen)
        assert enrichment["seen"]["first_seen"] == (NOW - timedelta(days=9)).isoformat()
        assert enrichment["seen"]["last_seen"] == NOW.isoformat()

    def test_seen_absent_serialises_as_null(self):
        assert to_enrichment(_record())["seen"] is None


class TestSourceStateSurvivesSerialisation:
    """The third place this failure mode could hide: ``SourceState.as_dict``."""

    def test_last_attempt_survives_a_round_trip(self):
        state = SourceState(
            kind=SourceKind.NVD,
            status=CollectionStatus.FAILED,
            checked_at=NOW,
            last_success=NOW - timedelta(days=7),
            last_attempt=NOW,
            error="connection reset",
            records=0,
        )
        restored = SourceState.from_dict(state.as_dict())
        assert restored.last_attempt == NOW, (
            "last_attempt was dropped at serialisation: the collector kept it and the "
            "report lost it"
        )
        assert restored.last_success == NOW - timedelta(days=7)

    def test_the_two_timestamps_are_independently_meaningful_after_a_round_trip(self):
        state = SourceState(
            kind=SourceKind.NVD,
            status=CollectionStatus.FAILED,
            checked_at=NOW,
            last_success=NOW - timedelta(days=7),
            last_attempt=NOW,
        )
        restored = SourceState.from_dict(state.as_dict())
        assert restored.last_attempt is not None
        assert restored.last_success is not None
        assert restored.last_attempt - restored.last_success == timedelta(days=7)

    def test_a_legacy_payload_falls_back_to_the_checked_at_attempt(self):
        legacy = SourceState(
            kind=SourceKind.NVD, status=CollectionStatus.OK, checked_at=NOW
        ).as_dict()
        legacy.pop("last_attempt")
        restored = SourceState.from_dict(legacy)
        assert restored.last_attempt == NOW, (
            "an absent attempt in an old payload falls back to checked_at, which is when "
            "the attempt happened"
        )

    def test_the_attempt_time_is_preserved_when_it_differs_from_the_check(self):
        """The case every other test here missed.

        Each of the earlier tests set ``checked_at == last_attempt``, so a payload that
        dropped ``last_attempt`` was silently repaired by the ``from_dict`` fallback and
        the round trip still passed. The defect only becomes visible when the two
        differ — which is the normal case for a source that was attempted at 09:00 and
        reported at 12:00. A fallback that hides a dropped field is worse than no
        fallback, so it must not be able to hide this one.
        """
        attempt = NOW - timedelta(hours=3)
        state = SourceState(
            kind=SourceKind.NVD,
            status=CollectionStatus.FAILED,
            checked_at=NOW,
            last_success=NOW - timedelta(days=7),
            last_attempt=attempt,
        )
        payload = state.as_dict()
        assert payload["last_attempt"] is not None, (
            "as_dict dropped last_attempt: the field exists, the payload must carry it"
        )
        restored = SourceState.from_dict(payload)
        assert restored.last_attempt == attempt, (
            "a dropped last_attempt is silently replaced by checked_at, so the outage "
            "duration reported to an operator would be wrong"
        )
        assert restored.last_attempt != restored.checked_at

    def test_a_never_succeeded_state_reports_no_success_but_an_attempt(self):
        """The pair that makes "never worked" distinguishable from "broke recently"."""
        restored = SourceState.from_dict(
            SourceState(
                kind=SourceKind.NVD,
                status=CollectionStatus.FAILED,
                checked_at=NOW,
                last_success=None,
                last_attempt=NOW,
            ).as_dict()
        )
        assert restored.last_success is None
        assert restored.last_attempt == NOW


class TestStoreRoundTrip:
    def test_a_stored_record_keeps_the_enrichment_blocks(self):
        store = InMemoryVulnerabilityStore()
        record = _record()
        confidence = derive_confidence(
            sources=record.sources, policy="p", policy_approved=False
        )
        freshness = describe_freshness(
            observed_at=NOW - timedelta(hours=1),
            source_state=SourceSynchronisation(
                source="nvd", last_success=NOW, last_attempt=NOW
            ),
            now=NOW,
        )
        payload = to_store_payload(
            record, tenant_id="t1", confidence=confidence, freshness=freshness
        )
        store.upsert(
            tenant_id="t1",
            cve=str(record.cve),
            entity=payload["entity"],
            details=payload["details"],
            enrichment=payload["enrichment"],
            provenance=payload["provenance"],
            collected_at=NOW,
            dry_run=False,
        )
        row = store.find(tenant_id="t1", cve=str(record.cve))
        assert row is not None
        shaped = shape_record(row)
        assert shaped["confidence"]["value"] == 0.7, (
            "the value survived the store and the API shaper"
        )
        assert shaped["freshness"]["state"] == FreshnessState.FRESH
