"""
Unit tests for the Threat Intelligence cross-agent integration contract layer.

Covers:
- Agent 1 Coordination Contract v1.0 + Issue #5 ops-worker heartbeat payloads
- Agent 3 Vulnerability Intelligence M1-M6 mismatch resolutions
- Agent 4 Frontend typed DTO envelopes
"""

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from apps.threat_intelligence.cisa_kev import CISAKEVIngestionService
from apps.threat_intelligence.integration_contracts import (
    Agent1OpsWorkerHeartbeatPayload,
    Agent1RegistrationPayload,
    Agent1TaskEnqueuePayload,
    AttackTechniqueMappingEntryDTO,
    CVETechniqueCorrelationDTO,
    KEVVulnerabilityCorrelationDTO,
    ProvenanceSummaryDTO,
    ThreatIntelligenceIntegrationBridge,
    VendorAdvisoryLinkDTO,
)
from apps.threat_intelligence.vendor_advisories import VendorSecurityAdvisoryIngestionService


@pytest.fixture
def kev_service() -> CISAKEVIngestionService:
    svc = CISAKEVIngestionService(tenant_id="tenant-contracts")
    svc.ingest_kev_record({
        "kev_id": "KEV-2026-0001",
        "cve_id": "CVE-2026-0001",
        "vendor": "AcmeRouter",
        "product": "ACME VPN",
        "vulnerability_name": "ACME VPN Auth Bypass",
        "date_added": datetime(2026, 9, 1, 12, 0, 0),
        "required_action": "Apply updates per vendor instructions.",
        "due_date": datetime(2026, 9, 22, 12, 0, 0),
        "known_ransomware_use": True,
    })
    return svc


@pytest.fixture
def advisory_service() -> VendorSecurityAdvisoryIngestionService:
    svc = VendorSecurityAdvisoryIngestionService(vendor_type="debian", tenant_id="tenant-contracts")
    svc.parse_vendor_advisory("debian", {
        "dsa_id": "DSA-5678-1",
        "cves": ["cve-2026-0001"],
        "packages": ["acme-vpn"],
        "fixed_versions": ["2.1.4"],
        "severity": "High",
        "published": datetime(2026, 9, 2, 8, 0, 0),
        "action": "Upgrade package",
    })
    return svc


class TestAgent1Contracts:
    """Agent 1 (Central Coordination & System Health) contract compliance."""

    def test_registration_payload_is_extra_forbid_and_defaults(self):
        payload = Agent1RegistrationPayload()
        assert payload.agent == "agent-2-threat-intel"
        assert "osint_stix_taxii" in payload.capabilities
        assert payload.meta["acting_agent"] == "agent-6-backup"
        assert payload.meta["primary_owner"] == "agent-2"
        with pytest.raises(ValidationError):
            Agent1RegistrationPayload(agent="a", unexpected_field="boom")

    def test_ops_heartbeat_payload_matches_issue5_constraints(self):
        hb = Agent1OpsWorkerHeartbeatPayload(worker="ti-worker-01")
        assert hb.queue == "threat_intel"
        assert hb.interval_seconds >= 30
        assert hb.stall_threshold_seconds == 120
        with pytest.raises(ValidationError):
            Agent1OpsWorkerHeartbeatPayload(worker="ti-worker-01", interval_seconds=5)
        with pytest.raises(ValidationError):
            Agent1OpsWorkerHeartbeatPayload(worker="")

    def test_task_enqueue_rejects_unsafe_task_id_and_kind(self):
        payload = Agent1TaskEnqueuePayload(
            task_id="ti-osint-sync.2026-11-05",
            kind="threat_intel_sync",
            title="OSINT sync",
        )
        assert payload.repo == "oldman-088/cicc"
        assert payload.branch_ref == "arena/28e50255-cicc"
        with pytest.raises(ValidationError):
            Agent1TaskEnqueuePayload(task_id="bad/slash", kind="threat_intel_sync", title="x")
        with pytest.raises(ValidationError):
            Agent1TaskEnqueuePayload(kind="Threat-Intel Sync!", title="x")

    def test_bridge_builds_coordination_payloads(self):
        bridge = ThreatIntelligenceIntegrationBridge(tenant_id="tenant-contracts")
        reg = bridge.build_agent1_registration()
        assert isinstance(reg, Agent1RegistrationPayload)
        hb = bridge.build_agent1_ops_heartbeat(worker_id="ti-worker-09", details="ingesting_kev")
        assert hb.worker == "ti-worker-09"
        assert hb.details == "ingesting_kev"


class TestAgent3M1M2KEVAndVendorCorrelation:
    """Agent 3 M1 (requiredAction) + M2 (vendor advisories are not CVE aliases)."""

    def test_kev_present_correlation_carries_verbatim_required_action(self, kev_service, advisory_service):
        bridge = ThreatIntelligenceIntegrationBridge(
            kev_service=kev_service, advisory_service=advisory_service
        )
        corr = bridge.correlate_cve_kev_and_advisories("cve-2026-0001")
        assert isinstance(corr, KEVVulnerabilityCorrelationDTO)
        assert corr.cve_id == "CVE-2026-0001"
        assert corr.kev is True
        assert corr.kev_required_action == "Apply updates per vendor instructions."
        assert corr.kev_due_date == datetime(2026, 9, 22, 12, 0, 0)
        assert corr.known_ransomware_use is True
        assert len(corr.vendor_advisories) == 1
        adv = corr.vendor_advisories[0]
        assert isinstance(adv, VendorAdvisoryLinkDTO)
        assert adv.advisory_id == "DSA-5678-1"
        assert adv.vendor_source_id == "debian"
        assert adv.affected_products == ["acme-vpn"]

    def test_kev_absent_is_false_not_none(self, kev_service, advisory_service):
        bridge = ThreatIntelligenceIntegrationBridge(
            kev_service=kev_service, advisory_service=advisory_service
        )
        corr = bridge.correlate_cve_kev_and_advisories("CVE-2026-9999")
        assert corr.kev is False
        assert corr.kev_required_action is None
        assert corr.vendor_advisories == []

    def test_kev_not_consulted_is_tri_state_none(self, kev_service, advisory_service):
        """M1/M6: 'never looked' must never be encoded as False."""
        bridge = ThreatIntelligenceIntegrationBridge(
            kev_service=kev_service, advisory_service=advisory_service
        )
        corr = bridge.correlate_cve_kev_and_advisories("CVE-2026-0001", kev_consulted=False)
        assert corr.kev is None
        assert corr.kev_required_action is None
        # Vendor advisories are still reported even when KEV was not consulted
        assert len(corr.vendor_advisories) == 1

    def test_correlation_without_services_degrades_to_not_consulted(self, advisory_service):
        bridge = ThreatIntelligenceIntegrationBridge(advisory_service=advisory_service)
        corr = bridge.correlate_cve_kev_and_advisories("CVE-2026-0001")
        assert corr.kev is None


class TestAgent3M3M4M6TechniqueRollup:
    """Agent 3 M3 (mapping_type), M4 (sub-technique identity), M6 (tri-state consulted)."""

    def _corr(self, cve_id, techniques, consulted="consulted_mapped"):
        return CVETechniqueCorrelationDTO(
            cve_id=cve_id,
            consulted=consulted,
            techniques=[AttackTechniqueMappingEntryDTO(**t) for t in techniques],
        )

    def test_sub_technique_identity_is_preserved_not_truncated(self):
        entry = AttackTechniqueMappingEntryDTO(
            technique_id="t1059.001", name="PowerShell", mapping_type="exploitation_technique"
        )
        assert entry.technique_id == "T1059.001"
        with pytest.raises(ValidationError):
            AttackTechniqueMappingEntryDTO(technique_id="T1059.0011", name="Bad", mapping_type="exploitation_technique")
        with pytest.raises(ValidationError):
            AttackTechniqueMappingEntryDTO(technique_id="TECH-1", name="Bad", mapping_type="exploitation_technique")

    def test_mapping_type_is_restricted_to_ctid_values(self):
        with pytest.raises(ValidationError):
            AttackTechniqueMappingEntryDTO(technique_id="T1190", name="Bad", mapping_type="random_type")

    def test_consulted_field_is_tri_state_validated(self):
        with pytest.raises(ValidationError):
            CVETechniqueCorrelationDTO(cve_id="CVE-2026-0001", consulted="maybe")

    def test_rollup_filters_exploitation_and_splits_all_mapping_types(self):
        bridge = ThreatIntelligenceIntegrationBridge()
        correlations = [
            self._corr("CVE-2026-0001", [
                {"technique_id": "T1059.001", "name": "PowerShell", "mapping_type": "exploitation_technique"},
                {"technique_id": "T1486", "name": "Data Encrypted for Impact", "mapping_type": "primary_impact"},
                {"technique_id": "T1078", "name": "Valid Accounts", "mapping_type": "mitigation"},
            ]),
            self._corr("CVE-2026-0002", [
                {"technique_id": "T1059.001", "name": "PowerShell", "mapping_type": "exploitation_technique"},
                {"technique_id": "T1090", "name": "Proxy", "mapping_type": "secondary_impact"},
            ]),
        ]
        rollup = bridge.build_technique_rollup(correlations)
        assert rollup.consulted == "consulted_mapped"
        assert rollup.total_cves == 2
        # Only exploitation techniques appear in `techniques`
        assert [t["technique_id"] for t in rollup.techniques] == ["T1059.001"]
        assert rollup.techniques[0]["cve_count"] == 2
        assert sorted(rollup.techniques[0]["cves"]) == ["CVE-2026-0001", "CVE-2026-0002"]
        assert rollup.techniques_by_mapping_type == {
            "exploitation_technique": 2,
            "primary_impact": 1,
            "secondary_impact": 1,
            "mitigation": 1,
        }

    def test_rollup_not_consulted_when_mapping_unloaded(self):
        bridge = ThreatIntelligenceIntegrationBridge()
        correlations = [self._corr("CVE-2026-0001", [], consulted="not_consulted")]
        rollup = bridge.build_technique_rollup(correlations, mapping_loaded=False)
        assert rollup.consulted == "not_consulted"
        assert rollup.techniques == []
        assert sum(rollup.techniques_by_mapping_type.values()) == 0

    def test_rollup_distinguishes_unmapped_from_not_consulted(self):
        bridge = ThreatIntelligenceIntegrationBridge()
        rollup = bridge.build_technique_rollup([self._corr("CVE-2026-0003", [], consulted="consulted_unmapped")])
        assert rollup.consulted == "consulted_unmapped"
        assert rollup.total_cves == 1
        assert rollup.techniques == []


class TestAgent3M5ProvenanceGranularity:
    """Agent 3 M5: sources is a deduplicated set, observations are append-only history."""

    def test_provenance_summary_deduplicates_sources_and_counts_observations(self):
        bridge = ThreatIntelligenceIntegrationBridge()
        summary = bridge.summarize_provenance(
            "IOC-0001", ["source-a", "source-b", "source-a", "source-c", "source-a"]
        )
        assert isinstance(summary, ProvenanceSummaryDTO)
        assert summary.sources == ["source-a", "source-b", "source-c"]
        assert summary.observations_count == 5
        assert summary.corroboration_count == 3
        assert summary.observations_count >= len(summary.sources)


class TestAgent4FrontendEnvelopes:
    """Agent 4 (Frontend) typed DTO envelopes."""

    def test_bridge_exposes_frontend_freshness_metadata(self):
        from apps.threat_intelligence.integration_contracts import (
            ConfidenceDTO,
            DataOrigin,
            FreshnessMetaDTO,
            HostMountStatus,
            ProvenanceRefDTO,
            ThreatIntelDetailEnvelope,
            ThreatIntelEntityDTO,
            ThreatIntelEntityType,
            ThreatIntelErrorBody,
            ThreatIntelErrorEnvelope,
            ThreatIntelListEnvelope,
            VerificationMode,
        )

        bridge = ThreatIntelligenceIntegrationBridge(tenant_id="tenant-contracts")
        summary = bridge.summarize_provenance("IOC-0001", ["source-a", "source-a"])
        now = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)

        entity = ThreatIntelEntityDTO(
            id="IOC-0001",
            type=ThreatIntelEntityType.INDICATOR,
            name="192.0.2.10",
            confidence=ConfidenceDTO(score=0.72, corroborating_source_count=1),
            first_seen=now,
            last_seen=now,
            provenance=[ProvenanceRefDTO(source_id="source-a", observation_count=2)],
            attributes={"value": "192.0.2.10", "indicator_type": "ipv4"},
        )
        freshness = FreshnessMetaDTO(collected_at=now, age_seconds=60, stale_after_seconds=3600)

        detail = ThreatIntelDetailEnvelope(
            data=entity, provenance_summary=summary, freshness=freshness
        )
        assert detail.freshness.origin is DataOrigin.EXPERIMENTAL_DEMO
        assert detail.freshness.verification_mode is VerificationMode.FIXTURE_TESTED
        assert (
            detail.freshness.host_mount_status
            is HostMountStatus.NOT_MOUNTED_PENDING_OWNER_APPROVAL
        )

        listing = ThreatIntelListEnvelope(data=[detail.data], freshness=freshness)
        assert listing.page.limit == 50
        assert listing.page.next_cursor is None
        assert listing.page.has_more is False

        err = ThreatIntelErrorEnvelope(
            status=422,
            error=ThreatIntelErrorBody(code="validation_error", message="bad input"),
        )
        assert 400 <= err.status <= 599
        assert err.to_response_body() == {
            "error": {"code": "validation_error", "message": "bad input"}
        }
        with pytest.raises(ValidationError):
            ThreatIntelErrorEnvelope(
                status=200, error=ThreatIntelErrorBody(code="ok", message="not an error")
            )


class TestAgent4Amendments:
    """
    The seven amendments submitted by Backup Agent 4 on PR #6
    (https://github.com/oldman-088/cicc/pull/6#issuecomment-6657783177).
    """

    NOW = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)

    def _freshness(self, **kw):
        from apps.threat_intelligence.integration_contracts import FreshnessMetaDTO

        base = {"collected_at": self.NOW}
        base.update(kw)
        return FreshnessMetaDTO(**base)

    # 1. Typed payloads ------------------------------------------------------
    def test_amendment_1_entity_dto_is_typed_with_a_closed_type_enum(self):
        from apps.threat_intelligence.integration_contracts import (
            ThreatIntelEntityDTO,
            ThreatIntelEntityType,
        )

        entity = ThreatIntelEntityDTO(
            id="a-1", type=ThreatIntelEntityType.THREAT_ACTOR, name="APT-Test"
        )
        assert entity.type is ThreatIntelEntityType.THREAT_ACTOR
        assert entity.confidence.score == 0.0
        assert entity.first_seen is None and entity.last_seen is None
        assert entity.provenance == []
        with pytest.raises(ValidationError):
            ThreatIntelEntityDTO(id="a-1", type="not_a_real_entity_type")

    def test_amendment_1_confidence_and_verification_are_separate_semantics(self):
        from apps.threat_intelligence.integration_contracts import (
            ConfidenceDTO,
            VerificationMode,
        )

        conf = ConfidenceDTO(
            score=0.95, verification_mode=VerificationMode.FIXTURE_TESTED, conflict_open=True
        )
        assert conf.score == 0.95
        assert conf.verification_mode is VerificationMode.FIXTURE_TESTED
        assert conf.conflict_open is True
        with pytest.raises(ValidationError):
            ConfidenceDTO(score=1.5)

    def test_amendment_1_envelopes_reject_untyped_dicts(self):
        from apps.threat_intelligence.integration_contracts import (
            ThreatIntelDetailEnvelope,
            ThreatIntelListEnvelope,
        )

        with pytest.raises(ValidationError):
            ThreatIntelListEnvelope(
                data=[{"indicator_id": "IOC-1"}], freshness=self._freshness()
            )
        with pytest.raises(ValidationError):
            ThreatIntelDetailEnvelope(
                data={"indicator_id": "IOC-1"}, freshness=self._freshness()
            )

    def test_amendment_1_list_items_carry_per_record_provenance(self):
        from apps.threat_intelligence.integration_contracts import (
            ProvenanceRefDTO,
            ThreatIntelEntityDTO,
            ThreatIntelEntityType,
            ThreatIntelListEnvelope,
        )

        listing = ThreatIntelListEnvelope(
            data=[
                ThreatIntelEntityDTO(
                    id="IOC-1",
                    type=ThreatIntelEntityType.INDICATOR,
                    provenance=[
                        ProvenanceRefDTO(
                            source_id="urlhaus",
                            observation_count=3,
                            source_reference="https://urlhaus.example.invalid/1",
                            retrieved_at=self.NOW,
                        )
                    ],
                )
            ],
            freshness=self._freshness(),
        )
        assert listing.data[0].provenance[0].source_id == "urlhaus"
        assert listing.data[0].provenance[0].observation_count == 3

    # 2. Timestamps ----------------------------------------------------------
    def test_amendment_2_collected_at_has_no_default(self):
        from apps.threat_intelligence.integration_contracts import FreshnessMetaDTO

        with pytest.raises(ValidationError):
            FreshnessMetaDTO()

    def test_amendment_2_naive_timestamps_are_rejected(self):
        from apps.threat_intelligence.integration_contracts import (
            FreshnessMetaDTO,
            ThreatIntelEntityDTO,
            ThreatIntelEntityType,
        )

        naive = datetime(2026, 11, 5, 12, 0)
        with pytest.raises(ValidationError):
            FreshnessMetaDTO(collected_at=naive)
        with pytest.raises(ValidationError):
            FreshnessMetaDTO(collected_at=self.NOW, last_successful_sync=naive)
        with pytest.raises(ValidationError):
            ThreatIntelEntityDTO(
                id="a-1", type=ThreatIntelEntityType.THREAT_ACTOR, first_seen=naive
            )

    def test_amendment_2_aware_timestamps_are_accepted(self):
        freshness = self._freshness(last_successful_sync=self.NOW)
        assert freshness.collected_at.tzinfo is not None
        assert freshness.last_successful_sync.tzinfo is not None

    # 3. No tenant_id in frontend envelopes ----------------------------------
    def test_amendment_3_tenant_id_is_absent_from_frontend_envelopes(self):
        from apps.threat_intelligence.integration_contracts import (
            ThreatIntelDetailEnvelope,
            ThreatIntelEntityDTO,
            ThreatIntelEntityType,
            ThreatIntelListEnvelope,
        )

        assert "tenant_id" not in ThreatIntelListEnvelope.model_fields
        assert "tenant_id" not in ThreatIntelDetailEnvelope.model_fields
        entity = ThreatIntelEntityDTO(id="a-1", type=ThreatIntelEntityType.THREAT_ACTOR)
        with pytest.raises(ValidationError):
            ThreatIntelListEnvelope(
                data=[entity], freshness=self._freshness(), tenant_id="tenant-x"
            )
        with pytest.raises(ValidationError):
            ThreatIntelDetailEnvelope(
                data=entity, freshness=self._freshness(), tenant_id="tenant-x"
            )

    # 4. Error envelope alignment -------------------------------------------
    def test_amendment_4_error_envelope_serialises_as_nested_error_object(self):
        from apps.threat_intelligence.integration_contracts import (
            ThreatIntelErrorBody,
            ThreatIntelErrorEnvelope,
        )

        err = ThreatIntelErrorEnvelope(
            status=422,
            error=ThreatIntelErrorBody(
                code="validation_error",
                message="field is required",
                correlation_id="corr-123",
                details={"field": "indicator_type"},
            ),
        )
        assert err.to_response_body() == {
            "error": {
                "code": "validation_error",
                "message": "field is required",
                "correlation_id": "corr-123",
                "details": {"field": "indicator_type"},
            }
        }
        assert "error_code" not in ThreatIntelErrorEnvelope.model_fields

    def test_amendment_4_429_requires_retry_after_and_others_forbid_it(self):
        from apps.threat_intelligence.integration_contracts import (
            ThreatIntelErrorBody,
            ThreatIntelErrorEnvelope,
        )

        ok = ThreatIntelErrorEnvelope(
            status=429,
            error=ThreatIntelErrorBody(
                code="rate_limited", message="slow down", retry_after_seconds=30
            ),
        )
        assert ok.to_response_body()["error"]["retry_after_seconds"] == 30
        with pytest.raises(ValidationError):
            ThreatIntelErrorEnvelope(
                status=429, error=ThreatIntelErrorBody(code="rate_limited", message="x")
            )
        with pytest.raises(ValidationError):
            ThreatIntelErrorEnvelope(
                status=503, error=ThreatIntelErrorBody(code="unavailable", message="x")
            )
        with pytest.raises(ValidationError):
            ThreatIntelErrorEnvelope(
                status=404,
                error=ThreatIntelErrorBody(
                    code="not_found", message="x", retry_after_seconds=10
                ),
            )

    # 5. Pagination semantics -----------------------------------------------
    def test_amendment_5_total_count_is_nullable_and_cursor_is_authoritative(self):
        from apps.threat_intelligence.integration_contracts import PaginationMetaDTO

        unknown = PaginationMetaDTO(limit=50, next_cursor="eyJvZmZzZXQiOjUwfQ")
        assert unknown.total_count is None
        assert unknown.has_more is True

        exhausted = PaginationMetaDTO(limit=50, total_count=12)
        assert exhausted.has_more is False
        assert exhausted.total_count == 12

        with pytest.raises(ValidationError):
            PaginationMetaDTO(total_count=-1)

    # 6. Freshness enums and thresholds -------------------------------------
    def test_amendment_6_freshness_fields_are_enums_not_free_strings(self):
        from apps.threat_intelligence.integration_contracts import (
            DataOrigin,
            HostMountStatus,
            VerificationMode,
        )

        freshness = self._freshness()
        assert isinstance(freshness.origin, DataOrigin)
        assert isinstance(freshness.verification_mode, VerificationMode)
        assert isinstance(freshness.host_mount_status, HostMountStatus)
        with pytest.raises(ValidationError):
            self._freshness(origin="probably_live")
        with pytest.raises(ValidationError):
            self._freshness(verification_mode="live_verified_i_promise")
        with pytest.raises(ValidationError):
            self._freshness(host_mount_status="mounted")

    def test_amendment_6_staleness_is_explainable_not_a_bare_boolean(self):
        from apps.threat_intelligence.integration_contracts import FreshnessMetaDTO

        explained = FreshnessMetaDTO(
            collected_at=self.NOW, age_seconds=7200, stale_after_seconds=3600, is_stale=True
        )
        assert explained.age_seconds == 7200
        assert explained.stale_after_seconds == 3600
        assert explained.is_stale is True

        # A bare `is_stale` with no declared horizon is refused.
        with pytest.raises(ValidationError):
            FreshnessMetaDTO(collected_at=self.NOW, is_stale=True)
        # So is a stale flag that contradicts the arithmetic.
        with pytest.raises(ValidationError):
            FreshnessMetaDTO(
                collected_at=self.NOW,
                age_seconds=10,
                stale_after_seconds=3600,
                is_stale=True,
            )

    # 7. Nullable provenance on detail --------------------------------------
    def test_amendment_7_detail_provenance_summary_is_nullable(self):
        from apps.threat_intelligence.integration_contracts import (
            ThreatIntelDetailEnvelope,
            ThreatIntelEntityDTO,
            ThreatIntelEntityType,
        )

        entity = ThreatIntelEntityDTO(id="a-1", type=ThreatIntelEntityType.THREAT_ACTOR)
        detail = ThreatIntelDetailEnvelope(data=entity, freshness=self._freshness())
        assert detail.provenance_summary is None

        bridge = ThreatIntelligenceIntegrationBridge(tenant_id="tenant-contracts")
        with_prov = ThreatIntelDetailEnvelope(
            data=entity,
            provenance_summary=bridge.summarize_provenance("a-1", ["src-a"]),
            freshness=self._freshness(),
        )
        assert with_prov.provenance_summary.sources == ["src-a"]

    # 8. Contract status unchanged ------------------------------------------
    def test_amendment_8_contract_remains_proposed_and_unmounted(self):
        from apps.threat_intelligence.integration_contracts import (
            HostMountStatus,
            ThreatIntelListEnvelope,
        )

        listing = ThreatIntelListEnvelope(data=[], freshness=self._freshness())
        assert listing.freshness.host_mount_status is (
            HostMountStatus.NOT_MOUNTED_PENDING_OWNER_APPROVAL
        )
        assert listing.contract_version.endswith("-proposed")
        assert listing.freshness.verification_mode.value == "fixture_tested"


class TestEndToEndCrossDomainFlow:
    """KEV + vendor advisory + OSINT provenance flow through the bridge (fixture-based)."""

    def test_kev_advisory_and_osint_provenance_join(self, kev_service, advisory_service):
        from apps.threat_intelligence.osint_sources import OSINTIngestionService

        osint = OSINTIngestionService(tenant_id="tenant-contracts")
        osint.ingest_indicator({
            "indicator_id": "IOC-X-1",
            "indicator_type": "ipv4",
            "raw_value": "192.0.2.10",
            "source_id": "source-a",
        })
        osint.ingest_indicator({
            "indicator_type": "ipv4",
            "raw_value": "192.0.2.10",
            "source_id": "source-b",
        })
        obs_sources = [o.source_id for o in osint.get_observations_for_entity("IOC-X-1")]

        bridge = ThreatIntelligenceIntegrationBridge(
            kev_service=kev_service, advisory_service=advisory_service, tenant_id="tenant-contracts"
        )
        corr = bridge.correlate_cve_kev_and_advisories("CVE-2026-0001")
        provenance = bridge.summarize_provenance("IOC-X-1", obs_sources)

        assert corr.kev is True
        assert corr.vendor_advisories[0].advisory_id == "DSA-5678-1"
        assert provenance.corroboration_count == 2
        assert provenance.observations_count == 2
        assert provenance.observations_count >= len(provenance.sources)

    def test_kev_catalog_feed_drives_correlation(self):
        """Ingesting a CISA KEV catalog payload must make the CVE reportable as KEV-listed."""
        svc = CISAKEVIngestionService(tenant_id="tenant-contracts")
        result = svc.ingest_kev_catalog_feed({
            "title": "CISA KEV",
            "catalogVersion": "2026.11.05",
            "vulnerabilities": [{
                "cveID": "CVE-2026-1234",
                "vendorProject": "Acme",
                "product": "Widget",
                "vulnerabilityName": "Acme Widget RCE",
                "dateAdded": "2026-10-01",
                "shortDescription": "RCE in Acme Widget",
                "requiredAction": "Apply updates per vendor instructions.",
                "dueDate": (datetime.utcnow() + timedelta(days=21)).date().isoformat(),
                "knownRansomwareCampaignUse": "Known",
            }],
        })
        assert len(result["records"]) == 1
        assert result["source"].framework_version == "2026.11.05"
        assert result["verification_mode"] == "fixture_tested"

        bridge = ThreatIntelligenceIntegrationBridge(kev_service=svc)
        corr = bridge.correlate_cve_kev_and_advisories("CVE-2026-1234")
        assert corr.kev is True
        assert corr.kev_required_action == "Apply updates per vendor instructions."
        assert corr.known_ransomware_use is True
