"""
Unit tests for the Threat Intelligence cross-agent integration contract layer.

Covers:
- Agent 1 Coordination Contract v1.0 + Issue #5 ops-worker heartbeat payloads
- Agent 3 Vulnerability Intelligence M1-M6 mismatch resolutions
- Agent 4 Frontend typed DTO envelopes
"""

from datetime import datetime, timedelta

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
            FreshnessMetaDTO,
            ThreatIntelDetailEnvelope,
            ThreatIntelErrorEnvelope,
            ThreatIntelListEnvelope,
        )

        bridge = ThreatIntelligenceIntegrationBridge(tenant_id="tenant-contracts")
        summary = bridge.summarize_provenance("IOC-0001", ["source-a", "source-a"])

        detail = ThreatIntelDetailEnvelope(
            data={"indicator_id": "IOC-0001", "value": "192.0.2.10"},
            provenance_summary=summary,
            tenant_id="tenant-contracts",
        )
        assert detail.freshness.origin == "EXPERIMENTAL_DEMO_DATA_ONLY"
        assert detail.freshness.verification_mode == "fixture_tested"
        assert detail.freshness.host_mount_status == "not_mounted_pending_owner_approval"

        listing = ThreatIntelListEnvelope(data=[detail.data])
        assert listing.page.limit == 50
        assert listing.page.next_cursor is None

        err = ThreatIntelErrorEnvelope(status=422, error_code="validation_error", message="bad input")
        assert 400 <= err.status <= 599
        assert isinstance(FreshnessMetaDTO().collected_at, datetime)
        with pytest.raises(ValidationError):
            ThreatIntelErrorEnvelope(status=200, error_code="ok", message="not an error")


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
