import pytest
from datetime import datetime, timedelta
from apps.threat_intelligence.osint_sources import (
    EXPERIMENTAL_DEMO_DATA_ONLY,
    OSINTSourceModel,
    OSINTObservationModel,
    OSINTConflictRecordModel,
    OSINTThreatActorModel,
    OSINTIndicatorModel,
    OSINTCampaignModel,
    OSINTMalwareModel,
    OSINTInfrastructureModel,
    OSINTRelationshipModel,
    OSINTIngestionService,
    STIX21CompatibilityReport,
    TAXII21CollectionModel,
    TAXII21EnvelopeModel,
    TAXII21ManifestEntryModel,
    TAXII21SyncStateModel,
    SecurityError,
)


class TestOSINTModelsAndValidation:
    """Tests for P1-04 OSINT Models, TLP Markings, and Experimental Labeling"""

    def test_source_model_and_tlp_validation(self):
        source = OSINTSourceModel(
            source_id="otx-alienvault",
            source_name="AlienVault OTX",
            provider_type="otx",
            reliability_tier="B",
            default_confidence=0.85,
            tlp_marking="tlp:amber",
            provenance="osint_registry",
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY,
            tenant_id="tenant-001",
        )
        assert source.tlp_marking == "TLP:AMBER"
        assert source.verification_mode == "fixture_tested"
        assert source.health_status == "never_synced"

        with pytest.raises(ValueError):
            OSINTSourceModel(
                source_id="bad-tlp",
                source_name="Bad TLP",
                provider_type="generic_osint",
                tlp_marking="TLP:PURPLE",
                provenance="test",
            )

        with pytest.raises(ValueError):
            OSINTSourceModel(
                source_id="bad-exp",
                source_name="Bad Exp",
                provider_type="generic_osint",
                experimental_label="NOT_ALLOWED",
                provenance="test",
            )

    def test_indicator_model_type_validation(self):
        ind = OSINTIndicatorModel(
            indicator_id="IOC-001",
            indicator_type="ipv4",
            raw_value="198.51.100[.]42",
            normalized_value="198.51.100.42",
            sources=["urlhaus"],
            provenance="osint:urlhaus",
            experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY,
        )
        assert ind.indicator_type == "ipv4"
        assert ind.normalized_value == "198.51.100.42"

        with pytest.raises(ValueError):
            OSINTIndicatorModel(
                indicator_id="IOC-BAD",
                indicator_type="unsupported_type",
                raw_value="abc",
                normalized_value="abc",
                provenance="test",
            )

    def test_infrastructure_and_relationship_validation(self):
        infra = OSINTInfrastructureModel(
            infrastructure_id="INFRA-001",
            name="CobaltStrike C2 Cluster",
            infrastructure_types=["Command-and-Control", "botnet"],
            provenance="osint:misp",
        )
        assert infra.infrastructure_types == ["command-and-control", "botnet"]

        with pytest.raises(ValueError):
            OSINTInfrastructureModel(
                infrastructure_id="INFRA-BAD",
                name="Bad Infra",
                infrastructure_types=["invalid-infra-type"],
                provenance="test",
            )

        rel = OSINTRelationshipModel(
            relationship_id="REL-001",
            source_entity_id="IOC-001",
            source_entity_type="Indicator",
            target_entity_id="INFRA-001",
            target_entity_type="Infrastructure",
            relationship_type="communicates-with",
            provenance="osint:misp",
        )
        assert rel.relationship_type == "COMMUNICATES_WITH"

        with pytest.raises(ValueError):
            OSINTRelationshipModel(
                relationship_id="REL-BAD",
                source_entity_id="A",
                source_entity_type="Indicator",
                target_entity_id="B",
                target_entity_type="Malware",
                relationship_type="unknown_verb",
                provenance="test",
            )


class TestOSINTNormalizationAndRefanging:
    """Tests for IOC refanging, validation, STIX pattern extraction, and confidence scaling"""

    def test_refang_and_normalize_indicators(self):
        assert OSINTIngestionService.refang_and_normalize_indicator("ipv4", "203.0.113[.]19") == "203.0.113.19"
        assert OSINTIngestionService.refang_and_normalize_indicator("ipv6", "2001:0db8::0001") == "2001:db8::1"
        assert OSINTIngestionService.refang_and_normalize_indicator("domain", "Bad-C2[.]Example[.]ORG.") == "bad-c2.example.org"
        assert OSINTIngestionService.refang_and_normalize_indicator("url", "hxxps://mal[.]example[.]org/drop.bin") == "https://mal.example.org/drop.bin"
        assert OSINTIngestionService.refang_and_normalize_indicator("email", "phish[@]bad[.]example.com") == "phish@bad.example.com"
        sha256_upper = "A" * 64
        assert OSINTIngestionService.refang_and_normalize_indicator("sha256", sha256_upper) == "a" * 64

        with pytest.raises(ValueError):
            OSINTIngestionService.refang_and_normalize_indicator("ipv4", "999.999.999.999")
        with pytest.raises(ValueError):
            OSINTIngestionService.refang_and_normalize_indicator("sha256", "not-a-sha256")

    def test_parse_stix_indicator_patterns(self):
        assert OSINTIngestionService.parse_stix_indicator_pattern("[ipv4-addr:value = '192.0.2.55']") == ("ipv4", "192.0.2.55")
        assert OSINTIngestionService.parse_stix_indicator_pattern("[domain-name:value = 'C2.EXAMPLE.COM']") == ("domain", "c2.example.com")
        assert OSINTIngestionService.parse_stix_indicator_pattern("[url:value = 'hxxp://bad[.]example.com/a']") == ("url", "http://bad.example.com/a")
        digest = "b" * 64
        assert OSINTIngestionService.parse_stix_indicator_pattern(f"[file:hashes.'SHA-256' = '{digest}']") == ("sha256", digest)

    def test_confidence_scaling(self):
        assert OSINTIngestionService.normalize_confidence(85) == 0.85
        assert OSINTIngestionService.normalize_confidence(0.92) == 0.92
        assert OSINTIngestionService.normalize_confidence(None, default=0.7) == 0.7
        with pytest.raises(ValueError):
            OSINTIngestionService.normalize_confidence(150)
        with pytest.raises(ValueError):
            OSINTIngestionService.normalize_confidence(-0.1)


class TestSTIX21AndTAXII21Integration:
    """Tests for STIX 2.1 bundle ingestion and TAXII 2.1 collection/envelope compatibility"""

    def setup_method(self):
        self.service = OSINTIngestionService(tenant_id="tenant-osint-01")

    def test_stix21_compatibility_evaluation(self):
        bundle = {
            "type": "bundle",
            "id": "bundle--aaaa-bbbb",
            "spec_version": "2.1",
            "objects": [
                {"type": "threat-actor", "spec_version": "2.1", "id": "threat-actor--1", "name": "APT-OSINT"},
                {"type": "indicator", "spec_version": "2.1", "id": "indicator--1", "pattern": "[ipv4-addr:value = '198.51.100.7']"},
                {"type": "x-custom-ext", "spec_version": "2.1", "id": "x-custom-ext--1"},
            ],
        }
        report = self.service.evaluate_stix_taxii_compatibility(bundle)
        assert isinstance(report, STIX21CompatibilityReport)
        assert report.is_stix21_compatible is True
        assert report.supported_object_counts["threat-actor"] == 1
        assert report.supported_object_counts["indicator"] == 1
        assert "x-custom-ext" in report.unsupported_object_types
        assert report.verification_mode == "fixture_tested"

    def test_ingest_stix21_bundle_end_to_end(self):
        bundle = {
            "type": "bundle",
            "id": "bundle--stix21-full",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "threat-actor",
                    "spec_version": "2.1",
                    "id": "threat-actor--apt42-osint",
                    "name": "APT- Mirage",
                    "aliases": ["MirageGroup"],
                    "threat_actor_types": ["nation-state"],
                    "primary_motivation": "espionage",
                    "confidence": 90,
                    "object_marking_refs": ["marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"],
                },
                {
                    "type": "campaign",
                    "spec_version": "2.1",
                    "id": "campaign--op-glass",
                    "name": "Operation Glass Horizon",
                    "objective": "Telecom reconnaissance",
                    "confidence": 85,
                },
                {
                    "type": "malware",
                    "spec_version": "2.1",
                    "id": "malware--glass-beacon",
                    "name": "GlassBeacon",
                    "is_family": True,
                    "malware_types": ["backdoor"],
                    "confidence": 92,
                },
                {
                    "type": "infrastructure",
                    "spec_version": "2.1",
                    "id": "infrastructure--c2-node-01",
                    "name": "Mirage Core C2",
                    "infrastructure_types": ["command-and-control"],
                    "confidence": 88,
                },
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": "indicator--ioc-c2-ip",
                    "pattern": "[ipv4-addr:value = '198.51.100.88']",
                    "indicator_types": ["malicious-activity"],
                    "valid_from": "2026-10-01T00:00:00Z",
                    "confidence": 95,
                },
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": "relationship--rel-1",
                    "relationship_type": "uses",
                    "source_ref": "threat-actor--apt42-osint",
                    "target_ref": "malware--glass-beacon",
                    "confidence": 90,
                },
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": "relationship--rel-2",
                    "relationship_type": "indicates",
                    "source_ref": "indicator--ioc-c2-ip",
                    "target_ref": "infrastructure--c2-node-01",
                    "confidence": 90,
                },
            ],
        }
        result = self.service.ingest_stix21_bundle(bundle, source_id="circl-misp-feed")
        assert len(result["threat_actors"]) == 1
        assert result["threat_actors"][0].tlp_marking == "TLP:AMBER"
        assert result["threat_actors"][0].confidence == 0.9
        assert result["threat_actors"][0].verification_status == "verified"
        assert len(result["campaigns"]) == 1
        assert len(result["malware"]) == 1
        assert len(result["infrastructure"]) == 1
        assert len(result["indicators"]) == 1
        assert result["indicators"][0].normalized_value == "198.51.100.88"
        assert len(result["relationships"]) == 2
        assert result["relationships"][0].relationship_type == "USES"
        assert result["relationships"][1].relationship_type == "INDICATES"

    def test_taxii21_envelope_and_sync_state(self):
        collection = TAXII21CollectionModel(
            id="col-otx-001",
            title="OTX Public Threat Indicators",
            can_read=True,
            can_write=False,
        )
        envelope = {
            "more": True,
            "next": "cursor-page-02",
            "objects": [
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": "indicator--taxii-01",
                    "pattern": "[domain-name:value = 'login-update[.]example.net']",
                    "confidence": 80,
                }
            ],
        }
        res = self.service.ingest_taxii21_envelope(collection, envelope, api_root="/taxii2/root/")
        state: TAXII21SyncStateModel = res["taxii_sync_state"]
        assert state.collection_id == "col-otx-001"
        assert state.next_cursor == "cursor-page-02"
        assert state.objects_ingested == 1
        assert state.sync_status == "synced_fixture"
        assert state.verification_mode == "fixture_tested"

        # Unreadable collection must raise SecurityError
        unreadable = TAXII21CollectionModel(id="col-private", title="Private", can_read=False)
        with pytest.raises(SecurityError):
            self.service.ingest_taxii21_envelope(unreadable, envelope)


class TestOSINTDeduplicationProvenanceAndConflicts:
    """Tests for deduplication, multi-source corroboration, Agent 3 M5 provenance invariant, and conflict handling"""

    def setup_method(self):
        self.service = OSINTIngestionService(tenant_id="tenant-osint-01")

    def test_indicator_deduplication_and_provenance_granularity(self):
        # First observation from URLhaus (defanged)
        ind1 = self.service.ingest_indicator({
            "indicator_id": "IOC-DOM-01",
            "indicator_type": "domain",
            "raw_value": "C2-Panel[.]EvilExample[.]org",
            "source_id": "abuse_ch_urlhaus",
            "confidence": 0.80,
        })
        # Second observation from OTX (canonical form) -> must deduplicate to same indicator_id
        ind2 = self.service.ingest_indicator({
            "indicator_type": "domain",
            "raw_value": "c2-panel.evilexample.org",
            "source_id": "alienvault_otx",
            "confidence": 0.85,
        })
        # Re-fetch from URLhaus -> observations count increases (3), but distinct sources remains 2 (Agent 3 M5 rule)
        ind3 = self.service.ingest_indicator({
            "indicator_type": "domain",
            "raw_value": "c2-panel.evilexample.org",
            "source_id": "abuse_ch_urlhaus",
            "confidence": 0.85,
        })

        assert ind1.indicator_id == ind2.indicator_id == ind3.indicator_id
        assert ind3.sources == ["abuse_ch_urlhaus", "alienvault_otx"]
        assert ind3.corroboration_count == 2
        assert ind3.confidence == 0.9  # 0.85 + 0.05 boost for 2 distinct sources
        observations = self.service.get_observations_for_entity(ind3.indicator_id)
        assert len(observations) == 3
        assert len(observations) > len(ind3.sources)

    def test_conflict_detection_and_resolution(self):
        # Source 1 asserts espionage with 0.90 confidence
        self.service.ingest_threat_actor({
            "actor_id": "TA-CONFLICT-01",
            "name": "ShadowLynx",
            "primary_motivation": "espionage",
            "source_id": "cert-eu",
            "confidence": 0.90,
        })
        # Source 2 asserts financial-gain with lower 0.65 confidence -> conflict recorded, espionage kept
        actor = self.service.ingest_threat_actor({
            "actor_id": "TA-CONFLICT-01",
            "name": "ShadowLynx",
            "primary_motivation": "financial-gain",
            "source_id": "open-blog-feed",
            "confidence": 0.65,
        })
        assert actor.primary_motivation == "espionage"
        assert actor.corroboration_count == 2
        conflicts = self.service.get_conflicts_for_entity("TA-CONFLICT-01")
        assert len(conflicts) == 1
        assert conflicts[0].field_name == "primary_motivation"
        assert conflicts[0].kept_value == "espionage"
        assert conflicts[0].discarded_values == ["financial-gain"]
        assert conflicts[0].dissenting_sources == ["open-blog-feed"]

    def test_urlhaus_and_malwarebazaar_connectors(self):
        url_ioc = self.service.parse_urlhaus_entry({
            "id": "2900112",
            "url": "hxxp://198.51.100[.]99/loader.exe",
            "tags": ["emotet", "exe"],
            "dateadded": "2026-11-04T12:00:00Z",
        })
        assert url_ioc.indicator_type == "url"
        assert url_ioc.normalized_value == "http://198.51.100.99/loader.exe"
        assert url_ioc.verification_status == "verified"

        hash_val = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        mb_ioc, mb_mal = self.service.parse_malwarebazaar_entry({
            "sha256_hash": hash_val,
            "signature": "AgentTesla",
            "tags": ["stealer"],
            "first_seen": "2026-11-01T08:30:00Z",
        })
        assert mb_ioc.indicator_type == "sha256"
        assert mb_ioc.normalized_value == hash_val
        assert mb_mal is not None
        assert mb_mal.name == "AgentTesla"

    def test_malicious_input_protection_and_circuit_breaker(self):
        self.service.register_source({
            "source_id": "untrusted-osint",
            "source_name": "Untrusted OSINT",
            "provider_type": "generic_osint",
        })
        with pytest.raises(SecurityError):
            self.service.ingest_threat_actor({
                "actor_id": "TA-XSS",
                "name": "<script>alert('xss')</script>",
            })

        # Simulate 3 consecutive collection failures -> circuit breaker opens & source marked unavailable
        for _ in range(3):
            self.service.record_collection_failure("untrusted-osint", TimeoutError("Upstream feed timeout"))

        assert len(self.service._failed_collections) == 3
        assert self.service._resilience_config["circuit_breaker_state"] == "OPEN"
        assert self.service._sources["untrusted-osint"].health_status == "unavailable"

        with pytest.raises(SecurityError):
            self.service.ingest_campaign({"campaign_id": "CAMP-BLOCKED", "name": "Blocked while breaker OPEN"})

        self.service.reset_circuit_breaker()
        camp = self.service.ingest_campaign({"campaign_id": "CAMP-RECOVERED", "name": "Recovered"})
        assert camp.campaign_id == "CAMP-RECOVERED"

    def test_expired_indicator_and_confidence_conflict(self):
        past_dt = datetime.utcnow() - timedelta(days=5)
        ind = self.service.ingest_indicator({
            "indicator_id": "IOC-EXP-01",
            "indicator_type": "ipv4",
            "raw_value": "192.0.2.100",
            "valid_until": past_dt,
            "source_id": "source-high",
            "confidence": 0.95,
        })
        assert ind.is_expired is True

        # Second source with >0.4 confidence divergence triggers conflict record
        ind2 = self.service.ingest_indicator({
            "indicator_type": "ipv4",
            "raw_value": "192.0.2.100",
            "source_id": "source-low",
            "confidence": 0.45,
        })
        assert ind2.corroboration_count == 2
        conflicts = self.service.get_conflicts_for_entity("IOC-EXP-01")
        assert len(conflicts) == 1
        assert conflicts[0].field_name == "confidence"
        assert conflicts[0].kept_value == 0.95
        assert conflicts[0].discarded_values == [0.45]

    def test_campaign_malware_infra_relationship_corroboration(self):
        self.service.ingest_campaign({"campaign_id": "CAMP-01", "name": "Op1", "source_id": "s1", "confidence": 0.8})
        c2 = self.service.ingest_campaign({"campaign_id": "CAMP-01", "name": "Op1", "source_id": "s2", "confidence": 0.85})
        assert c2.corroboration_count == 2
        assert c2.confidence == 0.9

        self.service.ingest_malware({"malware_id": "MAL-01", "name": "Mal1", "source_id": "s1", "confidence": 0.8})
        m2 = self.service.ingest_malware({"malware_id": "MAL-01", "name": "Mal1", "source_id": "s2", "confidence": 0.85})
        assert m2.corroboration_count == 2

        self.service.ingest_infrastructure({"infrastructure_id": "INF-01", "name": "Inf1", "source_id": "s1", "confidence": 0.8})
        i2 = self.service.ingest_infrastructure({"infrastructure_id": "INF-01", "name": "Inf1", "source_id": "s2", "confidence": 0.85})
        assert i2.corroboration_count == 2

        self.service.ingest_relationship({
            "relationship_id": "REL-CORR-01",
            "source_entity_id": "MAL-01",
            "source_entity_type": "Malware",
            "target_entity_id": "INF-01",
            "target_entity_type": "Infrastructure",
            "relationship_type": "COMMUNICATES_WITH",
            "source_id": "s1",
            "confidence": 0.8,
        })
        r2 = self.service.ingest_relationship({
            "relationship_id": "REL-CORR-01",
            "source_entity_id": "MAL-01",
            "source_entity_type": "Malware",
            "target_entity_id": "INF-01",
            "target_entity_type": "Infrastructure",
            "relationship_type": "COMMUNICATES_WITH",
            "source_id": "s2",
            "confidence": 0.85,
        })
        assert r2.corroboration_count == 2
        assert self.service.detect_duplicates("REL-CORR-01", "relationship") is True

    def test_incompatible_stix_and_oversized_payload_protection(self):
        with pytest.raises(ValueError):
            self.service.ingest_stix21_bundle({"type": "not-a-bundle", "spec_version": "2.0", "objects": []})

        tiny_service = OSINTIngestionService(tenant_id="t1", max_payload_bytes=64)
        with pytest.raises(SecurityError):
            tiny_service.ingest_campaign({"campaign_id": "CAMP-BIG", "name": "X" * 200})

        manifest = TAXII21ManifestEntryModel(
            id="indicator--1234",
            date_added=datetime.utcnow(),
            version="2026-11-05T00:00:00Z",
        )
        assert manifest.media_type == "application/stix+json;version=2.1"
