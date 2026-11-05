"""
Tests for indicator enrichment (Domain B items 15-18: IP, domain, URL, file hash).

The honesty rules are the point of this file. Several tests exist only to prove that:
- nothing is invented (no built-in ASN/WHOIS/geo/family tables),
- unknown stays unknown,
- conflicting attribution is preserved rather than silently resolved,
- confidence clamping is reported rather than silent,
- live access is refused without the gate.
"""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from apps.threat_intelligence.cisa_kev import EXPERIMENTAL_DEMO_DATA_ONLY
from apps.threat_intelligence.indicator_enrichment import (
    ALLOWED_URL_SCHEMES,
    MAX_URL_LENGTH,
    ASNRecord,
    AttributionConflict,
    DNSRecordObservation,
    DNSRecordType,
    DomainEnrichmentRecord,
    DomainIntelligenceService,
    DomainRelationship,
    DomainRelationshipKind,
    EnrichmentHistoryEntry,
    EnrichmentObservation,
    EnrichmentState,
    EnrichmentValidationError,
    FileEnrichmentRecord,
    FileHashIntelligenceService,
    FileIdentity,
    GeolocationEvidence,
    HashAlgorithm,
    IPEnrichmentRecord,
    IndicatorEnrichmentError,
    IndicatorNotFoundError,
    NetworkBlock,
    ThreatVerdict,
    URLComponents,
    URLEnrichmentRecord,
    URLIntelligenceService,
    WhoisRecord,
    IPIntelligenceService,
)
from apps.threat_intelligence.live_source_readiness import (
    LiveAccessRefusedError,
    LiveSourceGate,
    LiveSourcePolicy,
    LiveSourceReadinessService,
    SourceSchema,
)
from apps.threat_intelligence.malware_families import MalwareFamilyService
from apps.threat_intelligence.relationship_analysis import AssertionOrigin

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)

MD5_HASH = "44d88612fea8a8f36de82e1278abb02f"
SHA1_HASH = "3395856ce81f2b7382dee72602f798b642f14140"
SHA256_HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _evidence(count: int = 1, *, distinct_sources: bool = True) -> list:
    rows = []
    for index in range(count):
        ref = f"https://evidence.example/{index}" if distinct_sources else "https://evidence.example/0"
        rows.append(
            {
                "evidence_id": f"ev-{index}",
                "kind": "url",
                "source_ref": ref,
                "retrieved_at": NOW,
                "description": f"supporting observation {index}",
            }
        )
    return rows


# ----------------------------------------------------------------------
# IP normalisation and classification
# ----------------------------------------------------------------------

class TestIPNormalisation:
    def test_ipv4_is_normalised(self):
        assert IPIntelligenceService.normalize("  8.8.8.8  ") == "8.8.8.8"

    def test_ipv6_is_compressed_and_lowercased(self):
        assert IPIntelligenceService.normalize("2001:0DB8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"

    def test_defanged_ipv4_is_refanged(self):
        assert IPIntelligenceService.normalize("8[.]8[.]8[.]8") == "8.8.8.8"

    def test_non_address_is_rejected(self):
        with pytest.raises(EnrichmentValidationError):
            IPIntelligenceService.normalize("not-an-address")

    def test_malformed_ipv4_is_rejected(self):
        with pytest.raises((EnrichmentValidationError, ValueError)):
            IPIntelligenceService.normalize("999.1.1.1")

    def test_address_classification_is_computed_not_source_supplied(self):
        """Private/global/version come from the address itself, so they cannot be fabricated."""
        service = IPIntelligenceService(tenant_id="t1")
        private = service.record_asn(
            "192.168.1.1",
            ASNRecord(asn=64512, source_id="s", source_reference="https://r", observed_at=NOW),
            now=NOW,
        )
        public = service.record_asn(
            "8.8.8.8",
            ASNRecord(asn=15169, source_id="s", source_reference="https://r", observed_at=NOW),
            now=NOW,
        )
        assert private.is_private is True and private.is_global is False
        assert public.is_private is False and public.is_global is True
        assert private.version == 4

    def test_ipv6_version_is_recorded(self):
        service = IPIntelligenceService(tenant_id="t1")
        record = service.record_asn(
            "2001:db8::1",
            ASNRecord(asn=1, source_id="s", source_reference="https://r", observed_at=NOW),
            now=NOW,
        )
        assert record.version == 6
        assert record.indicator_type == "ipv6"

    def test_address_is_a_stable_lookup_key_across_forms(self):
        service = IPIntelligenceService(tenant_id="t1")
        service.record_asn(
            "2001:0DB8::1",
            ASNRecord(asn=1, source_id="s", source_reference="https://r", observed_at=NOW),
            now=NOW,
        )
        assert service.get("2001:db8:0:0:0:0:0:1") is not None


# ----------------------------------------------------------------------
# Item 15 - IP enrichment
# ----------------------------------------------------------------------

class TestIPIntelligence:
    def _asn(self, **kwargs) -> ASNRecord:
        defaults = dict(asn=15169, name="GOOGLE", country="US", registry="arin",
                        source_id="rir", source_reference="https://stat.ripe.net/AS15169",
                        observed_at=NOW)
        defaults.update(kwargs)
        return ASNRecord(**defaults)

    def test_record_asn_creates_an_enriched_record(self):
        service = IPIntelligenceService(tenant_id="t1")
        record = service.record_asn(
            "8.8.8.8", self._asn(), origin=AssertionOrigin.DIRECTLY_SOURCED,
            confidence=0.95, now=NOW
        )
        assert isinstance(record, IPEnrichmentRecord)
        assert record.asn.asn == 15169
        assert record.enrichment_state == EnrichmentState.ENRICHED
        assert record.provider == "GOOGLE"

    def test_nothing_is_invented_without_a_recorded_enrichment(self):
        """The service holds no built-in ASN table: an unrecorded address reports nothing."""
        service = IPIntelligenceService(tenant_id="t1")
        assert service.get("8.8.8.8") is None
        assert service.list_records() == []
        assert service.stats()["records"] == 0

    def test_verified_asn_requires_a_source_reference(self):
        with pytest.raises(ValidationError):
            ASNRecord(asn=15169, source_id="rir", verified=True, observed_at=NOW)

    def test_unverified_asn_needs_no_reference(self):
        record = ASNRecord(asn=15169, source_id="rir", observed_at=NOW)
        assert record.verified is False

    def test_record_network_validates_the_cidr(self):
        service = IPIntelligenceService(tenant_id="t1")
        with pytest.raises(ValidationError):
            NetworkBlock(cidr="not-a-cidr", source_id="s", observed_at=NOW)

    def test_record_network_is_normalised(self):
        service = IPIntelligenceService(tenant_id="t1")
        record = service.record_network(
            "8.8.8.8",
            NetworkBlock(cidr="8.8.8.0/24", organisation="Google LLC", handle="NET-8-8-8-0-1",
                         source_id="arin", observed_at=NOW),
            now=NOW,
        )
        assert record.network.cidr == "8.8.8.0/24"
        assert record.provider == "Google LLC"

    def test_provider_prefers_network_organisation_over_asn_name(self):
        service = IPIntelligenceService(tenant_id="t1")
        service.record_asn("8.8.8.8", self._asn(name="GOOGLE"), now=NOW)
        record = service.record_network(
            "8.8.8.8", NetworkBlock(cidr="8.8.8.0/24", organisation="Google LLC",
                                    source_id="arin", observed_at=NOW),
            now=NOW,
        )
        assert record.provider == "Google LLC"

    def test_geolocation_carries_the_sources_own_accuracy_claim(self):
        """Geo-IP is an estimate; the stated accuracy keeps it one."""
        service = IPIntelligenceService(tenant_id="t1")
        record = service.record_geolocation(
            "8.8.8.8",
            GeolocationEvidence(country="US", region="California", city="Mountain View",
                                latitude=37.4, longitude=-122.07, accuracy_radius_km=1000.0,
                                source_id="geoip", source_reference="https://geoip.example",
                                observed_at=NOW),
            now=NOW,
        )
        assert record.geolocation.accuracy_radius_km == 1000.0
        assert record.geolocation.country == "US"

    def test_geolocation_coordinates_are_range_checked(self):
        with pytest.raises(ValidationError):
            GeolocationEvidence(latitude=91.0, source_id="s", observed_at=NOW)
        with pytest.raises(ValidationError):
            GeolocationEvidence(longitude=-181.0, source_id="s", observed_at=NOW)

    def test_malicious_verdict_requires_evidence(self):
        """An unverified accusation must not land where downstream systems treat it as fact."""
        service = IPIntelligenceService(tenant_id="t1")
        with pytest.raises(EnrichmentValidationError):
            service.record_verdict("8.8.8.8", ThreatVerdict.MALICIOUS, source_id="s", now=NOW)

    def test_malicious_verdict_with_evidence_is_accepted(self):
        service = IPIntelligenceService(tenant_id="t1")
        record = service.record_verdict(
            "8.8.8.8", ThreatVerdict.MALICIOUS, source_id="abuse", evidence=_evidence(1), now=NOW
        )
        assert record.verdict == ThreatVerdict.MALICIOUS

    def test_benign_verdict_needs_no_evidence(self):
        service = IPIntelligenceService(tenant_id="t1")
        record = service.record_verdict("8.8.8.8", ThreatVerdict.BENIGN, source_id="s", now=NOW)
        assert record.verdict == ThreatVerdict.BENIGN

    def test_verdict_defaults_to_unknown_not_benign(self):
        """Absence of data is not a claim of innocence."""
        service = IPIntelligenceService(tenant_id="t1")
        record = service.record_asn("8.8.8.8", self._asn(), now=NOW)
        assert record.verdict == ThreatVerdict.UNKNOWN

    def test_confidence_is_capped_by_origin_and_clamping_is_reported(self):
        service = IPIntelligenceService(tenant_id="t1")
        service.record_asn(
            "1.1.1.1",
            ASNRecord(asn=13335, name="CLOUDFLARE", source_id="sandbox", observed_at=NOW),
            origin=AssertionOrigin.MACHINE_INFERRED, confidence=0.99, now=NOW
        )
        observation = service.observations_for("1.1.1.1")[0]
        assert observation.confidence == 0.60
        assert observation.confidence_ceiling == 0.60
        assert observation.confidence_was_clamped is True

    def test_confidence_below_the_ceiling_is_not_clamped(self):
        service = IPIntelligenceService(tenant_id="t1")
        service.record_asn(
            "8.8.8.8", self._asn(), origin=AssertionOrigin.DIRECTLY_SOURCED,
            confidence=0.4, now=NOW
        )
        observation = service.observations_for("8.8.8.8")[0]
        assert observation.confidence == 0.4
        assert observation.confidence_was_clamped is False

    def test_out_of_range_confidence_is_rejected(self):
        service = IPIntelligenceService(tenant_id="t1")
        with pytest.raises(EnrichmentValidationError):
            service.record_asn("8.8.8.8", self._asn(), confidence=1.5, now=NOW)

    def test_conflicting_asn_from_two_sources_is_preserved(self):
        """Neither view is overwritten; the record reports the conflict."""
        service = IPIntelligenceService(tenant_id="t1")
        service.record_asn("8.8.8.8", self._asn(asn=15169, name="GOOGLE"), now=NOW)
        service.record_asn(
            "8.8.8.8",
            ASNRecord(asn=99999, name="SOMETHING-ELSE", source_id="other",
                      source_reference="https://other.example", observed_at=NOW),
            now=NOW,
        )
        conflicts = service.conflicts()
        assert len(conflicts) == 1
        assert isinstance(conflicts[0], AttributionConflict)
        assert conflicts[0].field_name == "asn"
        assert set(conflicts[0].distinct_values) == {"15169", "99999"}
        assert dict(conflicts[0].values) == {"15169": "rir", "99999": "other"}

    def test_conflicting_record_is_marked_conflicting(self):
        service = IPIntelligenceService(tenant_id="t1")
        service.record_asn("8.8.8.8", self._asn(), now=NOW)
        service.record_asn(
            "8.8.8.8",
            ASNRecord(asn=1, name="OTHER", source_id="other",
                      source_reference="https://o", observed_at=NOW),
            now=NOW,
        )
        assert service.get("8.8.8.8").enrichment_state == EnrichmentState.CONFLICTING

    def test_two_sources_agreeing_is_not_a_conflict(self):
        service = IPIntelligenceService(tenant_id="t1")
        service.record_asn("8.8.8.8", self._asn(), now=NOW)
        service.record_asn("8.8.8.8", self._asn(source_id="rir-mirror"), now=NOW)
        assert service.conflicts() == []

    def test_observations_are_appended_not_overwritten(self):
        service = IPIntelligenceService(tenant_id="t1")
        service.record_asn("8.8.8.8", self._asn(), now=NOW)
        service.record_asn("8.8.8.8", self._asn(source_id="rir-2"), now=NOW)
        assert len(service.observations_for("8.8.8.8")) == 2

    def test_observation_payload_preserves_the_source_values_verbatim(self):
        service = IPIntelligenceService(tenant_id="t1")
        service.record_asn("8.8.8.8", self._asn(), now=NOW)
        payload = service.observations_for("8.8.8.8")[0].payload
        assert payload["asn"] == 15169
        assert payload["name"] == "GOOGLE"

    def test_first_and_last_seen_track_the_observations(self):
        from datetime import timedelta

        service = IPIntelligenceService(tenant_id="t1")
        service.record_asn(
            "8.8.8.8", self._asn(observed_at=NOW - timedelta(days=30)), now=NOW
        )
        service.record_asn(
            "8.8.8.8", self._asn(source_id="s2", observed_at=NOW), now=NOW
        )
        record = service.get("8.8.8.8")
        assert record.first_seen == NOW - timedelta(days=30)
        assert record.last_seen == NOW

    def test_history_records_every_event(self):
        service = IPIntelligenceService(tenant_id="t1")
        service.record_asn("8.8.8.8", self._asn(), now=NOW)
        service.record_verdict("8.8.8.8", ThreatVerdict.BENIGN, source_id="s", now=NOW)
        actions = [h.action for h in service.history_for("8.8.8.8")]
        assert actions == ["asn_recorded", "verdict_recorded"]
        assert all(isinstance(h, EnrichmentHistoryEntry) for h in service.history_for("8.8.8.8"))

    def test_require_raises_when_nothing_is_recorded(self):
        with pytest.raises(IndicatorNotFoundError):
            IPIntelligenceService(tenant_id="t1").require("8.8.8.8")

    def test_search_filters(self):
        service = IPIntelligenceService(tenant_id="t1")
        service.record_asn("8.8.8.8", self._asn(), now=NOW)
        service.record_geolocation(
            "1.1.1.1",
            GeolocationEvidence(country="AU", source_id="geo", observed_at=NOW), now=NOW
        )
        service.record_network(
            "192.168.0.1", NetworkBlock(cidr="192.168.0.0/24", source_id="rfc1918", observed_at=NOW),
            now=NOW,
        )
        assert len(service.search(has_asn=True)) == 1
        assert [r.address for r in service.search(country="au")] == ["1.1.1.1"]
        assert [r.address for r in service.search(is_private=True)] == ["192.168.0.1"]
        assert service.search(has_asn=True, country="au") == []

    def test_search_paginates(self):
        service = IPIntelligenceService(tenant_id="t1")
        for index in range(5):
            service.record_asn(
                f"8.8.8.{index}", self._asn(), now=NOW
            )
        assert len(service.search(limit=2)) == 2
        assert len(service.search(limit=2, offset=2)) == 2
        assert len(service.search(limit=2, offset=4)) == 1

    def test_search_rejects_negative_pagination(self):
        with pytest.raises(EnrichmentValidationError):
            IPIntelligenceService(tenant_id="t1").search(limit=-1)

    def test_blank_tenant_is_rejected(self):
        with pytest.raises(EnrichmentValidationError):
            IPIntelligenceService(tenant_id="   ")

    def test_stats_reports_verification_honesty(self):
        stats = IPIntelligenceService(tenant_id="t1").stats()
        assert stats["verification_mode"] == "fixture_tested_only_no_outbound_requests"
        assert stats["records"] == 0

    def test_stats_counts_verdicts_and_enrichment(self):
        service = IPIntelligenceService(tenant_id="t1")
        service.record_asn("8.8.8.8", self._asn(), now=NOW)
        service.record_verdict("8.8.8.8", ThreatVerdict.BENIGN, source_id="s", now=NOW)
        stats = service.stats()
        assert stats["records"] == 1
        assert stats["with_asn"] == 1
        assert stats["verdicts"]["benign"] == 1

    def test_records_are_tenant_isolated(self):
        first = IPIntelligenceService(tenant_id="t1")
        second = IPIntelligenceService(tenant_id="t2")
        first.record_asn("8.8.8.8", self._asn(), now=NOW)
        assert second.get("8.8.8.8") is None
        assert len(second.list_records()) == 0


# ----------------------------------------------------------------------
# Item 16 - Domain enrichment
# ----------------------------------------------------------------------

class TestDomainIntelligence:
    def _service(self) -> DomainIntelligenceService:
        return DomainIntelligenceService(tenant_id="t1")

    def test_domain_is_normalised(self):
        assert DomainIntelligenceService.normalize("  EVIL[.]COM.  ") == "evil.com"

    def test_record_dns_appends_an_observation(self):
        service = self._service()
        record = service.record_dns(
            "example.com",
            DNSRecordObservation(record_type=DNSRecordType.A, value="93.184.216.34",
                                 ttl_seconds=300, source_id="dns", observed_at=NOW),
            now=NOW,
        )
        assert isinstance(record, DomainEnrichmentRecord)
        assert len(record.dns_records) == 1
        assert record.enrichment_state == EnrichmentState.ENRICHED

    def test_blank_dns_value_is_rejected(self):
        with pytest.raises(ValidationError):
            DNSRecordObservation(record_type=DNSRecordType.A, value="   ", source_id="s")

    def test_resolved_addresses_come_only_from_a_and_aaaa(self):
        service = self._service()
        service.record_dns(
            "example.com",
            DNSRecordObservation(record_type=DNSRecordType.A, value="93.184.216.34",
                                 source_id="dns", observed_at=NOW),
            now=NOW,
        )
        service.record_dns(
            "example.com",
            DNSRecordObservation(record_type=DNSRecordType.MX, value="10 mail.example.com",
                                 source_id="dns", observed_at=NOW),
            now=NOW,
        )
        assert service.get("example.com").resolved_addresses == ("93.184.216.34",)

    def test_nameservers_are_normalised_and_deduplicated(self):
        whois = WhoisRecord(registrar="R", nameservers=["NS1.EXAMPLE.COM.", "ns1.example.com"],
                            source_id="rdap", observed_at=NOW)
        assert whois.nameservers == ["ns1.example.com"]

    def test_nameservers_prefer_dns_over_whois(self):
        service = self._service()
        service.record_whois(
            "example.com",
            WhoisRecord(registrar="R", nameservers=["whois-ns.example.com"],
                        source_id="rdap", observed_at=NOW),
            now=NOW,
        )
        service.record_dns(
            "example.com",
            DNSRecordObservation(record_type=DNSRecordType.NS, value="dns-ns.example.com",
                                 source_id="dns", observed_at=NOW),
            now=NOW,
        )
        assert service.get("example.com").nameservers == ("dns-ns.example.com",)

    def test_nameservers_fall_back_to_whois(self):
        service = self._service()
        service.record_whois(
            "example.com",
            WhoisRecord(registrar="R", nameservers=["whois-ns.example.com"],
                        source_id="rdap", observed_at=NOW),
            now=NOW,
        )
        assert service.get("example.com").nameservers == ("whois-ns.example.com",)

    def test_no_whois_means_no_registrar(self):
        service = self._service()
        service.record_dns(
            "example.com",
            DNSRecordObservation(record_type=DNSRecordType.A, value="1.2.3.4",
                                 source_id="dns", observed_at=NOW),
            now=NOW,
        )
        assert service.get("example.com").registrar is None
        assert service.get("example.com").whois is None

    def test_whois_protocol_is_restricted(self):
        with pytest.raises(ValidationError):
            WhoisRecord(registrar="R", protocol="dns-zone-transfer", source_id="s", observed_at=NOW)

    def test_rdap_is_accepted(self):
        whois = WhoisRecord(registrar="R", protocol="rdap", source_id="s", observed_at=NOW)
        assert whois.protocol == "rdap"

    def test_conflicting_registrar_is_flagged_and_both_kept(self):
        service = self._service()
        service.record_whois(
            "example.com",
            WhoisRecord(registrar="First Registrar", source_id="rdap", observed_at=NOW),
            now=NOW,
        )
        service.record_whois(
            "example.com",
            WhoisRecord(registrar="Second Registrar", source_id="whois", observed_at=NOW),
            now=NOW,
        )
        record = service.get("example.com")
        assert record.enrichment_state == EnrichmentState.CONFLICTING
        # The earlier claim survives in the observation history.
        registrars = {o.payload.get("registrar") for o in service.observations_for("example.com")}
        assert registrars == {"First Registrar", "Second Registrar"}

    def test_same_registrar_from_two_sources_is_not_a_conflict(self):
        service = self._service()
        service.record_whois(
            "example.com",
            WhoisRecord(registrar="Same", source_id="rdap", observed_at=NOW), now=NOW
        )
        service.record_whois(
            "example.com",
            WhoisRecord(registrar="Same", source_id="whois", observed_at=NOW), now=NOW
        )
        assert service.get("example.com").enrichment_state == EnrichmentState.ENRICHED

    def test_parent_relationship_is_derived_from_the_name(self):
        """This is the one derivation the service performs, because it follows from the name."""
        service = self._service()
        service.record_dns(
            "a.example.com",
            DNSRecordObservation(record_type=DNSRecordType.A, value="1.2.3.4",
                                 source_id="dns", observed_at=NOW),
            now=NOW,
        )
        service.derive_parent_relationships("a.example.com", now=NOW)
        relationships = service.get("a.example.com").relationships
        assert len(relationships) == 1
        assert relationships[0].kind == DomainRelationshipKind.PARENT
        assert relationships[0].other_domain == "example.com"
        assert "derived" in relationships[0].basis

    def test_parent_derivation_is_idempotent(self):
        service = self._service()
        service.derive_parent_relationships("a.example.com", now=NOW)
        service.derive_parent_relationships("a.example.com", now=NOW)
        assert len(service.get("a.example.com").relationships) == 1

    def test_two_label_domain_has_no_parent(self):
        service = self._service()
        service.derive_parent_relationships("example.com", now=NOW)
        assert service.get("example.com").relationships == []

    def test_sibling_relationships_need_a_stated_basis(self):
        """Shared infrastructure is a lead, not proof of common ownership."""
        service = self._service()
        service.record_dns(
            "a.example.com",
            DNSRecordObservation(record_type=DNSRecordType.NS, value="ns1.shared.com",
                                 source_id="dns", observed_at=NOW),
            now=NOW,
        )
        service.record_dns(
            "b.other.org",
            DNSRecordObservation(record_type=DNSRecordType.NS, value="ns1.shared.com",
                                 source_id="dns", observed_at=NOW),
            now=NOW,
        )
        found = service.derive_sibling_relationships("a.example.com", now=NOW)
        assert len(found) == 1
        assert found[0].kind == DomainRelationshipKind.SIBLING_NAMESERVER
        assert found[0].other_domain == "b.other.org"
        assert "ns1.shared.com" in found[0].basis

    def test_sibling_via_shared_registrar(self):
        service = self._service()
        for domain in ("one.example.com", "two.other.org"):
            service.record_whois(
                domain,
                WhoisRecord(registrar="Same Registrar", source_id="rdap", observed_at=NOW),
                now=NOW,
            )
        found = service.derive_sibling_relationships("one.example.com", now=NOW)
        assert len(found) == 1
        assert found[0].kind == DomainRelationshipKind.SIBLING_REGISTRAR

    def test_a_domain_is_not_its_own_sibling(self):
        service = self._service()
        service.record_dns(
            "a.example.com",
            DNSRecordObservation(record_type=DNSRecordType.NS, value="ns1.shared.com",
                                 source_id="dns", observed_at=NOW),
            now=NOW,
        )
        assert service.derive_sibling_relationships("a.example.com", now=NOW) == []

    def test_sibling_lookup_on_unknown_domain_returns_empty(self):
        assert self._service().derive_sibling_relationships("nothing.example", now=NOW) == []

    def test_relationship_requires_a_basis(self):
        with pytest.raises(ValidationError):
            DomainRelationship(
                kind=DomainRelationshipKind.PARENT, other_domain="example.com",
                basis="   ", source_id="s", observed_at=NOW
            )

    def test_duplicate_relationship_is_not_stored_twice(self):
        service = self._service()
        rel = DomainRelationship(kind=DomainRelationshipKind.PARENT, other_domain="example.com",
                                 basis="derived", source_id="s", observed_at=NOW)
        service.record_relationship("a.example.com", rel, now=NOW)
        service.record_relationship("a.example.com", rel, now=NOW)
        assert len(service.get("a.example.com").relationships) == 1

    def test_malicious_verdict_requires_evidence(self):
        service = self._service()
        with pytest.raises(EnrichmentValidationError):
            service.record_verdict("evil.com", ThreatVerdict.MALICIOUS, source_id="s", now=NOW)

    def test_malicious_verdict_with_evidence_is_accepted(self):
        service = self._service()
        record = service.record_verdict(
            "evil.com", ThreatVerdict.MALICIOUS, source_id="s", evidence=_evidence(1), now=NOW
        )
        assert record.verdict == ThreatVerdict.MALICIOUS

    def test_search_filters(self):
        service = self._service()
        service.record_whois(
            "a.example.com",
            WhoisRecord(registrar="RegistrarA", nameservers=["ns1.a.com"], source_id="rdap",
                        observed_at=NOW),
            now=NOW,
        )
        service.record_dns(
            "b.other.org",
            DNSRecordObservation(record_type=DNSRecordType.NS, value="ns2.b.com",
                                 source_id="dns", observed_at=NOW),
            now=NOW,
        )
        assert [r.domain for r in service.search(registrar="registrara")] == ["a.example.com"]
        assert [r.domain for r in service.search(nameserver="ns2.b.com")] == ["b.other.org"]
        assert [r.domain for r in service.search(has_whois=True)] == ["a.example.com"]
        assert [r.domain for r in service.search(has_whois=False)] == ["b.other.org"]

    def test_history_records_events(self):
        service = self._service()
        service.record_dns(
            "example.com",
            DNSRecordObservation(record_type=DNSRecordType.A, value="1.2.3.4",
                                 source_id="dns", observed_at=NOW),
            now=NOW,
        )
        service.record_whois(
            "example.com", WhoisRecord(registrar="R", source_id="rdap", observed_at=NOW), now=NOW
        )
        assert [h.action for h in service.history_for("example.com")] == [
            "dns_recorded", "whois_recorded"
        ]

    def test_stats_reports_verification_honesty(self):
        stats = self._service().stats()
        assert stats["verification_mode"] == "fixture_tested_only_no_outbound_requests"
        assert stats["records"] == 0


# ----------------------------------------------------------------------
# Item 17 - URL enrichment
# ----------------------------------------------------------------------

class TestURLIntelligence:
    def _service(self) -> URLIntelligenceService:
        return URLIntelligenceService(tenant_id="t1")

    def test_url_is_normalised(self):
        assert URLIntelligenceService.normalize("  HTTPS://EVIL[.]COM/Path  ") == "https://evil.com/Path"

    def test_defanged_url_is_refanged(self):
        assert URLIntelligenceService.normalize("hxxps://evil[.]com/x") == "https://evil.com/x"

    def test_empty_path_becomes_root(self):
        assert URLIntelligenceService.normalize("https://evil.com") == "https://evil.com/"

    def test_javascript_scheme_is_refused(self):
        """A stored-XSS hazard if echoed into a UI, so refused rather than stored optimistically."""
        with pytest.raises((EnrichmentValidationError, ValueError)):
            URLIntelligenceService.normalize("javascript:alert(1)")

    def test_data_scheme_is_refused(self):
        with pytest.raises((EnrichmentValidationError, ValueError)):
            URLIntelligenceService.normalize("data:text/html,<script>")

    def test_ftp_scheme_is_refused(self):
        with pytest.raises((EnrichmentValidationError, ValueError)):
            URLIntelligenceService.normalize("ftp://evil.com/x")

    def test_only_http_and_https_are_allowed(self):
        assert ALLOWED_URL_SCHEMES == frozenset({"http", "https"})

    def test_embedded_credentials_are_refused(self):
        with pytest.raises(EnrichmentValidationError):
            URLIntelligenceService.normalize("https://user:password@evil.com/x")

    def test_oversized_url_is_refused(self):
        with pytest.raises(EnrichmentValidationError):
            URLIntelligenceService.normalize("https://evil.com/" + "a" * (MAX_URL_LENGTH + 100))

    def test_hostless_url_is_refused(self):
        with pytest.raises((EnrichmentValidationError, ValueError)):
            URLIntelligenceService.normalize("https:///path")

    def test_parse_extracts_components_without_a_request(self):
        components = URLIntelligenceService.parse("https://evil.com:8443/a/b?x=1#frag")
        assert isinstance(components, URLComponents)
        assert components.scheme == "https"
        assert components.host == "evil.com"
        assert components.port == 8443
        assert components.path == "/a/b"
        assert components.query == "x=1"
        assert components.fragment == "frag"

    def test_host_is_lowercased(self):
        assert URLIntelligenceService.parse("https://EVIL.COM/x").host == "evil.com"

    def test_urlhaus_record_populates_the_record(self):
        service = self._service()
        record = service.record_urlhaus(
            "https://evil.com/payload.exe",
            urlhaus_id="1234567",
            source_reference="https://urlhaus.abuse.ch/url/1234567/",
            threat_type="exe_download",
            tags=["Emotet"],
            evidence=_evidence(1),
            origin=AssertionOrigin.DIRECTLY_SOURCED,
            confidence=0.9,
            now=NOW,
        )
        assert isinstance(record, URLEnrichmentRecord)
        assert record.urlhaus_id == "1234567"
        assert record.threat_type == "exe_download"
        assert record.verdict == ThreatVerdict.MALICIOUS
        assert record.host_domain == "evil.com"

    def test_tags_are_deduplicated_and_lowercased(self):
        service = self._service()
        record = service.record_urlhaus(
            "https://evil.com/x", urlhaus_id="1", tags=["Emotet", "emotet", " TRICKBOT "],
            evidence=_evidence(1), now=NOW
        )
        assert record.tags == ["emotet", "trickbot"]

    def test_malicious_urlhaus_record_requires_evidence(self):
        service = self._service()
        with pytest.raises(EnrichmentValidationError):
            service.record_urlhaus("https://evil.com/x", urlhaus_id="1", now=NOW)

    def test_benign_urlhaus_record_needs_no_evidence(self):
        service = self._service()
        record = service.record_urlhaus(
            "https://ok.com/x", urlhaus_id="1", verdict=ThreatVerdict.BENIGN, now=NOW
        )
        assert record.verdict == ThreatVerdict.BENIGN

    def test_redirect_chain_needs_two_hops(self):
        """This service never follows a redirect, so a single hop records nothing."""
        service = self._service()
        with pytest.raises(EnrichmentValidationError) as exc:
            service.record_redirect_chain(
                "https://evil.com/x", ["https://evil.com/x"], source_id="s", now=NOW
            )
        assert "does not follow redirects" in str(exc.value)

    def test_empty_redirect_chain_is_rejected(self):
        service = self._service()
        with pytest.raises(EnrichmentValidationError):
            service.record_redirect_chain("https://evil.com/x", [], source_id="s", now=NOW)

    def test_redirect_chain_is_stored_normalised(self):
        service = self._service()
        service.record_redirect_chain(
            "https://t.co/abc",
            ["https://t.co/abc", "https://bit.ly/x", "https://evil.com/final"],
            source_id="crawler",
            now=NOW,
        )
        chain = service.get("https://t.co/abc").redirect_chain
        assert chain == ["https://t.co/abc", "https://bit.ly/x", "https://evil.com/final"]

    def test_redirect_chain_with_a_bad_hop_is_rejected_whole(self):
        service = self._service()
        with pytest.raises((EnrichmentValidationError, ValueError)):
            service.record_redirect_chain(
                "https://t.co/abc", ["https://t.co/abc", "javascript:alert(1)"],
                source_id="crawler", now=NOW
            )

    def test_for_host_groups_urls_by_host(self):
        service = self._service()
        service.record_urlhaus("https://evil.com/a", urlhaus_id="1", evidence=_evidence(1), now=NOW)
        service.record_urlhaus("https://evil.com/b", urlhaus_id="2", evidence=_evidence(1), now=NOW)
        service.record_urlhaus("https://other.com/c", urlhaus_id="3", evidence=_evidence(1), now=NOW)
        assert len(service.for_host("evil.com")) == 2
        assert len(service.for_host("EVIL.COM")) == 2

    def test_search_filters(self):
        service = self._service()
        service.record_urlhaus(
            "https://evil.com/a", urlhaus_id="1", threat_type="exe_download",
            tags=["emotet"], evidence=_evidence(1), now=NOW
        )
        service.record_urlhaus(
            "https://other.com/b", urlhaus_id="2", threat_type="html_download",
            evidence=_evidence(1), now=NOW
        )
        assert [r.url for r in service.search(host="evil.com")] == ["https://evil.com/a"]
        assert [r.url for r in service.search(threat_type="exe_download")] == ["https://evil.com/a"]
        assert [r.url for r in service.search(tag="emotet")] == ["https://evil.com/a"]
        assert len(service.search(has_urlhaus=True)) == 2

    def test_history_records_events(self):
        service = self._service()
        service.record_urlhaus("https://evil.com/a", urlhaus_id="1", evidence=_evidence(1), now=NOW)
        service.record_redirect_chain(
            "https://evil.com/a", ["https://evil.com/a", "https://evil.com/b"],
            source_id="crawler", now=NOW
        )
        assert [h.action for h in service.history_for("https://evil.com/a")] == [
            "urlhaus_recorded", "redirect_chain_recorded"
        ]

    def test_stats_counts_distinct_hosts(self):
        service = self._service()
        service.record_urlhaus("https://evil.com/a", urlhaus_id="1", evidence=_evidence(1), now=NOW)
        service.record_urlhaus("https://evil.com/b", urlhaus_id="2", evidence=_evidence(1), now=NOW)
        stats = service.stats()
        assert stats["records"] == 2
        assert stats["distinct_hosts"] == 1
        assert stats["verification_mode"] == "fixture_tested_only_no_outbound_requests"


# ----------------------------------------------------------------------
# Item 18 - File hash enrichment
# ----------------------------------------------------------------------

class TestFileHashIntelligence:
    def _service(self, **kwargs) -> FileHashIntelligenceService:
        return FileHashIntelligenceService(tenant_id="t1", **kwargs)

    def test_algorithm_detection(self):
        service = self._service()
        assert service.detect_algorithm(MD5_HASH) == HashAlgorithm.MD5
        assert service.detect_algorithm(SHA1_HASH) == HashAlgorithm.SHA1
        assert service.detect_algorithm(SHA256_HASH) == HashAlgorithm.SHA256

    def test_detection_is_case_insensitive(self):
        assert self._service().detect_algorithm(MD5_HASH.upper()) == HashAlgorithm.MD5

    def test_unrecognised_hash_is_rejected(self):
        with pytest.raises(EnrichmentValidationError):
            self._service().detect_algorithm("not-a-hash")

    def test_wrong_length_hex_is_rejected(self):
        with pytest.raises(EnrichmentValidationError):
            self._service().detect_algorithm("abc123")

    def test_canonicalize_lowercases(self):
        algorithm, canonical = self._service().canonicalize("  " + MD5_HASH.upper() + "  ")
        assert algorithm == HashAlgorithm.MD5
        assert canonical == MD5_HASH

    def test_identity_requires_at_least_one_hash(self):
        with pytest.raises(ValidationError):
            FileIdentity(file_name="x.exe")

    def test_record_identity_creates_a_record(self):
        service = self._service()
        record = service.record_identity(
            MD5_HASH,
            FileIdentity(md5=MD5_HASH, file_name="invoice.exe", file_size=204800,
                         file_type="PE32 executable"),
            source_id="mb",
            now=NOW,
        )
        assert isinstance(record, FileEnrichmentRecord)
        assert record.identity.file_name == "invoice.exe"

    def test_record_is_reachable_by_any_of_its_hashes(self):
        service = self._service()
        service.record_identity(
            MD5_HASH,
            FileIdentity(md5=MD5_HASH, sha1=SHA1_HASH, sha256=SHA256_HASH),
            source_id="mb",
            now=NOW,
        )
        assert service.get(SHA1_HASH).hash_value == MD5_HASH
        assert service.get(SHA256_HASH).hash_value == MD5_HASH

    def test_unknown_hash_returns_none_rather_raising(self):
        assert self._service().get("deadbeef") is None

    def test_unattributed_file_stays_unknown(self):
        """Unknown must stay unknown: never defaulted to a plausible family."""
        service = self._service()
        service.record_identity(
            MD5_HASH, FileIdentity(md5=MD5_HASH, file_name="invoice.exe"), source_id="mb", now=NOW
        )
        record = service.get(MD5_HASH)
        assert record.family_name is None
        assert record.attribution_state == EnrichmentState.UNKNOWN
        assert len(service.unattributed()) == 1

    def test_malwarebazaar_record_populates_the_record(self):
        service = self._service()
        record = service.record_malwarebazaar(
            MD5_HASH,
            malwarebazaar_id="abc-123",
            source_reference="https://mb-api.abuse.ch/api/v1/",
            signature="Emotet.Gen",
            file_name="invoice.exe",
            file_size=204800,
            file_type="exe",
            origin=AssertionOrigin.DIRECTLY_SOURCED,
            confidence=0.9,
            now=NOW,
        )
        assert record.malwarebazaar_id == "abc-123"
        assert record.signature == "Emotet.Gen"
        assert record.identity.file_name == "invoice.exe"

    def test_first_family_attribution_sets_the_family(self):
        service = self._service()
        service.record_family_attribution(
            MD5_HASH, "Emotet", source_id="vendor-a",
            origin=AssertionOrigin.DIRECTLY_SOURCED, confidence=0.9, now=NOW
        )
        record = service.get(MD5_HASH)
        assert record.family_name == "Emotet"
        assert record.attribution_state == EnrichmentState.ENRICHED

    def test_conflicting_attribution_preserves_both_sides(self):
        """The core requirement of item 18: never silently overwrite attribution."""
        service = self._service()
        service.record_family_attribution(MD5_HASH, "Emotet", source_id="vendor-a", now=NOW)
        service.record_family_attribution(MD5_HASH, "TrickBot", source_id="vendor-b", now=NOW)
        record = service.get(MD5_HASH)
        assert record.attribution_state == EnrichmentState.CONFLICTING
        assert dict(record.competing_families) == {"Emotet": "vendor-a", "TrickBot": "vendor-b"}
        # The original attribution is still readable.
        assert record.family_name == "Emotet"

    def test_conflicting_attribution_names_both_real_sources(self):
        """
        Regression: the first attributing source was recorded as the literal placeholder
        "first_attributing_source" instead of its real source id - fabricated provenance.
        """
        service = self._service()
        service.record_family_attribution(MD5_HASH, "Emotet", source_id="vendor-a", now=NOW)
        service.record_family_attribution(MD5_HASH, "TrickBot", source_id="vendor-b", now=NOW)
        sources = {src for _, src in service.get(MD5_HASH).competing_families}
        assert sources == {"vendor-a", "vendor-b"}
        assert "first_attributing_source" not in sources

    def test_first_attributing_source_is_tracked(self):
        service = self._service()
        service.record_family_attribution(MD5_HASH, "Emotet", source_id="vendor-a", now=NOW)
        assert service.get(MD5_HASH).first_attributing_source == "vendor-a"

    def test_disputed_family_link_is_cleared(self):
        """A contested attribution must not stay linked as if it were settled."""
        service = self._service()
        families = MalwareFamilyService(tenant_id="t1")
        profile = families.create_family(canonical_name="Emotet", now=NOW)
        linked = FileHashIntelligenceService(tenant_id="t1", family_service=families)
        linked.record_family_attribution(
            MD5_HASH, "Emotet", source_id="vendor-a", family_id=profile.family_id, now=NOW
        )
        assert linked.get(MD5_HASH).family_id == profile.family_id
        linked.record_family_attribution(MD5_HASH, "TrickBot", source_id="vendor-b", now=NOW)
        assert linked.get(MD5_HASH).family_id is None

    def test_same_attribution_from_a_second_source_is_idempotent(self):
        service = self._service()
        service.record_family_attribution(MD5_HASH, "Emotet", source_id="vendor-a", now=NOW)
        service.record_family_attribution(MD5_HASH, "emotet", source_id="vendor-b", now=NOW)
        record = service.get(MD5_HASH)
        assert record.attribution_state == EnrichmentState.ENRICHED
        assert record.family_name == "Emotet"
        assert set(record.attribution_sources) == {"vendor-a", "vendor-b"}

    def test_blank_family_name_is_rejected(self):
        service = self._service()
        with pytest.raises(EnrichmentValidationError):
            service.record_family_attribution(MD5_HASH, "   ", source_id="s", now=NOW)

    def test_unknown_family_id_is_rejected_when_a_family_service_is_supplied(self):
        families = MalwareFamilyService(tenant_id="t1")
        service = FileHashIntelligenceService(tenant_id="t1", family_service=families)
        with pytest.raises(EnrichmentValidationError):
            service.record_family_attribution(
                MD5_HASH, "Emotet", source_id="s", family_id="MWF-doesnotexist", now=NOW
            )

    def test_known_family_id_is_accepted(self):
        families = MalwareFamilyService(tenant_id="t1")
        profile = families.create_family(canonical_name="Emotet", now=NOW)
        service = FileHashIntelligenceService(tenant_id="t1", family_service=families)
        record = service.record_family_attribution(
            MD5_HASH, "Emotet", source_id="s", family_id=profile.family_id, now=NOW
        )
        assert record.family_id == profile.family_id

    def test_family_id_is_not_validated_without_a_family_service(self):
        """Without the family layer there is nothing to validate against, and that is allowed."""
        service = self._service()
        record = service.record_family_attribution(
            MD5_HASH, "Emotet", source_id="s", family_id="MWF-freeform", now=NOW
        )
        assert record.family_id == "MWF-freeform"

    def test_malicious_verdict_requires_evidence(self):
        service = self._service()
        with pytest.raises(EnrichmentValidationError):
            service.record_verdict(MD5_HASH, ThreatVerdict.MALICIOUS, source_id="s", now=NOW)

    def test_malicious_verdict_with_evidence_is_accepted(self):
        service = self._service()
        record = service.record_verdict(
            MD5_HASH, ThreatVerdict.MALICIOUS, source_id="sandbox", evidence=_evidence(1), now=NOW
        )
        assert record.verdict == ThreatVerdict.MALICIOUS

    def test_conflicting_records_are_listed(self):
        service = self._service()
        service.record_family_attribution(MD5_HASH, "Emotet", source_id="a", now=NOW)
        service.record_family_attribution(MD5_HASH, "TrickBot", source_id="b", now=NOW)
        assert [r.hash_value for r in service.family_conflicts()] == [MD5_HASH]

    def test_search_filters(self):
        service = self._service()
        service.record_malwarebazaar(
            MD5_HASH, malwarebazaar_id="1", signature="Emotet.Gen", file_type="exe", now=NOW
        )
        service.record_family_attribution(SHA256_HASH, "TrickBot", source_id="a", now=NOW)
        assert [r.hash_value for r in service.search(family="trickbot")] == [SHA256_HASH]
        assert [r.hash_value for r in service.search(signature="emotet.gen")] == [MD5_HASH]
        assert [r.hash_value for r in service.search(file_type="exe")] == [MD5_HASH]
        assert [r.hash_value for r in service.search(has_malwarebazaar=True)] == [MD5_HASH]
        assert [
            r.hash_value
            for r in service.search(attribution_state=EnrichmentState.ENRICHED)
        ] == [SHA256_HASH]

    def test_history_records_events(self):
        service = self._service()
        service.record_identity(MD5_HASH, FileIdentity(md5=MD5_HASH), source_id="mb", now=NOW)
        service.record_family_attribution(MD5_HASH, "Emotet", source_id="a", now=NOW)
        assert [h.action for h in service.history_for(MD5_HASH)] == [
            "identity_recorded", "family_attribution_recorded"
        ]

    def test_history_is_reachable_by_an_alternate_hash(self):
        service = self._service()
        service.record_identity(
            MD5_HASH, FileIdentity(md5=MD5_HASH, sha256=SHA256_HASH), source_id="mb", now=NOW
        )
        assert len(service.history_for(SHA256_HASH)) == 1

    def test_stats_counts_unknown_and_conflicting(self):
        service = self._service()
        service.record_identity(MD5_HASH, FileIdentity(md5=MD5_HASH), source_id="mb", now=NOW)
        service.record_family_attribution(SHA256_HASH, "Emotet", source_id="a", now=NOW)
        service.record_family_attribution(SHA256_HASH, "TrickBot", source_id="b", now=NOW)
        stats = service.stats()
        assert stats["records"] == 2
        assert stats["with_family"] == 1
        assert stats["unattributed"] == 1
        assert stats["conflicting_attribution"] == 1
        assert stats["verification_mode"] == "fixture_tested_only_no_outbound_requests"


# ----------------------------------------------------------------------
# Live-source gating
# ----------------------------------------------------------------------

class TestLiveSourceGating:
    def _readiness(self) -> LiveSourceReadinessService:
        """A readiness service whose environment opt-in is absent."""
        return LiveSourceReadinessService(tenant_id="t1", gate=LiveSourceGate(env={}))

    def test_live_enrich_is_refused_without_a_readiness_service(self):
        """
        Failing loudly is the point: silently returning nothing would let a caller believe a
        live enrichment had been attempted.
        """
        for service, arg in (
            (IPIntelligenceService(tenant_id="t1"), "8.8.8.8"),
            (DomainIntelligenceService(tenant_id="t1"), "example.com"),
            (URLIntelligenceService(tenant_id="t1"), "https://evil.com/x"),
            (FileHashIntelligenceService(tenant_id="t1"), MD5_HASH),
        ):
            with pytest.raises(LiveAccessRefusedError):
                service.live_enrich(arg, "some-source", allow_live=True, now=NOW)

    def test_live_plan_is_refused_without_a_readiness_service(self):
        with pytest.raises(LiveAccessRefusedError):
            IPIntelligenceService(tenant_id="t1").live_enrichment_plan("s", allow_live=True)

    def test_live_enrich_is_refused_without_the_environment_opt_in(self):
        """Even with a readiness service and allow_live=True, the env gate must also be open."""
        readiness = self._readiness()
        readiness.register_policy(
            LiveSourcePolicy(
                source_id="rir",
                url="https://stat.ripe.net/data/asn-neighbours/data.json?resource=8.8.8.8",
                payload_schema=SourceSchema(required_top_level_keys=["data"]),
                license_terms="RIPE NCC terms of use",
                rate_limit_documented=True,
            )
        )
        service = IPIntelligenceService(tenant_id="t1", live_readiness=readiness)
        with pytest.raises(LiveAccessRefusedError):
            service.live_enrich("8.8.8.8", "rir", allow_live=True, now=NOW)

    def test_live_enrich_is_refused_without_an_injected_transport(self):
        """This module holds no network client, so there is nothing that could fetch."""
        readiness = LiveSourceReadinessService(
            tenant_id="t1",
            gate=LiveSourceGate(env={"CICC_TI_ALLOW_LIVE_SOURCES": "1"}),
        )
        readiness.register_policy(
            LiveSourcePolicy(
                source_id="rir",
                url="https://stat.ripe.net/data/asn-neighbours/data.json?resource=8.8.8.8",
                payload_schema=SourceSchema(required_top_level_keys=["data"]),
                license_terms="RIPE NCC terms of use",
                rate_limit_documented=True,
            )
        )
        service = IPIntelligenceService(tenant_id="t1", live_readiness=readiness)
        with pytest.raises(LiveAccessRefusedError):
            service.live_enrich("8.8.8.8", "rir", allow_live=True, now=NOW)

    def test_plan_reports_that_live_is_not_permitted(self):
        """The plan performs no I/O and states honestly that live access is closed."""
        readiness = self._readiness()
        readiness.register_policy(
            LiveSourcePolicy(
                source_id="rir",
                url="https://stat.ripe.net/data/asn-neighbours/data.json?resource=8.8.8.8",
                payload_schema=SourceSchema(required_top_level_keys=["data"]),
                license_terms="RIPE NCC terms of use",
                rate_limit_documented=True,
            )
        )
        plan = IPIntelligenceService(tenant_id="t1", live_readiness=readiness).live_enrichment_plan(
            "rir", allow_live=False
        )
        assert plan.live_permitted is False
        assert plan.reason_if_not_permitted

    def test_no_enrichment_service_holds_a_network_client(self):
        """Static guarantee: none of the four services import or hold an HTTP client."""
        import inspect

        import apps.threat_intelligence.indicator_enrichment as module

        source = inspect.getsource(module)
        for forbidden in ("import requests", "import httpx", "import urllib.request",
                          "urlopen", "socket.socket"):
            assert forbidden not in source, f"{forbidden} must not appear in this module"


# ----------------------------------------------------------------------
# Shared behaviour
# ----------------------------------------------------------------------

class TestSharedBehaviour:
    def test_fixture_records_are_labelled_experimental(self):
        service = IPIntelligenceService(tenant_id="t1")
        record = service.record_asn(
            "8.8.8.8",
            ASNRecord(asn=1, source_id="s", source_reference="https://r", observed_at=NOW),
            now=NOW,
        )
        assert record.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_timestamps_are_always_aware(self):
        service = IPIntelligenceService(tenant_id="t1")
        record = service.record_asn(
            "8.8.8.8",
            ASNRecord(asn=1, source_id="s", source_reference="https://r",
                      observed_at=datetime(2026, 1, 1)),
            now=datetime(2026, 11, 5),
        )
        for value in (record.first_seen, record.last_seen, record.created_at, record.updated_at):
            assert value is not None and value.tzinfo is not None

    def test_observation_validates_the_indicator_type(self):
        with pytest.raises(ValidationError):
            EnrichmentObservation(
                observation_id="o1", indicator_type="carrier-pigeon", indicator_value="x",
                source_id="s",
            )

    def test_observation_caps_evidence(self):
        from apps.threat_intelligence.indicator_enrichment import MAX_EVIDENCE_PER_OBSERVATION

        with pytest.raises(ValidationError):
            EnrichmentObservation(
                observation_id="o1", indicator_type="ipv4", indicator_value="8.8.8.8",
                source_id="s", evidence=_evidence(MAX_EVIDENCE_PER_OBSERVATION + 1),
            )

    def test_errors_share_a_base_class(self):
        assert issubclass(EnrichmentValidationError, IndicatorEnrichmentError)
        assert issubclass(IndicatorNotFoundError, IndicatorEnrichmentError)
        assert issubclass(EnrichmentValidationError, ValueError)

    def test_concurrent_recording_loses_no_observations(self):
        import threading

        service = IPIntelligenceService(tenant_id="t1")
        barrier = threading.Barrier(4)
        errors: list = []

        def worker(index: int) -> None:
            try:
                barrier.wait(timeout=5)
                for step in range(20):
                    service.record_asn(
                        "8.8.8.8",
                        ASNRecord(asn=15169 + step, name=f"AS{step}", source_id=f"src-{index}",
                                  source_reference=f"https://r/{index}/{step}", observed_at=NOW),
                        now=NOW,
                    )
            except Exception as exc:  # pragma: no cover - surfaces in the assertion below
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)

        assert errors == []
        assert len(service.observations_for("8.8.8.8")) == 80


# ----------------------------------------------------------------------
# Package surface
# ----------------------------------------------------------------------

class TestPackageSurface:
    def test_module_exports_are_bound_on_the_package(self):
        import apps.threat_intelligence as ti

        for name in (
            "IPIntelligenceService",
            "DomainIntelligenceService",
            "URLIntelligenceService",
            "FileHashIntelligenceService",
            "IPEnrichmentRecord",
            "DomainEnrichmentRecord",
            "URLEnrichmentRecord",
            "FileEnrichmentRecord",
            "ASNRecord",
            "NetworkBlock",
            "GeolocationEvidence",
            "DNSRecordObservation",
            "WhoisRecord",
            "DomainRelationship",
            "FileIdentity",
            "EnrichmentObservation",
            "EnrichmentState",
            "ThreatVerdict",
            "DNSRecordType",
            "HashAlgorithm",
            "EnrichmentValidationError",
            "IndicatorNotFoundError",
        ):
            assert hasattr(ti, name), f"{name} is not exported from the package"
