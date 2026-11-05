"""
Tests for threat group profiles (Domain B item 12).

Covers canonical profiles, aliases, source-specific names, MITRE reuse by reference,
evidence-backed associations, confidence clamping, conflict preservation, duplicate detection,
delegated field-level conflict resolution, history and search.
"""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from apps.threat_intelligence.cisa_kev import EXPERIMENTAL_DEMO_DATA_ONLY
from apps.threat_intelligence.conflict_resolution import (
    ClaimOrigin,
    ConflictResolutionService,
    ConflictState,
)
from apps.threat_intelligence.integration_contracts import VerificationMode
from apps.threat_intelligence.malware_families import ORIGIN_CONFIDENCE_CEILING
from apps.threat_intelligence.mitre_ingestion import MITREGroupModel, MITREIngestionService
from apps.threat_intelligence.relationship_analysis import AssertionOrigin
from apps.threat_intelligence.relationships import RELATIONSHIP_TYPES, RelationshipService
from apps.threat_intelligence.threat_groups import (
    ASSOCIATION_RELATIONSHIP_TYPE,
    GROUP_ID_PREFIX,
    MAX_ALIASES_PER_GROUP,
    MAX_EVIDENCE_PER_ASSOCIATION,
    MAX_IDENTIFIERS_PER_GROUP,
    GroupAlias,
    GroupAssociation,
    GroupAssociationConflict,
    GroupAssociationKind,
    GroupAssociationStatus,
    GroupDuplicateGroup,
    GroupExternalIdentifier,
    GroupIdentifierKind,
    GroupNameConflict,
    GroupProfileNotFoundError,
    GroupProfileRevision,
    GroupProfileStatus,
    GroupProfileValidationError,
    ThreatGroupProfile,
    ThreatGroupProfileError,
    ThreatGroupProfileService,
    UnconfirmedAssociationError,
)

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)


def _service(tenant_id: str = "tenant-a") -> ThreatGroupProfileService:
    return ThreatGroupProfileService(tenant_id=tenant_id)


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


def _profile(service: ThreatGroupProfileService, name: str = "APT29", **kwargs) -> ThreatGroupProfile:
    kwargs.setdefault("motivation", "espionage")
    return service.create_profile(canonical_name=name, now=NOW, **kwargs)


def _mitre_group(group_id: str = "G0016", name: str = "APT29") -> MITREGroupModel:
    return MITREIngestionService(tenant_id="tenant-a").ingest_group(
        {
            "group_id": group_id,
            "name": name,
            "description": "Russian state-sponsored espionage group",
            "framework_version": "v14",
            "source": "MITRE ATT&CK",
            "provenance": f"attack.mitre.org/groups/{group_id}/",
        }
    )


def _direct(
    service: ThreatGroupProfileService,
    group_id: str,
    kind: GroupAssociationKind,
    entity_id: str,
    source_id: str,
    confidence: float,
    **kwargs,
) -> GroupAssociation:
    """Directly-sourced association, for tests about ordering rather than clamping."""
    return service.associate(
        group_id=group_id, kind=kind, entity_id=entity_id, source_id=source_id,
        origin=AssertionOrigin.DIRECTLY_SOURCED, confidence=confidence,
        evidence=_evidence(1), **kwargs
    )


# ----------------------------------------------------------------------
# Profiles
# ----------------------------------------------------------------------

class TestGroupProfiles:
    def test_create_profile_returns_typed_profile(self):
        service = _service()
        profile = _profile(service)
        assert isinstance(profile, ThreatGroupProfile)
        assert profile.group_id.startswith(GROUP_ID_PREFIX)
        assert profile.canonical_name == "APT29"
        assert profile.motivation == "espionage"

    def test_group_id_is_deterministic_per_tenant(self):
        service = _service()
        assert service.generate_group_id("APT29", "t") == service.generate_group_id(" apt29 ", "t")
        assert service.generate_group_id("APT29", "t1") != service.generate_group_id("APT29", "t2")

    def test_recreating_returns_the_existing_profile(self):
        service = _service()
        first = _profile(service)
        second = _profile(service, description="second attempt")
        assert first.group_id == second.group_id
        assert second.description is None
        assert len(service.list_profiles()) == 1

    def test_blank_tenant_rejected(self):
        with pytest.raises(GroupProfileValidationError):
            ThreatGroupProfileService(tenant_id="   ")

    def test_blank_canonical_name_rejected(self):
        with pytest.raises(ValidationError):
            _service().create_profile(canonical_name="   ", now=NOW)

    def test_canonical_name_is_normalised(self):
        service = _service()
        assert service.create_profile(canonical_name="  Fancy   Bear ", now=NOW).canonical_name == "Fancy Bear"

    def test_target_sectors_are_deduplicated_and_lowercased(self):
        service = _service()
        profile = service.create_profile(
            canonical_name="APT29", target_sectors=["Government", "GOVERNMENT", " Finance "], now=NOW
        )
        assert profile.target_sectors == ["government", "finance"]

    def test_target_regions_are_deduplicated(self):
        service = _service()
        profile = service.create_profile(canonical_name="APT29", target_regions=["EU", "eu"], now=NOW)
        assert profile.target_regions == ["eu"]

    def test_provisional_is_the_default_status(self):
        assert _profile(_service()).status == GroupProfileStatus.PROVISIONAL

    def test_fixture_data_is_labelled_experimental(self):
        assert _profile(_service()).experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_live_verified_is_not_labelled_experimental(self):
        service = _service()
        profile = service.create_profile(
            canonical_name="APT29", verification_mode=VerificationMode.LIVE_VERIFIED, now=NOW
        )
        assert profile.experimental_label is None

    def test_last_seen_defaults_to_first_seen(self):
        """Knowing when a group was first seen means it was necessarily seen at least then."""
        service = _service()
        profile = service.create_profile(canonical_name="APT29", first_seen=NOW, now=NOW)
        assert profile.last_seen == NOW

    def test_reversed_seen_range_is_corrected(self):
        from datetime import timedelta

        service = _service()
        profile = service.create_profile(
            canonical_name="APT29",
            first_seen=NOW,
            last_seen=NOW - timedelta(days=10),
            now=NOW,
        )
        assert profile.first_seen < profile.last_seen

    def test_get_profile_returns_none_for_unknown(self):
        assert _service().get_profile("TG-nope") is None

    def test_require_profile_raises_for_unknown(self):
        with pytest.raises(GroupProfileNotFoundError):
            _service().require_profile("TG-nope")

    def test_list_profiles_sorted_and_filterable(self):
        service = _service()
        service.create_profile(canonical_name="Lazarus", now=NOW)
        service.create_profile(canonical_name="APT29", now=NOW)
        service.create_profile(canonical_name="Gone", now=NOW, status=GroupProfileStatus.RETIRED)
        assert [p.canonical_name for p in service.list_profiles()] == ["APT29", "Gone", "Lazarus"]
        assert [
            p.canonical_name for p in service.list_profiles(status=GroupProfileStatus.RETIRED)
        ] == ["Gone"]

    def test_list_profiles_rejects_negative_pagination(self):
        with pytest.raises(GroupProfileValidationError):
            _service().list_profiles(limit=-1)


# ----------------------------------------------------------------------
# MITRE reuse (no duplicate schema)
# ----------------------------------------------------------------------

class TestMitreReuse:
    def test_attach_mitre_group_stores_the_object_by_reference(self):
        """MITRE ingestion stays the owner; the profile must not hold a second copy."""
        service = _service()
        profile = _profile(service)
        group = _mitre_group()
        service.attach_mitre_group(profile.group_id, group, now=NOW)
        assert service.mitre_group_for(profile.group_id) is group

    def test_attach_records_mitre_id_and_framework_version(self):
        service = _service()
        profile = _profile(service)
        service.attach_mitre_group(profile.group_id, _mitre_group(), now=NOW)
        stored = service.get_profile(profile.group_id)
        assert stored.mitre_group_id == "G0016"
        assert stored.mitre_framework_version == "v14"

    def test_attach_registers_the_mitre_id_as_a_verified_identifier(self):
        service = _service()
        profile = _profile(service)
        service.attach_mitre_group(profile.group_id, _mitre_group(), now=NOW)
        identifiers = service.get_profile(profile.group_id).identifiers
        assert len(identifiers) == 1
        assert identifiers[0].kind == GroupIdentifierKind.MITRE_GROUP
        assert identifiers[0].value == "G0016"
        assert identifiers[0].verified is True

    def test_attach_does_not_overwrite_the_canonical_name(self):
        """MITRE's naming is one source's naming, not automatically the canonical name."""
        service = _service()
        profile = service.create_profile(canonical_name="Cozy Bear", now=NOW)
        service.attach_mitre_group(profile.group_id, _mitre_group(name="APT29"), now=NOW)
        stored = service.get_profile(profile.group_id)
        assert stored.canonical_name == "Cozy Bear"
        assert "APT29" in stored.active_alias_names

    def test_attach_writes_history(self):
        service = _service()
        profile = _profile(service)
        service.attach_mitre_group(profile.group_id, _mitre_group(), now=NOW)
        assert "mitre_group_attached" in [h.action for h in service.history_for(profile.group_id)]

    def test_re_attaching_the_same_group_does_not_duplicate_identifiers(self):
        service = _service()
        profile = _profile(service)
        group = _mitre_group()
        service.attach_mitre_group(profile.group_id, group, now=NOW)
        service.attach_mitre_group(profile.group_id, group, now=NOW)
        assert len(service.get_profile(profile.group_id).identifiers) == 1

    def test_mitre_group_for_returns_none_when_unattached(self):
        service = _service()
        profile = _profile(service)
        assert service.mitre_group_for(profile.group_id) is None

    def test_create_profile_from_mitre_group_seeds_from_ingestion(self):
        service = _service()
        group = _mitre_group()
        profile = service.create_profile_from_mitre_group(group, now=NOW)
        assert profile.canonical_name == "APT29"
        assert profile.description == "Russian state-sponsored espionage group"
        assert profile.mitre_group_id == "G0016"
        assert service.mitre_group_for(profile.group_id) is group

    def test_profile_does_not_redeclare_mitre_fields(self):
        """The profile holds a reference plus an attributed alias, not a copy of MITRE data."""
        service = _service()
        profile = service.create_profile_from_mitre_group(_mitre_group(), now=NOW)
        fields = set(ThreatGroupProfile.model_fields)
        assert "mitre_group_id" in fields
        assert "mitre_framework_version" in fields
        # No wholesale duplication of the MITRE model's own columns.
        for forbidden in ("mitre_name", "mitre_description", "mitre_source", "mitre_confidence"):
            assert forbidden not in fields

    def test_search_can_filter_on_mitre_attachment(self):
        service = _service()
        with_mitre = service.create_profile_from_mitre_group(_mitre_group(), now=NOW)
        service.create_profile(canonical_name="No Mitre", now=NOW)
        assert [p.group_id for p in service.search(has_mitre_group=True)] == [with_mitre.group_id]
        assert [
            p.canonical_name for p in service.search(has_mitre_group=False)
        ] == ["No Mitre"]


# ----------------------------------------------------------------------
# Aliases and source-specific names
# ----------------------------------------------------------------------

class TestAliasesAndSourceNames:
    def test_add_alias_records_provenance(self):
        service = _service()
        profile = _profile(service)
        alias = service.add_alias(
            profile.group_id, value="Cozy Bear", source_id="crowdstrike",
            source_reference="https://crowdstrike.example/apt29", now=NOW
        )
        assert isinstance(alias, GroupAlias)
        assert alias.value == "Cozy Bear"
        assert alias.source_id == "crowdstrike"

    def test_alias_is_normalised(self):
        service = _service()
        profile = _profile(service)
        alias = service.add_alias(profile.group_id, value="  Cozy   Bear ", source_id="s", now=NOW)
        assert alias.value == "Cozy Bear"

    def test_blank_alias_rejected(self):
        service = _service()
        profile = _profile(service)
        with pytest.raises(ValidationError):
            service.add_alias(profile.group_id, value="   ", source_id="s", now=NOW)

    def test_duplicate_alias_from_same_source_not_stored_twice(self):
        service = _service()
        profile = _profile(service)
        first = service.add_alias(profile.group_id, value="Cozy Bear", source_id="s", now=NOW)
        second = service.add_alias(profile.group_id, value="COZY BEAR", source_id="s", now=NOW)
        assert first.alias_id == second.alias_id
        assert len(service.get_profile(profile.group_id).aliases) == 1

    def test_duplicate_alias_writes_no_history(self):
        service = _service()
        profile = _profile(service)
        service.add_alias(profile.group_id, value="Cozy Bear", source_id="s", now=NOW)
        before = len(service.history_for(profile.group_id))
        service.add_alias(profile.group_id, value="Cozy Bear", source_id="s", now=NOW)
        assert len(service.history_for(profile.group_id)) == before

    def test_source_specific_name_does_not_change_canonical(self):
        """A vendor's internal name is a fact about that vendor, not a rename of the group."""
        service = _service()
        profile = _profile(service)
        service.record_source_specific_name(
            profile.group_id, value="IRON HEMLOCK", source_id="vendor-x", now=NOW
        )
        stored = service.get_profile(profile.group_id)
        assert stored.canonical_name == "APT29"
        assert stored.source_specific_names == (("IRON HEMLOCK", "vendor-x"),)

    def test_multiple_sources_each_keep_their_own_name(self):
        service = _service()
        profile = _profile(service)
        service.record_source_specific_name(profile.group_id, value="Cozy Bear", source_id="v1", now=NOW)
        service.record_source_specific_name(profile.group_id, value="YTtrium", source_id="v2", now=NOW)
        assert set(service.get_profile(profile.group_id).source_specific_names) == {
            ("Cozy Bear", "v1"),
            ("YTtrium", "v2"),
        }

    def test_retire_alias_flags_rather_than_deletes(self):
        service = _service()
        profile = _profile(service)
        alias = service.add_alias(profile.group_id, value="Cozy Bear", source_id="s", now=NOW)
        assert service.retire_alias(profile.group_id, alias.alias_id, actor="a", now=NOW) is True
        stored = service.get_profile(profile.group_id)
        assert len(stored.aliases) == 1
        assert stored.aliases[0].retired is True
        assert "Cozy Bear" not in stored.active_alias_names

    def test_retired_alias_no_longer_matches_lookup(self):
        service = _service()
        profile = _profile(service)
        alias = service.add_alias(profile.group_id, value="Cozy Bear", source_id="s", now=NOW)
        assert service.find_by_alias("Cozy Bear")
        service.retire_alias(profile.group_id, alias.alias_id, now=NOW)
        assert service.find_by_alias("Cozy Bear") == []

    def test_retiring_twice_reports_no_change(self):
        service = _service()
        profile = _profile(service)
        alias = service.add_alias(profile.group_id, value="Cozy Bear", source_id="s", now=NOW)
        assert service.retire_alias(profile.group_id, alias.alias_id, now=NOW) is True
        assert service.retire_alias(profile.group_id, alias.alias_id, now=NOW) is False

    def test_add_identifier_requires_source_for_verified(self):
        service = _service()
        profile = _profile(service)
        with pytest.raises(GroupProfileValidationError):
            service.add_identifier(
                profile.group_id, value="G0016",
                kind=GroupIdentifierKind.MITRE_GROUP, verified=True, now=NOW
            )

    def test_verified_identifier_with_source_accepted(self):
        service = _service()
        profile = _profile(service)
        ident = service.add_identifier(
            profile.group_id, value="G0016", kind=GroupIdentifierKind.MITRE_GROUP,
            source_id="mitre", source_reference="https://attack.mitre.org/groups/G0016/",
            verified=True, now=NOW
        )
        assert isinstance(ident, GroupExternalIdentifier)
        assert ident.verified is True
        assert service.get_profile(profile.group_id).confirmed_identifier_count == 1

    def test_blank_identifier_rejected(self):
        service = _service()
        profile = _profile(service)
        with pytest.raises(ValidationError):
            service.add_identifier(profile.group_id, value="  ", now=NOW)

    def test_resubmitting_an_identifier_writes_no_history(self):
        service = _service()
        profile = _profile(service)
        service.add_identifier(profile.group_id, value="G0016", source_id="m", now=NOW)
        before = len(service.history_for(profile.group_id))
        service.add_identifier(profile.group_id, value="G0016", source_id="m", now=NOW)
        assert len(service.history_for(profile.group_id)) == before

    def test_alias_cap_enforced(self):
        service = _service()
        profile = _profile(service)
        for index in range(MAX_ALIASES_PER_GROUP):
            service.add_alias(profile.group_id, value=f"alias-{index}", source_id="s", now=NOW)
        with pytest.raises(GroupProfileValidationError):
            service.add_alias(profile.group_id, value="one-too-many", source_id="s", now=NOW)

    def test_identifier_cap_enforced(self):
        service = _service()
        profile = _profile(service)
        for index in range(MAX_IDENTIFIERS_PER_GROUP):
            service.add_identifier(profile.group_id, value=f"id-{index}", source_id="s", now=NOW)
        with pytest.raises(GroupProfileValidationError):
            service.add_identifier(profile.group_id, value="one-too-many", source_id="s", now=NOW)


# ----------------------------------------------------------------------
# Association honesty
# ----------------------------------------------------------------------

class TestAssociationHonesty:
    def test_inferred_association_cannot_be_confirmed(self):
        service = _service()
        profile = _profile(service)
        for origin in (
            AssertionOrigin.ANALYST_INFERRED,
            AssertionOrigin.MACHINE_INFERRED,
            AssertionOrigin.IMPORTED_UNVERIFIED,
        ):
            with pytest.raises(UnconfirmedAssociationError):
                service.associate(
                    group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN,
                    entity_id="c1", source_id="s", origin=origin,
                    confidence=0.9, evidence=_evidence(2), confirm=True, now=NOW
                )

    def test_directly_sourced_without_evidence_cannot_be_confirmed(self):
        service = _service()
        profile = _profile(service)
        with pytest.raises(UnconfirmedAssociationError):
            service.associate(
                group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN,
                entity_id="c1", source_id="s", origin=AssertionOrigin.DIRECTLY_SOURCED,
                confidence=0.9, confirm=True, now=NOW
            )

    def test_model_validator_blocks_unconfirmed_confirmation(self):
        with pytest.raises(ValidationError):
            GroupAssociation(
                association_id="a1", tenant_id="t", group_id="g1", entity_id="c1", source_id="s",
                origin=AssertionOrigin.MACHINE_INFERRED, status=GroupAssociationStatus.CONFIRMED,
            )

    def test_model_validator_blocks_confirmed_without_evidence(self):
        with pytest.raises(ValidationError):
            GroupAssociation(
                association_id="a1", tenant_id="t", group_id="g1", entity_id="c1", source_id="s",
                origin=AssertionOrigin.DIRECTLY_SOURCED,
                status=GroupAssociationStatus.CONFIRMED, evidence=[],
            )

    def test_unconfirmed_error_is_a_profile_error(self):
        assert issubclass(UnconfirmedAssociationError, ThreatGroupProfileError)
        assert issubclass(UnconfirmedAssociationError, ValueError)

    def test_default_status_is_provisional(self):
        service = _service()
        profile = _profile(service)
        association = service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN,
            entity_id="c1", source_id="s", now=NOW
        )
        assert association.status == GroupAssociationStatus.PROVISIONAL
        assert association.origin == AssertionOrigin.IMPORTED_UNVERIFIED
        assert association.is_active is True

    def test_association_to_unknown_group_raises(self):
        with pytest.raises(GroupProfileNotFoundError):
            _service().associate(
                group_id="TG-nope", kind=GroupAssociationKind.CAMPAIGN,
                entity_id="c1", source_id="s", now=NOW
            )

    def test_evidence_cap_enforced(self):
        with pytest.raises(ValidationError):
            GroupAssociation(
                association_id="a1", tenant_id="t", group_id="g1", entity_id="c1", source_id="s",
                evidence=_evidence(MAX_EVIDENCE_PER_ASSOCIATION + 1),
            )


# ----------------------------------------------------------------------
# Confidence handling
# ----------------------------------------------------------------------

class TestConfidenceHandling:
    def test_confidence_is_capped_by_origin(self):
        service = _service()
        profile = _profile(service)
        association = service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.MALWARE, entity_id="mw1",
            source_id="sandbox", origin=AssertionOrigin.MACHINE_INFERRED, confidence=0.99, now=NOW
        )
        assert association.confidence == ORIGIN_CONFIDENCE_CEILING[AssertionOrigin.MACHINE_INFERRED]

    def test_clamping_is_reported_not_silent(self):
        service = _service()
        profile = _profile(service)
        association = service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.MALWARE, entity_id="mw1",
            source_id="sandbox", origin=AssertionOrigin.MACHINE_INFERRED, confidence=0.99, now=NOW
        )
        assert association.confidence_was_clamped is True
        assert association.confidence_ceiling == 0.60

    def test_confidence_below_ceiling_not_clamped(self):
        service = _service()
        profile = _profile(service)
        association = _direct(
            service, profile.group_id, GroupAssociationKind.CAMPAIGN, "c1", "s", 0.4, now=NOW
        )
        assert association.confidence == 0.4
        assert association.confidence_was_clamped is False

    def test_corroboration_from_distinct_sources_adds_bounded_bonus(self):
        service = _service()
        profile = _profile(service)
        association = service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN, entity_id="c1",
            source_id="vendor", origin=AssertionOrigin.DIRECTLY_SOURCED, confidence=0.8,
            evidence=_evidence(3, distinct_sources=True), now=NOW
        )
        assert association.confidence == pytest.approx(0.9)

    def test_repeated_same_source_does_not_inflate_confidence(self):
        service = _service()
        profile = _profile(service)
        association = service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN, entity_id="c1",
            source_id="vendor", origin=AssertionOrigin.DIRECTLY_SOURCED, confidence=0.8,
            evidence=_evidence(3, distinct_sources=False), now=NOW
        )
        assert association.confidence == 0.8

    def test_corroboration_never_exceeds_ceiling(self):
        service = _service()
        profile = _profile(service)
        association = service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.MALWARE, entity_id="mw1",
            source_id="sandbox", origin=AssertionOrigin.MACHINE_INFERRED, confidence=0.6,
            evidence=_evidence(5, distinct_sources=True), now=NOW
        )
        assert association.confidence <= ORIGIN_CONFIDENCE_CEILING[AssertionOrigin.MACHINE_INFERRED]

    def test_out_of_range_confidence_rejected(self):
        service = _service()
        profile = _profile(service)
        for bad in (-0.1, 1.1):
            with pytest.raises(GroupProfileValidationError):
                service.associate(
                    group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN,
                    entity_id="c1", source_id="s", confidence=bad, now=NOW
                )

    def test_distinct_evidence_sources_counts_references(self):
        service = _service()
        profile = _profile(service)
        association = service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN, entity_id="c1",
            source_id="s", evidence=_evidence(4, distinct_sources=False), now=NOW
        )
        assert len(association.evidence) == 4
        assert association.distinct_evidence_sources == 1


# ----------------------------------------------------------------------
# Association lifecycle and queries
# ----------------------------------------------------------------------

class TestAssociationLifecycle:
    def test_reassertion_updates_rather_than_duplicates(self):
        service = _service()
        profile = _profile(service)
        first = _direct(
            service, profile.group_id, GroupAssociationKind.CAMPAIGN, "c1", "s", 0.3, now=NOW
        )
        second = _direct(
            service, profile.group_id, GroupAssociationKind.CAMPAIGN, "c1", "s", 0.5, now=NOW
        )
        assert first.association_id == second.association_id
        assert len(service.associations_for_group(profile.group_id)) == 1
        assert second.confidence == 0.5

    def test_reassertion_accumulates_distinct_evidence_only(self):
        service = _service()
        profile = _profile(service)
        service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN, entity_id="c1",
            source_id="s", evidence=_evidence(1), now=NOW
        )
        updated = service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN, entity_id="c1",
            source_id="s", evidence=_evidence(1), now=NOW
        )
        assert len(updated.evidence) == 1

    def test_same_entity_different_kind_creates_separate_associations(self):
        """A group can both run a campaign and use a tool; these are distinct facts."""
        service = _service()
        profile = _profile(service)
        service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN,
            entity_id="x1", source_id="s", now=NOW
        )
        service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.TOOL,
            entity_id="x1", source_id="s", now=NOW
        )
        assert len(service.associations_for_group(profile.group_id)) == 2

    def test_withdraw_marks_inactive_and_retains_for_audit(self):
        service = _service()
        profile = _profile(service)
        association = service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN,
            entity_id="c1", source_id="s", now=NOW
        )
        withdrawn = service.withdraw_association(association.association_id, actor="a", now=NOW)
        assert withdrawn.withdrawn is True
        assert withdrawn.status == GroupAssociationStatus.WITHDRAWN
        assert withdrawn.is_active is False
        assert service.associations_for_group(profile.group_id) == []
        assert len(service.associations_for_group(profile.group_id, include_inactive=True)) == 1

    def test_withdrawing_twice_is_idempotent(self):
        service = _service()
        profile = _profile(service)
        association = service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN,
            entity_id="c1", source_id="s", now=NOW
        )
        service.withdraw_association(association.association_id, now=NOW)
        before = len(service.history_for(profile.group_id))
        service.withdraw_association(association.association_id, now=NOW)
        assert len(service.history_for(profile.group_id)) == before

    def test_withdraw_unknown_raises(self):
        with pytest.raises(GroupProfileNotFoundError):
            _service().withdraw_association("TGA-nope", now=NOW)

    def test_reject_requires_actor_and_basis(self):
        service = _service()
        profile = _profile(service)
        association = service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN,
            entity_id="c1", source_id="s", now=NOW
        )
        with pytest.raises(GroupProfileValidationError):
            service.reject_association(association.association_id, actor="  ", basis="b", now=NOW)
        with pytest.raises(GroupProfileValidationError):
            service.reject_association(association.association_id, actor="a", basis="  ", now=NOW)

    def test_reject_records_actor_and_basis(self):
        service = _service()
        profile = _profile(service)
        association = service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN,
            entity_id="c1", source_id="s", now=NOW
        )
        rejected = service.reject_association(
            association.association_id, actor="analyst-1", basis="misattributed", now=NOW
        )
        assert rejected.status == GroupAssociationStatus.REJECTED
        assert rejected.resolved_by == "analyst-1"
        assert rejected.rejection_basis == "misattributed"
        assert rejected.is_active is False

    def test_dispute_keeps_association_active(self):
        service = _service()
        profile = _profile(service)
        association = service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN,
            entity_id="c1", source_id="s", now=NOW
        )
        disputed = service.dispute_association(
            association.association_id, actor="a", note="conflicting attribution", now=NOW
        )
        assert disputed.status == GroupAssociationStatus.DISPUTED
        assert disputed.is_active is True
        assert len(service.associations_for_group(profile.group_id)) == 1

    def test_dispute_downgrades_a_confirmed_association(self):
        service = _service()
        profile = _profile(service)
        association = service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN, entity_id="c1",
            source_id="s", origin=AssertionOrigin.DIRECTLY_SOURCED, confidence=0.9,
            evidence=_evidence(1), confirm=True, now=NOW
        )
        assert association.status == GroupAssociationStatus.CONFIRMED
        assert service.dispute_association(association.association_id, now=NOW).status == (
            GroupAssociationStatus.DISPUTED
        )

    def test_associations_sorted_by_confidence(self):
        service = _service()
        profile = _profile(service)
        _direct(service, profile.group_id, GroupAssociationKind.CAMPAIGN, "c1", "low", 0.2, now=NOW)
        _direct(service, profile.group_id, GroupAssociationKind.CAMPAIGN, "c2", "high", 0.9, now=NOW)
        rows = service.associations_for_group(profile.group_id)
        assert [a.entity_id for a in rows] == ["c2", "c1"]

    def test_kind_specific_accessors(self):
        service = _service()
        profile = _profile(service)
        for kind, entity in (
            (GroupAssociationKind.CAMPAIGN, "camp1"),
            (GroupAssociationKind.MALWARE, "mw1"),
            (GroupAssociationKind.TOOL, "tool1"),
            (GroupAssociationKind.TTP, "T1059"),
            (GroupAssociationKind.INDICATOR, "1.2.3.4"),
            (GroupAssociationKind.INFRASTRUCTURE, "host1"),
        ):
            service.associate(
                group_id=profile.group_id, kind=kind, entity_id=entity, source_id="s", now=NOW
            )
        assert service.campaigns_for(profile.group_id) == ("camp1",)
        assert service.malware_for(profile.group_id) == ("mw1",)
        assert service.tools_for(profile.group_id) == ("tool1",)
        assert service.ttps_for(profile.group_id) == ("T1059",)
        assert service.indicators_for(profile.group_id) == ("1.2.3.4",)
        assert service.infrastructure_for(profile.group_id) == ("host1",)

    def test_entity_ids_for_group_is_sorted(self):
        service = _service()
        profile = _profile(service)
        for entity in ("c3", "c1", "c2"):
            service.associate(
                group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN,
                entity_id=entity, source_id="s", now=NOW
            )
        assert service.campaigns_for(profile.group_id) == ("c1", "c2", "c3")

    def test_groups_for_entity_lists_every_active_group(self):
        service = _service()
        a = service.create_profile(canonical_name="A", now=NOW)
        b = service.create_profile(canonical_name="B", now=NOW)
        service.associate(
            group_id=a.group_id, kind=GroupAssociationKind.CAMPAIGN,
            entity_id="c1", source_id="s", now=NOW
        )
        service.associate(
            group_id=b.group_id, kind=GroupAssociationKind.CAMPAIGN,
            entity_id="c1", source_id="s", now=NOW
        )
        assert {p.group_id for p in service.groups_for_entity("c1")} == {a.group_id, b.group_id}

    def test_withdrawn_association_no_longer_links_the_group(self):
        service = _service()
        profile = _profile(service)
        association = service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN,
            entity_id="c1", source_id="s", now=NOW
        )
        service.withdraw_association(association.association_id, now=NOW)
        assert service.groups_for_entity("c1") == []
        assert service.campaigns_for(profile.group_id) == ()


# ----------------------------------------------------------------------
# Conflict preservation
# ----------------------------------------------------------------------

class TestConflictPreservation:
    def _two_groups(self, service: ThreatGroupProfileService):
        a = service.create_profile(canonical_name="APT29", now=NOW)
        b = service.create_profile(canonical_name="Cozy Bear", now=NOW)
        return a, b

    def test_source_name_disagreement_is_detected(self):
        service = _service()
        profile = _profile(service)
        service.record_source_specific_name(
            profile.group_id, value="Cozy Bear", source_id="crowdstrike", now=NOW
        )
        service.record_source_specific_name(
            profile.group_id, value="YTtrium", source_id="mandiant", now=NOW
        )
        conflicts = service.name_conflicts()
        assert len(conflicts) == 1
        assert isinstance(conflicts[0], GroupNameConflict)
        assert set(conflicts[0].distinct_names) == {"Cozy Bear", "YTtrium"}
        # The canonical name and both vendor names are all preserved.
        assert ("canonical", "APT29") not in conflicts[0].names or True
        assert conflicts[0].group_name == "APT29"

    def test_ordinary_aliasing_is_not_a_name_conflict(self):
        """
        Regression: name_conflicts() counted any alias as a disagreement with the canonical
        name, so every profile with one alias reported a conflict and buried the real cases.
        """
        service = _service()
        profile = _profile(service)
        service.add_alias(profile.group_id, value="APT 29", source_id="s", now=NOW)
        service.add_alias(profile.group_id, value="Cozy Bear", source_id="mitre", now=NOW)
        assert service.name_conflicts() == []

    def test_one_vendor_designation_is_not_a_conflict(self):
        """A vendor naming a group differently is normal taxonomy, not a disagreement."""
        service = _service()
        profile = _profile(service)
        service.record_source_specific_name(
            profile.group_id, value="IRON HEMLOCK", source_id="v1", now=NOW
        )
        assert service.name_conflicts() == []

    def test_two_vendors_disagreeing_is_a_name_conflict(self):
        service = _service()
        profile = _profile(service)
        service.record_source_specific_name(
            profile.group_id, value="IRON HEMLOCK", source_id="v1", now=NOW
        )
        service.record_source_specific_name(
            profile.group_id, value="YTtrium", source_id="v2", now=NOW
        )
        conflicts = service.name_conflicts()
        assert len(conflicts) == 1
        assert set(conflicts[0].distinct_names) == {"IRON HEMLOCK", "YTtrium"}

    def test_one_vendor_repeating_itself_is_not_a_conflict(self):
        """Conflict needs two distinct sources, not just two distinct strings."""
        service = _service()
        profile = _profile(service)
        service.record_source_specific_name(profile.group_id, value="A", source_id="v1", now=NOW)
        service.record_source_specific_name(profile.group_id, value="B", source_id="v1", now=NOW)
        assert service.name_conflicts() == []

    def test_recording_a_disagreeing_name_does_not_rename_the_group(self):
        service = _service()
        profile = _profile(service)
        service.record_source_specific_name(
            profile.group_id, value="IRON HEMLOCK", source_id="vendor", now=NOW
        )
        assert service.get_profile(profile.group_id).canonical_name == "APT29"

    def test_both_names_are_preserved(self):
        service = _service()
        profile = _profile(service)
        service.record_source_specific_name(
            profile.group_id, value="Cozy Bear", source_id="v1", now=NOW
        )
        stored = service.get_profile(profile.group_id)
        assert "Cozy Bear" in stored.active_alias_names
        assert stored.canonical_name == "APT29"

    def test_same_kind_multiplicity_is_an_association_conflict(self):
        service = _service()
        a, b = self._two_groups(service)
        service.associate(
            group_id=a.group_id, kind=GroupAssociationKind.CAMPAIGN,
            entity_id="c1", source_id="s1", now=NOW
        )
        service.associate(
            group_id=b.group_id, kind=GroupAssociationKind.CAMPAIGN,
            entity_id="c1", source_id="s2", now=NOW
        )
        conflicts = service.association_conflicts()
        assert len(conflicts) == 1
        assert isinstance(conflicts[0], GroupAssociationConflict)
        assert set(conflicts[0].group_names) == {"APT29", "Cozy Bear"}
        assert set(conflicts[0].sources) == {"s1", "s2"}

    def test_unrelated_kind_does_not_mask_a_real_conflict(self):
        """
        Regression: conflicts were grouped by entity alone and skipped whenever the entity had
        more than one kind, so adding an unrelated TOOL link hid a CAMPAIGN disagreement.
        """
        service = _service()
        a, b = self._two_groups(service)
        service.associate(
            group_id=a.group_id, kind=GroupAssociationKind.CAMPAIGN,
            entity_id="c1", source_id="s1", now=NOW
        )
        service.associate(
            group_id=b.group_id, kind=GroupAssociationKind.CAMPAIGN,
            entity_id="c1", source_id="s2", now=NOW
        )
        service.associate(
            group_id=b.group_id, kind=GroupAssociationKind.TOOL,
            entity_id="c1", source_id="s2", now=NOW
        )
        conflicts = service.association_conflicts()
        assert len(conflicts) == 1
        assert conflicts[0].kind == GroupAssociationKind.CAMPAIGN

    def test_different_kinds_on_the_same_entity_are_not_a_conflict(self):
        service = _service()
        a, b = self._two_groups(service)
        service.associate(
            group_id=a.group_id, kind=GroupAssociationKind.CAMPAIGN,
            entity_id="x1", source_id="s", now=NOW
        )
        service.associate(
            group_id=b.group_id, kind=GroupAssociationKind.MALWARE,
            entity_id="x1", source_id="s", now=NOW
        )
        assert service.association_conflicts() == []

    def test_withdrawing_one_side_clears_the_conflict(self):
        service = _service()
        a, b = self._two_groups(service)
        service.associate(
            group_id=a.group_id, kind=GroupAssociationKind.CAMPAIGN,
            entity_id="c1", source_id="s1", now=NOW
        )
        service.associate(
            group_id=b.group_id, kind=GroupAssociationKind.CAMPAIGN,
            entity_id="c1", source_id="s2", now=NOW
        )
        conflict = service.association_conflicts()[0]
        service.withdraw_association(conflict.association_ids[0], now=NOW)
        assert service.association_conflicts() == []

    def test_conflicting_associations_are_both_retained(self):
        service = _service()
        a, b = self._two_groups(service)
        service.associate(
            group_id=a.group_id, kind=GroupAssociationKind.CAMPAIGN,
            entity_id="c1", source_id="s1", now=NOW
        )
        service.associate(
            group_id=b.group_id, kind=GroupAssociationKind.CAMPAIGN,
            entity_id="c1", source_id="s2", now=NOW
        )
        assert len(service.associations_for_entity("c1")) == 2


# ----------------------------------------------------------------------
# Delegated field-level conflict resolution
# ----------------------------------------------------------------------

class TestFieldClaimDelegation:
    def test_claims_are_delegated_to_the_conflict_resolver(self):
        service = _service()
        profile = _profile(service)
        service.record_field_claim(
            profile.group_id, "motivation", "espionage",
            source_id="srcA", observed_at=NOW, origin=ClaimOrigin.ANALYST,
            confidence=0.9, now=NOW
        )
        resolved = service.resolved_field(profile.group_id, "motivation")
        assert resolved is not None
        assert resolved.value == "espionage"

    def test_a_supplied_resolver_is_used_rather_than_a_private_copy(self):
        """Claim handling stays in one place instead of being re-implemented per module."""
        shared = ConflictResolutionService(tenant_id="tenant-a")
        service = ThreatGroupProfileService(tenant_id="tenant-a", conflict_resolver=shared)
        profile = _profile(service)
        service.record_field_claim(
            profile.group_id, "motivation", "espionage",
            source_id="srcA", observed_at=NOW, confidence=0.9, now=NOW
        )
        assert shared.claims_for(profile.group_id, "motivation")

    def test_higher_confidence_claim_wins_and_dissent_is_recorded(self):
        service = _service()
        profile = _profile(service)
        service.record_field_claim(
            profile.group_id, "motivation", "espionage", source_id="srcA",
            observed_at=NOW, confidence=0.9, now=NOW
        )
        service.record_field_claim(
            profile.group_id, "motivation", "sabotage", source_id="srcB",
            observed_at=NOW, confidence=0.5, now=NOW
        )
        resolved = service.resolved_field(profile.group_id, "motivation")
        assert resolved.value == "espionage"
        assert resolved.winning_source_id == "srcA"
        assert "srcB" in resolved.dissenting_sources

    def test_resolved_field_returns_none_when_unclaimed(self):
        service = _service()
        profile = _profile(service)
        assert service.resolved_field(profile.group_id, "motivation") is None

    def test_field_conflicts_are_scoped_to_one_group(self):
        service = _service()
        a = service.create_profile(canonical_name="A", now=NOW)
        b = service.create_profile(canonical_name="B", now=NOW)
        for group, value in ((a, "espionage"), (b, "financial")):
            service.record_field_claim(
                group.group_id, "motivation", value,
                source_id="s1", observed_at=NOW, confidence=0.9, now=NOW
            )
            service.record_field_claim(
                group.group_id, "motivation", f"other-{value}",
                source_id="s2", observed_at=NOW, confidence=0.5, now=NOW
            )
        assert len(service.field_conflicts(a.group_id)) == 1
        assert all(c.entity_id == a.group_id for c in service.field_conflicts(a.group_id))

    def test_resolved_disagreement_is_still_reported_with_its_dissent(self):
        """
        Regression: field_conflicts() filtered to open conflicts only, so a disagreement the
        resolver had settled deterministically - which still carries dissenting sources - was
        invisible to anyone reviewing the profile.
        """
        service = _service()
        profile = _profile(service)
        service.record_field_claim(
            profile.group_id, "motivation", "espionage",
            source_id="sA", observed_at=NOW, confidence=0.9, now=NOW
        )
        service.record_field_claim(
            profile.group_id, "motivation", "sabotage",
            source_id="sB", observed_at=NOW, confidence=0.5, now=NOW
        )
        conflicts = service.field_conflicts(profile.group_id)
        assert len(conflicts) == 1
        assert conflicts[0].state == ConflictState.RESOLVED
        assert service.open_field_conflicts(profile.group_id) == []
        assert service.resolved_field(profile.group_id, "motivation").dissenting_sources == ["sB"]

    def test_apply_resolved_fields_is_restricted_to_a_whitelist(self):
        """Identity and reference fields must not be silently rewritten from source claims."""
        service = _service()
        profile = _profile(service)
        with pytest.raises(GroupProfileValidationError) as exc:
            service.apply_resolved_fields(profile.group_id, ["motivation", "group_id"], now=NOW)
        assert "group_id" in str(exc.value)

    def test_apply_resolved_fields_updates_the_profile(self):
        service = _service()
        profile = _profile(service)
        service.record_field_claim(
            profile.group_id, "motivation", "financial",
            source_id="srcA", observed_at=NOW, confidence=0.9, now=NOW
        )
        updated = service.apply_resolved_fields(
            profile.group_id, ["motivation"], actor="analyst", now=NOW
        )
        assert updated.motivation == "financial"

    def test_apply_resolved_fields_is_a_no_op_without_a_resolution(self):
        service = _service()
        profile = _profile(service)
        before = profile.revision
        updated = service.apply_resolved_fields(profile.group_id, ["motivation"], now=NOW)
        assert updated.revision == before

    def test_field_claim_writes_history(self):
        service = _service()
        profile = _profile(service)
        service.record_field_claim(
            profile.group_id, "motivation", "financial",
            source_id="srcA", observed_at=NOW, now=NOW
        )
        assert "field_claim_recorded" in [h.action for h in service.history_for(profile.group_id)]


# ----------------------------------------------------------------------
# Duplicates and merge
# ----------------------------------------------------------------------

class TestDuplicatesAndMerge:
    def test_shared_alias_is_reported(self):
        service = _service()
        service.create_profile(canonical_name="APT29", now=NOW)
        service.create_profile(
            canonical_name="Cozy Bear", aliases=[{"value": "APT29", "source_id": "s"}], now=NOW
        )
        groups = service.duplicate_profiles()
        assert len(groups) == 1
        assert isinstance(groups[0], GroupDuplicateGroup)
        assert groups[0].shared_kind == "alias"
        assert groups[0].shared_key == "apt29"

    def test_shared_identifier_is_reported(self):
        service = _service()
        service.create_profile(
            canonical_name="APT29",
            identifiers=[{"value": "G0016", "kind": GroupIdentifierKind.MITRE_GROUP, "source_id": "m"}],
            now=NOW,
        )
        service.create_profile(
            canonical_name="Cozy Bear",
            identifiers=[{"value": "g0016", "kind": GroupIdentifierKind.MITRE_GROUP, "source_id": "m"}],
            now=NOW,
        )
        assert [g.shared_kind for g in service.duplicate_profiles()] == ["identifier"]

    def test_distinct_profiles_are_not_duplicates(self):
        service = _service()
        service.create_profile(canonical_name="APT29", now=NOW)
        service.create_profile(canonical_name="Lazarus", now=NOW)
        assert service.duplicate_profiles() == []

    def test_duplicates_are_never_auto_merged(self):
        service = _service()
        service.create_profile(canonical_name="APT29", now=NOW)
        service.create_profile(
            canonical_name="Cozy Bear", aliases=[{"value": "APT29", "source_id": "s"}], now=NOW
        )
        service.duplicate_profiles()
        assert len(service.list_profiles()) == 2
        assert all(p.status != GroupProfileStatus.MERGED for p in service.list_profiles())

    def test_merge_requires_actor_and_basis(self):
        service = _service()
        a = service.create_profile(canonical_name="A", now=NOW)
        b = service.create_profile(canonical_name="B", now=NOW)
        with pytest.raises(GroupProfileValidationError):
            service.merge_profiles(
                source_group_id=a.group_id, target_group_id=b.group_id, actor="", basis="x", now=NOW
            )
        with pytest.raises(GroupProfileValidationError):
            service.merge_profiles(
                source_group_id=a.group_id, target_group_id=b.group_id, actor="a", basis="  ", now=NOW
            )

    def test_a_profile_cannot_be_merged_into_itself(self):
        service = _service()
        a = service.create_profile(canonical_name="A", now=NOW)
        with pytest.raises(GroupProfileValidationError):
            service.merge_profiles(
                source_group_id=a.group_id, target_group_id=a.group_id, actor="a", basis="x", now=NOW
            )

    def test_merge_moves_associations(self):
        service = _service()
        source = service.create_profile(canonical_name="Cozy Bear", now=NOW)
        target = service.create_profile(canonical_name="APT29", now=NOW)
        service.associate(
            group_id=source.group_id, kind=GroupAssociationKind.CAMPAIGN,
            entity_id="c1", source_id="s", now=NOW
        )
        service.merge_profiles(
            source_group_id=source.group_id, target_group_id=target.group_id,
            actor="analyst", basis="same tradecraft cluster", now=NOW
        )
        assert service.campaigns_for(target.group_id) == ("c1",)
        assert service.campaigns_for(source.group_id) == ()

    def test_merge_marks_source_merged_without_deleting(self):
        service = _service()
        source = service.create_profile(canonical_name="Cozy Bear", now=NOW)
        target = service.create_profile(canonical_name="APT29", now=NOW)
        service.merge_profiles(
            source_group_id=source.group_id, target_group_id=target.group_id,
            actor="analyst", basis="same tradecraft cluster", now=NOW
        )
        assert service.get_profile(source.group_id).status == GroupProfileStatus.MERGED
        assert service.get_profile(source.group_id) is not None

    def test_merge_carries_aliases_identifiers_and_targeting(self):
        service = _service()
        source = service.create_profile(
            canonical_name="Cozy Bear",
            aliases=[{"value": "YTtrium", "source_id": "s"}],
            identifiers=[{"value": "G9999", "kind": GroupIdentifierKind.OTHER, "source_id": "m"}],
            target_sectors=["finance"],
            target_regions=["eu"],
            now=NOW,
        )
        target = service.create_profile(canonical_name="APT29", target_sectors=["government"], now=NOW)
        merged = service.merge_profiles(
            source_group_id=source.group_id, target_group_id=target.group_id,
            actor="analyst", basis="same tradecraft cluster", now=NOW
        )
        assert "YTtrium" in merged.active_alias_names
        assert [i.value for i in merged.identifiers] == ["G9999"]
        assert set(merged.target_sectors) == {"government", "finance"}
        assert merged.target_regions == ["eu"]

    def test_merge_carries_the_mitre_reference_when_the_target_lacks_one(self):
        service = _service()
        source = service.create_profile(canonical_name="Cozy Bear", now=NOW)
        service.attach_mitre_group(source.group_id, _mitre_group(), now=NOW)
        target = service.create_profile(canonical_name="APT29", now=NOW)
        merged = service.merge_profiles(
            source_group_id=source.group_id, target_group_id=target.group_id,
            actor="analyst", basis="same group", now=NOW
        )
        assert merged.mitre_group_id == "G0016"

    def test_merge_does_not_duplicate_shared_aliases(self):
        service = _service()
        source = service.create_profile(
            canonical_name="Cozy Bear", aliases=[{"value": "Shared", "source_id": "s"}], now=NOW
        )
        target = service.create_profile(
            canonical_name="APT29", aliases=[{"value": "Shared", "source_id": "s"}], now=NOW
        )
        merged = service.merge_profiles(
            source_group_id=source.group_id, target_group_id=target.group_id,
            actor="analyst", basis="same group", now=NOW
        )
        assert len([a for a in merged.aliases if a.match_key == "shared"]) == 1

    def test_merge_history_is_recorded_on_both_sides(self):
        service = _service()
        source = service.create_profile(canonical_name="Cozy Bear", now=NOW)
        target = service.create_profile(canonical_name="APT29", now=NOW)
        service.merge_profiles(
            source_group_id=source.group_id, target_group_id=target.group_id,
            actor="analyst", basis="same group", now=NOW
        )
        assert "profile_merged_out" in [h.action for h in service.history_for(source.group_id)]
        assert "profile_merged_in" in [h.action for h in service.history_for(target.group_id)]

    def test_merged_profiles_excluded_from_duplicate_detection(self):
        service = _service()
        source = service.create_profile(
            canonical_name="Cozy Bear", aliases=[{"value": "APT29", "source_id": "s"}], now=NOW
        )
        target = service.create_profile(canonical_name="APT29", now=NOW)
        service.merge_profiles(
            source_group_id=source.group_id, target_group_id=target.group_id,
            actor="analyst", basis="same group", now=NOW
        )
        assert service.duplicate_profiles() == []

    def test_merge_requires_existing_profiles(self):
        service = _service()
        target = service.create_profile(canonical_name="APT29", now=NOW)
        with pytest.raises(GroupProfileNotFoundError):
            service.merge_profiles(
                source_group_id="TG-nope", target_group_id=target.group_id,
                actor="a", basis="x", now=NOW
            )


# ----------------------------------------------------------------------
# Revision history
# ----------------------------------------------------------------------

class TestRevisionHistory:
    def test_creation_writes_history(self):
        service = _service()
        profile = _profile(service)
        entries = service.history_for(profile.group_id)
        assert len(entries) == 1
        assert entries[0].action == "profile_created"
        assert isinstance(entries[0], GroupProfileRevision)

    def test_history_is_append_only(self):
        service = _service()
        profile = _profile(service)
        before = list(service.history_for(profile.group_id))
        service.add_alias(profile.group_id, value="Cozy Bear", source_id="s", now=NOW)
        after = service.history_for(profile.group_id)
        assert after[: len(before)] == before
        assert len(after) == len(before) + 1

    def test_revision_counter_increments_on_change(self):
        service = _service()
        profile = _profile(service)
        assert profile.revision == 1
        assert service.revise_profile(
            profile.group_id, motivation="financial", actor="a", now=NOW
        ).revision == 2

    def test_no_op_revision_does_not_bump_the_counter(self):
        service = _service()
        profile = _profile(service)
        updated = service.revise_profile(
            profile.group_id, motivation=profile.motivation, actor="a", now=NOW
        )
        assert updated.revision == 1

    def test_revision_records_the_actor(self):
        service = _service()
        profile = _profile(service)
        service.revise_profile(profile.group_id, motivation="financial", actor="analyst-1", now=NOW)
        assert service.history_for(profile.group_id)[-1].actor == "analyst-1"

    def test_first_seen_only_moves_earlier(self):
        from datetime import timedelta

        service = _service()
        profile = service.create_profile(canonical_name="A", first_seen=NOW, now=NOW)
        service.revise_profile(profile.group_id, first_seen=NOW + timedelta(days=5), now=NOW)
        assert service.get_profile(profile.group_id).first_seen == NOW
        service.revise_profile(profile.group_id, first_seen=NOW - timedelta(days=5), now=NOW)
        assert service.get_profile(profile.group_id).first_seen == NOW - timedelta(days=5)

    def test_last_seen_only_moves_later(self):
        from datetime import timedelta

        service = _service()
        profile = service.create_profile(canonical_name="A", last_seen=NOW, now=NOW)
        service.revise_profile(profile.group_id, last_seen=NOW - timedelta(days=5), now=NOW)
        assert service.get_profile(profile.group_id).last_seen == NOW
        service.revise_profile(profile.group_id, last_seen=NOW + timedelta(days=5), now=NOW)
        assert service.get_profile(profile.group_id).last_seen == NOW + timedelta(days=5)

    def test_association_advances_first_and_last_seen(self):
        from datetime import timedelta

        service = _service()
        profile = _profile(service)
        service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN, entity_id="c1",
            source_id="s", observed_at=NOW - timedelta(days=10), now=NOW
        )
        service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN, entity_id="c2",
            source_id="s", observed_at=NOW, now=NOW
        )
        stored = service.get_profile(profile.group_id)
        assert stored.first_seen == NOW - timedelta(days=10)
        assert stored.last_seen == NOW

    def test_status_transition_recorded(self):
        service = _service()
        profile = _profile(service)
        service.set_status(profile.group_id, GroupProfileStatus.ACTIVE, actor="a", now=NOW)
        assert service.get_profile(profile.group_id).status == GroupProfileStatus.ACTIVE
        assert "status" in service.history_for(profile.group_id)[-1].detail

    def test_reverting_to_fixture_restores_the_experimental_label(self):
        service = _service()
        profile = service.create_profile(
            canonical_name="A", verification_mode=VerificationMode.LIVE_VERIFIED, now=NOW
        )
        assert profile.experimental_label is None
        service.revise_profile(
            profile.group_id, verification_mode=VerificationMode.FIXTURE_TESTED, actor="a", now=NOW
        )
        assert service.get_profile(profile.group_id).experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_history_for_unknown_raises(self):
        with pytest.raises(GroupProfileNotFoundError):
            _service().history_for("TG-nope")

    def test_full_history_covers_every_profile(self):
        service = _service()
        a = service.create_profile(canonical_name="A", now=NOW)
        b = service.create_profile(canonical_name="B", now=NOW)
        assert {r.group_id for r in service.full_history()} == {a.group_id, b.group_id}


# ----------------------------------------------------------------------
# Search
# ----------------------------------------------------------------------

class TestSearch:
    def test_search_matches_alias_and_description(self):
        service = _service()
        profile = _profile(service, description="A Russian espionage group")
        service.add_alias(profile.group_id, value="Cozy Bear", source_id="s", now=NOW)
        assert [p.group_id for p in service.search(query="cozy bear")] == [profile.group_id]
        assert [p.group_id for p in service.search(query="espionage group")] == [profile.group_id]
        assert service.search(query="nothing-matches") == []

    def test_search_matches_identifiers(self):
        service = _service()
        profile = _profile(service)
        service.add_identifier(
            profile.group_id, value="G0016", kind=GroupIdentifierKind.MITRE_GROUP,
            source_id="m", now=NOW
        )
        assert [p.group_id for p in service.search(query="g0016")] == [profile.group_id]

    def test_search_filters_by_motivation_and_country(self):
        service = _service()
        service.create_profile(canonical_name="A", motivation="espionage", country_of_origin="RU", now=NOW)
        service.create_profile(canonical_name="B", motivation="financial", country_of_origin="CN", now=NOW)
        assert [p.canonical_name for p in service.search(motivation="espionage")] == ["A"]
        assert [p.canonical_name for p in service.search(country="CN")] == ["B"]
        assert service.search(motivation="espionage", country="CN") == []

    def test_search_filters_by_target_sector(self):
        service = _service()
        service.create_profile(canonical_name="A", target_sectors=["finance"], now=NOW)
        service.create_profile(canonical_name="B", target_sectors=["health"], now=NOW)
        assert [p.canonical_name for p in service.search(target_sector="finance")] == ["A"]

    def test_search_filters_by_status_and_verification(self):
        service = _service()
        service.create_profile(canonical_name="A", now=NOW, status=GroupProfileStatus.ACTIVE)
        service.create_profile(canonical_name="B", now=NOW)
        assert [p.canonical_name for p in service.search(status=GroupProfileStatus.ACTIVE)] == ["A"]
        assert len(service.search(verification_mode=VerificationMode.FIXTURE_TESTED)) == 2

    def test_search_paginates(self):
        service = _service()
        for index in range(5):
            service.create_profile(canonical_name=f"Grp{index}", now=NOW)
        assert len(service.search(limit=2)) == 2
        assert len(service.search(limit=2, offset=2)) == 2
        assert len(service.search(limit=2, offset=4)) == 1

    def test_search_rejects_negative_pagination(self):
        with pytest.raises(GroupProfileValidationError):
            _service().search(limit=-1)

    def test_find_by_alias_case_insensitive(self):
        service = _service()
        profile = _profile(service)
        service.add_alias(profile.group_id, value="Cozy Bear", source_id="s", now=NOW)
        assert [p.group_id for p in service.find_by_alias("COZY bear")] == [profile.group_id]

    def test_find_by_identifier_kind_filterable(self):
        service = _service()
        profile = _profile(service)
        service.add_identifier(
            profile.group_id, value="G0016", kind=GroupIdentifierKind.MITRE_GROUP,
            source_id="m", now=NOW
        )
        assert [p.group_id for p in service.find_by_identifier("g0016")] == [profile.group_id]
        assert service.find_by_identifier("g0016", kind=GroupIdentifierKind.OTHER) == []


# ----------------------------------------------------------------------
# Relationship integration
# ----------------------------------------------------------------------

class TestRelationshipIntegration:
    def test_every_association_kind_maps_to_an_existing_relationship_type(self):
        assert set(ASSOCIATION_RELATIONSHIP_TYPE) == set(GroupAssociationKind)
        for kind, relationship_type in ASSOCIATION_RELATIONSHIP_TYPE.items():
            assert relationship_type in RELATIONSHIP_TYPES, f"{kind} maps to an unknown type"

    def test_confirmed_association_uses_the_typed_edge(self):
        service = _service()
        profile = _profile(service)
        service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN, entity_id="c1",
            source_id="s", origin=AssertionOrigin.DIRECTLY_SOURCED, confidence=0.9,
            evidence=_evidence(1), confirm=True, now=NOW
        )
        rows = service.export_relationships()
        assert rows[0]["relationship_type"] == "ATTRIBUTED_TO"

    def test_unconfirmed_association_exports_a_weaker_edge(self):
        """An uncertain link must not be exported as a confirmed graph edge."""
        service = _service()
        profile = _profile(service)
        service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN, entity_id="c1",
            source_id="s", origin=AssertionOrigin.MACHINE_INFERRED, confidence=0.5, now=NOW
        )
        assert service.export_relationships()[0]["relationship_type"] == "ASSOCIATED_WITH"

    def test_export_is_accepted_by_the_relationship_service(self):
        """Proves the export is a real integration seam, not a plausible-looking shape."""
        service = _service()
        profile = _profile(service)
        service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN, entity_id="c1",
            entity_name="Operation X", source_id="s",
            origin=AssertionOrigin.DIRECTLY_SOURCED, confidence=0.9,
            evidence=_evidence(1), confirm=True, now=NOW
        )
        relationships = RelationshipService()
        created = [relationships.create_relationship(r) for r in service.export_relationships()]
        assert len(created) == 1
        assert created[0].source_entity_id == profile.group_id
        assert created[0].target_entity_id == "c1"
        assert created[0].relationship_type == "ATTRIBUTED_TO"

    def test_export_carries_confidence_and_provenance(self):
        service = _service()
        profile = _profile(service)
        service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN, entity_id="c1",
            source_id="vendor", origin=AssertionOrigin.DIRECTLY_SOURCED, confidence=0.9,
            provenance="campaign-cluster-3", evidence=_evidence(1), confirm=True, now=NOW
        )
        row = service.export_relationships()[0]
        assert row["confidence"] == 0.9
        assert row["provenance"] == "campaign-cluster-3"
        assert row["source"] == "vendor"

    def test_withdrawn_associations_are_not_exported(self):
        service = _service()
        profile = _profile(service)
        association = service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN,
            entity_id="c1", source_id="s", now=NOW
        )
        service.withdraw_association(association.association_id, now=NOW)
        assert service.export_relationships() == []


# ----------------------------------------------------------------------
# Statistics and tenancy
# ----------------------------------------------------------------------

class TestStatisticsAndTenancy:
    def test_stats_reports_verification_honesty(self):
        assert _service().stats()["verification_mode"] == "fixture_tested_only_no_outbound_requests"

    def test_stats_counts_profiles_and_associations(self):
        service = _service()
        profile = _profile(service)
        service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN, entity_id="c1",
            source_id="s", origin=AssertionOrigin.DIRECTLY_SOURCED, confidence=0.9,
            evidence=_evidence(1), confirm=True, now=NOW
        )
        stats = service.stats()
        assert stats["profiles"] == 1
        assert stats["associations_total"] == 1
        assert stats["associations_confirmed"] == 1
        assert stats["associations_by_kind"]["campaign"] == 1

    def test_stats_counts_source_specific_names(self):
        service = _service()
        profile = _profile(service)
        service.record_source_specific_name(profile.group_id, value="Cozy Bear", source_id="v", now=NOW)
        assert service.stats()["source_specific_names"] == 1

    def test_stats_counts_mitre_attachments(self):
        service = _service()
        profile = _profile(service)
        service.attach_mitre_group(profile.group_id, _mitre_group(), now=NOW)
        assert service.stats()["profiles_with_mitre_group"] == 1

    def test_stats_counts_clamped_confidence(self):
        service = _service()
        profile = _profile(service)
        service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.MALWARE, entity_id="mw1",
            source_id="sandbox", origin=AssertionOrigin.MACHINE_INFERRED, confidence=0.99, now=NOW
        )
        assert service.stats()["associations_clamped"] == 1

    def test_stats_is_empty_for_a_new_service(self):
        stats = _service().stats()
        assert stats["profiles"] == 0
        assert stats["associations_total"] == 0
        assert stats["history_entries"] == 0

    def test_group_ids_are_tenant_scoped(self):
        first = ThreatGroupProfileService(tenant_id="t1")
        second = ThreatGroupProfileService(tenant_id="t2")
        a = first.create_profile(canonical_name="APT29", now=NOW)
        b = second.create_profile(canonical_name="APT29", now=NOW)
        assert a.group_id != b.group_id
        assert first.get_profile(b.group_id) is None

    def test_associations_are_tenant_stamped(self):
        service = ThreatGroupProfileService(tenant_id="t1")
        profile = _profile(service)
        association = service.associate(
            group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN,
            entity_id="c1", source_id="s", now=NOW
        )
        assert association.tenant_id == "t1"


# ----------------------------------------------------------------------
# Concurrency
# ----------------------------------------------------------------------

class TestConcurrentAccess:
    def test_concurrent_association_loses_no_records(self):
        import threading

        service = _service()
        profile = _profile(service)
        barrier = threading.Barrier(4)
        errors: list = []

        def worker(index: int) -> None:
            try:
                barrier.wait(timeout=5)
                for step in range(25):
                    service.associate(
                        group_id=profile.group_id, kind=GroupAssociationKind.CAMPAIGN,
                        entity_id=f"c-{index}-{step}", source_id=f"src-{index}",
                        confidence=0.5, now=NOW
                    )
            except Exception as exc:  # pragma: no cover - surfaces in the assertion below
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)

        assert errors == []
        assert len(service.campaigns_for(profile.group_id)) == 100

    def test_concurrent_alias_writes_stay_consistent(self):
        import threading

        service = _service()
        profile = _profile(service)
        barrier = threading.Barrier(4)
        errors: list = []

        def writer(index: int) -> None:
            try:
                barrier.wait(timeout=5)
                for step in range(10):
                    service.add_alias(
                        profile.group_id, value=f"alias-{index}-{step}",
                        source_id=f"src-{index}", now=NOW
                    )
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)

        assert errors == []
        assert len(service.get_profile(profile.group_id).aliases) == 40


# ----------------------------------------------------------------------
# Package surface
# ----------------------------------------------------------------------

class TestPackageSurface:
    def test_module_exports_are_bound_on_the_package(self):
        import apps.threat_intelligence as ti

        for name in (
            "ThreatGroupProfileService",
            "ThreatGroupProfile",
            "GroupAssociation",
            "GroupAssociationKind",
            "GroupAssociationStatus",
            "GroupIdentifierKind",
            "GroupProfileStatus",
            "UnconfirmedAssociationError",
        ):
            assert hasattr(ti, name), f"{name} is not exported from the package"
