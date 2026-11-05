"""Tests for apps.threat_intelligence.reports — Domain B item 24 (Threat Intelligence Reports)."""

import pytest
from datetime import datetime, timedelta

from apps.threat_intelligence.reports import (
    DuplicateReportError,
    MAX_REFERENCES_PER_REPORT,
    ReportAppendOnlyViolationError,
    ReportClassification,
    ReportEntityReference,
    ReportEvidenceRef,
    ReportKind,
    ReportOrigin,
    ReportRelationshipRef,
    ReportSourceAttribution,
    ReportStatus,
    ReportValidationError,
    ReportVerificationMode,
    ThreatIntelReport,
    ThreatIntelReportService,
)

TENANT = "tenant-reports"
T0 = datetime(2026, 11, 5, 12, 0, 0)


def _refs():
    return [
        ReportEntityReference(
            entity_id="actor-1",
            entity_type="threat_actor",
            entity_name="APT-Test",
            referenced_at=T0,
        ),
        ReportEntityReference(
            entity_id="mal-1", entity_type="malware", entity_name="TestLoader", referenced_at=T0
        ),
    ]


def _rels(inferred: bool = True):
    return [
        ReportRelationshipRef(
            source_entity_id="actor-1",
            relationship_type="uses",
            target_entity_id="mal-1",
            confidence=0.72,
            inferred=inferred,
            provenance="analyst-inference",
        )
    ]


def _svc():
    return ThreatIntelReportService(tenant_id=TENANT)


def _report(svc, **kw):
    base = dict(
        title="APT-Test profile",
        summary="Observed actor using TestLoader against logistics targets.",
        body="Detailed analytical body with supporting reasoning.",
        author_ref="agent-6",
        kind=ReportKind.ACTOR_PROFILE,
        entity_refs=_refs(),
        relationship_refs=_rels(),
        confidence=0.72,
        freshness_at=T0,
        now=T0,
    )
    base.update(kw)
    return svc.create_report(**base)


# --------------------------------------------------------------------- basics


def test_tenant_id_is_required():
    with pytest.raises(ReportValidationError):
        ThreatIntelReportService(tenant_id="   ")


def test_report_id_is_stable_and_prefixed():
    svc = _svc()
    report = _report(svc)
    assert report.report_id.startswith("TIR-actor_profile-")
    assert svc.get_report(report.report_id).report_id == report.report_id


def test_caller_supplied_report_id_is_honoured_and_unique():
    svc = _svc()
    report = _report(svc, report_id="TIR-fixed-0001")
    assert report.report_id == "TIR-fixed-0001"
    with pytest.raises(ReportValidationError):
        _report(svc, report_id="TIR-fixed-0001", body="different body entirely")


def test_empty_title_summary_or_body_rejected():
    svc = _svc()
    for field in ("title", "summary", "body"):
        with pytest.raises(ReportValidationError):
            _report(svc, **{field: "   "})


def test_author_ref_is_required_for_attributability():
    svc = _svc()
    with pytest.raises(ReportValidationError):
        _report(svc, author_ref="   ")


def test_indicator_brief_requires_at_least_one_entity_reference():
    svc = _svc()
    with pytest.raises(ReportValidationError):
        _report(svc, kind=ReportKind.INDICATOR_BRIEF, entity_refs=[], relationship_refs=[])


def test_tags_are_deduplicated_and_trimmed():
    svc = _svc()
    report = _report(svc, tags=[" apt ", "apt", "", "logistics"])
    assert report.tags == ["apt", "logistics"]


# ------------------------------------------------------- no invented entities


def test_relationship_endpoint_must_be_referenced():
    """Reports may only reference entities they were given - no invented entity IDs."""
    svc = _svc()
    phantom = [
        ReportRelationshipRef(
            source_entity_id="actor-1",
            relationship_type="uses",
            target_entity_id="ghost-malware",
            confidence=0.5,
        )
    ]
    with pytest.raises(ReportValidationError):
        _report(svc, relationship_refs=phantom)


def test_inferred_relationships_are_flagged_not_hidden():
    svc = _svc()
    inferred = _report(svc)
    confirmed = _report(svc, relationship_refs=_rels(inferred=False), body="Different body.")
    assert inferred.has_inferred_relationships() is True
    assert confirmed.has_inferred_relationships() is False


def test_entity_type_and_relationship_type_are_normalised():
    ref = ReportEntityReference(entity_id="x", entity_type="  Threat_Actor ", referenced_at=T0)
    assert ref.entity_type == "threat_actor"
    rel = ReportRelationshipRef(
        source_entity_id="a", relationship_type="  attributed_to ", target_entity_id="b"
    )
    assert rel.relationship_type == "ATTRIBUTED_TO"


# ------------------------------------------------------------- deduplication


def test_identical_report_deduplicates():
    svc = _svc()
    first = _report(svc)
    with pytest.raises(DuplicateReportError):
        _report(svc)
    # allow_duplicate makes admission idempotent instead of raising
    again = _report(svc, allow_duplicate=True)
    assert again.report_id == first.report_id
    assert svc.stats()["report_count"] == 1


def test_content_hash_ignores_bookkeeping_fields():
    svc = _svc()
    first = _report(svc)
    # Same analysis, different id/author/metadata -> same hash
    same_hash = svc.compute_content_hash(
        first.title, first.summary, first.body, first.kind, first.classification, _refs(), _rels()
    )
    assert same_hash == first.content_hash


def test_content_hash_is_order_insensitive_for_references():
    svc = _svc()
    forward = _refs()
    backward = list(reversed(_refs()))
    a = svc.compute_content_hash("t", "s", "b", ReportKind.ACTOR_PROFILE, ReportClassification.INTERNAL, forward, _rels())
    b = svc.compute_content_hash("t", "s", "b", ReportKind.ACTOR_PROFILE, ReportClassification.INTERNAL, backward, _rels())
    assert a == b


def test_content_hash_changes_with_analytical_content():
    svc = _svc()
    a = svc.compute_content_hash("t", "s", "b", ReportKind.ACTOR_PROFILE, ReportClassification.INTERNAL, _refs(), [])
    b = svc.compute_content_hash("t", "s", "b2", ReportKind.ACTOR_PROFILE, ReportClassification.INTERNAL, _refs(), [])
    c = svc.compute_content_hash("t", "s", "b", ReportKind.MALWARE_PROFILE, ReportClassification.INTERNAL, _refs(), [])
    assert len({a, b, c}) == 3


def test_content_hash_distinguishes_inferred_from_confirmed_relationships():
    svc = _svc()
    a = svc.compute_content_hash("t", "s", "b", ReportKind.ACTOR_PROFILE, ReportClassification.INTERNAL, _refs(), _rels(True))
    b = svc.compute_content_hash("t", "s", "b", ReportKind.ACTOR_PROFILE, ReportClassification.INTERNAL, _refs(), _rels(False))
    assert a != b


def test_supersedes_must_reference_a_known_report():
    svc = _svc()
    with pytest.raises(ReportValidationError):
        _report(svc, supersedes="TIR-does-not-exist", body="brand new body")


# ------------------------------------------------------------------- history


def test_create_appends_history_entry():
    svc = _svc()
    report = _report(svc)
    history = svc.history_for(report.report_id)
    assert len(history) == 1
    assert history[0].change_type == "created"
    assert history[0].version == 1
    assert history[0].previous_content_hash is None


def test_history_requires_basis_and_actor():
    svc = _svc()
    report = _report(svc)
    with pytest.raises(ReportValidationError):
        svc.revise_report(report.report_id, change_basis="   ", actor="agent-6", body="new body")
    with pytest.raises(ReportValidationError):
        svc.revise_report(report.report_id, change_basis="ok", actor="  ", body="new body")


def test_revision_increments_version_and_chains_hashes():
    svc = _svc()
    report = _report(svc)
    original_hash = report.content_hash
    revised = svc.revise_report(
        report.report_id, change_basis="new attribution from corroboration", actor="agent-6", body="Revised body."
    )
    assert revised.version == 2
    assert revised.content_hash != original_hash
    history = svc.history_for(report.report_id)
    assert [h.change_type for h in history] == ["created", "revised"]
    assert history[1].previous_content_hash == original_hash
    assert history[1].content_hash == revised.content_hash


def test_revision_does_not_mutate_the_previous_record():
    svc = _svc()
    report = _report(svc)
    original_body = report.body
    svc.revise_report(report.report_id, change_basis="edit", actor="agent-6", body="Revised body.")
    assert report.body == original_body
    assert report.version == 1
    assert svc.get_report(report.report_id).version == 2


def test_no_op_revision_is_rejected():
    svc = _svc()
    report = _report(svc)
    with pytest.raises(ReportValidationError):
        svc.revise_report(report.report_id, change_basis="nothing", actor="agent-6")


def test_revision_cannot_duplicate_another_report():
    svc = _svc()
    a = _report(svc)
    _report(svc, body="Second report body.")
    with pytest.raises(DuplicateReportError):
        svc.revise_report(a.report_id, change_basis="copy", actor="agent-6", body="Second report body.")


def test_history_is_returned_immutable():
    svc = _svc()
    report = _report(svc)
    snapshot = svc.full_history()
    assert isinstance(snapshot, tuple)
    with pytest.raises(Exception):
        snapshot[0] = None  # type: ignore[index]


def test_unknown_history_change_type_is_a_violation():
    svc = _svc()
    report = _report(svc)
    with pytest.raises(ReportAppendOnlyViolationError):
        svc._append_history(report, "destroyed", "bad", "agent-6", None)


# -------------------------------------------------------------------- status


def test_status_lifecycle_and_terminal_states():
    svc = _svc()
    report = _report(svc)
    assert report.status is ReportStatus.DRAFT

    in_review = svc.transition_status(report.report_id, ReportStatus.IN_REVIEW, "sent for review", "agent-6")
    assert in_review.status is ReportStatus.IN_REVIEW

    published = svc.transition_status(report.report_id, ReportStatus.PUBLISHED, "review passed", "agent-6")
    assert published.status is ReportStatus.PUBLISHED

    with pytest.raises(ReportValidationError):
        svc.transition_status(report.report_id, ReportStatus.DRAFT, "retract to draft", "agent-6")

    retracted = svc.transition_status(report.report_id, ReportStatus.RETRACTED, "withdrawn", "agent-6")
    assert retracted.status is ReportStatus.RETRACTED
    with pytest.raises(ReportValidationError):
        svc.transition_status(report.report_id, ReportStatus.PUBLISHED, "undo", "agent-6")
    with pytest.raises(ReportValidationError):
        svc.revise_report(report.report_id, change_basis="x", actor="agent-6", body="y")


def test_same_status_transition_is_a_no_op():
    svc = _svc()
    report = _report(svc)
    svc.transition_status(report.report_id, ReportStatus.DRAFT, "no change", "agent-6")
    assert len(svc.history_for(report.report_id)) == 1


def test_publishing_records_inferred_relationships_in_history():
    svc = _svc()
    report = _report(svc)
    svc.transition_status(report.report_id, ReportStatus.PUBLISHED, "review passed", "agent-6")
    stored = svc.get_report(report.report_id)
    assert stored.has_inferred_relationships() is True
    assert stored.relationship_refs[0].inferred is True


# ------------------------------------------------------- freshness semantics


def test_stale_only_when_a_horizon_was_declared():
    svc = _svc()
    with_horizon = _report(svc, stale_after_seconds=3600)
    without = _report(svc, body="Different body.", stale_after_seconds=None)
    assert with_horizon.is_stale(T0 + timedelta(hours=2)) is True
    assert with_horizon.is_stale(T0 + timedelta(minutes=30)) is False
    assert without.is_stale(T0 + timedelta(days=365)) is False


def test_future_dated_freshness_yields_no_age():
    svc = _svc()
    report = _report(svc, freshness_at=T0 + timedelta(days=3), stale_after_seconds=60)
    assert report.age_seconds(T0) is None
    assert report.is_stale(T0) is False


def test_freshness_far_after_created_at_is_rejected():
    svc = _svc()
    with pytest.raises(ReportValidationError):
        _report(svc, freshness_at=T0 + timedelta(days=800))


def test_age_seconds_is_exact():
    svc = _svc()
    report = _report(svc)
    assert report.age_seconds(T0 + timedelta(seconds=90)) == 90


# -------------------------------------------------------------------- search


def test_search_by_text_kind_status_and_tag():
    svc = _svc()
    a = _report(svc)
    _report(svc, title="Logistics campaign summary", body="Campaign body.", kind=ReportKind.CAMPAIGN_SUMMARY, tags=["logistics"])
    svc.transition_status(a.report_id, ReportStatus.PUBLISHED, "ok", "agent-6")

    assert len(svc.search(text="logistics")) == 2
    assert len(svc.search(kind=ReportKind.CAMPAIGN_SUMMARY)) == 1
    assert len(svc.search(status=ReportStatus.PUBLISHED)) == 1
    assert len(svc.search(tag="logistics")) == 1
    assert len(svc.search(tag="LOGISTICS")) == 1
    assert svc.search(text="nothing-matches-xyz") == []


def test_search_by_entity_and_confidence_and_staleness():
    svc = _svc()
    _report(svc)
    _report(svc, body="Other body.", confidence=0.10, stale_after_seconds=10)
    assert len(svc.search(entity_id="actor-1")) == 2
    assert len(svc.search(entity_id="mal-1")) == 2
    assert len(svc.search(entity_id="unknown-entity")) == 0
    assert len(svc.search(min_confidence=0.5)) == 1
    assert len(svc.search(stale_only=True, as_of=T0 + timedelta(hours=1))) == 1
    assert len(svc.search(stale_only=False, as_of=T0 + timedelta(hours=1))) == 1


def test_search_pagination_is_ordered_and_bounded():
    svc = _svc()
    for i in range(5):
        _report(svc, title=f"Report {i}", body=f"Body {i}", now=T0 + timedelta(minutes=i))
    page = svc.search(limit=2, offset=0)
    assert len(page) == 2
    assert page[0].created_at >= page[1].created_at
    assert svc.search(limit=2, offset=4)[0].title == "Report 0"
    assert len(svc.search(limit=9999)) == 5


def test_find_reports_for_entity_tracks_revisions():
    svc = _svc()
    report = _report(svc)
    new_ref = ReportEntityReference(entity_id="campaign-9", entity_type="campaign", referenced_at=T0)
    svc.revise_report(
        report.report_id,
        change_basis="added campaign context",
        actor="agent-6",
        add_entity_refs=[new_ref],
    )
    assert svc.find_reports_for_entity("campaign-9")[0].report_id == report.report_id


# --------------------------------------------------------------- provenance


def test_source_attributions_and_evidence_are_preserved():
    svc = _svc()
    report = _report(
        svc,
        source_attributions=[
            ReportSourceAttribution(
                source_id="urlhaus", observation_count=12, reliability_tier="tier1", reliability_score=0.95
            )
        ],
        evidence_refs=[
            ReportEvidenceRef(evidence_id="ev-1", evidence_kind="URL", source_ref="https://example.invalid/1")
        ],
    )
    assert report.source_attributions[0].source_id == "urlhaus"
    assert report.evidence_refs[0].evidence_kind == "url"
    assert report.evidence_refs[0].source_ref == "https://example.invalid/1"


def test_evidence_refs_are_added_on_revision():
    svc = _svc()
    report = _report(svc)
    revised = svc.revise_report(
        report.report_id,
        change_basis="added citation",
        actor="agent-6",
        add_evidence_refs=[ReportEvidenceRef(evidence_id="ev-2")],
    )
    assert len(revised.evidence_refs) == 1
    assert revised.evidence_refs[0].evidence_id == "ev-2"


def test_reference_count_limits_are_enforced():
    svc = _svc()
    too_many = [
        ReportEntityReference(entity_id=f"e-{i}", entity_type="indicator", referenced_at=T0)
        for i in range(MAX_REFERENCES_PER_REPORT + 1)
    ]
    with pytest.raises(ReportValidationError):
        _report(svc, entity_refs=too_many, relationship_refs=[])


# ------------------------------------------------- honesty / demo labelling


def test_experimental_origin_carries_the_demo_label():
    svc = _svc()
    demo = _report(svc)
    live = _report(
        svc,
        body="Live body.",
        origin=ReportOrigin.LIVE_SOURCE,
        verification_mode=ReportVerificationMode.LIVE_VERIFIED,
    )
    assert demo.experimental_label == "EXPERIMENTAL_DEMO_DATA_ONLY"
    assert demo.verification_mode is ReportVerificationMode.FIXTURE_TESTED
    assert live.experimental_label is None
    assert live.verification_mode is ReportVerificationMode.LIVE_VERIFIED


def test_defaults_never_claim_live_verification():
    svc = _svc()
    report = _report(svc)
    assert report.verification_mode is ReportVerificationMode.FIXTURE_TESTED
    assert report.origin is ReportOrigin.EXPERIMENTAL_DEMO


def test_tenant_mismatch_is_rejected():
    svc = _svc()
    report = _report(svc)
    forged = ThreatIntelReport(**{**report.model_dump(), "tenant_id": "other-tenant"})
    with pytest.raises(ReportValidationError):
        svc._validate(forged)


def test_stats_reports_no_mounted_storage():
    svc = _svc()
    _report(svc)
    stats = svc.stats()
    assert stats["report_count"] == 1
    assert stats["history_entry_count"] == 1
    assert stats["verification_modes"] == ["fixture_tested"]
    assert "mounted" in stats["note"] and "in-memory" in stats["note"]


def test_list_reports_bounds_and_orders_by_recency():
    svc = _svc()
    for i in range(3):
        _report(svc, title=f"T{i}", body=f"B{i}", now=T0 + timedelta(minutes=i))
    listing = svc.list_reports(limit=2)
    assert len(listing) == 2
    assert listing[0].created_at == T0 + timedelta(minutes=2)
    assert len(svc.list_reports(limit=100)) == 3
