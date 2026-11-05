"""Tests for apps.threat_intelligence.relationship_analysis — typed semantics, provenance, contradictions, traversal."""

import pytest
from datetime import datetime, timedelta

from apps.threat_intelligence.relationship_analysis import (
    AssertionOrigin,
    AssertionStatus,
    ContradictionRecord,
    DEFAULT_SEMANTICS,
    Direction,
    DuplicateGroup,
    EvidenceItem,
    MAX_TRAVERSAL_DEPTH,
    PathResult,
    RelationshipAnalysisService,
    RelationshipAssertion,
    RelationshipError,
    RelationshipSemantics,
    TraversalResult,
    build_default_semantics,
)
from apps.threat_intelligence.relationships import RELATIONSHIP_TYPES, RelationshipService

TENANT = "t-rel"
T0 = datetime(2026, 11, 5, 12, 0, 0)


def _svc(**kw):
    return RelationshipAnalysisService(tenant_id=TENANT, **kw)


def _ev(n=1):
    return [EvidenceItem(evidence_id=f"e{i}", kind="url", source_ref=f"https://example.invalid/{i}") for i in range(n)]


def _uses(svc, source, target, by, **kw):
    base = dict(confidence=0.8, provenance=f"{by}:2026-11-05", evidence=_ev(), now=T0)
    base.update(kw)
    return svc.assert_relationship(source, target, "USES", by, **base)


# ------------------------------------------------------------------ semantics


def test_semantics_cover_every_declared_relationship_type():
    assert set(build_default_semantics()) == set(RELATIONSHIP_TYPES)
    assert set(DEFAULT_SEMANTICS) == set(RELATIONSHIP_TYPES)


def test_symmetric_types_are_marked_symmetric():
    for rel_type in ("ASSOCIATED_WITH", "RELATED_TO", "CORROBORATES"):
        sem = DEFAULT_SEMANTICS[rel_type]
        assert sem.symmetric is True
        assert sem.direction is Direction.SYMMETRIC


def test_directed_types_are_marked_directed():
    for rel_type in ("USES", "ATTRIBUTED_TO", "TARGETS", "EXPLOITS"):
        sem = DEFAULT_SEMANTICS[rel_type]
        assert sem.symmetric is False
        assert sem.direction is Direction.DIRECTED


def test_inverse_pairs_are_mutual():
    sem = DEFAULT_SEMANTICS
    assert sem["CONTAINS"].inverse == "BELONGS_TO"
    assert sem["BELONGS_TO"].inverse == "CONTAINS"


def test_exclusivity_and_transitivity_are_declared():
    assert "TARGETS" in DEFAULT_SEMANTICS["ATTRIBUTED_TO"].exclusive_with
    assert DEFAULT_SEMANTICS["DEPENDS_ON"].transitive is True
    assert DEFAULT_SEMANTICS["USES"].transitive is False


def test_semantics_for_unknown_type_raises():
    svc = _svc()
    with pytest.raises(RelationshipError):
        svc.semantics_for("NOT_A_REAL_TYPE")


def test_register_semantics_rejects_unknown_types():
    svc = _svc()
    with pytest.raises(RelationshipError):
        svc.register_semantics(RelationshipSemantics(relationship_type="INVENTED_TYPE"))


def test_tenant_id_is_required():
    with pytest.raises(RelationshipError):
        RelationshipAnalysisService(tenant_id="  ")


# ------------------------------------------------------------- malformed data


def test_self_relationship_is_rejected_as_malformed():
    svc = _svc()
    with pytest.raises(RelationshipError):
        svc.assert_relationship("x-1", "x-1", "USES", "source-a", now=T0)


def test_self_relationship_is_rejected_after_whitespace_normalisation():
    svc = _svc()
    with pytest.raises(RelationshipError):
        svc.assert_relationship(" x-1 ", "x-1", "USES", "source-a", now=T0)


def test_empty_endpoints_are_rejected():
    svc = _svc()
    with pytest.raises(RelationshipError):
        svc.assert_relationship("", "b", "USES", "s", now=T0)
    with pytest.raises(RelationshipError):
        svc.assert_relationship("a", "   ", "USES", "s", now=T0)


def test_unattributable_assertion_is_rejected():
    svc = _svc()
    with pytest.raises(RelationshipError):
        svc.assert_relationship("a", "b", "USES", "   ", now=T0)


def test_unknown_relationship_type_is_rejected():
    svc = _svc()
    with pytest.raises(RelationshipError):
        svc.assert_relationship("a", "b", "TOTALLY_MADE_UP", "source-a", now=T0)


def test_duplicate_assertion_id_is_rejected():
    svc = _svc()
    svc.assert_relationship("a", "b", "USES", "source-a", assertion_id="RA-fixed", now=T0)
    with pytest.raises(RelationshipError):
        svc.assert_relationship("a", "c", "USES", "source-a", assertion_id="RA-fixed", now=T0)


def test_confidence_is_bounded():
    svc = _svc()
    with pytest.raises(Exception):
        svc.assert_relationship("a", "b", "USES", "s", confidence=1.5, now=T0)
    with pytest.raises(Exception):
        svc.assert_relationship("a", "b", "USES", "s", confidence=-0.1, now=T0)


def test_relationship_type_is_upper_cased():
    svc = _svc()
    assertion = svc.assert_relationship("a", "b", "  uses ", "source-a", now=T0)
    assert assertion.relationship_type == "USES"


def test_incomplete_assertions_are_reported_not_silently_accepted():
    svc = _svc()
    complete = _uses(svc, "a", "b", "source-a")
    no_evidence = svc.assert_relationship("c", "d", "USES", "source-b", provenance="x", now=T0)
    no_provenance = svc.assert_relationship("e", "f", "USES", "source-c", evidence=_ev(), now=T0)

    incomplete_ids = {a.assertion_id for a in svc.incomplete_assertions()}
    assert complete.assertion_id not in incomplete_ids
    assert {no_evidence.assertion_id, no_provenance.assertion_id} <= incomplete_ids


def test_missing_temporal_bound_is_flagged_separately_from_incomplete():
    """Most legitimate relationships have no expiry, so this is flagged rather than rejected."""
    svc = _svc()
    unbounded = _uses(svc, "a", "b", "source-a")
    bounded = svc.assert_relationship(
        "c", "d", "USES", "source-b", provenance="x", evidence=_ev(),
        valid_until=T0 + timedelta(days=30), now=T0,
    )
    unbounded_ids = {a.assertion_id for a in svc.unbounded_assertions()}
    assert unbounded.assertion_id in unbounded_ids
    assert bounded.assertion_id not in unbounded_ids
    assert unbounded.assertion_id not in {a.assertion_id for a in svc.incomplete_assertions()}
    assert svc.health(now=T0)["unbounded_count"] == 1


def test_evidence_cap_is_enforced_at_both_layers():
    from pydantic import ValidationError

    from apps.threat_intelligence.relationship_analysis import MAX_EVIDENCE_ITEMS

    overflow = [EvidenceItem(evidence_id=f"e{i}") for i in range(MAX_EVIDENCE_ITEMS + 1)]
    with pytest.raises(RelationshipError):
        _svc().assert_relationship("a", "b", "USES", "s", evidence=overflow, provenance="x", now=T0)
    with pytest.raises((RelationshipError, ValidationError)):
        RelationshipAssertion(
            assertion_id="RA-x",
            source_entity_id="a",
            source_entity_type="t",
            target_entity_id="b",
            target_entity_type="t",
            relationship_type="USES",
            asserted_by="s",
            evidence=overflow,
        )


# ------------------------------------------------------- direction/provenance


def test_ordered_and_unordered_pairs():
    svc = _svc()
    assertion = _uses(svc, "b-1", "a-1", "source-a")
    assert assertion.ordered_pair() == ("b-1", "a-1")
    assert assertion.unordered_pair() == ("a-1", "b-1")


def test_inference_origin_is_tracked_and_never_hidden():
    svc = _svc()
    sourced = _uses(svc, "a", "b", "urlhaus")
    analyst = svc.assert_relationship(
        "c", "d", "USES", "analyst", origin=AssertionOrigin.ANALYST_INFERRED, confidence=0.99,
        provenance="analyst-note", now=T0,
    )
    machine = svc.assert_relationship(
        "e", "f", "USES", "graph-model", origin=AssertionOrigin.MACHINE_INFERRED, confidence=0.9,
        provenance="model-v3", now=T0,
    )
    assert sourced.is_inferred is False and sourced.is_verified_origin is True
    assert analyst.is_inferred is True and analyst.is_verified_origin is False
    assert machine.is_inferred is True
    assert svc.health(now=T0)["inferred_count"] == 2
    assert svc.health(now=T0)["verified_origin_count"] == 1


def test_corroboration_raises_confidence_without_duplicating_the_normalized_record():
    svc = _svc()
    first = _uses(svc, "actor-1", "mal-1", "urlhaus", confidence=0.60)
    second = _uses(svc, "actor-1", "mal-1", "malwarebazaar", confidence=0.90)

    normalized = svc.relationship_service.list_relationships()
    assert len(normalized) == 1
    assert normalized[0].confidence == pytest.approx(0.90)
    assert first.relationship_id == second.relationship_id == normalized[0].id


def test_lower_confidence_reassertion_does_not_lower_the_normalized_record():
    svc = _svc()
    _uses(svc, "actor-1", "mal-1", "urlhaus", confidence=0.90)
    _uses(svc, "actor-1", "mal-1", "weak-source", confidence=0.10)
    assert svc.relationship_service.list_relationships()[0].confidence == pytest.approx(0.90)


def test_inferred_assertion_does_not_launder_a_sourced_record():
    svc = _svc()
    _uses(svc, "actor-1", "mal-1", "urlhaus", confidence=0.8)
    before = svc.relationship_service.list_relationships()[0].experimental_label
    svc.assert_relationship(
        "actor-1", "mal-1", "USES", "analyst", origin=AssertionOrigin.ANALYST_INFERRED,
        confidence=0.95, provenance="note", now=T0,
    )
    assert svc.relationship_service.list_relationships()[0].experimental_label == before


# ------------------------------------------------------------ temporal window


def test_assertion_validity_uses_an_explicit_clock():
    svc = _svc()
    assertion = svc.assert_relationship(
        "a", "b", "USES", "source-a",
        valid_from=T0 - timedelta(days=1), valid_until=T0 + timedelta(days=1),
        provenance="x", evidence=_ev(), now=T0,
    )
    assert assertion.is_valid_at(T0) is True
    assert assertion.is_valid_at(T0 + timedelta(days=2)) is False


def test_future_dated_valid_from_is_not_yet_valid():
    svc = _svc()
    assertion = svc.assert_relationship(
        "a", "b", "USES", "source-a", valid_from=T0 + timedelta(days=1),
        provenance="x", evidence=_ev(), now=T0,
    )
    assert assertion.is_valid_at(T0) is False
    assert assertion.is_valid_at(T0 + timedelta(days=2)) is True


def test_undclared_window_is_treated_as_valid():
    svc = _svc()
    assertion = _uses(svc, "a", "b", "source-a")
    assert assertion.is_valid_at(T0 + timedelta(days=3650)) is True


def test_expire_out_of_window_is_idempotent_and_non_destructive():
    svc = _svc()
    assertion = svc.assert_relationship(
        "a", "b", "USES", "source-a", valid_until=T0 + timedelta(hours=1),
        provenance="x", evidence=_ev(), now=T0,
    )
    assert svc.expire_out_of_window(now=T0 + timedelta(hours=2)) == 1
    assert assertion.status is AssertionStatus.EXPIRED
    assert svc.expire_out_of_window(now=T0 + timedelta(hours=3)) == 0
    # The assertion is still retrievable - expiry never deletes evidence.
    assert svc.get_assertion(assertion.assertion_id) is not None


def test_expired_assertions_are_excluded_by_default_and_included_on_request():
    svc = _svc()
    assertion = svc.assert_relationship(
        "a", "b", "USES", "source-a", valid_until=T0 - timedelta(hours=1),
        provenance="x", evidence=_ev(), now=T0,
    )
    assert svc.assertions_for("a", now=T0) == []
    assert len(svc.assertions_for("a", include_expired=True, now=T0)) == 1


def test_orphan_entities_lists_those_with_no_live_assertion():
    svc = _svc()
    _uses(svc, "live-1", "live-2", "source-a")
    svc.assert_relationship(
        "stale-1", "stale-2", "USES", "source-b", valid_until=T0 - timedelta(hours=1),
        provenance="x", evidence=_ev(), now=T0,
    )
    orphans = svc.orphan_entities(now=T0)
    assert orphans == ["stale-1", "stale-2"]


# -------------------------------------------------------------- duplicates


def test_duplicate_groups_collect_distinct_sources():
    svc = _svc()
    a1 = _uses(svc, "actor-1", "mal-1", "urlhaus", confidence=0.85)
    a2 = _uses(svc, "actor-1", "mal-1", "malwarebazaar", confidence=0.90)
    _uses(svc, "actor-2", "mal-9", "urlhaus")

    groups = svc.duplicate_groups()
    assert len(groups) == 1
    assert set(groups[0].assertion_ids) == {a1.assertion_id, a2.assertion_id}
    assert set(groups[0].sources) == {"urlhaus", "malwarebazaar"}
    assert groups[0].agreeing is True


def test_wide_confidence_spread_marks_a_group_as_not_agreeing():
    svc = _svc()
    _uses(svc, "a", "b", "source-a", confidence=0.95)
    _uses(svc, "a", "b", "source-b", confidence=0.20)
    assert svc.duplicate_groups()[0].agreeing is False


def test_symmetric_duplicates_group_regardless_of_direction():
    svc = _svc()
    svc.assert_relationship("a", "b", "ASSOCIATED_WITH", "source-a", confidence=0.7, provenance="x", now=T0)
    svc.assert_relationship("b", "a", "ASSOCIATED_WITH", "source-b", confidence=0.75, provenance="y", now=T0)
    groups = svc.duplicate_groups()
    assert len(groups) == 1
    assert len(groups[0].assertion_ids) == 2


def test_single_source_assertions_are_not_reported_as_duplicates():
    svc = _svc()
    _uses(svc, "a", "b", "source-a")
    assert svc.duplicate_groups(min_sources=2) == []
    assert len(svc.duplicate_groups(min_sources=1)) == 1


# ----------------------------------------------------------- contradictions


def test_reversed_direction_on_a_directed_type_is_a_contradiction():
    svc = _svc()
    a = _uses(svc, "actor-1", "mal-1", "urlhaus")
    b = _uses(svc, "mal-1", "actor-1", "bad-source", confidence=0.5)
    records = svc.contradictions(kind="direction_reversed")
    assert len(records) == 1
    assert set(records[0].assertion_ids) == {a.assertion_id, b.assertion_id}
    assert records[0].resolved is False
    assert a.status is AssertionStatus.DISPUTED
    assert b.status is AssertionStatus.DISPUTED


def test_reversed_direction_on_a_symmetric_type_is_not_a_contradiction():
    svc = _svc()
    svc.assert_relationship("a", "b", "ASSOCIATED_WITH", "source-a", confidence=0.7, provenance="x", now=T0)
    svc.assert_relationship("b", "a", "ASSOCIATED_WITH", "source-b", confidence=0.72, provenance="y", now=T0)
    assert svc.contradictions(kind="direction_reversed") == []


def test_mutually_exclusive_types_are_detected():
    svc = _svc()
    svc.assert_relationship("a", "b", "ATTRIBUTED_TO", "source-a", provenance="x", now=T0)
    svc.assert_relationship("a", "b", "TARGETS", "source-b", provenance="y", now=T0)
    records = svc.contradictions(kind="mutually_exclusive_types")
    assert len(records) == 1
    assert "mutually exclusive" in records[0].detail


def test_explicit_contradicts_assertion_is_recorded():
    svc = _svc()
    _uses(svc, "a", "b", "source-a")
    svc.assert_relationship("a", "b", "CONTRADICTS", "source-b", provenance="rebuttal", now=T0)
    assert len(svc.contradictions(kind="explicit_contradiction")) == 1


def test_large_confidence_dispute_on_a_symmetric_type_is_surfaced():
    svc = _svc()
    svc.assert_relationship("a", "b", "RELATED_TO", "source-a", confidence=0.95, provenance="x", now=T0)
    svc.assert_relationship("a", "b", "RELATED_TO", "source-b", confidence=0.10, provenance="y", now=T0)
    assert len(svc.contradictions(kind="confidence_dispute")) == 1


def test_close_confidence_agreement_is_not_a_contradiction():
    svc = _svc()
    svc.assert_relationship("a", "b", "RELATED_TO", "source-a", confidence=0.80, provenance="x", now=T0)
    svc.assert_relationship("a", "b", "RELATED_TO", "source-b", confidence=0.85, provenance="y", now=T0)
    assert svc.contradictions(kind="confidence_dispute") == []


def test_contradiction_preserves_both_sides():
    """Neither assertion is deleted or overwritten when they disagree."""
    svc = _svc()
    a = _uses(svc, "actor-1", "mal-1", "urlhaus", confidence=0.9)
    b = _uses(svc, "mal-1", "actor-1", "bad-source", confidence=0.2)
    svc.contradictions(kind="direction_reversed")
    assert svc.get_assertion(a.assertion_id).confidence == pytest.approx(0.9)
    assert svc.get_assertion(b.assertion_id).confidence == pytest.approx(0.2)
    assert svc.get_assertion(a.assertion_id).source_entity_id == "actor-1"
    assert svc.get_assertion(b.assertion_id).source_entity_id == "mal-1"


def test_resolution_requires_basis_and_actor():
    svc = _svc()
    _uses(svc, "a", "b", "source-a")
    _uses(svc, "b", "a", "source-b", confidence=0.5)
    record = svc.contradictions(kind="direction_reversed")[0]
    with pytest.raises(RelationshipError):
        svc.resolve_contradiction(record.contradiction_id, "  ", "analyst")
    with pytest.raises(RelationshipError):
        svc.resolve_contradiction(record.contradiction_id, "source-b retracted", "  ")


def test_resolution_records_basis_and_keeps_assertions():
    svc = _svc()
    a = _uses(svc, "a", "b", "source-a")
    b = _uses(svc, "b", "a", "source-b", confidence=0.5)
    record = svc.contradictions(kind="direction_reversed")[0]
    resolved = svc.resolve_contradiction(
        record.contradiction_id, "source-b withdrawn after provenance check", "analyst-1", now=T0
    )
    assert resolved.resolved is True
    assert resolved.resolution_basis.startswith("source-b withdrawn")
    assert resolved.resolved_at == T0
    assert svc.get_assertion(a.assertion_id) is not None
    assert svc.get_assertion(b.assertion_id) is not None
    assert svc.contradiction_summary().unresolved == 0


def test_resolving_an_unknown_contradiction_raises():
    svc = _svc()
    with pytest.raises(RelationshipError):
        svc.resolve_contradiction("CX-999999", "basis", "analyst")


def test_contradiction_summary_counts_by_kind():
    svc = _svc()
    # one direction_reversed pair on a directed type
    _uses(svc, "a", "b", "source-a")
    _uses(svc, "b", "a", "source-b", confidence=0.5)
    # one mutually_exclusive_types pair (ATTRIBUTED_TO vs TARGETS)
    svc.assert_relationship("c", "d", "ATTRIBUTED_TO", "source-c", provenance="x", now=T0)
    svc.assert_relationship("c", "d", "TARGETS", "source-d", provenance="y", now=T0)

    summary = svc.contradiction_summary()
    assert summary.total == 2
    assert summary.unresolved == 2
    assert summary.by_kind == {"direction_reversed": 1, "mutually_exclusive_types": 1}


def test_exclusivity_detection_does_not_depend_on_arrival_order():
    """
    Regression: a one-directional exclusivity table flags A-then-B but silently accepts
    B-then-A. Contradiction detection must be order-independent.
    """
    forward = _svc()
    forward.assert_relationship("a", "b", "ATTRIBUTED_TO", "s1", provenance="x", now=T0)
    forward.assert_relationship("a", "b", "TARGETS", "s2", provenance="y", now=T0)

    backward = _svc()
    backward.assert_relationship("a", "b", "TARGETS", "s2", provenance="y", now=T0)
    backward.assert_relationship("a", "b", "ATTRIBUTED_TO", "s1", provenance="x", now=T0)

    assert len(forward.contradictions(kind="mutually_exclusive_types")) == 1
    assert len(backward.contradictions(kind="mutually_exclusive_types")) == 1


def test_withdrawn_assertions_stop_generating_contradictions():
    svc = _svc()
    a = _uses(svc, "a", "b", "source-a")
    svc.withdraw_assertion(a.assertion_id, "provenance could not be confirmed", now=T0)
    assert a.status is AssertionStatus.WITHDRAWN
    assert "withdrawn" in (a.provenance or "")
    svc.assert_relationship("b", "a", "USES", "source-b", provenance="y", now=T0)
    assert svc.contradictions(kind="direction_reversed") == []


def test_withdrawal_requires_a_basis():
    svc = _svc()
    a = _uses(svc, "a", "b", "source-a")
    with pytest.raises(RelationshipError):
        svc.withdraw_assertion(a.assertion_id, "   ")
    with pytest.raises(RelationshipError):
        svc.withdraw_assertion("RA-nope", "basis")


# ----------------------------------------------------------------- traversal


def _chain(svc, **kw):
    _uses(svc, "actor-1", "mal-1", "s1", **kw)
    _uses(svc, "mal-1", "camp-1", "s2", **kw)
    _uses(svc, "camp-1", "sector-1", "s3", **kw)


def test_traverse_is_depth_bounded():
    svc = _svc()
    _chain(svc)
    shallow = svc.traverse("actor-1", max_depth=1, now=T0)
    deep = svc.traverse("actor-1", max_depth=3, now=T0)
    assert shallow.nodes_visited < deep.nodes_visited
    assert shallow.depth_reached == 1
    assert deep.nodes_visited == 4


def test_traverse_detects_cycles_instead_of_looping():
    svc = _svc()
    _uses(svc, "a", "b", "s1")
    _uses(svc, "b", "c", "s2")
    _uses(svc, "c", "a", "s3")
    result = svc.traverse("a", max_depth=6, now=T0)
    assert result.cycles_detected >= 1
    assert result.nodes_visited == 3


def test_self_loop_cannot_be_created_so_cyclic_input_is_contained():
    svc = _svc()
    with pytest.raises(RelationshipError):
        svc.assert_relationship("a", "a", "USES", "s1", now=T0)
    _uses(svc, "a", "b", "s1")
    assert svc.traverse("a", max_depth=5, now=T0).cycles_detected == 0


def test_traverse_node_limit_truncates_with_a_reason():
    svc = _svc()
    for i in range(10):
        _uses(svc, "root", f"leaf-{i}", "s1")
    result = svc.traverse("root", max_depth=2, max_nodes=4, now=T0)
    assert result.truncated is True
    assert result.truncation_reason == "node_limit_4_reached"
    assert result.nodes_visited <= 4


def test_traverse_rejects_invalid_bounds():
    svc = _svc()
    _uses(svc, "a", "b", "s1")
    with pytest.raises(RelationshipError):
        svc.traverse("a", max_depth=-1, now=T0)
    with pytest.raises(RelationshipError):
        svc.traverse("a", max_depth=MAX_TRAVERSAL_DEPTH + 1, now=T0)
    with pytest.raises(RelationshipError):
        svc.traverse("a", max_nodes=0, now=T0)
    with pytest.raises(RelationshipError):
        svc.traverse("  ", now=T0)


def test_traverse_root_with_no_relationships():
    svc = _svc()
    _uses(svc, "a", "b", "s1")
    result = svc.traverse("isolated-entity", max_depth=3, now=T0)
    assert result.nodes_visited == 1
    assert result.edges_traversed == 0
    assert result.contains_inferred_edges is False
    assert result.all_edges_verified_origin is False


def test_traverse_flags_inferred_edges():
    svc = _svc()
    svc.assert_relationship(
        "a", "b", "USES", "analyst", origin=AssertionOrigin.ANALYST_INFERRED,
        confidence=0.7, provenance="note", now=T0,
    )
    result = svc.traverse("a", max_depth=2, now=T0)
    assert result.contains_inferred_edges is True
    assert result.all_edges_verified_origin is False


def test_traverse_on_all_sourced_edges_reports_verified_origin():
    svc = _svc()
    _uses(svc, "a", "b", "s1")
    _uses(svc, "b", "c", "s2")
    result = svc.traverse("a", max_depth=3, now=T0)
    assert result.contains_inferred_edges is False
    assert result.all_edges_verified_origin is True


# ------------------------------------------------------------------- paths


def test_shortest_path_is_found_and_bounded():
    svc = _svc()
    _chain(svc)
    svc.assert_relationship("actor-1", "sector-1", "ASSOCIATED_WITH", "s4", provenance="x", now=T0)
    path = svc.find_path("actor-1", "sector-1", max_hops=4, now=T0)
    assert path.found is True
    assert path.hops == 1
    assert path.path == ["actor-1", "sector-1"]


def test_path_to_self_is_zero_hops():
    svc = _svc()
    _uses(svc, "a", "b", "s1")
    path = svc.find_path("a", "a", now=T0)
    assert path.found is True and path.hops == 0 and path.path == ["a"]


def test_no_path_is_reported_honestly():
    svc = _svc()
    _uses(svc, "a", "b", "s1")
    _uses(svc, "x", "y", "s2")
    path = svc.find_path("a", "y", max_hops=5, now=T0)
    assert path.found is False
    assert path.reliability_statement == "no_path_found"


def test_path_rejects_invalid_arguments():
    svc = _svc()
    _uses(svc, "a", "b", "s1")
    with pytest.raises(RelationshipError):
        svc.find_path("", "b", now=T0)
    with pytest.raises(RelationshipError):
        svc.find_path("a", "b", max_hops=0, now=T0)


def test_inferred_only_path_is_never_reported_as_confirmed():
    svc = _svc()
    svc.assert_relationship(
        "actor-1", "camp-1", "ATTRIBUTED_TO", "analyst",
        origin=AssertionOrigin.ANALYST_INFERRED, confidence=0.99, provenance="analyst-note", now=T0,
    )
    path = svc.find_path("actor-1", "camp-1", max_hops=1, now=T0)
    assert path.found is True
    assert path.contains_inferred_edges is True
    assert "not_confirmed" in path.reliability_statement


def test_strongest_edge_represents_a_hop():
    """
    Regression: choosing an edge alphabetically let an inferred assertion stand in for a
    directly-sourced one. The strongest-origin assertion must represent the hop.
    """
    svc = _svc()
    svc.assert_relationship(
        "actor-1", "camp-1", "ATTRIBUTED_TO", "analyst",
        origin=AssertionOrigin.ANALYST_INFERRED, confidence=0.99, provenance="note", now=T0,
    )
    svc.assert_relationship(
        "actor-1", "camp-1", "ATTRIBUTED_TO", "mitre",
        confidence=0.90, provenance="mitre-attack", evidence=_ev(), now=T0,
    )
    path = svc.find_path("actor-1", "camp-1", max_hops=1, now=T0)
    assert path.edges[0]["origin"] == "directly_sourced"
    assert path.contains_inferred_edges is False
    assert path.reliability_statement == "path_uses_only_directly_sourced_edges"


def test_mixed_path_is_reported_as_partly_inferred():
    svc = _svc()
    _uses(svc, "a", "b", "s1")
    svc.assert_relationship(
        "b", "c", "USES", "analyst", origin=AssertionOrigin.MACHINE_INFERRED,
        confidence=0.6, provenance="model", now=T0,
    )
    path = svc.find_path("a", "c", max_hops=3, now=T0)
    assert path.found is True
    assert path.contains_inferred_edges is True
    assert path.reliability_statement == "path_rests_partly_on_inferred_edges_not_confirmed"


def test_min_confidence_reflects_the_weakest_link():
    svc = _svc()
    _uses(svc, "a", "b", "s1", confidence=0.9)
    _uses(svc, "b", "c", "s2", confidence=0.3)
    path = svc.find_path("a", "c", max_hops=3, now=T0)
    assert path.min_confidence == pytest.approx(0.3)


# ------------------------------------------------------------ analysis extras


def test_transitive_candidates_are_candidates_only():
    svc = _svc()
    svc.assert_relationship("a", "b", "DEPENDS_ON", "s1", provenance="x", now=T0)
    svc.assert_relationship("b", "c", "DEPENDS_ON", "s2", provenance="y", now=T0)
    candidates = svc.transitive_candidates("DEPENDS_ON")
    assert len(candidates) == 1
    assert candidates[0]["source_entity_id"] == "a"
    assert candidates[0]["target_entity_id"] == "c"
    assert candidates[0]["note"] == "candidate_only_needs_analyst_confirmation"
    # Nothing was auto-asserted into the store.
    assert svc.find_path("a", "c", max_hops=1, now=T0).found is False


def test_transitive_candidates_empty_for_non_transitive_types():
    svc = _svc()
    _uses(svc, "a", "b", "s1")
    _uses(svc, "b", "c", "s2")
    assert svc.transitive_candidates("USES") == []


def test_existing_closure_is_not_re_suggested():
    svc = _svc()
    svc.assert_relationship("a", "b", "DEPENDS_ON", "s1", provenance="x", now=T0)
    svc.assert_relationship("b", "c", "DEPENDS_ON", "s2", provenance="y", now=T0)
    svc.assert_relationship("a", "c", "DEPENDS_ON", "s3", provenance="z", now=T0)
    assert svc.transitive_candidates("DEPENDS_ON") == []


def test_subgraph_extraction_is_induced():
    svc = _svc()
    _chain(svc)
    _uses(svc, "outside", "mal-1", "s9")
    sub = svc.subgraph(["actor-1", "mal-1", "camp-1"])
    assert sub["nodes"] == ["actor-1", "camp-1", "mal-1"]
    assert sub["node_count"] == 3
    for edge in sub["edges"]:
        assert edge["source"] in sub["nodes"] and edge["target"] in sub["nodes"]


def test_subgraph_ignores_unknown_entities():
    svc = _svc()
    _uses(svc, "a", "b", "s1")
    sub = svc.subgraph(["a", "never-seen"])
    assert sub["nodes"] == ["a"]
    assert sub["edge_count"] == 0


def test_normalization_can_be_disabled():
    svc = _svc()
    assertion = svc.assert_relationship(
        "a", "b", "USES", "source-a", provenance="x", evidence=_ev(), now=T0, normalize=False
    )
    assert assertion.relationship_id is None
    assert svc.relationship_service.list_relationships() == []
    # Analysis still works without a normalized record.
    assert svc.traverse("a", max_depth=2, now=T0).nodes_visited == 2


def test_analysis_layer_reuses_the_existing_relationship_store():
    service = RelationshipService()
    svc = _svc(relationship_service=service)
    _uses(svc, "actor-1", "mal-1", "source-a")
    assert len(service.list_relationships()) == 1
    assert service.find_by_type("USES")[0].source_entity_id == "actor-1"


def test_health_snapshot_is_explicit_about_mounting():
    svc = _svc()
    _uses(svc, "a", "b", "source-a")
    health = svc.health(now=T0)
    assert health["tenant_id"] == TENANT
    assert health["assertion_count"] == 1
    assert health["active_count"] == 1
    assert health["distinct_entities"] == 2
    assert health["temporally_valid_count"] == 1
    assert "mounted" in health["note"] and "in-memory" in health["note"]


def test_assertions_for_filters_by_type():
    svc = _svc()
    _uses(svc, "a", "b", "s1")
    svc.assert_relationship("a", "c", "TARGETS", "s2", provenance="x", now=T0)
    assert len(svc.assertions_for("a", relationship_type="USES", now=T0)) == 1
    assert len(svc.assertions_for("a", relationship_type=" uses ", now=T0)) == 1
    assert len(svc.assertions_for("a", now=T0)) == 2
    assert svc.assertions_for("unrelated", now=T0) == []
