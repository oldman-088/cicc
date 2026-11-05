"""Tests for apps.threat_intelligence.conflict_resolution — deterministic, evidence-preserving resolution."""

import pytest
from datetime import datetime, timedelta

from apps.threat_intelligence.conflict_resolution import (
    ClaimOrigin,
    ConflictError,
    ConflictResolutionRecord,
    ConflictResolutionService,
    ConflictState,
    MAX_CLAIMS_PER_FIELD,
    ResolvedValue,
    ResolutionStrategy,
    SourceClaim,
    _value_key,
)

TENANT = "t-cx"
T0 = datetime(2026, 11, 5, 12, 0, 0)


def _svc(**kw):
    return ConflictResolutionService(tenant_id=TENANT, **kw)


def _claim(svc, entity, field, value, source, **kw):
    base = dict(observed_at=T0, provenance=f"{source}:fixture", confidence=0.5)
    base.update(kw)
    return svc.record_claim(entity, field, value, source, **base)


# ------------------------------------------------------------------ validation


def test_tenant_id_is_required():
    with pytest.raises(ConflictError):
        ConflictResolutionService(tenant_id="   ")


def test_claim_requires_entity_field_and_source():
    svc = _svc()
    with pytest.raises(ConflictError):
        svc.record_claim("", "f", "v", "s", observed_at=T0)
    with pytest.raises(ConflictError):
        svc.record_claim("e", "  ", "v", "s", observed_at=T0)
    with pytest.raises(ConflictError):
        svc.record_claim("e", "f", "v", "   ", observed_at=T0)


def test_confidence_is_bounded():
    svc = _svc()
    with pytest.raises(Exception):
        _claim(svc, "e", "f", "v", "s", confidence=1.5)
    with pytest.raises(Exception):
        _claim(svc, "e", "f", "v", "s", reliability_score=2.0)


def test_duplicate_claim_id_is_rejected():
    svc = _svc()
    _claim(svc, "e", "f", "v", "s", claim_id="CL-fixed")
    with pytest.raises(ConflictError):
        _claim(svc, "e", "f2", "v", "s", claim_id="CL-fixed")


def test_claim_count_cap_is_enforced():
    svc = _svc()
    for i in range(MAX_CLAIMS_PER_FIELD):
        _claim(svc, "e", "f", f"v{i}", f"source-{i}")
    with pytest.raises(ConflictError):
        _claim(svc, "e", "f", "overflow", "one-too-many")


# ----------------------------------------------------- claims vs conclusions


def test_claim_and_conclusion_are_distinct_objects():
    svc = _svc()
    claim = _claim(svc, "actor-1", "motivation", "financial", "urlhaus", confidence=0.7)
    resolved = svc.resolved_value("actor-1", "motivation")
    assert isinstance(claim, SourceClaim)
    assert isinstance(resolved, ResolvedValue)
    assert claim.claim_id == resolved.winning_claim_id
    assert resolved.value == claim.value


def test_resolved_value_records_its_derivation():
    svc = _svc()
    claim = _claim(svc, "actor-1", "motivation", "financial", "urlhaus", confidence=0.7)
    resolved = svc.resolved_value("actor-1", "motivation")
    assert resolved.winning_source_id == "urlhaus"
    assert resolved.considered_claim_ids == [claim.claim_id]
    assert "agree on one value" in resolved.resolution_basis


def test_resolved_entity_gives_the_normalized_view():
    svc = _svc()
    _claim(svc, "actor-1", "motivation", "financial", "urlhaus")
    _claim(svc, "actor-1", "sophistication", "advanced", "mitre")
    _claim(svc, "actor-2", "motivation", "espionage", "mitre")
    assert svc.resolved_entity("actor-1") == {
        "motivation": "financial",
        "sophistication": "advanced",
    }


def test_unknown_field_has_no_resolved_value():
    svc = _svc()
    _claim(svc, "e", "f", "v", "s")
    assert svc.resolved_value("e", "never-recorded") is None
    assert svc.resolved_entity("never-recorded") == {}


# ------------------------------------------- repeated ingestion (regression)


def test_identical_reassertion_is_idempotent():
    """
    Regression: a source polled repeatedly must not accumulate claims and must not inflate
    confidence. Previously a re-fetch of the same value created a second claim whose higher
    confidence then won.
    """
    svc = _svc()
    first = _claim(svc, "actor-1", "motivation", "financial", "urlhaus", confidence=0.60)
    again = _claim(svc, "actor-1", "motivation", "financial", "urlhaus", confidence=0.95)
    assert again.claim_id == first.claim_id
    assert len(svc.claims_for("actor-1", "motivation")) == 1
    assert svc.resolved_value("actor-1", "motivation").confidence == pytest.approx(0.60)


def test_changed_value_from_the_same_source_appends_and_supersedes():
    svc = _svc()
    old = _claim(svc, "actor-1", "motivation", "financial", "urlhaus", confidence=0.9)
    new = _claim(svc, "actor-1", "motivation", "espionage", "urlhaus", confidence=0.9)
    assert old.claim_id != new.claim_id
    history = svc.history_for("actor-1", "motivation")
    assert len(history) == 2
    withdrawn = [c for c in history if c.withdrawn]
    assert len(withdrawn) == 1
    assert withdrawn[0].value == "financial"
    # Only the live claim is considered.
    assert svc.resolved_value("actor-1", "motivation").value == "espionage"
    assert len(svc.claims_for("actor-1", "motivation", include_withdrawn=False)) == 1


def test_newer_observation_from_the_same_source_supersedes():
    svc = _svc()
    _claim(svc, "e", "f", "old", "s", observed_at=T0)
    _claim(svc, "e", "f", "old", "s", observed_at=T0 + timedelta(days=1))
    history = svc.history_for("e", "f")
    assert len(history) == 2
    assert sum(1 for c in history if c.withdrawn) == 1
    assert svc.resolved_value("e", "f").value == "old"


def test_withdrawal_keeps_the_claim_and_re_resolves():
    svc = _svc()
    a = _claim(svc, "e", "f", "x", "s1", confidence=0.9)
    b = _claim(svc, "e", "f", "y", "s2", confidence=0.5)
    assert svc.resolved_value("e", "f").value == "x"
    svc.withdraw_claim(a.claim_id, "source retracted after provenance check")
    assert svc.resolved_value("e", "f").value == "y"
    # Nothing was deleted.
    assert len(svc.history_for("e", "f")) == 2
    assert any(c.withdrawn for c in svc.history_for("e", "f"))


def test_withdrawal_requires_a_basis():
    svc = _svc()
    a = _claim(svc, "e", "f", "x", "s1")
    with pytest.raises(ConflictError):
        svc.withdraw_claim(a.claim_id, "   ")
    with pytest.raises(ConflictError):
        svc.withdraw_claim("CL-nope", "basis")


def test_withdrawal_records_the_reason_in_provenance():
    svc = _svc()
    a = _claim(svc, "e", "f", "x", "s1", provenance="original")
    svc.withdraw_claim(a.claim_id, "bad provenance")
    assert "withdrawn:bad provenance" in svc.history_for("e", "f")[0].provenance


def test_all_claims_withdrawn_leaves_no_value():
    svc = _svc()
    a = _claim(svc, "e", "f", "x", "s1")
    svc.withdraw_claim(a.claim_id, "retracted")
    resolved = svc.resolved_value("e", "f")
    assert resolved.value is None
    assert resolved.winning_claim_id is None
    assert resolved.strategy is ResolutionStrategy.UNRESOLVED
    assert "no live claims" in resolved.resolution_basis


# ------------------------------------------------------------- value equality


def test_value_key_distinguishes_types():
    assert _value_key(1) != _value_key("1")
    assert _value_key(True) != _value_key(1)
    assert _value_key(None) != _value_key("None")
    assert _value_key("  x  ") == _value_key("x")
    assert _value_key({"a": 1}) == _value_key({"a": 1})
    assert _value_key({"a": 1}) != _value_key({"a": 2})
    assert _value_key(T0) == _value_key(T0)
    assert _value_key(T0) != _value_key(T0 + timedelta(days=1))


# --------------------------------------------------------- resolution rules


def test_higher_effective_weight_wins_by_default():
    svc = _svc()
    _claim(svc, "e", "f", "low", "weak", confidence=0.30)
    _claim(svc, "e", "f", "high", "strong", confidence=0.90)
    resolved = svc.resolved_value("e", "f")
    assert resolved.value == "high"
    assert resolved.winning_source_id == "strong"
    assert resolved.dissenting_sources == ["weak"]
    assert resolved.rejected_claim_ids


def test_reliability_moderates_confidence():
    svc = _svc()
    _claim(svc, "e", "f", "unreliable", "s1", confidence=0.9, reliability_score=0.1)
    _claim(svc, "e", "f", "reliable", "s2", confidence=0.7, reliability_score=0.95)
    resolved = svc.resolved_value("e", "f")
    # 0.9 * (0.5 + 0.05) = 0.495  vs  0.7 * (0.5 + 0.475) = 0.6825
    assert resolved.value == "reliable"


def test_unscored_source_is_not_treated_as_perfectly_reliable():
    svc = _svc()
    _claim(svc, "e", "f", "unscored", "s1", confidence=0.80, reliability_score=None)
    _claim(svc, "e", "f", "scored", "s2", confidence=0.70, reliability_score=1.0)
    # unscored -> 0.80 raw; scored -> 0.70 * 1.0 = 0.70. Unscored still wins on its own merit,
    # but it receives no reliability bonus.
    claim = svc.claims_for("e", "f")[0]
    scored = svc.claims_for("e", "f")[1]
    assert claim.effective_weight() == pytest.approx(0.80)
    assert scored.effective_weight() == pytest.approx(0.70)
    assert svc.resolved_value("e", "f").value == "unscored"


def test_newest_breaks_an_equal_weight_tie():
    svc = _svc()
    _claim(svc, "e", "f", "old", "s1", observed_at=T0, confidence=0.5)
    _claim(svc, "e", "f", "new", "s2", observed_at=T0 + timedelta(minutes=1), confidence=0.5)
    assert svc.resolved_value("e", "f").value == "new"


def test_resolution_is_deterministic_across_arrival_order():
    first = _svc()
    _claim(first, "e", "f", "a", "s1", observed_at=T0, confidence=0.4)
    _claim(first, "e", "f", "b", "s2", observed_at=T0 + timedelta(minutes=5), confidence=0.9)

    second = _svc()
    _claim(second, "e", "f", "b", "s2", observed_at=T0 + timedelta(minutes=5), confidence=0.9)
    _claim(second, "e", "f", "a", "s1", observed_at=T0, confidence=0.4)

    assert first.resolved_value("e", "f").value == second.resolved_value("e", "f").value == "b"


def test_newest_first_strategy():
    svc = _svc()
    _claim(svc, "e", "f", "confident-old", "s1", observed_at=T0, confidence=0.99)
    _claim(svc, "e", "f", "weak-new", "s2", observed_at=T0 + timedelta(hours=1), confidence=0.10)
    resolved = svc.re_resolve("e", "f", ResolutionStrategy.NEWEST_THEN_HIGHEST_CONFIDENCE)
    assert resolved.value == "weak-new"
    assert resolved.strategy is ResolutionStrategy.NEWEST_THEN_HIGHEST_CONFIDENCE


def test_source_priority_strategy():
    svc = _svc()
    _claim(svc, "e", "f", "community", "crowd", observed_at=T0, confidence=0.99, origin=ClaimOrigin.COMMUNITY)
    _claim(svc, "e", "f", "vendor", "redhat", observed_at=T0, confidence=0.30, origin=ClaimOrigin.AUTHORITATIVE)
    resolved = svc.re_resolve("e", "f", ResolutionStrategy.SOURCE_PRIORITY_THEN_CONFIDENCE)
    assert resolved.value == "vendor"


def test_majority_strategy():
    svc = _svc()
    _claim(svc, "e", "f", "x", "s1", confidence=0.9, strategy=ResolutionStrategy.MAJORITY_THEN_CONFIDENCE)
    _claim(svc, "e", "f", "x", "s2", confidence=0.2, strategy=ResolutionStrategy.MAJORITY_THEN_CONFIDENCE)
    _claim(svc, "e", "f", "y", "s3", confidence=0.99, strategy=ResolutionStrategy.MAJORITY_THEN_CONFIDENCE)
    resolved = svc.resolved_value("e", "f")
    assert resolved.value == "x"
    assert resolved.strategy is ResolutionStrategy.MAJORITY_THEN_CONFIDENCE


def test_re_resolve_on_an_unknown_field_raises():
    svc = _svc()
    with pytest.raises(ConflictError):
        svc.re_resolve("e", "never", ResolutionStrategy.MANUAL)


# ------------------------------------------------------------------ tie-break


def test_exact_tie_is_left_unresolved_rather_than_guessed():
    """
    Regression: including claim_id in the tie-break key made every pair distinguishable, so the
    'refuse to guess' branch was dead code and an arbitrary claim silently won.
    """
    svc = _svc()
    _claim(svc, "e", "f", "x", "s1", observed_at=T0, confidence=0.5)
    _claim(svc, "e", "f", "y", "s2", observed_at=T0, confidence=0.5)
    resolved = svc.resolved_value("e", "f")
    assert resolved.strategy is ResolutionStrategy.UNRESOLVED
    assert resolved.value is None
    assert resolved.winning_claim_id is None
    assert "tie on every tie-break rule" in resolved.resolution_basis
    assert set(resolved.dissenting_sources) == {"s1", "s2"}


def test_exact_tie_leaves_an_unresolvable_conflict_open():
    svc = _svc()
    _claim(svc, "e", "f", "x", "s1", observed_at=T0, confidence=0.5)
    _claim(svc, "e", "f", "y", "s2", observed_at=T0, confidence=0.5)
    open_conflicts = svc.open_conflicts()
    assert len(open_conflicts) == 1
    assert open_conflicts[0].state is ConflictState.UNRESOLVABLE
    assert open_conflicts[0].distinct_values == 2


def test_agreeing_claims_never_create_a_conflict():
    svc = _svc()
    _claim(svc, "e", "f", "same", "s1", confidence=0.5)
    _claim(svc, "e", "f", "same", "s2", confidence=0.9)
    assert svc.conflicts() == []
    assert svc.resolved_value("e", "f").conflict_id is None


# ------------------------------------------------------------- conflict state


def test_conflict_records_the_disagreement_and_its_resolution():
    svc = _svc()
    a = _claim(svc, "e", "f", "x", "s1", confidence=0.4)
    b = _claim(svc, "e", "f", "y", "s2", confidence=0.9)
    conflicts = svc.conflicts()
    assert len(conflicts) == 1
    record = conflicts[0]
    assert record.state is ConflictState.RESOLVED
    assert record.distinct_values == 2
    assert set(record.sources) == {"s1", "s2"}
    assert set(record.claim_ids) == {a.claim_id, b.claim_id}
    assert record.winning_claim_id == b.claim_id
    assert record.resolution_basis and record.resolved_at is not None


def test_conflict_survives_resolution_for_audit():
    svc = _svc()
    _claim(svc, "e", "f", "x", "s1", confidence=0.4)
    _claim(svc, "e", "f", "y", "s2", confidence=0.9)
    before = svc.conflicts()[0].conflict_id
    # A third agreeing claim re-resolves; the record must still exist.
    _claim(svc, "e", "f", "y", "s3", confidence=0.95)
    assert svc.get_conflict(before) is not None
    assert svc.conflicts(entity_id="e")[0].conflict_id == before


def test_open_conflict_is_reused_not_duplicated():
    """An unresolved (still open) conflict absorbs new disagreeing claims instead of spawning a new record."""
    svc = _svc()
    _claim(svc, "e", "f", "x", "s1", observed_at=T0, confidence=0.5)
    _claim(svc, "e", "f", "y", "s2", observed_at=T0, confidence=0.5)
    assert len(svc.conflicts()) == 1
    assert svc.conflicts()[0].state is ConflictState.UNRESOLVABLE
    open_id = svc.conflicts()[0].conflict_id

    # A third distinct value breaks the tie; the same record is reused, not duplicated.
    _claim(svc, "e", "f", "z", "s3", observed_at=T0 + timedelta(minutes=2), confidence=0.5)
    assert len(svc.conflicts()) == 1
    record = svc.conflicts()[0]
    assert record.conflict_id == open_id
    assert record.distinct_values == 3
    assert record.state is ConflictState.RESOLVED
    assert svc.resolved_value("e", "f").value == "z"


def test_each_disagreement_episode_gets_its_own_audit_record():
    """Once a disagreement is resolved, a later new disagreement is a new episode, not an edit."""
    svc = _svc()
    _claim(svc, "e", "f", "x", "s1", observed_at=T0, confidence=0.1)
    _claim(svc, "e", "f", "y", "s2", observed_at=T0 + timedelta(minutes=1), confidence=0.9)
    first_id = svc.conflicts()[0].conflict_id
    assert svc.conflicts()[0].state is ConflictState.RESOLVED

    _claim(svc, "e", "f", "z", "s3", observed_at=T0 + timedelta(minutes=2), confidence=0.95)
    records = svc.conflicts()
    assert len(records) == 2
    assert records[0].conflict_id == first_id
    assert records[0].state is ConflictState.RESOLVED
    # The earlier record was never rewritten to describe the newer episode.
    assert records[0].distinct_values == 2
    assert records[1].distinct_values == 3


def test_conflict_can_be_filtered_by_entity_and_state():
    svc = _svc()
    _claim(svc, "e1", "f", "x", "s1", confidence=0.9)
    _claim(svc, "e1", "f", "y", "s2", confidence=0.1)
    _claim(svc, "e2", "f", "x", "s1", observed_at=T0, confidence=0.5)
    _claim(svc, "e2", "f", "y", "s2", observed_at=T0, confidence=0.5)
    assert len(svc.conflicts(entity_id="e1")) == 1
    assert len(svc.conflicts(entity_id="e2")) == 1
    assert len(svc.conflicts(state=ConflictState.RESOLVED)) == 1
    assert len(svc.conflicts(state=ConflictState.UNRESOLVABLE)) == 1


def test_conflicts_close_when_claims_come_to_agree():
    svc = _svc()
    a = _claim(svc, "e", "f", "x", "s1", observed_at=T0, confidence=0.5)
    _claim(svc, "e", "f", "y", "s2", observed_at=T0 + timedelta(minutes=1), confidence=0.5)
    assert svc.resolved_value("e", "f").value == "y"
    svc.withdraw_claim(a.claim_id, "s1 retracted")
    assert svc.open_conflicts() == []
    assert svc.conflicts()[0].state is ConflictState.RESOLVED


# --------------------------------------------------------------- manual input


def test_manual_resolution_requires_basis_and_actor():
    svc = _svc()
    a = _claim(svc, "e", "f", "x", "s1")
    with pytest.raises(ConflictError):
        svc.resolve_manually("e", "f", a.claim_id, "  ", "analyst")
    with pytest.raises(ConflictError):
        svc.resolve_manually("e", "f", a.claim_id, "corroborated", "  ")


def test_manual_resolution_promotes_a_specific_claim():
    svc = _svc()
    a = _claim(svc, "e", "f", "x", "s1", confidence=0.1)
    _claim(svc, "e", "f", "y", "s2", confidence=0.9)
    assert svc.resolved_value("e", "f").value == "y"
    resolved = svc.resolve_manually("e", "f", a.claim_id, "second analyst corroborated s1", "analyst-1", now=T0)
    assert resolved.value == "x"
    assert resolved.winning_claim_id == a.claim_id
    assert resolved.strategy is ResolutionStrategy.MANUAL
    assert resolved.resolved_by == "analyst-1"
    assert "manual selection" in resolved.resolution_basis


def test_manual_resolution_rejects_a_non_live_claim():
    svc = _svc()
    a = _claim(svc, "e", "f", "x", "s1")
    svc.withdraw_claim(a.claim_id, "retracted")
    with pytest.raises(ConflictError):
        svc.resolve_manually("e", "f", a.claim_id, "basis", "analyst")
    with pytest.raises(ConflictError):
        svc.resolve_manually("e", "f", "CL-nope", "basis", "analyst")
    with pytest.raises(ConflictError):
        svc.resolve_manually("e", "other-field", a.claim_id, "basis", "analyst")


def test_manual_resolution_supersedes_the_automated_conflict():
    svc = _svc()
    a = _claim(svc, "e", "f", "x", "s1", confidence=0.1)
    _claim(svc, "e", "f", "y", "s2", confidence=0.9)
    automated_id = svc.conflicts()[0].conflict_id
    svc.resolve_manually("e", "f", a.claim_id, "corroborated", "analyst-1", now=T0)
    record = svc.get_conflict(automated_id)
    assert record.state is ConflictState.SUPERSEDED
    assert record.superseded_by == a.claim_id
    assert "superseded by manual resolution" in record.resolution_basis


def test_re_resolution_supersedes_a_prior_conflict_record():
    svc = _svc()
    _claim(svc, "e", "f", "x", "s1", observed_at=T0, confidence=0.5)
    _claim(svc, "e", "f", "y", "s2", observed_at=T0, confidence=0.5)
    prior_id = svc.conflicts()[0].conflict_id
    assert svc.get_conflict(prior_id).state is ConflictState.UNRESOLVABLE
    svc.re_resolve("e", "f", ResolutionStrategy.SOURCE_PRIORITY_THEN_CONFIDENCE)
    assert svc.get_conflict(prior_id).state is ConflictState.SUPERSEDED


# ------------------------------------------------------------------ provenance


def test_provenance_and_source_reference_are_preserved_on_the_claim():
    svc = _svc()
    claim = _claim(
        svc, "e", "f", "x", "s1",
        provenance="urlhaus:2026-11-05T12:00Z",
        source_reference="https://urlhaus.example.invalid/payload/1",
    )
    assert claim.provenance.startswith("urlhaus:")
    assert claim.source_reference.startswith("https://")
    assert svc.history_for("e", "f")[0].provenance == claim.provenance


def test_non_authoritative_conclusions_carry_the_demo_label():
    svc = _svc()
    _claim(svc, "e", "f", "x", "s1", origin=ClaimOrigin.AGGREGATOR)
    assert svc.resolved_value("e", "f").experimental_label == "EXPERIMENTAL_DEMO_DATA_ONLY"


def test_only_fully_authoritative_agreement_clears_the_demo_label():
    svc = _svc()
    _claim(svc, "e", "f", "x", "vendor-a", origin=ClaimOrigin.AUTHORITATIVE, confidence=0.9)
    _claim(svc, "e", "f", "x", "vendor-b", origin=ClaimOrigin.AUTHORITATIVE, confidence=0.9)
    assert svc.resolved_value("e", "f").experimental_label is None


def test_agreement_with_one_non_authoritative_source_keeps_the_demo_label():
    svc = _svc()
    _claim(svc, "e", "f", "x", "vendor-a", origin=ClaimOrigin.AUTHORITATIVE, confidence=0.9)
    _claim(svc, "e", "f", "x", "crowd", origin=ClaimOrigin.COMMUNITY, confidence=0.9)
    assert svc.resolved_value("e", "f").experimental_label == "EXPERIMENTAL_DEMO_DATA_ONLY"


# --------------------------------------------------------------------- stats


def test_stats_are_explicit_about_mounting():
    svc = _svc()
    _claim(svc, "e", "f", "x", "s1", confidence=0.9)
    _claim(svc, "e", "f", "y", "s2", confidence=0.1)
    stats = svc.stats()
    assert stats["tenant_id"] == TENANT
    assert stats["claim_count"] == 2
    assert stats["distinct_sources"] == 2
    assert stats["fields_tracked"] == 1
    assert stats["conflict_count"] == 1
    assert stats["open_conflict_count"] == 0
    assert stats["withdrawn_claim_count"] == 0
    assert "mounted" in stats["note"] and "in-memory" in stats["note"]


def test_stats_count_unresolved_fields():
    svc = _svc()
    _claim(svc, "e", "f", "x", "s1", observed_at=T0, confidence=0.5)
    _claim(svc, "e", "f", "y", "s2", observed_at=T0, confidence=0.5)
    stats = svc.stats()
    assert stats["unresolved_count"] == 1
    assert stats["open_conflict_count"] == 1
    assert stats["conflicts_by_state"] == {"unresolvable": 1}


def test_tenant_isolation_between_services():
    a = ConflictResolutionService(tenant_id="tenant-a")
    b = ConflictResolutionService(tenant_id="tenant-b")
    _claim(a, "e", "f", "x", "s1")
    assert b.resolved_value("e", "f") is None
    assert b.stats()["claim_count"] == 0
    assert a.claims_for("e", "f")[0].tenant_id == "tenant-a"
