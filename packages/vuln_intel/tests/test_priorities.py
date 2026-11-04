"""Prioritization: determinism, transparency, and honest handling of unknowns."""

from __future__ import annotations

from datetime import timedelta

import pytest

from vuln_intel.errors import ValidationError
from vuln_intel.priorities import (
    WEIGHTS,
    PriorityContext,
    rank_vulnerabilities,
    score_vulnerability,
)
from vuln_intel.schema import CveId, CvssScore, NormalizedVulnerability, Origin, Severity

from .conftest import FIXED_NOW


def rec(cve="CVE-2026-0001", *, origin=Origin.LIVE, sources=("nvd",), **kwargs):
    return NormalizedVulnerability(
        cve=CveId.parse(cve), origin=origin, sources=sources, **kwargs
    )


def critical(**kwargs):
    return dict(
        cvss=(CvssScore("3.1", 9.8, Severity.CRITICAL, vector="v", source="nvd"),),
        severity=Severity.CRITICAL,
        modified=FIXED_NOW - timedelta(days=1),
        **kwargs,
    )


def test_weights_sum_to_one_hundred() -> None:
    assert sum(WEIGHTS.values()) == 100


def test_score_is_bounded_and_deterministic() -> None:
    record = rec(**critical(kev=True, epss_score=1.0, epss_percentile=1.0))
    first = score_vulnerability(record, now=FIXED_NOW)
    second = score_vulnerability(record, now=FIXED_NOW)
    assert first.as_dict() == second.as_dict()
    assert 0.0 <= first.score <= 100.0


def test_kev_outranks_a_perfect_epss_forecast() -> None:
    """A confirmed exploited-in-the-wild CVE must beat a merely likely one."""
    kev_record = rec(**critical(kev=True))
    epss_record = rec(**critical(kev=False, epss_score=1.0, epss_percentile=1.0))
    assert score_vulnerability(kev_record, now=FIXED_NOW).score > score_vulnerability(
        epss_record, now=FIXED_NOW
    ).score


def test_unknown_exploitation_is_neutral_and_flagged() -> None:
    result = score_vulnerability(rec(**critical()), now=FIXED_NOW)
    assert result.exploitation_unknown is True
    assert any("unknown" in warning for warning in result.warnings)
    assert 0.0 < result.components["exploitation"] < WEIGHTS["exploitation"]


def test_epss_points_are_capped() -> None:
    result = score_vulnerability(
        rec(**critical(epss_score=1.0, epss_percentile=1.0, kev=False)), now=FIXED_NOW
    )
    assert result.components["exploitation"] <= WEIGHTS["exploitation"]


def test_missing_cvss_is_flagged_not_guessed() -> None:
    result = score_vulnerability(rec(sources=("nvd",)), now=FIXED_NOW)
    assert result.components["severity"] == 0.0
    assert any("no CVSS" in warning for warning in result.warnings)
    assert result.severity is Severity.UNKNOWN


def test_stated_severity_without_vector_is_mapped_and_disclosed() -> None:
    result = score_vulnerability(rec(severity=Severity.HIGH), now=FIXED_NOW)
    assert result.components["severity"] == pytest.approx(WEIGHTS["severity"] * 0.8)
    assert any("mapped" in warning for warning in result.warnings)


def test_unassessed_components_are_excluded_not_assumed_safe() -> None:
    result = score_vulnerability(rec(**critical()), context=PriorityContext(), now=FIXED_NOW)
    assert result.components["exposure"] == 0.0
    assert result.components["business"] == 0.0
    assert any("exposure not assessed" in reason for reason in result.reasons)
    assert any("business criticality not assessed" in reason for reason in result.reasons)


def test_context_components_add_points() -> None:
    base = score_vulnerability(rec(**critical(kev=True)), now=FIXED_NOW)
    boosted = score_vulnerability(
        rec(**critical(kev=True)),
        context=PriorityContext(exposure=1.0, business_criticality=1.0),
        now=FIXED_NOW,
    )
    assert boosted.score - base.score == pytest.approx(WEIGHTS["exposure"] + WEIGHTS["business"])
    assert boosted.band in ("critical", "high")


def test_context_bounds() -> None:
    with pytest.raises(ValidationError):
        PriorityContext(exposure=1.5)
    with pytest.raises(ValidationError):
        PriorityContext(business_criticality=-0.1)


def test_demo_origin_is_labelled_in_the_result() -> None:
    result = score_vulnerability(rec(origin=Origin.DEMO, sources=("nvd",)), now=FIXED_NOW)
    assert result.origin is Origin.DEMO
    assert any("not production intelligence" in warning for warning in result.warnings)


def test_conflicts_are_surfaced_as_warnings() -> None:
    result = score_vulnerability(
        rec(**critical(conflict_notes=("severity disagreement across sources",))), now=FIXED_NOW
    )
    assert any("disagreements" in warning for warning in result.warnings)


def test_corroboration_increases_confidence_component() -> None:
    single = score_vulnerability(rec(**critical(sources=("nvd",))), now=FIXED_NOW)
    triple = score_vulnerability(
        rec(**critical(sources=("nvd", "osv", "cisa-kev"))), now=FIXED_NOW
    )
    assert triple.components["confidence"] > single.components["confidence"]


def test_rank_is_sorted_and_stable() -> None:
    records = [
        rec("CVE-2026-0003", severity=Severity.LOW, sources=("nvd",)),
        rec("CVE-2026-0001", **critical(kev=True)),
        rec("CVE-2026-0002", **critical(epss_score=0.5, epss_percentile=0.9, kev=False)),
    ]
    ranking = rank_vulnerabilities(records, now=FIXED_NOW)
    assert [str(r.cve) for r in ranking] == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
    scores = [r.score for r in ranking]
    assert scores == sorted(scores, reverse=True)


def test_rank_tie_breaks_are_deterministic() -> None:
    a = rec("CVE-2026-0002", severity=Severity.MEDIUM, sources=("nvd",))
    b = rec("CVE-2026-0001", severity=Severity.MEDIUM, sources=("nvd",))
    assert [str(r.cve) for r in rank_vulnerabilities([a, b], now=FIXED_NOW)] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
    ]
    assert [str(r.cve) for r in rank_vulnerabilities([b, a], now=FIXED_NOW)] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
    ]


def test_rank_accepts_per_cve_context_and_limit() -> None:
    records = [
        rec("CVE-2026-0001", severity=Severity.MEDIUM, sources=("nvd",)),
        rec("CVE-2026-0002", severity=Severity.MEDIUM, sources=("nvd",)),
    ]
    context = {"CVE-2026-0002": PriorityContext(exposure=1.0, business_criticality=1.0)}
    ranking = rank_vulnerabilities(records, context=context, now=FIXED_NOW, limit=1)
    assert len(ranking) == 1
    assert str(ranking[0].cve) == "CVE-2026-0002"


def test_rank_rejects_negative_limit() -> None:
    with pytest.raises(ValidationError):
        rank_vulnerabilities([], limit=-1)


def test_explanation_is_reconstructable() -> None:
    """Every component in the score must have a matching human-readable reason."""
    result = score_vulnerability(
        rec(**critical(kev=True)), context=PriorityContext(exposure=0.5), now=FIXED_NOW
    )
    text = " | ".join(result.reasons)
    for component in ("severity", "exploitation", "confidence", "exposure"):
        assert component in text
    assert result.as_dict()["score"] == round(result.score, 2)


def test_cvss_explanation_is_a_reason_not_a_warning() -> None:
    """Regression: explanation text must never appear in ``warnings``.

    A warning means "data was missing"; mixing reasons into it hides real gaps.
    """
    result = score_vulnerability(rec(**critical(kev=True)), now=FIXED_NOW)
    assert any("CVSS 3.1 base" in reason for reason in result.reasons)
    assert not any("CVSS 3.1 base" in warning for warning in result.warnings)
