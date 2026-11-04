"""Prioritization: determinism, transparency, and honest handling of unknowns."""

from __future__ import annotations

from datetime import timedelta

import pytest

from vuln_intel.errors import ValidationError
from vuln_intel.priorities import (
    WEIGHTS,
    PriorityContext,
    RankingPolicy,
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


class TestRankingPolicy:
    """Weights are provisional and must be replaceable without editing code.

    The requirement is not "a dataclass exists" — it is that a tenant can rank with
    its own approved weights, that an invalid policy is rejected rather than
    silently producing a meaningless 0-100 score, and that a score always states
    which policy produced it.
    """

    def _record(self, **kwargs):
        from vuln_intel.schema import CveId, CvssScore, NormalizedVulnerability, Origin, Severity

        defaults = {
            "cve": CveId.parse("CVE-2026-0001"),
            "origin": Origin.LIVE,
            "cvss": (
                CvssScore(
                    version="4.0", base_score=9.3, severity=Severity.CRITICAL, assessed=True
                ),
            ),
            "sources": ("nvd", "osv", "kev"),
        }
        defaults.update(kwargs)
        return NormalizedVulnerability(**defaults)

    def test_default_policy_is_marked_provisional(self):
        from vuln_intel.priorities import DEFAULT_POLICY

        assert DEFAULT_POLICY.approved is False
        assert sum(DEFAULT_POLICY.weights.values()) == 100

    def test_default_result_states_the_policy_and_that_it_is_unapproved(self):
        from vuln_intel.priorities import score_vulnerability

        result = score_vulnerability(self._record())
        assert result.policy
        assert result.policy_approved is False
        assert any("PROVISIONAL" in warning for warning in result.warnings)

    def test_custom_policy_changes_the_score(self):
        from vuln_intel.priorities import RankingPolicy, score_vulnerability

        severity_heavy = RankingPolicy(
            weights={
                "severity": 70,
                "exploitation": 10,
                "exposure": 5,
                "business": 5,
                "recency": 5,
                "confidence": 5,
            },
            name="severity-heavy",
            approved=True,
        )
        default = score_vulnerability(self._record())
        custom = score_vulnerability(self._record(), policy=severity_heavy)
        assert custom.score > default.score
        assert custom.policy == "severity-heavy"
        assert custom.policy_approved is True
        assert not any("PROVISIONAL" in warning for warning in custom.warnings)

    def test_max_components_follow_the_policy(self):
        from vuln_intel.priorities import RankingPolicy, score_vulnerability

        policy = RankingPolicy(
            weights={
                "severity": 60,
                "exploitation": 20,
                "exposure": 5,
                "business": 5,
                "recency": 5,
                "confidence": 5,
            }
        )
        result = score_vulnerability(self._record(), policy=policy)
        assert result.max_components["severity"] == 60

    @pytest.mark.parametrize(
        "weights",
        [
            {"severity": 40},  # missing components
            {
                "severity": 40,
                "exploitation": 30,
                "exposure": 10,
                "business": 10,
                "recency": 5,
                "confidence": 6,
            },  # sums to 101
            {
                "severity": 40,
                "exploitation": 30,
                "exposure": 10,
                "business": 10,
                "recency": 5,
                "confidence": 5,
                "nonsense": 0,
            },  # unknown component
            {
                "severity": -40,
                "exploitation": 70,
                "exposure": 10,
                "business": 10,
                "recency": 5,
                "confidence": 5,
            },  # negative
            {
                "severity": 40.0,
                "exploitation": 30,
                "exposure": 10,
                "business": 10,
                "recency": 5,
                "confidence": 5,
            },  # non-integer
        ],
    )
    def test_invalid_policies_are_rejected(self, weights):
        """A policy summing to 101 makes the 0-100 scale a lie."""
        from vuln_intel.priorities import RankingPolicy

        with pytest.raises(ValidationError):
            RankingPolicy(weights=weights)

    def test_epss_budget_is_derived_when_not_given(self):
        from vuln_intel.priorities import RankingPolicy

        policy = RankingPolicy(
            weights={
                "severity": 70,
                "exploitation": 10,
                "exposure": 5,
                "business": 5,
                "recency": 5,
                "confidence": 5,
            }
        )
        # Two thirds of the exploitation budget, so the ratio is preserved.
        assert 0.0 < policy.epss_budget <= 10.0

    def test_epss_budget_cannot_exceed_the_exploitation_weight(self):
        from vuln_intel.priorities import RankingPolicy

        with pytest.raises(ValidationError):
            RankingPolicy(
                weights={
                    "severity": 70,
                    "exploitation": 10,
                    "exposure": 5,
                    "business": 5,
                    "recency": 5,
                    "confidence": 5,
                },
                epss_max=30.0,
            )

    def test_rank_accepts_a_policy(self):
        from vuln_intel.priorities import RankingPolicy, rank_vulnerabilities

        policy = RankingPolicy(
            weights={
                "severity": 50,
                "exploitation": 20,
                "exposure": 10,
                "business": 10,
                "recency": 5,
                "confidence": 5,
            },
            name="tenant-a",
        )
        results = rank_vulnerabilities([self._record()], policy=policy)
        assert results[0].policy == "tenant-a"


class TestExplanationsReconcileWithTheScore:
    """The reasons are part of the result, not decoration.

    Every stated component figure must sum to the returned score.  A hidden
    adjustment is indistinguishable from a scoring bug to anyone reading the
    breakdown, which is exactly what this class of engine exists to prevent.
    """

    @staticmethod
    def _record(**kwargs):
        return NormalizedVulnerability(
            cve=CveId.parse("CVE-2026-8888"),
            origin=Origin.FIXTURE,
            cvss=(CvssScore(version="3.1", base_score=9.8, severity=Severity.CRITICAL),),
            modified=FIXED_NOW - timedelta(days=1),
            sources=("nvd", "osv"),
            **kwargs,
        )

    def _stated_points(self, result) -> float:
        """Sum every 'x/y' component figure quoted in the reasons."""
        import re

        total = 0.0
        for reason in result.reasons:
            # Integers matter too: a full-budget award states "30/30".
            match = re.search(r"(\d+(?:\.\d+)?)/\d+", reason)
            if match:
                total += float(match.group(1))
        return total

    def test_kev_record_reconciles(self) -> None:
        result = score_vulnerability(
            self._record(kev=True), context=PriorityContext(), now=FIXED_NOW
        )
        assert self._stated_points(result) == pytest.approx(result.score, abs=0.05)

    def test_epss_with_confirmed_absence_from_kev_reconciles(self) -> None:
        # This is the case that exposed the defect: "+2.0" was applied silently.
        result = score_vulnerability(
            self._record(kev=False, epss_score=0.72), context=PriorityContext(), now=FIXED_NOW
        )
        assert self._stated_points(result) == pytest.approx(result.score, abs=0.05)

    def test_the_bonus_amount_is_named(self) -> None:
        result = score_vulnerability(
            self._record(kev=False, epss_score=0.72), context=PriorityContext(), now=FIXED_NOW
        )
        assert any("2.0 for a confirmed absence" in reason for reason in result.reasons)

    def test_worked_example_in_the_methodology_document(self) -> None:
        """SCORING_METHODOLOGY.md §7 quotes 77.7 and 64.1 for these inputs."""
        kev = score_vulnerability(
            self._record(kev=True), context=PriorityContext(), now=FIXED_NOW
        )
        epss = score_vulnerability(
            self._record(kev=False, epss_score=0.72), context=PriorityContext(), now=FIXED_NOW
        )
        assert kev.score == pytest.approx(77.7, abs=0.05)
        assert epss.score == pytest.approx(64.1, abs=0.05)


class TestSsvcInScoring:
    """CISA SSVC's three provider inputs plus local mission context, in the score.

    The rules worth protecting: an absent input must never be read as a benign one,
    the provider's own assessment must beat a local inference, and the exposure
    nudge must be small and bounded because it is evidence about the *flaw*, not
    about our estate.
    """

    @staticmethod
    def _record(**kwargs):
        base = dict(
            cve=CveId.parse("CVE-2026-7000"),
            origin=Origin.FIXTURE,
            cvss=(CvssScore(version="3.1", base_score=9.8, severity=Severity.CRITICAL),),
            modified=FIXED_NOW - timedelta(days=1),
            sources=("nvd",),
        )
        base.update(kwargs)
        return NormalizedVulnerability(**base)

    def _score(self, record, **policy_kwargs):
        return score_vulnerability(
            record,
            context=PriorityContext(),
            now=FIXED_NOW,
            policy=RankingPolicy(**policy_kwargs) if policy_kwargs else None,
        )

    def test_no_ssvc_data_adds_no_reason_and_no_points(self) -> None:
        result = self._score(self._record())
        assert not any("SSVC" in r for r in result.reasons)
        assert result.components["exposure"] == 0.0

    def test_incomplete_ssvc_is_reported_as_not_evaluable(self) -> None:
        """Exploitation alone cannot drive the tree; saying nothing would hide that."""
        result = self._score(
            self._record(ssvc=(("exploitation", "active"),))
        )
        assert any("not evaluable" in r for r in result.reasons)
        assert result.components["exposure"] == 0.0

    def test_full_provider_inputs_yield_a_decision_range(self) -> None:
        result = self._score(
            self._record(
                ssvc=(
                    ("automatable", "yes"),
                    ("exploitation", "active"),
                    ("technical_impact", "total"),
                )
            )
        )
        note = next(r for r in result.reasons if r.startswith("CISA SSVC"))
        assert "range" in note
        assert "stakeholder-specific" in note

    def test_supplied_mission_context_resolves_to_one_decision(self) -> None:
        result = score_vulnerability(
            self._record(
                ssvc=(
                    ("automatable", "yes"),
                    ("exploitation", "active"),
                    ("technical_impact", "total"),
                )
            ),
            context=PriorityContext(mission_prevalence="essential",
                                    public_wellbeing="irreversible"),
            now=FIXED_NOW,
        )
        note = next(r for r in result.reasons if r.startswith("CISA SSVC"))
        assert "Act" in note
        assert "range" not in note

    def test_kev_membership_supplies_active_exploitation(self) -> None:
        """KEV asserts active exploitation, so it can stand in for that input."""
        result = self._score(
            self._record(
                kev=True,
                ssvc=(("automatable", "no"), ("technical_impact", "partial")),
            )
        )
        note = next(r for r in result.reasons if r.startswith("CISA SSVC"))
        assert "active" in note

    def test_epss_alone_does_not_supply_exploitation(self) -> None:
        """A forecast is not evidence; it must not move a decision input."""
        result = self._score(
            self._record(
                epss_score=0.99,
                ssvc=(("automatable", "yes"), ("technical_impact", "total")),
            )
        )
        assert any("not evaluable" in r for r in result.reasons)

    def test_automatable_earns_a_bounded_share_of_exposure(self) -> None:
        baseline = self._score(
            self._record(
                ssvc=(("exploitation", "active"), ("technical_impact", "total"),
                      ("automatable", "no"))
            )
        )
        automatable = self._score(
            self._record(
                ssvc=(("exploitation", "active"), ("technical_impact", "total"),
                      ("automatable", "yes"))
            )
        )
        assert automatable.components["exposure"] > baseline.components["exposure"]
        # Bounded: 40% of the exposure budget, never the whole of it.
        assert automatable.components["exposure"] == pytest.approx(
            automatable.max_components["exposure"] * 0.4
        )

    def test_exploitability_reason_is_still_stated(self) -> None:
        """Every component that moves the score must explain itself."""
        result = self._score(
            self._record(
                ssvc=(("exploitation", "active"), ("technical_impact", "total"),
                      ("automatable", "yes"))
            )
        )
        assert any(r.startswith("CISA SSVC") for r in result.reasons)

    def test_bad_context_values_fail_at_construction(self) -> None:
        with pytest.raises(ValidationError):
            PriorityContext(mission_prevalence="enormous", public_wellbeing="minimal")
