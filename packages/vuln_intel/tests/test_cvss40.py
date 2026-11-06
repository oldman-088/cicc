"""CVSS v4.0 scoring.

The core of this suite is a corpus of vectors and scores published by FIRST in
the CVSS v4.0 Examples document (v1.9). Matching all of them is the only credible
evidence that the macrovector/interpolation algorithm is implemented correctly:
a plausible-looking implementation that is off by 0.1 in one branch would pass
every hand-written test but fail here.
"""

from __future__ import annotations

import pytest

from vuln_intel.cvss import cvss_from_source, score_vector
from vuln_intel.cvss40 import (
    CVSS40_METRIC_ORDER,
    REQUIRED_BASE_METRICS,
    is_v4_vector,
    score_vector_v4,
)
from vuln_intel.errors import UnsupportedVector, ValidationError

BASE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

#: (expected score, vector) transcribed from FIRST's CVSS v4.0 Examples v1.9.
#: Covers base, base+threat, base+environmental and base+supplemental scoring.
FIRST_EXAMPLES: tuple[tuple[float, str], ...] = (
    (7.3, "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
    (7.7, "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
    (5.2, "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U"),
    (8.3, "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N"),
    (
        8.1,
        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N"
        "/CR:H/IR:L/AR:L/MAV:N/MAC:H/MVC:H/MVI:L/MVA:L",
    ),
    (4.6, "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"),
    (5.1, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N"),
    (6.9, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N"),
    (5.9, "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N"),
    (9.4, "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"),
    # CVE-2023-48228. FIRST's prose heading says 9.4 but the vector's own
    # macrovector (001100) is 9.3 in FIRST's lookup table, and 9.4 appears to
    # have been carried over from the preceding example. We assert the value the
    # reference table gives; the discrepancy is recorded here deliberately.
    (9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:H"),
    (8.3, "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N/S:P/V:D"),
    (8.6, "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A"),
)


class TestOfficialExamples:
    @pytest.mark.parametrize(("expected", "vector"), FIRST_EXAMPLES)
    def test_matches_first_published_score(self, expected, vector):
        assert score_vector_v4(vector).base_score == expected

    def test_full_impact_network_vector_is_critical(self):
        score = score_vector_v4(BASE)
        assert score.base_score == 9.3
        assert score.severity.value == "critical"

    def test_scope_changed_variant_is_maximum(self):
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        assert score_vector_v4(vector).base_score == 10.0

    @pytest.mark.parametrize("impact", ["VC", "VI", "VA", "SC", "SI", "SA"])
    def test_no_impact_anywhere_scores_zero(self, impact):
        """Specification 8.2: all impact metrics N short-circuits to 0.0."""
        parts = {name: "N" for name in ("VC", "VI", "VA", "SC", "SI", "SA")}
        parts[impact] = "N"
        vector = (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/"
            f"VC:{parts['VC']}/VI:{parts['VI']}/VA:{parts['VA']}/"
            f"SC:{parts['SC']}/SI:{parts['SI']}/SA:{parts['SA']}"
        )
        score = score_vector_v4(vector)
        assert score.base_score == 0.0
        assert score.severity.value == "none"

    def test_score_is_always_within_range(self):
        for _expected, vector in FIRST_EXAMPLES:
            assert 0.0 <= score_vector_v4(vector).base_score <= 10.0

    def test_one_decimal_place(self):
        for _expected, vector in FIRST_EXAMPLES:
            raw = score_vector_v4(vector).base_score
            assert round(raw, 1) == raw


class TestThreatMetrics:
    def test_unreported_lowers_the_score(self):
        """E:U asserts no known exploitation, so the threat-aware score drops."""
        base = score_vector_v4(BASE).base_score
        with_u = score_vector_v4(f"{BASE}/E:U").base_score
        assert with_u < base

    def test_attacked_is_the_default(self):
        """E:X means "not assessed", which the spec defines as E:A, so the score
        is unchanged when E is omitted."""
        assert score_vector_v4(BASE).base_score == score_vector_v4(f"{BASE}/E:A").base_score

    def test_proof_of_concept_sits_between(self):
        base = score_vector_v4(BASE).base_score
        poc = score_vector_v4(f"{BASE}/E:P").base_score
        unreported = score_vector_v4(f"{BASE}/E:U").base_score
        assert unreported <= poc <= base


class TestEnvironmentalMetrics:
    def test_modified_metric_overrides_the_base_value(self):
        lowered = f"{BASE}/MAV:P"
        assert score_vector_v4(lowered).base_score < score_vector_v4(BASE).base_score

    def test_unmodified_metric_defers_to_base(self):
        assert score_vector_v4(f"{BASE}/MAV:X").base_score == score_vector_v4(BASE).base_score

    def test_requirement_zeroes_are_respected(self):
        """CR/IR/AR of L reduce impact, and must not be silently ignored."""
        lowered = f"{BASE}/CR:L/IR:L/AR:L"
        assert score_vector_v4(lowered).base_score < score_vector_v4(BASE).base_score


class TestSupplementalMetrics:
    def test_supplemental_values_are_accepted_but_never_change_the_score(self):
        """S/AU/R/V/RE/U are legal in a vector and affect no score (spec 2.6)."""
        plain = score_vector_v4(BASE).base_score
        for suffix in ("/S:P", "/AU:Y", "/R:I", "/V:C", "/RE:H", "/U:Red"):
            assert score_vector_v4(BASE + suffix).base_score == plain

    def test_word_valued_metric_is_accepted(self):
        score = score_vector_v4(f"{BASE}/U:Amber")
        assert score.assessed is True


class TestVectorValidation:
    def test_is_v4_vector(self):
        assert is_v4_vector(BASE) is True
        assert is_v4_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is False
        assert is_v4_vector(None) is False
        assert is_v4_vector("") is False

    def test_v3_vector_is_refused_by_the_v4_scorer(self):
        with pytest.raises(UnsupportedVector):
            score_vector_v4("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    @pytest.mark.parametrize(
        "vector",
        [
            "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # missing AT
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",  # missing SC/SI/SA
            "CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # bad value
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/ZZ:Q",
            "CVSS:4.0/AV:N/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "not-a-vector",
        ],
    )
    def test_malformed_vectors_raise(self, vector):
        with pytest.raises(ValidationError):
            score_vector_v4(vector)

    def test_duplicate_metric_is_rejected(self):
        with pytest.raises(ValidationError):
            score_vector_v4(f"{BASE}/AV:P")

    def test_out_of_order_metrics_are_rejected(self):
        """The specification fixes the order; accepting any order would let a
        malformed vector look valid."""
        scrambled = "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        with pytest.raises(ValidationError):
            score_vector_v4(scrambled)

    def test_every_required_metric_is_covered_by_the_order(self):
        assert set(REQUIRED_BASE_METRICS) <= set(CVSS40_METRIC_ORDER)
        assert CVSS40_METRIC_ORDER[:11] == REQUIRED_BASE_METRICS


class TestIntegrationWithUnifiedEntryPoint:
    def test_score_vector_routes_v4(self):
        assert score_vector(BASE).version == "4.0"
        assert score_vector(BASE).base_score == 9.3

    def test_cvss_from_source_computes_v4(self):
        score = cvss_from_source(
            version="4.0",
            vector=BASE,
            base_score=9.3,
            source="nvd",
        )
        assert score is not None
        assert score.assessed is True
        assert score.version == "4.0"

    def test_malformed_v4_vector_does_not_escape_as_an_exception(self):
        """External data must never abort a batch."""
        score = cvss_from_source(
            version="4.0",
            vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
            base_score=None,
        )
        assert score is not None
        assert score.assessed is False

    def test_malformed_v4_vector_falls_back_to_the_stated_score(self):
        score = cvss_from_source(
            version="4.0",
            vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
            base_score=8.8,
        )
        assert score is not None
        assert score.base_score == 8.8
        assert score.assessed is False

    def test_severity_bands_follow_the_specification(self):
        cases = {
            0.0: "none",
            3.9: "low",
            6.9: "medium",
            8.9: "high",
            9.3: "critical",
        }
        for score_value, band in cases.items():
            from vuln_intel.schema import severity_from_score

            assert severity_from_score(score_value).value == band


class TestBestScoreSelection:
    """`best_cvss` decides which score represents a record.

    It considered only 3.x vectors, so a v4-only record — which NVD increasingly
    publishes — reported no score and "unknown" severity despite having a
    computed, validated 9.3. That fed into ranking, where the severity component
    silently scored 0.
    """

    def _record(self, *scores):
        from vuln_intel.schema import CveId, NormalizedVulnerability, Origin

        return NormalizedVulnerability(
            cve=CveId.parse("CVE-2026-1234"),
            origin=Origin.LIVE,
            cvss=scores,
            sources=("nvd",),
        )

    def test_v4_only_record_reports_its_score(self):
        score = score_vector_v4(BASE)
        record = self._record(score)
        assert record.best_cvss is not None
        assert record.best_cvss.base_score == 9.3
        assert record.effective_severity.value == "critical"

    def test_v4_is_preferred_over_v3(self):
        """The standards are not comparable, so the current one wins."""
        from vuln_intel.schema import CvssScore, Severity

        v3 = CvssScore(version="3.1", base_score=9.8, severity=Severity.CRITICAL)
        record = self._record(v3, score_vector_v4(BASE))
        assert record.best_cvss is not None
        assert record.best_cvss.version == "4.0"

    def test_highest_score_wins_within_a_version(self):
        from vuln_intel.schema import CvssScore, Severity

        low = CvssScore(version="3.1", base_score=5.0, severity=Severity.MEDIUM)
        high = CvssScore(version="3.1", base_score=8.1, severity=Severity.HIGH)
        record = self._record(low, high)
        assert record.best_cvss is not None
        assert record.best_cvss.base_score == 8.1

    def test_unassessed_v4_is_not_selected(self):
        from vuln_intel.schema import CvssScore, Severity

        placeholder = CvssScore(
            version="4.0", base_score=0.0, severity=Severity.UNKNOWN, assessed=False
        )
        assert self._record(placeholder).best_cvss is None

    def test_v2_is_never_selected(self):
        """A v2 score is not comparable to v3/v4 and is not "the" score."""
        from vuln_intel.schema import CvssScore, Severity

        v2 = CvssScore(version="2.0", base_score=7.5, severity=Severity.HIGH)
        assert self._record(v2).best_cvss is None


class TestOsvSeverityVectors:
    """OSV ships v4 vectors; one bad string must not abort a collection page."""

    def _connector(self, severity):
        import copy

        from tests import fixtures as fx
        from tests.conftest import FakeTransport, no_wait, response
        from vuln_intel.connectors.osv import OsvConnector
        from vuln_intel.ratelimit import RateGate
        from vuln_intel.retry import RetryPolicy
        from vuln_intel.schema import Origin

        body = copy.deepcopy(fx.OSV_CVE)
        body["severity"] = severity
        return OsvConnector(
            transport=FakeTransport(script=[response(body)]),
            gate=RateGate(0.0, clock=lambda: 0.0, sleep=no_wait),
            retry=RetryPolicy(attempts=1),
            sleep=no_wait,
            origin=Origin.FIXTURE,
        )

    def test_v4_vector_is_converted_into_a_score(self):
        connector = self._connector([{"type": "CVSS_V4", "score": BASE}])
        record, _advisory = connector.get_vulnerability("GHSA-0000-aaaa-bbbb")
        assert record is not None
        assert record.best_cvss is not None
        assert record.best_cvss.version == "4.0"
        assert record.best_cvss.base_score == 9.3

    def test_malformed_v4_vector_is_recorded_not_raised(self):
        truncated = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"
        connector = self._connector([{"type": "CVSS_V4", "score": truncated}])
        record, _advisory = connector.get_vulnerability("GHSA-0000-aaaa-bbbb")
        assert record is not None
        assert record.best_cvss is None
        assert any("not assessed" in note for note in record.conflict_notes)
