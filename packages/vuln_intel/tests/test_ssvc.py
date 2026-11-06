"""SSVC (CISA's Stakeholder-Specific Vulnerability Categorization).

The decision table is transcribed data, so the tests verify it structurally
(every combination present, monotonicity) as well as by example — a transcription
slip in one of 36 rows is exactly the kind of error a spot check misses.
"""

from __future__ import annotations

import itertools

import pytest

from vuln_intel.errors import ValidationError
from vuln_intel.ssvc import (
    CISA_COORDINATOR_TREE,
    CisaAutomatable,
    CisaExploitation,
    CisaTechnicalImpact,
    Decision,
    MissionWellbeing,
    assess_ssvc,
    mission_wellbeing,
    parse_ssvc_options,
)


class TestDecisionTable:
    def test_every_combination_is_present(self) -> None:
        """3 x 2 x 2 = 12 rows, each covering all three well-being values."""
        expected = set(
            itertools.product(
                CisaExploitation, CisaAutomatable, CisaTechnicalImpact
            )
        )
        assert set(CISA_COORDINATOR_TREE) == expected
        for row in CISA_COORDINATOR_TREE.values():
            assert set(row) == set(MissionWellbeing)

    @pytest.mark.parametrize(
        ("exploitation", "automatable", "impact", "expected"),
        [
            # Straight from CISA's published table.
            (CisaExploitation.NONE, CisaAutomatable.NO, CisaTechnicalImpact.PARTIAL, "track"),
            (CisaExploitation.NONE, CisaAutomatable.NO, CisaTechnicalImpact.TOTAL, "track"),
            (CisaExploitation.NONE, CisaAutomatable.YES, CisaTechnicalImpact.PARTIAL, "track"),
            (CisaExploitation.POC, CisaAutomatable.NO, CisaTechnicalImpact.PARTIAL, "track"),
            (CisaExploitation.ACTIVE, CisaAutomatable.NO, CisaTechnicalImpact.PARTIAL, "track"),
            (CisaExploitation.ACTIVE, CisaAutomatable.YES, CisaTechnicalImpact.PARTIAL, "attend"),
        ],
    )
    def test_low_wellbeing_rows(self, exploitation, automatable, impact, expected) -> None:
        row = CISA_COORDINATOR_TREE[(exploitation, automatable, impact)]
        assert row[MissionWellbeing.LOW].value == expected

    def test_active_total_yes_reaches_act_only_above_low(self) -> None:
        """The canonical 'worst case' row: Act at medium/high, Attend at low."""
        row = CISA_COORDINATOR_TREE[
            (
                CisaExploitation.ACTIVE,
                CisaAutomatable.YES,
                CisaTechnicalImpact.TOTAL,
            )
        ]
        assert row[MissionWellbeing.LOW] is Decision.ATTEND
        assert row[MissionWellbeing.MEDIUM] is Decision.ACT
        assert row[MissionWellbeing.HIGH] is Decision.ACT

    def test_no_exploitation_never_reaches_act(self) -> None:
        """With no known exploitation the table never authorises emergency action."""
        for key, row in CISA_COORDINATOR_TREE.items():
            if key[0] is CisaExploitation.NONE:
                assert all(d is not Decision.ACT for d in row.values()), key

    def test_decisions_are_monotonic_in_wellbeing(self) -> None:
        """More consequence must never lower urgency. A transposed row breaks this."""
        for key, row in CISA_COORDINATOR_TREE.items():
            ranks = [row[m].rank for m in MissionWellbeing]
            assert ranks == sorted(ranks), f"non-monotonic row for {key}: {ranks}"

    def test_decisions_are_monotonic_in_exploitation(self) -> None:
        """For a fixed automatable/impact/wellbeing, more exploitation is never safer."""
        for automatable, impact, mw in itertools.product(
            CisaAutomatable, CisaTechnicalImpact, MissionWellbeing
        ):
            ranks = [
                CISA_COORDINATOR_TREE[(e, automatable, impact)][mw].rank
                for e in CisaExploitation
            ]
            assert ranks == sorted(ranks), (automatable, impact, mw, ranks)

    def test_decision_ordering_is_defined_for_all_four(self) -> None:
        assert [d.rank for d in Decision] == [0, 1, 2, 3]
        assert Decision.TRACK_STAR.label == "Track*"


class TestMissionWellbeing:
    @pytest.mark.parametrize(
        ("prevalence", "impact", "expected"),
        [
            ("minimal", "minimal", MissionWellbeing.LOW),
            ("minimal", "material", MissionWellbeing.MEDIUM),
            ("minimal", "irreversible", MissionWellbeing.HIGH),
            ("support", "minimal", MissionWellbeing.MEDIUM),
            # CISA Table 8: support + material is Medium, not High.
            ("support", "material", MissionWellbeing.MEDIUM),
            ("support", "irreversible", MissionWellbeing.HIGH),
            ("essential", "minimal", MissionWellbeing.HIGH),
        ],
    )
    def test_published_grid(self, prevalence, impact, expected) -> None:
        assert mission_wellbeing(prevalence, impact) is expected

    def test_moderate_is_accepted_as_an_alias_for_material(self) -> None:
        """Secondary sources say "moderate"; CISA says "material". Same cell."""
        assert (
            mission_wellbeing("minimal", "moderate")
            is mission_wellbeing("minimal", "material")
        )

    def test_irreversible_outweighs_minimal_prevalence(self) -> None:
        """The grid is not an average; one irreversible outcome dominates."""
        assert (
            mission_wellbeing("minimal", "irreversible") is MissionWellbeing.HIGH
        )

    @pytest.mark.parametrize(
        ("prevalence", "impact"),
        [("big", "minimal"), ("minimal", "huge")],
    )
    def test_unknown_values_raise(self, prevalence, impact) -> None:
        with pytest.raises(ValidationError):
            mission_wellbeing(prevalence, impact)


class TestParsingNvdOptions:
    def test_reads_the_list_of_single_key_objects(self) -> None:
        options = [
            {"exploitation": "poc"},
            {"automatable": "yes"},
            {"technicalImpact": "partial"},
        ]
        assert parse_ssvc_options(options) == (
            CisaExploitation.POC,
            CisaAutomatable.YES,
            CisaTechnicalImpact.PARTIAL,
        )

    def test_absent_keys_stay_none(self) -> None:
        assert parse_ssvc_options([{"exploitation": "active"}]) == (
            CisaExploitation.ACTIVE,
            None,
            None,
        )

    def test_garbage_yields_none_rather_than_a_default(self) -> None:
        assert parse_ssvc_options("not a list") == (None, None, None)
        assert parse_ssvc_options(None) == (None, None, None)

    def test_unknown_enum_value_raises(self) -> None:
        with pytest.raises(ValidationError):
            parse_ssvc_options([{"exploitation": "probably"}])


class TestAssessment:
    def _assess(self, **kwargs):
        return assess_ssvc(
            exploitation=CisaExploitation.ACTIVE,
            automatable=CisaAutomatable.YES,
            technical_impact=CisaTechnicalImpact.TOTAL,
            **kwargs,
        )

    def test_exact_decision_when_all_inputs_known(self) -> None:
        result = self._assess(mission_wellbeing=MissionWellbeing.HIGH)
        assert result is not None
        assert result.exact is True
        assert result.decision is Decision.ACT
        assert result.possible == (Decision.ACT,)

    def test_unknown_wellbeing_yields_a_range_not_a_guess(self) -> None:
        result = self._assess()
        assert result is not None
        assert result.exact is False
        assert result.decision is None, (
            "returning the worst case would spend emergency capacity on a guess"
        )
        assert result.floor is Decision.ATTEND
        assert result.ceiling is Decision.ACT
        assert any("stakeholder-specific" in n for n in result.notes)

    def test_missing_technical_input_makes_ssvc_unavailable(self) -> None:
        """Absence must render as unknown, never as Track."""
        assert (
            assess_ssvc(
                exploitation=None,
                automatable=CisaAutomatable.YES,
                technical_impact=CisaTechnicalImpact.TOTAL,
            )
            is None
        )

    def test_accepts_plain_strings_as_well_as_enums(self) -> None:
        result = assess_ssvc(
            exploitation="active",
            automatable="yes",
            technical_impact="total",
            mission_wellbeing="high",
        )
        assert result is not None and result.decision is Decision.ACT

    def test_invalid_string_raises(self) -> None:
        with pytest.raises(ValidationError):
            assess_ssvc(
                exploitation="active",
                automatable="maybe",
                technical_impact="total",
            )

    def test_serialises_for_consumers(self) -> None:
        payload = self._assess().as_dict()  # type: ignore[union-attr]
        assert payload["decision"] is None
        assert payload["possible"] == ["attend", "act"]
        assert payload["floor"] == "attend"
        assert payload["ceiling"] == "act"
        assert payload["source"] == "nvd"

    def test_kev_derived_exploitation_is_attributed(self) -> None:
        result = assess_ssvc(
            exploitation=CisaExploitation.ACTIVE,
            automatable=CisaAutomatable.YES,
            technical_impact=CisaTechnicalImpact.PARTIAL,
            mission_wellbeing=MissionWellbeing.HIGH,
            source="kev",
        )
        assert result is not None
        assert result.as_dict()["source"] == "kev"
        assert result.decision is Decision.ACT
