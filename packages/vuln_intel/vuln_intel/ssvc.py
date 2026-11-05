"""SSVC: CISA's Stakeholder-Specific Vulnerability Categorization.

Why this module exists
----------------------
CVSS answers "how bad if exploited". KEV answers "is it being exploited". EPSS
answers "will it be". None of them answers the question a responder actually asks:
**what do I do, and how soon?** SSVC does, because its four decision points combine
exploitability with organizational consequence into four named actions
(``Track``/``Track*``/``Attend``/``Act``).

CISA publishes SSVC assessments in the NVD API (``cve.ssvc.ssvcV203[].ssvcData``),
so for many CVEs we can consume an authoritative decision rather than compute one.

The honest complication
-----------------------
The CISA *coordinator* tree has four inputs:

============================  ================================================
Exploitation                  none | poc | active
Automatable                   no | yes
Technical Impact              partial | total
Mission & Well-being          low | medium | high
============================  ================================================

NVD supplies the first three. The fourth is **stakeholder-specific by
definition** — it depends on which mission the asset supports and what the
consequence of its failure is. No feed can supply it for us.

So when it is unknown this module does **not** guess. It returns the *range* of
decisions the tree can produce across all three well-being values, which is the
complete, honest answer available: ``active/yes/total`` is ``Attend..Act``, so a
responder knows the floor and the ceiling without being told a single number that
could be wrong in either direction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Mapping, TypeVar

from .errors import ValidationError

__all__ = [
    "CISA_COORDINATOR_TREE",
    "CisaAutomatable",
    "CisaExploitation",
    "CisaTechnicalImpact",
    "Decision",
    "MissionWellbeing",
    "SsvcAssessment",
    "SsvcTimelinePolicy",
    "assess_ssvc",
    "mission_wellbeing",
    "next_review",
    "parse_ssvc_options",
]


class CisaExploitation(str, Enum):
    NONE = "none"
    POC = "poc"
    ACTIVE = "active"


class CisaAutomatable(str, Enum):
    NO = "no"
    YES = "yes"


class CisaTechnicalImpact(str, Enum):
    PARTIAL = "partial"
    TOTAL = "total"


class MissionWellbeing(str, Enum):
    """The stakeholder-supplied input.  Ordered low < medium < high."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Decision(str, Enum):
    """The four CISA actions, ordered by urgency."""

    TRACK = "track"
    TRACK_STAR = "track_star"
    ATTEND = "attend"
    ACT = "act"

    @property
    def rank(self) -> int:
        return {
            Decision.TRACK: 0,
            Decision.TRACK_STAR: 1,
            Decision.ATTEND: 2,
            Decision.ACT: 3,
        }[self]

    @property
    def label(self) -> str:
        # The published spelling of Track* uses an asterisk; JSON consumers get the
        # underscore form so the value stays a safe identifier.
        return "Track*" if self is Decision.TRACK_STAR else self.value.capitalize()


#: CISA's coordinator decision tree: ``(exploitation, automatable, technical
#: impact) -> {mission & well-being: decision}``.  All 36 rows, transcribed from
#: the published CISA decision table; a test asserts every row is present so a
#: transcription slip cannot pass silently.
CISA_COORDINATOR_TREE: Mapping[
    tuple[CisaExploitation, CisaAutomatable, CisaTechnicalImpact],
    Mapping[MissionWellbeing, Decision],
] = {
    (CisaExploitation.NONE, CisaAutomatable.NO, CisaTechnicalImpact.PARTIAL): {
        MissionWellbeing.LOW: Decision.TRACK,
        MissionWellbeing.MEDIUM: Decision.TRACK,
        MissionWellbeing.HIGH: Decision.TRACK,
    },
    (CisaExploitation.NONE, CisaAutomatable.NO, CisaTechnicalImpact.TOTAL): {
        MissionWellbeing.LOW: Decision.TRACK,
        MissionWellbeing.MEDIUM: Decision.TRACK,
        MissionWellbeing.HIGH: Decision.TRACK_STAR,
    },
    (CisaExploitation.NONE, CisaAutomatable.YES, CisaTechnicalImpact.PARTIAL): {
        MissionWellbeing.LOW: Decision.TRACK,
        MissionWellbeing.MEDIUM: Decision.TRACK,
        MissionWellbeing.HIGH: Decision.ATTEND,
    },
    (CisaExploitation.NONE, CisaAutomatable.YES, CisaTechnicalImpact.TOTAL): {
        MissionWellbeing.LOW: Decision.TRACK,
        MissionWellbeing.MEDIUM: Decision.TRACK,
        MissionWellbeing.HIGH: Decision.ATTEND,
    },
    (CisaExploitation.POC, CisaAutomatable.NO, CisaTechnicalImpact.PARTIAL): {
        MissionWellbeing.LOW: Decision.TRACK,
        MissionWellbeing.MEDIUM: Decision.TRACK,
        MissionWellbeing.HIGH: Decision.TRACK_STAR,
    },
    (CisaExploitation.POC, CisaAutomatable.NO, CisaTechnicalImpact.TOTAL): {
        MissionWellbeing.LOW: Decision.TRACK,
        MissionWellbeing.MEDIUM: Decision.TRACK_STAR,
        MissionWellbeing.HIGH: Decision.ATTEND,
    },
    (CisaExploitation.POC, CisaAutomatable.YES, CisaTechnicalImpact.PARTIAL): {
        MissionWellbeing.LOW: Decision.TRACK,
        MissionWellbeing.MEDIUM: Decision.TRACK,
        MissionWellbeing.HIGH: Decision.ATTEND,
    },
    (CisaExploitation.POC, CisaAutomatable.YES, CisaTechnicalImpact.TOTAL): {
        MissionWellbeing.LOW: Decision.TRACK,
        MissionWellbeing.MEDIUM: Decision.TRACK_STAR,
        MissionWellbeing.HIGH: Decision.ATTEND,
    },
    (CisaExploitation.ACTIVE, CisaAutomatable.NO, CisaTechnicalImpact.PARTIAL): {
        MissionWellbeing.LOW: Decision.TRACK,
        MissionWellbeing.MEDIUM: Decision.TRACK,
        MissionWellbeing.HIGH: Decision.ATTEND,
    },
    (CisaExploitation.ACTIVE, CisaAutomatable.NO, CisaTechnicalImpact.TOTAL): {
        MissionWellbeing.LOW: Decision.TRACK,
        MissionWellbeing.MEDIUM: Decision.ATTEND,
        MissionWellbeing.HIGH: Decision.ACT,
    },
    (CisaExploitation.ACTIVE, CisaAutomatable.YES, CisaTechnicalImpact.PARTIAL): {
        MissionWellbeing.LOW: Decision.ATTEND,
        MissionWellbeing.MEDIUM: Decision.ATTEND,
        MissionWellbeing.HIGH: Decision.ACT,
    },
    (CisaExploitation.ACTIVE, CisaAutomatable.YES, CisaTechnicalImpact.TOTAL): {
        MissionWellbeing.LOW: Decision.ATTEND,
        MissionWellbeing.MEDIUM: Decision.ACT,
        MissionWellbeing.HIGH: Decision.ACT,
    },
}


def mission_wellbeing(
    mission_prevalence: str, public_wellbeing_impact: str
) -> MissionWellbeing:
    """Combine CISA's two consequence inputs into the Mission & Well-being value.

    CISA's published grid, which is not a simple average — one
    ``irreversible`` outcome outweighs a minimal mission prevalence::

        prevalence \\ well-being   minimal   moderate   irreversible
        minimal                   Low       Medium     High
        support                   Medium    High       High
        essential                 High      High       High
    """
    prevalence = (mission_prevalence or "").strip().lower()
    impact = (public_wellbeing_impact or "").strip().lower()
    if prevalence not in ("minimal", "support", "essential"):
        raise ValidationError(
            f"unknown mission prevalence: {mission_prevalence!r}",
            field="mission_prevalence",
        )
    # "material" is CISA's term; "moderate" is a common mis-spelling in secondary
    # sources and is accepted so a caller is not silently downgraded to Low.
    if impact == "moderate":
        impact = "material"
    if impact not in ("minimal", "material", "irreversible"):
        raise ValidationError(
            f"unknown public well-being impact: {public_wellbeing_impact!r}",
            field="public_wellbeing_impact",
        )
    # Table 8, transcribed directly. Written as the grid rather than as a set of
    # clever predicates because the grid is what a reviewer can check.
    if prevalence == "essential" or impact == "irreversible":
        return MissionWellbeing.HIGH
    if prevalence == "support" and impact == "minimal":
        return MissionWellbeing.MEDIUM
    if impact == "material":
        # minimal+material and support+material are both Medium.
        return MissionWellbeing.MEDIUM
    return MissionWellbeing.LOW


@dataclass(frozen=True)
class SsvcAssessment:
    """An SSVC decision, or the range of decisions when an input is unknown."""

    exploitation: CisaExploitation
    automatable: CisaAutomatable
    technical_impact: CisaTechnicalImpact
    #: ``None`` when the stakeholder-specific input was not supplied.
    mission_wellbeing: MissionWellbeing | None
    #: Who supplied the inputs: ``nvd`` for a published CISA assessment,
    #: ``kev`` when exploitation was inferred from KEV membership.
    source: str
    notes: tuple[str, ...] = ()

    @property
    def possible(self) -> tuple[Decision, ...]:
        """Every decision the tree can produce given what we know."""
        row = CISA_COORDINATOR_TREE[
            (self.exploitation, self.automatable, self.technical_impact)
        ]
        if self.mission_wellbeing is not None:
            return (row[self.mission_wellbeing],)
        return tuple(sorted({row[m] for m in MissionWellbeing}, key=lambda d: d.rank))

    @property
    def decision(self) -> Decision | None:
        """The single decision, or ``None`` when it depends on local context.

        Returning ``None`` rather than the worst case is deliberate: telling a team
        to ``Act`` on the strength of an assumed mission value would spend
        emergency capacity on a guess.
        """
        if self.mission_wellbeing is None:
            return None
        return self.possible[0]

    @property
    def floor(self) -> Decision:
        """Least urgent decision still consistent with the known inputs."""
        return self.possible[0]

    @property
    def ceiling(self) -> Decision:
        """Most urgent decision consistent with the known inputs."""
        return self.possible[-1]

    @property
    def exact(self) -> bool:
        return self.mission_wellbeing is not None

    def as_dict(self) -> dict[str, Any]:
        return {
            "exploitation": self.exploitation.value,
            "automatable": self.automatable.value,
            "technical_impact": self.technical_impact.value,
            "mission_wellbeing": (
                self.mission_wellbeing.value if self.mission_wellbeing else None
            ),
            "decision": self.decision.value if self.decision else None,
            "decision_label": self.decision.label if self.decision else None,
            "possible": [d.value for d in self.possible],
            "floor": self.floor.value,
            "ceiling": self.ceiling.value,
            "exact": self.exact,
            "source": self.source,
            "notes": list(self.notes),
        }


_E = TypeVar("_E", bound=Enum)


def _enum(kind: type[_E], value: object, field: str) -> _E:
    """Coerce a string into ``kind``, raising a typed error on anything else.

    Generic in the enum type so each call site keeps its precise type: a widened
    ``Enum`` return would satisfy the checker only by discarding the information
    that makes these values meaningful.
    """
    if not isinstance(value, str):
        raise ValidationError(f"SSVC input {field} must be a string", field=field)
    try:
        return kind(value.strip().lower())
    except ValueError:
        raise ValidationError(
            f"unknown SSVC {field}: {value!r}", field=field
        ) from None


def parse_ssvc_options(
    options: object,
) -> tuple[CisaExploitation | None, CisaAutomatable | None, CisaTechnicalImpact | None]:
    """Read NVD's ``ssvcData.options`` list into the three named values.

    NVD encodes the inputs as a list of one-key objects, which is awkward to
    consume directly::

        [{"exploitation": "poc"}, {"automatable": "yes"},
         {"technicalImpact": "partial"}]

    Absent keys stay ``None`` — a missing input is not a default.
    """
    values: dict[str, object] = {}
    if isinstance(options, list):
        for entry in options:
            if isinstance(entry, Mapping):
                for key, value in entry.items():
                    values[str(key).strip().lower()] = value
    exploitation = values.get("exploitation")
    automatable = values.get("automatable")
    impact = values.get("technicalimpact", values.get("technical_impact"))
    return (
        _enum(CisaExploitation, exploitation, "exploitation") if exploitation else None,
        _enum(CisaAutomatable, automatable, "automatable") if automatable else None,
        _enum(CisaTechnicalImpact, impact, "technical_impact") if impact else None,
    )


def assess_ssvc(
    *,
    exploitation: CisaExploitation | str | None,
    automatable: CisaAutomatable | str | None,
    technical_impact: CisaTechnicalImpact | str | None,
    mission_wellbeing: MissionWellbeing | str | None = None,
    source: str = "nvd",
) -> SsvcAssessment | None:
    """Build an assessment, or ``None`` when an input the tree needs is missing.

    ``None`` here means "SSVC cannot be evaluated", which callers must render as
    unknown — never as ``Track``.  The three technical inputs are mandatory because
    every branch of the tree needs them; only mission & well-being may be absent.
    """
    if exploitation is None or automatable is None or technical_impact is None:
        return None
    exp = _enum(CisaExploitation, exploitation, "exploitation") if isinstance(exploitation, str) else exploitation
    aut = _enum(CisaAutomatable, automatable, "automatable") if isinstance(automatable, str) else automatable
    imp = (
        _enum(CisaTechnicalImpact, technical_impact, "technical_impact")
        if isinstance(technical_impact, str)
        else technical_impact
    )
    mw: MissionWellbeing | None = None
    if mission_wellbeing is not None:
        mw = (
            _enum(MissionWellbeing, mission_wellbeing, "mission_wellbeing")
            if isinstance(mission_wellbeing, str)
            else mission_wellbeing
        )
    notes: list[str] = []
    if mw is None:
        notes.append(
            "mission & well-being not supplied: it is stakeholder-specific, so the "
            "decision is reported as a range rather than a single action"
        )
    return SsvcAssessment(
        exploitation=exp,
        automatable=aut,
        technical_impact=imp,
        mission_wellbeing=mw,
        source=source,
        notes=tuple(notes),
    )


@dataclass(frozen=True)
class SsvcTimelinePolicy:
    """B-13 groundwork: how long an SSVC decision stays valid before re-review.

    **PROVISIONAL — owner approval required.** Without an approved policy,
    :func:`next_review` returns ``None`` ("no timeline"), never an invented date.
    Intervals are per decision outcome; a ``0`` interval means "re-evaluate on
    every ingest".
    """

    #: Review interval per decision, in days. Empty = no timelines at all.
    review_intervals_days: Mapping[str, int] = field(default_factory=dict)
    approved: bool = False
    name: str = "unapproved"

    def __post_init__(self) -> None:
        for decision, days in self.review_intervals_days.items():
            if decision not in {d.value for d in Decision}:
                raise ValidationError(f"unknown SSVC decision {decision!r}", field="review_intervals_days")
            if not isinstance(days, int) or isinstance(days, bool) or days < 0:
                raise ValidationError(f"interval for {decision!r} must be a non-negative int", field="review_intervals_days")


def next_review(
    assessment: SsvcAssessment,
    *,
    assessed_at: datetime,
    policy: SsvcTimelinePolicy | None = None,
) -> datetime | None:
    """When this assessment should be re-evaluated, or ``None`` when no approved
    timeline policy exists (or the decision is a range, not a single outcome)."""
    if policy is None or not policy.approved or not policy.review_intervals_days:
        return None
    decision = assessment.decision
    if decision is None:
        return None  # a decision range has no single timeline
    days = policy.review_intervals_days.get(decision.value)
    if days is None:
        return None
    return assessed_at + timedelta(days=days)
