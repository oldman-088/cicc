"""Vulnerability prioritization.

The score answers one operational question: *which of these do we fix first,
and why?*  It is a transparent, additive model with named components so an
analyst can always reconstruct the number and disagree with it.

Components (weights are module constants and appear in every explanation):

======================  ======  ==================================================
component               max     meaning
======================  ======  ==================================================
``severity``             40      CVSS base score / 10
``exploitation``        30      CISA KEV (certain), EPSS probability, or unknown
``exposure``            10      caller-supplied asset exposure
``business``            10      caller-supplied business criticality
``recency``              5      how recently the record changed
``confidence``           5      corroboration across sources
======================  ======  ==================================================

Guard rails:

* **EPSS is a forecast.**  It contributes at most ``EPSS_MAX`` points, so a high
  probability alone can never outrank a confirmed KEV hit.
* **Unknown is not zero and not good news.**  A record whose exploitation status
  was never checked scores a neutral mid-point and is flagged
  ``exploitation_unknown``; it is not treated as "probably not exploited".
* **Demo/fixture data is scored but labelled.**  ``origin`` travels with the
  result so a demo ranking can never be mistaken for a production queue.
* No randomness, no hidden model, no network access — same inputs, same output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable, Mapping

from .errors import ValidationError
from .schema import (
    CveId,
    Freshness,
    NormalizedVulnerability,
    Origin,
    Severity,
    compute_freshness,
    utcnow,
)
from .ssvc import (
    CisaAutomatable,
    CisaExploitation,
    assess_ssvc,
    mission_wellbeing,
)

__all__ = [
    "WEIGHTS",
    "PriorityContext",
    "PriorityResult",
    "rank_vulnerabilities",
    "score_vulnerability",
]

#: Provisional weights. Not approved organizational policy.
_PROVISIONAL_WEIGHTS: Mapping[str, int] = {
    "severity": 40,
    "exploitation": 30,
    "exposure": 10,
    "business": 10,
    "recency": 5,
    "confidence": 5,
}

#: Maximum points contributed by each component under the provisional policy.
#: Retained for callers that read it directly; scoring uses ``RankingPolicy``.
WEIGHTS: Mapping[str, int] = _PROVISIONAL_WEIGHTS

#: Share of the exploitation budget a mere EPSS probability can earn.
EPSS_MAX = 20.0

#: Components a policy must define. Kept explicit so a typo in a custom policy
#: fails at construction instead of silently scoring zero for that component.
_REQUIRED_WEIGHTS = (
    "severity",
    "exploitation",
    "exposure",
    "business",
    "recency",
    "confidence",
)


@dataclass(frozen=True)
class RankingPolicy:
    """A transparent, replaceable weighting policy.

    These weights are **provisional** and have not been approved as organizational
    policy. They live in an object rather than a module constant so a tenant can
    rank with its own sign-off, and so the provisional numbers can be superseded
    without editing code paths.

    Every result states the policy it was scored under, which is the property that
    makes a ranking arguable: two scores can only be compared if you know they used
    the same weights.

    ``epss_max`` is the share of the exploitation budget an EPSS *probability* can
    earn; KEV membership is worth the whole budget because it is evidence of
    exploitation rather than a forecast of it.
    """

    weights: Mapping[str, int] = field(
        default_factory=lambda: dict(_PROVISIONAL_WEIGHTS)
    )
    #: ``None`` derives it as two thirds of the exploitation budget, which is what
    #: the provisional policy encodes (20 of 30). Requiring every caller to restate
    #: it invites the inconsistency the check below rejects.
    epss_max: float | None = None
    #: CISA's stakeholder-specific SSVC input, which no feed can supply.  When set,
    #: SSVC produces a single decision instead of a range.  ``None`` is the honest
    #: default: mission consequence depends on the deployment, not on the CVE.
    mission_wellbeing: str | None = None
    name: str = "provisional-40/30/10/10/5/5"
    #: True only when an owner has approved these weights as organizational policy.
    approved: bool = False

    def __post_init__(self) -> None:
        missing = [name for name in _REQUIRED_WEIGHTS if name not in self.weights]
        if missing:
            raise ValidationError(
                "ranking policy is missing component(s): " + ", ".join(missing),
                field="weights",
            )
        extra = [name for name in self.weights if name not in _REQUIRED_WEIGHTS]
        if extra:
            raise ValidationError(
                "ranking policy has unknown component(s): " + ", ".join(extra),
                field="weights",
            )
        for name, value in self.weights.items():
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValidationError(
                    f"weight for {name} must be an integer", field="weights"
                )
            if value < 0:
                raise ValidationError(
                    f"weight for {name} must not be negative", field="weights"
                )
        total = sum(self.weights.values())
        if total != 100:
            # Not cosmetic: a total != 100 makes the 0-100 scale a lie and bands
            # meaningless, and it is exactly the mistake a hand-edited policy makes.
            raise ValidationError(
                f"ranking weights must sum to 100 (got {total})", field="weights"
            )
        budget = float(self.weights["exploitation"])
        raw = self.epss_max if self.epss_max is not None else round(budget * 2 / 3, 2)
        if not 0.0 <= float(raw) <= budget:
            raise ValidationError(
                f"epss_max must be within 0 and the exploitation weight ({budget:g})",
                field="epss_max",
            )
        # Frozen dataclass: resolve the default once, at construction.
        object.__setattr__(self, "epss_max", float(raw))

    @property
    def epss_budget(self) -> float:
        """Resolved EPSS budget. Always a float, never ``None`` after construction."""
        return float(self.epss_max or 0.0)

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "weights": dict(self.weights),
            "epss_max": self.epss_max,
            "approved": self.approved,
            "notice": (
                "owner-approved organizational policy"
                if self.approved
                else "PROVISIONAL weights, not approved organizational policy"
            ),
        }


#: The provisional policy. ``approved=False`` is the honest default and is what
#: every existing caller keeps getting, so behaviour is unchanged.
DEFAULT_POLICY = RankingPolicy()

#: Score used when exploitation status was never established.
_UNKNOWN_EXPLOITATION = 10.0

_SEVERITY_FALLBACK = {
    Severity.NONE: 0.0,
    Severity.LOW: 2.5,
    Severity.MEDIUM: 5.5,
    Severity.HIGH: 8.0,
    Severity.CRITICAL: 9.5,
    Severity.UNKNOWN: 0.0,
}

_BANDS = (
    ("critical", 80.0),
    ("high", 65.0),
    ("elevated", 45.0),
    ("moderate", 25.0),
    ("low", 0.0),
)


@dataclass(frozen=True)
class PriorityContext:
    """Tenant/organization facts that only the caller knows.

    Both factors are ``None`` by default, meaning *not assessed*: the
    corresponding points are excluded from the score rather than assumed to be
    zero risk, and the exclusion is stated in the explanation.
    """

    exposure: float | None = None
    business_criticality: float | None = None
    #: How long a record counts as "recently updated" for the recency component.
    recency_window: timedelta = timedelta(days=30)
    #: CISA SSVC's two stakeholder-specific inputs.  Supplying both lets SSVC
    #: resolve to a single decision instead of a range, which is the only way this
    #: package can state an action rather than a floor and a ceiling.  Left
    #: ``None`` by default because they are facts about a deployment, not about a
    #: CVE, and guessing them would spend emergency capacity on an assumption.
    mission_prevalence: str | None = None
    public_wellbeing: str | None = None

    def __post_init__(self) -> None:
        for name in ("exposure", "business_criticality"):
            value = getattr(self, name)
            if value is not None and not 0.0 <= float(value) <= 1.0:
                raise ValidationError(f"{name} must be within 0.0-1.0", field=name)
        # Validated here rather than at scoring time: a typo in a deployment's
        # configuration should fail when it is configured, not silently downgrade
        # every SSVC decision in production.
        if self.mission_prevalence is not None:
            mission_wellbeing(self.mission_prevalence, self.public_wellbeing or "minimal")


@dataclass(frozen=True)
class PriorityResult:
    cve: CveId
    origin: Origin
    score: float
    band: str
    components: Mapping[str, float]
    max_components: Mapping[str, int]
    reasons: tuple[str, ...]
    warnings: tuple[str, ...]
    exploitation_unknown: bool
    kev: bool | None
    epss: float | None
    severity: Severity
    freshness: str
    #: Name of the ranking policy used. Two scores are only comparable if these
    #: match, so the name travels with the number.
    policy: str = DEFAULT_POLICY.name
    #: False means the policy is provisional and not organizational policy.
    policy_approved: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "cve": str(self.cve),
            "origin": self.origin.value,
            "score": round(self.score, 2),
            "band": self.band,
            "policy": self.policy,
            "policy_approved": self.policy_approved,
            "components": {k: round(v, 2) for k, v in self.components.items()},
            "max_components": dict(self.max_components),
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
            "exploitation_unknown": self.exploitation_unknown,
            "kev": self.kev,
            "epss": self.epss,
            "severity": self.severity.value,
            "freshness": self.freshness,
        }


def _band(score: float) -> str:
    for name, threshold in _BANDS:
        if score >= threshold:
            return name
    return "low"


#: Share of the exposure budget an SSVC `automatable: yes` may earn.  Small on
#: purpose: it is evidence about the *flaw*, not about our estate.
_SSVC_EXPOSURE_SHARE = 0.4


def _ssvc_points(
    record: NormalizedVulnerability, policy: RankingPolicy, context: PriorityContext
) -> tuple[str | None, float]:
    """Derive CISA's SSVC decision from published inputs plus local context.

    Returns ``(reason, exposure_nudge)``.  The reason is ``None`` when SSVC cannot
    be evaluated; a policy that silently substituted ``Track`` for "unknown" would
    make an unassessed finding look benign.

    Exploitation is taken from CISA's own assessment when present.  KEV membership
    is used as a fallback for *active* exploitation, because that is exactly what
    KEV asserts.  Nothing else is inferred: an absent EPSS score is not evidence of
    anything, so it never moves this input.
    """
    inputs = dict(record.ssvc)
    exploitation = inputs.get("exploitation")
    automatable = inputs.get("automatable")
    technical_impact = inputs.get("technical_impact")
    if exploitation is None and record.kev is True:
        exploitation = CisaExploitation.ACTIVE.value
    if exploitation is None:
        # Silent omission here would look identical to "SSVC says nothing to do".
        # Say which input is absent so the gap is visible in the report.
        if automatable is not None or technical_impact is not None:
            return (
                "CISA SSVC not evaluable: exploitation is not supplied and the "
                "record is not in CISA KEV",
                0.0,
            )
        return None, 0.0

    # The stakeholder input: from the policy if the deployment declared one,
    # otherwise from the per-record PriorityContext (which knows the asset).
    stakeholder = policy.mission_wellbeing
    if stakeholder is None and context.mission_prevalence and context.public_wellbeing:
        try:
            stakeholder = mission_wellbeing(
                context.mission_prevalence, context.public_wellbeing
            ).value
        except Exception:  # a bad context value must not sink the whole ranking
            stakeholder = None

    assessment = assess_ssvc(
        exploitation=exploitation,
        automatable=automatable,
        technical_impact=technical_impact,
        mission_wellbeing=stakeholder,
        source="nvd" if inputs else "kev",
    )
    if assessment is None:
        missing = [
            name
            for name, value in (
                ("automatable", automatable),
                ("technical_impact", technical_impact),
            )
            if value is None
        ]
        return (
            f"CISA SSVC not evaluable: {', '.join(missing)} not supplied by the provider",
            0.0,
        )

    nudge = (
        float(policy.weights["exposure"]) * _SSVC_EXPOSURE_SHARE
        if automatable == CisaAutomatable.YES.value
        else 0.0
    )
    if assessment.decision is not None:
        return (
            f"CISA SSVC {assessment.decision.label} "
            f"({assessment.exploitation.value}/{assessment.automatable.value}/"
            f"{assessment.technical_impact.value}, mission & well-being "
            f"{assessment.mission_wellbeing.value if assessment.mission_wellbeing else '?'})",
            nudge,
        )
    return (
        "CISA SSVC range "
        f"{assessment.floor.label}..{assessment.ceiling.label} "
        f"({assessment.exploitation.value}/{assessment.automatable.value}/"
        f"{assessment.technical_impact.value}; mission & well-being is "
        "stakeholder-specific and was not supplied)",
        nudge,
    )


def _severity_points(
    record: NormalizedVulnerability, policy: RankingPolicy
) -> tuple[float, str, list[str]]:
    """Return ``(points, reason, warnings)``.

    Reasons explain the number; warnings flag data that was *missing*.  Keeping
    them separate matters: a reason is not a defect, and a warning must not be
    diluted by ordinary explanation text.
    """
    warnings: list[str] = []
    best = record.best_cvss
    severity = record.effective_severity
    if best is not None:
        base = best.base_score
        reason = f"CVSS {best.version} base {base:.1f} ({best.severity.value})"
    elif severity is not Severity.UNKNOWN:
        base = _SEVERITY_FALLBACK[severity]
        reason = f"source-stated severity {severity.value} (no vector)"
        warnings.append(
            f"no CVSS vector/score; severity '{severity.value}' mapped to {base:.1f}/10"
        )
    else:
        base = 0.0
        reason = "severity unavailable"
        warnings.append("no CVSS data and no stated severity: severity component is 0")
    points = policy.weights["severity"] * (max(0.0, min(10.0, base)) / 10.0)
    return points, f"severity {points:.1f}/{policy.weights['severity']}: {reason}", warnings


def _exploitation_points(
    record: NormalizedVulnerability, policy: RankingPolicy
) -> tuple[float, bool, list[str]]:
    notes: list[str] = []
    if record.kev is True:
        # The figure is quoted even though it is the whole budget: a component line
        # without a number cannot be reconciled against the total by a reader.
        notes.append(
            f"exploitation {policy.weights['exploitation']}/{policy.weights['exploitation']}: "
            "listed in CISA KEV, confirmed exploitation in the wild"
        )
        return float(policy.weights["exploitation"]), False, notes
    epss = record.epss_score
    if epss is not None:
        points = policy.epss_budget * float(epss)
        kev_bonus = 0.0 if record.kev is None else 2.0
        notes.append(
            f"exploitation {points + kev_bonus:.1f}/{policy.weights['exploitation']}: "
            f"EPSS forecast {float(epss):.3f} (prediction, not proof)"
            + (
                ", plus 2.0 for a confirmed absence from CISA KEV"
                if kev_bonus
                else ""
            )
        )
        # The bonus used to be added to the score while the explanation only said
        # "not in CISA KEV", so summing the stated figures gave a total 2 points
        # lower than the one returned.
        return points + kev_bonus, False, notes
    if record.kev is False:
        points = float(policy.weights["exploitation"]) * 0.4
        notes.append(
            f"exploitation {points:.1f}/{policy.weights['exploitation']}: "
            "not in CISA KEV and no EPSS score, exploitation unlikely but unproven"
        )
        return points, False, notes
    notes.append(
        f"exploitation {_UNKNOWN_EXPLOITATION}/{policy.weights['exploitation']}: "
        "status unknown (KEV not consulted, no EPSS), neutral score assigned"
    )
    return _UNKNOWN_EXPLOITATION, True, notes


def _confidence_points(
    record: NormalizedVulnerability, policy: RankingPolicy
) -> tuple[float, list[str]]:
    sources = sorted(set(record.sources))
    if len(sources) >= 3:
        return float(policy.weights["confidence"]), [
            f"confidence {policy.weights['confidence']}/"
            f"{policy.weights['confidence']}: corroborated by {len(sources)} sources"
        ]
    if len(sources) == 2:
        return policy.weights["confidence"] * 0.7, [
            f"confidence {policy.weights['confidence'] * 0.7:.1f}/"
            f"{policy.weights['confidence']}: corroborated by 2 sources"
        ]
    if len(sources) == 1:
        return policy.weights["confidence"] * 0.3, [
            f"confidence {policy.weights['confidence'] * 0.3:.1f}/"
            f"{policy.weights['confidence']}: single source ({sources[0]})"
        ]
    return 0.0, [
        f"confidence 0.0/{policy.weights['confidence']}: no recorded source provenance"
    ]


def _recency_points(
    record: NormalizedVulnerability,
    context: PriorityContext,
    now: datetime,
    policy: RankingPolicy,
) -> tuple[float, Freshness, list[str]]:
    observed = record.modified or record.published
    freshness = compute_freshness(
        observed, now=now, fresh_within=context.recency_window, stale_after=context.recency_window * 4
    )
    if freshness.age is None:
        return 0.0, freshness, [
            f"recency 0.0/{policy.weights['recency']}: no publication/modification "
            "timestamp, not scored"
        ]
    fraction = max(0.0, 1.0 - (freshness.age / (context.recency_window * 4)))
    points = policy.weights["recency"] * fraction
    return points, freshness, [
        f"recency {points:.1f}/{policy.weights['recency']}: last updated "
        f"{freshness.age.days}d ago ({freshness.bucket})"
    ]


def score_vulnerability(
    record: NormalizedVulnerability,
    *,
    context: PriorityContext | None = None,
    now: datetime | None = None,
    policy: RankingPolicy | None = None,
) -> PriorityResult:
    """Compute a deterministic 0-100 priority score with an explanation.

    Pass ``policy`` to rank with weights other than the provisional default. The
    policy is recorded on the result and quoted in the explanation, so a score can
    never be read as if it used different weights.
    """
    context = context or PriorityContext()
    now = now or utcnow()
    policy = policy or DEFAULT_POLICY

    severity_points, severity_reason, severity_warnings = _severity_points(record, policy)
    exploitation_points, unknown, exploitation_notes = _exploitation_points(
        record, policy
    )
    confidence_points, confidence_notes = _confidence_points(record, policy)
    recency_points, freshness, recency_notes = _recency_points(
        record, context, now, policy
    )

    warnings: list[str] = list(severity_warnings)
    warnings.extend(n for n in exploitation_notes if "unknown" in n or "unproven" in n)
    warnings.extend(n for n in recency_notes if "not scored" in n)

    components = {
        "severity": severity_points,
        "exploitation": exploitation_points,
        "exposure": 0.0,
        "business": 0.0,
        "recency": recency_points,
        "confidence": confidence_points,
    }
    reasons = [severity_reason, *exploitation_notes, *confidence_notes, *recency_notes]

    if context.exposure is not None:
        components["exposure"] = policy.weights["exposure"] * float(context.exposure)
        reasons.append(
            f"asset exposure {float(context.exposure):.2f} -> "
            f"{components['exposure']:.1f}/{policy.weights['exposure']}"
        )
    else:
        reasons.append("asset exposure not assessed: component excluded (max unchanged)")

    if context.business_criticality is not None:
        components["business"] = policy.weights["business"] * float(context.business_criticality)
        reasons.append(
            f"business criticality {float(context.business_criticality):.2f} -> "
            f"{components['business']:.1f}/{policy.weights['business']}"
        )
    else:
        reasons.append("business criticality not assessed: component excluded")

    if not policy.approved:
        warnings.append(
            f"ranking policy '{policy.name}' is PROVISIONAL, not approved "
            "organizational policy"
        )
    if record.origin is not Origin.LIVE:
        warnings.append(
            f"origin is '{record.origin.value}': this ranking is not production intelligence"
        )
    # -- standing: a withdrawn or contested claim must not rank like a settled one -
    claim = record.is_actionable_claim
    if claim is False:
        reasons.append(
            f"record standing '{record.record_status.value if record.record_status else '?'}': "
            "the advisory is not a live claim, so no remediation is implied"
        )
    elif record.record_status is not None and record.record_status.value != "published":
        reasons.append(
            f"record standing '{record.record_status.value}': the claim is not settled"
        )
    if claim is not None and claim is False:
        warnings.append(
            "ranking a withdrawn/rejected advisory: it is reported for completeness, "
            "not as work to do"
        )

    if record.conflict_notes:
        warnings.append(
            "source disagreements present: " + "; ".join(record.conflict_notes[:3])
        )

    # -- SSVC: turn the combined evidence into an action, not just a number -----
    ssvc_note, exposure_nudge = _ssvc_points(record, policy, context)
    if ssvc_note is not None:
        reasons.append(ssvc_note)
    if exposure_nudge:
        # SSVC's Automatable/Exploitation inputs are provider assertions about the
        # flaw, which is the closest thing to reachability evidence available
        # without an inventory.  It is a small, bounded share of the exposure
        # budget and it never claims to be asset context.
        components["exposure"] = min(
            float(policy.weights["exposure"]), components["exposure"] + exposure_nudge
        )

    total = sum(components.values())
    total = max(0.0, min(100.0, total))
    return PriorityResult(
        cve=record.cve,
        origin=record.origin,
        score=total,
        band=_band(total),
        components=components,
        max_components=policy.weights,
        policy=policy.name,
        policy_approved=policy.approved,
        reasons=tuple(reasons),
        warnings=tuple(dict.fromkeys(warnings)),
        exploitation_unknown=unknown,
        kev=record.kev,
        epss=record.epss_score,
        severity=record.effective_severity,
        freshness=freshness.bucket,
    )


def rank_vulnerabilities(
    records: Iterable[NormalizedVulnerability],
    *,
    context: PriorityContext | Mapping[str, PriorityContext] | None = None,
    now: datetime | None = None,
    limit: int | None = None,
    policy: RankingPolicy | None = None,
) -> list[PriorityResult]:
    """Score and sort records, highest priority first.

    Ties break deterministically on (KEV, EPSS, CVE id) so pagination and
    reproducible reports are possible.

    ``context`` may be a single policy or a per-CVE mapping.
    """
    if limit is not None and limit < 0:
        raise ValidationError("limit must be >= 0", field="limit")
    now = now or utcnow()

    def context_for(cve: CveId) -> PriorityContext:
        if context is None:
            return PriorityContext()
        if isinstance(context, PriorityContext):
            return context
        return context.get(str(cve), PriorityContext())

    results = [
        score_vulnerability(
            record, context=context_for(record.cve), now=now, policy=policy
        )
        for record in records
    ]
    results.sort(
        key=lambda r: (
            -r.score,
            -int(bool(r.kev)),
            -(r.epss or 0.0),
            str(r.cve),
        )
    )
    return results[:limit] if limit is not None else results
