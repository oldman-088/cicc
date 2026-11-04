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

    def __post_init__(self) -> None:
        for name in ("exposure", "business_criticality"):
            value = getattr(self, name)
            if value is not None and not 0.0 <= float(value) <= 1.0:
                raise ValidationError(f"{name} must be within 0.0-1.0", field=name)


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
        notes.append("listed in CISA KEV: confirmed exploitation in the wild")
        return float(policy.weights["exploitation"]), False, notes
    epss = record.epss_score
    if epss is not None:
        points = policy.epss_budget * float(epss)
        notes.append(
            f"EPSS forecast {float(epss):.3f} contributes {points:.1f}/"
            f"{policy.weights['exploitation']} (prediction, not proof)"
        )
        if record.kev is False:
            notes.append("not in CISA KEV")
            points += 2.0
        return points, False, notes
    if record.kev is False:
        notes.append("not in CISA KEV and no EPSS score: exploitation unlikely but unproven")
        return float(policy.weights["exploitation"]) * 0.4, False, notes
    notes.append(
        "exploitation status unknown (KEV not consulted, no EPSS): neutral score assigned"
    )
    return _UNKNOWN_EXPLOITATION, True, notes


def _confidence_points(
    record: NormalizedVulnerability, policy: RankingPolicy
) -> tuple[float, list[str]]:
    sources = sorted(set(record.sources))
    if len(sources) >= 3:
        return float(policy.weights["confidence"]), [
            f"confidence {policy.weights['confidence']}/5: corroborated by {len(sources)} sources"
        ]
    if len(sources) == 2:
        return policy.weights["confidence"] * 0.7, ["confidence 3.5/5: corroborated by 2 sources"]
    if len(sources) == 1:
        return policy.weights["confidence"] * 0.3, [
            f"confidence 1.5/5: single source ({sources[0]})"
        ]
    return 0.0, ["confidence 0/5: no recorded source provenance"]


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
        return 0.0, freshness, ["no publication/modification timestamp: recency not scored"]
    fraction = max(0.0, 1.0 - (freshness.age / (context.recency_window * 4)))
    points = policy.weights["recency"] * fraction
    return points, freshness, [
        f"last updated {freshness.age.days}d ago ({freshness.bucket})"
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
    if record.conflict_notes:
        warnings.append(
            "source disagreements present: " + "; ".join(record.conflict_notes[:3])
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
