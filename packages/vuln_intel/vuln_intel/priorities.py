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

from dataclasses import dataclass
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
    "score_vulnerability",
    "rank_vulnerabilities",
]

#: Maximum points contributed by each component. Must sum to 100.
WEIGHTS: Mapping[str, int] = {
    "severity": 40,
    "exploitation": 30,
    "exposure": 10,
    "business": 10,
    "recency": 5,
    "confidence": 5,
}

#: Share of the exploitation budget a mere EPSS probability can earn.
EPSS_MAX = 20.0

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

    def as_dict(self) -> dict[str, object]:
        return {
            "cve": str(self.cve),
            "origin": self.origin.value,
            "score": round(self.score, 2),
            "band": self.band,
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
    record: NormalizedVulnerability,
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
    points = WEIGHTS["severity"] * (max(0.0, min(10.0, base)) / 10.0)
    return points, f"severity {points:.1f}/{WEIGHTS['severity']}: {reason}", warnings


def _exploitation_points(
    record: NormalizedVulnerability,
) -> tuple[float, bool, list[str]]:
    notes: list[str] = []
    if record.kev is True:
        notes.append("listed in CISA KEV: confirmed exploitation in the wild")
        return float(WEIGHTS["exploitation"]), False, notes
    epss = record.epss_score
    if epss is not None:
        points = EPSS_MAX * float(epss)
        notes.append(
            f"EPSS forecast {float(epss):.3f} contributes {points:.1f}/"
            f"{WEIGHTS['exploitation']} (prediction, not proof)"
        )
        if record.kev is False:
            notes.append("not in CISA KEV")
            points += 2.0
        return points, False, notes
    if record.kev is False:
        notes.append("not in CISA KEV and no EPSS score: exploitation unlikely but unproven")
        return float(WEIGHTS["exploitation"]) * 0.4, False, notes
    notes.append(
        "exploitation status unknown (KEV not consulted, no EPSS): neutral score assigned"
    )
    return _UNKNOWN_EXPLOITATION, True, notes


def _confidence_points(record: NormalizedVulnerability) -> tuple[float, list[str]]:
    sources = sorted(set(record.sources))
    if len(sources) >= 3:
        return float(WEIGHTS["confidence"]), [
            f"confidence {WEIGHTS['confidence']}/5: corroborated by {len(sources)} sources"
        ]
    if len(sources) == 2:
        return WEIGHTS["confidence"] * 0.7, ["confidence 3.5/5: corroborated by 2 sources"]
    if len(sources) == 1:
        return WEIGHTS["confidence"] * 0.3, [
            f"confidence 1.5/5: single source ({sources[0]})"
        ]
    return 0.0, ["confidence 0/5: no recorded source provenance"]


def _recency_points(
    record: NormalizedVulnerability, context: PriorityContext, now: datetime
) -> tuple[float, Freshness, list[str]]:
    observed = record.modified or record.published
    freshness = compute_freshness(
        observed, now=now, fresh_within=context.recency_window, stale_after=context.recency_window * 4
    )
    if freshness.age is None:
        return 0.0, freshness, ["no publication/modification timestamp: recency not scored"]
    fraction = max(0.0, 1.0 - (freshness.age / (context.recency_window * 4)))
    points = WEIGHTS["recency"] * fraction
    return points, freshness, [
        f"last updated {freshness.age.days}d ago ({freshness.bucket})"
    ]


def score_vulnerability(
    record: NormalizedVulnerability,
    *,
    context: PriorityContext | None = None,
    now: datetime | None = None,
) -> PriorityResult:
    """Compute a deterministic 0-100 priority score with an explanation."""
    context = context or PriorityContext()
    now = now or utcnow()

    severity_points, severity_reason, severity_warnings = _severity_points(record)
    exploitation_points, unknown, exploitation_notes = _exploitation_points(record)
    confidence_points, confidence_notes = _confidence_points(record)
    recency_points, freshness, recency_notes = _recency_points(record, context, now)

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
        components["exposure"] = WEIGHTS["exposure"] * float(context.exposure)
        reasons.append(
            f"asset exposure {float(context.exposure):.2f} -> "
            f"{components['exposure']:.1f}/{WEIGHTS['exposure']}"
        )
    else:
        reasons.append("asset exposure not assessed: component excluded (max unchanged)")

    if context.business_criticality is not None:
        components["business"] = WEIGHTS["business"] * float(context.business_criticality)
        reasons.append(
            f"business criticality {float(context.business_criticality):.2f} -> "
            f"{components['business']:.1f}/{WEIGHTS['business']}"
        )
    else:
        reasons.append("business criticality not assessed: component excluded")

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
        max_components=WEIGHTS,
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
        score_vulnerability(record, context=context_for(record.cve), now=now)
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
