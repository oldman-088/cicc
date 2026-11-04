"""Remediation intelligence: turn data into an action an operator can take.

A ranking tells you *what* matters.  This module answers the next question —
*what do I do, and what will it cost me?* — with the same discipline:

* the action is derived from published data (a fixed version, a KEV due date, an
  OSV ``affected`` entry), never invented;
* when no fixed release exists the module says so and offers mitigations
  instead of a fictional upgrade target;
* every recommendation carries the evidence that produced it, so an operator can
  disagree with the reasoning rather than with an opaque verdict;
* upgrade *cost* is expressed as a semver distance, which is an honest proxy for
  "how risky is this bump" and is labelled as a proxy.

Nothing here performs network I/O or version resolution beyond what
:mod:`vuln_intel.versions` supports.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from enum import Enum
from typing import Iterable, Sequence

from .affected import AffectedAssessment, Verdict, assess_affected
from .schema import AffectedPackage, NormalizedVulnerability, Severity
from .versions import VersionScheme, compare, scheme_for_ecosystem

__all__ = [
    "RecommendedAction",
    "Remediation",
    "UpgradeCost",
    "assess_upgrade_cost",
    "plan_remediation",
    "summarize_remediation",
]


class RecommendedAction(str, Enum):
    """Ordered from most to least urgent.  The enum value is the wire format."""

    EMERGENCY_PATCH = "emergency_patch"  # exploited in the wild, due date passed/soon
    PATCH = "patch"  # a fixed version exists
    UPGRADE_MAJOR = "upgrade_major"  # the fix crosses a major boundary
    MITIGATE = "mitigate"  # affected, no fixed release
    MONITOR = "monitor"  # not affected on this version, but watch the package
    NONE = "none"  # not applicable

    @property
    def is_actionable(self) -> bool:
        return self in (
            RecommendedAction.EMERGENCY_PATCH,
            RecommendedAction.PATCH,
            RecommendedAction.UPGRADE_MAJOR,
            RecommendedAction.MITIGATE,
        )


class UpgradeCost(str, Enum):
    """Semver distance of the required bump — a proxy, explicitly not a risk model."""

    NONE = "none"  # already fixed
    PATCH = "patch"  # x.y.Z
    MINOR = "minor"  # x.Y.z
    MAJOR = "major"  # X.y.z
    UNKNOWN = "unknown"  # cannot be ordered


#: Days before the CISA due date at which remediation becomes urgent.
KEV_URGENCY_WINDOW_DAYS = 14


@dataclass(frozen=True)
class Remediation:
    """One recommendation, with its evidence."""

    cve: str
    action: RecommendedAction
    priority: str
    package: str | None = None
    ecosystem: str | None = None
    installed_version: str | None = None
    target_version: str | None = None
    upgrade_cost: UpgradeCost = UpgradeCost.UNKNOWN
    due_date: date | None = None
    overdue: bool = False
    days_remaining: int | None = None
    mitigations: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def instruction(self) -> str:
        """One sentence an operator can paste into a ticket."""
        if self.package and self.target_version:
            target = f"{self.package} to {self.target_version}"
        else:
            target = self.package or self.cve
        if self.action is RecommendedAction.NONE:
            return "no action required"
        if self.action is RecommendedAction.MONITOR:
            return f"monitor {self.package}: not affected on the current version"
        if self.action in (RecommendedAction.PATCH, RecommendedAction.UPGRADE_MAJOR):
            text = f"upgrade {target}"
            if self.upgrade_cost is UpgradeCost.MAJOR:
                text += " (major version change: review breaking changes and test)"
            return text
        if self.action is RecommendedAction.EMERGENCY_PATCH:
            text = f"emergency upgrade {target}"
            if self.due_date:
                text += f" — CISA remediation due {self.due_date.isoformat()}"
            return text
        return f"apply mitigations for {self.package}: no fixed release published"

    def as_dict(self) -> dict[str, object]:
        return {
            "cve": self.cve,
            "action": self.action.value,
            "priority": self.priority,
            "package": self.package,
            "ecosystem": self.ecosystem,
            "installed_version": self.installed_version,
            "target_version": self.target_version,
            "upgrade_cost": self.upgrade_cost.value,
            "due_date": self.due_date.isoformat() if self.due_date else None,
            "overdue": self.overdue,
            "days_remaining": self.days_remaining,
            "instruction": self.instruction,
            "mitigations": list(self.mitigations),
            "reasons": list(self.reasons),
            "evidence": list(self.evidence),
            "warnings": list(self.warnings),
        }


def _cost(candidate: str | None) -> UpgradeCost:
    if candidate is None:
        return UpgradeCost.UNKNOWN
    return UpgradeCost.PATCH


def assess_upgrade_cost(
    installed: str | None, target: str | None, ecosystem: str | None
) -> UpgradeCost:
    """Classify the bump from ``installed`` to ``target``.

    "Major/minor/patch" is a statement about the *shape* of the version
    strings, not about the ordering scheme, so any dot-numeric version is
    classified (2.14.1 -> 2.15.0 is a minor bump in Maven too). Versions that
    are not dot-numeric — Debian's ``1:1.0-1``, a commit sha — are ``UNKNOWN``
    rather than a guess.
    """
    if not installed or not target:
        return UpgradeCost.UNKNOWN
    scheme = scheme_for_ecosystem(ecosystem)
    if scheme in (VersionScheme.SEMVER, VersionScheme.PEP440) and compare(
        installed, target, scheme
    ) == 0:
        return UpgradeCost.NONE
    if installed.strip() == target.strip():
        return UpgradeCost.NONE

    def numbers(text: str) -> tuple[int, ...] | None:
        cleaned = text.strip().lstrip("vV")
        for separator in ("-", "+"):
            cleaned = cleaned.split(separator)[0]
        if "!" in cleaned:  # PEP 440 epoch
            cleaned = cleaned.split("!", 1)[1]
        parts = cleaned.split(".")
        if not all(p.isdigit() for p in parts if p):
            return None
        return tuple(int(p) for p in parts if p)
    left, right = numbers(installed), numbers(target)
    if left is None or right is None:
        return UpgradeCost.UNKNOWN
    padded = max(len(left), len(right))
    left = left + (0,) * (padded - len(left))
    right = right + (0,) * (padded - len(right))
    if left[0] != right[0]:
        return UpgradeCost.MAJOR
    if len(left) > 1 and left[1] != right[1]:
        return UpgradeCost.MINOR
    return UpgradeCost.PATCH


def _parse_due(entry: NormalizedVulnerability) -> date | None:
    """CISA publishes ``dueDate`` as ``YYYY-MM-DD``; it is stored as text."""
    raw = getattr(entry, "kev_due_date", None)
    if isinstance(raw, (date, datetime)):
        return raw.date() if isinstance(raw, datetime) else raw
    return None


_DEFAULT_MITIGATIONS: dict[str, tuple[str, ...]] = {
    "network": (
        "restrict network access to the affected service",
        "apply the vendor workaround documented in the advisory",
    ),
    "default": (
        "monitor the advisory for a fixed release",
        "reduce exposure until a fix is published",
    ),
}


def _mitigations_for(record: NormalizedVulnerability) -> tuple[str, ...]:
    """Suggest mitigations grounded in the record, not generic advice."""
    suggestions: list[str] = []
    vector = record.best_cvss.vector if record.best_cvss else None
    if vector and "AV:N" in vector:
        suggestions.append("limit network reachability: the CVSS vector is AV:N (network)")
    if vector and "PR:N" in vector:
        suggestions.append("attack requires no privileges: prioritise any internet-facing instance")
    if record.kev is True:
        suggestions.append("CISA confirms exploitation in the wild: review logs for prior exploitation")
    suggestions.extend(_DEFAULT_MITIGATIONS["default"])
    return tuple(dict.fromkeys(suggestions))


def plan_remediation(
    record: NormalizedVulnerability,
    *,
    ecosystem: str | None = None,
    name: str | None = None,
    installed_version: str | None = None,
    today: date | None = None,
    priority_band: str | None = None,
) -> Remediation:
    """Produce one recommendation for ``record`` against a concrete install.

    With no ``installed_version`` the function still returns an actionable plan
    ("upgrade to the published fixed version") but states that applicability was
    not checked, rather than implying it was.
    """
    today = today or datetime.now(timezone.utc).date()
    reasons: list[str] = []
    warnings: list[str] = []
    evidence: list[str] = [f"sources: {', '.join(record.sources) or 'none recorded'}"]

    packages: Sequence[AffectedPackage] = record.affected
    assessment: AffectedAssessment | None = None
    if installed_version and ecosystem and name:
        assessment = assess_affected(
            packages, ecosystem=ecosystem, name=name, version=installed_version
        )
        evidence.extend(assessment.reasons)
    else:
        warnings.append(
            "no installed version supplied: applicability was not evaluated, so this "
            "plan states the published fix rather than a confirmed action"
        )

    target = _best_fixed_version(packages, ecosystem=ecosystem, name=name)
    cost = assess_upgrade_cost(installed_version, target, ecosystem or None)
    due = _parse_due(record)
    days_remaining = (due - today).days if due else None

    if assessment is not None and assessment.verdict is Verdict.NOT_AFFECTED:
        action = RecommendedAction.MONITOR if record.kev else RecommendedAction.NONE
        reasons.append(f"installed version {installed_version} is outside every affected range")
    elif assessment is not None and assessment.verdict is Verdict.UNKNOWN:
        action = RecommendedAction.MONITOR
        reasons.append(
            "applicability could not be determined; the advisory still applies to this "
            "package, so treat as unverified rather than safe"
        )
    elif target is not None:
        action = (
            RecommendedAction.UPGRADE_MAJOR
            if cost is UpgradeCost.MAJOR
            else RecommendedAction.PATCH
        )
        reasons.append(f"fixed release published: {target}")
        if record.kev:
            action = RecommendedAction.EMERGENCY_PATCH
            reasons.append("listed in CISA KEV: exploitation confirmed in the wild")
    elif record.kev:
        action = RecommendedAction.EMERGENCY_PATCH
        reasons.append("listed in CISA KEV with no published fixed version")
    else:
        action = RecommendedAction.MITIGATE
        reasons.append("no fixed release published for this package")

    if due is not None:
        if days_remaining is not None and days_remaining < 0:
            reasons.append(f"CISA remediation due date passed {abs(days_remaining)} day(s) ago")
        elif days_remaining is not None and days_remaining <= KEV_URGENCY_WINDOW_DAYS:
            reasons.append(f"CISA remediation due in {days_remaining} day(s)")
        if action is RecommendedAction.PATCH and record.kev:
            action = RecommendedAction.EMERGENCY_PATCH

    if record.effective_severity is Severity.CRITICAL:
        evidence.append("severity: critical")
    if record.conflict_notes:
        warnings.extend(record.conflict_notes[:2])
    if not record.sources:
        warnings.append("record carries no source provenance: treat with suspicion")

    return Remediation(
        cve=str(record.cve),
        action=action,
        priority=priority_band or "unranked",
        package=name or (packages[0].name if packages else None),
        ecosystem=ecosystem or (packages[0].ecosystem if packages else None),
        installed_version=installed_version,
        target_version=target,
        upgrade_cost=cost,
        due_date=due,
        overdue=bool(days_remaining is not None and days_remaining < 0),
        days_remaining=days_remaining,
        mitigations=(
            _mitigations_for(record)
            if action in (RecommendedAction.MITIGATE, RecommendedAction.EMERGENCY_PATCH)
            else ()
        ),
        reasons=tuple(reasons),
        evidence=tuple(evidence),
        warnings=tuple(dict.fromkeys(warnings)),
    )


def _best_fixed_version(
    packages: Iterable[AffectedPackage], *, ecosystem: str | None, name: str | None
) -> str | None:
    """Lowest published fix that resolves the advisory for this package.

    The lowest, not the highest: an operator should be told the smallest change
    that removes the vulnerability, since a larger jump carries more risk.
    """
    scheme = scheme_for_ecosystem(ecosystem) if ecosystem else None
    candidates: list[str] = []
    for package in packages:
        if not package.fixed:
            continue
        if name and package.name.strip().lower() != name.strip().lower():
            continue
        if ecosystem and package.ecosystem.strip().lower() != ecosystem.strip().lower():
            continue
        candidates.append(package.fixed)
    if not candidates:
        return None
    if scheme is None or scheme is VersionScheme.OPAQUE:
        return sorted(candidates)[0]
    best = candidates[0]
    for candidate in candidates[1:]:
        if compare(candidate, best, scheme) == -1:
            best = candidate
    return best


def summarize_remediation(remediations: Sequence[Remediation]) -> dict[str, object]:
    """Aggregate a remediation plan for a dashboard or a change request."""
    by_action: dict[str, int] = {}
    for item in remediations:
        by_action[item.action.value] = by_action.get(item.action.value, 0) + 1
    return {
        "total": len(remediations),
        "actionable": sum(1 for r in remediations if r.action.is_actionable),
        "emergency": sum(
            1 for r in remediations if r.action is RecommendedAction.EMERGENCY_PATCH
        ),
        "overdue": sum(1 for r in remediations if r.overdue),
        "by_action": dict(sorted(by_action.items())),
        "by_cost": _count(r.upgrade_cost.value for r in remediations),
        "unverifiable": sum(
            1 for r in remediations if any("not evaluated" in w for w in r.warnings)
        ),
    }


def _count(values: Iterable[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for value in values:
        out[value] = out.get(value, 0) + 1
    return dict(sorted(out.items()))
