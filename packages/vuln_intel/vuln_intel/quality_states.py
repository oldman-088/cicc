"""Evidence quality per finding, and the explicit statement of what is unknown.

The problem this solves
-----------------------
`ExposureReport` already separates `matches`, `unverified`, `not_affected` and
`unexplorable`, which is the right structure. What it cannot do is answer the question
that comes *next*:

    Of the components in this inventory, which ones did we actually reach a conclusion
    about, and for which ones is exposure genuinely unknown?

Those are different. A component with no advisories at all is **checked and clean**. A
component whose advisory had no version ranges is **checked and unanswerable**. A
component whose SBOM entry could not be matched to an ecosystem is **not checked at all**.
Collapsing all three into "not vulnerable" is the single most dangerous simplification in
vulnerability management, because it converts ignorance into a clean bill of health.

This module keeps them apart and counts them, per component and in total.

What it deliberately does not do
--------------------------------
**It never infers a vulnerability from a component's presence.** A component existing is
not evidence that it is affected. Exposure comes only from `ExposureReport`, which comes
only from advisory data with version ranges. This module reads that report; it does not
create findings.

It also invents no applicability. Every state below is derived mechanically from what the
caller already computed. Where the input does not settle a question, the answer is
`UNKNOWN`, and `UNKNOWN` is rendered as unknown rather than defaulted.

States
------
- ``CLEAN``: an inventory entry that matched no advisory. Checked, nothing found.
- ``AFFECTED``: matched an advisory whose range the component is inside.
- ``NOT_AFFECTED``: matched an advisory whose range the component is provably outside.
- ``UNVERIFIABLE``: an advisory names this package but its range could not be evaluated.
- ``UNCHECKED``: the SBOM entry could not be turned into a matchable dependency
  (no purl, unknown ecosystem). Excluded from analysis entirely.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence

__all__ = [
    "ComponentQuality",
    "InventoryQualityReport",
    "QualityState",
    "assess_inventory_quality",
]


class QualityState(str, Enum):
    """What is known about one component. Ordered from most to least certain."""

    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    CLEAN = "clean"
    UNVERIFIABLE = "unverifiable"
    UNCHECKED = "unchecked"


#: States that represent a conclusion the caller may rely on.
CONCLUDED = frozenset({QualityState.AFFECTED, QualityState.NOT_AFFECTED, QualityState.CLEAN})

#: States that represent ignorance. A report must never present these as safety.
UNKNOWN = frozenset({QualityState.UNVERIFIABLE, QualityState.UNCHECKED})


@dataclass(frozen=True)
class ComponentQuality:
    """One component's state, with the evidence behind it and nothing inferred."""

    #: `ecosystem:name`, or the SBOM's own label when the entry was unmatchable.
    component: str
    state: QualityState
    #: Advisory identifiers that produced this state. Empty for CLEAN and UNCHECKED.
    advisories: tuple[str, ...] = ()
    #: Why the state is UNKNOWN, or why a component was skipped. Empty when concluded.
    reason: str = ""
    #: True when the state is derived from advisory data. Always False for UNCHECKED.
    evaluated: bool = True

    def __post_init__(self) -> None:
        if self.state in UNKNOWN and not self.reason:
            # Without a reason, an unknown is indistinguishable from a bug.
            raise ValueError(
                f"component {self.component!r} is {self.state.value} but states no "
                "reason; an unexplained unknown cannot be acted on"
            )
        if self.state is QualityState.UNCHECKED and self.evaluated:
            raise ValueError("an unchecked component cannot claim it was evaluated")
        if self.state is QualityState.CLEAN and self.advisories:
            raise ValueError("a clean component cannot cite advisories")

    @property
    def is_certain(self) -> bool:
        return self.state in CONCLUDED

    def as_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "state": self.state.value,
            "advisories": list(self.advisories),
            "reason": self.reason,
            "evaluated": self.evaluated,
            "certain": self.is_certain,
        }


@dataclass(frozen=True)
class InventoryQualityReport:
    """Per-component states plus totals, with coverage stated as a fraction."""

    components: tuple[ComponentQuality, ...] = ()
    #: Advisories that named no package we run, or had no affected data at all.
    unexplorable: tuple[str, ...] = ()
    #: Metadata the caller supplied about the evidence basis, passed through unchanged.
    provenance: Mapping[str, Any] = field(default_factory=dict)

    def by_state(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for component in self.components:
            counts[component.state.value] = counts.get(component.state.value, 0) + 1
        return dict(sorted(counts.items()))

    @property
    def total(self) -> int:
        return len(self.components)

    @property
    def concluded(self) -> int:
        return sum(1 for c in self.components if c.state in CONCLUDED)

    @property
    def unknown(self) -> int:
        return sum(1 for c in self.components if c.state in UNKNOWN)

    @property
    def coverage(self) -> float | None:
        """Fraction of components with a conclusion. None when there are none.

        ``None`` rather than ``1.0`` or ``0.0`` on an empty inventory: an empty
        inventory has no coverage, and reporting it as 0% or 100% would both be wrong.
        """
        if not self.components:
            return None
        return self.concluded / self.total

    @property
    def affected(self) -> tuple[ComponentQuality, ...]:
        return tuple(c for c in self.components if c.state is QualityState.AFFECTED)

    @property
    def unknowns(self) -> tuple[ComponentQuality, ...]:
        return tuple(c for c in self.components if c.state in UNKNOWN)

    @property
    def is_conclusive(self) -> bool:
        """True only when every component has a conclusion. False is the normal case."""
        return self.unknown == 0

    def as_dict(self) -> dict[str, Any]:
        coverage = self.coverage
        return {
            "total": self.total,
            "concluded": self.concluded,
            "unknown": self.unknown,
            "coverage": None if coverage is None else round(coverage, 4),
            "conclusive": self.is_conclusive,
            "by_state": self.by_state(),
            "unexplorable": list(self.unexplorable),
            "provenance": dict(sorted(self.provenance.items())),
            "components": [c.as_dict() for c in self.components],
        }

    def summary_line(self) -> str:
        """One deterministic sentence for a report header. No clock, no randomness."""
        if not self.components:
            return "No components were available to assess; exposure is not known."
        coverage = self.coverage or 0.0
        parts = [
            f"{self.concluded} of {self.total} components concluded "
            f"({coverage:.0%})",
        ]
        if self.affected:
            parts.append(f"{len(self.affected)} affected")
        if self.unknown:
            parts.append(
                f"{self.unknown} unknown — these are not a clean result, they are "
                f"unexamined"
            )
        if self.unexplorable:
            parts.append(f"{len(self.unexplorable)} advisories could not be evaluated")
        return "; ".join(parts) + "."


def _key(ecosystem: str | None, name: str) -> str:
    return f"{ecosystem}:{name}" if ecosystem else name


def _advisory_id(match: Any) -> str:
    """The advisory identifier on a match, trying the real field first.

    `PackageMatch` carries it as `.cve`; a nested `.advisory` object is only a fallback
    for other shapes. Reading the wrong one would label every finding
    "unspecified-advisory" while still passing a loose test.
    """
    return str(
        getattr(match, "cve", None)
        or getattr(getattr(match, "advisory", None), "cve", None)
        or getattr(getattr(match, "advisory", None), "id", None)
        or getattr(match, "vulnerability_id", None)
        or "unspecified-advisory"
    )


def _verdict_classifier() -> Any:
    """Return a function mapping an assessment to a verdict string, or None."""

    def classify(assessment: Any) -> str | None:
        if assessment is None:
            return None
        verdict = getattr(assessment, "verdict", None)
        if verdict is None:
            return None
        value = getattr(verdict, "value", verdict)
        return str(value).lower()

    return classify


def assess_inventory_quality(
    *,
    dependencies: Iterable[Any],
    exposure: Any | None,
    skipped: Sequence[Mapping[str, Any]] = (),
    provenance: Mapping[str, Any] | None = None,
) -> InventoryQualityReport:
    """Derive per-component states from what the caller already computed.

    ``dependencies`` are the matchable inventory entries (anything with ``ecosystem``
    and ``name``). ``exposure`` is an `ExposureReport`-shaped object; when it is ``None``
    every component is ``UNCHECKED`` with a reason, never ``CLEAN``.

    Dependency and advisory *presence* is never treated as a finding: a component only
    becomes ``AFFECTED`` if the exposure report says an advisory's range contains it.
    """
    entries: list[ComponentQuality] = []
    seen: set[str] = set()

    # Components the SBOM could not turn into a matchable dependency at all.
    for record in skipped:
        label = str(record.get("name") or record.get("component") or "unknown")
        reason = str(record.get("reason") or "the SBOM entry could not be matched")
        key = f"unmatched:{label}"
        if key in seen:
            continue
        seen.add(key)
        entries.append(
            ComponentQuality(
                component=key,
                state=QualityState.UNCHECKED,
                reason=reason,
                evaluated=False,
            )
        )

    if exposure is None:
        for dependency in dependencies:
            key = _key(getattr(dependency, "ecosystem", None), str(getattr(dependency, "name", "")))
            if key in seen:
                continue
            seen.add(key)
            entries.append(
                ComponentQuality(
                    component=key,
                    state=QualityState.UNCHECKED,
                    reason="no advisory data was supplied, so this was not evaluated",
                    evaluated=False,
                )
            )
        return _finish(entries, (), provenance)

    # Index the exposure report by component so each dependency is judged once.
    affected: dict[str, list[str]] = {}
    not_affected: dict[str, list[str]] = {}
    unverifiable: dict[str, list[str]] = {}

    def _collect(items: Iterable[Any], into: dict[str, list[str]]) -> None:
        for match in items:
            dependency = getattr(match, "dependency", None) or getattr(match, "package", None)
            if dependency is None:
                continue
            key = _key(
                getattr(dependency, "ecosystem", None), str(getattr(dependency, "name", ""))
            )
            into.setdefault(key, []).append(_advisory_id(match))

    # `ExposureReport.affected` is a *property derived from `.matches`*, so reading only
    # `.affected` misses every match whose verdict is not AFFECTED. Classify each match
    # by its own verdict instead.
    verdict_of = _verdict_classifier()
    for match in getattr(exposure, "matches", ()) or ():
        dependency = getattr(match, "dependency", None)
        if dependency is None:
            continue
        key = _key(
            getattr(dependency, "ecosystem", None), str(getattr(dependency, "name", ""))
        )
        identifier = _advisory_id(match)
        verdict = verdict_of(getattr(match, "assessment", None))
        if verdict == "affected":
            affected.setdefault(key, []).append(identifier)
        elif verdict == "not_affected":
            not_affected.setdefault(key, []).append(identifier)
        elif verdict is not None:
            # Any other verdict means the range could not be settled.
            unverifiable.setdefault(key, []).append(identifier)

    # `matches` and `not_affected` are INDEPENDENT fields on `ExposureReport`, not one
    # derived from the other. Collecting the explicit tuples only when `matches` was
    # empty meant a report with both an affected and a cleared match silently lost the
    # cleared one, and the component fell through to CLEAN — wrong in the optimistic
    # direction. Both sources are read; duplicates are removed below.
    _collect(getattr(exposure, "not_affected", ()) or (), not_affected)
    _collect(getattr(exposure, "unverified", ()) or (), unverifiable)

    # De-duplicate: a match may be reachable from both `.matches` and an explicit tuple.
    for mapping in (affected, not_affected, unverifiable):
        for key in list(mapping):
            mapping[key] = sorted(set(mapping[key]))

    for dependency in dependencies:
        key = _key(getattr(dependency, "ecosystem", None), str(getattr(dependency, "name", "")))
        if key in seen:
            continue
        seen.add(key)
        if key in affected:
            # A component can be affected by one advisory and cleared by another;
            # AFFECTED wins, because this must never be optimistic.
            entries.append(
                ComponentQuality(
                    component=key,
                    state=QualityState.AFFECTED,
                    advisories=tuple(sorted(set(affected[key]))),
                )
            )
        elif key in unverifiable:
            entries.append(
                ComponentQuality(
                    component=key,
                    state=QualityState.UNVERIFIABLE,
                    advisories=tuple(sorted(set(unverifiable[key]))),
                    reason=(
                        "an advisory names this package but its version ranges could "
                        "not be evaluated, so applicability is unknown"
                    ),
                )
            )
        elif key in not_affected:
            entries.append(
                ComponentQuality(
                    component=key,
                    state=QualityState.NOT_AFFECTED,
                    advisories=tuple(sorted(set(not_affected[key]))),
                )
            )
        else:
            entries.append(ComponentQuality(component=key, state=QualityState.CLEAN))

    unexplorable = tuple(str(item) for item in (getattr(exposure, "unexplorable", ()) or ()))
    return _finish(entries, unexplorable, provenance)


def _finish(
    entries: list[ComponentQuality],
    unexplorable: Sequence[str],
    provenance: Mapping[str, Any] | None,
) -> InventoryQualityReport:
    entries.sort(key=lambda c: (c.component, c.state.value))
    return InventoryQualityReport(
        components=tuple(entries),
        unexplorable=tuple(unexplorable),
        provenance=dict(provenance or {}),
    )
