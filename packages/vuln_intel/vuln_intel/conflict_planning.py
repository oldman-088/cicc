"""Plan what *would* resolve a source disagreement — without resolving it.

Why this is not a resolver
--------------------------
Deciding which of two sources is right about a CVE's severity is an analyst's decision
with legal and operational consequences. A package that picked one automatically would be
manufacturing authority it does not have. So this module produces a **plan**: for each
conflict, what evidence exists, which evidence would settle it, and what a human would
need to look at. It writes nothing, mutates nothing, and never selects a value.

That is also why every plan entry is explicitly ``unresolved``. A plan that looked
"resolved" would be worse than no plan, because a UI would render it as settled.

Why it is useful anyway
-----------------------
"Three hundred records have a disputed severity" is not actionable. "Two hundred of them
are disputes between NVD and OSV where NVD is newer by more than a day, and forty have no
provenance at all so nobody can even tell who said what" is actionable. The plan makes
that distinction, deterministically, so two runs over the same input produce byte-
identical output and a diff means the evidence changed.

Determinism
-----------
Every collection is sorted by a stable key before it is returned. Nothing here reads a
clock, a random value, or a hash seed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Mapping, Sequence

__all__ = [
    "NEVER_AUTOMATIC",
    "ConflictPlan",
    "ConflictPlanEntry",
    "NextStep",
    "plan_conflict_resolution",
]

#: Fields where an automatic choice would be wrong in a way a human must own. Listed as
#: data so a test can assert every one of them is marked as requiring review.
NEVER_AUTOMATIC = (
    "severity",
    "cvss",
    "kev",
    "record_status",
    "affected",
    "epss_score",
)

#: The only fields where "keep the newer observation" is a defensible *default to
#: propose*, because the field is a timestamp about the record rather than a judgement
#: about the vulnerability.
TIMESTAMP_FIELDS = ("published", "modified", "kev_date_added", "epss_model_date")


class NextStep(str):
    """What a human should do next. A vocabulary, not a decision."""

    #: Provenance is missing, so nobody can tell which source said what.
    GATHER_PROVENANCE = "gather_provenance"
    #: One source is clearly newer; review whether the difference is a correction.
    REVIEW_NEWER_SOURCE = "review_newer_source"
    #: Sources disagree and are contemporaneous; needs an analyst's judgement.
    ANALYST_JUDGEMENT = "analyst_judgement"
    #: A timestamp differs; propose the newer value for confirmation.
    CONFIRM_NEWER_TIMESTAMP = "confirm_newer_timestamp"


@dataclass(frozen=True)
class ConflictPlanEntry:
    """One disagreement, with the evidence needed to resolve it and nothing chosen."""

    cve: str
    field_name: str
    kept: str
    discarded: tuple[str, ...]
    dissenters: tuple[str, ...]
    next_step: str
    #: Always False. Present so a consumer that renders the plan has to read a field
    #: called ``resolved`` and cannot mistake a plan for a decision.
    resolved: bool = False
    #: Human-readable reason, deterministic, no timestamps.
    rationale: str = ""
    #: Extra evidence a reviewer needs, e.g. which source is newer.
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "field": self.field_name,
            "kept": self.kept,
            "discarded": list(self.discarded),
            "dissenters": list(self.dissenters),
            "next_step": self.next_step,
            "resolved": self.resolved,
            "rationale": self.rationale,
            "evidence": dict(sorted(self.evidence.items())),
        }


@dataclass(frozen=True)
class ConflictPlan:
    """A deterministic, non-persistent plan over a set of records."""

    entries: tuple[ConflictPlanEntry, ...] = ()

    @property
    def count(self) -> int:
        return len(self.entries)

    @property
    def requires_analyst(self) -> int:
        return sum(
            1 for e in self.entries if e.next_step == NextStep.ANALYST_JUDGEMENT
        )

    @property
    def blocked_on_provenance(self) -> int:
        return sum(
            1 for e in self.entries if e.next_step == NextStep.GATHER_PROVENANCE
        )

    def by_field(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for entry in self.entries:
            counts[entry.field_name] = counts.get(entry.field_name, 0) + 1
        return dict(sorted(counts.items()))

    def by_next_step(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for entry in self.entries:
            counts[entry.next_step] = counts.get(entry.next_step, 0) + 1
        return dict(sorted(counts.items()))

    @property
    def anything_resolved(self) -> bool:
        """Always False. A test asserts it stays that way."""
        return any(entry.resolved for entry in self.entries)

    def as_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "requires_analyst": self.requires_analyst,
            "blocked_on_provenance": self.blocked_on_provenance,
            "by_field": self.by_field(),
            "by_next_step": self.by_next_step(),
            "anything_resolved": self.anything_resolved,
            "entries": [entry.as_dict() for entry in self.entries],
        }


def _step_for(field_name: str, dissenters: Sequence[str]) -> tuple[str, str]:
    """Which human action unblocks this conflict, and why."""
    if not dissenters:
        return (
            NextStep.GATHER_PROVENANCE,
            "no dissenters are recorded, so it is not known which source asserted "
            "the discarded value",
        )
    if field_name in TIMESTAMP_FIELDS:
        return (
            NextStep.CONFIRM_NEWER_TIMESTAMP,
            "the field is a timestamp, so the newer observation is a defensible "
            "proposal for a human to confirm",
        )
    return (
        NextStep.ANALYST_JUDGEMENT,
        "sources disagree contemporaneously on a judgement field; choosing one "
        "automatically would assert authority the package does not have",
    )


def plan_conflict_resolution(records: Iterable[Mapping[str, Any]]) -> ConflictPlan:
    """Build a deterministic plan from merged records carrying conflicts.

    ``records`` are mappings with ``cve`` and ``conflicts``, each conflict exposing
    ``field``/``kept``/``discarded``/``dissenters``. Accepts dataclasses or plain dicts
    so a caller does not have to reshape its data to plan.

    Reads nothing outside its arguments: no clock, no store, no network. Calling it twice
    with equal input returns equal output, which is what makes a plan reviewable.
    """
    entries: list[ConflictPlanEntry] = []
    for record in records:
        cve = str(_get(record, "cve") or "")
        for conflict in _get(record, "conflicts") or ():
            field_name = str(_get(conflict, "field") or "")
            kept = str(_get(conflict, "kept") or "")
            discarded = tuple(str(v) for v in (_get(conflict, "discarded") or ()))
            dissenters = tuple(
                sorted({str(s) for s in (_get(conflict, "dissenters") or ()) if s})
            )
            step, rationale = _step_for(field_name, dissenters)
            evidence: dict[str, Any] = {}
            if step == NextStep.CONFIRM_NEWER_TIMESTAMP:
                newer = _newer_value(kept, discarded)
                if newer is not None:
                    evidence["proposed_value"] = newer
            entries.append(
                ConflictPlanEntry(
                    cve=cve,
                    field_name=field_name,
                    kept=kept,
                    discarded=discarded,
                    dissenters=dissenters,
                    next_step=step,
                    rationale=rationale,
                    evidence=evidence,
                )
            )
    # Stable, total ordering: two plans over the same evidence are byte-identical.
    # Sorting by CVE then field is what makes a plan diffable, and a diff is the only
    # thing that tells a reviewer "the evidence changed" rather than "the tool changed".
    entries.sort(key=lambda e: (e.cve, e.field_name, e.kept, e.discarded, e.dissenters))
    return ConflictPlan(entries=tuple(entries))


def _get(obj: Any, name: str) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name)
    return getattr(obj, name, None)


def _parse(value: str) -> datetime | None:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _newer_value(kept: str, discarded: Sequence[str]) -> str | None:
    """The later of the timestamp values, or None when any is unparseable.

    Returns None rather than guessing: if a value is not a timestamp, "newer" is not a
    well-defined question and proposing one would be an invention.
    """
    candidates = [kept, *discarded]
    parsed = [(value, _parse(value)) for value in candidates]
    if any(moment is None for _, moment in parsed):
        return None
    best = max(parsed, key=lambda pair: pair[1])  # type: ignore[arg-type,return-value]
    return best[0]
