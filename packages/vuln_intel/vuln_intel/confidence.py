"""Persistent confidence: the value, where it came from, and how it was computed.

Confidence was computed for ranking and then discarded, so nothing downstream could
read it. Master Prompt §2.3 requires that "confidence must be distinguishable from
factual certainty" and §7 requires a confidence on every record — a number that exists
only inside a ranking call satisfies neither, because a consumer of the record sees
nothing at all.

Two requirements shape this module:

**Provenance.** A bare float is unfalsifiable: 0.62 could mean "three sources agreed"
or "one source said so" or "a provider published it". Every stored value therefore
carries who produced it, from what inputs, and under which policy version.

**Source-provided vs internally calculated.** These are different kinds of claim and
must never be silently mixed. A provider that publishes its own confidence is asserting
something about the vulnerability; a computed one is this system's judgement about the
*evidence*. Conflating them would let our arithmetic masquerade as a provider statement.
:class:`ConfidenceBasis` keeps them apart, and a merge of the two is explicitly labelled
rather than averaged into a third number that is neither.

**Historical values must not silently change.** Recomputing a score with new weights and
overwriting the old one destroys the audit trail. :class:`ConfidenceHistory` appends, and
:meth:`ConfidenceHistory.current` returns the latest — the earlier values remain
readable, each with the reason it was superseded.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Iterable, Mapping

from .errors import ValidationError
from .schema import Origin, utcnow

__all__ = [
    "CONFIDENCE_SCHEMA",
    "ConfidenceBasis",
    "ConfidenceHistory",
    "ConfidenceValue",
    "SourceReliabilityPolicy",
    "derive_confidence",
    "deserialise_confidence",
    "serialise_confidence",
]

#: Bumped when the persisted shape changes incompatibly.
CONFIDENCE_SCHEMA = "cicc.vuln_intel.confidence.v1"


class ConfidenceBasis:
    """Where a confidence number came from. Never inferred at read time."""

    #: A provider published the value (e.g. an advisory's own confidence field).
    SOURCE_PROVIDED = "source_provided"
    #: This package computed it from corroboration across sources.
    CORROBORATION = "corroboration"
    #: This package computed it from the ranking policy's weighted components.
    POLICY_WEIGHTED = "policy_weighted"
    #: More than one basis contributed; ``inputs`` records each.
    MIXED = "mixed"
    #: Nothing usable; the value is absent rather than zero.
    NONE = "none"


@dataclass(frozen=True)
class ConfidenceValue:
    """One confidence assertion, with everything needed to audit it.

    ``value`` is ``None`` when nothing could be computed. That is deliberate and is the
    most important rule in this module: **``None`` is not ``0.0``**. A zero says "we are
    certain this is wrong"; ``None`` says "we do not know". Rendering the second as the
    first is how a record with no evidence ends up looking deliberately dismissed.
    """

    value: float | None
    basis: str
    #: Human-readable inputs to the calculation, so the number is explainable.
    inputs: tuple[str, ...] = ()
    #: Which policy produced it, when ``basis`` is policy-derived. Two confidences are
    #: only comparable if this matches, so it travels with the value.
    policy: str | None = None
    #: False when the policy is provisional. A provisional confidence must not be
    #: presented as organizational policy.
    policy_approved: bool = False
    computed_at: datetime | None = None
    origin: str = Origin.LIVE.value
    #: Free-text note for anything a consumer must know before using the number.
    note: str | None = None

    def __post_init__(self) -> None:
        if self.value is not None:
            if not 0.0 <= self.value <= 1.0:
                raise ValueError("confidence value must be within 0.0-1.0")
            if self.basis == ConfidenceBasis.NONE:
                raise ValueError("a value cannot have basis 'none'")
        elif self.basis != ConfidenceBasis.NONE:
            raise ValueError("a missing value must have basis 'none'")

    @property
    def is_known(self) -> bool:
        return self.value is not None

    @property
    def is_provisional(self) -> bool:
        """True when the *reported* number is our judgement under an unapproved policy.

        The corroboration curve (one source 0.3, two 0.7, three or more 1.0) is as much
        a policy choice as the ranking weights are, so a value derived from it under a
        provisional policy is provisional too. Presenting it as settled would be the
        thing the ranking policy's ``approved`` flag exists to prevent.

        Two bases escape this, for the same reason: the number is not ours.
        ``SOURCE_PROVIDED`` is the provider's statement, and ``MIXED`` reports the
        provider's value with our estimate kept only as context.
        """
        if self.policy_approved:
            return False
        return self.basis in (
            ConfidenceBasis.CORROBORATION,
            ConfidenceBasis.POLICY_WEIGHTED,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": CONFIDENCE_SCHEMA,
            "value": self.value,
            "basis": self.basis,
            "inputs": list(self.inputs),
            "policy": self.policy,
            "policy_approved": self.policy_approved,
            "computed_at": self.computed_at.isoformat() if self.computed_at else None,
            "origin": self.origin,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ConfidenceValue:
        value = payload.get("value")
        if value is not None:
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ValueError("confidence value must be a number or None")
            value = float(value)
        computed_raw = payload.get("computed_at")
        computed: datetime | None = None
        if isinstance(computed_raw, str) and computed_raw:
            computed = datetime.fromisoformat(computed_raw)
        inputs = payload.get("inputs") or ()
        basis = str(payload.get("basis") or ConfidenceBasis.NONE)
        return cls(
            value=value,
            basis=basis,
            inputs=tuple(str(i) for i in inputs),
            policy=str(payload["policy"]) if payload.get("policy") else None,
            policy_approved=bool(payload.get("policy_approved")),
            computed_at=computed,
            origin=str(payload.get("origin") or Origin.LIVE.value),
            note=str(payload["note"]) if payload.get("note") else None,
        )


@dataclass(frozen=True)
class SourceReliabilityPolicy:
    """B-10 groundwork: per-source reliability weights + recency decay.

    **PROVISIONAL — owner approval required before these weights mean anything
    organizational.** The default instance reproduces the current count-based
    curve exactly, so existing behaviour is unchanged until the owner approves a
    weighted policy. Weights are validated (0..1, at least one non-zero) but
    validity is not approval: ``approved`` defaults to ``False`` and every
    result computed under an unapproved policy is marked provisional.
    """

    weights: Mapping[str, float] = field(default_factory=dict)
    #: Weight multiplier decay per day since the newest contributing observation.
    recency_decay_per_day: float = 0.0
    approved: bool = False
    name: str = "default-count-curve"

    def __post_init__(self) -> None:
        for source, weight in self.weights.items():
            if not isinstance(weight, (int, float)) or isinstance(weight, bool):
                raise ValidationError(f"weight for {source!r} must be a number", field="weights")
            if not 0.0 <= float(weight) <= 1.0:
                raise ValidationError(f"weight for {source!r} must be within 0..1", field="weights")
        if self.weights and not any(w > 0 for w in self.weights.values()):
            raise ValidationError("at least one weight must be > 0", field="weights")
        if not 0.0 <= self.recency_decay_per_day <= 1.0:
            raise ValidationError("recency_decay_per_day must be within 0..1", field="recency_decay_per_day")

    def weight_of(self, source: str) -> float:
        """Explicit weight, else the neutral default (count-curve behaviour)."""
        return float(self.weights.get(source, 1.0))


def derive_confidence(
    *,
    sources: Iterable[str],
    policy: str,
    policy_approved: bool,
    computed_at: datetime | None = None,
    origin: Origin | str = Origin.LIVE,
    reliability: SourceReliabilityPolicy | None = None,
    newest_observation: datetime | None = None,
) -> ConfidenceValue:
    """Compute a corroboration confidence and record how it was reached.

    The curve mirrors the ranking policy so the two cannot disagree: one source is weak
    evidence, two is moderate, three or more is as good as corroboration gets. The point
    of storing it separately from the score is that the score mixes in severity and
    exploitation, whereas this number is *only* about how many independent sources
    agree.

    A record with no source names gets ``None``, not a low number: no provenance is not
    weak evidence, it is the absence of evidence.
    """
    names = sorted({str(s) for s in sources if str(s)})
    if not names:
        return ConfidenceValue(
            value=None,
            basis=ConfidenceBasis.NONE,
            inputs=("no source provenance recorded",),
            policy=policy,
            policy_approved=policy_approved,
            computed_at=computed_at,
            origin=origin.value if isinstance(origin, Origin) else str(origin),
            note="no sources named: absence of evidence, not evidence of absence",
        )

    count = len(names)
    if reliability is not None and reliability.weights:
        # Weighted corroboration (B-10): sum of per-source weights, normalized by
        # the maximum possible (number of sources at weight 1), then the same
        # saturating curve shape so the two policies stay comparable. Recency
        # decay applies when a newest observation timestamp is supplied.
        raw = sum(reliability.weight_of(name) for name in names)
        value = min(1.0, raw / max(1, count))
        if newest_observation is not None and reliability.recency_decay_per_day > 0:
            moment = computed_at or utcnow()
            age_days = max(0.0, (moment - newest_observation).total_seconds() / 86400.0)
            value = round(value * (1.0 - reliability.recency_decay_per_day) ** age_days, 4)
        policy_approved = policy_approved and reliability.approved
        policy = f"{policy}+reliability:{reliability.name}"
        inputs_extra: tuple[str, ...] = (
            "weighted corroboration: " + ", ".join(
                f"{n}={reliability.weight_of(n):.2f}" for n in names
            ),
            f"reliability policy '{reliability.name}' approved={reliability.approved}",
        )
    else:
        if count >= 3:
            value = 1.0
        elif count == 2:
            value = 0.7
        else:
            value = 0.3
        inputs_extra = (f"curve: 1 source=0.3, 2=0.7, 3+=1.0 (policy '{policy}')",)

    return ConfidenceValue(
        value=value,
        basis=ConfidenceBasis.CORROBORATION,
        inputs=(
            f"{count} independent source(s): " + ", ".join(names),
            *inputs_extra,
        ),
        policy=policy,
        policy_approved=policy_approved,
        computed_at=computed_at,
        origin=origin.value if isinstance(origin, Origin) else str(origin),
    )


def blend(
    source_value: ConfidenceValue, computed: ConfidenceValue
) -> ConfidenceValue:
    """Combine a provider's confidence with ours **without averaging them**.

    Averaging would produce a number that is neither a provider assertion nor our
    judgement, and no consumer could tell which. Instead the provider's value is kept
    as the reported one — it is a statement about the vulnerability from someone with
    better information — and our computed value is retained in ``inputs`` as
    corroborating context, with the basis marked ``mixed`` so nobody mistakes it for a
    pure provider statement.
    """
    if not source_value.is_known:
        return computed
    if not computed.is_known:
        return replace(source_value, basis=ConfidenceBasis.SOURCE_PROVIDED)
    detail = (
        f"provider published {source_value.value:.2f}; "
        f"local corroboration estimate {computed.value:.2f} "
        f"(not averaged: keeping the provider's assertion as the reported value)"
    )
    return replace(
        source_value,
        basis=ConfidenceBasis.MIXED,
        inputs=(*source_value.inputs, *computed.inputs, detail),
        policy=computed.policy,
        policy_approved=computed.policy_approved,
        note="provider value reported; local estimate retained as corroborating context",
    )


@dataclass
class ConfidenceHistory:
    """Append-only record of every confidence ever attached to one CVE.

    ``current`` is the newest value. Older ones stay readable, each with the reason it
    was superseded, because "the confidence was 0.3 last week and 0.7 today" is a fact
    an auditor needs — and overwriting it is how a system quietly rewrites its own past.
    """

    cve: str
    entries: list[ConfidenceValue] = field(default_factory=list)
    superseded_reasons: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.cve:
            raise ValueError("confidence history needs a cve")

    def append(self, value: ConfidenceValue, *, reason: str | None = None) -> None:
        """Record a new value. ``reason`` explains why the previous one no longer holds."""
        if self.entries and reason is None:
            reason = "recomputed: no reason given by the caller"
        self.entries.append(value)
        if reason is not None:
            self.superseded_reasons.append(reason)

    @property
    def current(self) -> ConfidenceValue | None:
        return self.entries[-1] if self.entries else None

    @property
    def history(self) -> tuple[ConfidenceValue, ...]:
        return tuple(self.entries)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": CONFIDENCE_SCHEMA,
            "cve": self.cve,
            "current": self.current.as_dict() if self.current else None,
            "history": [e.as_dict() for e in self.entries],
            "superseded_reasons": list(self.superseded_reasons),
        }


def serialise_confidence(value: ConfidenceValue) -> dict[str, Any]:
    return value.as_dict()


def deserialise_confidence(payload: Mapping[str, Any]) -> ConfidenceValue:
    return ConfidenceValue.from_dict(payload)
