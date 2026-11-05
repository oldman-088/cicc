"""
Threat Intelligence Conflict Resolution — deterministic, evidence-preserving.
Branch: arena/28e50255-cicc (Agent 6 - Full Threat Intelligence Backup Engineer)

Design rules this module is built around:

1. **A source claim is not a conclusion.** `SourceClaim` is what a source asserted.
   `ResolvedValue` is what the system concluded. They are different objects and never collapse
   into one another.

2. **Nothing is overwritten.** Every claim is retained for the life of the record. Resolution
   chooses which claim to *promote*; it never deletes or edits the losers.

3. **Resolution is deterministic.** Given the same claims and the same clock, the same winner is
   selected, and the tie-break chain is recorded so the outcome can be re-derived and audited.

4. **Unresolved is a valid, first-class outcome.** When claims disagree and no rule can decide,
   the conflict stays open and is reported as open rather than being quietly settled.

5. **No network, no threads, no event loop.** The clock is injected everywhere it matters.
"""

import hashlib
import threading
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator

from apps.threat_intelligence.cisa_kev import EXPERIMENTAL_DEMO_DATA_ONLY

MAX_CLAIMS_PER_FIELD = 500
MAX_OPEN_CONFLICTS = 10_000


class ConflictError(ValueError):
    """Raised when a claim or resolution request is invalid."""


class ClaimOrigin(str, Enum):
    """Where a claim came from. Drives tie-breaking but never overrides evidence."""

    AUTHORITATIVE = "authoritative"
    PRIMARY_SOURCE = "primary_source"
    AGGREGATOR = "aggregator"
    COMMUNITY = "community"
    ANALYST = "analyst"
    UNKNOWN = "unknown"


class ResolutionStrategy(str, Enum):
    """Named, deterministic resolution rules."""

    HIGHEST_CONFIDENCE_THEN_NEWEST = "highest_confidence_then_newest"
    NEWEST_THEN_HIGHEST_CONFIDENCE = "newest_then_highest_confidence"
    SOURCE_PRIORITY_THEN_CONFIDENCE = "source_priority_then_confidence"
    MAJORITY_THEN_CONFIDENCE = "majority_then_confidence"
    MANUAL = "manual"
    UNRESOLVED = "unresolved"


class ConflictState(str, Enum):
    OPEN = "open"
    RESOLVED = "resolved"
    UNRESOLVABLE = "unresolvable"
    SUPERSEDED = "superseded"


# Lower number = higher standing. Used only as a tie-break, never as the primary rule, so a
# low-quality source cannot win purely by being labelled authoritative.
_ORIGIN_PRIORITY: Dict[ClaimOrigin, int] = {
    ClaimOrigin.AUTHORITATIVE: 0,
    ClaimOrigin.PRIMARY_SOURCE: 1,
    ClaimOrigin.AGGREGATOR: 2,
    ClaimOrigin.ANALYST: 3,
    ClaimOrigin.COMMUNITY: 4,
    ClaimOrigin.UNKNOWN: 5,
}


def _value_key(value: Any) -> str:
    """Stable string key for a claim value so equality does not depend on Python repr details."""
    if value is None:
        return "\x00null"
    if isinstance(value, bool):
        return f"\x01bool:{'1' if value else '0'}"
    if isinstance(value, (int, float)):
        return f"\x02num:{float(value)!r}"
    if isinstance(value, datetime):
        return f"\x03dt:{value.isoformat()}"
    if isinstance(value, str):
        return f"\x04str:{value.strip()}"
    return f"\x09json:{hashlib.sha256(repr(value).encode('utf-8')).hexdigest()}"


class SourceClaim(BaseModel):
    """
    One source's assertion about one field of one entity.

    Immutable once recorded: the service appends claims and never mutates them.
    """

    model_config = ConfigDict(extra="forbid")

    claim_id: str = Field(..., min_length=1, max_length=256)
    entity_id: str = Field(..., min_length=1, max_length=512)
    field_name: str = Field(..., min_length=1, max_length=256)
    value: Any = Field(..., description="The value the source asserted")
    source_id: str = Field(..., min_length=1, max_length=256)
    origin: ClaimOrigin = ClaimOrigin.UNKNOWN
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    reliability_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    observed_at: datetime = Field(..., description="When the source observed this")
    recorded_at: datetime = Field(default_factory=datetime.utcnow)
    provenance: Optional[str] = Field(None, max_length=512)
    source_reference: Optional[str] = Field(None, max_length=512)
    tenant_id: Optional[str] = Field(None, max_length=256)
    withdrawn: bool = Field(False, description="Set rather than deleted when a source retracts")

    @field_validator("field_name")
    @classmethod
    def _normalise_field(cls, v: str) -> str:
        return v.strip()

    @property
    def value_key(self) -> str:
        return _value_key(self.value)

    def effective_weight(self) -> float:
        """
        Confidence moderated by source reliability.

        An unscored source (reliability_score None) is NOT treated as perfectly reliable: it
        falls back to its raw confidence, and callers can see that no reliability adjustment was
        applied. A source cannot inflate itself by omitting a reliability score.
        """
        if self.reliability_score is None:
            return self.confidence
        return round(self.confidence * (0.5 + 0.5 * self.reliability_score), 6)


class ResolvedValue(BaseModel):
    """
    The normalized conclusion for one field.

    Distinct from `SourceClaim` on purpose: this is what downstream consumers read, and it always
    records which claims it was derived from and why.
    """

    model_config = ConfigDict(extra="forbid")

    entity_id: str = Field(..., min_length=1, max_length=512)
    field_name: str = Field(..., min_length=1, max_length=256)
    value: Any = None
    winning_claim_id: Optional[str] = Field(None, max_length=256)
    winning_source_id: Optional[str] = Field(None, max_length=256)
    strategy: ResolutionStrategy = ResolutionStrategy.UNRESOLVED
    resolution_basis: str = Field(
        "unresolved", max_length=2000, description="Human-readable, re-derivable explanation"
    )
    considered_claim_ids: List[str] = Field(default_factory=list)
    rejected_claim_ids: List[str] = Field(default_factory=list)
    dissenting_sources: List[str] = Field(default_factory=list)
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    conflict_id: Optional[str] = Field(None, max_length=256)
    resolved_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_by: Optional[str] = Field(None, max_length=256)
    tenant_id: Optional[str] = Field(None, max_length=256)
    experimental_label: Optional[str] = Field(EXPERIMENTAL_DEMO_DATA_ONLY)


class ConflictResolutionRecord(BaseModel):
    """
    A durable record of a disagreement. Retained after resolution so history is auditable.
    """

    model_config = ConfigDict(extra="forbid")

    conflict_id: str = Field(..., min_length=1, max_length=256)
    entity_id: str = Field(..., min_length=1, max_length=512)
    field_name: str = Field(..., min_length=1, max_length=256)
    state: ConflictState = ConflictState.OPEN
    claim_ids: List[str] = Field(default_factory=list)
    distinct_values: int = Field(0, ge=0)
    sources: List[str] = Field(default_factory=list)
    strategy: ResolutionStrategy = ResolutionStrategy.UNRESOLVED
    resolution_basis: Optional[str] = Field(None, max_length=2000)
    resolved_by: Optional[str] = Field(None, max_length=256)
    winning_claim_id: Optional[str] = Field(None, max_length=256)
    resolved_at: Optional[datetime] = None
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    superseded_by: Optional[str] = Field(None, max_length=256)
    tenant_id: Optional[str] = Field(None, max_length=256)


class ConflictResolutionService:
    """
    Deterministic conflict resolution over append-only source claims.

    In-memory. Safe under re-entrant use via an RLock, but starts no thread and no loop.
    """

    def __init__(self, tenant_id: str = "default"):
        if not tenant_id or not tenant_id.strip():
            raise ConflictError("tenant_id is required")
        self.tenant_id = tenant_id.strip()
        self._lock = threading.RLock()
        self._claims: Dict[str, SourceClaim] = {}
        # (entity_id, field_name) -> [claim_id] in arrival order
        self._claims_by_field: Dict[Tuple[str, str], List[str]] = {}
        self._conflicts: Dict[str, ConflictResolutionRecord] = {}
        self._conflicts_by_field: Dict[Tuple[str, str], List[str]] = {}
        self._resolved: Dict[Tuple[str, str], ResolvedValue] = {}
        self._claim_counter = 0
        self._conflict_counter = 0

    # ------------------------------------------------------------------ claims

    def record_claim(
        self,
        entity_id: str,
        field_name: str,
        value: Any,
        source_id: str,
        observed_at: datetime,
        origin: ClaimOrigin = ClaimOrigin.UNKNOWN,
        confidence: float = 0.0,
        reliability_score: Optional[float] = None,
        provenance: Optional[str] = None,
        source_reference: Optional[str] = None,
        claim_id: Optional[str] = None,
        now: Optional[datetime] = None,
        strategy: ResolutionStrategy = ResolutionStrategy.HIGHEST_CONFIDENCE_THEN_NEWEST,
    ) -> SourceClaim:
        """
        Append a source claim and re-resolve the field.

        Repeated ingestion from the same source with the same value is idempotent: it does not
        create a second claim, so a source cannot win by being polled repeatedly. A repeated
        ingestion with a *different* value appends a new claim and supersedes the old one for that
        source, keeping the old claim in history.
        """
        if not entity_id or not entity_id.strip():
            raise ConflictError("entity_id is required")
        if not field_name or not field_name.strip():
            raise ConflictError("field_name is required")
        if not source_id or not source_id.strip():
            raise ConflictError("source_id is required: a claim must be attributable to a source")

        moment = now or datetime.utcnow()
        entity_id = entity_id.strip()
        field_name = field_name.strip()
        source_id = source_id.strip()
        key = (entity_id, field_name)

        with self._lock:
            existing_ids = self._claims_by_field.get(key, [])
            same_source = [self._claims[c] for c in existing_ids if self._claims[c].source_id == source_id]
            latest_same_source = same_source[-1] if same_source else None

            if latest_same_source is not None:
                if (
                    latest_same_source.value_key == _value_key(value)
                    and latest_same_source.observed_at == observed_at
                    and not latest_same_source.withdrawn
                ):
                    # Identical re-assertion: idempotent, no new claim, no confidence inflation.
                    self._resolve_field(key, strategy=strategy, now=moment)
                    return latest_same_source
                # Same source, changed or newer value: keep the old claim, mark it superseded by
                # withdrawing it from consideration without deleting it.
                superseded = SourceClaim(
                    **{**latest_same_source.model_dump(), "withdrawn": True}
                )
                self._claims[latest_same_source.claim_id] = superseded

            self._claim_counter += 1
            claim = SourceClaim(
                claim_id=claim_id or f"CL-{self._claim_counter:08d}",
                entity_id=entity_id,
                field_name=field_name,
                value=value,
                source_id=source_id,
                origin=origin,
                confidence=confidence,
                reliability_score=reliability_score,
                observed_at=observed_at,
                recorded_at=moment,
                provenance=provenance,
                source_reference=source_reference,
                tenant_id=self.tenant_id,
            )
            if claim.claim_id in self._claims:
                raise ConflictError(f"claim_id {claim.claim_id!r} already exists")

            self._claims[claim.claim_id] = claim
            bucket = self._claims_by_field.setdefault(key, [])
            bucket.append(claim.claim_id)
            if len(bucket) > MAX_CLAIMS_PER_FIELD:
                raise ConflictError(
                    f"more than {MAX_CLAIMS_PER_FIELD} claims for {entity_id}.{field_name}"
                )

            self._resolve_field(key, strategy=strategy, now=moment)
            return claim

    def withdraw_claim(
        self, claim_id: str, basis: str, now: Optional[datetime] = None
    ) -> SourceClaim:
        """Withdraw a claim without deleting it, then re-resolve the field."""
        if not basis or not basis.strip():
            raise ConflictError("withdrawal basis is required")
        with self._lock:
            claim = self._claims.get(claim_id)
            if claim is None:
                raise ConflictError(f"unknown claim_id {claim_id!r}")
            updated = SourceClaim(
                **{
                    **claim.model_dump(),
                    "withdrawn": True,
                    "provenance": f"{claim.provenance or ''}|withdrawn:{basis.strip()}".strip("|"),
                }
            )
            self._claims[claim_id] = updated
            self._resolve_field((claim.entity_id, claim.field_name), now=now)
            return updated

    def claims_for(
        self, entity_id: str, field_name: Optional[str] = None, include_withdrawn: bool = True
    ) -> List[SourceClaim]:
        with self._lock:
            if field_name is None:
                items = [c for c in self._claims.values() if c.entity_id == entity_id.strip()]
            else:
                ids = self._claims_by_field.get((entity_id.strip(), field_name.strip()), [])
                items = [self._claims[c] for c in ids]
        if not include_withdrawn:
            items = [c for c in items if not c.withdrawn]
        return sorted(items, key=lambda c: (c.recorded_at, c.claim_id))

    # --------------------------------------------------------------- resolution

    def _live_claims(self, key: Tuple[str, str]) -> List[SourceClaim]:
        ids = self._claims_by_field.get(key, [])
        return [self._claims[c] for c in ids if not self._claims[c].withdrawn]

    def _resolve_field(
        self,
        key: Tuple[str, str],
        strategy: Optional[ResolutionStrategy] = None,
        now: Optional[datetime] = None,
        actor: Optional[str] = None,
        forced_claim_id: Optional[str] = None,
    ) -> ResolvedValue:
        """
        Recompute the normalized value for a field from its live claims.

        Appends or updates a `ConflictResolutionRecord` whenever more than one distinct value is present,
        and supersedes the prior conflict record rather than editing it.
        """
        moment = now or datetime.utcnow()
        entity_id, field_name = key
        live = self._live_claims(key)
        use_strategy = strategy or self._strategy_for(key)

        # Validate a forced claim before anything else. Doing it later would let the
        # "no live claims" early-return below swallow an invalid manual selection.
        if forced_claim_id is not None:
            forced_claim = self._claims.get(forced_claim_id)
            if (
                forced_claim is None
                or forced_claim.withdrawn
                or (forced_claim.entity_id, forced_claim.field_name) != key
            ):
                raise ConflictError(
                    f"forced claim {forced_claim_id!r} is not a live claim for {entity_id}.{field_name}"
                )

        prior_conflict_ids = self._conflicts_by_field.get(key, [])
        # Same definition as `_open_or_create_conflict`: UNRESOLVABLE is still an open
        # disagreement, so it must be closable once the claims stop disagreeing.
        open_conflicts = [
            self._conflicts[c]
            for c in prior_conflict_ids
            if self._conflicts[c].state in (ConflictState.OPEN, ConflictState.UNRESOLVABLE)
        ]

        if not live:
            resolved = ResolvedValue(
                entity_id=entity_id,
                field_name=field_name,
                value=None,
                winning_claim_id=None,
                winning_source_id=None,
                strategy=ResolutionStrategy.UNRESOLVED,
                resolution_basis="no live claims: all claims withdrawn or none recorded",
                considered_claim_ids=[],
                rejected_claim_ids=[],
                dissenting_sources=[],
                confidence=0.0,
                conflict_id=open_conflicts[-1].conflict_id if open_conflicts else None,
                resolved_at=moment,
                resolved_by=actor,
                tenant_id=self.tenant_id,
                experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY,
            )
            self._resolved[key] = resolved
            for conflict in open_conflicts:
                self._close_conflict(conflict, moment, actor, note="all claims withdrawn")
            return resolved

        distinct_values = {c.value_key for c in live}

        if len(distinct_values) == 1 and forced_claim_id is None:
            # Agreement. No conflict record is created; existing open ones are closed.
            winner = self._rank(live, use_strategy, moment)[0]
            resolved = ResolvedValue(
                entity_id=entity_id,
                field_name=field_name,
                value=winner.value,
                winning_claim_id=winner.claim_id,
                winning_source_id=winner.source_id,
                strategy=use_strategy,
                resolution_basis=(
                    f"all {len(live)} live claim(s) agree on one value; "
                    f"winner {winner.claim_id} from {winner.source_id} "
                    f"(effective_weight={winner.effective_weight():.4f})"
                ),
                considered_claim_ids=[c.claim_id for c in live],
                rejected_claim_ids=[],
                dissenting_sources=[],
                confidence=max(c.confidence for c in live),
                conflict_id=None,
                resolved_at=moment,
                resolved_by=actor,
                tenant_id=self.tenant_id,
                experimental_label=(
                    None if all(c.origin is ClaimOrigin.AUTHORITATIVE for c in live)
                    else EXPERIMENTAL_DEMO_DATA_ONLY
                ),
            )
            self._resolved[key] = resolved
            for conflict in open_conflicts:
                self._close_conflict(conflict, moment, actor, note="claims now agree")
            return resolved

        # Genuine disagreement: record (or reuse) a conflict, then resolve or leave open.
        conflict = self._open_or_create_conflict(key, live, moment)

        if forced_claim_id is not None:
            winner = self._claims[forced_claim_id]
            basis = f"manual selection of {winner.claim_id} by {actor or 'unattributed'}"
            use_strategy = ResolutionStrategy.MANUAL
        else:
            ranked = self._rank(live, use_strategy, moment)
            winner = ranked[0]
            runner_up = ranked[1] if len(ranked) > 1 else None
            if (
                runner_up is not None
                and winner.value_key != runner_up.value_key
                and self._substantive_key(winner, use_strategy)
                == self._substantive_key(runner_up, use_strategy)
            ):
                # Exact tie on every tie-break: refuse to guess.
                resolved = ResolvedValue(
                    entity_id=entity_id,
                    field_name=field_name,
                    value=None,
                    winning_claim_id=None,
                    winning_source_id=None,
                    strategy=ResolutionStrategy.UNRESOLVED,
                    resolution_basis=(
                        f"{len(distinct_values)} distinct values tie on every tie-break rule; "
                        "left unresolved rather than choosing arbitrarily"
                    ),
                    considered_claim_ids=[c.claim_id for c in live],
                    rejected_claim_ids=[],
                    dissenting_sources=sorted({c.source_id for c in live}),
                    confidence=0.0,
                    conflict_id=conflict.conflict_id,
                    resolved_at=moment,
                    resolved_by=actor,
                    tenant_id=self.tenant_id,
                    experimental_label=EXPERIMENTAL_DEMO_DATA_ONLY,
                )
                self._resolved[key] = resolved
                conflict.state = ConflictState.UNRESOLVABLE
                conflict.resolution_basis = resolved.resolution_basis
                return resolved
            basis = self._explain(winner, live, use_strategy, moment)

        rejected = [c.claim_id for c in live if c.claim_id != winner.claim_id]
        dissenting = sorted(
            {
                c.source_id
                for c in live
                if c.claim_id != winner.claim_id and c.value_key != winner.value_key
            }
        )

        resolved = ResolvedValue(
            entity_id=entity_id,
            field_name=field_name,
            value=winner.value,
            winning_claim_id=winner.claim_id,
            winning_source_id=winner.source_id,
            strategy=use_strategy,
            resolution_basis=basis,
            considered_claim_ids=[c.claim_id for c in live],
            rejected_claim_ids=rejected,
            dissenting_sources=dissenting,
            confidence=winner.confidence,
            conflict_id=conflict.conflict_id,
            resolved_at=moment,
            resolved_by=actor,
            tenant_id=self.tenant_id,
            experimental_label=(
                None if winner.origin is ClaimOrigin.AUTHORITATIVE else EXPERIMENTAL_DEMO_DATA_ONLY
            ),
        )
        self._resolved[key] = resolved

        conflict.state = ConflictState.RESOLVED
        conflict.strategy = use_strategy
        conflict.resolution_basis = basis
        conflict.winning_claim_id = winner.claim_id
        conflict.resolved_at = moment
        conflict.resolved_by = actor
        return resolved

    def _strategy_for(self, key: Tuple[str, str]) -> ResolutionStrategy:
        resolved = self._resolved.get(key)
        if resolved is not None and resolved.strategy is not ResolutionStrategy.UNRESOLVED:
            return resolved.strategy
        return ResolutionStrategy.HIGHEST_CONFIDENCE_THEN_NEWEST

    @staticmethod
    def _substantive_key(claim: SourceClaim, strategy: ResolutionStrategy) -> Tuple[Any, ...]:
        """
        The evidential part of the sort key: everything a tie-break rule actually reasons about.

        `claim_id` is deliberately absent. Including it would make every pair of claims
        distinguishable and so make a genuine tie undetectable - the "refuse to guess" branch
        would become dead code and an arbitrary claim would silently win.
        """
        weight = claim.effective_weight()
        # timestamp() normalises naive/aware datetimes to a comparable float.
        observed_ts = -(claim.observed_at.timestamp())
        origin_rank = _ORIGIN_PRIORITY.get(claim.origin, 9)
        if strategy is ResolutionStrategy.NEWEST_THEN_HIGHEST_CONFIDENCE:
            return (observed_ts, -weight, origin_rank)
        if strategy is ResolutionStrategy.SOURCE_PRIORITY_THEN_CONFIDENCE:
            return (origin_rank, -weight, observed_ts)
        # HIGHEST_CONFIDENCE_THEN_NEWEST, MANUAL and MAJORITY_THEN_CONFIDENCE share this order;
        # majority count is prepended by `_rank` before this key is consulted.
        return (-weight, observed_ts, origin_rank)

    @classmethod
    def _rank_key(cls, claim: SourceClaim, strategy: ResolutionStrategy) -> Tuple[Any, ...]:
        """Full deterministic sort key: evidential key plus claim_id so ordering is total."""
        return cls._substantive_key(claim, strategy) + (claim.claim_id,)

    def _rank(
        self, claims: Sequence[SourceClaim], strategy: ResolutionStrategy, moment: datetime
    ) -> List[SourceClaim]:
        if strategy is ResolutionStrategy.MAJORITY_THEN_CONFIDENCE:
            counts: Dict[str, int] = {}
            for c in claims:
                counts[c.value_key] = counts.get(c.value_key, 0) + 1
            return sorted(
                claims,
                key=lambda c: ((-counts[c.value_key],) + self._rank_key(c, strategy)),
            )
        return sorted(claims, key=lambda c: self._rank_key(c, strategy))

    @staticmethod
    def _explain(
        winner: SourceClaim,
        live: Sequence[SourceClaim],
        strategy: ResolutionStrategy,
        moment: datetime,
    ) -> str:
        distinct = {c.value_key for c in live}
        return (
            f"strategy={strategy.value}; {len(distinct)} distinct value(s) from "
            f"{len({c.source_id for c in live})} source(s); winner={winner.claim_id} "
            f"source={winner.source_id} origin={winner.origin.value} "
            f"confidence={winner.confidence:.4f} "
            f"effective_weight={winner.effective_weight():.4f} "
            f"observed_at={winner.observed_at.isoformat()}"
        )

    def _open_or_create_conflict(
        self, key: Tuple[str, str], live: Sequence[SourceClaim], moment: datetime
    ) -> ConflictResolutionRecord:
        entity_id, field_name = key
        existing_ids = self._conflicts_by_field.get(key, [])
        # An UNRESOLVABLE conflict is still an open disagreement - it just has no winner yet.
        # Reusing it keeps one audit record per ongoing disagreement instead of spawning a new
        # record every time another source weighs in.
        open_conflicts = [
            self._conflicts[c]
            for c in existing_ids
            if self._conflicts[c].state in (ConflictState.OPEN, ConflictState.UNRESOLVABLE)
        ]
        distinct = {c.value_key for c in live}
        sources = sorted({c.source_id for c in live})

        if open_conflicts:
            conflict = open_conflicts[-1]
            conflict.claim_ids = [c.claim_id for c in live]
            conflict.distinct_values = len(distinct)
            conflict.sources = sources
            return conflict

        self._conflict_counter += 1
        conflict = ConflictResolutionRecord(
            conflict_id=f"CFL-{self._conflict_counter:08d}",
            entity_id=entity_id,
            field_name=field_name,
            state=ConflictState.OPEN,
            claim_ids=[c.claim_id for c in live],
            distinct_values=len(distinct),
            sources=sources,
            detected_at=moment,
            tenant_id=self.tenant_id,
        )
        self._conflicts[conflict.conflict_id] = conflict
        self._conflicts_by_field.setdefault(key, []).append(conflict.conflict_id)
        return conflict

    def _close_conflict(
        self, conflict: ConflictResolutionRecord, moment: datetime, actor: Optional[str], note: str
    ) -> None:
        conflict.state = ConflictState.RESOLVED
        conflict.resolved_at = moment
        conflict.resolved_by = actor
        conflict.resolution_basis = note

    # --------------------------------------------------------------- public API

    def resolved_value(self, entity_id: str, field_name: str) -> Optional[ResolvedValue]:
        with self._lock:
            return self._resolved.get((entity_id.strip(), field_name.strip()))

    def resolved_entity(self, entity_id: str) -> Dict[str, Any]:
        """The normalized view of an entity: field -> resolved value."""
        with self._lock:
            items = [
                r for (eid, _), r in self._resolved.items() if eid == entity_id.strip()
            ]
        return {r.field_name: r.value for r in items}

    def resolve_manually(
        self,
        entity_id: str,
        field_name: str,
        claim_id: str,
        basis: str,
        actor: str,
        now: Optional[datetime] = None,
    ) -> ResolvedValue:
        """
        Manually promote a specific claim. Requires an attributable actor and a stated basis.

        Supersedes any open conflict rather than editing it, so the earlier automated outcome
        stays in the audit trail.
        """
        if not basis or not basis.strip():
            raise ConflictError("manual resolution requires a stated basis")
        if not actor or not actor.strip():
            raise ConflictError("manual resolution requires an attributable actor")
        key = (entity_id.strip(), field_name.strip())
        moment = now or datetime.utcnow()
        with self._lock:
            for cid in self._conflicts_by_field.get(key, []):
                conflict = self._conflicts[cid]
                # A manual decision overrides the automated outcome whether that outcome was a
                # resolved promotion or an unresolvable tie, so both are marked superseded.
                if conflict.state in (
                    ConflictState.OPEN,
                    ConflictState.RESOLVED,
                    ConflictState.UNRESOLVABLE,
                ):
                    conflict.state = ConflictState.SUPERSEDED
                    conflict.superseded_by = claim_id
                    conflict.resolved_at = moment
                    conflict.resolved_by = actor.strip()
                    conflict.resolution_basis = f"superseded by manual resolution: {basis.strip()}"
            return self._resolve_field(
                key,
                strategy=ResolutionStrategy.MANUAL,
                now=moment,
                actor=actor.strip(),
                forced_claim_id=claim_id,
            )

    def re_resolve(
        self,
        entity_id: str,
        field_name: str,
        strategy: ResolutionStrategy,
        now: Optional[datetime] = None,
    ) -> ResolvedValue:
        """Re-run resolution under a different named strategy."""
        key = (entity_id.strip(), field_name.strip())
        with self._lock:
            if key not in self._claims_by_field:
                raise ConflictError(f"no claims recorded for {entity_id}.{field_name}")
            for cid in self._conflicts_by_field.get(key, []):
                conflict = self._conflicts[cid]
                if conflict.state in (ConflictState.OPEN, ConflictState.UNRESOLVABLE):
                    conflict.state = ConflictState.SUPERSEDED
                    conflict.resolution_basis = f"superseded by re-resolution under {strategy.value}"
            return self._resolve_field(key, strategy=strategy, now=now)

    def conflicts(
        self,
        entity_id: Optional[str] = None,
        state: Optional[ConflictState] = None,
    ) -> List[ConflictResolutionRecord]:
        with self._lock:
            items = list(self._conflicts.values())
        if entity_id is not None:
            items = [c for c in items if c.entity_id == entity_id.strip()]
        if state is not None:
            items = [c for c in items if c.state is state]
        return sorted(items, key=lambda c: (c.detected_at, c.conflict_id))

    def open_conflicts(self) -> List[ConflictResolutionRecord]:
        return [
            c
            for c in self.conflicts()
            if c.state in (ConflictState.OPEN, ConflictState.UNRESOLVABLE)
        ]

    def get_conflict(self, conflict_id: str) -> Optional[ConflictResolutionRecord]:
        with self._lock:
            return self._conflicts.get(conflict_id)

    def history_for(self, entity_id: str, field_name: str) -> List[SourceClaim]:
        """Full append-only claim history for a field, including withdrawn and rejected claims."""
        return self.claims_for(entity_id, field_name, include_withdrawn=True)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            claims = list(self._claims.values())
            conflicts = list(self._conflicts.values())
            resolved = list(self._resolved.values())
            by_origin: Dict[str, int] = {}
            for c in claims:
                by_origin[c.origin.value] = by_origin.get(c.origin.value, 0) + 1
            by_state: Dict[str, int] = {}
            for c in conflicts:
                by_state[c.state.value] = by_state.get(c.state.value, 0) + 1
            return {
                "tenant_id": self.tenant_id,
                "claim_count": len(claims),
                "withdrawn_claim_count": sum(1 for c in claims if c.withdrawn),
                "distinct_sources": len({c.source_id for c in claims}),
                "fields_tracked": len(self._resolved),
                "resolved_count": len(resolved),
                "unresolved_count": sum(
                    1 for r in resolved if r.strategy is ResolutionStrategy.UNRESOLVED
                ),
                "conflict_count": len(conflicts),
                "open_conflict_count": sum(
                    1
                    for c in conflicts
                    if c.state in (ConflictState.OPEN, ConflictState.UNRESOLVABLE)
                ),
                "claims_by_origin": by_origin,
                "conflicts_by_state": by_state,
                "note": "in-memory conflict store; no conflict storage is mounted",
            }
