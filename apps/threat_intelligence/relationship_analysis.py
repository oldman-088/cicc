"""
Threat Intelligence Relationship Analysis — Domain B / Master Prompt relationship foundation.
Branch: arena/28e50255-cicc (Agent 6 - Full Threat Intelligence Backup Engineer)

This module is an ANALYSIS layer over the existing relationship storage in
`relationships.py`. It deliberately does not define a second relationship schema:
`RelationshipModel` and `RELATIONSHIP_TYPES` are reused as the authoritative record type.

What this layer adds:
- Typed relationship semantics: directionality, symmetry, exclusivity and cardinality per type
- Direction and relationship provenance (who asserted it, from where, with what evidence)
- Confidence and evidence carried on every assertion
- Temporal validity (`valid_from` / `valid_until`) evaluated against an explicit clock
- Duplicate detection and contradictory-assertion handling that preserves both sides
- Cycle-safe traversal with depth and fan-out bounds
- Analysis services: neighbours, shortest path, subgraph extraction, contradiction review

HONESTY CONSTRAINT:
An inferred relationship is never silently promoted to a confirmed one. Inference status is
carried through every derived structure, and aggregation refuses to report a path built from
inferred edges as a confirmed chain.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator

from apps.threat_intelligence.relationships import (
    RELATIONSHIP_TYPES,
    EXPERIMENTAL_DEMO_DATA_ONLY,
    RelationshipModel,
    RelationshipService,
)

MAX_TRAVERSAL_DEPTH = 10
DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_NODES = 500
MAX_EVIDENCE_ITEMS = 200


class RelationshipError(ValueError):
    """Raised when a relationship assertion or analysis request is invalid."""


class Direction(str, Enum):
    """Whether a relationship type is directional."""

    DIRECTED = "directed"
    SYMMETRIC = "symmetric"


class AssertionOrigin(str, Enum):
    """How the assertion came into being. Never conflated with confidence."""

    DIRECTLY_SOURCED = "directly_sourced"
    ANALYST_INFERRED = "analyst_inferred"
    MACHINE_INFERRED = "machine_inferred"
    IMPORTED_UNVERIFIED = "imported_unverified"


class AssertionStatus(str, Enum):
    """Lifecycle of an individual assertion (not of the normalized relationship)."""

    ACTIVE = "active"
    SUPERSEDED = "superseded"
    EXPIRED = "expired"
    DISPUTED = "disputed"
    WITHDRAWN = "withdrawn"


class EvidenceItem(BaseModel):
    """A single piece of supporting evidence for an assertion."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(..., min_length=1, max_length=256)
    kind: str = Field("note", max_length=32, description="note | url | file | observation | source_document")
    source_ref: Optional[str] = Field(None, max_length=512)
    retrieved_at: Optional[datetime] = Field(None)
    description: Optional[str] = Field(None, max_length=2000)

    @field_validator("kind")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.strip().lower()


# --------------------------------------------------------------------------
# Typed relationship semantics
# --------------------------------------------------------------------------

class RelationshipSemantics(BaseModel):
    """
    Static semantic properties of a relationship type.

    `symmetric`: if True, `A rel B` and `B rel A` are the same assertion.
    `inverse`: the type that means the reverse direction (e.g. CONTAINS / BELONGS_TO).
    `exclusive_with`: types that cannot simultaneously hold between the same ordered pair.
    `transitive`: if True, `A rel B` and `B rel C` imply `A rel C` (never auto-asserted,
    only surfaced as a candidate for analyst review).
    """

    model_config = ConfigDict(extra="forbid")

    relationship_type: str
    direction: Direction = Direction.DIRECTED
    symmetric: bool = False
    inverse: Optional[str] = None
    exclusive_with: Tuple[str, ...] = ()
    transitive: bool = False
    description: str = ""


_SYMMETRIC_TYPES = ("ASSOCIATED_WITH", "RELATED_TO", "CORROBORATES")

_INVERSE_PAIRS = (
    ("CONTAINS", "BELONGS_TO"),
    ("DERIVED_FROM", "CORROBORATES"),
)

# Declared as unordered pairs, then expanded in both directions.
#
# A one-directional mapping here is a real defect: {"ATTRIBUTED_TO": ("TARGETS",)} would flag
# ATTRIBUTED_TO-then-TARGETS as a contradiction but silently accept TARGETS-then-ATTRIBUTED_TO.
# Contradiction detection must not depend on the order assertions arrive in.
_EXCLUSIVE_PAIRS = (
    ("ATTRIBUTED_TO", "TARGETS"),
    ("ATTRIBUTED_TO", "EXPLOITS"),
    ("ATTRIBUTED_TO", "AFFECTS"),
    ("EXPLOITS", "AFFECTS"),
    ("CONTRADICTS", "CORROBORATES"),
)


def _build_exclusivity() -> Dict[str, Tuple[str, ...]]:
    table: Dict[str, List[str]] = {}
    for left, right in _EXCLUSIVE_PAIRS:
        table.setdefault(left, [])
        table.setdefault(right, [])
        if right not in table[left]:
            table[left].append(right)
        if left not in table[right]:
            table[right].append(left)
    return {key: tuple(sorted(values)) for key, values in table.items()}


_EXCLUSIVITY: Dict[str, Tuple[str, ...]] = _build_exclusivity()

_TRANSITIVE_TYPES = ("DEPENDS_ON", "BELONGS_TO", "ASSOCIATED_WITH", "RELATED_TO")


def build_default_semantics() -> Dict[str, RelationshipSemantics]:
    """
    Derive semantics for every type already declared in `RELATIONSHIP_TYPES`.

    Semantics are derived from the existing type registry rather than inventing new types, so
    adding a type upstream automatically yields an entry here.
    """
    semantics: Dict[str, RelationshipSemantics] = {}
    symmetric = set(_SYMMETRIC_TYPES)
    inverse_of: Dict[str, str] = {}
    for a, b in _INVERSE_PAIRS:
        inverse_of[a] = b
        inverse_of[b] = a

    for rel_type, description in RELATIONSHIP_TYPES.items():
        is_sym = rel_type in symmetric
        semantics[rel_type] = RelationshipSemantics(
            relationship_type=rel_type,
            direction=Direction.SYMMETRIC if is_sym else Direction.DIRECTED,
            symmetric=is_sym,
            inverse=inverse_of.get(rel_type),
            exclusive_with=_EXCLUSIVITY.get(rel_type, ()),
            transitive=rel_type in _TRANSITIVE_TYPES,
            description=description,
        )
    return semantics


DEFAULT_SEMANTICS: Dict[str, RelationshipSemantics] = build_default_semantics()


# --------------------------------------------------------------------------
# Assertions
# --------------------------------------------------------------------------

class RelationshipAssertion(BaseModel):
    """
    One source's claim about one relationship.

    The normalized `RelationshipModel` in `RelationshipService` is the conclusion; this is the
    claim. Keeping the two separate is what makes conflict handling possible: disagreeing
    sources each keep their assertion, and the normalized record records the resolution basis.
    """

    model_config = ConfigDict(extra="forbid")

    assertion_id: str = Field(..., min_length=1, max_length=256)
    source_entity_id: str = Field(..., min_length=1, max_length=512)
    source_entity_type: str = Field(..., min_length=1, max_length=64)
    target_entity_id: str = Field(..., min_length=1, max_length=512)
    target_entity_type: str = Field(..., min_length=1, max_length=64)
    relationship_type: str = Field(..., min_length=1, max_length=64)
    asserted_by: str = Field(..., min_length=1, max_length=256, description="Source that made this claim")
    origin: AssertionOrigin = AssertionOrigin.DIRECTLY_SOURCED
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    provenance: Optional[str] = Field(None, max_length=512)
    valid_from: Optional[datetime] = Field(None)
    valid_until: Optional[datetime] = Field(None)
    asserted_at: datetime = Field(default_factory=datetime.utcnow)
    status: AssertionStatus = AssertionStatus.ACTIVE
    relationship_id: Optional[str] = Field(
        None, max_length=256, description="Normalized relationship record this assertion feeds"
    )
    tenant_id: Optional[str] = Field(None, max_length=256)

    @field_validator("relationship_type")
    @classmethod
    def _upper_type(cls, v: str) -> str:
        return v.strip().upper()

    @field_validator("evidence")
    @classmethod
    def _cap_evidence(cls, v: List[EvidenceItem]) -> List[EvidenceItem]:
        if len(v) > MAX_EVIDENCE_ITEMS:
            raise RelationshipError(f"too many evidence items (>{MAX_EVIDENCE_ITEMS})")
        return v

    @property
    def is_inferred(self) -> bool:
        """True when this assertion is an inference rather than a direct observation."""
        return self.origin in (AssertionOrigin.ANALYST_INFERRED, AssertionOrigin.MACHINE_INFERRED)

    @property
    def is_verified_origin(self) -> bool:
        return self.origin is AssertionOrigin.DIRECTLY_SOURCED

    def ordered_pair(self) -> Tuple[str, str]:
        """The pair as asserted, preserving direction."""
        return (self.source_entity_id, self.target_entity_id)

    def unordered_pair(self) -> Tuple[str, str]:
        """The pair ignoring direction - used for symmetric types and duplicate detection."""
        return tuple(sorted((self.source_entity_id, self.target_entity_id)))  # type: ignore[return-value]

    def is_valid_at(self, moment: Optional[datetime] = None) -> bool:
        """
        Temporal validity.

        An assertion with no declared window is treated as valid (absence of a bound is not a
        claim of expiry). A future-dated `valid_from` makes it not-yet-valid rather than valid.
        """
        when = moment or datetime.utcnow()
        if self.valid_from is not None and when < self.valid_from:
            return False
        if self.valid_until is not None and when > self.valid_until:
            return False
        return True


class ContradictionRecord(BaseModel):
    """
    A recorded disagreement between assertions. Both sides are preserved; nothing is overwritten.
    """

    model_config = ConfigDict(extra="forbid")

    contradiction_id: str = Field(..., min_length=1, max_length=256)
    kind: str = Field(
        ..., max_length=64,
        description="direction_reversed | mutually_exclusive_types | explicit_contradiction | confidence_dispute",
    )
    assertion_ids: List[str] = Field(default_factory=list)
    source_entity_id: str = Field(..., min_length=1, max_length=512)
    target_entity_id: str = Field(..., min_length=1, max_length=512)
    detail: str = Field(..., max_length=2000)
    resolved: bool = False
    resolution_basis: Optional[str] = Field(None, max_length=2000)
    resolved_by: Optional[str] = Field(None, max_length=256)
    resolved_at: Optional[datetime] = None
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    tenant_id: Optional[str] = Field(None, max_length=256)


class DuplicateGroup(BaseModel):
    """Multiple sources asserting the same relationship."""

    model_config = ConfigDict(extra="forbid")

    group_key: str
    relationship_type: str
    assertion_ids: List[str] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)
    agreeing: bool = True


# --------------------------------------------------------------------------
# Analysis results
# --------------------------------------------------------------------------

class TraversalResult(BaseModel):
    """Bounded, cycle-safe traversal output."""

    model_config = ConfigDict(extra="forbid")

    root: str
    depth_reached: int = 0
    nodes_visited: int = 0
    edges_traversed: int = 0
    nodes: List[str] = Field(default_factory=list)
    edges: List[Dict[str, Any]] = Field(default_factory=list)
    cycles_detected: int = 0
    truncated: bool = False
    truncation_reason: Optional[str] = None
    contains_inferred_edges: bool = False
    all_edges_verified_origin: bool = True


class PathResult(BaseModel):
    """A path between two entities, with an honest provenance statement."""

    model_config = ConfigDict(extra="forbid")

    source: str
    target: str
    found: bool = False
    hops: int = 0
    path: List[str] = Field(default_factory=list)
    edges: List[Dict[str, Any]] = Field(default_factory=list)
    min_confidence: float = 1.0
    contains_inferred_edges: bool = False
    all_edges_verified_origin: bool = True
    search_limit_reached: bool = False

    @property
    def reliability_statement(self) -> str:
        """
        A human-readable honesty statement. An inferred path is never described as confirmed.
        """
        if not self.found:
            return "no_path_found"
        if self.contains_inferred_edges:
            # Whether one hop or every hop is inferred, the chain is not a confirmed fact.
            return "path_rests_partly_on_inferred_edges_not_confirmed"
        if not self.all_edges_verified_origin:
            return "path_uses_only_unverified_imported_edges_not_confirmed"
        return "path_uses_only_directly_sourced_edges"


class ContradictionSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total: int = 0
    unresolved: int = 0
    by_kind: Dict[str, int] = Field(default_factory=dict)


# --------------------------------------------------------------------------
# Service
# --------------------------------------------------------------------------

class RelationshipAnalysisService:
    """
    Assertion-level analysis over the existing relationship store.

    All state is in-memory. No network, no threads, no event loop. The clock is injected
    everywhere it matters so temporal behaviour is deterministic under test.
    """

    def __init__(
        self,
        tenant_id: str = "default",
        relationship_service: Optional[RelationshipService] = None,
        semantics: Optional[Dict[str, RelationshipSemantics]] = None,
    ):
        if not tenant_id or not tenant_id.strip():
            raise RelationshipError("tenant_id is required")
        self.tenant_id = tenant_id.strip()
        self.relationship_service = relationship_service or RelationshipService()
        self._semantics: Dict[str, RelationshipSemantics] = dict(semantics or DEFAULT_SEMANTICS)
        self._assertions: Dict[str, RelationshipAssertion] = {}
        self._contradictions: Dict[str, ContradictionRecord] = {}
        self._by_unordered_pair: Dict[Tuple[str, str], List[str]] = {}
        self._adjacency: Dict[str, Set[str]] = {}

    # ------------------------------------------------------------- semantics

    def semantics_for(self, relationship_type: str) -> RelationshipSemantics:
        key = relationship_type.strip().upper()
        semantics = self._semantics.get(key)
        if semantics is None:
            raise RelationshipError(
                f"unknown relationship_type {relationship_type!r}; must be one of "
                f"{sorted(RELATIONSHIP_TYPES)}"
            )
        return semantics

    def register_semantics(self, semantics: RelationshipSemantics) -> None:
        """Allow a host to extend semantics without forking this module."""
        if semantics.relationship_type not in RELATIONSHIP_TYPES:
            raise RelationshipError(
                f"cannot register semantics for unknown type {semantics.relationship_type!r}"
            )
        self._semantics[semantics.relationship_type.upper()] = semantics

    # ------------------------------------------------------------- assertions

    def assert_relationship(
        self,
        source_entity_id: str,
        target_entity_id: str,
        relationship_type: str,
        asserted_by: str,
        source_entity_type: str = "unknown",
        target_entity_type: str = "unknown",
        origin: AssertionOrigin = AssertionOrigin.DIRECTLY_SOURCED,
        confidence: float = 0.0,
        evidence: Optional[List[EvidenceItem]] = None,
        provenance: Optional[str] = None,
        valid_from: Optional[datetime] = None,
        valid_until: Optional[datetime] = None,
        assertion_id: Optional[str] = None,
        now: Optional[datetime] = None,
        normalize: bool = True,
    ) -> RelationshipAssertion:
        """
        Record one source's claim. Detects duplicates and contradictions, recording rather than
        discarding either.

        `normalize=True` writes the normalized `RelationshipModel` into the underlying
        `RelationshipService` so existing traversal and lookups keep working. A repeated
        assertion from a new source does not create a second normalized record.
        """
        moment = now or datetime.utcnow()

        if not source_entity_id or not source_entity_id.strip():
            raise RelationshipError("source_entity_id is required")
        if not target_entity_id or not target_entity_id.strip():
            raise RelationshipError("target_entity_id is required")
        if source_entity_id.strip() == target_entity_id.strip():
            raise RelationshipError(
                f"self-relationship on {source_entity_id!r} is malformed: "
                "an entity cannot relate to itself"
            )
        if not asserted_by or not asserted_by.strip():
            raise RelationshipError("asserted_by is required: assertions must be attributable")

        if evidence is not None and len(evidence) > MAX_EVIDENCE_ITEMS:
            raise RelationshipError(f"too many evidence items (>{MAX_EVIDENCE_ITEMS})")

        semantics = self.semantics_for(relationship_type)
        rel_type = semantics.relationship_type

        assertion = RelationshipAssertion(
            assertion_id=assertion_id or f"RA-{len(self._assertions) + 1}-{abs(hash((source_entity_id, target_entity_id, rel_type, asserted_by))) % 10**8:08d}",
            source_entity_id=source_entity_id.strip(),
            source_entity_type=source_entity_type.strip().lower() or "unknown",
            target_entity_id=target_entity_id.strip(),
            target_entity_type=target_entity_type.strip().lower() or "unknown",
            relationship_type=rel_type,
            asserted_by=asserted_by.strip(),
            origin=origin,
            confidence=confidence,
            evidence=list(evidence or []),
            provenance=provenance,
            valid_from=valid_from,
            valid_until=valid_until,
            asserted_at=moment,
            status=AssertionStatus.ACTIVE,
            tenant_id=self.tenant_id,
        )
        if assertion.assertion_id in self._assertions:
            raise RelationshipError(f"assertion_id {assertion.assertion_id!r} already exists")

        self._assertions[assertion.assertion_id] = assertion
        pair = assertion.unordered_pair()
        self._by_unordered_pair.setdefault(pair, []).append(assertion.assertion_id)
        self._adjacency.setdefault(assertion.source_entity_id, set()).add(assertion.target_entity_id)
        self._adjacency.setdefault(assertion.target_entity_id, set()).add(assertion.source_entity_id)

        self._detect_contradictions(assertion, semantics, now=moment)

        if normalize:
            self._normalize(assertion, now=moment)
        return assertion

    def _normalize(self, assertion: RelationshipAssertion, now: Optional[datetime] = None) -> None:
        """
        Write or update the normalized relationship record.

        Repeated assertions from different sources do not create duplicate normalized records:
        the first creates it, later ones raise its confidence toward the best available and
        append provenance, so corroboration strengthens without duplicating.
        """
        moment = now or datetime.utcnow()
        existing = self._find_normalized(assertion)
        if existing is None:
            created = self.relationship_service.create_relationship(
                {
                    "source_entity_id": assertion.source_entity_id,
                    "source_entity_type": assertion.source_entity_type,
                    "target_entity_id": assertion.target_entity_id,
                    "target_entity_type": assertion.target_entity_type,
                    "relationship_type": assertion.relationship_type,
                    "confidence": assertion.confidence,
                    "source": assertion.asserted_by,
                    "provenance": assertion.provenance or assertion.origin.value,
                    "evidence": assertion.evidence[0].description if assertion.evidence else None,
                    "valid_until": assertion.valid_until,
                    "experimental_label": (
                        None if assertion.is_verified_origin else EXPERIMENTAL_DEMO_DATA_ONLY
                    ),
                }
            )
            assertion.relationship_id = created.id
            return

        updates: Dict[str, Any] = {}
        if assertion.confidence > existing.confidence:
            updates["confidence"] = assertion.confidence
        if assertion.valid_until is not None and (
            existing.valid_until is None or assertion.valid_until > existing.valid_until
        ):
            updates["valid_until"] = assertion.valid_until
        # Inference status must survive corroboration: a directly-sourced assertion upgrades the
        # provenance, but an inferred one never launders an inferred record.
        if assertion.is_verified_origin and existing.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY:
            updates["experimental_label"] = None
        if updates:
            self.relationship_service.update_relationship(existing.id, updates)
        assertion.relationship_id = existing.id

    def _find_normalized(self, assertion: RelationshipAssertion) -> Optional[RelationshipModel]:
        semantics = self._semantics[assertion.relationship_type]
        candidates = self.relationship_service.find_by_type(assertion.relationship_type)
        for rel in candidates:
            direct = (
                rel.source_entity_id == assertion.source_entity_id
                and rel.target_entity_id == assertion.target_entity_id
            )
            reversed_ = (
                semantics.symmetric
                and rel.source_entity_id == assertion.target_entity_id
                and rel.target_entity_id == assertion.source_entity_id
            )
            if direct or reversed_:
                return rel
        return None

    # --------------------------------------------------------- contradiction

    def _detect_contradictions(
        self,
        assertion: RelationshipAssertion,
        semantics: RelationshipSemantics,
        now: Optional[datetime] = None,
    ) -> List[ContradictionRecord]:
        found: List[ContradictionRecord] = []
        pair = assertion.unordered_pair()
        for other_id in self._by_unordered_pair.get(pair, []):
            if other_id == assertion.assertion_id:
                continue
            other = self._assertions[other_id]
            if other.status in (AssertionStatus.WITHDRAWN, AssertionStatus.SUPERSEDED):
                continue

            other_sem = self._semantics.get(other.relationship_type)
            if other_sem is None:
                continue

            kind: Optional[str] = None
            detail = ""

            same_type = other.relationship_type == assertion.relationship_type
            if same_type and not semantics.symmetric:
                if other.ordered_pair() == tuple(reversed(assertion.ordered_pair())):
                    kind = "direction_reversed"
                    detail = (
                        f"{other.asserted_by} asserts {other.source_entity_id} "
                        f"{other.relationship_type} {other.target_entity_id} while "
                        f"{assertion.asserted_by} asserts the reverse direction for a directed type"
                    )

            if other.relationship_type in semantics.exclusive_with:
                kind = "mutually_exclusive_types"
                detail = (
                    f"{other.relationship_type} and {assertion.relationship_type} are declared "
                    f"mutually exclusive between {pair[0]!r} and {pair[1]!r}"
                )

            if (
                assertion.relationship_type == "CONTRADICTS"
                or other.relationship_type == "CONTRADICTS"
            ):
                kind = "explicit_contradiction"
                detail = (
                    f"an explicit CONTRADICTS assertion exists between {pair[0]!r} and {pair[1]!r}"
                )

            if kind is None and same_type and semantics.symmetric:
                # Symmetric agreement is corroboration, not contradiction - unless the sources
                # wildly disagree on confidence, which is worth surfacing.
                if abs(other.confidence - assertion.confidence) >= 0.5:
                    kind = "confidence_dispute"
                    detail = (
                        f"confidence differs by >= 0.5 between {other.asserted_by} "
                        f"({other.confidence:.2f}) and {assertion.asserted_by} "
                        f"({assertion.confidence:.2f})"
                    )

            if kind is not None:
                record = ContradictionRecord(
                    contradiction_id=f"CX-{len(self._contradictions) + 1:06d}",
                    kind=kind,
                    assertion_ids=sorted({other.assertion_id, assertion.assertion_id}),
                    source_entity_id=pair[0],
                    target_entity_id=pair[1],
                    detail=detail,
                    detected_at=now or datetime.utcnow(),
                    tenant_id=self.tenant_id,
                )
                self._contradictions[record.contradiction_id] = record
                other.status = AssertionStatus.DISPUTED
                assertion.status = AssertionStatus.DISPUTED
                found.append(record)
        return found

    def resolve_contradiction(
        self,
        contradiction_id: str,
        resolution_basis: str,
        resolved_by: str,
        now: Optional[datetime] = None,
    ) -> ContradictionRecord:
        """Mark a contradiction resolved with an attributable basis. Neither assertion is deleted."""
        record = self._contradictions.get(contradiction_id)
        if record is None:
            raise RelationshipError(f"unknown contradiction_id {contradiction_id!r}")
        if not resolution_basis or not resolution_basis.strip():
            raise RelationshipError("resolution_basis is required")
        if not resolved_by or not resolved_by.strip():
            raise RelationshipError("resolved_by is required: resolution must be attributable")
        record.resolved = True
        record.resolution_basis = resolution_basis.strip()
        record.resolved_by = resolved_by.strip()
        record.resolved_at = now or datetime.utcnow()
        return record

    def contradictions(
        self, kind: Optional[str] = None, unresolved_only: bool = False
    ) -> List[ContradictionRecord]:
        items = list(self._contradictions.values())
        if kind is not None:
            items = [c for c in items if c.kind == kind]
        if unresolved_only:
            items = [c for c in items if not c.resolved]
        return sorted(items, key=lambda c: (c.detected_at, c.contradiction_id))

    def contradiction_summary(self) -> ContradictionSummary:
        items = list(self._contradictions.values())
        by_kind: Dict[str, int] = {}
        for c in items:
            by_kind[c.kind] = by_kind.get(c.kind, 0) + 1
        return ContradictionSummary(
            total=len(items),
            unresolved=sum(1 for c in items if not c.resolved),
            by_kind=by_kind,
        )

    # ------------------------------------------------------------ duplicates

    def duplicate_groups(self, min_sources: int = 2) -> List[DuplicateGroup]:
        """
        Group assertions that describe the same relationship.

        For directed types the group key preserves direction; for symmetric types it does not.
        """
        groups: Dict[str, DuplicateGroup] = {}
        for assertion in self._assertions.values():
            semantics = self._semantics.get(assertion.relationship_type)
            if semantics is None:
                continue
            if semantics.symmetric:
                key = f"{assertion.relationship_type}|{'|'.join(assertion.unordered_pair())}"
            else:
                key = f"{assertion.relationship_type}|{'|'.join(assertion.ordered_pair())}"
            group = groups.setdefault(
                key,
                DuplicateGroup(
                    group_key=key, relationship_type=assertion.relationship_type, assertion_ids=[], sources=[]
                ),
            )
            group.assertion_ids.append(assertion.assertion_id)
            if assertion.asserted_by not in group.sources:
                group.sources.append(assertion.asserted_by)

        result: List[DuplicateGroup] = []
        for group in groups.values():
            distinct_sources = len(group.sources)
            if distinct_sources < min_sources:
                continue
            confidences = [self._assertions[a].confidence for a in group.assertion_ids]
            group.agreeing = bool(confidences) and (max(confidences) - min(confidences)) < 0.2
            result.append(group)
        return sorted(result, key=lambda g: g.group_key)

    def assertions_for(
        self,
        entity_id: str,
        relationship_type: Optional[str] = None,
        include_expired: bool = False,
        now: Optional[datetime] = None,
    ) -> List[RelationshipAssertion]:
        moment = now or datetime.utcnow()
        items = [
            a
            for a in self._assertions.values()
            if entity_id in (a.source_entity_id, a.target_entity_id)
        ]
        if relationship_type is not None:
            items = [a for a in items if a.relationship_type == relationship_type.strip().upper()]
        if not include_expired:
            items = [a for a in items if a.is_valid_at(moment)]
        return sorted(items, key=lambda a: (a.asserted_at, a.assertion_id))

    def get_assertion(self, assertion_id: str) -> Optional[RelationshipAssertion]:
        return self._assertions.get(assertion_id)

    def withdraw_assertion(
        self, assertion_id: str, basis: str, now: Optional[datetime] = None
    ) -> RelationshipAssertion:
        """Withdraw an assertion without deleting it. History is preserved."""
        assertion = self._assertions.get(assertion_id)
        if assertion is None:
            raise RelationshipError(f"unknown assertion_id {assertion_id!r}")
        if not basis or not basis.strip():
            raise RelationshipError("withdrawal basis is required")
        assertion.status = AssertionStatus.WITHDRAWN
        assertion.provenance = f"{assertion.provenance or ''}|withdrawn:{basis.strip()}".strip("|")
        return assertion

    def expire_out_of_window(self, now: Optional[datetime] = None) -> int:
        """Mark assertions past their `valid_until` as EXPIRED. Idempotent, never deletes."""
        moment = now or datetime.utcnow()
        count = 0
        for assertion in self._assertions.values():
            if assertion.status is AssertionStatus.ACTIVE and assertion.valid_until is not None:
                if moment > assertion.valid_until:
                    assertion.status = AssertionStatus.EXPIRED
                    count += 1
        return count

    # ------------------------------------------------------------- traversal

    def traverse(
        self,
        root: str,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_nodes: int = DEFAULT_MAX_NODES,
        include_expired: bool = False,
        now: Optional[datetime] = None,
    ) -> TraversalResult:
        """
        Bounded breadth-first traversal.

        Cycles are detected and counted rather than followed, so a cyclic graph terminates.
        Fan-out and depth are both bounded; hitting either sets `truncated` with a reason.
        """
        if not root or not root.strip():
            raise RelationshipError("traversal root is required")
        if max_depth < 0:
            raise RelationshipError("max_depth must be >= 0")
        if max_depth > MAX_TRAVERSAL_DEPTH:
            raise RelationshipError(f"max_depth exceeds hard bound {MAX_TRAVERSAL_DEPTH}")
        if max_nodes < 1:
            raise RelationshipError("max_nodes must be >= 1")

        moment = now or datetime.utcnow()
        visited: Set[str] = {root.strip()}
        order: List[str] = [root.strip()]
        queue: List[Tuple[str, int]] = [(root.strip(), 0)]
        edges: List[Dict[str, Any]] = []
        seen_edge_ids: Set[str] = set()
        cycles = 0
        truncated = False
        reason: Optional[str] = None
        depth_reached = 0

        while queue:
            current, depth = queue.pop(0)
            depth_reached = max(depth_reached, depth)
            if depth >= max_depth:
                continue

            neighbours = sorted(
                self._adjacency.get(current, ()),
                key=lambda n: n,
            )
            for neighbour in neighbours:
                if len(order) >= max_nodes:
                    truncated = True
                    reason = f"node_limit_{max_nodes}_reached"
                    queue = []
                    break

                connecting = self._edges_between(current, neighbour, include_expired, moment)
                unseen = [e for e in connecting if e["assertion_id"] not in seen_edge_ids]
                for edge in unseen:
                    seen_edge_ids.add(edge["assertion_id"])
                    edges.append(edge)

                if neighbour in visited:
                    # Only an edge we have not already walked is a real cycle. Walking back over
                    # the edge we arrived on is not one, and counting it would report a cycle for
                    # every ordinary two-node chain.
                    if unseen:
                        cycles += 1
                    continue
                if not connecting:
                    continue
                visited.add(neighbour)
                order.append(neighbour)
                queue.append((neighbour, depth + 1))

        contains_inferred, all_verified = self._provenance_of(edges)

        return TraversalResult(
            root=root.strip(),
            depth_reached=depth_reached,
            nodes_visited=len(order),
            edges_traversed=len(edges),
            nodes=order,
            edges=edges,
            cycles_detected=cycles,
            truncated=truncated,
            truncation_reason=reason,
            contains_inferred_edges=contains_inferred,
            all_edges_verified_origin=all_verified,
        )

    @staticmethod
    def _rank_edge(edge: Dict[str, Any]) -> Tuple[int, float, str]:
        """
        Rank connecting assertions so the *strongest* one represents the hop.

        Origin rank first (directly sourced beats inferred beats unverified import), then
        confidence, then assertion_id for determinism. Selecting alphabetically would let an
        inferred edge silently stand in for a directly-sourced one, or vice versa.
        """
        origin_rank = {
            AssertionOrigin.DIRECTLY_SOURCED.value: 0,
            AssertionOrigin.ANALYST_INFERRED.value: 1,
            AssertionOrigin.MACHINE_INFERRED.value: 2,
            AssertionOrigin.IMPORTED_UNVERIFIED.value: 3,
        }
        return (origin_rank.get(edge["origin"], 9), -float(edge["confidence"]), edge["assertion_id"])

    def _best_edge(self, connecting: Sequence[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """The strongest assertion connecting two entities, or None when there is none."""
        if not connecting:
            return None
        return sorted(connecting, key=self._rank_edge)[0]

    @staticmethod
    def _provenance_of(edges: Sequence[Dict[str, Any]]) -> Tuple[bool, bool]:
        """
        Honest provenance roll-up for a set of chosen edges.

        Returns (contains_inferred, all_verified_origin). Note that `all_verified_origin` is
        False for an empty edge set: the absence of evidence is not verified provenance.
        """
        inferred_origins = (
            AssertionOrigin.ANALYST_INFERRED.value,
            AssertionOrigin.MACHINE_INFERRED.value,
        )
        contains_inferred = any(e["origin"] in inferred_origins for e in edges)
        all_verified = bool(edges) and all(
            e["origin"] == AssertionOrigin.DIRECTLY_SOURCED.value for e in edges
        )
        return contains_inferred, all_verified

    def _edges_between(
        self, a: str, b: str, include_expired: bool, moment: datetime
    ) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for assertion in self._assertions.values():
            if assertion.status is AssertionStatus.WITHDRAWN:
                continue
            if not include_expired and assertion.status is AssertionStatus.EXPIRED:
                continue
            if not include_expired and not assertion.is_valid_at(moment):
                continue
            if {assertion.source_entity_id, assertion.target_entity_id} != {a, b}:
                continue
            out.append(
                {
                    "assertion_id": assertion.assertion_id,
                    "relationship_id": assertion.relationship_id,
                    "relationship_type": assertion.relationship_type,
                    "source": assertion.source_entity_id,
                    "target": assertion.target_entity_id,
                    "direction": "forward" if assertion.source_entity_id == a else "reverse",
                    "confidence": assertion.confidence,
                    "origin": assertion.origin.value,
                    "asserted_by": assertion.asserted_by,
                    "provenance": assertion.provenance,
                    "status": assertion.status.value,
                }
            )
        return sorted(out, key=lambda e: e["assertion_id"])

    def find_path(
        self,
        source: str,
        target: str,
        max_hops: int = DEFAULT_MAX_DEPTH,
        include_expired: bool = False,
        now: Optional[datetime] = None,
    ) -> PathResult:
        """
        Shortest path between two entities, with an explicit reliability statement.

        A path built partly from inferred edges is reported as not confirmed. The search is
        hop-bounded and node-bounded so a large graph cannot exhaust the interpreter.
        """
        if not source or not target:
            raise RelationshipError("both source and target are required")
        if max_hops < 1:
            raise RelationshipError("max_hops must be >= 1")

        moment = now or datetime.utcnow()
        source, target = source.strip(), target.strip()
        if source == target:
            return PathResult(source=source, target=target, found=True, hops=0, path=[source])

        queue: List[Tuple[str, List[str], List[Dict[str, Any]]]] = [(source, [source], [])]
        visited: Set[str] = {source}
        budget = DEFAULT_MAX_NODES
        limit_reached = False

        while queue:
            current, path, edges = queue.pop(0)
            if len(path) - 1 >= max_hops:
                continue
            for neighbour in sorted(self._adjacency.get(current, ())):
                if neighbour in visited:
                    continue
                connecting = self._edges_between(current, neighbour, include_expired, moment)
                if not connecting:
                    continue
                best = self._best_edge(connecting)
                if best is None:
                    continue
                new_edges = edges + [best]
                new_path = path + [neighbour]
                if neighbour == target:
                    confidences = [e["confidence"] for e in new_edges]
                    contains_inferred, all_verified = self._provenance_of(new_edges)
                    return PathResult(
                        source=source,
                        target=target,
                        found=True,
                        hops=len(new_path) - 1,
                        path=new_path,
                        edges=new_edges,
                        min_confidence=min(confidences) if confidences else 1.0,
                        contains_inferred_edges=contains_inferred,
                        all_edges_verified_origin=all_verified,
                    )
                visited.add(neighbour)
                queue.append((neighbour, new_path, new_edges))
                budget -= 1
                if budget <= 0:
                    limit_reached = True
                    queue = []
                    break
            if limit_reached:
                break

        return PathResult(
            source=source, target=target, found=False, search_limit_reached=limit_reached
        )

    def subgraph(self, entity_ids: Iterable[str]) -> Dict[str, Any]:
        """Extract the induced subgraph over a set of entities."""
        wanted = {e.strip() for e in entity_ids if e and e.strip()}
        nodes = sorted(wanted & set(self._adjacency))
        edges: List[Dict[str, Any]] = []
        seen: Set[str] = set()
        moment = datetime.utcnow()
        for a in nodes:
            for b in sorted(self._adjacency.get(a, ())):
                if b not in wanted:
                    continue
                for edge in self._edges_between(a, b, False, moment):
                    if edge["assertion_id"] in seen:
                        continue
                    seen.add(edge["assertion_id"])
                    edges.append(edge)
        return {"nodes": nodes, "edges": edges, "node_count": len(nodes), "edge_count": len(edges)}

    # ------------------------------------------------------------- analytics

    def transitive_candidates(self, relationship_type: str) -> List[Dict[str, Any]]:
        """
        Surface candidate transitive closures for analyst review.

        Never auto-asserted: returning candidates is what keeps an inference from becoming a
        claimed fact without an analyst recording it.
        """
        semantics = self.semantics_for(relationship_type)
        if not semantics.transitive:
            return []
        rel_type = semantics.relationship_type
        active = [
            a
            for a in self._assertions.values()
            if a.relationship_type == rel_type and a.status is AssertionStatus.ACTIVE
        ]
        outgoing: Dict[str, List[str]] = {}
        for a in active:
            outgoing.setdefault(a.source_entity_id, []).append(a.target_entity_id)

        candidates: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, str]] = set()
        for first in active:
            for mid_target in outgoing.get(first.target_entity_id, []):
                if mid_target == first.source_entity_id:
                    continue
                if any(
                    x.source_entity_id == first.source_entity_id and x.target_entity_id == mid_target
                    for x in active
                ):
                    continue
                key = (first.source_entity_id, mid_target)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(
                    {
                        "source_entity_id": first.source_entity_id,
                        "target_entity_id": mid_target,
                        "relationship_type": rel_type,
                        "via": [first.source_entity_id, first.target_entity_id, mid_target],
                        "note": "candidate_only_needs_analyst_confirmation",
                    }
                )
        return candidates

    def orphan_entities(self, now: Optional[datetime] = None) -> List[str]:
        """
        Entities whose every assertion is expired, withdrawn, or out of its temporal window.

        These are the entities that look connected in the index but have no live evidence behind
        them - exactly the set that must not be reported as active.
        """
        moment = now or datetime.utcnow()
        live_endpoints: Set[str] = set()
        for assertion in self._assertions.values():
            if assertion.status in (AssertionStatus.WITHDRAWN, AssertionStatus.EXPIRED):
                continue
            if not assertion.is_valid_at(moment):
                continue
            live_endpoints.add(assertion.source_entity_id)
            live_endpoints.add(assertion.target_entity_id)
        return sorted(set(self._adjacency) - live_endpoints)

    def incomplete_assertions(self) -> List[RelationshipAssertion]:
        """
        Assertions missing evidence or provenance.

        Reported, never silently accepted: an assertion without provenance cannot be audited,
        and one without evidence cannot be reviewed. Temporal bounds are reported separately by
        `unbounded_assertions`, because most legitimate relationships simply have no expiry.
        """
        return sorted(
            (a for a in self._assertions.values() if not a.evidence or not a.provenance),
            key=lambda a: (a.asserted_at, a.assertion_id),
        )

    def unbounded_assertions(self) -> List[RelationshipAssertion]:
        """Assertions with no declared `valid_until`. Flagged, not rejected."""
        return sorted(
            (
                a
                for a in self._assertions.values()
                if a.valid_until is None and a.status is AssertionStatus.ACTIVE
            ),
            key=lambda a: (a.asserted_at, a.assertion_id),
        )

    def health(self, now: Optional[datetime] = None) -> Dict[str, Any]:
        """Aggregate state for observability."""
        moment = now or datetime.utcnow()
        assertions = list(self._assertions.values())
        by_origin: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        for a in assertions:
            by_origin[a.origin.value] = by_origin.get(a.origin.value, 0) + 1
            by_status[a.status.value] = by_status.get(a.status.value, 0) + 1
        active = [a for a in assertions if a.status is AssertionStatus.ACTIVE]
        return {
            "tenant_id": self.tenant_id,
            "assertion_count": len(assertions),
            "active_count": len(active),
            "by_origin": by_origin,
            "by_status": by_status,
            "distinct_entities": len(self._adjacency),
            "inferred_count": sum(1 for a in assertions if a.is_inferred),
            "verified_origin_count": sum(1 for a in assertions if a.is_verified_origin),
            "temporally_valid_count": sum(1 for a in assertions if a.is_valid_at(moment)),
            "incomplete_count": len(self.incomplete_assertions()),
            "unbounded_count": len(self.unbounded_assertions()),
            "contradictions": self.contradiction_summary().model_dump(),
            "normalized_relationship_count": len(self.relationship_service.list_relationships()),
            "note": "in-memory analysis layer; no relationship storage is mounted",
        }
