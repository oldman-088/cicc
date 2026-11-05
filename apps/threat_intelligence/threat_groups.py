"""
Threat Group Profiles — Domain B item 12 (Master Prompt README.md line 228).

Branch: arena/28e50255-cicc (Agent 6 - Full Threat Intelligence Backup Engineer)

Before this module, "threat group" intelligence existed only as ``MITREGroupModel`` rows
produced by MITRE ATT&CK ingestion. That is a framework catalogue entry: a group ID, a name and
a description. It is not a group *profile* — it carries no aliases from other sources, no
source-specific names, no campaign or malware associations, no indicators, and no notion of one
source disagreeing with another.

This module adds the profile layer over the existing entities. It deliberately owns no second
copy of anything:

- MITRE group data is attached by reference to the already-ingested ``MITREGroupModel``.
- Evidence items reuse ``relationship_analysis.EvidenceItem``.
- Attribution provenance reuses ``relationship_analysis.AssertionOrigin``.
- Field-level source disagreements are delegated to ``conflict_resolution.ConflictResolutionService``
  rather than re-implementing claim resolution here.
- Relationships are exported into the existing ``RELATIONSHIP_TYPES`` vocabulary.

HONESTY CONSTRAINTS (enforced in code):

1. **Association is not confirmation.** A campaign/malware/tool/TTP/indicator link whose origin
   is inferred can never be CONFIRMED; attempting it raises ``UnconfirmedAssociationError``.
2. **Confidence is capped by origin and the cap is reported**, never applied silently.
3. **Source-specific names stay source-specific.** A vendor's name for a group is recorded with
   its source and is never promoted to the canonical name automatically.
4. **Disagreement is preserved.** Two sources naming the same group differently produce a
   conflict record; neither is overwritten.
5. **Duplicates are reported, never auto-merged.**
6. **History is append-only.**
7. **Verification mode defaults to ``fixture_tested``** — this module makes no outbound request.
"""

from __future__ import annotations

import hashlib
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from apps.threat_intelligence.cisa_kev import EXPERIMENTAL_DEMO_DATA_ONLY
from apps.threat_intelligence.conflict_resolution import (
    ClaimOrigin,
    ConflictResolutionService,
    ConflictState,
)
from apps.threat_intelligence.integration_contracts import VerificationMode
from apps.threat_intelligence.malware_families import ORIGIN_CONFIDENCE_CEILING, to_utc
from apps.threat_intelligence.mitre_ingestion import MITREGroupModel
from apps.threat_intelligence.relationship_analysis import AssertionOrigin, EvidenceItem

# --------------------------------------------------------------------------
# Limits
# --------------------------------------------------------------------------

GROUP_ID_PREFIX = "TG"
MAX_ALIASES_PER_GROUP = 200
MAX_IDENTIFIERS_PER_GROUP = 100
MAX_ASSOCIATIONS_PER_GROUP = 2_000
MAX_EVIDENCE_PER_ASSOCIATION = 50
MAX_DESCRIPTION_CHARS = 20_000
MAX_SEARCH_LIMIT = 500
MAX_HISTORY_ENTRIES = 5_000


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------

class ThreatGroupProfileError(Exception):
    """Base error for the threat group profile layer."""


class GroupProfileValidationError(ThreatGroupProfileError, ValueError):
    """A group profile or association failed validation."""


class UnconfirmedAssociationError(GroupProfileValidationError):
    """Raised when an association that cannot be confirmed is submitted as CONFIRMED."""


class GroupProfileNotFoundError(ThreatGroupProfileError, KeyError):
    """The referenced group profile does not exist in this tenant."""


# --------------------------------------------------------------------------
# Enums
# --------------------------------------------------------------------------

class GroupProfileStatus(str, Enum):
    """Lifecycle of the group profile itself."""

    ACTIVE = "active"
    PROVISIONAL = "provisional"
    MERGED = "merged"
    RETIRED = "retired"
    DISPUTED = "disputed"


class GroupAssociationKind(str, Enum):
    """What kind of entity a group is associated with."""

    CAMPAIGN = "campaign"
    MALWARE = "malware"
    TOOL = "tool"
    TTP = "ttp"
    INDICATOR = "indicator"
    INFRASTRUCTURE = "infrastructure"
    ACTOR = "actor"
    VICTIM_SECTOR = "victim_sector"


class GroupAssociationStatus(str, Enum):
    """Lifecycle of one group-to-entity association."""

    CONFIRMED = "confirmed"
    PROVISIONAL = "provisional"
    DISPUTED = "disputed"
    WITHDRAWN = "withdrawn"
    REJECTED = "rejected"


class GroupIdentifierKind(str, Enum):
    """Where a group identifier comes from."""

    MITRE_GROUP = "mitre_group"
    VENDOR_TAXONOMY = "vendor_taxonomy"
    SOURCE_SPECIFIC_NAME = "source_specific_name"
    GOVERNMENT_DESIGNATION = "government_designation"
    OTHER = "other"


#: Relationship type used per association kind, restricted to types that already exist in
#: ``relationships.RELATIONSHIP_TYPES``. No new edge vocabulary is invented.
ASSOCIATION_RELATIONSHIP_TYPE: Dict[GroupAssociationKind, str] = {
    GroupAssociationKind.CAMPAIGN: "ATTRIBUTED_TO",
    GroupAssociationKind.MALWARE: "USES",
    GroupAssociationKind.TOOL: "USES",
    GroupAssociationKind.TTP: "USES",
    GroupAssociationKind.INDICATOR: "INDICATES",
    GroupAssociationKind.INFRASTRUCTURE: "ASSOCIATED_WITH",
    GroupAssociationKind.ACTOR: "ASSOCIATED_WITH",
    GroupAssociationKind.VICTIM_SECTOR: "TARGETS",
}


# --------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------

class GroupAlias(BaseModel):
    """An alternate name for a group, attributed to the source that used it."""

    model_config = ConfigDict(extra="forbid")

    alias_id: str = Field(..., min_length=1, max_length=256)
    value: str = Field(..., min_length=1, max_length=256)
    source_id: str = Field(..., min_length=1, max_length=256)
    source_reference: Optional[str] = Field(None, max_length=512)
    kind: GroupIdentifierKind = GroupIdentifierKind.OTHER
    recorded_at: datetime = Field(default_factory=lambda: to_utc(None))
    retired: bool = Field(False, description="Set rather than deleted when a name is retracted")

    @field_validator("value")
    @classmethod
    def _normalise(cls, v: str) -> str:
        stripped = " ".join(v.split())
        if not stripped:
            raise ValueError("alias value must not be blank")
        return stripped

    @property
    def match_key(self) -> str:
        return " ".join(self.value.lower().split())


class GroupExternalIdentifier(BaseModel):
    """An external identifier for a group (MITRE G-id, vendor taxonomy entry, ...)."""

    model_config = ConfigDict(extra="forbid")

    identifier_id: str = Field(..., min_length=1, max_length=256)
    kind: GroupIdentifierKind = GroupIdentifierKind.OTHER
    value: str = Field(..., min_length=1, max_length=256)
    source_id: Optional[str] = Field(None, max_length=256)
    source_reference: Optional[str] = Field(None, max_length=512)
    recorded_at: datetime = Field(default_factory=lambda: to_utc(None))
    verified: bool = Field(False, description="Only True when a cited source confirms it")

    @field_validator("value")
    @classmethod
    def _strip(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("identifier value must not be blank")
        return stripped

    @property
    def match_key(self) -> str:
        return f"{self.kind.value}:{self.value.lower()}"


class GroupAssociation(BaseModel):
    """
    One source's assertion that a group is associated with one other entity.

    Immutable in practice: the service appends new associations and marks old ones withdrawn or
    rejected rather than editing them.
    """

    model_config = ConfigDict(extra="forbid")

    association_id: str = Field(..., min_length=1, max_length=256)
    tenant_id: str = Field(..., min_length=1, max_length=256)
    group_id: str = Field(..., min_length=1, max_length=256)
    kind: GroupAssociationKind = GroupAssociationKind.CAMPAIGN
    entity_id: str = Field(..., min_length=1, max_length=512)
    entity_name: Optional[str] = Field(None, max_length=256)
    origin: AssertionOrigin = AssertionOrigin.IMPORTED_UNVERIFIED
    status: GroupAssociationStatus = GroupAssociationStatus.PROVISIONAL
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    confidence_ceiling: float = Field(1.0, ge=0.0, le=1.0)
    confidence_was_clamped: bool = Field(False)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    source_id: str = Field(..., min_length=1, max_length=256)
    source_reference: Optional[str] = Field(None, max_length=512)
    provenance: Optional[str] = Field(None, max_length=512)
    observed_at: datetime = Field(default_factory=lambda: to_utc(None))
    recorded_at: datetime = Field(default_factory=lambda: to_utc(None))
    withdrawn: bool = Field(False)
    withdrawn_at: Optional[datetime] = None
    rejection_basis: Optional[str] = Field(None, max_length=2000)
    resolved_by: Optional[str] = Field(None, max_length=256)

    @field_validator("observed_at", "recorded_at", "withdrawn_at")
    @classmethod
    def _aware(cls, v: Optional[datetime]) -> Optional[datetime]:
        return None if v is None else to_utc(v)

    @field_validator("evidence")
    @classmethod
    def _cap_evidence(cls, v: List[EvidenceItem]) -> List[EvidenceItem]:
        if len(v) > MAX_EVIDENCE_PER_ASSOCIATION:
            raise ValueError(
                f"an association may carry at most {MAX_EVIDENCE_PER_ASSOCIATION} evidence items, "
                f"got {len(v)}"
            )
        return v

    @model_validator(mode="after")
    def _confirmed_requires_evidence(self) -> "GroupAssociation":
        """A CONFIRMED association must be directly sourced and evidenced."""
        if self.status == GroupAssociationStatus.CONFIRMED:
            if self.origin != AssertionOrigin.DIRECTLY_SOURCED:
                raise ValueError(
                    "only DIRECTLY_SOURCED associations may be CONFIRMED; "
                    f"got origin={self.origin.value}"
                )
            if not self.evidence:
                raise ValueError("a CONFIRMED association requires at least one evidence item")
        return self

    @property
    def is_active(self) -> bool:
        return not self.withdrawn and self.status not in (
            GroupAssociationStatus.WITHDRAWN,
            GroupAssociationStatus.REJECTED,
        )

    @property
    def distinct_evidence_sources(self) -> int:
        refs = {e.source_ref for e in self.evidence if e.source_ref}
        if self.source_reference:
            refs.add(self.source_reference)
        return len(refs)


class ThreatGroupProfile(BaseModel):
    """
    A threat group as a first-class intelligence profile.

    The profile aggregates names, identifiers and associations from many sources. It does not
    re-declare the entities it points at: MITRE data stays in the MITRE ingestion service,
    campaigns and malware stay in their own services, and this record holds references plus the
    evidence that justifies each one.
    """

    model_config = ConfigDict(extra="forbid")

    group_id: str = Field(..., min_length=1, max_length=256)
    tenant_id: str = Field(..., min_length=1, max_length=256)
    canonical_name: str = Field(..., min_length=1, max_length=256)
    description: Optional[str] = Field(None, max_length=MAX_DESCRIPTION_CHARS)
    motivation: Optional[str] = Field(None, max_length=256)
    country_of_origin: Optional[str] = Field(None, max_length=128)
    target_sectors: List[str] = Field(default_factory=list)
    target_regions: List[str] = Field(default_factory=list)
    aliases: List[GroupAlias] = Field(default_factory=list)
    identifiers: List[GroupExternalIdentifier] = Field(default_factory=list)
    mitre_group_id: Optional[str] = Field(
        None, max_length=64, description="Reference to an ingested MITREGroupModel, not a copy"
    )
    mitre_framework_version: Optional[str] = Field(None, max_length=32)
    status: GroupProfileStatus = GroupProfileStatus.PROVISIONAL
    verification_mode: VerificationMode = VerificationMode.FIXTURE_TESTED
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: to_utc(None))
    updated_at: datetime = Field(default_factory=lambda: to_utc(None))
    revision: int = Field(1, ge=1)
    experimental_label: Optional[str] = Field(None, max_length=64)

    @field_validator("canonical_name")
    @classmethod
    def _normalise_name(cls, v: str) -> str:
        stripped = " ".join(v.split())
        if not stripped:
            raise ValueError("canonical_name must not be blank")
        return stripped

    @field_validator("target_sectors", "target_regions")
    @classmethod
    def _dedupe(cls, v: List[str]) -> List[str]:
        return list(dict.fromkeys(item.strip().lower() for item in v if item.strip()))

    @field_validator("first_seen", "last_seen", "created_at", "updated_at")
    @classmethod
    def _aware(cls, v: Optional[datetime]) -> Optional[datetime]:
        return None if v is None else to_utc(v)

    @model_validator(mode="after")
    def _label_demo_data(self) -> "ThreatGroupProfile":
        if self.verification_mode != VerificationMode.LIVE_VERIFIED and self.experimental_label is None:
            self.experimental_label = EXPERIMENTAL_DEMO_DATA_ONLY
        return self

    @property
    def active_alias_names(self) -> Tuple[str, ...]:
        return tuple(a.value for a in self.aliases if not a.retired)

    @property
    def source_specific_names(self) -> Tuple[Tuple[str, str], ...]:
        """
        Names asserted by a specific source, as ``(name, source_id)`` pairs.

        Kept separate from aliases on purpose: a vendor's internal name for a group is a fact
        about that vendor's taxonomy, and promoting it to the canonical name would erase which
        source used it.
        """
        return tuple(
            (a.value, a.source_id)
            for a in self.aliases
            if not a.retired and a.kind == GroupIdentifierKind.SOURCE_SPECIFIC_NAME
        )

    @property
    def confirmed_identifier_count(self) -> int:
        return sum(1 for i in self.identifiers if i.verified)

    @property
    def match_keys(self) -> Tuple[str, ...]:
        keys = [" ".join(self.canonical_name.lower().split())]
        keys.extend(a.match_key for a in self.aliases if not a.retired)
        return tuple(dict.fromkeys(keys))


class GroupProfileRevision(BaseModel):
    """An append-only record of one change to a group profile or its associations."""

    model_config = ConfigDict(extra="forbid")

    revision_id: str = Field(..., min_length=1, max_length=256)
    group_id: str = Field(..., min_length=1, max_length=256)
    action: str = Field(..., min_length=1, max_length=64)
    actor: Optional[str] = Field(None, max_length=256)
    detail: Optional[str] = Field(None, max_length=2000)
    recorded_at: datetime = Field(default_factory=lambda: to_utc(None))
    profile_revision: int = Field(1, ge=1)

    @field_validator("action")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.strip().lower()


class GroupDuplicateGroup(BaseModel):
    """Group profiles that appear to be the same group, reported for human decision."""

    model_config = ConfigDict(extra="forbid")

    shared_key: str = Field(..., min_length=1, max_length=512)
    shared_kind: str = Field(..., min_length=1, max_length=32, description="alias | identifier")
    group_ids: Tuple[str, ...] = Field(..., min_length=2)
    group_names: Tuple[str, ...] = Field(..., min_length=2)


class GroupNameConflict(BaseModel):
    """
    Two sources naming the same group differently.

    Both names are preserved with their sources. Neither is overwritten, and the canonical name
    is never changed automatically as a side effect of ingesting a disagreeing source.
    """

    model_config = ConfigDict(extra="forbid")

    group_id: str = Field(..., min_length=1, max_length=256)
    group_name: str = Field(..., min_length=1, max_length=256)
    names: Tuple[Tuple[str, str], ...] = Field(..., min_length=2, description="(name, source_id) pairs")
    distinct_names: Tuple[str, ...] = Field(..., min_length=2)


class GroupAssociationConflict(BaseModel):
    """
    One entity associated with two or more groups by sources that disagree.

    Both sides are preserved verbatim; nothing is auto-resolved.
    """

    model_config = ConfigDict(extra="forbid")

    entity_id: str = Field(..., min_length=1, max_length=512)
    entity_name: Optional[str] = Field(None, max_length=256)
    kind: GroupAssociationKind
    group_ids: Tuple[str, ...] = Field(..., min_length=2)
    group_names: Tuple[str, ...] = Field(..., min_length=2)
    association_ids: Tuple[str, ...] = Field(..., min_length=2)
    sources: Tuple[str, ...] = Field(..., min_length=1)


# --------------------------------------------------------------------------
# Service
# --------------------------------------------------------------------------

class ThreatGroupProfileService:
    """
    Threat group profiles over the existing MITRE ingestion and entity models.

    Thread-safe: every mutation takes an internal lock, so a profile and its associations cannot
    be observed half-written.
    """

    def __init__(
        self,
        tenant_id: str = "default",
        conflict_resolver: Optional[ConflictResolutionService] = None,
    ) -> None:
        stripped = tenant_id.strip()
        if not stripped:
            raise GroupProfileValidationError("tenant_id must not be blank")
        self.tenant_id = stripped
        #: Field-level source disagreements are delegated, not re-implemented. When no resolver
        #: is supplied one is created, so conflicts are always recorded rather than dropped.
        self.conflict_resolver = conflict_resolver or ConflictResolutionService(tenant_id=stripped)
        self._lock = threading.RLock()
        self._profiles: Dict[str, ThreatGroupProfile] = {}
        self._associations: Dict[str, GroupAssociation] = {}
        self._history: List[GroupProfileRevision] = []
        self._mitre_references: Dict[str, MITREGroupModel] = {}
        #: entity_id -> set(group_id), active associations only
        self._entity_to_groups: Dict[str, set] = {}
        #: group_id -> set(entity_id), active associations only
        self._group_to_entities: Dict[str, set] = {}
        self._name_index: Dict[str, set] = {}
        self._identifier_index: Dict[str, set] = {}

    # ------------------------------------------------------------------
    # Identifiers
    # ------------------------------------------------------------------

    @staticmethod
    def generate_group_id(canonical_name: str, tenant_id: str) -> str:
        """Deterministic group ID: one canonical name per tenant maps to one profile."""
        digest = hashlib.sha256(
            f"{tenant_id}|{' '.join(canonical_name.lower().split())}".encode("utf-8")
        ).hexdigest()[:16]
        return f"{GROUP_ID_PREFIX}-{digest}"

    @staticmethod
    def _new_id(prefix: str) -> str:
        return f"{prefix}-{uuid.uuid4().hex[:16]}"

    # ------------------------------------------------------------------
    # Profile lifecycle
    # ------------------------------------------------------------------

    def create_profile(
        self,
        *,
        canonical_name: str,
        description: Optional[str] = None,
        motivation: Optional[str] = None,
        country_of_origin: Optional[str] = None,
        target_sectors: Optional[Sequence[str]] = None,
        target_regions: Optional[Sequence[str]] = None,
        aliases: Optional[Sequence[Dict[str, Any]]] = None,
        identifiers: Optional[Sequence[Dict[str, Any]]] = None,
        first_seen: Optional[datetime] = None,
        last_seen: Optional[datetime] = None,
        verification_mode: VerificationMode = VerificationMode.FIXTURE_TESTED,
        status: GroupProfileStatus = GroupProfileStatus.PROVISIONAL,
        group_id: Optional[str] = None,
        actor: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> ThreatGroupProfile:
        """Register a group profile. Re-submitting the same name returns the existing profile."""
        moment = to_utc(now)
        gid = group_id or self.generate_group_id(canonical_name, self.tenant_id)

        with self._lock:
            existing = self._profiles.get(gid)
            if existing is not None:
                return existing

            first = to_utc(first_seen) if first_seen else None
            last = to_utc(last_seen) if last_seen else None
            if last is None and first is not None:
                last = first
            if first is not None and last is not None and last < first:
                first, last = last, first

            profile = ThreatGroupProfile(
                group_id=gid,
                tenant_id=self.tenant_id,
                canonical_name=" ".join(canonical_name.split()),
                description=description,
                motivation=motivation,
                country_of_origin=country_of_origin,
                target_sectors=list(target_sectors or []),
                target_regions=list(target_regions or []),
                first_seen=first,
                last_seen=last,
                verification_mode=verification_mode,
                status=status,
                created_at=moment,
                updated_at=moment,
            )
            self._profiles[gid] = profile

            for raw in aliases or []:
                self._attach_alias(profile, raw, moment)
            for raw in identifiers or []:
                self._attach_identifier(profile, raw, moment)
            self._index_profile(profile)

            self._append_history(
                group_id=gid,
                action="profile_created",
                actor=actor,
                detail=f"canonical_name={profile.canonical_name}",
                moment=moment,
                profile_revision=profile.revision,
            )
            return profile

    def get_profile(self, group_id: str) -> Optional[ThreatGroupProfile]:
        with self._lock:
            return self._profiles.get(group_id)

    def require_profile(self, group_id: str) -> ThreatGroupProfile:
        with self._lock:
            profile = self._profiles.get(group_id)
        if profile is None:
            raise GroupProfileNotFoundError(f"unknown group_id: {group_id}")
        return profile

    def list_profiles(
        self,
        *,
        status: Optional[GroupProfileStatus] = None,
        limit: int = MAX_SEARCH_LIMIT,
        offset: int = 0,
    ) -> List[ThreatGroupProfile]:
        if limit < 0 or offset < 0:
            raise GroupProfileValidationError("limit and offset must be non-negative")
        limit = min(limit, MAX_SEARCH_LIMIT)
        with self._lock:
            rows = [
                p for p in self._profiles.values() if status is None or p.status == status
            ]
        rows.sort(key=lambda p: (p.canonical_name.lower(), p.group_id))
        return rows[offset:offset + limit]

    def revise_profile(
        self,
        group_id: str,
        *,
        description: Optional[str] = None,
        motivation: Optional[str] = None,
        country_of_origin: Optional[str] = None,
        target_sectors: Optional[Sequence[str]] = None,
        target_regions: Optional[Sequence[str]] = None,
        status: Optional[GroupProfileStatus] = None,
        verification_mode: Optional[VerificationMode] = None,
        first_seen: Optional[datetime] = None,
        last_seen: Optional[datetime] = None,
        actor: Optional[str] = None,
        detail: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> ThreatGroupProfile:
        """Apply a profile revision, recording the change in append-only history."""
        moment = to_utc(now)
        with self._lock:
            profile = self.require_profile(group_id)
            changes: List[str] = []

            for field_name, value in (
                ("description", description),
                ("motivation", motivation),
                ("country_of_origin", country_of_origin),
            ):
                if value is not None and value != getattr(profile, field_name):
                    changes.append(field_name)
                    setattr(profile, field_name, value)

            if target_sectors is not None:
                new_value = list(dict.fromkeys(s.strip().lower() for s in target_sectors if s.strip()))
                if new_value != profile.target_sectors:
                    changes.append("target_sectors")
                    profile.target_sectors = new_value
            if target_regions is not None:
                new_value = list(dict.fromkeys(r.strip().lower() for r in target_regions if r.strip()))
                if new_value != profile.target_regions:
                    changes.append("target_regions")
                    profile.target_regions = new_value
            if status is not None and status != profile.status:
                changes.append(f"status:{profile.status.value}->{status.value}")
                profile.status = status
            if verification_mode is not None and verification_mode != profile.verification_mode:
                changes.append(f"verification_mode->{verification_mode.value}")
                profile.verification_mode = verification_mode
                profile.experimental_label = (
                    None if verification_mode == VerificationMode.LIVE_VERIFIED
                    else EXPERIMENTAL_DEMO_DATA_ONLY
                )
            if first_seen is not None:
                candidate = to_utc(first_seen)
                if profile.first_seen is None or candidate < profile.first_seen:
                    changes.append("first_seen")
                    profile.first_seen = candidate
            if last_seen is not None:
                candidate = to_utc(last_seen)
                if profile.last_seen is None or candidate > profile.last_seen:
                    changes.append("last_seen")
                    profile.last_seen = candidate

            if not changes:
                return profile

            profile.revision += 1
            profile.updated_at = moment
            self._append_history(
                group_id=group_id,
                action="profile_revised",
                actor=actor,
                detail=detail or ",".join(changes),
                moment=moment,
                profile_revision=profile.revision,
            )
            return profile

    def set_status(
        self,
        group_id: str,
        status: GroupProfileStatus,
        *,
        actor: Optional[str] = None,
        detail: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> ThreatGroupProfile:
        return self.revise_profile(group_id, status=status, actor=actor, detail=detail, now=now)

    # ------------------------------------------------------------------
    # MITRE integration
    # ------------------------------------------------------------------

    def attach_mitre_group(
        self,
        group_id: str,
        mitre_group: MITREGroupModel,
        *,
        actor: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> ThreatGroupProfile:
        """
        Attach an already-ingested ``MITREGroupModel`` to a profile.

        The model is held by reference, not copied: MITRE ingestion stays the owner of MITRE
        data, and this profile only records which MITRE group it corresponds to. The MITRE name
        is registered as an alias attributed to the MITRE source rather than overwriting the
        canonical name, because MITRE's naming is one source's naming.
        """
        moment = to_utc(now)
        with self._lock:
            profile = self.require_profile(group_id)
            changes: List[str] = []

            if profile.mitre_group_id != mitre_group.group_id:
                changes.append(f"mitre_group_id->{mitre_group.group_id}")
                profile.mitre_group_id = mitre_group.group_id
                self._mitre_references[mitre_group.group_id] = mitre_group
            if (
                mitre_group.framework_version
                and profile.mitre_framework_version != mitre_group.framework_version
            ):
                changes.append(f"mitre_framework_version->{mitre_group.framework_version}")
                profile.mitre_framework_version = mitre_group.framework_version

            self._attach_identifier(
                profile,
                {
                    "value": mitre_group.group_id,
                    "kind": GroupIdentifierKind.MITRE_GROUP,
                    "source_id": mitre_group.source,
                    "source_reference": mitre_group.provenance,
                    "verified": True,
                },
                moment,
            )
            self._attach_alias(
                profile,
                {
                    "value": mitre_group.name,
                    "source_id": mitre_group.source,
                    "source_reference": mitre_group.provenance,
                    "kind": GroupIdentifierKind.MITRE_GROUP,
                },
                moment,
            )

            profile.updated_at = moment
            if changes:
                profile.revision += 1
            self._append_history(
                group_id=group_id,
                action="mitre_group_attached",
                actor=actor,
                detail=f"{mitre_group.group_id} ({mitre_group.name})",
                moment=moment,
                profile_revision=profile.revision,
            )
            return profile

    def mitre_group_for(self, group_id: str) -> Optional[MITREGroupModel]:
        """The attached MITRE model, if any. Returns the ingested object, not a copy."""
        with self._lock:
            profile = self.require_profile(group_id)
            if profile.mitre_group_id is None:
                return None
            return self._mitre_references.get(profile.mitre_group_id)

    def create_profile_from_mitre_group(
        self,
        mitre_group: MITREGroupModel,
        *,
        actor: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> ThreatGroupProfile:
        """
        Create a profile seeded from an ingested MITRE group.

        Convenience over ``create_profile`` + ``attach_mitre_group``; it does not duplicate MITRE
        fields into the profile beyond the reference and the attributed alias.
        """
        profile = self.create_profile(
            canonical_name=mitre_group.name,
            description=mitre_group.description,
            actor=actor,
            now=now,
        )
        return self.attach_mitre_group(profile.group_id, mitre_group, actor=actor, now=now)

    # ------------------------------------------------------------------
    # Aliases, identifiers and source-specific names
    # ------------------------------------------------------------------

    def add_alias(
        self,
        group_id: str,
        *,
        value: str,
        source_id: str,
        kind: GroupIdentifierKind = GroupIdentifierKind.OTHER,
        source_reference: Optional[str] = None,
        actor: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> GroupAlias:
        moment = to_utc(now)
        with self._lock:
            profile = self.require_profile(group_id)
            alias, added = self._attach_alias(
                profile,
                {
                    "value": value,
                    "source_id": source_id,
                    "source_reference": source_reference,
                    "kind": kind,
                },
                moment,
            )
            if not added:
                return alias
            self._append_history(
                group_id=group_id,
                action="alias_added",
                actor=actor,
                detail=f"{alias.value} (source={source_id}, kind={alias.kind.value})",
                moment=moment,
                profile_revision=profile.revision,
            )
            return alias

    def record_source_specific_name(
        self,
        group_id: str,
        *,
        value: str,
        source_id: str,
        source_reference: Optional[str] = None,
        actor: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> GroupAlias:
        """
        Record the name a specific source uses for this group.

        This never changes ``canonical_name``. A source's internal name is a fact about that
        source's taxonomy; silently promoting it would erase which source used it and would let
        the most recently ingested source rename the group.
        """
        return self.add_alias(
            group_id,
            value=value,
            source_id=source_id,
            kind=GroupIdentifierKind.SOURCE_SPECIFIC_NAME,
            source_reference=source_reference,
            actor=actor,
            now=now,
        )

    def retire_alias(
        self,
        group_id: str,
        alias_id: str,
        *,
        actor: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> bool:
        moment = to_utc(now)
        with self._lock:
            profile = self.require_profile(group_id)
            for alias in profile.aliases:
                if alias.alias_id == alias_id:
                    if alias.retired:
                        return False
                    alias.retired = True
                    profile.updated_at = moment
                    self._rebuild_name_index(profile)
                    self._append_history(
                        group_id=group_id,
                        action="alias_retired",
                        actor=actor,
                        detail=alias.value,
                        moment=moment,
                        profile_revision=profile.revision,
                    )
                    return True
            return False

    def add_identifier(
        self,
        group_id: str,
        *,
        value: str,
        kind: GroupIdentifierKind = GroupIdentifierKind.OTHER,
        source_id: Optional[str] = None,
        source_reference: Optional[str] = None,
        verified: bool = False,
        actor: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> GroupExternalIdentifier:
        if verified and not source_reference and not source_id:
            raise GroupProfileValidationError(
                "an identifier cannot be marked verified without a cited source"
            )
        moment = to_utc(now)
        with self._lock:
            profile = self.require_profile(group_id)
            identifier, changed = self._attach_identifier(
                profile,
                {
                    "value": value,
                    "kind": kind,
                    "source_id": source_id,
                    "source_reference": source_reference,
                    "verified": verified,
                },
                moment,
            )
            if not changed:
                return identifier
            self._append_history(
                group_id=group_id,
                action="identifier_added",
                actor=actor,
                detail=f"{identifier.kind.value}:{identifier.value} verified={identifier.verified}",
                moment=moment,
                profile_revision=profile.revision,
            )
            return identifier

    # ------------------------------------------------------------------
    # Field-level source claims (delegated conflict resolution)
    # ------------------------------------------------------------------

    def record_field_claim(
        self,
        group_id: str,
        field_name: str,
        value: Any,
        *,
        source_id: str,
        observed_at: datetime,
        origin: ClaimOrigin = ClaimOrigin.UNKNOWN,
        confidence: float = 0.0,
        reliability_score: Optional[float] = None,
        source_reference: Optional[str] = None,
        actor: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> Any:
        """
        Record what one source says about one scalar profile field.

        Resolution is delegated to ``ConflictResolutionService`` so claim handling stays in one
        place instead of being re-implemented per domain module. A disagreement produces a
        conflict record there and does not silently overwrite the profile.
        """
        moment = to_utc(now)
        profile = self.require_profile(group_id)
        claim = self.conflict_resolver.record_claim(
            entity_id=profile.group_id,
            field_name=field_name,
            value=value,
            source_id=source_id,
            observed_at=to_utc(observed_at),
            origin=origin,
            confidence=confidence,
            reliability_score=reliability_score,
            source_reference=source_reference,
            now=moment,
        )
        with self._lock:
            self._append_history(
                group_id=group_id,
                action="field_claim_recorded",
                actor=actor,
                detail=f"{field_name}={value} source={source_id}",
                moment=moment,
                profile_revision=profile.revision,
            )
        return claim

    def resolved_field(self, group_id: str, field_name: str) -> Any:
        """The resolved value for a scalar field, or None if no source has claimed it."""
        profile = self.require_profile(group_id)
        return self.conflict_resolver.resolved_value(profile.group_id, field_name)

    def field_conflicts(self, group_id: str, *, open_only: bool = False) -> List[Any]:
        """
        Field-level disagreements for this group, as recorded by the resolver.

        Returns every conflict record by default, including resolved ones. That matters: a
        disagreement the resolver settled deterministically still carries dissenting sources, and
        hiding it behind an "open only" filter would conceal exactly the cases an analyst needs
        to review. Pass ``open_only=True`` for just the unresolved ones.
        """
        profile = self.require_profile(group_id)
        return [
            conflict for conflict in self.conflict_resolver.conflicts(entity_id=profile.group_id)
            if not open_only or conflict.state in (ConflictState.OPEN, ConflictState.UNRESOLVABLE)
        ]

    def open_field_conflicts(self, group_id: str) -> List[Any]:
        """Unresolved field-level disagreements for this group."""
        return self.field_conflicts(group_id, open_only=True)

    def apply_resolved_fields(
        self,
        group_id: str,
        field_names: Sequence[str],
        *,
        actor: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> ThreatGroupProfile:
        """
        Copy resolved field values onto the profile.

        Applied explicitly rather than automatically: a profile should change when someone
        decides it should, not as a side effect of ingesting another source.
        """
        allowed = {"description", "motivation", "country_of_origin"}
        unknown = [name for name in field_names if name not in allowed]
        if unknown:
            raise GroupProfileValidationError(
                f"fields cannot be auto-applied to a profile: {unknown}; "
                f"allowed: {sorted(allowed)}"
            )
        moment = to_utc(now)
        kwargs: Dict[str, Any] = {}
        for name in field_names:
            resolved = self.resolved_field(group_id, name)
            if resolved is not None and resolved.value is not None:
                kwargs[name] = resolved.value
        if not kwargs:
            return self.require_profile(group_id)
        return self.revise_profile(
            group_id, actor=actor, detail="applied_resolved_fields", now=moment, **kwargs
        )

    # ------------------------------------------------------------------
    # Associations
    # ------------------------------------------------------------------

    def associate(
        self,
        *,
        group_id: str,
        kind: GroupAssociationKind,
        entity_id: str,
        source_id: str,
        entity_name: Optional[str] = None,
        origin: AssertionOrigin = AssertionOrigin.IMPORTED_UNVERIFIED,
        confidence: float = 0.0,
        evidence: Optional[Sequence[Dict[str, Any]]] = None,
        source_reference: Optional[str] = None,
        provenance: Optional[str] = None,
        observed_at: Optional[datetime] = None,
        confirm: bool = False,
        actor: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> GroupAssociation:
        """
        Record that a source associates this group with one other entity.

        Confidence is capped at the origin's ceiling and any clamping is recorded on the record.
        ``confirm=True`` is honoured only for directly-sourced, evidenced associations; otherwise
        ``UnconfirmedAssociationError`` is raised rather than silently downgrading.
        """
        moment = to_utc(now)
        if confidence < 0.0 or confidence > 1.0:
            raise GroupProfileValidationError("confidence must be within [0, 1]")

        items = [EvidenceItem(**e) for e in (evidence or [])]
        ceiling = ORIGIN_CONFIDENCE_CEILING[origin]

        if confirm and (origin != AssertionOrigin.DIRECTLY_SOURCED or not items):
            raise UnconfirmedAssociationError(
                "cannot confirm this association: CONFIRMED requires origin=directly_sourced "
                "and at least one evidence item "
                f"(got origin={origin.value}, evidence={len(items)})"
            )

        clamped = confidence > ceiling
        adjusted = min(confidence, ceiling)
        if items:
            distinct = len({e.source_ref for e in items if e.source_ref})
            if distinct > 1:
                adjusted = min(ceiling, adjusted + 0.05 * (distinct - 1))
        adjusted = round(adjusted, 6)

        status = (
            GroupAssociationStatus.CONFIRMED if confirm else GroupAssociationStatus.PROVISIONAL
        )

        with self._lock:
            profile = self.require_profile(group_id)
            if len(self._associations) >= MAX_ASSOCIATIONS_PER_GROUP * max(1, len(self._profiles)):
                raise GroupProfileValidationError("association store limit reached")

            existing = self._find_existing(group_id, kind, entity_id, source_id)
            if existing is not None:
                existing.observed_at = to_utc(observed_at) if observed_at else existing.observed_at
                existing.confidence = adjusted
                existing.confidence_ceiling = ceiling
                existing.confidence_was_clamped = clamped or existing.confidence_was_clamped
                if items:
                    known = {e.evidence_id for e in existing.evidence}
                    for item in items:
                        if item.evidence_id not in known:
                            existing.evidence.append(item)
                if status == GroupAssociationStatus.CONFIRMED:
                    existing.status = status
                self._touch_seen(profile, existing.observed_at, moment)
                self._append_history(
                    group_id=group_id,
                    action="association_reasserted",
                    actor=actor,
                    detail=f"{kind.value}:{entity_id} source={source_id} confidence={adjusted}",
                    moment=moment,
                    profile_revision=profile.revision,
                )
                return existing

            association = GroupAssociation(
                association_id=self._new_id("TGA"),
                tenant_id=self.tenant_id,
                group_id=group_id,
                kind=kind,
                entity_id=entity_id,
                entity_name=entity_name,
                origin=origin,
                status=status,
                confidence=adjusted,
                confidence_ceiling=ceiling,
                confidence_was_clamped=clamped,
                evidence=items,
                source_id=source_id,
                source_reference=source_reference,
                provenance=provenance,
                observed_at=to_utc(observed_at) if observed_at else moment,
                recorded_at=moment,
            )
            self._associations[association.association_id] = association
            self._entity_to_groups.setdefault(entity_id, set()).add(group_id)
            self._group_to_entities.setdefault(group_id, set()).add(entity_id)
            self._touch_seen(profile, association.observed_at, moment)
            self._append_history(
                group_id=group_id,
                action="association_recorded",
                actor=actor,
                detail=(
                    f"{kind.value}:{entity_id} source={source_id} origin={origin.value} "
                    f"status={status.value} confidence={adjusted} clamped={clamped}"
                ),
                moment=moment,
                profile_revision=profile.revision,
            )
            return association

    def withdraw_association(
        self,
        association_id: str,
        *,
        actor: Optional[str] = None,
        reason: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> GroupAssociation:
        moment = to_utc(now)
        with self._lock:
            association = self._associations.get(association_id)
            if association is None:
                raise GroupProfileNotFoundError(f"unknown association_id: {association_id}")
            if association.withdrawn:
                return association
            association.withdrawn = True
            association.withdrawn_at = moment
            association.status = GroupAssociationStatus.WITHDRAWN
            self._group_to_entities.get(association.group_id, set()).discard(association.entity_id)
            if not self._active_groups_for(association.entity_id):
                self._entity_to_groups.pop(association.entity_id, None)
            self._append_history(
                group_id=association.group_id,
                action="association_withdrawn",
                actor=actor,
                detail=f"association={association_id} reason={reason}",
                moment=moment,
                profile_revision=self._revision_of(association.group_id),
            )
            return association

    def reject_association(
        self,
        association_id: str,
        *,
        actor: str,
        basis: str,
        now: Optional[datetime] = None,
    ) -> GroupAssociation:
        if not actor.strip():
            raise GroupProfileValidationError("rejecting an association requires an actor")
        if not basis.strip():
            raise GroupProfileValidationError("rejecting an association requires a stated basis")
        moment = to_utc(now)
        with self._lock:
            association = self._associations.get(association_id)
            if association is None:
                raise GroupProfileNotFoundError(f"unknown association_id: {association_id}")
            association.status = GroupAssociationStatus.REJECTED
            association.rejection_basis = basis.strip()
            association.resolved_by = actor.strip()
            self._group_to_entities.get(association.group_id, set()).discard(association.entity_id)
            if not self._active_groups_for(association.entity_id):
                self._entity_to_groups.pop(association.entity_id, None)
            self._append_history(
                group_id=association.group_id,
                action="association_rejected",
                actor=actor,
                detail=f"association={association_id} basis={basis.strip()}",
                moment=moment,
                profile_revision=self._revision_of(association.group_id),
            )
            return association

    def dispute_association(
        self,
        association_id: str,
        *,
        actor: Optional[str] = None,
        note: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> GroupAssociation:
        """Mark an association disputed without withdrawing it, so the disagreement stays visible."""
        moment = to_utc(now)
        with self._lock:
            association = self._associations.get(association_id)
            if association is None:
                raise GroupProfileNotFoundError(f"unknown association_id: {association_id}")
            if association.status in (
                GroupAssociationStatus.CONFIRMED,
                GroupAssociationStatus.PROVISIONAL,
            ):
                association.status = GroupAssociationStatus.DISPUTED
            if note:
                association.rejection_basis = note.strip()
            if actor:
                association.resolved_by = actor.strip()
            self._append_history(
                group_id=association.group_id,
                action="association_disputed",
                actor=actor,
                detail=f"association={association_id} note={note}",
                moment=moment,
                profile_revision=self._revision_of(association.group_id),
            )
            return association

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def associations_for_group(
        self,
        group_id: str,
        *,
        kind: Optional[GroupAssociationKind] = None,
        include_inactive: bool = False,
    ) -> List[GroupAssociation]:
        with self._lock:
            self.require_profile(group_id)
            rows = [
                a for a in self._associations.values()
                if a.group_id == group_id
                and (kind is None or a.kind == kind)
                and (include_inactive or a.is_active)
            ]
        rows.sort(key=lambda a: (-a.confidence, a.recorded_at, a.association_id))
        return rows

    def associations_for_entity(self, entity_id: str, *, include_inactive: bool = False) -> List[GroupAssociation]:
        with self._lock:
            rows = [
                a for a in self._associations.values()
                if a.entity_id == entity_id and (include_inactive or a.is_active)
            ]
        rows.sort(key=lambda a: (-a.confidence, a.recorded_at, a.association_id))
        return rows

    def entity_ids_for_group(
        self, group_id: str, *, kind: Optional[GroupAssociationKind] = None
    ) -> Tuple[str, ...]:
        with self._lock:
            self.require_profile(group_id)
            ids = {
                a.entity_id
                for a in self._associations.values()
                if a.group_id == group_id and a.is_active and (kind is None or a.kind == kind)
            }
        return tuple(sorted(ids))

    def campaigns_for(self, group_id: str) -> Tuple[str, ...]:
        return self.entity_ids_for_group(group_id, kind=GroupAssociationKind.CAMPAIGN)

    def malware_for(self, group_id: str) -> Tuple[str, ...]:
        return self.entity_ids_for_group(group_id, kind=GroupAssociationKind.MALWARE)

    def tools_for(self, group_id: str) -> Tuple[str, ...]:
        return self.entity_ids_for_group(group_id, kind=GroupAssociationKind.TOOL)

    def ttps_for(self, group_id: str) -> Tuple[str, ...]:
        return self.entity_ids_for_group(group_id, kind=GroupAssociationKind.TTP)

    def indicators_for(self, group_id: str) -> Tuple[str, ...]:
        return self.entity_ids_for_group(group_id, kind=GroupAssociationKind.INDICATOR)

    def infrastructure_for(self, group_id: str) -> Tuple[str, ...]:
        return self.entity_ids_for_group(group_id, kind=GroupAssociationKind.INFRASTRUCTURE)

    def groups_for_entity(self, entity_id: str) -> List[ThreatGroupProfile]:
        with self._lock:
            ids = self._active_groups_for(entity_id)
            rows = [self._profiles[gid] for gid in ids if gid in self._profiles]
        rows.sort(key=lambda p: p.canonical_name.lower())
        return rows

    def find_by_alias(self, name: str) -> List[ThreatGroupProfile]:
        key = " ".join(name.lower().split())
        with self._lock:
            ids = set(self._name_index.get(key, set()))
            return sorted(
                (self._profiles[gid] for gid in ids if gid in self._profiles),
                key=lambda p: p.canonical_name.lower(),
            )

    def find_by_identifier(
        self, value: str, kind: Optional[GroupIdentifierKind] = None
    ) -> List[ThreatGroupProfile]:
        wanted = value.strip().lower()
        with self._lock:
            hits: List[ThreatGroupProfile] = []
            for profile in self._profiles.values():
                for ident in profile.identifiers:
                    if ident.value.lower() != wanted:
                        continue
                    if kind is not None and ident.kind != kind:
                        continue
                    hits.append(profile)
                    break
        hits.sort(key=lambda p: p.canonical_name.lower())
        return hits

    def search(
        self,
        *,
        query: Optional[str] = None,
        motivation: Optional[str] = None,
        country: Optional[str] = None,
        target_sector: Optional[str] = None,
        status: Optional[GroupProfileStatus] = None,
        verification_mode: Optional[VerificationMode] = None,
        has_mitre_group: Optional[bool] = None,
        limit: int = MAX_SEARCH_LIMIT,
        offset: int = 0,
    ) -> List[ThreatGroupProfile]:
        """Filter profiles across name, description, aliases, identifiers and profile fields."""
        if limit < 0 or offset < 0:
            raise GroupProfileValidationError("limit and offset must be non-negative")
        limit = min(limit, MAX_SEARCH_LIMIT)

        needle = " ".join(query.lower().split()) if query else None
        with self._lock:
            candidates = list(self._profiles.values())

        results: List[ThreatGroupProfile] = []
        for profile in candidates:
            if status is not None and profile.status != status:
                continue
            if verification_mode is not None and profile.verification_mode != verification_mode:
                continue
            if motivation and (profile.motivation or "").lower() != motivation.strip().lower():
                continue
            if country and (profile.country_of_origin or "").lower() != country.strip().lower():
                continue
            if target_sector and target_sector.strip().lower() not in profile.target_sectors:
                continue
            if has_mitre_group is not None:
                if has_mitre_group != (profile.mitre_group_id is not None):
                    continue
            if needle:
                haystack = " ".join(
                    [profile.canonical_name.lower(), (profile.description or "").lower()]
                    + list(profile.match_keys)
                    + [i.value.lower() for i in profile.identifiers]
                )
                if needle not in haystack:
                    continue
            results.append(profile)

        results.sort(key=lambda p: (p.canonical_name.lower(), p.group_id))
        return results[offset:offset + limit]

    # ------------------------------------------------------------------
    # Conflicts and duplicates
    # ------------------------------------------------------------------

    def name_conflicts(self) -> List[GroupNameConflict]:
        """
        Groups whose sources genuinely diverge on the designation.

        This is deliberately narrow. Alternate names are normal — MITRE calls a group one thing
        and a vendor calls it another — so counting any alias as a conflict would flag almost
        every profile and bury the cases that matter.

        A conflict is reported only when **two or more distinct source-specific designations are
        asserted by two or more distinct sources**: that is a real disagreement between vendors
        rather than ordinary aliasing. Every name is preserved with its source, and the canonical
        name is never changed as a side effect of ingesting a disagreeing source.
        """
        conflicts: List[GroupNameConflict] = []
        with self._lock:
            for profile in self._profiles.values():
                specific = [
                    (a.value, a.source_id)
                    for a in profile.aliases
                    if not a.retired and a.kind == GroupIdentifierKind.SOURCE_SPECIFIC_NAME
                ]
                distinct_names = {" ".join(v.lower().split()): v for v, _ in specific}
                distinct_sources = {src for _, src in specific}
                if len(distinct_names) < 2 or len(distinct_sources) < 2:
                    continue
                pairs = [(profile.canonical_name, "canonical")] + specific
                conflicts.append(
                    GroupNameConflict(
                        group_id=profile.group_id,
                        group_name=profile.canonical_name,
                        names=tuple(pairs),
                        distinct_names=tuple(distinct_names.values()),
                    )
                )
        conflicts.sort(key=lambda c: c.group_id)
        return conflicts

    def association_conflicts(self) -> List[GroupAssociationConflict]:
        """
        Entities actively associated with more than one group.

        Both sides are reported with their sources; nothing is resolved here.
        """
        with self._lock:
            # Group by (entity_id, kind), not by entity_id alone. Different kinds are not a
            # disagreement - a group can both run a campaign and use a tool - so an unrelated
            # link must never mask a genuine same-kind disagreement about the same entity.
            candidates: Dict[Tuple[str, GroupAssociationKind], List[GroupAssociation]] = {}
            for association in self._associations.values():
                if association.is_active:
                    candidates.setdefault((association.entity_id, association.kind), []).append(association)

            conflicts: List[GroupAssociationConflict] = []
            for (entity_id, kind), rows in candidates.items():
                group_ids = {a.group_id for a in rows}
                if len(group_ids) < 2:
                    continue
                rows = sorted(rows, key=lambda a: (-a.confidence, a.recorded_at, a.association_id))
                names = {
                    gid: (self._profiles[gid].canonical_name if gid in self._profiles else gid)
                    for gid in group_ids
                }
                conflicts.append(
                    GroupAssociationConflict(
                        entity_id=entity_id,
                        entity_name=rows[0].entity_name,
                        kind=kind,
                        group_ids=tuple(sorted(group_ids)),
                        group_names=tuple(names[gid] for gid in sorted(group_ids)),
                        association_ids=tuple(a.association_id for a in rows),
                        sources=tuple(sorted({a.source_id for a in rows})),
                    )
                )
        conflicts.sort(key=lambda c: (c.kind.value, c.entity_id))
        return conflicts

    def duplicate_profiles(self) -> List[GroupDuplicateGroup]:
        """Profiles sharing an alias or identifier, reported for human decision."""
        alias_map: Dict[str, List[str]] = {}
        identifier_map: Dict[str, List[str]] = {}
        with self._lock:
            for profile in self._profiles.values():
                if profile.status == GroupProfileStatus.MERGED:
                    continue
                for key in profile.match_keys:
                    alias_map.setdefault(key, []).append(profile.group_id)
                for ident in profile.identifiers:
                    identifier_map.setdefault(ident.match_key, []).append(profile.group_id)

        groups: List[GroupDuplicateGroup] = []
        for kind, mapping in (("alias", alias_map), ("identifier", identifier_map)):
            for key, ids in mapping.items():
                unique = sorted(dict.fromkeys(ids))
                if len(unique) < 2:
                    continue
                groups.append(
                    GroupDuplicateGroup(
                        shared_key=key,
                        shared_kind=kind,
                        group_ids=tuple(unique),
                        group_names=tuple(
                            self._profiles[gid].canonical_name if gid in self._profiles else gid
                            for gid in unique
                        ),
                    )
                )
        groups.sort(key=lambda g: (g.shared_kind, g.shared_key))
        return groups

    def merge_profiles(
        self,
        *,
        source_group_id: str,
        target_group_id: str,
        actor: str,
        basis: str,
        now: Optional[datetime] = None,
    ) -> ThreatGroupProfile:
        """
        Merge one profile into another.

        Requires an actor and a stated basis. Associations move to the target, aliases and
        identifiers are carried over, and the source is marked MERGED rather than deleted so its
        history stays reachable.
        """
        if not actor.strip():
            raise GroupProfileValidationError("merging profiles requires an actor")
        if not basis.strip():
            raise GroupProfileValidationError("merging profiles requires a stated basis")
        if source_group_id == target_group_id:
            raise GroupProfileValidationError("a profile cannot be merged into itself")

        moment = to_utc(now)
        with self._lock:
            source = self.require_profile(source_group_id)
            target = self.require_profile(target_group_id)

            existing_alias_keys = {a.match_key for a in target.aliases}
            for alias in source.aliases:
                if alias.match_key in existing_alias_keys:
                    continue
                if len(target.aliases) >= MAX_ALIASES_PER_GROUP:
                    break
                self._attach_alias(
                    target,
                    {
                        "value": alias.value,
                        "source_id": alias.source_id,
                        "source_reference": alias.source_reference,
                        "kind": alias.kind,
                    },
                    moment,
                )
                existing_alias_keys.add(alias.match_key)

            existing_ident_keys = {i.match_key for i in target.identifiers}
            for ident in source.identifiers:
                if ident.match_key in existing_ident_keys:
                    continue
                if len(target.identifiers) >= MAX_IDENTIFIERS_PER_GROUP:
                    break
                self._attach_identifier(
                    target,
                    {
                        "value": ident.value,
                        "kind": ident.kind,
                        "source_id": ident.source_id,
                        "source_reference": ident.source_reference,
                        "verified": ident.verified,
                    },
                    moment,
                )
                existing_ident_keys.add(ident.match_key)

            if source.mitre_group_id and not target.mitre_group_id:
                target.mitre_group_id = source.mitre_group_id
                target.mitre_framework_version = source.mitre_framework_version

            for sector in source.target_sectors:
                if sector not in target.target_sectors:
                    target.target_sectors.append(sector)
            for region in source.target_regions:
                if region not in target.target_regions:
                    target.target_regions.append(region)

            moved = 0
            for association in list(self._associations.values()):
                if association.group_id != source_group_id:
                    continue
                association.group_id = target_group_id
                self._group_to_entities.setdefault(target_group_id, set()).add(association.entity_id)
                moved += 1
            self._group_to_entities.pop(source_group_id, None)

            source.status = GroupProfileStatus.MERGED
            source.updated_at = moment
            source.revision += 1
            target.revision += 1
            target.updated_at = moment
            self._rebuild_name_index(source)
            self._rebuild_name_index(target)

            self._append_history(
                group_id=target_group_id,
                action="profile_merged_in",
                actor=actor,
                detail=f"from={source_group_id} basis={basis.strip()} associations_moved={moved}",
                moment=moment,
                profile_revision=target.revision,
            )
            self._append_history(
                group_id=source_group_id,
                action="profile_merged_out",
                actor=actor,
                detail=f"into={target_group_id} basis={basis.strip()}",
                moment=moment,
                profile_revision=source.revision,
            )
            return target

    # ------------------------------------------------------------------
    # History, statistics, integration
    # ------------------------------------------------------------------

    def history_for(self, group_id: str) -> List[GroupProfileRevision]:
        with self._lock:
            self.require_profile(group_id)
            return [r for r in self._history if r.group_id == group_id]

    def full_history(self) -> Tuple[GroupProfileRevision, ...]:
        with self._lock:
            return tuple(self._history)

    def export_relationships(self) -> List[Dict[str, Any]]:
        """
        Render active associations as ``RelationshipService``-compatible payloads.

        Only relationship types that already exist in ``relationships.RELATIONSHIP_TYPES`` are
        used. An unconfirmed association keeps a weaker edge type so an uncertain link is not
        exported as a confirmed one.
        """
        rows: List[Dict[str, Any]] = []
        for association in self._active_associations():
            profile = self.get_profile(association.group_id)
            if profile is None:
                continue
            confirmed = association.status == GroupAssociationStatus.CONFIRMED
            base_type = ASSOCIATION_RELATIONSHIP_TYPE[association.kind]
            rows.append(
                {
                    "source_entity_id": profile.group_id,
                    "source_entity_type": "ThreatGroup",
                    "target_entity_id": association.entity_id,
                    "target_entity_type": association.kind.value.title(),
                    "relationship_type": base_type if confirmed else "ASSOCIATED_WITH",
                    "description": (
                        f"{profile.canonical_name} "
                        f"{'confirmed' if confirmed else 'unconfirmed'} "
                        f"{association.kind.value} link to "
                        f"{association.entity_name or association.entity_id}"
                    ),
                    "confidence": association.confidence,
                    "source": association.source_id,
                    "provenance": association.provenance,
                    "evidence": "; ".join(
                        f"{e.evidence_id}({e.kind})" for e in association.evidence
                    ) or None,
                }
            )
        return rows

    def _active_associations(self) -> List[GroupAssociation]:
        with self._lock:
            rows = [a for a in self._associations.values() if a.is_active]
        rows.sort(key=lambda a: (a.recorded_at, a.association_id), reverse=True)
        return rows

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            profiles = list(self._profiles.values())
            associations = list(self._associations.values())
            active = [a for a in associations if a.is_active]
            by_kind: Dict[str, int] = {}
            for a in associations:
                by_kind[a.kind.value] = by_kind.get(a.kind.value, 0) + 1
            by_status: Dict[str, int] = {}
            for a in associations:
                by_status[a.status.value] = by_status.get(a.status.value, 0) + 1
            open_field_conflicts = [
                c for c in self.conflict_resolver.open_conflicts()
                if c.state == ConflictState.OPEN
            ]
        return {
            "tenant_id": self.tenant_id,
            "profiles": len(profiles),
            "profiles_active": sum(1 for p in profiles if p.status == GroupProfileStatus.ACTIVE),
            "profiles_merged": sum(1 for p in profiles if p.status == GroupProfileStatus.MERGED),
            "profiles_with_mitre_group": sum(1 for p in profiles if p.mitre_group_id),
            "aliases_total": sum(len(p.aliases) for p in profiles),
            "aliases_retired": sum(1 for p in profiles for a in p.aliases if a.retired),
            "source_specific_names": sum(len(p.source_specific_names) for p in profiles),
            "identifiers_total": sum(len(p.identifiers) for p in profiles),
            "identifiers_verified": sum(i.verified for p in profiles for i in p.identifiers),
            "associations_total": len(associations),
            "associations_active": len(active),
            "associations_confirmed": sum(
                1 for a in active if a.status == GroupAssociationStatus.CONFIRMED
            ),
            "associations_clamped": sum(1 for a in associations if a.confidence_was_clamped),
            "associations_by_kind": by_kind,
            "associations_by_status": by_status,
            "name_conflicts": len(self.name_conflicts()),
            "association_conflicts": len(self.association_conflicts()),
            "duplicate_profile_groups": len(self.duplicate_profiles()),
            "open_field_conflicts": len(open_field_conflicts),
            "history_entries": len(self._history),
            "verification_mode": "fixture_tested_only_no_outbound_requests",
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _revision_of(self, group_id: str) -> int:
        profile = self._profiles.get(group_id)
        return profile.revision if profile else 1

    def _touch_seen(self, profile: ThreatGroupProfile, observed: datetime, moment: datetime) -> None:
        if profile.first_seen is None or observed < profile.first_seen:
            profile.first_seen = observed
        if profile.last_seen is None or observed > profile.last_seen:
            profile.last_seen = observed
        profile.updated_at = moment

    def _find_existing(
        self, group_id: str, kind: GroupAssociationKind, entity_id: str, source_id: str
    ) -> Optional[GroupAssociation]:
        for association in self._associations.values():
            if (
                association.group_id == group_id
                and association.kind == kind
                and association.entity_id == entity_id
                and association.source_id == source_id
                and not association.withdrawn
            ):
                return association
        return None

    def _active_groups_for(self, entity_id: str) -> set:
        return {
            a.group_id
            for a in self._associations.values()
            if a.entity_id == entity_id and a.is_active
        }

    def _index_profile(self, profile: ThreatGroupProfile) -> None:
        self._rebuild_name_index(profile)
        for ident in profile.identifiers:
            self._identifier_index.setdefault(ident.match_key, set()).add(profile.group_id)

    def _rebuild_name_index(self, profile: ThreatGroupProfile) -> None:
        for keys in self._name_index.values():
            keys.discard(profile.group_id)
        for key in profile.match_keys:
            self._name_index.setdefault(key, set()).add(profile.group_id)

    def _attach_alias(
        self, profile: ThreatGroupProfile, raw: Dict[str, Any], moment: datetime
    ) -> Tuple[GroupAlias, bool]:
        """Attach an alias, returning ``(alias, was_added)`` so no-op adds write no history."""
        if len(profile.aliases) >= MAX_ALIASES_PER_GROUP:
            raise GroupProfileValidationError(
                f"group {profile.group_id} already carries {MAX_ALIASES_PER_GROUP} aliases"
            )
        alias = GroupAlias(
            alias_id=self._new_id("TGN"),
            value=raw["value"],
            source_id=raw["source_id"],
            source_reference=raw.get("source_reference"),
            kind=raw.get("kind") or GroupIdentifierKind.OTHER,
            recorded_at=moment,
        )
        for existing in profile.aliases:
            if existing.match_key == alias.match_key and existing.source_id == alias.source_id:
                return existing, False
        if alias.match_key == " ".join(profile.canonical_name.lower().split()):
            return alias, False
        profile.aliases.append(alias)
        self._name_index.setdefault(alias.match_key, set()).add(profile.group_id)
        return alias, True

    def _attach_identifier(
        self, profile: ThreatGroupProfile, raw: Dict[str, Any], moment: datetime
    ) -> Tuple[GroupExternalIdentifier, bool]:
        """Attach an identifier, returning ``(identifier, changed)``."""
        if len(profile.identifiers) >= MAX_IDENTIFIERS_PER_GROUP:
            raise GroupProfileValidationError(
                f"group {profile.group_id} already carries {MAX_IDENTIFIERS_PER_GROUP} identifiers"
            )
        identifier = GroupExternalIdentifier(
            identifier_id=self._new_id("TGI"),
            kind=raw.get("kind") or GroupIdentifierKind.OTHER,
            value=raw["value"],
            source_id=raw.get("source_id"),
            source_reference=raw.get("source_reference"),
            verified=bool(raw.get("verified", False)),
            recorded_at=moment,
        )
        for existing in profile.identifiers:
            if existing.match_key == identifier.match_key:
                if identifier.verified and not existing.verified:
                    existing.verified = True
                    return existing, True
                return existing, False
        profile.identifiers.append(identifier)
        self._identifier_index.setdefault(identifier.match_key, set()).add(profile.group_id)
        return identifier, True

    def _append_history(
        self,
        *,
        group_id: str,
        action: str,
        actor: Optional[str],
        detail: Optional[str],
        moment: datetime,
        profile_revision: int,
    ) -> None:
        self._history.append(
            GroupProfileRevision(
                revision_id=self._new_id("TGH"),
                group_id=group_id,
                action=action,
                actor=actor,
                detail=detail,
                recorded_at=moment,
                profile_revision=profile_revision,
            )
        )
        if len(self._history) > MAX_HISTORY_ENTRIES:
            self._history = self._history[-MAX_HISTORY_ENTRIES:]
