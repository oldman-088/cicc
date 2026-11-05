"""
Threat Intelligence Reports — Domain B item 24 (Master Prompt README.md line 240).
Branch: arena/28e50255-cicc (Agent 6 - Full Threat Intelligence Backup Engineer)

Implements a typed Threat Intelligence reporting foundation:
- Stable, deterministic report identifiers
- Title / summary / body / classification
- References to existing TI entities (actors, campaigns, malware, software, indicators)
- Source attribution, provenance, confidence, freshness, evidence
- Relationships to existing TI entities (reuses relationship semantics, no duplicate graph)
- Validation and deduplication
- Append-only history
- Search and filtering foundations

HONESTY CONSTRAINTS:
- Reports are analytical summaries. They never fabricate observations. A report may only
  reference entities it was actually given; it cannot invent entity IDs.
- Every report carries an explicit verification_mode and a data-classification label.
- Reports generated from fixture data are labelled EXPERIMENTAL_DEMO_DATA_ONLY.
"""

import hashlib
import json
import threading
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator

from apps.threat_intelligence.cisa_kev import EXPERIMENTAL_DEMO_DATA_ONLY

REPORT_ID_PREFIX = "TIR"
MAX_REPORT_BODY_CHARS = 200_000
MAX_REFERENCES_PER_REPORT = 2_000
MAX_EVIDENCE_PER_REPORT = 500
MAX_SEARCH_LIMIT = 500


class ReportClassification(str, Enum):
    """Data classification labels. Deliberately small and explicit."""

    UNCLASSIFIED = "unclassified"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class ReportStatus(str, Enum):
    """Report lifecycle states. `published` and `retracted` are terminal."""

    DRAFT = "draft"
    IN_REVIEW = "in_review"
    PUBLISHED = "published"
    RETRACTED = "retracted"


class ReportKind(str, Enum):
    """Analytical report kinds."""

    ACTOR_PROFILE = "actor_profile"
    CAMPAIGN_SUMMARY = "campaign_summary"
    MALWARE_PROFILE = "malware_profile"
    INDICATOR_BRIEF = "indicator_brief"
    PERIODIC_DIGEST = "periodic_digest"
    INCIDENT_NOTE = "incident_note"
    TREND_ANALYSIS = "trend_analysis"


class ReportVerificationMode(str, Enum):
    """Verification evidence level of the report's underlying data."""

    FIXTURE_TESTED = "fixture_tested"
    ORACLE_VERIFIED = "oracle_verified"
    LIVE_VERIFIED = "live_verified"


class ReportOrigin(str, Enum):
    """Where the underlying data came from. Kept aligned with the frontend DTO enums."""

    EXPERIMENTAL_DEMO = EXPERIMENTAL_DEMO_DATA_ONLY
    LIVE_SOURCE = "live_source"


class ReportEntityReference(BaseModel):
    """
    A reference to an already-existing Threat Intelligence entity.

    This is a reference, not a copy. The entity itself stays in its owning service, so the
    report layer never becomes a second representation of actor/malware/indicator data.
    """

    model_config = ConfigDict(extra="forbid")

    entity_id: str = Field(..., min_length=1, max_length=512, description="Referenced entity ID")
    entity_type: str = Field(..., min_length=1, max_length=64, description="Entity kind")
    entity_name: Optional[str] = Field(None, max_length=512, description="Display name at time of writing")
    referenced_at: datetime = Field(..., description="When the reference was recorded")

    @field_validator("entity_type")
    @classmethod
    def _lower_type(cls, v: str) -> str:
        return v.strip().lower()


class ReportEvidenceRef(BaseModel):
    """A pointer to supporting evidence. Never the evidence payload itself."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(..., min_length=1, max_length=512)
    evidence_kind: str = Field("note", max_length=64, description="note | url | file | observation | source_document")
    description: Optional[str] = Field(None, max_length=2000)
    source_ref: Optional[str] = Field(None, max_length=512, description="Source reference / citation")

    @field_validator("evidence_kind")
    @classmethod
    def _lower_kind(cls, v: str) -> str:
        return v.strip().lower()


class ReportSourceAttribution(BaseModel):
    """Which sources contributed to this report, with their contribution weight."""

    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(..., min_length=1, max_length=256)
    observation_count: int = Field(0, ge=0)
    reliability_tier: Optional[str] = Field(None, max_length=32)
    reliability_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    verification_mode: ReportVerificationMode = ReportVerificationMode.FIXTURE_TESTED


class ReportRelationshipRef(BaseModel):
    """
    A relationship the report asserts or cites between two referenced entities.

    Relationships are described here, not owned here: `relationship_id` points at the
    authoritative record held by the relationship service when one exists.
    """

    model_config = ConfigDict(extra="forbid")

    source_entity_id: str = Field(..., min_length=1, max_length=512)
    relationship_type: str = Field(..., min_length=1, max_length=64)
    target_entity_id: str = Field(..., min_length=1, max_length=512)
    relationship_id: Optional[str] = Field(
        None, max_length=512, description="Authoritative relationship record ID, when one exists"
    )
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    inferred: bool = Field(
        False,
        description="True when the relationship is analyst-inferred rather than directly sourced. "
        "Inferred relationships must never be presented as confirmed facts.",
    )
    provenance: Optional[str] = Field(None, max_length=512)

    @field_validator("relationship_type")
    @classmethod
    def _upper_type(cls, v: str) -> str:
        return v.strip().upper()


class ThreatIntelReport(BaseModel):
    """
    Typed Threat Intelligence report record.

    `report_id` is caller-supplied or generated; either way it is stable for the report's life.
    `content_hash` is derived from the analytical content so byte-identical reports deduplicate.
    """

    model_config = ConfigDict(extra="forbid")

    report_id: str = Field(..., min_length=1, max_length=256)
    tenant_id: str = Field(..., min_length=1, max_length=256)
    kind: ReportKind
    title: str = Field(..., min_length=1, max_length=512)
    summary: str = Field(..., min_length=1, max_length=4000, description="Short analytical summary")
    body: str = Field(..., min_length=1, max_length=MAX_REPORT_BODY_CHARS)
    classification: ReportClassification = ReportClassification.INTERNAL
    status: ReportStatus = ReportStatus.DRAFT
    language: str = Field("en", max_length=16)

    entity_refs: List[ReportEntityReference] = Field(default_factory=list)
    relationship_refs: List[ReportRelationshipRef] = Field(default_factory=list)
    evidence_refs: List[ReportEvidenceRef] = Field(default_factory=list)
    source_attributions: List[ReportSourceAttribution] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)

    confidence: float = Field(0.0, ge=0.0, le=1.0, description="Analytical confidence in the report's conclusions")
    freshness_at: datetime = Field(..., description="As-of time of the underlying data")
    stale_after_seconds: Optional[int] = Field(None, ge=0, description="Age at which the report should be re-checked")
    verification_mode: ReportVerificationMode = ReportVerificationMode.FIXTURE_TESTED
    origin: ReportOrigin = ReportOrigin.EXPERIMENTAL_DEMO

    author_ref: str = Field(..., min_length=1, max_length=256, description="Attributable author (no secrets, no PII)")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    version: int = Field(1, ge=1)
    supersedes: Optional[str] = Field(None, max_length=256, description="report_id of the report this one replaces")
    content_hash: str = Field(..., min_length=16, max_length=128)
    experimental_label: Optional[str] = Field(EXPERIMENTAL_DEMO_DATA_ONLY)

    @field_validator("tags")
    @classmethod
    def _dedupe_tags(cls, v: List[str]) -> List[str]:
        cleaned = [t.strip() for t in v if t and t.strip()]
        return list(dict.fromkeys(cleaned))

    def age_seconds(self, as_of: Optional[datetime] = None) -> Optional[int]:
        """Report age in seconds relative to `as_of`, or None when the clock is not trustworthy."""
        moment = as_of or datetime.utcnow()
        if self.freshness_at.tzinfo is not None and moment.tzinfo is None:
            moment = moment.replace(tzinfo=self.freshness_at.tzinfo)
        delta = moment - self.freshness_at
        seconds = int(delta.total_seconds())
        if seconds < 0:
            return None
        return seconds

    def is_stale(self, as_of: Optional[datetime] = None) -> bool:
        """
        A report is stale only when a `stale_after_seconds` horizon was declared AND that
        horizon has passed. Absent a horizon this returns False rather than guessing.
        """
        if self.stale_after_seconds is None:
            return False
        age = self.age_seconds(as_of)
        if age is None:
            return False
        return age > self.stale_after_seconds

    def has_inferred_relationships(self) -> bool:
        return any(r.inferred for r in self.relationship_refs)


class ReportValidationError(ValueError):
    """Raised when a report cannot be admitted."""


class DuplicateReportError(ReportValidationError):
    """Raised when an identical report already exists for the tenant."""


class ReportAppendOnlyViolationError(RuntimeError):
    """Raised when history would be rewritten rather than appended to."""


class ReportHistoryEntry(BaseModel):
    """Immutable history entry for a report revision."""

    model_config = ConfigDict(extra="forbid")

    history_id: str = Field(..., max_length=256)
    report_id: str = Field(..., max_length=256)
    tenant_id: str = Field(..., max_length=256)
    version: int = Field(..., ge=1)
    change_type: str = Field(..., max_length=64, description="created | revised | status_changed | retracted")
    change_basis: str = Field(..., min_length=1, max_length=1000, description="Why the change was made")
    actor: str = Field(..., min_length=1, max_length=256)
    previous_content_hash: Optional[str] = Field(None, max_length=128)
    content_hash: str = Field(..., max_length=128)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ThreatIntelReportService:
    """
    Report store with deduplication, append-only history, and search/filter foundations.

    In-memory and append-only. No network, no threads, no event loop.
    """

    _HISTORY_CHANGE_TYPES = {"created", "revised", "status_changed", "retracted"}

    def __init__(self, tenant_id: str = "default"):
        if not tenant_id or not tenant_id.strip():
            raise ReportValidationError("tenant_id is required for report isolation")
        self.tenant_id = tenant_id.strip()
        self._lock = threading.RLock()
        self._reports: Dict[str, ThreatIntelReport] = {}
        self._content_index: Dict[str, str] = {}
        self._history: List[ReportHistoryEntry] = []
        self._by_entity: Dict[str, List[str]] = {}

    # ------------------------------------------------------------------ IDs

    @staticmethod
    def generate_report_id(kind: ReportKind, tenant_id: str) -> str:
        """Deterministic-by-input report ID; stable for a given kind/tenant/nonce."""
        nonce = uuid.uuid4().hex[:16]
        return f"{REPORT_ID_PREFIX}-{kind.value}-{tenant_id[:24]}-{nonce}"

    @staticmethod
    def compute_content_hash(
        title: str,
        summary: str,
        body: str,
        kind: ReportKind,
        classification: ReportClassification,
        entity_refs: Iterable[ReportEntityReference],
        relationship_refs: Iterable[ReportRelationshipRef],
        evidence_refs: Iterable[ReportEvidenceRef] = (),
    ) -> str:
        """
        Content hash over the analytical content only.

        Identity and bookkeeping fields (report_id, created_at, version, author) are excluded so
        that a re-publication of the same analysis deduplicates, while any change to the actual
        analysis - including the evidence it rests on - produces a different hash.
        """
        payload = {
            "kind": kind.value,
            "classification": classification.value,
            "title": title.strip(),
            "summary": summary.strip(),
            "body": body.strip(),
            "entities": sorted(
                {f"{r.entity_type}:{r.entity_id}" for r in entity_refs}
            ),
            "relationships": sorted(
                {
                    f"{r.source_entity_id}|{r.relationship_type}|{r.target_entity_id}|{str(r.inferred).lower()}"
                    for r in relationship_refs
                }
            ),
            "evidence": sorted(
                {f"{r.evidence_kind}:{r.evidence_id}:{r.source_ref or ''}" for r in evidence_refs}
            ),
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------- validation

    def _validate(self, report: ThreatIntelReport) -> None:
        if report.tenant_id != self.tenant_id:
            raise ReportValidationError(
                f"report tenant_id {report.tenant_id!r} does not match service tenant {self.tenant_id!r}"
            )
        if not report.title.strip() or not report.summary.strip() or not report.body.strip():
            raise ReportValidationError("title, summary and body must all be non-empty after stripping")
        if len(report.body) > MAX_REPORT_BODY_CHARS:
            raise ReportValidationError(f"body exceeds {MAX_REPORT_BODY_CHARS} characters")
        if len(report.entity_refs) > MAX_REFERENCES_PER_REPORT:
            raise ReportValidationError(f"too many entity references (>{MAX_REFERENCES_PER_REPORT})")
        if len(report.relationship_refs) > MAX_REFERENCES_PER_REPORT:
            raise ReportValidationError(f"too many relationship references (>{MAX_REFERENCES_PER_REPORT})")
        if len(report.evidence_refs) > MAX_EVIDENCE_PER_REPORT:
            raise ReportValidationError(f"too many evidence references (>{MAX_EVIDENCE_PER_REPORT})")
        if not report.author_ref.strip():
            raise ReportValidationError("author_ref is required: reports must be attributable")

        # Reports must not invent entities: every relationship endpoint must be referenced.
        known = {r.entity_id for r in report.entity_refs}
        for rel in report.relationship_refs:
            for endpoint in (rel.source_entity_id, rel.target_entity_id):
                if endpoint not in known:
                    raise ReportValidationError(
                        f"relationship endpoint {endpoint!r} is not present in entity_refs; "
                        "reports may only reference entities they were given"
                    )

        # A periodic digest with no entities is meaningless; guard the cheap case.
        if report.kind is ReportKind.INDICATOR_BRIEF and not report.entity_refs:
            raise ReportValidationError("indicator_brief reports must reference at least one entity")

        # Freshness must not predate the report's own creation by an implausible margin.
        if report.created_at < report.freshness_at and (
            report.created_at - report.freshness_at
        ).total_seconds() < -31_536_000:
            raise ReportValidationError("freshness_at is more than a year after created_at")

    # ---------------------------------------------------------------- create

    def create_report(
        self,
        title: str,
        summary: str,
        body: str,
        author_ref: str,
        kind: ReportKind = ReportKind.PERIODIC_DIGEST,
        classification: ReportClassification = ReportClassification.INTERNAL,
        entity_refs: Optional[List[ReportEntityReference]] = None,
        relationship_refs: Optional[List[ReportRelationshipRef]] = None,
        evidence_refs: Optional[List[ReportEvidenceRef]] = None,
        source_attributions: Optional[List[ReportSourceAttribution]] = None,
        tags: Optional[List[str]] = None,
        confidence: float = 0.0,
        freshness_at: Optional[datetime] = None,
        stale_after_seconds: Optional[int] = None,
        verification_mode: ReportVerificationMode = ReportVerificationMode.FIXTURE_TESTED,
        origin: ReportOrigin = ReportOrigin.EXPERIMENTAL_DEMO,
        language: str = "en",
        supersedes: Optional[str] = None,
        report_id: Optional[str] = None,
        allow_duplicate: bool = False,
        now: Optional[datetime] = None,
    ) -> ThreatIntelReport:
        """
        Validate, deduplicate and admit a new report, appending an immutable history entry.

        Duplicate detection: identical analytical content for the same tenant raises
        `DuplicateReportError` unless `allow_duplicate` is set, in which case the existing
        report is returned unchanged (idempotent admission).
        """
        moment = now or datetime.utcnow()
        entities = list(entity_refs or [])
        rels = list(relationship_refs or [])

        content_hash = self.compute_content_hash(
            title, summary, body, kind, classification, entities, rels, list(evidence_refs or [])
        )

        with self._lock:
            existing_id = self._content_index.get(content_hash)
            if existing_id is not None and existing_id in self._reports:
                if allow_duplicate:
                    return self._reports[existing_id]
                raise DuplicateReportError(
                    f"an identical report already exists for tenant {self.tenant_id!r}: {existing_id}"
                )

            if supersedes is not None and supersedes not in self._reports:
                raise ReportValidationError(f"supersedes references unknown report_id {supersedes!r}")
            if report_id is not None and report_id in self._reports:
                raise ReportValidationError(f"report_id {report_id!r} already exists")

            report = ThreatIntelReport(
                report_id=report_id or self.generate_report_id(kind, self.tenant_id),
                tenant_id=self.tenant_id,
                kind=kind,
                title=title,
                summary=summary,
                body=body,
                classification=classification,
                entity_refs=entities,
                relationship_refs=rels,
                evidence_refs=list(evidence_refs or []),
                source_attributions=list(source_attributions or []),
                tags=list(tags or []),
                confidence=confidence,
                freshness_at=freshness_at or moment,
                stale_after_seconds=stale_after_seconds,
                verification_mode=verification_mode,
                origin=origin,
                author_ref=author_ref,
                language=language,
                created_at=moment,
                updated_at=moment,
                version=1,
                supersedes=supersedes,
                content_hash=content_hash,
                experimental_label=(
                    EXPERIMENTAL_DEMO_DATA_ONLY
                    if origin is ReportOrigin.EXPERIMENTAL_DEMO
                    else None
                ),
            )
            self._validate(report)

            self._reports[report.report_id] = report
            self._content_index[report.content_hash] = report.report_id
            self._index_entities(report)
            self._append_history(
                report,
                change_type="created",
                change_basis="initial report admission",
                actor=author_ref,
                previous_hash=None,
                now=moment,
            )
            return report

    def _index_entities(self, report: ThreatIntelReport) -> None:
        for ref in report.entity_refs:
            bucket = self._by_entity.setdefault(ref.entity_id, [])
            if report.report_id not in bucket:
                bucket.append(report.report_id)

    def _append_history(
        self,
        report: ThreatIntelReport,
        change_type: str,
        change_basis: str,
        actor: str,
        previous_hash: Optional[str],
        now: Optional[datetime] = None,
    ) -> ReportHistoryEntry:
        if change_type not in self._HISTORY_CHANGE_TYPES:
            raise ReportAppendOnlyViolationError(f"unknown history change_type {change_type!r}")
        if not change_basis or not change_basis.strip():
            raise ReportValidationError("history change_basis is required: every change must state why")
        if not actor or not actor.strip():
            raise ReportValidationError("history actor is required: every change must be attributable")
        entry = ReportHistoryEntry(
            history_id=f"H-{report.report_id}-{report.version}-{uuid.uuid4().hex[:8]}",
            report_id=report.report_id,
            tenant_id=report.tenant_id,
            version=report.version,
            change_type=change_type,
            change_basis=change_basis.strip(),
            actor=actor.strip(),
            previous_content_hash=previous_hash,
            content_hash=report.content_hash,
            created_at=now or datetime.utcnow(),
        )
        self._history.append(entry)
        return entry

    # --------------------------------------------------------------- retrieve

    def get_report(self, report_id: str) -> Optional[ThreatIntelReport]:
        with self._lock:
            return self._reports.get(report_id)

    def list_reports(self, limit: int = MAX_SEARCH_LIMIT, offset: int = 0) -> List[ThreatIntelReport]:
        limit = max(1, min(int(limit), MAX_SEARCH_LIMIT))
        offset = max(0, int(offset))
        with self._lock:
            ordered = sorted(
                self._reports.values(),
                key=lambda r: (r.created_at, r.report_id),
                reverse=True,
            )
            return ordered[offset : offset + limit]

    def find_reports_for_entity(self, entity_id: str) -> List[ThreatIntelReport]:
        with self._lock:
            ids = self._by_entity.get(entity_id, [])
            return [self._reports[i] for i in ids if i in self._reports]

    def history_for(self, report_id: str) -> List[ReportHistoryEntry]:
        with self._lock:
            return [h for h in self._history if h.report_id == report_id]

    def full_history(self) -> Tuple[ReportHistoryEntry, ...]:
        """History is returned as an immutable tuple: callers cannot rewrite it in place."""
        with self._lock:
            return tuple(self._history)

    # ----------------------------------------------------------------- update

    def revise_report(
        self,
        report_id: str,
        change_basis: str,
        actor: str,
        title: Optional[str] = None,
        summary: Optional[str] = None,
        body: Optional[str] = None,
        classification: Optional[ReportClassification] = None,
        confidence: Optional[float] = None,
        freshness_at: Optional[datetime] = None,
        tags: Optional[List[str]] = None,
        add_entity_refs: Optional[List[ReportEntityReference]] = None,
        add_relationship_refs: Optional[List[ReportRelationshipRef]] = None,
        add_evidence_refs: Optional[List[ReportEvidenceRef]] = None,
        now: Optional[datetime] = None,
    ) -> ThreatIntelReport:
        """
        Replace the report record with a new version and append history.

        The previous record object is discarded, never mutated: history entries keep the prior
        content_hash, so the revision chain is auditable and no prior observation is overwritten
        in place.
        """
        moment = now or datetime.utcnow()
        with self._lock:
            current = self._reports.get(report_id)
            if current is None:
                raise ReportValidationError(f"unknown report_id {report_id!r}")
            if current.status in (ReportStatus.RETRACTED,):
                raise ReportValidationError("retracted reports cannot be revised; supersede them instead")

            previous_hash = current.content_hash
            entity_refs = list(current.entity_refs) + list(add_entity_refs or [])
            rel_refs = list(current.relationship_refs) + list(add_relationship_refs or [])

            new_title = current.title if title is None else title
            new_summary = current.summary if summary is None else summary
            new_body = current.body if body is None else body
            new_class = current.classification if classification is None else classification

            evidence_refs = list(current.evidence_refs) + list(add_evidence_refs or [])
            content_hash = self.compute_content_hash(
                new_title, new_summary, new_body, current.kind, new_class, entity_refs, rel_refs, evidence_refs
            )
            if content_hash == previous_hash and confidence is None and freshness_at is None and tags is None:
                raise ReportValidationError(
                    "revision changes nothing: supply changed analytical content or explicit metadata"
                )
            if content_hash != previous_hash:
                clash = self._content_index.get(content_hash)
                if clash is not None and clash != report_id:
                    raise DuplicateReportError(
                        f"revision would duplicate report {clash!r}; supersede it instead"
                    )

            revised = ThreatIntelReport(
                **{
                    **current.model_dump(exclude={"title", "summary", "body", "classification"}),
                    "title": new_title,
                    "summary": new_summary,
                    "body": new_body,
                    "classification": new_class,
                    "confidence": current.confidence if confidence is None else confidence,
                    "freshness_at": current.freshness_at if freshness_at is None else freshness_at,
                    "tags": tags if tags is not None else current.tags,
                    "entity_refs": entity_refs,
                    "relationship_refs": rel_refs,
                    "evidence_refs": evidence_refs,
                    "updated_at": moment,
                    "version": current.version + 1,
                    "content_hash": content_hash,
                }
            )
            self._validate(revised)

            if previous_hash != content_hash:
                if self._content_index.get(previous_hash) == report_id:
                    del self._content_index[previous_hash]
                self._content_index[content_hash] = report_id

            self._reports[report_id] = revised
            self._index_entities(revised)
            self._append_history(
                revised,
                change_type="revised",
                change_basis=change_basis,
                actor=actor,
                previous_hash=previous_hash,
                now=moment,
            )
            return revised

    def transition_status(
        self,
        report_id: str,
        new_status: ReportStatus,
        change_basis: str,
        actor: str,
        now: Optional[datetime] = None,
    ) -> ThreatIntelReport:
        """
        Move a report along its lifecycle. Terminal states cannot be left.

        Publishing a report that still rests entirely on inferred relationships is allowed but
        recorded, because an inferred relationship must never be silently presented as confirmed.
        """
        moment = now or datetime.utcnow()
        with self._lock:
            current = self._reports.get(report_id)
            if current is None:
                raise ReportValidationError(f"unknown report_id {report_id!r}")
            if current.status is new_status:
                return current
            if current.status in (ReportStatus.PUBLISHED, ReportStatus.RETRACTED) and new_status not in (
                ReportStatus.RETRACTED,
            ):
                raise ReportValidationError(
                    f"report in terminal state {current.status.value!r} may only be retracted, "
                    f"not moved to {new_status.value!r}"
                )
            if current.status is ReportStatus.RETRACTED:
                raise ReportValidationError("retracted is terminal")

            transitioned = ThreatIntelReport(
                **{**current.model_dump(), "status": new_status, "updated_at": moment}
            )
            self._reports[report_id] = transitioned
            self._append_history(
                transitioned,
                change_type="status_changed" if new_status is not ReportStatus.RETRACTED else "retracted",
                change_basis=change_basis,
                actor=actor,
                previous_hash=current.content_hash,
                now=moment,
            )
            return transitioned

    # --------------------------------------------------------------- filtering

    def search(
        self,
        text: Optional[str] = None,
        kind: Optional[ReportKind] = None,
        classification: Optional[ReportClassification] = None,
        status: Optional[ReportStatus] = None,
        tag: Optional[str] = None,
        entity_id: Optional[str] = None,
        min_confidence: Optional[float] = None,
        stale_only: Optional[bool] = None,
        verification_mode: Optional[ReportVerificationMode] = None,
        limit: int = 100,
        offset: int = 0,
        as_of: Optional[datetime] = None,
    ) -> List[ThreatIntelReport]:
        """
        Search/filter foundation. Every criterion is optional and conjunctive.

        Text matching is case-insensitive over title, summary and body. No external search
        engine is used or required.
        """
        needle = text.strip().lower() if text and text.strip() else None
        limit = max(1, min(int(limit), MAX_SEARCH_LIMIT))
        offset = max(0, int(offset))

        with self._lock:
            candidates = list(self._reports.values())

        if entity_id is not None:
            wanted = set(self._by_entity.get(entity_id, []))
            candidates = [r for r in candidates if r.report_id in wanted]
        if kind is not None:
            candidates = [r for r in candidates if r.kind is kind]
        if classification is not None:
            candidates = [r for r in candidates if r.classification is classification]
        if status is not None:
            candidates = [r for r in candidates if r.status is status]
        if verification_mode is not None:
            candidates = [r for r in candidates if r.verification_mode is verification_mode]
        if tag is not None:
            needle_tag = tag.strip().lower()
            candidates = [r for r in candidates if any(t.lower() == needle_tag for t in r.tags)]
        if min_confidence is not None:
            candidates = [r for r in candidates if r.confidence >= min_confidence]
        if stale_only is not None:
            candidates = [r for r in candidates if r.is_stale(as_of) is stale_only]
        if needle is not None:
            candidates = [
                r
                for r in candidates
                if needle in r.title.lower() or needle in r.summary.lower() or needle in r.body.lower()
            ]

        candidates.sort(key=lambda r: (r.created_at, r.report_id), reverse=True)
        return candidates[offset : offset + limit]

    def stats(self) -> Dict[str, Any]:
        """Aggregate counts for observability. Purely derived, no side effects."""
        with self._lock:
            reports = list(self._reports.values())
            by_kind: Dict[str, int] = {}
            by_status: Dict[str, int] = {}
            by_class: Dict[str, int] = {}
            for r in reports:
                by_kind[r.kind.value] = by_kind.get(r.kind.value, 0) + 1
                by_status[r.status.value] = by_status.get(r.status.value, 0) + 1
                by_class[r.classification.value] = by_class.get(r.classification.value, 0) + 1
            return {
                "tenant_id": self.tenant_id,
                "report_count": len(reports),
                "by_kind": by_kind,
                "by_status": by_status,
                "by_classification": by_class,
                "history_entry_count": len(self._history),
                "distinct_content_hashes": len(self._content_index),
                "verification_modes": sorted({r.verification_mode.value for r in reports}),
                "note": "in-memory store; no report storage is mounted or deployed",
            }
