"""
Threat Intelligence Source Reliability, Freshness & Verification State

Repository:  oldman-088/cicc   Branch: arena/28e50255-cicc (Agent 6 backup)

Purpose
-------
Give every intelligence source an explicit, auditable reliability and freshness
record, and make verification-state transitions *evidence-gated* rather than
asserted. The core rule this module enforces:

    A source may never be reported as `live_verified` unless a
    `VerificationEvidence` record with a real observation reference is
    attached. There is no code path that sets `live_verified` from a flag.

This is what stops fixture-tested data from being presented as verified
intelligence anywhere downstream -- API envelopes, rollups, or dashboards.

No network I/O. Time is injected.
"""

from __future__ import annotations

import hashlib
from collections import deque
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Deque, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

EXPERIMENTAL_DEMO_DATA_ONLY = "EXPERIMENTAL_DEMO_DATA_ONLY"

VALID_VERIFICATION_MODES = ("fixture_tested", "oracle_verified", "live_verified")
VERIFICATION_RANK = {"fixture_tested": 0, "oracle_verified": 1, "live_verified": 2}

DEFAULT_FRESH_TTL_SECONDS = 3600
DEFAULT_STALE_AFTER_SECONDS = 86400
DEFAULT_EXPIRED_AFTER_SECONDS = 604800  # 7 days
DEFAULT_RELIABILITY_WINDOW = 50


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


class FreshnessState(str, Enum):
    FRESH = "fresh"
    AGING = "aging"
    STALE = "stale"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


class SourceAvailability(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class ReliabilityTier(str, Enum):
    """Coarse, human-readable reliability band."""

    TIER1_AUTHORITATIVE = "tier1_authoritative"   # >= 0.90
    TIER2_RELIABLE = "tier2_reliable"             # >= 0.70
    TIER3_UNPROVEN = "tier3_unproven"             # >= 0.40
    TIER4_UNRELIABLE = "tier4_unreliable"         # <  0.40
    UNSCORED = "unscored"


class SourceReliabilityError(Exception):
    """Base error for reliability/freshness handling."""


class VerificationPromotionError(SourceReliabilityError):
    """A verification-state promotion was attempted without sufficient evidence."""


# ============================================================================
# Verification evidence
# ============================================================================

class VerificationEvidence(BaseModel):
    """
    The proof required to promote a source above `fixture_tested`.

    ``observation_ref`` must point at something real and retrievable -- a
    persisted observation id, a fetched-document digest, a collection-run id.
    ``performed_by`` must identify who or what actually did the check. A
    promotion with a blank reference is rejected outright.
    """

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(..., min_length=1)
    target_verification_mode: str = Field(...)
    observation_ref: str = Field(..., min_length=1, description="Retrievable reference to the real observation")
    performed_by: str = Field(..., min_length=1)
    performed_at: str = Field(...)
    method: str = Field(..., min_length=1, description="e.g. live_http_fetch, oracle_cross_check, fixture_replay")
    notes: Optional[str] = Field(None)

    @field_validator("target_verification_mode")
    @classmethod
    def _check_mode(cls, v: str) -> str:
        if v not in VERIFICATION_RANK or v == "fixture_tested":
            raise ValueError(
                "target_verification_mode must be 'oracle_verified' or 'live_verified'; "
                "'fixture_tested' is the default and needs no evidence"
            )
        return v

    @field_validator("performed_by")
    @classmethod
    def _check_actor(cls, v: str) -> str:
        cleaned = " ".join(v.split())
        if not cleaned:
            raise ValueError("performed_by must identify a real actor")
        if cleaned.lower() in {"unknown", "n/a", "none", "anonymous", "self"}:
            raise ValueError("performed_by must be a specific, attributable actor")
        return cleaned

    @field_validator("observation_ref")
    @classmethod
    def _check_ref(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("observation_ref must not be blank")
        if cleaned.lower() in {"none", "n/a", "placeholder", "todo", "tbd"}:
            raise ValueError("observation_ref must reference a real observation")
        return cleaned


# ============================================================================
# Freshness policy
# ============================================================================

class FreshnessPolicy(BaseModel):
    """Age thresholds that classify how current a source's data is."""

    model_config = ConfigDict(extra="forbid")

    fresh_ttl_seconds: int = Field(DEFAULT_FRESH_TTL_SECONDS, ge=1)
    stale_after_seconds: int = Field(DEFAULT_STALE_AFTER_SECONDS, ge=1)
    expired_after_seconds: int = Field(DEFAULT_EXPIRED_AFTER_SECONDS, ge=1)

    @field_validator("stale_after_seconds")
    @classmethod
    def _ordering(cls, v: int, info) -> int:
        fresh = info.data.get("fresh_ttl_seconds")
        if fresh is not None and v <= fresh:
            raise ValueError("stale_after_seconds must be greater than fresh_ttl_seconds")
        return v

    @field_validator("expired_after_seconds")
    @classmethod
    def _ordering2(cls, v: int, info) -> int:
        stale = info.data.get("stale_after_seconds")
        if stale is not None and v <= stale:
            raise ValueError("expired_after_seconds must be greater than stale_after_seconds")
        return v

    def classify(self, age_seconds: Optional[float]) -> FreshnessState:
        if age_seconds is None:
            return FreshnessState.UNKNOWN
        if age_seconds < 0:
            # A future-dated collection timestamp is a clock or data error, not freshness.
            return FreshnessState.UNKNOWN
        if age_seconds <= self.fresh_ttl_seconds:
            return FreshnessState.FRESH
        if age_seconds <= self.stale_after_seconds:
            return FreshnessState.AGING
        if age_seconds <= self.expired_after_seconds:
            return FreshnessState.STALE
        return FreshnessState.EXPIRED


# ============================================================================
# Source record
# ============================================================================

class SourceOutcome(BaseModel):
    """One observed collection outcome for a source."""

    model_config = ConfigDict(extra="forbid")

    success: bool
    observed_at: str
    latency_ms: Optional[float] = Field(None, ge=0)
    records_ingested: int = Field(0, ge=0)
    verification_mode: str = Field("fixture_tested")
    note: Optional[str] = Field(None)

    @field_validator("verification_mode")
    @classmethod
    def _check_mode(cls, v: str) -> str:
        if v not in VERIFICATION_RANK:
            raise ValueError(f"verification_mode must be one of {list(VERIFICATION_RANK)}")
        return v


class SourceReliabilityRecord(BaseModel):
    """Aggregate reliability, freshness and verification state for one source."""

    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(..., min_length=1)
    tenant_id: str = Field(..., min_length=1)
    source_name: Optional[str] = Field(None)
    source_kind: str = Field("osint", description="osint | kev | vendor_advisory | mitre | internal")

    outcomes: List[SourceOutcome] = Field(default_factory=list)
    consecutive_failures: int = Field(0, ge=0)
    total_successes: int = Field(0, ge=0)
    total_failures: int = Field(0, ge=0)
    last_success_at: Optional[str] = Field(None)
    last_failure_at: Optional[str] = Field(None)
    last_collection_at: Optional[str] = Field(None)

    reliability_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    reliability_tier: ReliabilityTier = Field(ReliabilityTier.UNSCORED)
    availability: SourceAvailability = Field(SourceAvailability.UNKNOWN)
    freshness_state: FreshnessState = Field(FreshnessState.UNKNOWN)
    data_age_seconds: Optional[float] = Field(None)

    verification_mode: str = Field("fixture_tested")
    verification_evidence: List[VerificationEvidence] = Field(default_factory=list)
    experimental_label: Optional[str] = Field(EXPERIMENTAL_DEMO_DATA_ONLY)
    updated_at: str = Field(...)

    @field_validator("verification_mode")
    @classmethod
    def _check_mode(cls, v: str) -> str:
        if v not in VERIFICATION_RANK:
            raise ValueError(f"verification_mode must be one of {list(VERIFICATION_RANK)}")
        return v

    @field_validator("experimental_label")
    @classmethod
    def _check_label(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v != EXPERIMENTAL_DEMO_DATA_ONLY:
            raise ValueError("experimental_label must be EXPERIMENTAL_DEMO_DATA_ONLY or None")
        return v

    @property
    def is_scored(self) -> bool:
        return self.reliability_score is not None


# ============================================================================
# Service
# ============================================================================

class SourceReliabilityService:
    """
    Maintains per-source reliability, freshness and verification state.

    Reliability scoring
    -------------------
    The score is the success ratio over a bounded sliding window of recent
    outcomes, blended with a small penalty for a current failure streak so a
    source that is failing *right now* cannot coast on old successes::

        score = window_success_ratio * (1 - 0.5 * min(1, consecutive_failures / 5))

    With zero recorded outcomes the score is ``None`` and the tier is
    ``UNSCORED`` -- never a fabricated default.
    """

    def __init__(
        self,
        *,
        freshness_policy: Optional[FreshnessPolicy] = None,
        reliability_window: int = DEFAULT_RELIABILITY_WINDOW,
        degraded_threshold: float = 0.70,
        unavailable_threshold: float = 0.40,
        failure_streak_unavailable: int = 3,
    ):
        if reliability_window < 1:
            raise ValueError("reliability_window must be >= 1")
        self.freshness_policy = freshness_policy or FreshnessPolicy()
        self.reliability_window = reliability_window
        self.degraded_threshold = degraded_threshold
        self.unavailable_threshold = unavailable_threshold
        self.failure_streak_unavailable = max(1, failure_streak_unavailable)
        self._records: Dict[str, SourceReliabilityRecord] = {}
        self._history: Deque[SourceOutcome] = deque(maxlen=reliability_window)

    # ------------------------------------------------------------- registry

    def register_source(
        self,
        *,
        tenant_id: str,
        source_id: str,
        source_name: Optional[str] = None,
        source_kind: str = "osint",
        now: Optional[datetime] = None,
    ) -> SourceReliabilityRecord:
        key = self._key(tenant_id, source_id)
        existing = self._records.get(key)
        if existing is not None:
            return existing
        record = SourceReliabilityRecord(
            source_id=source_id,
            tenant_id=tenant_id,
            source_name=source_name,
            source_kind=source_kind,
            updated_at=_iso(now or utcnow()),
        )
        self._records[key] = record
        return record

    def get(self, tenant_id: str, source_id: str) -> Optional[SourceReliabilityRecord]:
        return self._records.get(self._key(tenant_id, source_id))

    def list_sources(self, tenant_id: Optional[str] = None) -> List[SourceReliabilityRecord]:
        records = list(self._records.values())
        if tenant_id is not None:
            records = [r for r in records if r.tenant_id == tenant_id]
        return sorted(records, key=lambda r: (r.tenant_id, r.source_id))

    @staticmethod
    def _key(tenant_id: str, source_id: str) -> str:
        if not tenant_id:
            raise SourceReliabilityError("tenant_id is required")
        if not source_id:
            raise SourceReliabilityError("source_id is required")
        return f"{tenant_id}\x00{source_id}"

    # ----------------------------------------------------------- outcomes

    def record_outcome(
        self,
        *,
        tenant_id: str,
        source_id: str,
        success: bool,
        latency_ms: Optional[float] = None,
        records_ingested: int = 0,
        verification_mode: str = "fixture_tested",
        note: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> SourceReliabilityRecord:
        """Record one collection outcome and recompute the aggregate state."""
        moment = now or utcnow()
        record = self.register_source(
            tenant_id=tenant_id, source_id=source_id, now=moment
        )
        outcome = SourceOutcome(
            success=success,
            observed_at=_iso(moment),
            latency_ms=latency_ms,
            records_ingested=records_ingested,
            verification_mode=verification_mode,
            note=(note or "")[:300] or None,
        )
        record.outcomes.append(outcome)
        if len(record.outcomes) > self.reliability_window:
            record.outcomes = record.outcomes[-self.reliability_window:]

        if success:
            record.total_successes += 1
            record.consecutive_failures = 0
            record.last_success_at = outcome.observed_at
        else:
            record.total_failures += 1
            record.consecutive_failures += 1
            record.last_failure_at = outcome.observed_at

        record.last_collection_at = outcome.observed_at
        record.updated_at = _iso(moment)
        self._recompute(record, moment)
        return record

    def _recompute(self, record: SourceReliabilityRecord, moment: datetime) -> None:
        window = record.outcomes[-self.reliability_window:]
        if not window:
            record.reliability_score = None
            record.reliability_tier = ReliabilityTier.UNSCORED
            record.availability = SourceAvailability.UNKNOWN
        else:
            ratio = sum(1 for o in window if o.success) / len(window)
            streak_penalty = 0.5 * min(1.0, record.consecutive_failures / 5.0)
            score = max(0.0, min(1.0, ratio * (1.0 - streak_penalty)))
            record.reliability_score = round(score, 4)
            record.reliability_tier = self._tier_for(score)

            if record.consecutive_failures >= self.failure_streak_unavailable:
                record.availability = SourceAvailability.UNAVAILABLE
            elif score < self.unavailable_threshold:
                record.availability = SourceAvailability.UNAVAILABLE
            elif score < self.degraded_threshold:
                record.availability = SourceAvailability.DEGRADED
            else:
                record.availability = SourceAvailability.HEALTHY

        # Freshness is driven by the last successful collection, not the last
        # attempt: a source that keeps failing is not "fresh".
        reference = record.last_success_at
        if reference is None:
            record.data_age_seconds = None
            record.freshness_state = FreshnessState.UNKNOWN
        else:
            age = (moment - datetime.fromisoformat(reference)).total_seconds()
            record.data_age_seconds = round(age, 3)
            record.freshness_state = self.freshness_policy.classify(age)

    @staticmethod
    def _tier_for(score: float) -> ReliabilityTier:
        if score >= 0.90:
            return ReliabilityTier.TIER1_AUTHORITATIVE
        if score >= 0.70:
            return ReliabilityTier.TIER2_RELIABLE
        if score >= 0.40:
            return ReliabilityTier.TIER3_UNPROVEN
        return ReliabilityTier.TIER4_UNRELIABLE

    # ------------------------------------------------------ verification

    def promote_verification(
        self,
        *,
        tenant_id: str,
        source_id: str,
        target_mode: str,
        observation_ref: str,
        performed_by: str,
        method: str,
        evidence_id: Optional[str] = None,
        notes: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> SourceReliabilityRecord:
        """
        Promote a source's verification mode -- only with real evidence.

        Rules enforced here:
        * `observation_ref` and `performed_by` must be specific and attributable.
        * Promotion may move up one rank at a time: `fixture_tested` ->
          `oracle_verified` -> `live_verified`. Skipping a step is rejected.
        * Demotion back to `fixture_tested` is always allowed and needs no
          evidence, because it is the conservative direction.
        * Every promotion is retained in `verification_evidence` permanently.
        """
        moment = now or utcnow()
        record = self.register_source(tenant_id=tenant_id, source_id=source_id, now=moment)

        current_rank = VERIFICATION_RANK[record.verification_mode]
        target_rank = VERIFICATION_RANK.get(target_mode)
        if target_rank is None:
            raise VerificationPromotionError(f"Unknown verification mode: {target_mode}")

        if target_rank < current_rank:
            record.verification_mode = target_mode
            record.updated_at = _iso(moment)
            return record

        if target_rank == current_rank:
            raise VerificationPromotionError(
                f"Source is already '{target_mode}'; nothing to promote"
            )

        if target_rank > current_rank + 1:
            raise VerificationPromotionError(
                f"Cannot skip verification steps: '{record.verification_mode}' -> "
                f"'{target_mode}'. Promote one step at a time."
            )

        evidence = VerificationEvidence(
            evidence_id=evidence_id or hashlib.sha256(
                f"{record.source_id}|{target_mode}|{observation_ref}|{moment.isoformat()}"
                .encode("utf-8")
            ).hexdigest()[:16],
            target_verification_mode=target_mode,
            observation_ref=observation_ref,
            performed_by=performed_by,
            performed_at=_iso(moment),
            method=method,
            notes=(notes or "")[:500] or None,
        )
        record.verification_evidence.append(evidence)
        record.verification_mode = target_mode
        record.updated_at = _iso(moment)
        return record

    def demote_to_fixture(self, *, tenant_id: str, source_id: str,
                          now: Optional[datetime] = None) -> SourceReliabilityRecord:
        """Force a source back to `fixture_tested` (conservative direction)."""
        moment = now or utcnow()
        record = self.register_source(tenant_id=tenant_id, source_id=source_id, now=moment)
        record.verification_mode = "fixture_tested"
        record.updated_at = _iso(moment)
        return record

    # ------------------------------------------------------------- reports

    def health_report(self, *, tenant_id: Optional[str] = None,
                      now: Optional[datetime] = None) -> Dict[str, Any]:
        """Aggregate view suitable for an operations dashboard."""
        moment = now or utcnow()
        records = self.list_sources(tenant_id)
        # Recompute freshness against the report time so a stale source that
        # has had no new outcomes still reports correctly.
        for record in records:
            self._recompute(record, moment)

        by_tier: Dict[str, int] = {t.value: 0 for t in ReliabilityTier}
        by_availability: Dict[str, int] = {a.value: 0 for a in SourceAvailability}
        by_freshness: Dict[str, int] = {f.value: 0 for f in FreshnessState}
        by_verification: Dict[str, int] = {m: 0 for m in VALID_VERIFICATION_MODES}
        for record in records:
            by_tier[record.reliability_tier.value] += 1
            by_availability[record.availability.value] += 1
            by_freshness[record.freshness_state.value] += 1
            by_verification[record.verification_mode] += 1

        return {
            "generated_at": _iso(moment),
            "total_sources": len(records),
            "by_tier": by_tier,
            "by_availability": by_availability,
            "by_freshness": by_freshness,
            "by_verification_mode": by_verification,
            "live_verified_sources": by_verification["live_verified"],
            "experimental_label": EXPERIMENTAL_DEMO_DATA_ONLY,
            "sources": [r.model_dump(mode="json") for r in records],
        }

    def confidence_adjustment(self, tenant_id: str, source_id: str,
                              base_confidence: float) -> Dict[str, Any]:
        """
        Reliability- and freshness-weighted view of a source's confidence.

        Returns the inputs alongside the adjusted value so a consumer can see
        exactly what was applied. An unscored source is NOT silently trusted:
        it is reported with ``applied=False`` and the base value untouched.
        """
        record = self.get(tenant_id, source_id)
        if record is None or not record.is_scored:
            return {
                "source_id": source_id,
                "base_confidence": base_confidence,
                "adjusted_confidence": base_confidence,
                "reliability_score": None,
                "freshness_state": record.freshness_state.value if record else "unknown",
                "applied": False,
                "reason": "source_unscored",
            }

        freshness_factor = {
            FreshnessState.FRESH: 1.0,
            FreshnessState.AGING: 0.95,
            FreshnessState.STALE: 0.80,
            FreshnessState.EXPIRED: 0.50,
            FreshnessState.UNKNOWN: 0.75,
        }[record.freshness_state]

        adjusted = max(0.0, min(1.0, base_confidence * record.reliability_score * freshness_factor))
        return {
            "source_id": source_id,
            "base_confidence": round(base_confidence, 4),
            "adjusted_confidence": round(adjusted, 4),
            "reliability_score": record.reliability_score,
            "reliability_tier": record.reliability_tier.value,
            "availability": record.availability.value,
            "freshness_state": record.freshness_state.value,
            "freshness_factor": freshness_factor,
            "data_age_seconds": record.data_age_seconds,
            "verification_mode": record.verification_mode,
            "applied": True,
        }
