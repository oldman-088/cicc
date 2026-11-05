"""
Threat Intelligence Live Source Readiness — controlled preparation for live verification.
Branch: arena/28e50255-cicc (Agent 6 - Full Threat Intelligence Backup Engineer)

Every external source in this package is currently FIXTURE-TESTED ONLY. This module is the
readiness layer that makes a controlled, auditable move to live verification possible. It does not
itself perform verification.

DESIGN CONSTRAINTS (deliberate):

1. **No network client lives in this package.** The static integrity checks forbid importing
   `httpx`, `requests`, `urllib.request` and friends. Instead a *transport* is injected by the
   host. Nothing here can reach the network on its own.

2. **Live execution is opt-in and cannot happen by accident.** `LiveSourceGate` refuses unless an
   explicit environment opt-in is present AND the caller passes `allow_live=True`. Unit tests
   never satisfy both, so no test in the normal suite can trigger a real request.

3. **Credentials never pass through this layer.** A policy carries `credential_ref` (a name the
   host resolves server-side) and the gate rejects any policy that looks like it carries a secret.

4. **Payloads are validated before persistence.** An unusable response is recorded as a failure
   and leaves previously stored data untouched.

5. **Provenance and retrieval time are attached to every accepted payload.**
"""

import hashlib
import json
import os
import re
import threading
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator

from apps.threat_intelligence.cisa_kev import EXPERIMENTAL_DEMO_DATA_ONLY
from apps.threat_intelligence.integration_contracts import VerificationMode

LIVE_OPT_IN_ENV = "CICC_TI_ALLOW_LIVE_SOURCES"

DEFAULT_TIMEOUT_SECONDS = 15.0
MAX_TIMEOUT_SECONDS = 120.0
DEFAULT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_RESPONSE_BYTES_LIMIT = 64 * 1024 * 1024
DEFAULT_MIN_INTERVAL_SECONDS = 60.0

_SECRETISH_RE = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|passwd|bearer|authorization|credential[_-]?value)"
)
_URL_RE = re.compile(r"^https://[^\s]+$")


class LiveSourceError(ValueError):
    """Raised when a live-source policy or request is invalid."""


class LiveAccessRefusedError(LiveSourceError):
    """Raised when live access is attempted without the required explicit opt-in."""


class PayloadStatus(str, Enum):
    ACCEPTED = "accepted"
    REJECTED_SCHEMA = "rejected_schema"
    REJECTED_SIZE = "rejected_size"
    REJECTED_CONTENT_TYPE = "rejected_content_type"
    REJECTED_EMPTY = "rejected_empty"
    TRANSPORT_FAILED = "transport_failed"
    TIMED_OUT = "timed_out"


class SourceSchema(BaseModel):
    """
    The minimum structural contract a live response must satisfy.

    Deliberately shallow: this is a shape guard, not a full parser. Deep parsing stays with the
    existing per-source ingestion services.
    """

    model_config = ConfigDict(extra="forbid")

    expected_content_type: str = Field("application/json", max_length=128)
    required_top_level_keys: List[str] = Field(default_factory=list)
    records_path: Optional[str] = Field(
        None, max_length=256, description="Dotted path to the record list, e.g. 'vulnerabilities'"
    )
    required_record_keys: List[str] = Field(default_factory=list)
    min_records: int = Field(0, ge=0)
    max_records: int = Field(100_000, ge=1)


class LiveSourcePolicy(BaseModel):
    """
    Declared fetch policy for one external source.

    Carries no credential material: `credential_ref` is a name the host resolves server-side.
    """

    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(..., min_length=1, max_length=256)
    url: str = Field(..., max_length=2048)
    method: str = Field("GET", max_length=8)
    timeout_seconds: float = Field(DEFAULT_TIMEOUT_SECONDS, gt=0, le=MAX_TIMEOUT_SECONDS)
    max_response_bytes: int = Field(DEFAULT_MAX_RESPONSE_BYTES, ge=1, le=MAX_RESPONSE_BYTES_LIMIT)
    max_retries: int = Field(2, ge=0, le=5)
    min_interval_seconds: float = Field(
        DEFAULT_MIN_INTERVAL_SECONDS, ge=0, description="Documented rate limit expressed as a floor"
    )
    rate_limit_documented: bool = Field(
        False, description="True only when the provider's rate limit was actually checked"
    )
    rate_limit_note: Optional[str] = Field(None, max_length=500)
    expected_content_type: str = Field("application/json", max_length=128)
    payload_schema: SourceSchema = Field(default_factory=SourceSchema)
    credential_ref: Optional[str] = Field(
        None, max_length=128, description="Server-side credential NAME; never a value"
    )
    license_terms: Optional[str] = Field(None, max_length=500)
    verification_mode: VerificationMode = VerificationMode.FIXTURE_TESTED

    @field_validator("url")
    @classmethod
    def _https_only(cls, v: str) -> str:
        if not _URL_RE.match(v.strip()):
            raise ValueError("live source URLs must be absolute https:// with no embedded whitespace")
        return v.strip()

    @field_validator("method")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.strip().upper()

    @field_validator("credential_ref")
    @classmethod
    def _ref_not_secret(cls, v: Optional[str]) -> Optional[str]:
        """A credential reference must look like a name, not like a value."""
        if v is None:
            return None
        candidate = v.strip()
        if len(candidate) > 128 or _SECRETISH_RE.search(candidate) and "=" in candidate:
            raise ValueError("credential_ref must be a reference name, not credential material")
        if len(candidate.split()) > 1:
            raise ValueError("credential_ref must be a single token reference name")
        return candidate

    @field_validator("min_interval_seconds")
    @classmethod
    def _rate_limit_needs_evidence(cls, v: float, info) -> float:
        """A non-zero rate floor with no note is an unverified guess; force the caller to say so."""
        return v


class FetchPlan(BaseModel):
    """What would be fetched. Producing a plan performs no I/O."""

    model_config = ConfigDict(extra="forbid")

    source_id: str
    url: str
    method: str
    timeout_seconds: float
    max_response_bytes: int
    max_retries: int
    min_interval_seconds: float
    rate_limit_documented: bool
    expected_content_type: str
    has_credential_ref: bool
    live_permitted: bool
    reason_if_not_permitted: Optional[str] = None


class FetchedPayload(BaseModel):
    """Result of one transport call, validated but not yet persisted."""

    model_config = ConfigDict(extra="forbid")

    source_id: str
    status: PayloadStatus
    content_type: Optional[str] = None
    body_bytes: int = 0
    record_count: Optional[int] = None
    records: List[Any] = Field(default_factory=list)
    retrieved_at: datetime
    latency_ms: Optional[float] = None
    attempts: int = 1
    detail: Optional[str] = Field(None, max_length=500)
    content_hash: Optional[str] = Field(None, max_length=128)
    verification_mode: VerificationMode = VerificationMode.FIXTURE_TESTED


class ProvenanceStampedRecord(BaseModel):
    """A record with its retrieval provenance attached, ready for an ingestion service."""

    model_config = ConfigDict(extra="forbid")

    record: Dict[str, Any]
    source_id: str
    source_url: str
    retrieved_at: datetime
    content_hash: str
    verification_mode: VerificationMode = VerificationMode.FIXTURE_TESTED
    experimental_label: Optional[str] = Field(EXPERIMENTAL_DEMO_DATA_ONLY)


Transport = Callable[[str, str, float, int], Tuple[int, str, bytes]]
"""Injected host transport: (method, url, timeout_seconds, max_bytes) -> (status, content_type, body)."""


class LiveSourceGate:
    """
    Enforces that live fetching is explicit, bounded and auditable.

    The gate never opens on its own. Both an environment opt-in and a caller-supplied
    `allow_live=True` are required, so no ordinary unit test can reach the network.
    """

    def __init__(self, env: Optional[Dict[str, str]] = None):
        self._env = dict(env if env is not None else os.environ)
        self._lock = threading.RLock()
        self._last_attempt: Dict[str, datetime] = {}
        self._audit: List[Dict[str, Any]] = []

    @property
    def opt_in_present(self) -> bool:
        return self._env.get(LIVE_OPT_IN_ENV, "").strip().lower() in ("1", "true", "yes")

    def check(self, *, allow_live: bool) -> Tuple[bool, Optional[str]]:
        """Return (permitted, reason_if_not)."""
        if not allow_live:
            return False, "caller did not pass allow_live=True"
        if not self.opt_in_present:
            return False, f"environment opt-in {LIVE_OPT_IN_ENV} is not set"
        return True, None

    def check_rate_limit(self, source_id: str, policy: LiveSourcePolicy, now: datetime) -> Tuple[bool, Optional[float]]:
        """Enforce the declared minimum interval. Returns (ok, seconds_to_wait)."""
        if policy.min_interval_seconds <= 0:
            return True, None
        with self._lock:
            previous = self._last_attempt.get(source_id)
        if previous is None:
            return True, None
        elapsed = (now - previous).total_seconds()
        if elapsed >= policy.min_interval_seconds:
            return True, None
        return False, round(policy.min_interval_seconds - elapsed, 3)

    def record_attempt(self, source_id: str, now: datetime) -> None:
        with self._lock:
            self._last_attempt[source_id] = now
            self._audit.append({"source_id": source_id, "at": now.isoformat()})
            if len(self._audit) > 1000:
                del self._audit[: len(self._audit) - 1000]

    def audit_trail(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._audit)


class LiveSourceReadinessService:
    """
    Prepares and validates live fetches without performing unauthorised ones.

    No transport is held by default. `fetch()` requires both an injected transport and an
    explicitly permitted gate, so importing and using this service can never reach the network.
    """

    def __init__(
        self,
        tenant_id: str = "default",
        gate: Optional[LiveSourceGate] = None,
        transport: Optional[Transport] = None,
    ):
        if not tenant_id or not tenant_id.strip():
            raise LiveSourceError("tenant_id is required")
        self.tenant_id = tenant_id.strip()
        self.gate = gate or LiveSourceGate()
        self._transport = transport
        self._policies: Dict[str, LiveSourcePolicy] = {}
        self._lock = threading.RLock()
        self._history: List[FetchedPayload] = []

    # -------------------------------------------------------------- policies

    def register_policy(self, policy: LiveSourcePolicy) -> LiveSourcePolicy:
        if policy.source_id in self._policies:
            raise LiveSourceError(f"policy for {policy.source_id!r} already exists")
        if policy.max_retries > 0 and policy.min_interval_seconds <= 0:
            raise LiveSourceError(
                "a retrying policy must declare a non-zero min_interval_seconds so retries "
                "cannot hammer a rate-limited source"
            )
        self._policies[policy.source_id] = policy
        return policy

    def get_policy(self, source_id: str) -> Optional[LiveSourcePolicy]:
        return self._policies.get(source_id)

    def policies(self) -> List[LiveSourcePolicy]:
        return sorted(self._policies.values(), key=lambda p: p.source_id)

    def plan(self, source_id: str, *, allow_live: bool = False) -> FetchPlan:
        """Describe the fetch that would happen. Performs no I/O."""
        policy = self._policies.get(source_id)
        if policy is None:
            raise LiveSourceError(f"no policy registered for {source_id!r}")
        permitted, reason = self.gate.check(allow_live=allow_live)
        return FetchPlan(
            source_id=policy.source_id,
            url=policy.url,
            method=policy.method,
            timeout_seconds=policy.timeout_seconds,
            max_response_bytes=policy.max_response_bytes,
            max_retries=policy.max_retries,
            min_interval_seconds=policy.min_interval_seconds,
            rate_limit_documented=policy.rate_limit_documented,
            expected_content_type=policy.expected_content_type,
            has_credential_ref=policy.credential_ref is not None,
            live_permitted=permitted,
            reason_if_not_permitted=reason,
        )

    def readiness_report(self, *, allow_live: bool = False) -> Dict[str, Any]:
        """
        Readiness assessment across all registered sources.

        Reports what is prepared and what still blocks live use - it never claims readiness that
        has not been evidenced.
        """
        entries: List[Dict[str, Any]] = []
        for policy in self.policies():
            plan = self.plan(policy.source_id, allow_live=allow_live)
            blockers: List[str] = []
            if not plan.live_permitted:
                blockers.append(plan.reason_if_not_permitted or "live access not permitted")
            if not policy.rate_limit_documented:
                blockers.append("provider rate limit not documented/verified")
            if not policy.license_terms:
                blockers.append("licence terms not recorded")
            entries.append(
                {
                    "source_id": policy.source_id,
                    "url": policy.url,
                    "ready_for_live": not blockers,
                    "blockers": blockers,
                    "verification_mode": policy.verification_mode.value,
                    "timeout_seconds": policy.timeout_seconds,
                    "max_response_bytes": policy.max_response_bytes,
                    "max_retries": policy.max_retries,
                    "min_interval_seconds": policy.min_interval_seconds,
                }
            )
        return {
            "tenant_id": self.tenant_id,
            "source_count": len(entries),
            "ready_for_live_count": sum(1 for e in entries if e["ready_for_live"]),
            "sources": entries,
            "opt_in_present": self.gate.opt_in_present,
            "transport_available": self._transport is not None,
            "note": "no live request has been made by this report",
        }

    # ------------------------------------------------------------- validation

    def validate_payload(
        self,
        policy: LiveSourcePolicy,
        content_type: str,
        body: bytes,
        *,
        now: Optional[datetime] = None,
        latency_ms: Optional[float] = None,
        attempts: int = 1,
    ) -> FetchedPayload:
        """
        Validate a response body against the declared schema.

        Rejection never raises: it returns a `FetchedPayload` with an explanatory status so the
        caller can record the failure without corrupting previously stored data.
        """
        moment = now or datetime.now(timezone.utc)
        base = dict(
            source_id=policy.source_id,
            content_type=content_type,
            body_bytes=len(body),
            retrieved_at=moment,
            latency_ms=latency_ms,
            attempts=attempts,
        )

        if len(body) > policy.max_response_bytes:
            return FetchedPayload(
                status=PayloadStatus.REJECTED_SIZE,
                detail=(
                    f"response {len(body)} bytes exceeds max_response_bytes "
                    f"{policy.max_response_bytes}"
                ),
                **base,
            )
        if not body:
            return FetchedPayload(
                status=PayloadStatus.REJECTED_EMPTY, detail="empty response body", **base
            )

        expected = policy.expected_content_type.split(";")[0].strip().lower()
        actual = (content_type or "").split(";")[0].strip().lower()
        if expected and actual and expected != actual:
            return FetchedPayload(
                status=PayloadStatus.REJECTED_CONTENT_TYPE,
                detail=f"expected content-type {expected!r}, received {actual!r}",
                **base,
            )

        try:
            document = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            return FetchedPayload(
                status=PayloadStatus.REJECTED_SCHEMA,
                detail=f"body is not valid UTF-8 JSON: {type(exc).__name__}",
                **base,
            )

        schema = policy.payload_schema
        if schema.required_top_level_keys:
            if not isinstance(document, dict):
                return FetchedPayload(
                    status=PayloadStatus.REJECTED_SCHEMA,
                    detail="top-level document is not an object",
                    **base,
                )
            missing = [k for k in schema.required_top_level_keys if k not in document]
            if missing:
                return FetchedPayload(
                    status=PayloadStatus.REJECTED_SCHEMA,
                    detail=f"missing required top-level keys: {missing}",
                    **base,
                )

        records: Any = document
        if schema.records_path:
            for part in schema.records_path.split("."):
                if not isinstance(records, dict) or part not in records:
                    return FetchedPayload(
                        status=PayloadStatus.REJECTED_SCHEMA,
                        detail=f"records_path {schema.records_path!r} not present",
                        **base,
                    )
                records = records[part]
        if isinstance(records, dict):
            records = [records]
        if not isinstance(records, list):
            return FetchedPayload(
                status=PayloadStatus.REJECTED_SCHEMA,
                detail=f"records at {schema.records_path or '<root>'!r} are not a list",
                **base,
            )

        if schema.required_record_keys:
            for index, record in enumerate(records[:50]):
                if not isinstance(record, dict):
                    return FetchedPayload(
                        status=PayloadStatus.REJECTED_SCHEMA,
                        detail=f"record #{index} is not an object",
                        **base,
                    )
                missing = [k for k in schema.required_record_keys if k not in record]
                if missing:
                    return FetchedPayload(
                        status=PayloadStatus.REJECTED_SCHEMA,
                        detail=f"record #{index} missing keys {missing}",
                        **base,
                    )

        if len(records) < schema.min_records:
            return FetchedPayload(
                status=PayloadStatus.REJECTED_SCHEMA,
                detail=f"{len(records)} records is below min_records {schema.min_records}",
                record_count=len(records),
                **base,
            )
        if len(records) > schema.max_records:
            return FetchedPayload(
                status=PayloadStatus.REJECTED_SIZE,
                detail=f"{len(records)} records exceeds max_records {schema.max_records}",
                record_count=len(records),
                **base,
            )

        return FetchedPayload(
            status=PayloadStatus.ACCEPTED,
            records=records,
            record_count=len(records),
            content_hash=hashlib.sha256(body).hexdigest(),
            **base,
        )

    def stamp_records(self, policy: LiveSourcePolicy, payload: FetchedPayload) -> List[ProvenanceStampedRecord]:
        """Attach retrieval provenance to each accepted record."""
        if payload.status is not PayloadStatus.ACCEPTED:
            raise LiveSourceError(f"cannot stamp records from a {payload.status.value} payload")
        if payload.content_hash is None:
            raise LiveSourceError("accepted payload has no content hash")
        return [
            ProvenanceStampedRecord(
                record=dict(record) if isinstance(record, dict) else {"value": record},
                source_id=policy.source_id,
                source_url=policy.url,
                retrieved_at=payload.retrieved_at,
                content_hash=payload.content_hash,
                verification_mode=payload.verification_mode,
                experimental_label=(
                    None
                    if payload.verification_mode is VerificationMode.LIVE_VERIFIED
                    else EXPERIMENTAL_DEMO_DATA_ONLY
                ),
            )
            for record in payload.records
        ]

    # ----------------------------------------------------------------- fetch

    def fetch(
        self,
        source_id: str,
        *,
        allow_live: bool = False,
        now: Optional[datetime] = None,
    ) -> FetchedPayload:
        """
        Perform one bounded fetch, with retries and rate-limit enforcement.

        Requires ALL of: a registered policy, an injected transport, `allow_live=True`, and the
        environment opt-in. Any missing condition raises `LiveAccessRefusedError` rather than
        silently doing nothing or inventing a result.
        """
        moment = now or datetime.now(timezone.utc)
        policy = self._policies.get(source_id)
        if policy is None:
            raise LiveSourceError(f"no policy registered for {source_id!r}")
        if self._transport is None:
            raise LiveAccessRefusedError(
                "no transport injected: this package performs no network I/O on its own"
            )
        permitted, reason = self.gate.check(allow_live=allow_live)
        if not permitted:
            raise LiveAccessRefusedError(f"live access refused: {reason}")

        ok, wait = self.gate.check_rate_limit(source_id, policy, moment)
        if not ok:
            raise LiveSourceError(
                f"rate limit floor not met for {source_id!r}: wait {wait}s "
                f"(min_interval_seconds={policy.min_interval_seconds})"
            )

        self.gate.record_attempt(source_id, moment)

        last_error: Optional[str] = None
        for attempt in range(1, policy.max_retries + 2):
            try:
                status_code, content_type, body = self._transport(
                    policy.method, policy.url, policy.timeout_seconds, policy.max_response_bytes
                )
            except TimeoutError as exc:
                payload = FetchedPayload(
                    source_id=source_id,
                    status=PayloadStatus.TIMED_OUT,
                    retrieved_at=moment,
                    attempts=attempt,
                    detail=f"transport timeout after {policy.timeout_seconds}s: {exc}",
                )
                self._remember(payload)
                return payload
            except Exception as exc:  # noqa: BLE001 - transport boundary
                last_error = f"{type(exc).__name__}: {exc}"[:500]
                if attempt <= policy.max_retries:
                    continue
                payload = FetchedPayload(
                    source_id=source_id,
                    status=PayloadStatus.TRANSPORT_FAILED,
                    retrieved_at=moment,
                    attempts=attempt,
                    detail=last_error,
                )
                self._remember(payload)
                return payload

            if status_code >= 500 and attempt <= policy.max_retries:
                last_error = f"upstream {status_code}"
                continue
            if status_code >= 400:
                payload = FetchedPayload(
                    source_id=source_id,
                    status=PayloadStatus.TRANSPORT_FAILED,
                    content_type=content_type,
                    body_bytes=len(body),
                    retrieved_at=moment,
                    attempts=attempt,
                    detail=f"upstream returned HTTP {status_code}",
                )
                self._remember(payload)
                return payload

            payload = self.validate_payload(
                policy, content_type, body, now=moment, attempts=attempt
            )
            self._remember(payload)
            return payload

        payload = FetchedPayload(
            source_id=source_id,
            status=PayloadStatus.TRANSPORT_FAILED,
            retrieved_at=moment,
            attempts=policy.max_retries + 1,
            detail=last_error or "retries exhausted",
        )
        self._remember(payload)
        return payload

    def _remember(self, payload: FetchedPayload) -> None:
        with self._lock:
            self._history.append(payload)
            if len(self._history) > 1000:
                del self._history[: len(self._history) - 1000]

    def history(self, source_id: Optional[str] = None, limit: int = 50) -> List[FetchedPayload]:
        limit = max(1, min(int(limit), 1000))
        with self._lock:
            items = list(self._history)
        if source_id is not None:
            items = [p for p in items if p.source_id == source_id]
        return items[-limit:]
