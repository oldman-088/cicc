"""
Indicator Enrichment — Domain B items 15-18 (Master Prompt README.md lines 231-234).

Branch: arena/28e50255-cicc (Agent 6 - Full Threat Intelligence Backup Engineer)

    15. IP Intelligence
    16. Domain Intelligence
    17. URL Intelligence
    18. File Hash Intelligence

Before this module these indicators existed only as typed values on ``OSINTIndicatorModel``. An
indicator that has been *seen* is not an indicator that has been *enriched*: there was nowhere to
put an ASN, a WHOIS record, a URLhaus submission, or a malware family attribution, and nowhere to
record that two sources disagree about any of them.

This adds four enrichment services over the existing indicator types. Normalization is reused
from ``osint_sources.OSINTIngestionService.refang_and_normalize_indicator`` rather than
reimplemented, so a defanged indicator normalizes identically everywhere in the package.

Why one module rather than four: all four share the same provenance, confidence-capping,
observation-history and verification machinery. Copying that four times would mean four places
to get the honesty rules wrong. The capabilities themselves are independent and separately
addressable.

HONESTY CONSTRAINTS (enforced in code):

1. **Nothing is invented.** Every service is a *recorder* of enrichment supplied by a caller.
   There is no built-in ASN table, no WHOIS client, no geolocation database, no malware family
   list. An enrichment that was never recorded is absent, never guessed.
2. **Unknown stays unknown.** A hash with no recorded family attribution reports ``family=None``
   and ``attribution_state=UNKNOWN``. It is never defaulted to a plausible family.
3. **Conflicting attribution is preserved.** Two sources naming different families for one hash
   produce a conflict record and ``attribution_state=CONFLICTING``; neither is overwritten.
4. **Verification mode defaults to ``fixture_tested``.** ``live_verified`` is only settable
   through a gated live fetch that actually succeeded.
5. **Confidence is capped by origin**, and the clamping is reported rather than silent.
6. **Live access is double-gated.** ``live_*`` methods delegate to
   ``live_source_readiness.LiveSourceReadinessService``, which requires both the environment
   opt-in and an explicit ``allow_live=True``. This module holds no network client.
"""

from __future__ import annotations

import ipaddress
import re
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from apps.threat_intelligence.cisa_kev import EXPERIMENTAL_DEMO_DATA_ONLY
from apps.threat_intelligence.integration_contracts import VerificationMode
from apps.threat_intelligence.live_source_readiness import (
    LiveAccessRefusedError,
    LiveSourceReadinessService,
    PayloadStatus,
)
from apps.threat_intelligence.malware_families import (
    ORIGIN_CONFIDENCE_CEILING,
    MalwareFamilyService,
    to_utc,
)
from apps.threat_intelligence.osint_sources import (
    SUPPORTED_OSINT_INDICATOR_TYPES,
    OSINTIngestionService,
)
from apps.threat_intelligence.relationship_analysis import AssertionOrigin, EvidenceItem

# --------------------------------------------------------------------------
# Limits and shared constants
# --------------------------------------------------------------------------

MAX_OBSERVATIONS_PER_INDICATOR = 500
MAX_EVIDENCE_PER_OBSERVATION = 50
MAX_SEARCH_LIMIT = 500
MAX_HISTORY_ENTRIES = 10_000
MAX_URL_LENGTH = 4_096
MAX_DOMAIN_LENGTH = 253
MAX_DNS_RECORDS_PER_DOMAIN = 1_000

#: Schemes this package will parse. Anything else is rejected rather than parsed optimistically.
ALLOWED_URL_SCHEMES = frozenset({"http", "https"})

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_MD5_RE = re.compile(r"^[a-f0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-f0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------

class IndicatorEnrichmentError(Exception):
    """Base error for indicator enrichment."""


class EnrichmentValidationError(IndicatorEnrichmentError, ValueError):
    """An indicator or enrichment record failed validation."""


class IndicatorNotFoundError(IndicatorEnrichmentError, KeyError):
    """The referenced indicator has no enrichment record in this tenant."""


# --------------------------------------------------------------------------
# Shared enums
# --------------------------------------------------------------------------

class EnrichmentState(str, Enum):
    """
    What is actually known about an indicator's enrichment.

    Kept distinct from a threat verdict on purpose: "we have no data" is not the same claim as
    "this is benign".
    """

    #: No enrichment recorded at all.
    UNKNOWN = "unknown"
    #: At least one enrichment recorded.
    ENRICHED = "enriched"
    #: Sources disagree; both views are preserved.
    CONFLICTING = "conflicting"
    #: Recorded enrichment is older than the caller's staleness horizon.
    STALE = "stale"


class ThreatVerdict(str, Enum):
    """A recorded verdict about an indicator. Never derived from an absence of data."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class DNSRecordType(str, Enum):
    A = "a"
    AAAA = "aaaa"
    CNAME = "cname"
    MX = "mx"
    NS = "ns"
    TXT = "txt"
    SOA = "soa"
    PTR = "ptr"


class DomainRelationshipKind(str, Enum):
    PARENT = "parent"
    SUBDOMAIN = "subdomain"
    SIBLING_NAMESERVER = "sibling_nameserver"
    SIBLING_REGISTRAR = "sibling_registrar"
    RESOLVES_TO = "resolves_to"
    REDIRECTS_TO = "redirects_to"


class HashAlgorithm(str, Enum):
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


# --------------------------------------------------------------------------
# Shared models
# --------------------------------------------------------------------------

class EnrichmentObservation(BaseModel):
    """
    One source's enrichment observation about one indicator, at one moment.

    Observations are the unit of provenance. They are appended, never edited, so the history of
    what each source said survives later disagreements.
    """

    model_config = ConfigDict(extra="forbid")

    observation_id: str = Field(..., min_length=1, max_length=256)
    indicator_type: str = Field(..., min_length=1, max_length=32)
    indicator_value: str = Field(..., min_length=1, max_length=MAX_URL_LENGTH)
    source_id: str = Field(..., min_length=1, max_length=256)
    source_reference: Optional[str] = Field(None, max_length=1024)
    origin: AssertionOrigin = AssertionOrigin.IMPORTED_UNVERIFIED
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    confidence_ceiling: float = Field(1.0, ge=0.0, le=1.0)
    confidence_was_clamped: bool = Field(False)
    verification_mode: VerificationMode = VerificationMode.FIXTURE_TESTED
    evidence: List[EvidenceItem] = Field(default_factory=list)
    observed_at: datetime = Field(default_factory=lambda: to_utc(None))
    recorded_at: datetime = Field(default_factory=lambda: to_utc(None))
    payload: Dict[str, Any] = Field(default_factory=dict, description="Source-supplied fields, verbatim")

    @field_validator("indicator_type")
    @classmethod
    def _known_type(cls, v: str) -> str:
        normalised = v.strip().lower()
        if normalised not in SUPPORTED_OSINT_INDICATOR_TYPES:
            raise ValueError(
                f"unsupported indicator_type {v!r}; must be one of {sorted(SUPPORTED_OSINT_INDICATOR_TYPES)}"
            )
        return normalised

    @field_validator("observed_at", "recorded_at")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        return to_utc(v)

    @field_validator("evidence")
    @classmethod
    def _cap(cls, v: List[EvidenceItem]) -> List[EvidenceItem]:
        if len(v) > MAX_EVIDENCE_PER_OBSERVATION:
            raise ValueError(
                f"an observation may carry at most {MAX_EVIDENCE_PER_OBSERVATION} evidence items, got {len(v)}"
            )
        return v

    @property
    def distinct_evidence_sources(self) -> int:
        refs = {e.source_ref for e in self.evidence if e.source_ref}
        if self.source_reference:
            refs.add(self.source_reference)
        return len(refs)


class IndicatorEnrichmentBase(BaseModel):
    """Fields every enrichment record shares."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(..., min_length=1, max_length=256)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: to_utc(None))
    updated_at: datetime = Field(default_factory=lambda: to_utc(None))
    experimental_label: Optional[str] = Field(None, max_length=64)

    @field_validator("first_seen", "last_seen", "created_at", "updated_at")
    @classmethod
    def _aware(cls, v: Optional[datetime]) -> Optional[datetime]:
        return None if v is None else to_utc(v)


class EnrichmentHistoryEntry(BaseModel):
    """Append-only record of one enrichment event."""

    model_config = ConfigDict(extra="forbid")

    entry_id: str = Field(..., min_length=1, max_length=256)
    indicator_type: str = Field(..., min_length=1, max_length=32)
    indicator_value: str = Field(..., min_length=1, max_length=MAX_URL_LENGTH)
    action: str = Field(..., min_length=1, max_length=64)
    source_id: Optional[str] = Field(None, max_length=256)
    detail: Optional[str] = Field(None, max_length=2000)
    recorded_at: datetime = Field(default_factory=lambda: to_utc(None))

    @field_validator("action")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.strip().lower()


class AttributionConflict(BaseModel):
    """
    Two or more sources disagreeing about one field of one indicator.

    Both values are preserved with their sources. Nothing is overwritten.
    """

    model_config = ConfigDict(extra="forbid")

    indicator_type: str = Field(..., min_length=1, max_length=32)
    indicator_value: str = Field(..., min_length=1, max_length=MAX_URL_LENGTH)
    field_name: str = Field(..., min_length=1, max_length=128)
    values: Tuple[Tuple[str, str], ...] = Field(..., min_length=2, description="(value, source_id) pairs")
    distinct_values: Tuple[str, ...] = Field(..., min_length=2)


# --------------------------------------------------------------------------
# Item 15 - IP Intelligence
# --------------------------------------------------------------------------

class ASNRecord(BaseModel):
    """Autonomous system ownership for an address or block. Always source-supplied."""

    model_config = ConfigDict(extra="forbid")

    asn: int = Field(..., ge=0, le=4_294_967_295)
    name: Optional[str] = Field(None, max_length=256)
    country: Optional[str] = Field(None, max_length=8)
    registry: Optional[str] = Field(None, max_length=32, description="ripencc | arin | apnic | lacnic | afrinic")
    source_id: str = Field(..., min_length=1, max_length=256)
    source_reference: Optional[str] = Field(None, max_length=1024)
    observed_at: datetime = Field(default_factory=lambda: to_utc(None))
    verified: bool = Field(False, description="True only when a cited source confirms it")

    @field_validator("name")
    @classmethod
    def _strip(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        stripped = v.strip()
        return stripped or None

    @model_validator(mode="after")
    def _verified_needs_a_source_reference(self) -> "ASNRecord":
        if self.verified and not self.source_reference:
            raise ValueError("an ASN record cannot be marked verified without a source reference")
        return self


class NetworkBlock(BaseModel):
    """The network block an address belongs to, as reported by a source."""

    model_config = ConfigDict(extra="forbid")

    cidr: str = Field(..., min_length=1, max_length=128)
    organisation: Optional[str] = Field(None, max_length=256)
    handle: Optional[str] = Field(None, max_length=128, description="RIR allocation handle")
    source_id: str = Field(..., min_length=1, max_length=256)
    observed_at: datetime = Field(default_factory=lambda: to_utc(None))

    @field_validator("cidr")
    @classmethod
    def _valid_cidr(cls, v: str) -> str:
        try:
            return str(ipaddress.ip_network(v.strip(), strict=False))
        except ValueError as exc:
            raise ValueError(f"invalid CIDR block: {v!r} ({exc})") from exc


class GeolocationEvidence(BaseModel):
    """
    A geolocation claim, with the accuracy the source itself declared.

    Geo-IP is an estimate. Carrying the source's stated accuracy keeps it an estimate rather
    than letting it harden into a fact about where an address physically is.
    """

    model_config = ConfigDict(extra="forbid")

    country: Optional[str] = Field(None, max_length=8)
    region: Optional[str] = Field(None, max_length=128)
    city: Optional[str] = Field(None, max_length=128)
    latitude: Optional[float] = Field(None, ge=-90.0, le=90.0)
    longitude: Optional[float] = Field(None, ge=-180.0, le=180.0)
    accuracy_radius_km: Optional[float] = Field(None, ge=0.0)
    source_id: str = Field(..., min_length=1, max_length=256)
    source_reference: Optional[str] = Field(None, max_length=1024)
    observed_at: datetime = Field(default_factory=lambda: to_utc(None))


class IPEnrichmentRecord(IndicatorEnrichmentBase):
    """Enrichment state for one IP address."""

    indicator_type: str = Field(..., pattern=r"^(ipv4|ipv6)$")
    address: str = Field(..., min_length=1, max_length=64)
    version: int = Field(..., ge=4, le=6)
    asn: Optional[ASNRecord] = None
    network: Optional[NetworkBlock] = None
    geolocation: Optional[GeolocationEvidence] = None
    is_private: bool = Field(False, description="Computed from the address itself, not from a source")
    is_global: bool = Field(False, description="Computed from the address itself, not from a source")
    verdict: ThreatVerdict = ThreatVerdict.UNKNOWN
    enrichment_state: EnrichmentState = EnrichmentState.UNKNOWN

    @property
    def provider(self) -> Optional[str]:
        """Best available provider attribution, or None if no source recorded one."""
        if self.network and self.network.organisation:
            return self.network.organisation
        if self.asn and self.asn.name:
            return self.asn.name
        return None


class IPIntelligenceService:
    """
    IP intelligence (Domain B item 15).

    Address classification (private, global, version) is computed from the address itself and is
    therefore trustworthy. ASN, network ownership and geolocation are *only* what a source
    reported; this service holds no built-in tables and will not infer them.
    """

    INDICATOR_TYPES = ("ipv4", "ipv6")

    def __init__(
        self,
        tenant_id: str = "default",
        live_readiness: Optional[LiveSourceReadinessService] = None,
    ) -> None:
        self.tenant_id = _require_tenant(tenant_id)
        self.live_readiness = live_readiness
        self._lock = threading.RLock()
        self._records: Dict[str, IPEnrichmentRecord] = {}
        self._observations: Dict[str, List[EnrichmentObservation]] = {}
        self._history: List[EnrichmentHistoryEntry] = []

    # -- normalisation ---------------------------------------------------

    @staticmethod
    def normalize(value: str) -> str:
        """
        Normalise an IPv4/IPv6 address, refanging defanged forms first.

        Refanging happens before classification: a defanged `8[.]8[.]8[.]8` is not a valid
        address until the brackets are removed, so testing the raw string first would reject
        exactly the indicators this package exists to handle.
        """
        raw = value.strip()
        refanged = raw.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
        if _IPV4_RE.match(refanged):
            return OSINTIngestionService.refang_and_normalize_indicator("ipv4", refanged)
        if ":" in refanged:
            return OSINTIngestionService.refang_and_normalize_indicator("ipv6", refanged)
        raise EnrichmentValidationError(f"not a recognisable IPv4 or IPv6 address: {value!r}")

    # -- recording -------------------------------------------------------

    def record_asn(
        self,
        address: str,
        asn: ASNRecord,
        *,
        origin: AssertionOrigin = AssertionOrigin.IMPORTED_UNVERIFIED,
        confidence: float = 0.0,
        evidence: Optional[Sequence[Dict[str, Any]]] = None,
        source_reference: Optional[str] = None,
        verification_mode: VerificationMode = VerificationMode.FIXTURE_TESTED,
        now: Optional[datetime] = None,
    ) -> IPEnrichmentRecord:
        """Record ASN ownership reported by a source."""
        return self._record(
            address,
            field_name="asn",
            value=asn,
            source_id=asn.source_id,
            origin=origin,
            confidence=confidence,
            evidence=evidence,
            source_reference=source_reference,
            verification_mode=verification_mode,
            observed_at=asn.observed_at,
            action="asn_recorded",
            detail=f"AS{asn.asn} {asn.name or ''}".strip(),
            now=now,
        )

    def record_network(
        self,
        address: str,
        network: NetworkBlock,
        *,
        origin: AssertionOrigin = AssertionOrigin.IMPORTED_UNVERIFIED,
        confidence: float = 0.0,
        evidence: Optional[Sequence[Dict[str, Any]]] = None,
        verification_mode: VerificationMode = VerificationMode.FIXTURE_TESTED,
        now: Optional[datetime] = None,
    ) -> IPEnrichmentRecord:
        return self._record(
            address,
            field_name="network",
            value=network,
            source_id=network.source_id,
            origin=origin,
            confidence=confidence,
            evidence=evidence,
            verification_mode=verification_mode,
            observed_at=network.observed_at,
            action="network_recorded",
            detail=f"{network.cidr} {network.organisation or ''}".strip(),
            now=now,
        )

    def record_geolocation(
        self,
        address: str,
        geolocation: GeolocationEvidence,
        *,
        origin: AssertionOrigin = AssertionOrigin.IMPORTED_UNVERIFIED,
        confidence: float = 0.0,
        evidence: Optional[Sequence[Dict[str, Any]]] = None,
        verification_mode: VerificationMode = VerificationMode.FIXTURE_TESTED,
        now: Optional[datetime] = None,
    ) -> IPEnrichmentRecord:
        return self._record(
            address,
            field_name="geolocation",
            value=geolocation,
            source_id=geolocation.source_id,
            origin=origin,
            confidence=confidence,
            evidence=evidence,
            verification_mode=verification_mode,
            observed_at=geolocation.observed_at,
            action="geolocation_recorded",
            detail=f"{geolocation.country or '?'} accuracy_km={geolocation.accuracy_radius_km}",
            now=now,
        )

    def record_verdict(
        self,
        address: str,
        verdict: ThreatVerdict,
        *,
        source_id: str,
        origin: AssertionOrigin = AssertionOrigin.IMPORTED_UNVERIFIED,
        confidence: float = 0.0,
        evidence: Optional[Sequence[Dict[str, Any]]] = None,
        source_reference: Optional[str] = None,
        verification_mode: VerificationMode = VerificationMode.FIXTURE_TESTED,
        now: Optional[datetime] = None,
    ) -> IPEnrichmentRecord:
        """
        Record a verdict from a source.

        A malicious verdict requires evidence: labelling an address malicious on assertion alone
        would put an unverified claim into a place downstream systems treat as fact.
        """
        if verdict == ThreatVerdict.MALICIOUS and not evidence:
            raise EnrichmentValidationError(
                "a MALICIOUS verdict requires at least one evidence item"
            )
        return self._record(
            address,
            field_name="verdict",
            value=verdict,
            source_id=source_id,
            origin=origin,
            confidence=confidence,
            evidence=evidence,
            source_reference=source_reference,
            verification_mode=verification_mode,
            action="verdict_recorded",
            detail=verdict.value,
            now=now,
        )

    # -- queries ---------------------------------------------------------

    def get(self, address: str) -> Optional[IPEnrichmentRecord]:
        key = self.normalize(address)
        with self._lock:
            return self._records.get(f"{self.tenant_id}|{key}")

    def require(self, address: str) -> IPEnrichmentRecord:
        record = self.get(address)
        if record is None:
            raise IndicatorNotFoundError(f"no enrichment recorded for address: {address!r}")
        return record

    def list_records(self, *, limit: int = MAX_SEARCH_LIMIT, offset: int = 0) -> List[IPEnrichmentRecord]:
        rows = _paginate(self._all_records(), limit, offset)
        return sorted(rows, key=lambda r: r.address)

    def observations_for(self, address: str) -> List[EnrichmentObservation]:
        key = self.normalize(address)
        with self._lock:
            return list(self._observations.get(f"{self.tenant_id}|{key}", []))

    def conflicts(self) -> List[AttributionConflict]:
        """Indicators whose sources disagree about ASN, network or verdict."""
        return _detect_conflicts(
            self._all_records(),
            self._observations,
            self.tenant_id,
            fields=("asn", "network", "verdict"),
        )

    def history_for(self, address: str) -> List[EnrichmentHistoryEntry]:
        key = self.normalize(address)
        with self._lock:
            return [h for h in self._history if h.indicator_value == key]

    def search(
        self,
        *,
        has_asn: Optional[bool] = None,
        country: Optional[str] = None,
        verdict: Optional[ThreatVerdict] = None,
        is_private: Optional[bool] = None,
        limit: int = MAX_SEARCH_LIMIT,
        offset: int = 0,
    ) -> List[IPEnrichmentRecord]:
        rows = []
        for record in self._all_records():
            if has_asn is not None and (record.asn is not None) != has_asn:
                continue
            if country and (record.geolocation is None or (record.geolocation.country or "").lower() != country.strip().lower()):
                continue
            if verdict is not None and record.verdict != verdict:
                continue
            if is_private is not None and record.is_private != is_private:
                continue
            rows.append(record)
        rows.sort(key=lambda r: r.address)
        return _paginate(rows, limit, offset)

    def stats(self) -> Dict[str, Any]:
        rows = self._all_records()
        return {
            "tenant_id": self.tenant_id,
            "indicator": "ip",
            "records": len(rows),
            "with_asn": sum(1 for r in rows if r.asn is not None),
            "with_network": sum(1 for r in rows if r.network is not None),
            "with_geolocation": sum(1 for r in rows if r.geolocation is not None),
            "unknown_state": sum(1 for r in rows if r.enrichment_state == EnrichmentState.UNKNOWN),
            "conflicting": sum(1 for r in rows if r.enrichment_state == EnrichmentState.CONFLICTING),
            "verdicts": {v.value: sum(1 for r in rows if r.verdict == v) for v in ThreatVerdict},
            "observations": sum(len(v) for v in self._observations.values()),
            "conflicts": len(self.conflicts()),
            "verification_mode": "fixture_tested_only_no_outbound_requests",
        }

    # -- live (gated) ----------------------------------------------------

    def live_enrichment_plan(self, source_id: str, *, allow_live: bool = False) -> Any:
        """Describe the live fetch that would happen. Performs no I/O."""
        return _require_live(self.live_readiness).plan(source_id, allow_live=allow_live)

    def live_enrich(
        self, address: str, source_id: str, *, allow_live: bool = False, now: Optional[datetime] = None
    ) -> Any:
        """
        Attempt one gated live fetch for this address.

        Delegates to ``LiveSourceReadinessService.fetch``, which requires the environment opt-in,
        ``allow_live=True``, a registered policy and an injected transport. This module holds no
        network client, so nothing here can reach the internet on its own.
        """
        service = _require_live(self.live_readiness)
        key = self.normalize(address)
        return service.fetch(source_id, allow_live=allow_live, now=to_utc(now))

    # -- internals -------------------------------------------------------

    def _all_records(self) -> List[IPEnrichmentRecord]:
        with self._lock:
            return [r for k, r in self._records.items() if k.startswith(f"{self.tenant_id}|")]

    def _record(
        self,
        address: str,
        *,
        field_name: str,
        value: Any,
        source_id: str,
        origin: AssertionOrigin,
        confidence: float,
        evidence: Optional[Sequence[Dict[str, Any]]],
        verification_mode: VerificationMode,
        action: str,
        detail: str,
        now: Optional[datetime],
        source_reference: Optional[str] = None,
        observed_at: Optional[datetime] = None,
    ) -> IPEnrichmentRecord:
        moment = to_utc(now)
        key = self.normalize(address)
        store_key = f"{self.tenant_id}|{key}"
        items = [EvidenceItem(**e) for e in (evidence or [])]
        confidence, ceiling, clamped = _cap_confidence(confidence, origin, items)

        with self._lock:
            address_obj = ipaddress.ip_address(key)
            record = self._records.get(store_key)
            if record is None:
                record = IPEnrichmentRecord(
                    tenant_id=self.tenant_id,
                    indicator_type="ipv4" if address_obj.version == 4 else "ipv6",
                    address=key,
                    version=address_obj.version,
                    is_private=address_obj.is_private,
                    is_global=address_obj.is_global,
                    created_at=moment,
                    updated_at=moment,
                )
                record.experimental_label = (
                    None if verification_mode == VerificationMode.LIVE_VERIFIED
                    else EXPERIMENTAL_DEMO_DATA_ONLY
                )
                self._records[store_key] = record

            setattr(record, field_name, value)
            if field_name == "verdict":
                record.verdict = value

            observed = to_utc(observed_at) if observed_at else moment
            if record.first_seen is None or observed < record.first_seen:
                record.first_seen = observed
            if record.last_seen is None or observed > record.last_seen:
                record.last_seen = observed
            record.updated_at = moment
            record.enrichment_state = EnrichmentState.ENRICHED

            observation = EnrichmentObservation(
                observation_id=_new_id("OBS"),
                indicator_type=record.indicator_type,
                indicator_value=key,
                source_id=source_id,
                source_reference=source_reference,
                origin=origin,
                confidence=confidence,
                confidence_ceiling=ceiling,
                confidence_was_clamped=clamped,
                verification_mode=verification_mode,
                evidence=items,
                observed_at=observed,
                recorded_at=moment,
                payload=_payload_of(value),
            )
            bucket = self._observations.setdefault(store_key, [])
            if len(bucket) >= MAX_OBSERVATIONS_PER_INDICATOR:
                raise EnrichmentValidationError(
                    f"observation limit ({MAX_OBSERVATIONS_PER_INDICATOR}) reached for {key!r}"
                )
            bucket.append(observation)

            conflicts = _detect_conflicts([record], self._observations, self.tenant_id,
                                          fields=("asn", "network", "verdict"))
            if conflicts:
                record.enrichment_state = EnrichmentState.CONFLICTING

            self._history.append(
                EnrichmentHistoryEntry(
                    entry_id=_new_id("IPH"),
                    indicator_type=record.indicator_type,
                    indicator_value=key,
                    action=action,
                    source_id=source_id,
                    detail=detail,
                    recorded_at=moment,
                )
            )
            _trim_history(self._history)
            return record


# --------------------------------------------------------------------------
# Item 16 - Domain Intelligence
# --------------------------------------------------------------------------

class DNSRecordObservation(BaseModel):
    """One DNS record as observed by one source at one time."""

    model_config = ConfigDict(extra="forbid")

    record_type: DNSRecordType
    value: str = Field(..., min_length=1, max_length=1024)
    ttl_seconds: Optional[int] = Field(None, ge=0)
    source_id: str = Field(..., min_length=1, max_length=256)
    source_reference: Optional[str] = Field(None, max_length=1024)
    observed_at: datetime = Field(default_factory=lambda: to_utc(None))
    verification_mode: VerificationMode = VerificationMode.FIXTURE_TESTED

    @field_validator("value")
    @classmethod
    def _strip(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("DNS record value must not be blank")
        return stripped


class WhoisRecord(BaseModel):
    """WHOIS / RDAP registration data. Always source-supplied; never synthesised."""

    model_config = ConfigDict(extra="forbid")

    registrar: Optional[str] = Field(None, max_length=256)
    registrar_iana_id: Optional[str] = Field(None, max_length=32)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    nameservers: List[str] = Field(default_factory=list)
    status: List[str] = Field(default_factory=list)
    protocol: str = Field("whois", max_length=16, description="whois | rdap")
    source_id: str = Field(..., min_length=1, max_length=256)
    source_reference: Optional[str] = Field(None, max_length=1024)
    observed_at: datetime = Field(default_factory=lambda: to_utc(None))
    verification_mode: VerificationMode = VerificationMode.FIXTURE_TESTED

    @field_validator("nameservers")
    @classmethod
    def _normalise_ns(cls, v: List[str]) -> List[str]:
        return list(dict.fromkeys(ns.strip().lower().rstrip(".") for ns in v if ns.strip()))

    @field_validator("created_at", "updated_at", "expires_at", "observed_at")
    @classmethod
    def _aware(cls, v: Optional[datetime]) -> Optional[datetime]:
        return None if v is None else to_utc(v)

    @field_validator("protocol")
    @classmethod
    def _known(cls, v: str) -> str:
        normalised = v.strip().lower()
        if normalised not in ("whois", "rdap"):
            raise ValueError("protocol must be 'whois' or 'rdap'")
        return normalised


class DomainRelationship(BaseModel):
    """A relationship between two domains, with the basis for it."""

    model_config = ConfigDict(extra="forbid")

    kind: DomainRelationshipKind
    other_domain: str = Field(..., min_length=1, max_length=MAX_DOMAIN_LENGTH)
    basis: str = Field(..., min_length=1, max_length=512, description="Why this relationship holds")
    source_id: str = Field(..., min_length=1, max_length=256)
    observed_at: datetime = Field(default_factory=lambda: to_utc(None))

    @field_validator("other_domain")
    @classmethod
    def _normalise(cls, v: str) -> str:
        stripped = v.strip().lower().rstrip(".")
        if not stripped:
            raise ValueError("other_domain must not be blank")
        return stripped

    @field_validator("basis")
    @classmethod
    def _basis_not_blank(cls, v: str) -> str:
        # min_length alone is not enough: it counts whitespace, so "   " would pass and leave a
        # relationship with no stated reason.
        stripped = " ".join(v.split())
        if not stripped:
            raise ValueError("basis must state why the relationship holds; blank is not a basis")
        return stripped


class DomainEnrichmentRecord(IndicatorEnrichmentBase):
    """Enrichment state for one domain."""

    indicator_type: str = "domain"
    domain: str = Field(..., min_length=1, max_length=MAX_DOMAIN_LENGTH)
    dns_records: List[DNSRecordObservation] = Field(default_factory=list)
    whois: Optional[WhoisRecord] = None
    relationships: List[DomainRelationship] = Field(default_factory=list)
    verdict: ThreatVerdict = ThreatVerdict.UNKNOWN
    enrichment_state: EnrichmentState = EnrichmentState.UNKNOWN

    @property
    def nameservers(self) -> Tuple[str, ...]:
        """Nameservers from NS records, falling back to the WHOIS registrar data."""
        from_ns = tuple(
            dict.fromkeys(
                r.value.lower().rstrip(".")
                for r in self.dns_records
                if r.record_type == DNSRecordType.NS
            )
        )
        if from_ns:
            return from_ns
        return tuple(self.whois.nameservers) if self.whois else ()

    @property
    def registrar(self) -> Optional[str]:
        return self.whois.registrar if self.whois else None

    @property
    def resolved_addresses(self) -> Tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                r.value for r in self.dns_records
                if r.record_type in (DNSRecordType.A, DNSRecordType.AAAA)
            )
        )


class DomainIntelligenceService:
    """
    Domain intelligence (Domain B item 16).

    Records DNS observations, WHOIS/RDAP registration data and inter-domain relationships. Holds
    no resolver and no WHOIS client: everything here was supplied by a caller or a gated fetch.
    """

    def __init__(
        self,
        tenant_id: str = "default",
        live_readiness: Optional[LiveSourceReadinessService] = None,
    ) -> None:
        self.tenant_id = _require_tenant(tenant_id)
        self.live_readiness = live_readiness
        self._lock = threading.RLock()
        self._records: Dict[str, DomainEnrichmentRecord] = {}
        self._observations: Dict[str, List[EnrichmentObservation]] = {}
        self._history: List[EnrichmentHistoryEntry] = []

    @staticmethod
    def normalize(value: str) -> str:
        return OSINTIngestionService.refang_and_normalize_indicator("domain", value.strip())

    def record_dns(
        self,
        domain: str,
        record: DNSRecordObservation,
        *,
        origin: AssertionOrigin = AssertionOrigin.IMPORTED_UNVERIFIED,
        confidence: float = 0.0,
        evidence: Optional[Sequence[Dict[str, Any]]] = None,
        now: Optional[datetime] = None,
    ) -> DomainEnrichmentRecord:
        moment = to_utc(now)
        key = self.normalize(domain)
        store_key = f"{self.tenant_id}|{key}"
        items = [EvidenceItem(**e) for e in (evidence or [])]
        confidence, ceiling, clamped = _cap_confidence(confidence, origin, items)

        with self._lock:
            record_obj = self._ensure(key, store_key, moment, record.verification_mode)
            if len(record_obj.dns_records) >= MAX_DNS_RECORDS_PER_DOMAIN:
                raise EnrichmentValidationError(
                    f"DNS record limit ({MAX_DNS_RECORDS_PER_DOMAIN}) reached for {key!r}"
                )
            record_obj.dns_records.append(record)
            self._touch(record_obj, record.observed_at, moment)
            record_obj.enrichment_state = EnrichmentState.ENRICHED
            self._append_observation(
                store_key, record_obj, source_id=record.source_id,
                source_reference=record.source_reference, origin=origin, confidence=confidence,
                ceiling=ceiling, clamped=clamped, items=items,
                verification_mode=record.verification_mode, observed_at=record.observed_at,
                moment=moment, payload=record.model_dump(mode="json"),
            )
            self._append_history(record_obj, "dns_recorded", record.source_id,
                                 f"{record.record_type.value}={record.value}", moment)
            return record_obj

    def record_whois(
        self,
        domain: str,
        whois: WhoisRecord,
        *,
        origin: AssertionOrigin = AssertionOrigin.IMPORTED_UNVERIFIED,
        confidence: float = 0.0,
        evidence: Optional[Sequence[Dict[str, Any]]] = None,
        now: Optional[datetime] = None,
    ) -> DomainEnrichmentRecord:
        moment = to_utc(now)
        key = self.normalize(domain)
        store_key = f"{self.tenant_id}|{key}"
        items = [EvidenceItem(**e) for e in (evidence or [])]
        confidence, ceiling, clamped = _cap_confidence(confidence, origin, items)

        with self._lock:
            record_obj = self._ensure(key, store_key, moment, whois.verification_mode)
            prior = record_obj.whois
            record_obj.whois = whois
            self._touch(record_obj, whois.observed_at, moment)
            record_obj.enrichment_state = EnrichmentState.ENRICHED
            if prior is not None and prior.registrar and whois.registrar and prior.registrar != whois.registrar:
                record_obj.enrichment_state = EnrichmentState.CONFLICTING
            self._append_observation(
                store_key, record_obj, source_id=whois.source_id,
                source_reference=whois.source_reference, origin=origin, confidence=confidence,
                ceiling=ceiling, clamped=clamped, items=items,
                verification_mode=whois.verification_mode, observed_at=whois.observed_at,
                moment=moment, payload={"registrar": whois.registrar, "protocol": whois.protocol},
            )
            self._append_history(record_obj, "whois_recorded", whois.source_id,
                                 f"registrar={whois.registrar} protocol={whois.protocol}", moment)
            return record_obj

    def record_relationship(
        self,
        domain: str,
        relationship: DomainRelationship,
        *,
        now: Optional[datetime] = None,
    ) -> DomainEnrichmentRecord:
        """
        Record a relationship between two domains.

        A basis is mandatory and is not validated for truth: the point is that the relationship
        is traceable to a stated reason rather than appearing unexplained.
        """
        moment = to_utc(now)
        key = self.normalize(domain)
        store_key = f"{self.tenant_id}|{key}"
        with self._lock:
            record_obj = self._ensure(key, store_key, moment, VerificationMode.FIXTURE_TESTED)
            for existing in record_obj.relationships:
                if existing.kind == relationship.kind and existing.other_domain == relationship.other_domain:
                    return record_obj
            record_obj.relationships.append(relationship)
            self._touch(record_obj, relationship.observed_at, moment)
            record_obj.enrichment_state = EnrichmentState.ENRICHED
            self._append_history(record_obj, "relationship_recorded", relationship.source_id,
                                 f"{relationship.kind.value}->{relationship.other_domain}", moment)
            return record_obj

    def record_verdict(
        self,
        domain: str,
        verdict: ThreatVerdict,
        *,
        source_id: str,
        evidence: Optional[Sequence[Dict[str, Any]]] = None,
        origin: AssertionOrigin = AssertionOrigin.IMPORTED_UNVERIFIED,
        confidence: float = 0.0,
        now: Optional[datetime] = None,
    ) -> DomainEnrichmentRecord:
        if verdict == ThreatVerdict.MALICIOUS and not evidence:
            raise EnrichmentValidationError("a MALICIOUS verdict requires at least one evidence item")
        moment = to_utc(now)
        key = self.normalize(domain)
        store_key = f"{self.tenant_id}|{key}"
        with self._lock:
            record_obj = self._ensure(key, store_key, moment, VerificationMode.FIXTURE_TESTED)
            record_obj.verdict = verdict
            record_obj.enrichment_state = EnrichmentState.ENRICHED
            self._append_history(record_obj, "verdict_recorded", source_id, verdict.value, moment)
            return record_obj

    def derive_parent_relationships(self, domain: str, *, now: Optional[datetime] = None) -> DomainEnrichmentRecord:
        """
        Derive PARENT/SUBDOMAIN relationships from the domain name itself.

        This is the one derivation the service performs, because it follows from the name rather
        than from any external claim: `a.example.com` is definitionally a subdomain of
        `example.com`.
        """
        moment = to_utc(now)
        key = self.normalize(domain)
        labels = key.split(".")
        with self._lock:
            record_obj = self._ensure(key, f"{self.tenant_id}|{key}", moment, VerificationMode.FIXTURE_TESTED)
            if len(labels) > 2:
                parent = ".".join(labels[1:])
                self.record_relationship(
                    domain,
                    DomainRelationship(
                        kind=DomainRelationshipKind.PARENT,
                        other_domain=parent,
                        basis="derived from the domain name: one label removed",
                        source_id="name_derivation",
                        observed_at=moment,
                    ),
                    now=moment,
                )
                record_obj = self._ensure(key, f"{self.tenant_id}|{key}", moment, VerificationMode.FIXTURE_TESTED)
            return record_obj

    def derive_sibling_relationships(self, domain: str, *, now: Optional[datetime] = None) -> List[DomainRelationship]:
        """
        Find other known domains sharing this domain's nameservers or registrar.

        Reported, not asserted as attribution: shared infrastructure is an investigative lead,
        and presenting it as common ownership would overstate what the evidence supports.
        """
        moment = to_utc(now)
        target = self.get(domain)
        if target is None:
            return []
        found: List[DomainRelationship] = []
        for record in self.list_records():
            if record.domain == target.domain:
                continue
            shared_ns = set(target.nameservers) & set(record.nameservers)
            if shared_ns:
                found.append(
                    DomainRelationship(
                        kind=DomainRelationshipKind.SIBLING_NAMESERVER,
                        other_domain=record.domain,
                        basis=f"shares nameservers: {', '.join(sorted(shared_ns))}",
                        source_id="derived_from_recorded_dns",
                        observed_at=moment,
                    )
                )
            elif target.registrar and record.registrar and target.registrar == record.registrar:
                found.append(
                    DomainRelationship(
                        kind=DomainRelationshipKind.SIBLING_REGISTRAR,
                        other_domain=record.domain,
                        basis=f"shares registrar: {target.registrar}",
                        source_id="derived_from_recorded_whois",
                        observed_at=moment,
                    )
                )
        with self._lock:
            for relationship in found:
                self.record_relationship(domain, relationship, now=moment)
        return found

    def get(self, domain: str) -> Optional[DomainEnrichmentRecord]:
        with self._lock:
            return self._records.get(f"{self.tenant_id}|{self.normalize(domain)}")

    def list_records(self, *, limit: int = MAX_SEARCH_LIMIT, offset: int = 0) -> List[DomainEnrichmentRecord]:
        with self._lock:
            rows = [r for k, r in self._records.items() if k.startswith(f"{self.tenant_id}|")]
        rows.sort(key=lambda r: r.domain)
        return _paginate(rows, limit, offset)

    def observations_for(self, domain: str) -> List[EnrichmentObservation]:
        with self._lock:
            return list(self._observations.get(f"{self.tenant_id}|{self.normalize(domain)}", []))

    def history_for(self, domain: str) -> List[EnrichmentHistoryEntry]:
        key = self.normalize(domain)
        with self._lock:
            return [h for h in self._history if h.indicator_value == key]

    def search(
        self,
        *,
        registrar: Optional[str] = None,
        nameserver: Optional[str] = None,
        verdict: Optional[ThreatVerdict] = None,
        has_whois: Optional[bool] = None,
        limit: int = MAX_SEARCH_LIMIT,
        offset: int = 0,
    ) -> List[DomainEnrichmentRecord]:
        rows = []
        for record in self.list_records():
            if registrar and (record.registrar or "").lower() != registrar.strip().lower():
                continue
            if nameserver and nameserver.strip().lower().rstrip(".") not in record.nameservers:
                continue
            if verdict is not None and record.verdict != verdict:
                continue
            if has_whois is not None and (record.whois is not None) != has_whois:
                continue
            rows.append(record)
        return _paginate(rows, limit, offset)

    def stats(self) -> Dict[str, Any]:
        rows = self.list_records()
        return {
            "tenant_id": self.tenant_id,
            "indicator": "domain",
            "records": len(rows),
            "with_whois": sum(1 for r in rows if r.whois is not None),
            "dns_records": sum(len(r.dns_records) for r in rows),
            "relationships": sum(len(r.relationships) for r in rows),
            "conflicting": sum(1 for r in rows if r.enrichment_state == EnrichmentState.CONFLICTING),
            "verdicts": {v.value: sum(1 for r in rows if r.verdict == v) for v in ThreatVerdict},
            "observations": sum(len(v) for v in self._observations.values()),
            "verification_mode": "fixture_tested_only_no_outbound_requests",
        }

    def live_enrichment_plan(self, source_id: str, *, allow_live: bool = False) -> Any:
        return _require_live(self.live_readiness).plan(source_id, allow_live=allow_live)

    def live_enrich(self, domain: str, source_id: str, *, allow_live: bool = False,
                    now: Optional[datetime] = None) -> Any:
        service = _require_live(self.live_readiness)
        self.normalize(domain)
        return service.fetch(source_id, allow_live=allow_live, now=to_utc(now))

    # -- internals -------------------------------------------------------

    def _ensure(self, key: str, store_key: str, moment: datetime,
                verification_mode: VerificationMode) -> DomainEnrichmentRecord:
        record = self._records.get(store_key)
        if record is None:
            record = DomainEnrichmentRecord(
                tenant_id=self.tenant_id, indicator_type="domain", domain=key,
                created_at=moment, updated_at=moment,
            )
            record.experimental_label = (
                None if verification_mode == VerificationMode.LIVE_VERIFIED
                else EXPERIMENTAL_DEMO_DATA_ONLY
            )
            self._records[store_key] = record
        return record

    def _touch(self, record: DomainEnrichmentRecord, observed: datetime, moment: datetime) -> None:
        if record.first_seen is None or observed < record.first_seen:
            record.first_seen = observed
        if record.last_seen is None or observed > record.last_seen:
            record.last_seen = observed
        record.updated_at = moment

    def _append_observation(self, store_key, record, *, source_id, source_reference, origin,
                            confidence, ceiling, clamped, items, verification_mode,
                            observed_at, moment, payload) -> None:
        bucket = self._observations.setdefault(store_key, [])
        if len(bucket) >= MAX_OBSERVATIONS_PER_INDICATOR:
            raise EnrichmentValidationError(
                f"observation limit ({MAX_OBSERVATIONS_PER_INDICATOR}) reached"
            )
        bucket.append(
            EnrichmentObservation(
                observation_id=_new_id("OBS"),
                indicator_type=record.indicator_type,
                indicator_value=record.domain,
                source_id=source_id,
                source_reference=source_reference,
                origin=origin,
                confidence=confidence,
                confidence_ceiling=ceiling,
                confidence_was_clamped=clamped,
                verification_mode=verification_mode,
                evidence=items,
                observed_at=to_utc(observed_at),
                recorded_at=moment,
                payload=payload,
            )
        )

    def _append_history(self, record, action, source_id, detail, moment) -> None:
        self._history.append(
            EnrichmentHistoryEntry(
                entry_id=_new_id("DH"),
                indicator_type=record.indicator_type,
                indicator_value=record.domain,
                action=action,
                source_id=source_id,
                detail=detail,
                recorded_at=moment,
            )
        )
        _trim_history(self._history)


# --------------------------------------------------------------------------
# Item 17 - URL Intelligence
# --------------------------------------------------------------------------

class URLComponents(BaseModel):
    """The parsed parts of a URL. Parsing only; no request is ever made."""

    model_config = ConfigDict(extra="forbid")

    scheme: str = Field(..., min_length=1, max_length=16)
    host: str = Field(..., min_length=1, max_length=MAX_DOMAIN_LENGTH)
    port: Optional[int] = Field(None, ge=1, le=65_535)
    path: str = ""
    query: str = ""
    fragment: str = ""

    @property
    def registrable_host(self) -> str:
        return self.host.lower().rstrip(".")


class URLEnrichmentRecord(IndicatorEnrichmentBase):
    """Enrichment state for one URL."""

    indicator_type: str = "url"
    url: str = Field(..., min_length=1, max_length=MAX_URL_LENGTH)
    components: Optional[URLComponents] = None
    host_domain: Optional[str] = None
    urlhaus_id: Optional[str] = Field(None, max_length=64)
    urlhaus_reference: Optional[str] = Field(None, max_length=1024)
    threat_type: Optional[str] = Field(None, max_length=128)
    tags: List[str] = Field(default_factory=list)
    redirect_chain: List[str] = Field(default_factory=list)
    verdict: ThreatVerdict = ThreatVerdict.UNKNOWN
    enrichment_state: EnrichmentState = EnrichmentState.UNKNOWN

    @field_validator("tags")
    @classmethod
    def _dedupe(cls, v: List[str]) -> List[str]:
        return list(dict.fromkeys(t.strip().lower() for t in v if t.strip()))


class URLIntelligenceService:
    """
    URL intelligence (Domain B item 17).

    Parsing is done locally and defensively. Redirect chains are *recorded observations*, not
    something this service follows: following a redirect is a network request, and this package
    holds no network client.
    """

    def __init__(
        self,
        tenant_id: str = "default",
        live_readiness: Optional[LiveSourceReadinessService] = None,
    ) -> None:
        self.tenant_id = _require_tenant(tenant_id)
        self.live_readiness = live_readiness
        self._lock = threading.RLock()
        self._records: Dict[str, URLEnrichmentRecord] = {}
        self._observations: Dict[str, List[EnrichmentObservation]] = {}
        self._history: List[EnrichmentHistoryEntry] = []

    @staticmethod
    def normalize(value: str) -> str:
        """
        Normalise a URL, refanging defanged forms first.

        Rejects non-HTTP(S) schemes outright. `javascript:` and `data:` URLs are parsed
        differently by every consumer and are a stored-XSS hazard if echoed into a UI, so they
        are refused rather than stored optimistically.
        """
        candidate = value.strip()
        # The shared refang helper matches the scheme case-sensitively, so an uppercase
        # "HTTPS://" would be rejected as a bad scheme. Lowercase only the scheme here; the
        # path keeps its case, because paths are case-sensitive.
        scheme_match = re.match(r"^(hxxps?|https?)://", candidate, flags=re.IGNORECASE)
        if scheme_match:
            lowered = scheme_match.group(1).lower().replace("hxxp", "http")
            candidate = lowered + "://" + candidate[scheme_match.end():]
        raw = OSINTIngestionService.refang_and_normalize_indicator("url", candidate)
        if len(raw) > MAX_URL_LENGTH:
            raise EnrichmentValidationError(
                f"URL exceeds {MAX_URL_LENGTH} characters ({len(raw)})"
            )
        parts = urlsplit(raw)
        if parts.scheme.lower() not in ALLOWED_URL_SCHEMES:
            raise EnrichmentValidationError(
                f"refusing to store a {parts.scheme!r} URL: only {sorted(ALLOWED_URL_SCHEMES)} are accepted"
            )
        if not parts.hostname:
            raise EnrichmentValidationError(f"URL has no host: {value!r}")
        if "@" in (parts.netloc or ""):
            raise EnrichmentValidationError(
                "refusing to store a URL with embedded credentials in the authority component"
            )
        return urlunsplit(
            (parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, parts.fragment)
        )

    @staticmethod
    def parse(value: str) -> URLComponents:
        """Parse a normalised URL into components. Makes no request."""
        parts = urlsplit(value)
        host = parts.hostname
        if not host:
            raise EnrichmentValidationError(f"URL has no host: {value!r}")
        return URLComponents(
            scheme=parts.scheme.lower(),
            host=host.lower(),
            port=parts.port,
            path=parts.path or "/",
            query=parts.query,
            fragment=parts.fragment,
        )

    def record_urlhaus(
        self,
        url: str,
        *,
        urlhaus_id: str,
        source_id: str = "urlhaus",
        source_reference: Optional[str] = None,
        threat_type: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        verdict: ThreatVerdict = ThreatVerdict.MALICIOUS,
        origin: AssertionOrigin = AssertionOrigin.IMPORTED_UNVERIFIED,
        confidence: float = 0.0,
        evidence: Optional[Sequence[Dict[str, Any]]] = None,
        verification_mode: VerificationMode = VerificationMode.FIXTURE_TESTED,
        observed_at: Optional[datetime] = None,
        now: Optional[datetime] = None,
    ) -> URLEnrichmentRecord:
        """
        Record URLhaus evidence about a URL.

        A malicious verdict requires evidence, same as the other services.
        """
        if verdict == ThreatVerdict.MALICIOUS and not evidence:
            raise EnrichmentValidationError("a MALICIOUS verdict requires at least one evidence item")
        moment = to_utc(now)
        key = self.normalize(url)
        store_key = f"{self.tenant_id}|{key}"
        items = [EvidenceItem(**e) for e in (evidence or [])]
        confidence, ceiling, clamped = _cap_confidence(confidence, origin, items)
        observed = to_utc(observed_at) if observed_at else moment

        with self._lock:
            record = self._ensure(key, store_key, moment, verification_mode)
            record.urlhaus_id = urlhaus_id
            record.urlhaus_reference = source_reference
            record.threat_type = threat_type
            if tags:
                record.tags = list(dict.fromkeys(record.tags + [t.strip().lower() for t in tags if t.strip()]))
            record.verdict = verdict
            record.enrichment_state = EnrichmentState.ENRICHED
            self._touch(record, observed, moment)
            self._append_observation(
                store_key, record, source_id=source_id, source_reference=source_reference,
                origin=origin, confidence=confidence, ceiling=ceiling, clamped=clamped,
                items=items, verification_mode=verification_mode, observed_at=observed,
                moment=moment, payload={"urlhaus_id": urlhaus_id, "threat_type": threat_type},
            )
            self._append_history(record, "urlhaus_recorded", source_id,
                                 f"id={urlhaus_id} threat_type={threat_type}", moment)
            return record

    def record_redirect_chain(
        self,
        url: str,
        chain: Sequence[str],
        *,
        source_id: str,
        observed_at: Optional[datetime] = None,
        now: Optional[datetime] = None,
    ) -> URLEnrichmentRecord:
        """
        Record an observed redirect chain.

        The chain must have been observed by the caller. This service never follows a redirect
        itself, and an empty or single-element chain is rejected because it records nothing.
        """
        if len(chain) < 2:
            raise EnrichmentValidationError(
                "a redirect chain needs at least two hops; this service does not follow redirects itself"
            )
        moment = to_utc(now)
        key = self.normalize(url)
        store_key = f"{self.tenant_id}|{key}"
        observed = to_utc(observed_at) if observed_at else moment
        normalised_chain = [self.normalize(step) for step in chain]

        with self._lock:
            record = self._ensure(key, store_key, moment, VerificationMode.FIXTURE_TESTED)
            record.redirect_chain = normalised_chain
            record.enrichment_state = EnrichmentState.ENRICHED
            self._touch(record, observed, moment)
            self._append_history(record, "redirect_chain_recorded", source_id,
                                 f"{' -> '.join(normalised_chain)}", moment)
            return record

    def get(self, url: str) -> Optional[URLEnrichmentRecord]:
        with self._lock:
            return self._records.get(f"{self.tenant_id}|{self.normalize(url)}")

    def list_records(self, *, limit: int = MAX_SEARCH_LIMIT, offset: int = 0) -> List[URLEnrichmentRecord]:
        with self._lock:
            rows = [r for k, r in self._records.items() if k.startswith(f"{self.tenant_id}|")]
        rows.sort(key=lambda r: r.url)
        return _paginate(rows, limit, offset)

    def for_host(self, host: str) -> List[URLEnrichmentRecord]:
        wanted = host.strip().lower().rstrip(".")
        return [r for r in self.list_records() if r.host_domain == wanted]

    def observations_for(self, url: str) -> List[EnrichmentObservation]:
        with self._lock:
            return list(self._observations.get(f"{self.tenant_id}|{self.normalize(url)}", []))

    def history_for(self, url: str) -> List[EnrichmentHistoryEntry]:
        key = self.normalize(url)
        with self._lock:
            return [h for h in self._history if h.indicator_value == key]

    def search(
        self,
        *,
        host: Optional[str] = None,
        threat_type: Optional[str] = None,
        tag: Optional[str] = None,
        verdict: Optional[ThreatVerdict] = None,
        has_urlhaus: Optional[bool] = None,
        limit: int = MAX_SEARCH_LIMIT,
        offset: int = 0,
    ) -> List[URLEnrichmentRecord]:
        rows = []
        for record in self.list_records():
            if host and (record.host_domain or "") != host.strip().lower().rstrip("."):
                continue
            if threat_type and (record.threat_type or "").lower() != threat_type.strip().lower():
                continue
            if tag and tag.strip().lower() not in record.tags:
                continue
            if verdict is not None and record.verdict != verdict:
                continue
            if has_urlhaus is not None and (record.urlhaus_id is not None) != has_urlhaus:
                continue
            rows.append(record)
        return _paginate(rows, limit, offset)

    def stats(self) -> Dict[str, Any]:
        rows = self.list_records()
        return {
            "tenant_id": self.tenant_id,
            "indicator": "url",
            "records": len(rows),
            "with_urlhaus": sum(1 for r in rows if r.urlhaus_id),
            "with_redirect_chain": sum(1 for r in rows if r.redirect_chain),
            "distinct_hosts": len({r.host_domain for r in rows if r.host_domain}),
            "verdicts": {v.value: sum(1 for r in rows if r.verdict == v) for v in ThreatVerdict},
            "observations": sum(len(v) for v in self._observations.values()),
            "verification_mode": "fixture_tested_only_no_outbound_requests",
        }

    def live_enrichment_plan(self, source_id: str, *, allow_live: bool = False) -> Any:
        return _require_live(self.live_readiness).plan(source_id, allow_live=allow_live)

    def live_enrich(self, url: str, source_id: str, *, allow_live: bool = False,
                    now: Optional[datetime] = None) -> Any:
        service = _require_live(self.live_readiness)
        self.normalize(url)
        return service.fetch(source_id, allow_live=allow_live, now=to_utc(now))

    # -- internals -------------------------------------------------------

    def _ensure(self, key: str, store_key: str, moment: datetime,
                verification_mode: VerificationMode) -> URLEnrichmentRecord:
        record = self._records.get(store_key)
        if record is None:
            components = self.parse(key)
            record = URLEnrichmentRecord(
                tenant_id=self.tenant_id, indicator_type="url", url=key,
                components=components, host_domain=components.registrable_host,
                created_at=moment, updated_at=moment,
            )
            record.experimental_label = (
                None if verification_mode == VerificationMode.LIVE_VERIFIED
                else EXPERIMENTAL_DEMO_DATA_ONLY
            )
            self._records[store_key] = record
        return record

    def _touch(self, record: URLEnrichmentRecord, observed: datetime, moment: datetime) -> None:
        if record.first_seen is None or observed < record.first_seen:
            record.first_seen = observed
        if record.last_seen is None or observed > record.last_seen:
            record.last_seen = observed
        record.updated_at = moment

    def _append_observation(self, store_key, record, *, source_id, source_reference, origin,
                            confidence, ceiling, clamped, items, verification_mode,
                            observed_at, moment, payload) -> None:
        bucket = self._observations.setdefault(store_key, [])
        if len(bucket) >= MAX_OBSERVATIONS_PER_INDICATOR:
            raise EnrichmentValidationError(
                f"observation limit ({MAX_OBSERVATIONS_PER_INDICATOR}) reached"
            )
        bucket.append(
            EnrichmentObservation(
                observation_id=_new_id("OBS"),
                indicator_type=record.indicator_type,
                indicator_value=record.url,
                source_id=source_id,
                source_reference=source_reference,
                origin=origin,
                confidence=confidence,
                confidence_ceiling=ceiling,
                confidence_was_clamped=clamped,
                verification_mode=verification_mode,
                evidence=items,
                observed_at=to_utc(observed_at),
                recorded_at=moment,
                payload=payload,
            )
        )

    def _append_history(self, record, action, source_id, detail, moment) -> None:
        self._history.append(
            EnrichmentHistoryEntry(
                entry_id=_new_id("UH"),
                indicator_type=record.indicator_type,
                indicator_value=record.url,
                action=action,
                source_id=source_id,
                detail=detail,
                recorded_at=moment,
            )
        )
        _trim_history(self._history)


# --------------------------------------------------------------------------
# Item 18 - File Hash Intelligence
# --------------------------------------------------------------------------

class FileIdentity(BaseModel):
    """The hashes identifying one file. At least one must be present."""

    model_config = ConfigDict(extra="forbid")

    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    file_name: Optional[str] = Field(None, max_length=512)
    file_size: Optional[int] = Field(None, ge=0)
    file_type: Optional[str] = Field(None, max_length=256)

    @field_validator("md5", "sha1", "sha256")
    @classmethod
    def _lower(cls, v: Optional[str]) -> Optional[str]:
        return None if v is None else v.strip().lower()

    @model_validator(mode="after")
    def _at_least_one_hash(self) -> "FileIdentity":
        if not (self.md5 or self.sha1 or self.sha256):
            raise ValueError("at least one of md5, sha1 or sha256 must be provided")
        return self


class FileEnrichmentRecord(IndicatorEnrichmentBase):
    """Enrichment state for one file hash."""

    indicator_type: str = Field(..., pattern=r"^(sha256|sha1|md5)$")
    hash_value: str = Field(..., min_length=32, max_length=64)
    identity: Optional[FileIdentity] = None
    malwarebazaar_id: Optional[str] = Field(None, max_length=64)
    malwarebazaar_reference: Optional[str] = Field(None, max_length=1024)
    signature: Optional[str] = Field(None, max_length=256)
    family_name: Optional[str] = Field(
        None, max_length=256, description="None when no source attributed a family"
    )
    family_id: Optional[str] = Field(None, max_length=256, description="Link to a MalwareFamilyProfile")
    attribution_state: EnrichmentState = EnrichmentState.UNKNOWN
    attribution_sources: List[str] = Field(default_factory=list)
    first_attributing_source: Optional[str] = Field(
        None, max_length=256,
        description="The source that made the first family attribution; kept so a conflict can "
                    "name both sides truthfully rather than labelling one a placeholder.",
    )
    competing_families: List[Tuple[str, str]] = Field(
        default_factory=list, description="(family_name, source_id) pairs when sources disagree"
    )
    verdict: ThreatVerdict = ThreatVerdict.UNKNOWN
    enrichment_state: EnrichmentState = EnrichmentState.UNKNOWN

    @field_validator("attribution_sources")
    @classmethod
    def _dedupe(cls, v: List[str]) -> List[str]:
        return list(dict.fromkeys(v))


class FileHashIntelligenceService:
    """
    File hash intelligence (Domain B item 18).

    Holds no malware family table. A family attribution exists here only because a source
    supplied one, and when two sources supply different families both are kept and the record
    reports CONFLICTING rather than silently picking a winner.
    """

    def __init__(
        self,
        tenant_id: str = "default",
        live_readiness: Optional[LiveSourceReadinessService] = None,
        family_service: Optional[MalwareFamilyService] = None,
    ) -> None:
        self.tenant_id = _require_tenant(tenant_id)
        self.live_readiness = live_readiness
        #: Optional link to the malware family layer, so a family_id can be validated against a
        #: real profile rather than accepted as a free string.
        self.family_service = family_service
        self._lock = threading.RLock()
        self._records: Dict[str, FileEnrichmentRecord] = {}
        self._observations: Dict[str, List[EnrichmentObservation]] = {}
        self._history: List[EnrichmentHistoryEntry] = []
        self._by_alternate_hash: Dict[str, str] = {}

    # -- canonicalisation ------------------------------------------------

    @staticmethod
    def detect_algorithm(value: str) -> HashAlgorithm:
        """Identify a hash algorithm from its length and character set."""
        candidate = value.strip().lower()
        if _SHA256_RE.match(candidate):
            return HashAlgorithm.SHA256
        if _SHA1_RE.match(candidate):
            return HashAlgorithm.SHA1
        if _MD5_RE.match(candidate):
            return HashAlgorithm.MD5
        raise EnrichmentValidationError(
            f"not a recognisable md5/sha1/sha256 hash: {value!r}"
        )

    @classmethod
    def canonicalize(cls, value: str) -> Tuple[HashAlgorithm, str]:
        """Validate and lowercase a hash. Rejects malformed input rather than guessing."""
        algorithm = cls.detect_algorithm(value)
        return algorithm, OSINTIngestionService.refang_and_normalize_indicator(algorithm.value, value.strip())

    # -- recording -------------------------------------------------------

    def record_identity(
        self,
        hash_value: str,
        identity: FileIdentity,
        *,
        source_id: str,
        origin: AssertionOrigin = AssertionOrigin.IMPORTED_UNVERIFIED,
        confidence: float = 0.0,
        evidence: Optional[Sequence[Dict[str, Any]]] = None,
        verification_mode: VerificationMode = VerificationMode.FIXTURE_TESTED,
        now: Optional[datetime] = None,
    ) -> FileEnrichmentRecord:
        moment = to_utc(now)
        algorithm, canonical = self.canonicalize(hash_value)
        store_key = f"{self.tenant_id}|{canonical}"
        items = [EvidenceItem(**e) for e in (evidence or [])]
        confidence, ceiling, clamped = _cap_confidence(confidence, origin, items)

        with self._lock:
            record = self._ensure(algorithm, canonical, store_key, moment, verification_mode)
            record.identity = identity
            record.enrichment_state = EnrichmentState.ENRICHED
            record.updated_at = moment
            # Index every alternate hash so the same file is reachable by any of its digests.
            for alt in (identity.md5, identity.sha1, identity.sha256):
                if alt:
                    self._by_alternate_hash[f"{self.tenant_id}|{alt}"] = store_key
            self._append_observation(
                store_key, record, source_id=source_id, source_reference=None, origin=origin,
                confidence=confidence, ceiling=ceiling, clamped=clamped, items=items,
                verification_mode=verification_mode, observed_at=moment, moment=moment,
                payload=identity.model_dump(mode="json"),
            )
            self._append_history(record, "identity_recorded", source_id,
                                 f"file_name={identity.file_name} size={identity.file_size}", moment)
            return record

    def record_malwarebazaar(
        self,
        hash_value: str,
        *,
        malwarebazaar_id: str,
        source_id: str = "malwarebazaar",
        source_reference: Optional[str] = None,
        signature: Optional[str] = None,
        file_name: Optional[str] = None,
        file_size: Optional[int] = None,
        file_type: Optional[str] = None,
        origin: AssertionOrigin = AssertionOrigin.IMPORTED_UNVERIFIED,
        confidence: float = 0.0,
        evidence: Optional[Sequence[Dict[str, Any]]] = None,
        verification_mode: VerificationMode = VerificationMode.FIXTURE_TESTED,
        observed_at: Optional[datetime] = None,
        now: Optional[datetime] = None,
    ) -> FileEnrichmentRecord:
        moment = to_utc(now)
        algorithm, canonical = self.canonicalize(hash_value)
        store_key = f"{self.tenant_id}|{canonical}"
        items = [EvidenceItem(**e) for e in (evidence or [])]
        confidence, ceiling, clamped = _cap_confidence(confidence, origin, items)
        observed = to_utc(observed_at) if observed_at else moment

        with self._lock:
            record = self._ensure(algorithm, canonical, store_key, moment, verification_mode)
            record.malwarebazaar_id = malwarebazaar_id
            record.malwarebazaar_reference = source_reference
            if signature:
                record.signature = signature
            if file_name or file_size or file_type:
                existing = record.identity
                # Merge onto any identity already recorded, then make sure the digest this call
                # was keyed on is present. Building the identity from metadata alone would
                # leave it with no hash at all.
                hashes = {
                    "md5": existing.md5 if existing else None,
                    "sha1": existing.sha1 if existing else None,
                    "sha256": existing.sha256 if existing else None,
                }
                hashes[algorithm.value] = canonical
                record.identity = FileIdentity(
                    md5=hashes["md5"],
                    sha1=hashes["sha1"],
                    sha256=hashes["sha256"],
                    file_name=file_name or (existing.file_name if existing else None),
                    file_size=file_size if file_size is not None else (existing.file_size if existing else None),
                    file_type=file_type or (existing.file_type if existing else None),
                )
            record.enrichment_state = EnrichmentState.ENRICHED
            self._touch(record, observed, moment)
            self._append_observation(
                store_key, record, source_id=source_id, source_reference=source_reference,
                origin=origin, confidence=confidence, ceiling=ceiling, clamped=clamped,
                items=items, verification_mode=verification_mode, observed_at=observed,
                moment=moment, payload={"malwarebazaar_id": malwarebazaar_id, "signature": signature},
            )
            self._append_history(record, "malwarebazaar_recorded", source_id,
                                 f"id={malwarebazaar_id} signature={signature}", moment)
            return record

    def record_family_attribution(
        self,
        hash_value: str,
        family_name: str,
        *,
        source_id: str,
        family_id: Optional[str] = None,
        origin: AssertionOrigin = AssertionOrigin.IMPORTED_UNVERIFIED,
        confidence: float = 0.0,
        evidence: Optional[Sequence[Dict[str, Any]]] = None,
        verification_mode: VerificationMode = VerificationMode.FIXTURE_TESTED,
        observed_at: Optional[datetime] = None,
        now: Optional[datetime] = None,
    ) -> FileEnrichmentRecord:
        """
        Record a source's family attribution for a file.

        This is where item 18's "preserve unknown or conflicting attribution" requirement lives:

        - The first attribution sets ``family_name``.
        - A second, *different* attribution does not overwrite it. Both are kept in
          ``competing_families`` and the state becomes CONFLICTING.
        - Repeating the same attribution is idempotent and just adds the source.
        """
        if not family_name.strip():
            raise EnrichmentValidationError("family_name must not be blank")
        moment = to_utc(now)
        algorithm, canonical = self.canonicalize(hash_value)
        store_key = f"{self.tenant_id}|{canonical}"
        items = [EvidenceItem(**e) for e in (evidence or [])]
        confidence, ceiling, clamped = _cap_confidence(confidence, origin, items)
        observed = to_utc(observed_at) if observed_at else moment
        wanted = family_name.strip()

        if family_id is not None and self.family_service is not None:
            if self.family_service.get_family(family_id) is None:
                raise EnrichmentValidationError(
                    f"family_id {family_id!r} does not exist in the malware family service"
                )

        with self._lock:
            record = self._ensure(algorithm, canonical, store_key, moment, verification_mode)
            if source_id not in record.attribution_sources:
                record.attribution_sources.append(source_id)

            if record.family_name is None:
                record.family_name = wanted
                record.family_id = family_id
                record.first_attributing_source = source_id
                record.attribution_state = EnrichmentState.ENRICHED
            elif record.family_name.strip().lower() != wanted.lower():
                pairs = dict(record.competing_families)
                pairs[wanted] = source_id
                # Name the first attributing source by its real id. Falling back to a
                # placeholder here would fabricate provenance for the earlier claim.
                pairs.setdefault(
                    record.family_name,
                    record.first_attributing_source or "source_not_recorded",
                )
                record.competing_families = sorted(pairs.items())
                record.attribution_state = EnrichmentState.CONFLICTING
                # A disputed family must not stay linked as if settled.
                record.family_id = None
            else:
                record.attribution_state = (
                    EnrichmentState.ENRICHED
                    if record.attribution_state != EnrichmentState.CONFLICTING
                    else record.attribution_state
                )

            record.enrichment_state = record.attribution_state
            self._touch(record, observed, moment)
            self._append_observation(
                store_key, record, source_id=source_id, source_reference=None, origin=origin,
                confidence=confidence, ceiling=ceiling, clamped=clamped, items=items,
                verification_mode=verification_mode, observed_at=observed, moment=moment,
                payload={"family_name": wanted, "family_id": family_id},
            )
            self._append_history(record, "family_attribution_recorded", source_id,
                                 f"family={wanted} state={record.attribution_state.value}", moment)
            return record

    def record_verdict(
        self,
        hash_value: str,
        verdict: ThreatVerdict,
        *,
        source_id: str,
        evidence: Optional[Sequence[Dict[str, Any]]] = None,
        now: Optional[datetime] = None,
    ) -> FileEnrichmentRecord:
        if verdict == ThreatVerdict.MALICIOUS and not evidence:
            raise EnrichmentValidationError("a MALICIOUS verdict requires at least one evidence item")
        moment = to_utc(now)
        algorithm, canonical = self.canonicalize(hash_value)
        store_key = f"{self.tenant_id}|{canonical}"
        with self._lock:
            record = self._ensure(algorithm, canonical, store_key, moment, VerificationMode.FIXTURE_TESTED)
            record.verdict = verdict
            record.enrichment_state = EnrichmentState.ENRICHED
            self._append_history(record, "verdict_recorded", source_id, verdict.value, moment)
            return record

    # -- queries ---------------------------------------------------------

    def get(self, hash_value: str) -> Optional[FileEnrichmentRecord]:
        """Look up by any of the file's hashes."""
        try:
            _, canonical = self.canonicalize(hash_value)
        except EnrichmentValidationError:
            return None
        with self._lock:
            direct = self._records.get(f"{self.tenant_id}|{canonical}")
            if direct is not None:
                return direct
            alternate = self._by_alternate_hash.get(f"{self.tenant_id}|{canonical}")
            return self._records.get(alternate) if alternate else None

    def list_records(self, *, limit: int = MAX_SEARCH_LIMIT, offset: int = 0) -> List[FileEnrichmentRecord]:
        with self._lock:
            rows = [r for k, r in self._records.items() if k.startswith(f"{self.tenant_id}|")]
        rows.sort(key=lambda r: r.hash_value)
        return _paginate(rows, limit, offset)

    def observations_for(self, hash_value: str) -> List[EnrichmentObservation]:
        record = self.get(hash_value)
        if record is None:
            return []
        with self._lock:
            return list(self._observations.get(f"{self.tenant_id}|{record.hash_value}", []))

    def history_for(self, hash_value: str) -> List[EnrichmentHistoryEntry]:
        record = self.get(hash_value)
        if record is None:
            return []
        with self._lock:
            return [h for h in self._history if h.indicator_value == record.hash_value]

    def family_conflicts(self) -> List[FileEnrichmentRecord]:
        """Files whose sources attributed different malware families. Both views preserved."""
        return [
            r for r in self.list_records()
            if r.attribution_state == EnrichmentState.CONFLICTING
        ]

    def unattributed(self) -> List[FileEnrichmentRecord]:
        """
        Files with no family attribution.

        Reported explicitly rather than defaulting to a family: an unknown file stays unknown.
        """
        return [r for r in self.list_records() if r.family_name is None]

    def search(
        self,
        *,
        family: Optional[str] = None,
        signature: Optional[str] = None,
        file_type: Optional[str] = None,
        verdict: Optional[ThreatVerdict] = None,
        has_malwarebazaar: Optional[bool] = None,
        attribution_state: Optional[EnrichmentState] = None,
        limit: int = MAX_SEARCH_LIMIT,
        offset: int = 0,
    ) -> List[FileEnrichmentRecord]:
        rows = []
        for record in self.list_records():
            if family and (record.family_name or "").lower() != family.strip().lower():
                continue
            if signature and (record.signature or "").lower() != signature.strip().lower():
                continue
            if file_type and (
                record.identity is None or (record.identity.file_type or "").lower() != file_type.strip().lower()
            ):
                continue
            if verdict is not None and record.verdict != verdict:
                continue
            if has_malwarebazaar is not None and (record.malwarebazaar_id is not None) != has_malwarebazaar:
                continue
            if attribution_state is not None and record.attribution_state != attribution_state:
                continue
            rows.append(record)
        return _paginate(rows, limit, offset)

    def stats(self) -> Dict[str, Any]:
        rows = self.list_records()
        return {
            "tenant_id": self.tenant_id,
            "indicator": "file_hash",
            "records": len(rows),
            "with_malwarebazaar": sum(1 for r in rows if r.malwarebazaar_id),
            "with_family": sum(1 for r in rows if r.family_name),
            "unattributed": sum(1 for r in rows if r.family_name is None),
            "conflicting_attribution": sum(
                1 for r in rows if r.attribution_state == EnrichmentState.CONFLICTING
            ),
            "verdicts": {v.value: sum(1 for r in rows if r.verdict == v) for v in ThreatVerdict},
            "observations": sum(len(v) for v in self._observations.values()),
            "verification_mode": "fixture_tested_only_no_outbound_requests",
        }

    def live_enrichment_plan(self, source_id: str, *, allow_live: bool = False) -> Any:
        return _require_live(self.live_readiness).plan(source_id, allow_live=allow_live)

    def live_enrich(self, hash_value: str, source_id: str, *, allow_live: bool = False,
                    now: Optional[datetime] = None) -> Any:
        service = _require_live(self.live_readiness)
        self.canonicalize(hash_value)
        return service.fetch(source_id, allow_live=allow_live, now=to_utc(now))

    # -- internals -------------------------------------------------------

    def _ensure(self, algorithm: HashAlgorithm, canonical: str, store_key: str, moment: datetime,
                verification_mode: VerificationMode) -> FileEnrichmentRecord:
        record = self._records.get(store_key)
        if record is None:
            record = FileEnrichmentRecord(
                tenant_id=self.tenant_id,
                indicator_type=algorithm.value,
                hash_value=canonical,
                created_at=moment,
                updated_at=moment,
            )
            record.experimental_label = (
                None if verification_mode == VerificationMode.LIVE_VERIFIED
                else EXPERIMENTAL_DEMO_DATA_ONLY
            )
            self._records[store_key] = record
        return record

    def _touch(self, record: FileEnrichmentRecord, observed: datetime, moment: datetime) -> None:
        if record.first_seen is None or observed < record.first_seen:
            record.first_seen = observed
        if record.last_seen is None or observed > record.last_seen:
            record.last_seen = observed
        record.updated_at = moment

    def _append_observation(self, store_key, record, *, source_id, source_reference, origin,
                            confidence, ceiling, clamped, items, verification_mode,
                            observed_at, moment, payload) -> None:
        bucket = self._observations.setdefault(store_key, [])
        if len(bucket) >= MAX_OBSERVATIONS_PER_INDICATOR:
            raise EnrichmentValidationError(
                f"observation limit ({MAX_OBSERVATIONS_PER_INDICATOR}) reached"
            )
        bucket.append(
            EnrichmentObservation(
                observation_id=_new_id("OBS"),
                indicator_type=record.indicator_type,
                indicator_value=record.hash_value,
                source_id=source_id,
                source_reference=source_reference,
                origin=origin,
                confidence=confidence,
                confidence_ceiling=ceiling,
                confidence_was_clamped=clamped,
                verification_mode=verification_mode,
                evidence=items,
                observed_at=to_utc(observed_at),
                recorded_at=moment,
                payload=payload,
            )
        )

    def _append_history(self, record, action, source_id, detail, moment) -> None:
        self._history.append(
            EnrichmentHistoryEntry(
                entry_id=_new_id("FH"),
                indicator_type=record.indicator_type,
                indicator_value=record.hash_value,
                action=action,
                source_id=source_id,
                detail=detail,
                recorded_at=moment,
            )
        )
        _trim_history(self._history)


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------

def _require_tenant(tenant_id: str) -> str:
    stripped = tenant_id.strip()
    if not stripped:
        raise EnrichmentValidationError("tenant_id must not be blank")
    return stripped


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


def _paginate(rows: List[Any], limit: int, offset: int) -> List[Any]:
    if limit < 0 or offset < 0:
        raise EnrichmentValidationError("limit and offset must be non-negative")
    return rows[offset:offset + min(limit, MAX_SEARCH_LIMIT)]


def _trim_history(history: List[EnrichmentHistoryEntry]) -> None:
    if len(history) > MAX_HISTORY_ENTRIES:
        del history[: len(history) - MAX_HISTORY_ENTRIES]


def _require_live(service: Optional[LiveSourceReadinessService]) -> LiveSourceReadinessService:
    """
    Refuse a live operation when no readiness service is configured.

    Failing loudly is the point: silently returning nothing would let a caller believe a live
    enrichment had been attempted.
    """
    if service is None:
        raise LiveAccessRefusedError(
            "no LiveSourceReadinessService configured: live enrichment is not available, and "
            "this package performs no network I/O of its own"
        )
    return service


def _cap_confidence(
    confidence: float, origin: AssertionOrigin, items: Sequence[EvidenceItem]
) -> Tuple[float, float, bool]:
    """Cap confidence at the origin's ceiling, reporting whether clamping happened."""
    if confidence < 0.0 or confidence > 1.0:
        raise EnrichmentValidationError("confidence must be within [0, 1]")
    ceiling = ORIGIN_CONFIDENCE_CEILING[origin]
    clamped = confidence > ceiling
    adjusted = min(confidence, ceiling)
    if items:
        distinct = len({e.source_ref for e in items if e.source_ref})
        if distinct > 1:
            adjusted = min(ceiling, adjusted + 0.05 * (distinct - 1))
    return round(adjusted, 6), ceiling, clamped


def _payload_of(value: Any) -> Dict[str, Any]:
    """Render a recorded enrichment value as a plain dict for the observation payload."""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return {"value": value.value}
    return {"value": value}


def _detect_conflicts(
    records: Sequence[Any],
    observations: Dict[str, List[EnrichmentObservation]],
    tenant_id: str,
    *,
    fields: Sequence[str],
) -> List[AttributionConflict]:
    """
    Detect fields where two or more sources recorded different values.

    Both values are preserved with their sources. Nothing is resolved here.
    """
    found: List[AttributionConflict] = []
    for record in records:
        store_key = f"{tenant_id}|{getattr(record, _value_attr(record))}"
        buckets = observations.get(store_key, [])
        for field in fields:
            pairs: Dict[str, str] = {}
            for observation in buckets:
                if field not in observation.payload:
                    continue
                rendered = _render(observation.payload[field])
                if rendered is None:
                    continue
                pairs.setdefault(rendered, observation.source_id)
            if len(pairs) < 2:
                continue
            found.append(
                AttributionConflict(
                    indicator_type=record.indicator_type,
                    indicator_value=getattr(record, _value_attr(record)),
                    field_name=field,
                    values=tuple(sorted(pairs.items())),
                    distinct_values=tuple(sorted(pairs)),
                )
            )
    found.sort(key=lambda c: (c.indicator_value, c.field_name))
    return found


def _value_attr(record: Any) -> str:
    for candidate in ("address", "domain", "url", "hash_value"):
        if hasattr(record, candidate):
            return candidate
    raise EnrichmentValidationError(f"record {record!r} has no indicator value attribute")


def _render(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, dict):
        parts = [f"{k}={value[k]}" for k in sorted(value) if value[k] is not None]
        return ";".join(parts) or None
    return str(value)
