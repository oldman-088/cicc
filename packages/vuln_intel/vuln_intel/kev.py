"""CISA KEV catalogue connector.

The prioritization model grants CISA KEV the largest single exploitation
weight, so KEV membership must come from the published catalogue rather than
from an analyst's memory.  This module provides:

* a bounded, validating fetch of the official catalogue document;
* :class:`KevCatalog` — an indexed, versioned, timestamped snapshot;
* :class:`CachedKevCatalog` — a TTL cache that keeps the **last good** snapshot
  and reports staleness, so an outage degrades quality instead of erasing
  knowledge ("stale but labelled", never "empty and silent").

Endpoint, from the published CISA KEV JSON feed:

    GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    {"title": "...", "catalogVersion": "2025.03.14", "dateReleased": "...",
     "count": 1234,
     "vulnerabilities": [{"cveID": "CVE-2021-44228", "vendorProject": "...",
                          "product": "...", "dateAdded": "2021-12-10",
                          "shortDescription": "...", "requiredAction": "...",
                          "dueDate": "...", "knownRansomwareCampaignUse": "Known"}]}

**Verification status: NOT live-verified.**  ``LAST_VERIFIED_LIVE`` is ``None``;
this environment cannot reach ``www.cisa.gov``.  All tests use synthetic,
catalogue-shaped fixtures.

Data-integrity rules enforced here:

* ``count`` must equal ``len(vulnerabilities)`` — a truncated download is a
  failure, not a smaller catalogue;
* duplicate or malformed ``cveID`` values fail the whole document, because
  "listed=False" answers derived from a partial index would be wrong;
* the catalogue version and release date are preserved so downstream consumers
  can state exactly which snapshot an assessment used.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from .errors import SourceRateLimited, SourceResponseError, ValidationError, sanitize
from .ratelimit import RateGate
from .retry import RetryPolicy, call_with_retry
from .schema import CveId, coerce_text, parse_timestamp, utcnow
from .transport import Transport, transport_kind

__all__ = [
    "KEV_URL",
    "LAST_VERIFIED_LIVE",
    "MAX_CATALOG_BYTES",
    "CachedKevCatalog",
    "KevCatalog",
    "KevConnector",
    "KevEntry",
]

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

#: Set only after a recorded, successful real fetch.
LAST_VERIFIED_LIVE: str | None = None

#: The real catalogue is single-digit MB; anything far beyond that is an error.
MAX_CATALOG_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class KevEntry:
    """One catalogue row. Only fields CISA actually publishes are modelled."""

    cve: CveId
    date_added: datetime | None
    vendor: str | None
    product: str | None
    name: str | None
    ransomware_use: str | None
    due_date: date | None

    @property
    def known_ransomware(self) -> bool | None:
        """``None`` when the source says ``Unknown`` — never coerced to ``False``."""
        if self.ransomware_use is None:
            return None
        lowered = self.ransomware_use.strip().lower()
        if lowered == "known":
            return True
        if lowered == "unknown":
            return None
        return None


@dataclass(frozen=True)
class KevCatalog:
    """An immutable, versioned catalogue snapshot."""

    entries: Mapping[str, KevEntry]
    catalog_version: str | None
    released_at: datetime | None
    fetched_at: datetime
    origin: str = "live"

    @property
    def size(self) -> int:
        return len(self.entries)

    def lookup(self, cve: str | CveId) -> KevEntry | None:
        return self.entries.get(str(cve))

    def contains(self, cve: str | CveId) -> bool:
        return str(cve) in self.entries

    def as_dict(self) -> dict[str, Any]:
        return {
            "catalog_version": self.catalog_version,
            "released_at": self.released_at.isoformat() if self.released_at else None,
            "fetched_at": self.fetched_at.isoformat(),
            "entries": self.size,
            "origin": self.origin,
        }


def _catalog_from_document(
    document: Mapping[str, Any], *, fetched_at: datetime, origin: str
) -> KevCatalog:
    """Validate and index a catalogue document. Pure function, no I/O."""
    rows = document.get("vulnerabilities")
    if not isinstance(rows, list):
        raise ValidationError("KEV catalogue has no 'vulnerabilities' list", field="vulnerabilities")
    declared = document.get("count")
    if declared is not None:
        if not isinstance(declared, int) or isinstance(declared, bool):
            raise ValidationError("KEV 'count' is not an integer", field="count")
        if declared != len(rows):
            raise ValidationError(
                f"KEV catalogue is truncated: count={declared} rows={len(rows)}",
                field="count",
            )

    entries: dict[str, KevEntry] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValidationError("KEV row is not an object", field="vulnerabilities")
        try:
            cve = CveId.parse(row.get("cveID"))
        except ValidationError as exc:
            raise ValidationError(f"invalid KEV cveID: {exc}", field="cveID") from exc
        key = str(cve)
        if key in entries:
            # A duplicate means the feed is inconsistent; guessing which row wins
            # would silently change membership answers.
            raise ValidationError(f"duplicate KEV entry: {key}", field="cveID")
        entries[key] = KevEntry(
            cve=cve,
            date_added=_safe_date(row.get("dateAdded")),
            vendor=coerce_text(row.get("vendorProject"), field_name="vendorProject", limit=500),
            product=coerce_text(row.get("product"), field_name="product", limit=500),
            name=coerce_text(
                row.get("vulnerabilityName"), field_name="vulnerabilityName", limit=1000
            ),
            ransomware_use=coerce_text(
                row.get("knownRansomwareCampaignUse"),
                field_name="knownRansomwareCampaignUse",
                limit=50,
            ),
            due_date=_safe_calendar_date(row.get("dueDate")),
        )

    return KevCatalog(
        entries=entries,
        catalog_version=coerce_text(
            document.get("catalogVersion"), field_name="catalogVersion", limit=100
        ),
        released_at=_safe_date(document.get("dateReleased")),
        fetched_at=_aware(fetched_at),
        origin=origin,
    )


def _retry_after(headers: Mapping[str, str]) -> float | None:
    raw = headers.get("retry-after")
    if not raw:
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def _aware(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        raise ValidationError("timestamps must be timezone-aware", field="fetched_at")
    return moment.astimezone(timezone.utc)


def _safe_calendar_date(value: object) -> date | None:
    """Parse a ``YYYY-MM-DD`` deadline without inventing a time of day."""
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return date.fromisoformat(value.strip()[:10])
    except ValueError as exc:
        raise ValidationError("KEV dueDate is not a calendar date", field="dueDate") from exc


def _safe_date(value: object) -> datetime | None:
    """KEV dates are ``YYYY-MM-DD`` or a full timestamp; both are accepted."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError("date must be a string", field="date")
    text = value.strip()
    if not text:
        return None
    if len(text) == 10:
        text = f"{text}T00:00:00+00:00"
    return parse_timestamp(text, field_name="date")


@dataclass
class KevConnector:
    """Fetch the CISA KEV catalogue.

    ``transport`` is required; without it the call raises instead of returning an
    empty catalogue (an empty catalogue would read as "nothing is exploited").
    """

    transport: Transport | None = None
    retry: RetryPolicy = RetryPolicy()
    gate: RateGate | None = None
    timeout: float = 60.0
    origin: str = "live"
    sleep: Callable[[float], None] | None = None

    def __post_init__(self) -> None:
        if self.gate is None:
            # The feed is one large document, published once per day.
            self.gate = RateGate(min_interval=1.0)

    def fetch(self) -> KevCatalog:
        if self.transport is None:
            raise SourceResponseError("no transport configured", source="cisa-kev")

        def attempt() -> Mapping[str, Any]:
            assert self.gate is not None
            self.gate.wait()
            response = self.transport.get(  # type: ignore[union-attr]
                KEV_URL,
                headers={"Accept": "application/json", "User-Agent": "CICC-vuln-intel/0.1"},
                timeout=self.timeout,
            )
            if response.status == 429:
                raise SourceRateLimited(
                    "CISA KEV rate limited",
                    retry_after=_retry_after(response.headers),
                    status=429,
                    source="cisa-kev",
                )
            if response.status != 200:
                raise SourceResponseError(
                    f"unexpected CISA KEV status {response.status}",
                    status=response.status,
                    source="cisa-kev",
                )
            if len(response.body) > MAX_CATALOG_BYTES:
                raise SourceResponseError("KEV catalogue exceeds size limit", source="cisa-kev")
            try:
                document = json.loads(response.body)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SourceResponseError(
                    f"invalid KEV JSON: {sanitize(exc)}", source="cisa-kev"
                ) from exc
            if not isinstance(document, Mapping):
                raise SourceResponseError("KEV body is not an object", source="cisa-kev")
            return document

        document = call_with_retry(
            attempt, policy=self.retry, sleep=self.sleep or __import__("time").sleep
        )
        return _catalog_from_document(document, fetched_at=utcnow(), origin=self.origin)

    def parse(self, document: Mapping[str, Any], *, fetched_at: datetime | None = None) -> KevCatalog:
        """Parse an already-obtained document (fixtures, offline replay)."""
        return _catalog_from_document(
            document, fetched_at=fetched_at or utcnow(), origin=self.origin
        )

    @property
    def transport_kind(self) -> str:
        return transport_kind(self.transport)


@dataclass
class CachedKevCatalog:
    """TTL cache that keeps the last good catalogue across failures.

    Contract:

    * ``get()`` returns the catalogue and its age, or ``None`` if nothing has ever
      been fetched successfully;
    * a failed ``refresh()`` never destroys the previous snapshot — it returns it
      flagged ``stale`` with the failure recorded, so a caller can show
      "KEV data is 3 days old, last refresh failed" instead of an empty list;
    * ``stale`` is computed from ``max_age`` and is always reported.
    """

    connector: KevConnector
    max_age: timedelta = timedelta(days=2)
    clock: Callable[[], datetime] = utcnow
    _catalog: KevCatalog | None = None
    #: When *this cache* stored the snapshot, from the cache's own clock. Kept
    #: separate from ``catalog.fetched_at`` (source provenance) so TTL maths is
    #: driven by one clock and stays deterministic under test.
    _stored_at: datetime | None = None
    _last_error: str | None = None

    @property
    def last_error(self) -> str | None:
        return self._last_error

    def get(self) -> tuple[KevCatalog | None, timedelta | None, bool]:
        """Return ``(catalog, age, stale)``; ``catalog`` is ``None`` when empty."""
        if self._catalog is None or self._stored_at is None:
            return None, None, True
        age = self.clock() - self._stored_at
        return self._catalog, age, age > self.max_age

    def refresh(self) -> tuple[KevCatalog | None, bool, str | None]:
        """Attempt a refresh.

        Returns ``(catalog, used_stale_cache, error)``.  Never raises for a source
        failure: the outcome is data, and it must be visible to the caller.
        """
        try:
            fetched = self.connector.fetch()
        except Exception as exc:
            self._last_error = sanitize(exc)
            catalog, _, _ = self.get()
            return catalog, catalog is not None, self._last_error
        self._catalog = fetched
        self._stored_at = self.clock()
        self._last_error = None
        return fetched, False, None
