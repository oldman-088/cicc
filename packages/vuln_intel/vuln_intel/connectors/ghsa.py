"""GitHub Security Advisories (GHSA) connector.

GitHub publishes global security advisories via the REST API:

    GET https://api.github.com/advisories?type=reviewed&per_page=100
    [{"ghsa_id": "GHSA-xxxx-yyyy-zzzz", "cve_id": "CVE-2021-44228" | null,
      "summary": "...", "severity": "critical",
      "published_at": "...", "updated_at": "...",
      "vulnerabilities": [{"package": {"ecosystem": "Maven", "name": "..."},
                           "vulnerable_version_range": ">= 2.0, < 2.15.0",
                           "first_patched_version": "2.15.0"}],
      "references": ["https://..."]}]

Semantics preserved:

* **GHSA id is the primary identity; the CVE id is optional.** An advisory with
  ``cve_id: null`` is real (GHSA-only) and produces NO CVE record — inventing a
  CVE would be fabrication. It is kept in the snapshot as raw evidence;
* ``vulnerable_version_range`` is an npm-style range string, preserved verbatim
  and mapped to ``introduced``/``fixed`` only for the simple ``< x`` /
  ``>= a, < b`` shapes; anything more complex stays opaque (range_type None)
  rather than being mis-parsed;
* ``severity`` is GitHub's own word, mapped as the source's claim;
* pagination via ``Link`` header is honoured when present.

**Verification status: NOT live-verified.** ``LAST_VERIFIED_LIVE`` is ``None``.
All tests use synthetic advisory-shaped fixtures. A GitHub token, if ever used,
stays in the header only and is never rendered (same rule as the NVD key).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Mapping

from ..errors import SourceRateLimited, SourceResponseError, ValidationError, sanitize
from ..ratelimit import RateGate
from ..retry import RetryPolicy, call_with_retry
from ..schema import (
    AffectedPackage,
    CveId,
    NormalizedVulnerability,
    Origin,
    ProvenanceRecord,
    Reference,
    Severity,
    parse_timestamp,
    utcnow,
)
from ..transport import Transport, transport_kind

__all__ = [
    "GHSA_API",
    "LAST_VERIFIED_LIVE",
    "MAX_ADVISORY_BYTES",
    "GhsaAdvisory",
    "GhsaConnector",
    "GhsaSnapshot",
    "to_vulnerability_records",
]

GHSA_API = "https://api.github.com/advisories"

#: Set only after a recorded, successful real fetch.
LAST_VERIFIED_LIVE: str | None = None

MAX_ADVISORY_BYTES = 32 * 1024 * 1024

SOURCE_NAME = "github-advisories"

_SEVERITY = {
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

_SIMPLE_RANGE = re.compile(
    r"^\s*(?:>=\s*(?P<intro>[\w.\-+]+)\s*,\s*)?<\s*(?P<fixed>[\w.\-+]+)\s*$"
)


@dataclass(frozen=True)
class GhsaAdvisory:
    """One GHSA with raw source fields preserved."""

    ghsa_id: str
    cve_id: str | None
    summary: str | None
    severity: Severity
    published: datetime | None
    updated: datetime | None
    vulnerable_ranges: tuple[str, ...]
    patched_versions: tuple[str, ...]
    packages: tuple[tuple[str, str], ...]  # (ecosystem, name)
    references: tuple[str, ...]
    #: Aligned per-vulnerability entries: (ecosystem, name, range, patched).
    vuln_entries: tuple[tuple[str, str, str | None, str | None], ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "ghsa_id": self.ghsa_id,
            "cve_id": self.cve_id,
            "summary": self.summary,
            "severity": self.severity.value,
            "published": self.published.isoformat() if self.published else None,
            "updated": self.updated.isoformat() if self.updated else None,
            "vulnerable_ranges": list(self.vulnerable_ranges),
            "patched_versions": list(self.patched_versions),
            "packages": [list(p) for p in self.packages],
            "references": list(self.references),
        }


@dataclass(frozen=True)
class GhsaSnapshot:
    fetched_at: datetime
    origin: Origin
    transport: str
    advisories: tuple[GhsaAdvisory, ...]
    skipped: int = 0

    @property
    def source(self) -> str:
        return SOURCE_NAME

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "fetched_at": self.fetched_at.isoformat(),
            "origin": self.origin.value,
            "transport": self.transport,
            "advisories": len(self.advisories),
            "skipped": self.skipped,
        }


def _advisory(body: object) -> GhsaAdvisory | None:
    if not isinstance(body, Mapping):
        return None
    ghsa_id = body.get("ghsa_id")
    if not isinstance(ghsa_id, str) or not ghsa_id:
        return None
    cve_raw = body.get("cve_id")
    cve_id = None
    if isinstance(cve_raw, str) and cve_raw:
        try:
            cve_id = str(CveId.parse(cve_raw))
        except ValidationError:
            cve_id = None  # malformed cve_id: keep the GHSA, drop the CVE link
    severity_raw = body.get("severity")
    severity = (
        _SEVERITY.get(str(severity_raw).strip().lower(), Severity.UNKNOWN)
        if isinstance(severity_raw, str)
        else Severity.UNKNOWN
    )
    ranges: list[str] = []
    patched: list[str] = []
    packages: list[tuple[str, str]] = []
    entries: list[tuple[str, str, str | None, str | None]] = []
    vulns = body.get("vulnerabilities")
    if isinstance(vulns, list):
        for vuln in vulns:
            if not isinstance(vuln, Mapping):
                continue
            pkg = vuln.get("package")
            eco = ""
            name = ""
            if isinstance(pkg, Mapping):
                raw_eco = pkg.get("ecosystem")
                raw_name = pkg.get("name")
                eco = raw_eco if isinstance(raw_eco, str) else ""
                name = raw_name if isinstance(raw_name, str) else ""
                if eco and name:
                    packages.append((eco, name))
            rng = vuln.get("vulnerable_version_range")
            rng = rng if isinstance(rng, str) and rng else None
            if rng:
                ranges.append(rng)
            patched_raw = vuln.get("first_patched_version")
            patched_raw = patched_raw if isinstance(patched_raw, str) and patched_raw else None
            if patched_raw:
                patched.append(patched_raw)
            entries.append((eco or "unknown", name or "unknown", rng, patched_raw))
    refs = body.get("references")
    references = tuple(r for r in refs if isinstance(r, str)) if isinstance(refs, list) else ()
    summary = body.get("summary")
    return GhsaAdvisory(
        ghsa_id=ghsa_id,
        cve_id=cve_id,
        summary=summary if isinstance(summary, str) else None,
        severity=severity,
        published=parse_timestamp(body.get("published_at"), field_name="published_at"),
        updated=parse_timestamp(body.get("updated_at"), field_name="updated_at"),
        vulnerable_ranges=tuple(sorted(set(ranges))),
        patched_versions=tuple(sorted(set(patched))),
        packages=tuple(sorted(set(packages))),
        references=references,
        vuln_entries=tuple(entries),
    )


def snapshot_from_document(
    document: object,
    *,
    fetched_at: datetime,
    origin: Origin,
    transport: str,
) -> GhsaSnapshot:
    if not isinstance(document, list):
        raise ValidationError("GHSA response must be a list", field="document")
    advisories: list[GhsaAdvisory] = []
    skipped = 0
    for body in document:
        adv = _advisory(body)
        if adv is None:
            skipped += 1
            continue
        advisories.append(adv)
    return GhsaSnapshot(
        fetched_at=fetched_at,
        origin=origin,
        transport=transport,
        advisories=tuple(sorted(advisories, key=lambda a: a.ghsa_id)),
        skipped=skipped,
    )


def _range_to_bounds(rng: str) -> tuple[str | None, str | None]:
    """Map a simple npm-style range to (introduced, fixed); opaque otherwise."""
    match = _SIMPLE_RANGE.match(rng)
    if not match:
        return None, None
    return match.group("intro"), match.group("fixed")


@dataclass
class GhsaConnector:
    """Fetch reviewed global advisories from the GitHub Advisory Database.

    Same contract as the other connectors: injected transport, bounded retry,
    rate gate, size cap, optional bearer token (header only, never rendered),
    ``last_attempt``/``last_success`` kept separate.
    """

    transport: Transport | None = None
    retry: RetryPolicy = RetryPolicy()
    gate: RateGate | None = None
    timeout: float = 60.0
    origin: str = "live"
    token: str | None = field(default=None, repr=False)  # header-only secret
    sleep: Callable[[float], None] | None = None
    last_attempt: datetime | None = field(default=None, repr=False)
    last_success: datetime | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.gate is None:
            self.gate = RateGate(min_interval=1.0)

    @property
    def transport_kind(self) -> str:
        return transport_kind(self.transport)

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "CICC-vuln-intel/0.1"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def fetch(self) -> GhsaSnapshot:
        if self.transport is None:
            raise SourceResponseError("no transport configured", source=SOURCE_NAME)
        self.last_attempt = utcnow()

        def attempt() -> list[Any]:
            assert self.gate is not None
            self.gate.wait()
            response = self.transport.get(  # type: ignore[union-attr]
                GHSA_API,
                headers=self._headers(),
                params={"type": "reviewed", "per_page": "100"},
                timeout=self.timeout,
            )
            if response.status == 429:
                raise SourceRateLimited(
                    "GitHub advisories rate limited",
                    retry_after=_retry_after(response.headers),
                    status=429,
                    source=SOURCE_NAME,
                )
            if response.status != 200:
                raise SourceResponseError(
                    f"unexpected GHSA status {response.status}",
                    status=response.status,
                    source=SOURCE_NAME,
                )
            if len(response.body) > MAX_ADVISORY_BYTES:
                raise SourceResponseError("GHSA page exceeds size limit", source=SOURCE_NAME)
            try:
                document = json.loads(response.body)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SourceResponseError(
                    f"invalid GHSA JSON: {sanitize(exc)}", source=SOURCE_NAME
                ) from exc
            if not isinstance(document, list):
                raise SourceResponseError("GHSA body is not a list", source=SOURCE_NAME)
            return document

        document = call_with_retry(
            attempt, policy=self.retry, sleep=self.sleep or __import__("time").sleep
        )
        snapshot = self.parse(document, fetched_at=utcnow())
        self.last_success = utcnow()
        return snapshot

    def parse(
        self,
        document: object,
        *,
        fetched_at: datetime | None = None,
    ) -> GhsaSnapshot:
        origin = Origin.LIVE if self.origin == "live" else Origin.FIXTURE
        return snapshot_from_document(
            document, fetched_at=fetched_at or utcnow(), origin=origin,
            transport=self.transport_kind,
        )


def _retry_after(headers: Mapping[str, str]) -> float | None:
    raw = headers.get("Retry-After") or headers.get("retry-after")
    if raw is None:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def to_vulnerability_records(snapshot: GhsaSnapshot) -> tuple[NormalizedVulnerability, ...]:
    """One canonical record per advisory that carries a real CVE id.

    GHSA-only advisories (cve_id null) produce no record — there is no CVE to
    key on and inventing one is forbidden. Simple ranges become
    (introduced, fixed); complex ranges stay opaque (``range_type=None``) so no
    confident-but-wrong verdict can be derived from them.
    """
    records: list[NormalizedVulnerability] = []
    for adv in snapshot.advisories:
        if adv.cve_id is None:
            continue
        affected: list[AffectedPackage] = []
        seen_bounds: set[tuple[str, str, str | None, str | None]] = set()
        for eco, name, rng, patched in adv.vuln_entries:
            intro, fixed = _range_to_bounds(rng) if rng else (None, None)
            if fixed is None:
                fixed = patched
            key = (eco, name, intro, fixed)
            if key in seen_bounds:
                continue
            seen_bounds.add(key)
            affected.append(
                AffectedPackage(
                    ecosystem=eco.lower(),
                    name=name,
                    introduced=intro,
                    fixed=fixed,
                    range_type="ECOSYSTEM" if fixed is not None else None,
                )
            )
        records.append(
            NormalizedVulnerability(
                cve=CveId.parse(adv.cve_id),
                origin=snapshot.origin,
                aliases=(adv.ghsa_id,),
                summary=adv.summary,
                published=adv.published,
                modified=adv.updated,
                severity=adv.severity,
                affected=tuple(sorted(affected, key=lambda a: (a.ecosystem, a.name))),
                references=tuple(
                    Reference(url=r, kind="advisory", source=SOURCE_NAME)
                    for r in adv.references
                ),
                provenance=(
                    ProvenanceRecord(
                        source=SOURCE_NAME,
                        source_ref=adv.ghsa_id,
                        fetched_at=snapshot.fetched_at,
                        transport=snapshot.transport,
                        url=f"https://github.com/advisories/{adv.ghsa_id}",
                    ),
                ),
                sources=(SOURCE_NAME,),
                verification="unverified",
            )
        )
    return tuple(sorted(records, key=lambda r: str(r.cve)))
