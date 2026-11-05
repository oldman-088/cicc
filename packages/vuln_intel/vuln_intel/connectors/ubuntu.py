"""Ubuntu Security Notices (USN) connector — completes B-04's Ubuntu half.

Ubuntu publishes a machine-readable USN database:

    GET https://usn.ubuntu.com/usn-db/database.json.bz2   (bzip2-compressed JSON)

    {"USN-5800-1": {"id": "USN-5800-1", "title": "...",
                    "cves": ["CVE-2022-1234"], "severity": "high",
                    "published": "2022-12-14T00:00:00Z", "updated": "...",
                    "releases": {"jammy": {"sources": {"openssl": {
                        "status": "released", "fixed_version": "3.0.2-0ubuntu1.8"}}}}}}}

The document is large and republished on change, hence the bzip2 body and the
size cap.  Semantics preserved here:

* the **USN id is the primary key** of a notice; the CVEs it references are
  *published relationships* (``cves`` list), so mapping a notice to its CVEs is
  evidence-based, never guessed — and a notice with an empty ``cves`` list
  produces no vulnerability record;
* per-release, per-source-package ``status``/``fixed_version`` become Debian-
  style affected entries under ecosystem ``ubuntu``;
* ``severity`` is Ubuntu's own word (low/medium/high/critical/unknown) and is
  mapped onto our :class:`Severity` **as the source's claim** — it is never
  merged with CVSS severity;
* ``published``/``updated`` are preserved as timestamps.

**Verification status: NOT live-verified.**  ``LAST_VERIFIED_LIVE`` is ``None``;
this environment cannot reach ``usn.ubuntu.com``.  All tests use synthetic
USN-shaped fixtures.
"""

from __future__ import annotations

import bz2
import json
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
    "LAST_VERIFIED_LIVE",
    "MAX_USN_BYTES",
    "USN_DB_URL",
    "UbuntuSnapshot",
    "UbuntuUsnConnector",
    "UsnNotice",
    "UsnPackageFix",
    "to_vulnerability_records",
]

USN_DB_URL = "https://usn.ubuntu.com/usn-db/database.json.bz2"

#: Set only after a recorded, successful real fetch.
LAST_VERIFIED_LIVE: str | None = None

#: Decompressed cap: the real DB is tens of MB uncompressed; cap the *raw* body
#: lower and the decompressed document at this limit.
MAX_USN_BYTES = 64 * 1024 * 1024
MAX_USN_RAW_BYTES = 32 * 1024 * 1024

SOURCE_NAME = "ubuntu-usn"

#: Ubuntu's own severity vocabulary -> our Severity (source claim, not CVSS).
_SEVERITY = {
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


@dataclass(frozen=True)
class UsnPackageFix:
    """One (release, source package) verdict inside a notice."""

    release: str
    package: str
    status: str
    fixed_version: str | None = None

    @property
    def is_released(self) -> bool:
        return self.status in ("released", "released.*") and self.fixed_version is not None

    def as_dict(self) -> dict[str, Any]:
        return {
            "release": self.release,
            "package": self.package,
            "status": self.status,
            "fixed_version": self.fixed_version,
        }


@dataclass(frozen=True)
class UsnNotice:
    """One USN with its raw, source-faithful content."""

    usn_id: str
    title: str | None
    description: str | None
    cves: tuple[str, ...]
    severity: Severity
    published: datetime | None
    updated: datetime | None
    fixes: tuple[UsnPackageFix, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "usn_id": self.usn_id,
            "title": self.title,
            "description": self.description,
            "cves": list(self.cves),
            "severity": self.severity.value,
            "published": self.published.isoformat() if self.published else None,
            "updated": self.updated.isoformat() if self.updated else None,
            "fixes": [f.as_dict() for f in self.fixes],
        }


@dataclass(frozen=True)
class UbuntuSnapshot:
    """An immutable view of the USN database."""

    fetched_at: datetime
    origin: Origin
    transport: str
    notices: tuple[UsnNotice, ...]
    #: Notices skipped as malformed — counted, never silently dropped.
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
            "notices": len(self.notices),
            "skipped": self.skipped,
        }


def _package_fixes(releases: object) -> list[UsnPackageFix]:
    fixes: list[UsnPackageFix] = []
    if not isinstance(releases, Mapping):
        return fixes
    for release, release_body in releases.items():
        if not isinstance(release_body, Mapping):
            continue
        sources = release_body.get("sources")
        if not isinstance(sources, Mapping):
            continue
        for package, pkg_body in sources.items():
            if not isinstance(pkg_body, Mapping):
                continue
            status = pkg_body.get("status")
            if not isinstance(status, str) or not status:
                continue
            fixed = pkg_body.get("fixed_version")
            fixes.append(
                UsnPackageFix(
                    release=str(release),
                    package=str(package),
                    status=status,
                    fixed_version=fixed if isinstance(fixed, str) and fixed else None,
                )
            )
    return fixes


def _notice(usn_id: str, body: object) -> UsnNotice | None:
    if not isinstance(body, Mapping):
        return None
    raw_cves = body.get("cves")
    cves: list[str] = []
    if isinstance(raw_cves, list):
        for cve in raw_cves:
            if not isinstance(cve, str):
                continue
            try:
                cves.append(str(CveId.parse(cve)))
            except ValidationError:
                continue  # a malformed cve string is skipped, not fatal
    severity_raw = body.get("severity")
    severity = (
        _SEVERITY.get(str(severity_raw).strip().lower(), Severity.UNKNOWN)
        if isinstance(severity_raw, str)
        else Severity.UNKNOWN
    )
    title = body.get("title")
    description = body.get("description")
    return UsnNotice(
        usn_id=usn_id,
        title=title if isinstance(title, str) else None,
        description=description if isinstance(description, str) else None,
        cves=tuple(sorted(set(cves))),
        severity=severity,
        published=parse_timestamp(body.get("published"), field_name="published"),
        updated=parse_timestamp(body.get("updated"), field_name="updated"),
        fixes=tuple(sorted(_package_fixes(body.get("releases")),
                           key=lambda f: (f.release, f.package))),
    )


def snapshot_from_document(
    document: Mapping[str, Any],
    *,
    fetched_at: datetime,
    origin: Origin,
    transport: str,
) -> UbuntuSnapshot:
    if not isinstance(document, Mapping):
        raise ValidationError("USN document must be an object", field="document")
    notices: list[UsnNotice] = []
    skipped = 0
    for usn_id, body in document.items():
        notice = _notice(str(usn_id), body)
        if notice is None:
            skipped += 1
            continue
        notices.append(notice)
    return UbuntuSnapshot(
        fetched_at=fetched_at,
        origin=origin,
        transport=transport,
        notices=tuple(sorted(notices, key=lambda n: n.usn_id)),
        skipped=skipped,
    )


def _decode_body(body: bytes) -> Mapping[str, Any]:
    """Decode the USN DB body, transparently handling bzip2."""
    if len(body) > MAX_USN_RAW_BYTES:
        raise SourceResponseError("USN body exceeds raw size limit", source=SOURCE_NAME)
    raw = body
    if body[:3] == b"BZh":
        try:
            raw = bz2.decompress(body)
        except OSError as exc:
            raise SourceResponseError(
                f"invalid bzip2 USN body: {sanitize(exc)}", source=SOURCE_NAME
            ) from exc
    if len(raw) > MAX_USN_BYTES:
        raise SourceResponseError("USN document exceeds size limit", source=SOURCE_NAME)
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceResponseError(
            f"invalid USN JSON: {sanitize(exc)}", source=SOURCE_NAME
        ) from exc
    if not isinstance(document, Mapping):
        raise SourceResponseError("USN body is not an object", source=SOURCE_NAME)
    return document


def _retry_after(headers: Mapping[str, str]) -> float | None:
    raw = headers.get("Retry-After") or headers.get("retry-after")
    if raw is None:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


@dataclass
class UbuntuUsnConnector:
    """Fetch the Ubuntu USN database.

    Same contract as the other connectors: transport required for ``fetch``,
    bounded retry, rate gate, size caps, and ``last_attempt``/``last_success``
    kept separate — ``parse`` never touches them.
    """

    transport: Transport | None = None
    retry: RetryPolicy = RetryPolicy()
    gate: RateGate | None = None
    timeout: float = 180.0
    origin: str = "live"
    sleep: Callable[[float], None] | None = None
    last_attempt: datetime | None = field(default=None, repr=False)
    last_success: datetime | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.gate is None:
            self.gate = RateGate(min_interval=5.0)

    @property
    def transport_kind(self) -> str:
        return transport_kind(self.transport)

    def fetch(self) -> UbuntuSnapshot:
        if self.transport is None:
            raise SourceResponseError("no transport configured", source=SOURCE_NAME)
        self.last_attempt = utcnow()

        def attempt() -> Mapping[str, Any]:
            assert self.gate is not None
            self.gate.wait()
            response = self.transport.get(  # type: ignore[union-attr]
                USN_DB_URL,
                headers={"Accept": "application/json", "User-Agent": "CICC-vuln-intel/0.1"},
                timeout=self.timeout,
            )
            if response.status == 429:
                raise SourceRateLimited(
                    "Ubuntu USN rate limited",
                    retry_after=_retry_after(response.headers),
                    status=429,
                    source=SOURCE_NAME,
                )
            if response.status != 200:
                raise SourceResponseError(
                    f"unexpected Ubuntu USN status {response.status}",
                    status=response.status,
                    source=SOURCE_NAME,
                )
            return _decode_body(response.body)

        document = call_with_retry(
            attempt, policy=self.retry, sleep=self.sleep or __import__("time").sleep
        )
        snapshot = self.parse(document, fetched_at=utcnow())
        self.last_success = utcnow()
        return snapshot

    def parse(
        self,
        document: Mapping[str, Any],
        *,
        fetched_at: datetime | None = None,
    ) -> UbuntuSnapshot:
        origin = Origin.LIVE if self.origin == "live" else Origin.FIXTURE
        return snapshot_from_document(
            document, fetched_at=fetched_at or utcnow(), origin=origin,
            transport=self.transport_kind,
        )


def to_vulnerability_records(snapshot: UbuntuSnapshot) -> tuple[NormalizedVulnerability, ...]:
    """One canonical record per (USN, CVE) pair — the CVE list is published evidence.

    A notice with no CVE produces no record (there is nothing to key a
    vulnerability on, and inventing one is forbidden).  The USN id travels as an
    alias; per-release fixed versions become ``ubuntu``-ecosystem affected
    entries; severity is Ubuntu's own claim and is stored as the record's
    severity only because no CVSS exists for the notice.
    """
    records: list[NormalizedVulnerability] = []
    for notice in snapshot.notices:
        affected: list[AffectedPackage] = []
        for fix in notice.fixes:
            if fix.is_released or fix.status in ("needed", "pending", "ignored", "not-affected"):
                affected.append(
                    AffectedPackage(
                        ecosystem="ubuntu",
                        name=fix.package,
                        fixed=fix.fixed_version if fix.is_released else None,
                        range_type="ECOSYSTEM",
                    )
                )
        for cve in notice.cves:
            records.append(
                NormalizedVulnerability(
                    cve=CveId.parse(cve),
                    origin=snapshot.origin,
                    aliases=(notice.usn_id,),
                    summary=notice.title,
                    details=notice.description,
                    published=notice.published,
                    modified=notice.updated,
                    severity=notice.severity,
                    affected=tuple(
                        sorted(affected, key=lambda a: (a.name, a.fixed or ""))
                    ),
                    references=(
                        Reference(
                            url=f"https://ubuntu.com/security/{notice.usn_id}",
                            kind="advisory",
                            source=SOURCE_NAME,
                        ),
                    ),
                    provenance=(
                        ProvenanceRecord(
                            source=SOURCE_NAME,
                            source_ref=notice.usn_id,
                            fetched_at=snapshot.fetched_at,
                            transport=snapshot.transport,
                            url=USN_DB_URL,
                        ),
                    ),
                    sources=(SOURCE_NAME,),
                    verification="unverified",
                )
            )
    return tuple(sorted(records, key=lambda r: (str(r.cve), r.aliases)))
