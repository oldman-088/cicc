"""Debian Security Tracker connector (B-04).

The Debian security tracker (https://security-tracker.debian.org) publishes a
single public-domain (CC0) JSON document mapping every source package to the
issues filed against it, with **per-release** status and fixed version:

    GET https://security-tracker.debian.org/tracker/data/json
    {"<package>": {"CVE-2021-44228": {
        "description": "...", "debianbug": 1000123,
        "releases": {"bookworm": {"status": "resolved",
                                   "fixed_version": "2.17.0-1+deb12u1",
                                   "urgency": "high"}}}}}

Why this source matters: for Linux assets it is the highest-quality remediation
data available — the exact fixed package version *per distribution release*,
which NVD/OSV ranges cannot express.  It is consumed here as a cross-reference
that enriches CVE records with DSA/USN aliases and Debian fixed versions.

Status mapping (tracker -> our model), deliberately conservative:

* ``open`` / ``pending`` / ``undetermined`` -> affected, no fixed version yet;
* ``resolved`` -> affected range closed by ``fixed_version``;
* ``ignored`` / ``not-affected`` -> NOT emitted as an affected range (kept in the
  snapshot, which preserves the source's own words);
* unknown statuses -> kept in the snapshot, skipped from affected ranges, and
  counted in ``skipped`` so nothing disappears silently.

**Verification status: NOT live-verified.**  ``LAST_VERIFIED_LIVE`` is ``None``;
this environment cannot reach ``security-tracker.debian.org``.  All tests use
synthetic tracker-shaped fixtures.  The connector never invents a CVE: a
non-CVE issue key (e.g. ``TEMP-...``) is preserved as tracker data but produces
no :class:`~vuln_intel.schema.NormalizedVulnerability`.
"""

from __future__ import annotations

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
    utcnow,
)
from ..transport import Transport, transport_kind

__all__ = [
    "DEBIAN_TRACKER_URL",
    "LAST_VERIFIED_LIVE",
    "MAX_TRACKER_BYTES",
    "DebianIssue",
    "DebianReleaseFix",
    "DebianTrackerConnector",
    "DebianTrackerSnapshot",
    "to_vulnerability_records",
]

DEBIAN_TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"

#: Set only after a recorded, successful real fetch.
LAST_VERIFIED_LIVE: str | None = None

#: The real document is tens of MB; anything far beyond that is an error, not data.
MAX_TRACKER_BYTES = 256 * 1024 * 1024

#: Tracker statuses that mean "this release is vulnerable" (no fix shipped yet).
VULNERABLE_STATUSES = frozenset({"open", "pending", "undetermined"})
#: ``resolved`` carries the fix; these two explicitly say the release is fine.
CLOSED_STATUSES = frozenset({"resolved", "ignored", "not-affected"})

SOURCE_NAME = "debian-security-tracker"


@dataclass(frozen=True)
class DebianReleaseFix:
    """One release's verdict for one issue, in the tracker's own vocabulary."""

    release: str
    status: str
    fixed_version: str | None = None
    urgency: str | None = None
    #: Why the release was ignored / not-affected, when the tracker says so.
    note: str | None = None

    @property
    def is_vulnerable(self) -> bool:
        return self.status in VULNERABLE_STATUSES

    @property
    def is_resolved(self) -> bool:
        return self.status == "resolved" and self.fixed_version is not None

    def as_dict(self) -> dict[str, Any]:
        return {
            "release": self.release,
            "status": self.status,
            "fixed_version": self.fixed_version,
            "urgency": self.urgency,
            "note": self.note,
        }


@dataclass(frozen=True)
class DebianIssue:
    """One issue filed against one source package, with full per-release data."""

    package: str
    issue_id: str
    description: str | None
    releases: tuple[DebianReleaseFix, ...] = ()
    debianbug: int | None = None

    @property
    def cve(self) -> CveId | None:
        """The CVE identity, only when the issue key actually is one."""
        try:
            return CveId.parse(self.issue_id)
        except ValidationError:
            return None

    def as_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "issue_id": self.issue_id,
            "description": self.description,
            "debianbug": self.debianbug,
            "releases": [r.as_dict() for r in self.releases],
        }


@dataclass(frozen=True)
class DebianTrackerSnapshot:
    """An immutable, versioned view of the tracker document."""

    fetched_at: datetime
    origin: Origin
    transport: str
    issues: tuple[DebianIssue, ...]
    #: Rows skipped as malformed. Counted, never silently dropped: a partial
    #: parse must be visible, because "not listed" derived from it would be wrong.
    skipped: int = 0
    #: Packages present in the document (useful for coverage stats).
    packages: int = 0

    @property
    def source(self) -> str:
        return SOURCE_NAME

    def by_cve(self) -> Mapping[str, tuple[DebianIssue, ...]]:
        grouped: dict[str, list[DebianIssue]] = {}
        for issue in self.issues:
            cve = issue.cve
            if cve is not None:
                grouped.setdefault(str(cve), []).append(issue)
        return {cve: tuple(items) for cve, items in grouped.items()}

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "fetched_at": self.fetched_at.isoformat(),
            "origin": self.origin.value,
            "transport": self.transport,
            "packages": self.packages,
            "issues": len(self.issues),
            "skipped": self.skipped,
        }


def _release_fix(release: str, body: object) -> DebianReleaseFix | None:
    if not isinstance(body, Mapping):
        return None
    status = body.get("status")
    if not isinstance(status, str) or not status:
        return None
    fixed = body.get("fixed_version")
    urgency = body.get("urgency")
    note_parts = [body[k] for k in ("nodsa", "no-dsa", "reason") if isinstance(body.get(k), str)]
    return DebianReleaseFix(
        release=release,
        status=status,
        fixed_version=fixed if isinstance(fixed, str) and fixed else None,
        urgency=urgency if isinstance(urgency, str) and urgency else None,
        note="; ".join(note_parts) or None,
    )


def _issue(package: str, issue_id: str, body: object) -> DebianIssue | None:
    if not isinstance(body, Mapping):
        return None
    description = body.get("description")
    raw_releases = body.get("releases")
    releases: list[DebianReleaseFix] = []
    if isinstance(raw_releases, Mapping):
        for release_name, release_body in raw_releases.items():
            fix = _release_fix(str(release_name), release_body)
            if fix is not None:
                releases.append(fix)
    bug = body.get("debianbug")
    return DebianIssue(
        package=package,
        issue_id=issue_id,
        description=description if isinstance(description, str) else None,
        releases=tuple(sorted(releases, key=lambda r: r.release)),
        debianbug=bug if isinstance(bug, int) else None,
    )


def snapshot_from_document(
    document: Mapping[str, Any],
    *,
    fetched_at: datetime,
    origin: Origin,
    transport: str,
) -> DebianTrackerSnapshot:
    """Parse a tracker document, counting skipped rows instead of dropping them."""
    if not isinstance(document, Mapping):
        raise ValidationError("tracker document must be an object", field="document")
    issues: list[DebianIssue] = []
    skipped = 0
    for package, package_body in document.items():
        if not isinstance(package_body, Mapping):
            skipped += 1
            continue
        for issue_id, issue_body in package_body.items():
            issue = _issue(str(package), str(issue_id), issue_body)
            if issue is None:
                skipped += 1
                continue
            issues.append(issue)
    return DebianTrackerSnapshot(
        fetched_at=fetched_at,
        origin=origin,
        transport=transport,
        issues=tuple(sorted(issues, key=lambda i: (i.package, i.issue_id))),
        skipped=skipped,
        packages=len(document),
    )


@dataclass
class DebianTrackerConnector:
    """Fetch the Debian security tracker document.

    ``transport`` is required for ``fetch``; without it the call raises rather
    than returning an empty snapshot (an empty snapshot would read as "no
    package is affected anywhere").  ``last_attempt``/``last_success`` are kept
    separate per the Master Prompt §7 rule, and neither is ever set by
    ``parse`` — parsing a fixture is not a synchronization.
    """

    transport: Transport | None = None
    retry: RetryPolicy = RetryPolicy()
    gate: RateGate | None = None
    timeout: float = 120.0
    origin: str = "live"
    sleep: Callable[[float], None] | None = None
    last_attempt: datetime | None = field(default=None, repr=False)
    last_success: datetime | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.gate is None:
            # One large document, republished on change; be a polite citizen.
            self.gate = RateGate(min_interval=5.0)

    @property
    def transport_kind(self) -> str:
        return transport_kind(self.transport)

    def fetch(self) -> DebianTrackerSnapshot:
        if self.transport is None:
            raise SourceResponseError("no transport configured", source=SOURCE_NAME)
        self.last_attempt = utcnow()

        def attempt() -> Mapping[str, Any]:
            assert self.gate is not None
            self.gate.wait()
            response = self.transport.get(  # type: ignore[union-attr]
                DEBIAN_TRACKER_URL,
                headers={"Accept": "application/json", "User-Agent": "CICC-vuln-intel/0.1"},
                timeout=self.timeout,
            )
            if response.status == 429:
                raise SourceRateLimited(
                    "Debian tracker rate limited",
                    retry_after=_retry_after(response.headers),
                    status=429,
                    source=SOURCE_NAME,
                )
            if response.status != 200:
                raise SourceResponseError(
                    f"unexpected Debian tracker status {response.status}",
                    status=response.status,
                    source=SOURCE_NAME,
                )
            if len(response.body) > MAX_TRACKER_BYTES:
                raise SourceResponseError(
                    "tracker document exceeds size limit", source=SOURCE_NAME
                )
            try:
                document = json.loads(response.body)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SourceResponseError(
                    f"invalid tracker JSON: {sanitize(exc)}", source=SOURCE_NAME
                ) from exc
            if not isinstance(document, Mapping):
                raise SourceResponseError("tracker body is not an object", source=SOURCE_NAME)
            return document

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
    ) -> DebianTrackerSnapshot:
        """Parse an already-obtained document (fixtures, offline replay)."""
        origin = Origin.LIVE if self.origin == "live" else Origin.FIXTURE
        return snapshot_from_document(
            document,
            fetched_at=fetched_at or utcnow(),
            origin=origin,
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


def to_vulnerability_records(snapshot: DebianTrackerSnapshot) -> tuple[NormalizedVulnerability, ...]:
    """Normalize CVE-keyed tracker issues into canonical records.

    Each CVE becomes one record whose ``affected`` entries are Debian releases:
    vulnerable releases carry no fixed version, resolved ones carry theirs.
    The tracker's per-release urgency is preserved in ``details`` (the shared
    model has no per-range urgency field, and inventing a severity from it
    would overstate what the source said).  Non-CVE issue keys produce no
    record — the snapshot keeps them as raw evidence.
    """
    records: list[NormalizedVulnerability] = []
    for cve, issues in snapshot.by_cve().items():
        affected: list[AffectedPackage] = []
        urgencies: list[str] = []
        descriptions: list[str] = []
        for issue in issues:
            if issue.description:
                descriptions.append(issue.description)
            for fix in issue.releases:
                if fix.is_vulnerable or fix.is_resolved:
                    affected.append(
                        AffectedPackage(
                            ecosystem="debian",
                            name=issue.package,
                            fixed=fix.fixed_version,
                            range_type="ECOSYSTEM",
                        )
                    )
                if fix.urgency:
                    urgencies.append(f"{fix.release}={fix.urgency}")
        if not affected:
            # Every release is not-affected/ignored: still emit the record so
            # "tracker says not affected" is visible, with an empty affected set.
            pass
        records.append(
            NormalizedVulnerability(
                cve=CveId.parse(cve),
                origin=snapshot.origin,
                aliases=tuple(sorted({i.issue_id for i in issues} - {cve})),
                summary=descriptions[0] if descriptions else None,
                details="; ".join(f"debian urgency: {u}" for u in sorted(set(urgencies)))
                or None,
                affected=tuple(
                    sorted(affected, key=lambda a: (a.name, a.fixed or ""))
                ),
                references=(
                    Reference(
                        url=f"https://security-tracker.debian.org/tracker/{cve}",
                        kind="advisory",
                        source=SOURCE_NAME,
                    ),
                ),
                provenance=(
                    ProvenanceRecord(
                        source=SOURCE_NAME,
                        source_ref=cve,
                        fetched_at=snapshot.fetched_at,
                        transport=snapshot.transport,
                        url=DEBIAN_TRACKER_URL,
                    ),
                ),
                sources=(SOURCE_NAME,),
                verification="unverified",
            )
        )
    return tuple(sorted(records, key=lambda r: str(r.cve)))
