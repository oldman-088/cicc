"""OSV (Open Source Vulnerabilities) connector.

Endpoint contract, from the published OSV API documentation:

    GET https://api.osv.dev/v1/vulns/<id>            -> one OSV record
    POST https://api.osv.dev/v1/query                -> records for a package/version
    POST https://api.osv.dev/v1/querybatch           -> ids for many packages

A record (abridged):

    {
      "id": "GHSA-xxxx-xxxx-xxxx", "aliases": ["CVE-2024-1234"],
      "summary": "...", "details": "...",
      "published": "2024-01-01T00:00:00Z", "modified": "...",
      "severity": [{"type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
      "affected": [{"package": {"ecosystem": "npm", "name": "left-pad",
                                "purl": "pkg:npm/left-pad"},
                    "ranges": [{"type": "SEMVER",
                                "events": [{"introduced": "0"}, {"fixed": "1.3.0"}]}],
                    "versions": ["1.0.0"]}],
      "references": [{"type": "ADVISORY", "url": "..."}],
      "database_specific": {"severity": "HIGH"},
      "withdrawn": "2024-02-01T00:00:00Z"   # present when retracted
    }

**Verification status: NOT live-verified.**  ``api.osv.dev`` is unreachable from
this execution environment; all tests use synthetic fixtures built from the
documented shape.  ``LAST_VERIFIED_LIVE`` remains ``None``.

Normalization rules worth stating explicitly:

* OSV is keyed by advisory IDs (GHSA/PYSEC/…).  A record is only usable in the
  CVE-centric model when it carries a ``CVE-`` alias; otherwise it is returned as
  an *advisory-only* entry so a CVE is never invented for it.
* ``withdrawn`` records are surfaced as withdrawn, not silently deleted.
* Version ranges are preserved verbatim; no version comparison is attempted.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Mapping, Sequence

from ..cvss import UnsupportedVector, score_vector
from ..errors import (
    SourceNotFound,
    SourceRateLimited,
    SourceResponseError,
    ValidationError,
    sanitize,
)
from ..ratelimit import RateGate, quota_for_osv
from ..retry import RetryPolicy, call_with_retry
from ..schema import (
    AffectedPackage,
    CollectionStatus,
    CveId,
    CvssScore,
    NormalizedVulnerability,
    Origin,
    ProvenanceRecord,
    Reference,
    Severity,
    SourceKind,
    SourceState,
    coerce_text,
    mapping_list,
    parse_timestamp,
    utcnow,
)
from ..transport import Transport, transport_kind

__all__ = ["LAST_VERIFIED_LIVE", "OSV_API", "AdvisoryOnly", "OsvConnector"]

OSV_API = "https://api.osv.dev/v1"

#: Set only after a recorded, successful real fetch.
LAST_VERIFIED_LIVE: str | None = None

_CVE_ALIAS = "CVE-"


@dataclass(frozen=True)
class AdvisoryOnly:
    """An OSV record with no CVE alias.

    Kept separate on purpose: it carries real security value (a fixed version)
    but must not be forced into a CVE row by fabricating an identifier.
    """

    advisory_id: str
    summary: str | None
    affected: tuple[AffectedPackage, ...]
    published: datetime | None
    withdrawn: datetime | None
    references: tuple[Reference, ...]

    def as_summary(self) -> dict[str, Any]:
        return {
            "advisory_id": self.advisory_id,
            "summary": self.summary,
            "published": self.published.isoformat() if self.published else None,
            "withdrawn": self.withdrawn.isoformat() if self.withdrawn else None,
            "affected": [
                {"ecosystem": a.ecosystem, "name": a.name, "fixed": a.fixed}
                for a in self.affected
            ],
        }


@dataclass(frozen=True)
class OsvResult:
    """OSV collection outcome: CVE-bearing records plus advisory-only entries."""

    state: SourceState
    records: tuple[NormalizedVulnerability, ...] = ()
    advisories: tuple[AdvisoryOnly, ...] = ()
    warnings: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.as_dict(),
            "records": [r.as_summary() for r in self.records],
            "advisories": [a.as_summary() for a in self.advisories],
            "warnings": list(self.warnings),
        }


@dataclass
class OsvConnector:
    """Read-only OSV client.

    ``transport`` must support only ``get``; the query endpoints are POST-based
    in the real API, so :meth:`query_package` requires a transport that also
    implements ``post``.  When it does not, the call fails explicitly instead of
    degrading to a partial answer.
    """

    transport: Transport | None = None
    retry: RetryPolicy = RetryPolicy()
    gate: RateGate | None = None
    timeout: float = 30.0
    origin: Origin = Origin.LIVE
    sleep: Callable[[float], None] | None = None

    def __post_init__(self) -> None:
        if self.gate is None:
            self.gate = quota_for_osv()

    def _headers(self) -> dict[str, str]:
        return {"Accept": "application/json", "User-Agent": "CICC-vuln-intel/0.1"}

    def _get(self, path: str) -> Mapping[str, Any]:
        if self.transport is None:
            raise SourceResponseError("no transport configured", source="osv")
        url = f"{OSV_API}/{path.lstrip('/')}"

        def attempt() -> Mapping[str, Any]:
            assert self.gate is not None
            self.gate.wait()
            response = self.transport.get(  # type: ignore[union-attr]
                url, headers=self._headers(), timeout=self.timeout
            )
            if response.status == 404:
                raise SourceNotFound("OSV id not found", status=404, source="osv")
            if response.status == 429:
                raise SourceRateLimited(
                    "OSV rate limited",
                    retry_after=_retry_after(response.headers),
                    status=429,
                    source="osv",
                )
            if response.status != 200:
                raise SourceResponseError(
                    f"unexpected OSV status {response.status}",
                    status=response.status,
                    source="osv",
                )
            body = response.json()
            if not isinstance(body, Mapping):
                raise SourceResponseError("OSV body is not an object", source="osv")
            return body

        return call_with_retry(
            attempt, policy=self.retry, sleep=self.sleep or __import__("time").sleep
        )

    # -- public API -------------------------------------------------------
    def get_vulnerability(self, osv_id: str) -> tuple[NormalizedVulnerability | None, AdvisoryOnly]:
        """Fetch one OSV record.

        Returns ``(record, advisory)``: exactly one of the two is populated.
        A record without a CVE alias yields ``(None, advisory)`` — no synthetic
        CVE is created.
        """
        if not isinstance(osv_id, str) or not osv_id.strip():
            raise ValidationError("OSV id must be a non-empty string", field="id")
        identifier = osv_id.strip()
        if "/" in identifier or "?" in identifier:
            raise ValidationError("OSV id contains illegal characters", field="id")
        body = self._get(f"vulns/{identifier}")
        return self.parse_record(body, fetched_at=utcnow())

    def lookup_cve(self, cve_id: str | CveId) -> tuple[NormalizedVulnerability | None, AdvisoryOnly]:
        """Resolve a CVE through OSV's query endpoint (GET form used for CVE ids)."""
        identifier = cve_id if isinstance(cve_id, CveId) else CveId.parse(cve_id)
        body = self._get(f"vulns/{identifier}")
        record, advisory = self.parse_record(body, fetched_at=utcnow())
        if record is not None and record.cve != identifier:
            raise ValidationError(
                "OSV returned a record for a different CVE", field="cve"
            )
        return record, advisory

    def collect(
        self, osv_ids: Sequence[str]
    ) -> OsvResult:
        """Fetch several OSV ids, accumulating visible per-id failures."""
        records: list[NormalizedVulnerability] = []
        advisories: list[AdvisoryOnly] = []
        warnings: list[str] = []
        failures = 0
        for identifier in osv_ids:
            try:
                record, advisory = self.get_vulnerability(identifier)
            except SourceNotFound:
                failures += 1
                warnings.append(f"{identifier}: not found at OSV")
                continue
            except Exception as exc:
                failures += 1
                warnings.append(f"{identifier}: {sanitize(exc)}")
                continue
            if record is not None:
                records.append(record)
            else:
                advisories.append(advisory)
        if failures and not (records or advisories):
            status = CollectionStatus.FAILED
        elif warnings:
            status = CollectionStatus.PARTIAL
        else:
            status = CollectionStatus.OK
        return OsvResult(
            state=SourceState(
                kind=SourceKind.OSV,
                status=status,
                checked_at=utcnow(),
                last_success=utcnow() if (records or advisories) else None,
                error="; ".join(warnings[:5]) if warnings else None,
                records=len(records) + len(advisories),
            ),
            records=tuple(records),
            advisories=tuple(advisories),
            warnings=tuple(warnings),
        )

    # -- parsing ----------------------------------------------------------
    def parse_record(
        self, body: Mapping[str, Any], *, fetched_at: datetime
    ) -> tuple[NormalizedVulnerability | None, AdvisoryOnly]:
        """Normalize one OSV object. Pure function of its inputs (no I/O)."""
        advisory_id = coerce_text(body.get("id"), field_name="id", limit=200)
        if not advisory_id:
            raise ValidationError("OSV record has no id", field="id")

        aliases = [
            value.strip().upper()
            for value in (body.get("aliases") or [])
            if isinstance(value, str)
        ] if isinstance(body.get("aliases", []), list) else []
        identifiers = body.get("related") or []
        if isinstance(identifiers, list):
            aliases.extend(
                value.strip().upper() for value in identifiers if isinstance(value, str)
            )
        if advisory_id.upper().startswith(_CVE_ALIAS):
            aliases.append(advisory_id.upper())
        cve_alias = next(
            (alias for alias in aliases if alias.startswith(_CVE_ALIAS)), None
        )

        affected = _parse_affected(body.get("affected"))
        references = tuple(
            Reference(
                url=url,
                kind=(ref.get("type") or "other").lower()
                if isinstance(ref.get("type"), str)
                else "other",
                source="osv",
            )
            for ref in mapping_list(body.get("references"), field_name="references")
            if (url := coerce_text(ref.get("url"), field_name="url", limit=2000))
        )
        published = parse_timestamp(body.get("published"), field_name="published")
        withdrawn = parse_timestamp(body.get("withdrawn"), field_name="withdrawn")
        summary = coerce_text(body.get("summary"), field_name="summary", limit=2000)
        details = coerce_text(body.get("details"), field_name="details", limit=20000)

        if cve_alias is None:
            return None, AdvisoryOnly(
                advisory_id=advisory_id,
                summary=summary,
                affected=affected,
                published=published,
                withdrawn=withdrawn,
                references=references,
            )

        cvss_scores: list[CvssScore] = []
        notes: list[str] = []
        for entry in mapping_list(body.get("severity"), field_name="severity"):
            raw = coerce_text(entry.get("score"), field_name="severity.score", limit=500)
            if not raw:
                continue
            if raw.upper().startswith("CVSS:"):
                try:
                    cvss_scores.append(score_vector(raw, source="osv"))
                except UnsupportedVector:
                    notes.append(f"OSV severity vector not assessed here: {raw[:40]}")
            elif raw.replace(".", "", 1).isdigit():
                notes.append("OSV supplied a bare numeric score without a vector; ignored")

        severity = _database_specific_severity(body) or Severity.UNKNOWN
        if withdrawn is not None:
            notes.append(f"record withdrawn by OSV at {withdrawn.isoformat()}")

        record = NormalizedVulnerability(
            cve=CveId.parse(cve_alias),
            origin=self.origin,
            aliases=tuple(sorted({advisory_id.upper(), *aliases})),
            summary=summary,
            details=details,
            published=published,
            modified=parse_timestamp(body.get("modified"), field_name="modified"),
            cvss=tuple(cvss_scores),
            severity=severity,
            references=references,
            affected=affected,
            provenance=(
                ProvenanceRecord(
                    source=SourceKind.OSV,
                    source_ref=advisory_id,
                    fetched_at=fetched_at,
                    transport=transport_kind(self.transport),
                    url=f"{OSV_API}/vulns/{advisory_id}",
                ),
            ),
            sources=("osv",),
            conflict_notes=tuple(notes),
            verification="unverified",
        )
        return record, AdvisoryOnly(
            advisory_id=advisory_id,
            summary=summary,
            affected=affected,
            published=published,
            withdrawn=withdrawn,
            references=references,
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


def _parse_affected(value: object) -> tuple[AffectedPackage, ...]:
    """Parse OSV ``affected[]`` without losing range fidelity.

    Three things the previous implementation discarded, each of which changed
    the answer to "am I affected?":

    * ``ranges[].type`` — a ``GIT`` range holds commit SHAs; comparing one to a
      semantic version is meaningless, so the type must survive normalization;
    * ``last_affected`` — an inclusive upper bound was dropped entirely, making
      the last vulnerable release look safe;
    * multi-interval ranges — a package fixed, reintroduced and fixed again has
      four events; keeping only the first ``introduced``/``fixed`` pair hid the
      second vulnerable window.
    """
    packages: list[AffectedPackage] = []
    seen: set[tuple[str, str, str | None, str | None, str | None, str | None]] = set()
    for entry in mapping_list(value, field_name="affected"):
        package = entry.get("package")
        if not isinstance(package, Mapping):
            continue
        ecosystem = coerce_text(package.get("ecosystem"), field_name="ecosystem", limit=100)
        name = coerce_text(package.get("name"), field_name="package.name", limit=300)
        if not ecosystem or not name:
            continue
        purl = coerce_text(package.get("purl"), field_name="purl", limit=500)
        raw_versions = entry.get("versions", [])
        versions = (
            tuple(str(v) for v in raw_versions if isinstance(v, (str, int)))
            if isinstance(raw_versions, list)
            else ()
        )
        ranges = mapping_list(entry.get("ranges"), field_name="ranges")

        events: list[tuple[int, str, str]] = []
        intervals: list[AffectedPackage] = []
        for index, range_entry in enumerate(ranges):
            kind = coerce_text(range_entry.get("type"), field_name="ranges[].type", limit=20)
            kind = (kind or "ECOSYSTEM").upper()
            range_events: list[tuple[str, str]] = []
            for event in mapping_list(
                range_entry.get("events"), field_name="ranges[].events"
            ):
                for key in ("introduced", "fixed", "last_affected", "limit"):
                    if key in event and isinstance(event[key], (str, int)):
                        range_events.append((key, str(event[key])))
                        if key != "limit":
                            events.append((index, key, str(event[key])))
            if not range_events:
                continue
            # Every interval of the range is preserved; introduced/fixed stay as
            # an ergonomic summary of the first interval for simple consumers.
            opened: str | None = None
            open_flag = False
            for ekind, evalue in range_events:
                if ekind == "introduced":
                    if open_flag:
                        # A re-opened interval: the previous one had no close.
                        intervals.append(
                            _one_interval(ecosystem, name, purl, versions, kind,
                                           opened, None, None, tuple(events))
                        )
                    opened, open_flag = evalue, True
                elif ekind == "fixed" and open_flag:
                    intervals.append(
                        _one_interval(ecosystem, name, purl, versions, kind,
                                       opened, evalue, None, tuple(events))
                    )
                    open_flag = False
                elif ekind == "last_affected" and open_flag:
                    intervals.append(
                        _one_interval(ecosystem, name, purl, versions, kind,
                                       opened, None, evalue, tuple(events))
                    )
                    open_flag = False
            if open_flag:
                intervals.append(
                    _one_interval(ecosystem, name, purl, versions, kind,
                                   opened, None, None, tuple(events))
                )

        candidates = intervals or [
            _one_interval(ecosystem, name, purl, versions, None, None, None, None,
                          tuple(events))
        ]
        for candidate in candidates:
            dedupe_key = (
                candidate.ecosystem,
                candidate.name,
                candidate.introduced,
                candidate.fixed,
                candidate.last_affected,
                candidate.range_type,
            )
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            packages.append(candidate)
    return tuple(packages)


def _one_interval(
    ecosystem: str,
    name: str,
    purl: str | None,
    versions: tuple[str, ...],
    range_type: str | None,
    introduced: str | None,
    fixed: str | None,
    last_affected: str | None,
    events: tuple[tuple[int, str, str], ...] | None,
) -> AffectedPackage:
    return AffectedPackage(
        ecosystem=ecosystem,
        name=name,
        introduced=introduced,
        fixed=fixed,
        versions=versions,
        purl=purl,
        range_type=range_type,
        last_affected=last_affected,
        events=events or (),
    )


def _database_specific_severity(body: Mapping[str, Any]) -> Severity | None:
    specific = body.get("database_specific")
    if not isinstance(specific, Mapping):
        return None
    raw = specific.get("severity")
    if not isinstance(raw, str):
        return None
    try:
        return Severity(raw.strip().lower())
    except ValueError:
        return None
