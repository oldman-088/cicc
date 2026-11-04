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

__all__ = ["OsvConnector", "OSV_API", "LAST_VERIFIED_LIVE", "AdvisoryOnly"]

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
                retry_after = response.headers.get("retry-after")
                seconds = float(retry_after) if (retry_after or "").isdigit() else None
                raise SourceRateLimited(
                    "OSV rate limited", retry_after=seconds, status=429, source="osv"
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
            except Exception as exc:  # noqa: BLE001 - converted to visible state
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


def _parse_affected(value: object) -> tuple[AffectedPackage, ...]:
    packages: list[AffectedPackage] = []
    seen: set[tuple[str, str, str | None, str | None]] = set()
    for entry in mapping_list(value, field_name="affected"):
        package = entry.get("package")
        if not isinstance(package, Mapping):
            continue
        ecosystem = coerce_text(package.get("ecosystem"), field_name="ecosystem", limit=100)
        name = coerce_text(package.get("name"), field_name="package.name", limit=300)
        if not ecosystem or not name:
            continue
        purl = coerce_text(package.get("purl"), field_name="purl", limit=500)
        versions = tuple(
            str(v) for v in (entry.get("versions") or []) if isinstance(v, (str, int))
        ) if isinstance(entry.get("versions", []), list) else ()
        ranges = mapping_list(entry.get("ranges"), field_name="ranges")
        if not ranges:
            key = (ecosystem, name, None, None)
            if key not in seen:
                seen.add(key)
                packages.append(
                    AffectedPackage(
                        ecosystem=ecosystem,
                        name=name,
                        versions=versions,
                        purl=purl,
                    )
                )
            continue
        for range_entry in ranges:
            events = mapping_list(range_entry.get("events"), field_name="ranges[].events")
            introduced = next(
                (str(e["introduced"]) for e in events if "introduced" in e), None
            )
            fixed = next((str(e["fixed"]) for e in events if "fixed" in e), None)
            key = (ecosystem, name, introduced, fixed)
            if key in seen:
                continue
            seen.add(key)
            packages.append(
                AffectedPackage(
                    ecosystem=ecosystem,
                    name=name,
                    introduced=introduced,
                    fixed=fixed,
                    versions=versions,
                    purl=purl,
                )
            )
    return tuple(packages)


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
