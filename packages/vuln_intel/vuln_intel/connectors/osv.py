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

import re
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
    RecordStatus,
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

#: The OSV schema guarantees every id matches this charset across all exporting
#: databases. Validating against the documented contract is stronger than an ad-hoc
#: check, and it removes path-traversal, query-injection and fragment-injection
#: reachability from the URL builder in one step.
OSV_ID_PATTERN = re.compile(r"^[a-zA-Z0-9:_.-]+$")

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

    def _post(self, path: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        """POST JSON to OSV, mapping status the same way :meth:`_get` does."""
        if self.transport is None:
            raise SourceResponseError("no transport configured", source="osv")
        poster = getattr(self.transport, "post", None)
        if poster is None:
            raise SourceResponseError(
                "transport does not implement post; OSV query endpoints need it",
                source="osv",
            )
        url = f"{OSV_API}/{path.lstrip('/')}"

        def attempt() -> Mapping[str, Any]:
            assert self.gate is not None
            self.gate.wait()
            response = poster(
                url, json_body=dict(payload), headers=self._headers(), timeout=self.timeout
            )
            if response.status == 400:
                raise SourceResponseError(
                    "OSV rejected the query payload", status=400, source="osv"
                )
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
        # The OSV schema guarantees ids match ^[a-zA-Z0-9:_.-]+$ for every
        # exporting database, so validating against that is strictly stronger than
        # checking for a path separator. It also removes any possibility of path
        # traversal, query injection or fragment injection reaching the URL builder.
        if not OSV_ID_PATTERN.match(identifier):
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

    def query_batch(
        self, queries: Sequence[Mapping[str, Any]], *, max_pages: int = 5
    ) -> tuple[tuple[tuple[tuple[str, str | None], ...], ...], tuple[str, ...]]:
        """POST ``/v1/querybatch`` and return ids, honouring per-query pagination.

        Each returned element is ``(advisory_id, modified_or_None)``, grouped per
        input query by index so the caller can attribute an id to the package that
        produced it.

        Two documented properties are relied on rather than assumed:

        * results are ordered to match the input, so index *i* belongs to
          ``queries[i]``;
        * pagination is **per query** — only the entries that returned a
          ``next_page_token`` need a follow-up request, and those follow-ups must
          resend the *same* query with the token added. Requesting page two for
          every query would re-fetch complete results and multiply load for
          nothing.

        The endpoint returns ids and a ``modified`` timestamp only, not whole
        records: callers must fetch any id they actually need via
        :meth:`get_vulnerability`. Treating a batch hit as full intelligence would
        mean reporting a vulnerability with no severity, versions or summary.
        """
        if not queries:
            return (), ()
        warnings: list[str] = []
        collected: list[list[tuple[str, str | None]]] = [[] for _ in queries]
        pending = list(range(len(queries)))
        tokens: dict[int, str] = {}

        for page in range(max_pages):
            payload_queries: list[dict[str, Any]] = []
            for index in pending:
                item = dict(queries[index])
                if index in tokens:
                    item["page_token"] = tokens[index]
                payload_queries.append(item)
            body = self._post("querybatch", {"queries": payload_queries})
            results = body.get("results")
            if not isinstance(results, list) or len(results) != len(pending):
                raise SourceResponseError(
                    "OSV querybatch returned a result count that does not match "
                    "the request; refusing to misattribute ids",
                    source="osv",
                )

            next_pending: list[int] = []
            next_tokens: dict[int, str] = {}
            for position, index in enumerate(pending):
                entry = results[position]
                if not isinstance(entry, Mapping):
                    warnings.append(f"query {index}: malformed batch result ignored")
                    continue
                for vuln in mapping_list(entry.get("vulns"), field_name="vulns"):
                    identifier = coerce_text(
                        vuln.get("id"), field_name="vulns.id", limit=200
                    )
                    if identifier:
                        modified = coerce_text(
                            vuln.get("modified"), field_name="vulns.modified", limit=64
                        )
                        collected[index].append((identifier, modified))
                token = entry.get("next_page_token")
                if isinstance(token, str) and token:
                    next_pending.append(index)
                    next_tokens[index] = token

            if not next_pending:
                return tuple(tuple(items) for items in collected), tuple(warnings)
            pending, tokens = next_pending, next_tokens
            if page == max_pages - 1:
                warnings.append(
                    f"querybatch page budget ({max_pages}) exhausted with "
                    f"{len(pending)} quer{'y' if len(pending) == 1 else 'ies'} "
                    "still paginating; results are incomplete"
                )

        return tuple(tuple(items) for items in collected), tuple(warnings)

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
                except (UnsupportedVector, ValidationError) as exc:
                    # One malformed vector from OSV must not abort the page.
                    # A truncated vector (e.g. a v4 string missing SC/SI/SA) used
                    # to propagate out of here and fail the whole collection run.
                    # The record is still useful, so keep it and say what happened.
                    notes.append(
                        f"OSV severity vector not assessed ({type(exc).__name__}): {raw[:40]}"
                    )
            elif raw.replace(".", "", 1).isdigit():
                notes.append("OSV supplied a bare numeric score without a vector; ignored")

        severity = _database_specific_severity(body) or Severity.UNKNOWN
        if withdrawn is not None:
            notes.append(f"record withdrawn by OSV at {withdrawn.isoformat()}")

        top_level_severity = body.get("severity")
        notes.extend(
            _spec_fidelity_notes(
                body,
                affected,
                isinstance(top_level_severity, list) and bool(top_level_severity),
            )
        )
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
            # A withdrawn advisory is not a live claim. OSV states this explicitly,
            # so it becomes a typed standing rather than only a note in prose.
            record_status=(
                RecordStatus.REJECTED if withdrawn is not None else RecordStatus.PUBLISHED
            ),
            withdrawn=withdrawn,
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
                        # Every event is preserved, `limit` included.  It is not
                        # folded into an interval below, but dropping it from the
                        # record made the documented upper bound unrecoverable.
                        events.append((index, key, str(event[key])))
            if not range_events:
                continue
            # ``limit`` is deliberately *not* folded into the intervals.  The schema
            # describes it as "an upper limit on the range being described", not as a
            # fix: mapping it to ``fixed`` would make this package publish a remedy
            # version the source never claimed exists.  Keeping the interval open is
            # the cautious direction (it can over-report affectedness, never
            # under-report), and it matches ``affected._build_intervals``.
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
                elif ekind == "fixed" and not open_flag:
                    # `fixed` with no preceding `introduced` means "everything below
                    # this version", which the schema expresses as introduced="0".
                    # Skipping it (the previous behaviour) silently dropped the
                    # interval, reporting an affected package as unaffected.
                    intervals.append(
                        _one_interval(ecosystem, name, purl, versions, kind,
                                       "0", evalue, None, tuple(events))
                    )
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


#: Fields the OSV schema defines that this package does not (yet) model as
#: first-class data.  They are *ignored* rather than rejected, which the schema
#: requires for forward compatibility, but silently dropping them would let a
#: caller believe the record was fully ingested.  Naming them in ``conflict_notes``
#: makes the gap visible in the data instead of only in the documentation.
_UNMODELLED_FIELDS = ("credits", "upstream", "related", "schema_version")


def _spec_fidelity_notes(
    body: Mapping[str, Any],
    affected: Sequence[AffectedPackage],
    top_level_severity: bool,
) -> list[str]:
    """Report places where the parsed record is narrower than the source document."""
    notes: list[str] = []

    for field in _UNMODELLED_FIELDS:
        if body.get(field):
            notes.append(f"OSV field {field!r} is present but not modelled; ignored")

    # The schema states that if any ``affected[].severity`` is set then the
    # top-level ``severity`` must not be.  A record doing both is malformed, and
    # picking a winner silently would hide that: say so and keep the top-level
    # value, which is what the CVSS loop above already read.
    if top_level_severity and any("severity" in entry for entry in (body.get("affected") or []) if isinstance(entry, Mapping)):
        notes.append(
            "OSV record sets both top-level and affected[].severity, which the "
            "schema forbids; top-level severity kept"
        )
    return notes


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
