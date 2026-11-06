"""NVD (NIST National Vulnerability Database) connector.

Endpoint contract, from the published NVD API 2.0 specification:

    GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds=CVE-YYYY-NNNN
    GET https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=0&resultsPerPage=200

    {
      "resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
      "format": "NVD_CVE", "version": "2.0", "timestamp": "...",
      "vulnerabilities": [ { "cve": {
          "id": "CVE-...", "published": "2024-01-01T00:00:00.000",
          "lastModified": "2024-01-02T00:00:00.000", "vulnStatus": "Analyzed",
          "descriptions": [{"lang": "en", "value": "..."}],
          "metrics": {"cvssMetricV31": [{"source": "...", "type": "Primary",
                       "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/...",
                                    "baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
          "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
          "references": [{"url": "...", "tags": ["Patch"]}]
      }}]
    }

**Verification status: NOT live-verified.**  The execution environment for this
change has no outbound access to ``services.nvd.nist.gov``, so every test runs
against synthetic fixtures written from the specification above.  ``LAST_VERIFIED_LIVE``
stays ``None`` until a real fetch is recorded; nothing here may be described as a
confirmed working integration.

Fail-closed rules:

* a malformed *envelope* (no ``vulnerabilities`` list, non-integer counters)
  raises instead of yielding an empty result;
* a malformed *record* does not abort the batch, but downgrades the collection
  to ``PARTIAL`` and reports the reason — records are never silently dropped;
* naive NVD timestamps are interpreted as UTC (documented NVD behaviour).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable, Mapping, Sequence

from ..cvss import cvss_from_source, disagreement
from ..errors import (
    SourceNotFound,
    SourceRateLimited,
    SourceResponseError,
    ValidationError,
    sanitize,
)
from ..ratelimit import RateGate, quota_for_nvd
from ..retry import RetryPolicy, call_with_retry
from ..schema import (
    CollectionResult,
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
    strictest_status,
    utcnow,
)
from ..transport import Transport, transport_kind

__all__ = ["LAST_VERIFIED_LIVE", "NVD_API", "NvdConnector"]

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

#: Set to an ISO-8601 timestamp only after a successful *real* fetch is recorded.
LAST_VERIFIED_LIVE: str | None = None

_METRIC_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2")


@dataclass
class NvdConnector:
    """Read-only NVD client.

    ``transport`` is required for live use; passing ``None`` produces an explicit
    ``NOT_CONFIGURED`` result rather than pretending to have collected data.
    """

    transport: Transport | None = None
    #: ``repr=False`` is a security control, not cosmetics: a dataclass repr that
    #: includes the key leaks it through any log line, traceback or debug dump.
    api_key: str | None = field(default=None, repr=False)
    retry: RetryPolicy = RetryPolicy()
    gate: RateGate | None = None
    timeout: float = 30.0
    page_size: int = 200
    max_pages: int = 10
    sleep: Callable[[float], None] | None = None
    origin: Origin = Origin.LIVE

    def __post_init__(self) -> None:
        if self.gate is None:
            self.gate = quota_for_nvd(api_key=bool(self.api_key))
        if not 1 <= self.page_size <= 2000:
            raise ValueError("page_size must be within 1-2000")

    # -- transport plumbing ----------------------------------------------
    def _headers(self) -> dict[str, str]:
        # The key is sent in a header and never placed in a URL, so it cannot
        # leak into provenance or access logs.
        headers = {"Accept": "application/json", "User-Agent": "CICC-vuln-intel/0.1"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    @staticmethod
    def _retry_after(headers: Mapping[str, str]) -> float | None:
        """Parse ``Retry-After`` defensively; a malformed value means "unknown"."""
        raw = headers.get("retry-after")
        if not raw:
            return None
        try:
            value = float(raw)
        except (TypeError, ValueError):
            return None
        return value if value > 0 else None

    def _request(self, params: Mapping[str, str]) -> Mapping[str, Any]:
        if self.transport is None:
            raise SourceResponseError(
                "no transport configured", source=SourceKind.NVD.value
            )

        def attempt() -> Mapping[str, Any]:
            assert self.gate is not None
            self.gate.wait()
            response = self.transport.get(  # type: ignore[union-attr]
                NVD_API, params=params, headers=self._headers(), timeout=self.timeout
            )
            if response.status == 404:
                raise SourceNotFound("record not found", status=404, source="nvd")
            if response.status == 429:
                seconds = self._retry_after(response.headers)
                self.gate.observe_retry_after(seconds)
                raise SourceRateLimited(
                    "NVD quota exceeded", retry_after=seconds, status=429, source="nvd"
                )
            if response.status == 403:
                raise SourceResponseError(
                    "NVD refused the request (check API key)", status=403, source="nvd"
                )
            if response.status >= 500:
                raise SourceResponseError(
                    f"NVD server error {response.status}", status=response.status, source="nvd"
                )
            if response.status != 200:
                raise SourceResponseError(
                    f"unexpected NVD status {response.status}",
                    status=response.status,
                    source="nvd",
                )
            body = response.json()
            if not isinstance(body, Mapping):
                raise SourceResponseError("NVD body is not an object", source="nvd")
            return body

        return call_with_retry(
            attempt,
            policy=self.retry,
            sleep=self.sleep or __import__("time").sleep,
        )

    # -- public API -------------------------------------------------------
    def get_cve(self, cve_id: str | CveId) -> NormalizedVulnerability:
        """Fetch exactly one CVE. Raises :class:`SourceNotFound` if NVD has no record."""
        identifier = cve_id if isinstance(cve_id, CveId) else CveId.parse(cve_id)
        # NVD documents `cveId` as deprecated in favour of `cveIds`.  `cveId` still
        # answers today, but a deprecated parameter is a removal waiting to happen,
        # and the replacement has identical semantics for a single identifier.
        body = self._request({"cveIds": str(identifier)})
        entries = self._envelope(body)
        if not entries:
            raise SourceNotFound(
                f"{identifier} is not reported by NVD", status=200, source="nvd"
            )
        published_at = utcnow()
        source_ref = str(body.get("timestamp") or "")
        records, problems = self._parse_entries(entries, published_at, source_ref)
        if not records:
            raise ValidationError(
                "NVD returned no parseable record: " + "; ".join(problems[:3] or ["unknown"])
            )
        return records[0]

    def search(
        self,
        *,
        start_index: int = 0,
        results_per_page: int | None = None,
        modified_window: Mapping[str, str] | None = None,
    ) -> CollectionResult:
        """Fetch one page of NVD records.

        ``modified_window`` carries ``lastModStartDate``/``lastModEndDate`` for
        incremental synchronisation.  Both bounds are sent together because NVD
        rejects a lone ``lastModStartDate`` with 404, and the pair is documented
        to be limited to 120 consecutive days (enforced by :mod:`vuln_intel.sync`).
        """
        if start_index < 0:
            raise ValueError("start_index must be >= 0")
        size = results_per_page or self.page_size
        if not 1 <= size <= 2000:
            raise ValueError("results_per_page must be within 1-2000")
        params = {"startIndex": str(start_index), "resultsPerPage": str(size)}
        if modified_window:
            params.update(modified_window)
        try:
            body = self._request(params)
            entries = self._envelope(body)
        except SourceRateLimited as exc:
            return CollectionResult.failed(
                SourceKind.NVD,
                f"rate limited: {sanitize(exc.message)}",
                retry_after=exc.retry_after,
            )
        except Exception as exc:
            return CollectionResult.failed(SourceKind.NVD, sanitize(exc))

        records, problems = self._parse_entries(
            entries, utcnow(), str(body.get("timestamp") or "")
        )
        total = body.get("totalResults")
        if isinstance(total, int) and not isinstance(total, bool):
            expected_remaining = max(0, total - start_index - len(entries))
            if expected_remaining > 0 and len(entries) < size:
                # The source says more records exist but returned a short page;
                # paging on this would loop forever, so surface it instead.
                problems.append(
                    f"NVD reported {total} results but returned a short page at "
                    f"index {start_index}: stop paging and investigate"
                )
        status = CollectionStatus.OK if not problems else CollectionStatus.PARTIAL
        if problems and not records:
            status = CollectionStatus.FAILED
        return CollectionResult(
            state=SourceState(
                kind=SourceKind.NVD,
                status=status,
                checked_at=utcnow(),
                last_success=utcnow() if records else None,
                error="; ".join(problems[:5]) if problems else None,
                records=len(records),
            ),
            records=tuple(records),
            warnings=tuple(problems),
        )

    def search_all(self) -> CollectionResult:
        """Page through NVD up to ``max_pages``.

        Explicitly bounded: this is **not** a complete mirror of NVD.  The
        result reports how many pages were taken and whether the window was
        exhausted.
        """
        collected: list[NormalizedVulnerability] = []
        warnings: list[str] = []
        pages = 0
        exhausted = False
        for page in range(self.max_pages):
            result = self.search(start_index=page * self.page_size, results_per_page=self.page_size)
            if result.state.status is CollectionStatus.FAILED:
                if page == 0:
                    return result
                warnings.append(
                    f"page {page} failed: {result.state.error}; earlier pages kept"
                )
                break
            collected.extend(result.records)
            warnings.extend(result.warnings)
            pages += 1
            if len(result.records) < self.page_size:
                exhausted = True
                break
        if not exhausted:
            warnings.append(
                f"bounded window: stopped after {pages} page(s); NVD holds more records"
            )
        status = CollectionStatus.OK if not warnings else CollectionStatus.PARTIAL
        return CollectionResult(
            state=SourceState(
                kind=SourceKind.NVD,
                status=status,
                checked_at=utcnow(),
                last_success=utcnow() if collected else None,
                error=None,
                records=len(collected),
            ),
            records=tuple(collected),
            warnings=tuple(warnings),
        )

    # -- parsing ----------------------------------------------------------
    @staticmethod
    def _envelope(body: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        vulnerabilities = body.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            raise SourceResponseError(
                "NVD envelope has no 'vulnerabilities' list", source="nvd"
            )
        total = body.get("totalResults", 0)
        if total is not None and not isinstance(total, int):
            raise SourceResponseError("NVD 'totalResults' is not an integer", source="nvd")
        return [v for v in vulnerabilities if isinstance(v, Mapping)]

    def _parse_entries(
        self,
        entries: Sequence[Mapping[str, Any]],
        fetched_at: datetime,
        source_ref: str,
    ) -> tuple[list[NormalizedVulnerability], list[str]]:
        records: list[NormalizedVulnerability] = []
        problems: list[str] = []
        for entry in entries:
            try:
                records.append(self._parse_entry(entry, fetched_at, source_ref))
            except ValidationError as exc:
                problems.append(f"skipped malformed NVD record: {exc}")
            except (TypeError, ValueError, KeyError) as exc:
                # Defensive: an unexpected shape must never take down a batch,
                # but it must still be reported rather than silently dropped.
                problems.append(f"skipped unreadable NVD record: {sanitize(exc)}")
        return records, problems

    def _parse_entry(
        self, entry: Mapping[str, Any], fetched_at: datetime, source_ref: str
    ) -> NormalizedVulnerability:
        cve = entry.get("cve")
        if not isinstance(cve, Mapping):
            raise ValidationError("entry has no 'cve' object", field="cve")
        identifier = CveId.parse(cve.get("id"))

        notes: list[str] = []
        cvss_scores: list[CvssScore] = []
        metrics = cve.get("metrics")
        if metrics is not None and not isinstance(metrics, Mapping):
            raise ValidationError("'metrics' must be an object", field="metrics")
        for key in _METRIC_KEYS:
            for metric in mapping_list((metrics or {}).get(key), field_name=f"metrics.{key}"):
                data = metric.get("cvssData")
                if not isinstance(data, Mapping):
                    raise ValidationError("metric has no 'cvssData'", field=f"metrics.{key}")
                stated = data.get("baseScore")
                score = cvss_from_source(
                    version=_text(data.get("version")),
                    vector=_text(data.get("vectorString")),
                    base_score=stated if isinstance(stated, (int, float)) else None,
                    source=_text(metric.get("source")) or f"nvd:{key}",
                )
                if score is None:
                    continue
                cvss_scores.append(score)
                note = disagreement(score, stated if isinstance(stated, (int, float)) else None)
                if note:
                    notes.append(note)

        notes.extend(_status_notes(cve))
        record_status = _record_status(cve)
        ssvc_options = _ssvc_inputs(cve, notes)

        severity = Severity.UNKNOWN
        for key in ("cvssMetricV31", "cvssMetricV30"):
            for metric in mapping_list((metrics or {}).get(key), field_name=f"metrics.{key}"):
                data = metric.get("cvssData")
                if isinstance(data, Mapping):
                    severity = _severity_from(data.get("baseSeverity")) or severity
            if severity is not Severity.UNKNOWN:
                break

        cwe: list[str] = []
        for weakness in mapping_list(cve.get("weaknesses"), field_name="weaknesses"):
            # NOTE: do not name this loop variable ``description`` — it shadowed the
            # CVE description used below and made the record body ambiguous.
            for cwe_entry in mapping_list(
                weakness.get("description"), field_name="weaknesses[].description"
            ):
                value = _text(cwe_entry.get("value"))
                if value and value.upper().startswith("CWE-") and value not in cwe:
                    cwe.append(value.upper())

        references: list[Reference] = []
        for ref in mapping_list(cve.get("references"), field_name="references"):
            url = _text(ref.get("url"))
            if not url:
                continue
            tags = ref.get("tags")
            kind = ""
            if isinstance(tags, list) and tags:
                kind = str(tags[0]).lower()
            references.append(Reference(url=url, kind=kind or "other", source="nvd"))

        description = _first_english(cve.get("descriptions"))
        return NormalizedVulnerability(
            cve=identifier,
            origin=self.origin,
            summary=description[:300] if description else None,
            details=description,
            published=parse_timestamp(cve.get("published"), field_name="published"),
            modified=parse_timestamp(cve.get("lastModified"), field_name="lastModified"),
            cvss=tuple(cvss_scores),
            severity=severity,
            ssvc=ssvc_options,
            record_status=record_status,
            cwe=tuple(cwe),
            references=tuple(references),
            provenance=(
                ProvenanceRecord(
                    source=SourceKind.NVD,
                    source_ref=source_ref or None,
                    fetched_at=fetched_at,
                    transport=transport_kind(self.transport),
                    url=NVD_API,
                ),
            ),
            sources=("nvd",),
            conflict_notes=tuple(notes),
            verification="unverified",
        )


#: NVD statuses meaning "this record does not assert a finalised vulnerability".
#: ``Rejected`` is a withdrawn CVE; ``Awaiting Analysis`` / ``Undergoing Analysis``
#: mean NVD has not finished enrichment.  None of them means "safe", so they are
#: reported rather than dropped.
_UNRESOLVED_STATUSES = frozenset(
    {"Awaiting Analysis", "Undergoing Analysis", "Received", "Rejected"}
)


def _ssvc_inputs(cve: Mapping[str, Any], notes: list[str]) -> tuple[tuple[str, str], ...]:
    """Read CISA's published SSVC decision points out of an NVD record.

    NVD nests them as ``ssvc.ssvcV203[].ssvcData.options`` — a list of one-key
    objects.  Only the three provider-supplied inputs are kept; mission & well-being
    is stakeholder-specific and is deliberately never inferred here.

    A record with SSVC data but no usable inputs is reported in ``notes`` rather
    than silently ignored, because "CISA assessed this" and "CISA assessed this in
    a shape we cannot read" are different facts.
    """
    ssvc = cve.get("ssvc")
    if not isinstance(ssvc, Mapping):
        return ()

    # Pick the highest version block present, so a future ssvcV3 is preferred over
    # ssvcV203 without needing a code change for every new version string.
    blocks: list[tuple[str, Any]] = [
        (key, value) for key, value in ssvc.items() if isinstance(key, str)
    ]
    for _, entries in sorted(blocks, key=lambda kv: kv[0], reverse=True):
        for entry in mapping_list(entries, field_name="ssvc"):
            data = entry.get("ssvcData")
            if not isinstance(data, Mapping):
                continue
            options = data.get("options")
            values: dict[str, str] = {}
            for option in mapping_list(options, field_name="ssvcData.options"):
                for key, value in option.items():
                    name = str(key).strip().lower()
                    if name == "technicalimpact":
                        name = "technical_impact"
                    if name in ("exploitation", "automatable", "technical_impact") and isinstance(
                        value, str
                    ):
                        values[name] = value.strip().lower()
            if values:
                if data.get("role"):
                    notes.append(f"SSVC assessment role: {data.get('role')}")
                return tuple(sorted(values.items()))
            notes.append(
                "NVD supplied an SSVC block with no usable decision points; ignored"
            )
    return ()


def _record_status(cve: Mapping[str, Any]) -> RecordStatus | None:
    """Map NVD's ``vulnStatus`` plus ``cveTags`` onto a typed standing.

    Kept separate from the prose notes so a consumer can branch on it: a disputed
    claim and a withdrawn one call for different responses, and neither is
    recoverable from free text without re-parsing English.
    """
    found: list[RecordStatus | None] = []
    status = _text(cve.get("vulnStatus"))
    if status == "Rejected":
        found.append(RecordStatus.REJECTED)
    elif status in ("Awaiting Analysis", "Undergoing Analysis", "Received"):
        found.append(RecordStatus.UNDERGOING_ANALYSIS)
    elif status == "Analyzed":
        found.append(RecordStatus.PUBLISHED)

    tags = cve.get("cveTags")
    if isinstance(tags, list):
        for tag_block in tags:
            if not isinstance(tag_block, Mapping):
                continue
            for tag in tag_block.get("tags") or ():
                if isinstance(tag, str) and tag.strip().lower() == "disputed":
                    found.append(RecordStatus.DISPUTED)
    return strictest_status(found)


def _status_notes(cve: Mapping[str, Any]) -> list[str]:
    """Surface NVD status and ``disputed`` tags, which are otherwise invisible.

    A ``disputed`` CVE is one whose existence or severity a vendor contests.  NVD
    carries this in ``cveTags``; ignoring it means a contested claim is ranked and
    remediated as though it were agreed.  This module does not resolve the dispute,
    it reports it so the consumer can decide.
    """
    notes: list[str] = []

    status = _text(cve.get("vulnStatus"))
    if status in _UNRESOLVED_STATUSES:
        notes.append(f"NVD vulnStatus is '{status}': enrichment not final")

    tags = cve.get("cveTags")
    if isinstance(tags, list):
        for tag_block in tags:
            if not isinstance(tag_block, Mapping):
                continue
            for tag in tag_block.get("tags") or ():
                if isinstance(tag, str) and tag.strip():
                    notes.append(
                        f"NVD cveTag '{tag.strip()}' present: the record is contested "
                        "by its source"
                    )
    return notes


def _text(value: object) -> str | None:
    return coerce_text(value, field_name="text", limit=50000)


def _severity_from(value: object) -> Severity | None:
    if not isinstance(value, str):
        return None
    try:
        return Severity(value.strip().lower())
    except ValueError:
        return None


def _first_english(descriptions: object) -> str | None:
    entries = mapping_list(descriptions, field_name="descriptions")
    texts = [(e.get("lang"), _text(e.get("value"))) for e in entries]
    for lang, value in texts:
        if lang == "en" and value:
            return value
    for _, value in texts:
        if value:
            return value
    return None


def iter_batches(items: Iterable[NormalizedVulnerability], size: int = 100):
    """Chunk records for import; keeps callers from holding huge lists."""
    if size < 1:
        raise ValueError("size must be >= 1")
    batch: list[NormalizedVulnerability] = []
    for item in items:
        batch.append(item)
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch
