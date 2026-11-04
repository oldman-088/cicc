"""End-to-end enrichment pipeline: collect → observe → merge → prioritize.

This is the orchestration the API layer would call.  It exists so the host does
not have to re-implement ordering, deduplication, failure accounting and the
"never present partial data as complete" rules.

Failure philosophy
------------------
Every source is attempted independently and its outcome is recorded.  A source
that fails produces **no records** and a *failed* status — never an empty list
presented as "no vulnerabilities".  Partial success is reported as ``PARTIAL``
with the failing sources named, and the pipeline's report carries an explicit
``complete`` flag that is ``False`` whenever anything was skipped.

Ordering is deliberate:

1. collect per source (each with its own breaker and rate gate in the host);
2. append source observations **before** merging, so evidence exists even if
   scoring later throws;
3. merge per CVE (origin-separated);
4. attach KEV membership from a catalogue snapshot (or mark it unconsulted);
5. attach EPSS scores (or leave them unavailable);
6. prioritize — deterministic, explained, never silently downgraded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Mapping, Sequence

from .errors import SourceError, sanitize
from .integration.observations import (
    MERGED_VIEW_NOTICE,
    ImmutableObservationLog,
    to_observations,
)
from .kev import KevCatalog
from .normalization import KevSignal, attach_epss, attach_kev, normalize_sources
from .priorities import PriorityContext, PriorityResult, rank_vulnerabilities
from .schema import (
    NormalizedVulnerability,
    Origin,

    CollectionStatus,
    utcnow,
)

__all__ = ["PipelineReport", "EnrichmentPipeline", "SourceOutcome"]


@dataclass(frozen=True)
class SourceOutcome:
    """What one source contributed to a run."""

    source: str
    status: CollectionStatus
    records: int
    error: str | None = None
    retry_after: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "status": self.status.value,
            "records": self.records,
            "error": self.error,
            "retry_after": self.retry_after,
        }


@dataclass
class PipelineReport:
    """Complete, machine-readable account of one enrichment run."""

    run_at: datetime
    origin: str
    outcomes: list[SourceOutcome] = field(default_factory=list)
    records: list[NormalizedVulnerability] = field(default_factory=list)
    ranking: list[PriorityResult] = field(default_factory=list)
    observations_appended: int = 0
    observations_duplicate: int = 0
    observations_refused: int = 0
    kev_consulted: bool = False
    kev_catalog_version: str | None = None
    kev_stale: bool | None = None
    epss_available: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        """``True`` only when every attempted source succeeded and nothing was refused."""
        if self.observations_refused:
            return False
        return all(o.status is CollectionStatus.OK for o in self.outcomes)

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_at": self.run_at.isoformat(),
            "origin": self.origin,
            "complete": self.complete,
            "notice": MERGED_VIEW_NOTICE,
            "sources": [o.as_dict() for o in self.outcomes],
            "kev": {
                "consulted": self.kev_consulted,
                "catalog_version": self.kev_catalog_version,
                "stale": self.kev_stale,
            },
            "epss_available": self.epss_available,
            "observations": {
                "appended": self.observations_appended,
                "duplicate": self.observations_duplicate,
                "refused": self.observations_refused,
            },
            "records": [r.as_summary() for r in self.records],
            "ranking": [r.as_dict() for r in self.ranking],
            "warnings": list(self.warnings),
        }


class EnrichmentPipeline:
    """Compose collectors, an observation log and optional KEV/EPSS providers."""

    def __init__(
        self,
        *,
        log: ImmutableObservationLog | None = None,
        kev_catalog: KevCatalog | None = None,
        kev_stale: bool | None = None,
        epss_provider: Any | None = None,
        now: Callable[[], datetime] = utcnow,
    ) -> None:
        self.log = log
        self.kev_catalog = kev_catalog
        self.kev_stale = kev_stale
        self.epss_provider = epss_provider
        self.now = now

    def run(
        self,
        collectors: Mapping[str, Callable[[], Sequence[NormalizedVulnerability]]],
        *,
        tenant_id: str | None = None,
        context: PriorityContext | Mapping[str, PriorityContext] | None = None,
        limit: int | None = None,
    ) -> PipelineReport:
        """Execute one enrichment run across the supplied collectors."""
        run_at = self.now()
        collected: list[NormalizedVulnerability] = []
        report = PipelineReport(run_at=run_at, origin="unknown")

        for name, collector in collectors.items():
            try:
                produced = list(collector())
            except SourceError as exc:
                report.outcomes.append(
                    SourceOutcome(
                        source=name,
                        status=CollectionStatus.FAILED,
                        records=0,
                        error=sanitize(exc),
                        retry_after=getattr(exc, "retry_after", None),
                    )
                )
                report.warnings.append(f"{name} failed: collection error (no data recorded)")
                continue
            except Exception as exc:  # noqa: BLE001 - a broken collector must not abort the run
                report.outcomes.append(
                    SourceOutcome(
                        source=name,
                        status=CollectionStatus.FAILED,
                        records=0,
                        error=f"{type(exc).__name__}: {sanitize(exc)}",
                    )
                )
                report.warnings.append(f"{name} failed with an unexpected error")
                continue

            if not produced:
                report.outcomes.append(
                    SourceOutcome(source=name, status=CollectionStatus.OK, records=0)
                )
                report.warnings.append(
                    f"{name} returned zero records; this is an empty answer, not a failure"
                )
                continue

            report.outcomes.append(
                SourceOutcome(source=name, status=CollectionStatus.OK, records=len(produced))
            )
            collected.extend(produced)

        origins = {record.origin for record in collected}
        if len(origins) > 1:
            report.outcomes.append(
                SourceOutcome(
                    source="pipeline",
                    status=CollectionStatus.FAILED,
                    records=0,
                    error="mixed-origin input refused",
                )
            )
            report.warnings.append(
                "collectors returned mixed origins; nothing was merged or stored"
            )
            return report
        report.origin = next(iter(origins)).value if origins else Origin.LIVE.value

        # 1. Evidence first: observations are appended before any derivation.
        if self.log is not None and tenant_id is not None:
            for record in collected:
                for observation in to_observations(
                    record, tenant_id=tenant_id, collected_at=run_at
                ):
                    result = self.log.append(observation)
                    if result.outcome == "appended":
                        report.observations_appended += 1
                    elif result.outcome == "duplicate":
                        report.observations_duplicate += 1
                    else:
                        report.observations_refused += 1
            if report.observations_refused:
                report.warnings.append(
                    "some observations were refused by the log (origin gate); "
                    "the merged view excludes nothing but the evidence is incomplete"
                )

        # 2. Merge per CVE (raises on mixed origins, which was checked above).
        merged = normalize_sources(collected)

        # 3. KEV membership.
        report.kev_consulted = self.kev_catalog is not None
        report.kev_stale = self.kev_stale
        if self.kev_catalog is not None:
            report.kev_catalog_version = self.kev_catalog.catalog_version
        enriched: list[NormalizedVulnerability] = []
        for cve, record in merged.items():
            signal: KevSignal | None = None
            if self.kev_catalog is not None:
                entry = self.kev_catalog.lookup(cve)
                signal = KevSignal(
                    record.cve,
                    listed=entry is not None,
                    date_added=entry.date_added if entry else None,
                    checked=True,
                    catalog_version=self.kev_catalog.catalog_version,
                )
            record = attach_kev(record, signal, fetched_at=run_at)
            if self.kev_catalog is None:
                report.warnings.append(
                    "CISA KEV catalogue not supplied: exploitation status left unknown"
                )
            elif self.kev_stale:
                report.warnings.append(
                    "CISA KEV catalogue is stale; membership may have changed"
                )
            enriched.append(record)

        # 4. EPSS.
        if self.epss_provider is not None:
            try:
                scores = self.epss_provider.fetch([r.cve for r in enriched])
                report.epss_available = bool(scores)
                enriched = [attach_epss(r, scores.get(str(r.cve))) for r in enriched]
                if not scores:
                    report.warnings.append("EPSS provider returned no scores; none attached")
            except SourceError:
                report.warnings.append(
                    "EPSS unavailable: scores left empty (not zero) and excluded from ranking"
                )
        else:
            report.warnings.append(
                "no EPSS provider configured: exploitation forecasting excluded"
            )

        report.records = enriched
        report.ranking = rank_vulnerabilities(enriched, context=context, now=run_at, limit=limit)
        return report
