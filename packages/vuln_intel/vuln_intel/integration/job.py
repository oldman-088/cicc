"""The collection job: one runnable path from providers to storage.

Every piece of this pipeline existed and none of them were joined. A host had to
know to build connectors, wrap them in collectors, enrich them, rank them, then feed
them to an ingestion service with the right policy — four subsystems, in a specific
order, with several invariants that must not be violated. That is not something an
operator should re-derive from the source at 03:00.

What this module adds is composition, not new logic. It is deliberately thin, and
its value is in the ordering and the guarantees:

1. **Collect** — each provider is isolated. One provider failing never prevents the
   others from being collected, and the failure is recorded with its error rather
   than surfacing as "zero records".
2. **Correlate** — per-source records merge into one entity, with conflicting
   values kept and noted rather than silently resolved.
3. **Enrich** — KEV and EPSS are attached only from providers that actually
   answered. An unavailable provider leaves the field unset and says so.
4. **Rank** — deterministic, transparent, under an explicit policy.
5. **Ingest** — origin gate, age gate and audit apply. Dry run by default.

The job never claims more than it did. A run with no live transport produces a
report that says so, and every source outcome carries its own status.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Mapping, Sequence

from ..errors import SourceError
from ..kev import KevCatalog
from ..priorities import PriorityContext, PriorityResult, RankingPolicy, rank_vulnerabilities
from ..schema import CollectionStatus, NormalizedVulnerability, SourceState, utcnow
from .contracts import ImportReport
from .service import IngestionPolicy, IngestionService

__all__ = ["CollectionJob", "JobReport", "SourceResult"]


@dataclass(frozen=True)
class SourceResult:
    """Outcome of one provider within a job run."""

    source: str
    status: str
    records: int = 0
    error: str | None = None
    retry_after: float | None = None

    @property
    def ok(self) -> bool:
        return self.status in (CollectionStatus.OK.value, CollectionStatus.PARTIAL.value)

    def as_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "status": self.status,
            "records": self.records,
            "error": self.error,
            "retry_after": self.retry_after,
        }


@dataclass
class JobReport:
    """Everything one collection run did, and everything it did not do."""

    run_at: datetime
    origin: str
    sources: list[SourceResult] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    #: Records that survived correlation and enrichment.
    records: list[NormalizedVulnerability] = field(default_factory=list)
    ranking: list[PriorityResult] = field(default_factory=list)
    ingestion: ImportReport | None = None
    #: True only when at least one provider actually returned data this run.
    collected_anything: bool = False

    @property
    def failed_sources(self) -> tuple[str, ...]:
        return tuple(source.source for source in self.sources if not source.ok)

    @property
    def complete(self) -> bool:
        """True only when every source succeeded. Partial success is not complete."""
        return bool(self.sources) and not self.failed_sources

    def as_dict(self) -> dict[str, object]:
        return {
            "run_at": self.run_at.isoformat(),
            "origin": self.origin,
            "sources": [source.as_dict() for source in self.sources],
            "failed_sources": list(self.failed_sources),
            "complete": self.complete,
            "collected_anything": self.collected_anything,
            "warnings": list(self.warnings),
            "records": len(self.records),
            "ranking": [result.as_dict() for result in self.ranking],
            "ingestion": self.ingestion.as_dict() if self.ingestion else None,
        }


class CollectionJob:
    """Compose collect → correlate → enrich → rank → ingest.

    ``collectors`` maps a source name to a callable returning normalized records.
    They are ordinary callables on purpose: the job does not need to know whether a
    record came from NVD, OSV or a test double, and coupling it to connector types
    would make it untestable without them.
    """

    def __init__(
        self,
        *,
        collectors: Mapping[str, Callable[[], Sequence[NormalizedVulnerability]]],
        tenant_id: str,
        kev_catalog: KevCatalog | None = None,
        epss_provider: object | None = None,
        ingestion_store: object | None = None,
        audit: object | None = None,
        policy: IngestionPolicy | None = None,
        ranking_policy: RankingPolicy | None = None,
        context: PriorityContext | Mapping[str, PriorityContext] | None = None,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        if not tenant_id or not tenant_id.strip():
            raise ValueError("tenant_id is required")
        self.collectors = collectors
        self.tenant_id = tenant_id
        self.kev_catalog = kev_catalog
        self.epss_provider = epss_provider
        self.ranking_policy = ranking_policy
        self.context = context
        self.clock = clock
        self._ingestion = IngestionService(
            store=ingestion_store,  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
            policy=policy or IngestionPolicy(),
        )

    # -- run --------------------------------------------------------------
    def run(self, *, limit: int | None = None) -> JobReport:
        run_at = self.clock()
        report = JobReport(run_at=run_at, origin="unknown")
        collected: list[NormalizedVulnerability] = []

        for name, collector in self.collectors.items():
            try:
                produced = list(collector())
            except SourceError as exc:
                report.sources.append(
                    SourceResult(
                        source=name,
                        status=CollectionStatus.FAILED.value,
                        error=str(exc),
                        retry_after=getattr(exc, "retry_after", None),
                    )
                )
                report.warnings.append(
                    f"{name} failed: collection error, no data recorded for this source"
                )
                continue
            except Exception as exc:
                report.sources.append(
                    SourceResult(
                        source=name,
                        status=CollectionStatus.FAILED.value,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )
                report.warnings.append(f"{name} failed with an unexpected error")
                continue

            if not produced:
                # An empty answer is not a failure, and it is not data either.
                report.sources.append(
                    SourceResult(source=name, status=CollectionStatus.OK.value, records=0)
                )
                report.warnings.append(
                    f"{name} returned zero records; recorded as an empty answer, not a failure"
                )
                continue

            report.sources.append(
                SourceResult(
                    source=name, status=CollectionStatus.OK.value, records=len(produced)
                )
            )
            collected.extend(produced)

        if not collected:
            report.warnings.append(
                "no records collected this run; nothing to enrich, rank or store"
            )
            return report

        origins = {record.origin for record in collected}
        if len(origins) > 1:
            # Refuse rather than merge: a mixed batch cannot be attributed.
            report.warnings.append(
                "mixed-origin input refused: "
                + ", ".join(sorted(origin.value for origin in origins))
            )
            report.sources.append(
                SourceResult(
                    source="job",
                    status=CollectionStatus.FAILED.value,
                    error="mixed-origin input refused",
                )
            )
            return report
        report.origin = next(iter(origins)).value
        # Deliberately *not* set here. `collected_anything` is set after the
        # pipeline completes, so a batch refused at correlation or ingestion cannot
        # report that data was collected. It previously meant only "some provider
        # answered" and made a fully-refused run look successful.

        merged = _correlate(collected, report)
        enriched = self._enrich(merged, report)

        report.records = enriched
        report.ranking = rank_vulnerabilities(
            enriched,
            context=self.context,
            now=run_at,
            limit=limit,
            policy=self.ranking_policy,
        )

        # Ingestion runs only when it can actually do something. Calling it with no
        # store produced an ImportReport full of "skipped: no store configured"
        # outcomes, which reads like a per-record decision rather than the
        # configuration fact it is.
        if self._ingestion.store is None and not self._ingestion.policy.dry_run:
            report.warnings.append(
                "no ingestion store configured: records were enriched and ranked but "
                "nothing was written"
            )
            report.collected_anything = bool(enriched)
            return report
        report.ingestion = self._ingestion.import_records(
            enriched, tenant_id=self.tenant_id, collected_at=run_at
        )
        if report.ingestion.created or report.ingestion.updated or report.ingestion.unchanged:
            report.collected_anything = True
        return report

    # -- stages -----------------------------------------------------------
    def _enrich(
        self, records: Sequence[NormalizedVulnerability], report: JobReport
    ) -> list[NormalizedVulnerability]:
        from ..normalization import KevSignal, attach_epss, attach_kev

        out: list[NormalizedVulnerability] = []
        for record in records:
            if self.kev_catalog is not None:
                # `entries` is the catalogue's own mapping; there is no `get`
                # helper, and inventing one here would duplicate the lookup rule.
                #
                # The distinction that matters: absence from a catalogue we
                # *successfully loaded* is `listed=False` (checked, not listed),
                # which is real evidence. It is not `None` (unknown). Only a
                # catalogue we never obtained leaves KEV unassessed.
                entry = self.kev_catalog.entries.get(str(record.cve))
                signal = KevSignal(
                    record.cve,
                    listed=entry is not None,
                    date_added=entry.date_added if entry else None,
                    due_date=entry.due_date if entry else None,
                    checked=True,
                    catalog_version=self.kev_catalog.catalog_version,
                )
                record = attach_kev(record, signal)
            else:
                # Not consulted is not the same as "not exploited". Leaving `kev`
                # unset keeps that distinction visible downstream.
                report.warnings.append(
                    "KEV catalogue not configured: kev left unassessed, never false"
                )
            out.append(record)

        if self.epss_provider is not None and out:
            try:
                scores = self.epss_provider.fetch([record.cve for record in out])  # type: ignore[attr-defined]
            except SourceError:
                report.warnings.append(
                    "EPSS unavailable: scores left empty (not zero) and excluded from ranking"
                )
                scores = {}
            out = [attach_epss(record, scores.get(str(record.cve))) for record in out]
        else:
            report.warnings.append("no EPSS provider: exploitation forecasting excluded")
        return out


def _correlate(
    records: Sequence[NormalizedVulnerability], report: JobReport
) -> list[NormalizedVulnerability]:
    """Merge per-source records, keeping conflicts rather than resolving them."""
    from ..correlation import correlate

    try:
        clusters = correlate(records)
    except Exception as exc:  # correlation must not lose the collection
        report.warnings.append(
            f"correlation failed ({type(exc).__name__}); records kept unreconciled"
        )
        return list(records)

    merged = [cluster.merged for cluster in clusters]
    contested = sum(1 for cluster in clusters if cluster.contested)
    if contested:
        report.warnings.append(
            f"{contested} record(s) carry source disagreements; both values retained"
        )
    if len(merged) < len(records):
        report.warnings.append(
            f"{len(records) - len(merged)} duplicate record(s) merged across sources"
        )
    return merged


def source_state(result: SourceResult, *, checked_at: datetime) -> SourceState:
    """Adapt a job result to the health `SourceState` shape.

    Kept as a function rather than a method so health reporting can consume a job
    report without constructing a job.
    """
    from ..schema import SourceKind

    try:
        kind = SourceKind(result.source)
    except ValueError:
        kind = SourceKind.NVD
    return SourceState(
        kind=kind,
        status=CollectionStatus(result.status),
        checked_at=checked_at,
        error=result.error,
        retry_after=result.retry_after,
        records=result.records,
    )
