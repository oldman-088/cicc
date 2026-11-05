"""Cross-reference vendor tracker evidence into canonical records (B-04 integration).

Debian/Ubuntu trackers answer a question NVD/OSV cannot: *which exact package
version per distribution release is fixed*.  This module merges that evidence
into existing :class:`NormalizedVulnerability` records using the existing
correlation discipline — **only published identifiers join**, never text or
package-name similarity:

* a Debian issue joins a record only by CVE id (``snapshot.by_cve()`` already
  excludes TEMP/DSA keys, so those can never be treated as CVEs);
* affected entries are deduplicated by ``(ecosystem, name, fixed)``, so repeated
  ingestion is idempotent and changes nothing;
* when the tracker's fixed version for a package disagrees with one already on
  the record, the existing value is **kept** and the disagreement is recorded as
  a structured :class:`FieldConflict` — conflicting evidence is data, not noise;
* provenance gains one entry per merged source, so the merged record still says
  exactly who said what.

Records are frozen, so merging returns *new* records; the inputs are never
mutated.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable

from .connectors.debian import SOURCE_NAME as DEBIAN_SOURCE
from .connectors.debian import DebianTrackerSnapshot
from .schema import (
    AffectedPackage,
    FieldConflict,
    NormalizedVulnerability,
    ProvenanceRecord,
)

__all__ = [
    "CrossRefReport",
    "merge_debian_evidence",
]


@dataclass(frozen=True)
class CrossRefReport:
    """What a cross-reference pass did — every count is explicit."""

    records_in: int
    records_matched: int
    records_out: int
    affected_added: int
    conflicts: int
    #: CVE keys present in the tracker but with no canonical record to join.
    unmatched_cves: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "records_in": self.records_in,
            "records_matched": self.records_matched,
            "records_out": self.records_out,
            "affected_added": self.affected_added,
            "conflicts": self.conflicts,
            "unmatched_cves": list(self.unmatched_cves),
        }


def _debian_affected(snapshot: DebianTrackerSnapshot, cve: str) -> list[AffectedPackage]:
    out: list[AffectedPackage] = []
    for issue in snapshot.by_cve().get(cve, ()):
        for fix in issue.releases:
            if fix.is_vulnerable or fix.is_resolved:
                out.append(
                    AffectedPackage(
                        ecosystem="debian",
                        name=issue.package,
                        fixed=fix.fixed_version,
                        range_type="ECOSYSTEM",
                    )
                )
    return out


def merge_debian_evidence(
    records: Iterable[NormalizedVulnerability],
    snapshot: DebianTrackerSnapshot,
) -> tuple[tuple[NormalizedVulnerability, ...], CrossRefReport]:
    """Merge Debian per-release fixed-version evidence into canonical records.

    Idempotent: running it twice over the same snapshot adds nothing the second
    time (affected entries and provenance entries are deduplicated).
    """
    items = list(records)
    by_cve = snapshot.by_cve()
    matched_cves: set[str] = set()
    out: list[NormalizedVulnerability] = []
    added = conflicts = 0
    matched = 0

    for record in items:
        cve = str(record.cve)
        debian_entries = _debian_affected(snapshot, cve)
        if not debian_entries:
            out.append(record)
            continue
        matched += 1
        matched_cves.add(cve)

        existing = {(a.ecosystem, a.name, a.fixed) for a in record.affected}
        existing_fixed: dict[tuple[str, str], str | None] = {
            (a.name, a.ecosystem): a.fixed for a in record.affected
        }
        new_entries: list[AffectedPackage] = []
        new_conflicts: list[FieldConflict] = []
        for entry in debian_entries:
            key = (entry.ecosystem, entry.name, entry.fixed)
            if key in existing:
                continue  # already known: idempotent
            prior = existing_fixed.get((entry.name, entry.ecosystem))
            if prior is not None and prior != entry.fixed and entry.fixed is not None:
                # Conflicting fixed versions for the same package: keep the
                # existing (earlier-provenanced) value, record the dissent.
                new_conflicts.append(
                    FieldConflict(
                        field="affected.fixed",
                        kept=str(prior),
                        discarded=(str(entry.fixed),),
                        dissenters=(DEBIAN_SOURCE,),
                    )
                )
                conflicts += 1
                continue
            new_entries.append(entry)
            added += 1

        provenance = record.provenance + (
            ProvenanceRecord(
                source=DEBIAN_SOURCE,
                source_ref=cve,
                fetched_at=snapshot.fetched_at,
                transport=snapshot.transport,
                url="https://security-tracker.debian.org/tracker/" + cve,
            ),
        ) if all(p.source != DEBIAN_SOURCE or p.source_ref != cve for p in record.provenance) else record.provenance

        sources = record.sources
        if DEBIAN_SOURCE not in sources:
            sources = tuple(sorted((*sources, DEBIAN_SOURCE)))

        out.append(
            replace(
                record,
                affected=tuple(sorted((*record.affected, *new_entries),
                                      key=lambda a: (a.ecosystem, a.name, a.fixed or ""))),
                conflicts=tuple((*record.conflicts, *new_conflicts)),
                conflict_notes=tuple((*record.conflict_notes,
                                      *(f"fixed version for {cve} disputed: kept {c.kept}, "
                                        f"discarded {', '.join(c.discarded)} ({', '.join(c.dissenters)})"
                                        for c in new_conflicts))),
                provenance=provenance,
                sources=sources,
            )
        )

    unmatched = tuple(sorted(set(by_cve) - matched_cves))
    report = CrossRefReport(
        records_in=len(items),
        records_matched=matched,
        records_out=len(out),
        affected_added=added,
        conflicts=conflicts,
        unmatched_cves=unmatched,
    )
    return tuple(out), report
