"""Vulnerability identity, deduplication and cross-source correlation.

The same real-world defect arrives from several providers wearing different
identifiers: NVD calls it ``CVE-2024-1234``, OSV calls it
``GHSA-xxxx-yyyy-zzzz``, a vendor calls it ``RHSA-2024:5678``.  Ranking the same
defect five times, or counting it as five findings, is a reporting defect; so is
collapsing two genuinely different defects that happen to share a package.

This module resolves that.  It is deliberately conservative:

* an identifier only merges records when the *source itself* declared the
  relationship (an OSV ``aliases`` entry, or a matching CVE), never on string
  similarity or a shared package name;
* merging refuses mixed origins, so a fixture record can never borrow a live
  record's identity;
* the cluster keeps an explicit list of the identifiers it absorbed and of the
  conflicts it resolved, so a reviewer can audit every merge;
* a record whose identity cannot be established is reported as *unresolved*
  rather than being dropped or guessed at.

Scoring does not live here; this module only decides *what is the same thing*.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from .errors import MixedOriginError
from .schema import NormalizedVulnerability, Origin, merge_records

__all__ = [
    "IDENTIFIER_PATTERNS",
    "AdvisoryIdentity",
    "CorrelationCluster",
    "IdentityResolution",
    "correlate",
    "resolve_identity",
]

#: Identifier families this package can recognise.  Matching is anchored and
#: case-insensitive; anything unrecognised is kept as an opaque advisory id.
IDENTIFIER_PATTERNS: Mapping[str, re.Pattern[str]] = {
    "cve": re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE),
    "ghsa": re.compile(r"^GHSA(-[0-9a-z]{4}){3}$", re.IGNORECASE),
    "pysec": re.compile(r"^PYSEC-\d{4}-\d+$", re.IGNORECASE),
    "go": re.compile(r"^GO-\d{4}-\d+$", re.IGNORECASE),
    "rustsec": re.compile(r"^RUSTSEC-\d{4}-\d+$", re.IGNORECASE),
    "rhsa": re.compile(r"^RHSA-\d{4}:\d+$", re.IGNORECASE),
    "usn": re.compile(r"^USN-\d+-\d+$", re.IGNORECASE),
    "dla": re.compile(r"^DLA-\d+-\d+$", re.IGNORECASE),
    "debian": re.compile(r"^DSA-\d+-\d+(?:-\d+)?$", re.IGNORECASE),
    "mfsa": re.compile(r"^MFSA-\d{4}-\d+$", re.IGNORECASE),
    "cga": re.compile(r"^CGA-[0-9A-Z]{4}(?:-[0-9A-Z]{4}){2}$", re.IGNORECASE),
    "cert": re.compile(r"^(?:VU|CERT|ICSA)-\d+", re.IGNORECASE),
}


@dataclass(frozen=True)
class AdvisoryIdentity:
    """One recognised identifier, normalised for comparison."""

    kind: str
    value: str

    @classmethod
    def parse(cls, raw: str) -> AdvisoryIdentity | None:
        text = (raw or "").strip().upper()
        if not text:
            return None
        for kind, pattern in IDENTIFIER_PATTERNS.items():
            if pattern.match(text):
                return cls(kind=kind, value=text)
        return None


@dataclass(frozen=True)
class IdentityResolution:
    """How a record's identity was established."""

    primary: str  # the CVE when one exists, else the strongest advisory id
    identifiers: tuple[AdvisoryIdentity, ...]
    unresolved: bool
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "primary": self.primary,
            "identifiers": [f"{i.kind}:{i.value}" for i in self.identifiers],
            "unresolved": self.unresolved,
            "reasons": list(self.reasons),
        }


def resolve_identity(
    *,
    cve: str | None,
    advisory_id: str | None = None,
    aliases: Sequence[str] = (),
) -> IdentityResolution:
    """Establish a stable identity for one record.

    A CVE is preferred because it is the only identifier shared across NVD, OSV,
    KEV and EPSS.  Without one, the record keeps its advisory id and is marked
    ``unresolved`` for CVE-centric reporting — it is *not* assigned a synthetic
    CVE.
    """
    found: list[AdvisoryIdentity] = []
    reasons: list[str] = []
    seen: set[str] = set()

    def add(raw: str | None) -> None:
        identity = AdvisoryIdentity.parse(raw) if isinstance(raw, str) else None
        if identity is None:
            if raw:
                reasons.append(f"unrecognised identifier '{raw}' kept verbatim")
            return
        if identity.value in seen:
            return
        seen.add(identity.value)
        found.append(identity)

    add(cve)
    add(advisory_id)
    for alias in aliases:
        add(alias)

    if not found:
        return IdentityResolution(
            primary="", identifiers=(), unresolved=True,
            reasons=("no recognisable identifier: record cannot be correlated",),
        )

    cves = [i for i in found if i.kind == "cve"]
    if len(cves) > 1:
        # A record claiming two CVEs is either a bundle or a data error.  Do not
        # silently pick one; report it and keep the first for ordering.
        reasons.append(
            "record declares several CVEs ("
            + ", ".join(i.value for i in cves)
            + "): correlation may over-merge"
        )
        cves = sorted(cves, key=lambda i: i.value)
    primary = cves[0].value if cves else found[0].value
    return IdentityResolution(
        primary=primary,
        identifiers=tuple(found),
        unresolved=not cves,
        reasons=(
            tuple(reasons)
            if reasons
            else (
                ("identity established from CVE",)
                if cves
                else ("advisory-only: no CVE published",)
            )
        ),
    )


@dataclass(frozen=True)
class CorrelationCluster:
    """One real-world vulnerability, possibly reported by several sources."""

    identity: str
    origin: Origin
    records: tuple[NormalizedVulnerability, ...]
    identifier_map: Mapping[str, tuple[str, ...]]
    conflicts: tuple[str, ...] = ()
    contested: bool = False
    reasons: tuple[str, ...] = ()

    @property
    def sources(self) -> tuple[str, ...]:
        return tuple(sorted({s for r in self.records for s in r.sources}))

    @property
    def merged(self) -> NormalizedVulnerability:
        """Corroborated view.  Never asserts verification."""
        if len(self.records) == 1:
            return self.records[0]
        return merge_records(self.records)

    def as_dict(self) -> dict[str, object]:
        return {
            "identity": self.identity,
            "origin": self.origin.value,
            "sources": list(self.sources),
            "record_count": len(self.records),
            "identifier_map": {k: list(v) for k, v in self.identifier_map.items()},
            "contested": self.contested,
            "conflicts": list(self.conflicts),
            "reasons": list(self.reasons),
        }


def correlate(
    records: Iterable[NormalizedVulnerability],
    *,
    extra_aliases: Mapping[str, Sequence[str]] | None = None,
) -> tuple[CorrelationCluster, ...]:
    """Group records that describe the same vulnerability.

    ``extra_aliases`` lets a caller supply relationships the sources did not
    publish (for example a vendor erratum mapping).  It is a parameter rather
    than a heuristic on purpose: correlation must be *evidence*, not a guess.
    """
    items = list(records)
    if not items:
        return ()

    # Union-find over record indices, keyed by shared identifier.
    parent = list(range(len(items)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        a, b = find(left), find(right)
        if a != b:
            parent[b] = a

    def identifiers_of(record: NormalizedVulnerability) -> tuple[str, ...]:
        values: list[str] = [str(record.cve)]
        values.extend(a for a in record.aliases if isinstance(a, str))
        if extra_aliases:
            for key in (str(record.cve), *record.aliases):
                values.extend(extra_aliases.get(key, ()))
        return tuple(v.strip().upper() for v in values if v and v.strip())

    owner: dict[str, int] = {}
    for index, record in enumerate(items):
        for identifier in identifiers_of(record):
            if identifier in owner:
                union(owner[identifier], index)
            else:
                owner[identifier] = index

    groups: dict[int, list[NormalizedVulnerability]] = {}
    for index, record in enumerate(items):
        groups.setdefault(find(index), []).append(record)

    clusters: list[CorrelationCluster] = []
    for members in groups.values():
        origins = {m.origin for m in members}
        if len(origins) > 1:
            raise MixedOriginError(
                "refusing to correlate records from different origins: "
                + ", ".join(sorted(o.value for o in origins))
            )
        identity_map: dict[str, set[str]] = {}
        merged_identifiers: set[str] = set()
        for member in members:
            for identifier in identifiers_of(member):
                merged_identifiers.add(identifier)
                identity_map.setdefault(identifier, set()).add(str(member.cve))
        cves = sorted({str(m.cve) for m in members})
        identity = cves[0]
        contested = len(cves) > 1
        conflicts: list[str] = []
        if contested:
            conflicts.append(
                "cluster spans several CVE ids ("
                + ", ".join(cves)
                + "); review before treating as one finding"
            )
        clusters.append(
            CorrelationCluster(
                identity=identity,
                origin=members[0].origin,
                records=tuple(members),
                identifier_map={k: tuple(sorted(v)) for k, v in identity_map.items()},
                conflicts=tuple(conflicts),
                contested=contested,
                reasons=(
                    f"{len(members)} record(s) merged on "
                    f"{len(merged_identifiers)} shared identifier(s)",
                ),
            )
        )
    clusters.sort(key=lambda c: c.identity)
    return tuple(clusters)


class ClusterIndex:
    """Lookup helpers over correlation clusters."""

    def __init__(self, clusters: Iterable[CorrelationCluster]) -> None:
        self._clusters = tuple(clusters)
        self._by_identifier: dict[str, CorrelationCluster] = {}
        for cluster in self._clusters:
            for identifier in cluster.identifier_map:
                self._by_identifier.setdefault(identifier, cluster)

    def find(self, identifier: str) -> CorrelationCluster | None:
        return self._by_identifier.get(identifier.strip().upper())

    def for_package(self, name: str, ecosystem: str | None = None) -> list[CorrelationCluster]:
        target = name.strip().lower()
        eco = (ecosystem or "").strip().lower()
        out: list[CorrelationCluster] = []
        for cluster in self._clusters:
            for record in cluster.records:
                for affected in record.affected:
                    if affected.name.strip().lower() != target:
                        continue
                    if eco and affected.ecosystem.strip().lower() != eco:
                        continue
                    out.append(cluster)
                    break
                else:
                    continue
                break
        return out

    @property
    def contested(self) -> tuple[CorrelationCluster, ...]:
        return tuple(c for c in self._clusters if c.contested)

    def __len__(self) -> int:
        return len(self._clusters)

