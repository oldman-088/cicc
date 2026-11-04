"""Vulnerability → ATT&CK correlation: the bridge to threat intelligence.

Why this module exists
----------------------
A CVE record says *how bad* a flaw is. It does not say *who uses it and how*. That
second question is what threat intelligence (CICC Domain B, Agent 2) answers, and
without it a vulnerability ranking cannot say "this is on the path a ransomware
operator actually takes".

The join key is MITRE ATT&CK. The Center for Threat-Informed Defense publishes
public CVE→ATT&CK mappings (the "Prioritize Known Exploited Vulnerabilities"
project), which link a CVE to the techniques adversaries use to exploit it. This
module consumes that data as an *optional* enrichment and produces a stable
vocabulary the threat-intelligence side can key on.

Design constraints
------------------
* **The mapping is data, not code.** It ships as a JSON file the host loads and
  passes in. Nothing here fetches anything, so importing this module cannot open a
  connection, and tests use a small explicit fixture.
* **Absence is not safety.** A CVE with no ATT&CK mapping is *unmapped*, which is
  different from "not exploited". :class:`TechniqueCorrelation` keeps that
  distinction in a tri-state, exactly as ``kev`` does.
* **Attribution is mandatory.** The dataset is third-party work; every result
  carries the source and version it came from, so a report can credit it and a
  reviewer can tell which snapshot produced a claim.
* **No guessing.** Only ids present in the loaded mapping are reported. There is no
  CWE→ATT&CK inference, because CWE describes a weakness class while ATT&CK
  describes an adversary behaviour, and the two do not map one-to-one. Inventing
  that mapping would manufacture confident correlations that no source supports.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any

from .errors import ValidationError
from .schema import CveId, NormalizedVulnerability

__all__ = [
    "MAPPING_TYPES",
    "AttackTechnique",
    "CveTechniqueMap",
    "TechniqueCorrelation",
    "correlate_techniques",
    "technique_rollup",
]

#: The mapping types the CTID KEV dataset defines.  They answer different
#: questions, so a consumer that needs "how is it exploited" must filter on
#: ``exploitation_technique`` rather than reading every technique alike.
MAPPING_TYPES: tuple[str, ...] = (
    "exploitation_technique",
    "primary_impact",
    "secondary_impact",
    "uncategorized",
)

#: The technique an adversary uses to reach the flaw.  Worth calling out because
#: ``T1190`` (Exploit Public-Facing Application) is the single strongest signal
#: that a vulnerability is reachable from the internet rather than only locally.
EXPLOITATION_TECHNIQUE = "exploitation_technique"


@dataclass(frozen=True)
class AttackTechnique:
    """One ATT&CK technique attached to a CVE, with the reason it was attached."""

    technique_id: str
    name: str
    mapping_type: str
    #: The mapping curator's free-text justification.  Kept because an assertion
    #: without its evidence cannot be reviewed or disputed.
    comment: str | None = None

    def __post_init__(self) -> None:
        if not self.technique_id:
            raise ValidationError("technique id is required", field="technique_id")
        if self.mapping_type not in MAPPING_TYPES:
            raise ValidationError(
                f"unknown mapping type: {self.mapping_type!r}", field="mapping_type"
            )

    @property
    def is_exploitation(self) -> bool:
        return self.mapping_type == EXPLOITATION_TECHNIQUE

    def as_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "mapping_type": self.mapping_type,
            "comment": self.comment,
        }


@dataclass(frozen=True)
class CveTechniqueMap:
    """A loaded CVE→ATT&CK dataset, immutable once built.

    ``source``/``version`` are not decoration: they are what lets a report say
    *which* snapshot produced a correlation, so a stale mapping is detectable
    rather than invisible.
    """

    source: str
    version: str
    attack_version: str | None
    created: datetime | None
    #: CVE string -> techniques.  A tuple so iteration order is stable and the map
    #: cannot be mutated after a report has already quoted it.
    by_cve: Mapping[str, tuple[AttackTechnique, ...]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.source:
            raise ValidationError("mapping source is required", field="source")
        # A frozen dataclass with a dict inside is *not* immutable: the reference is
        # frozen, the contents are not. A report that has already quoted a
        # correlation could see the mapping change underneath it, which is exactly
        # the property this class claims. A read-only proxy makes the claim true.
        if not isinstance(self.by_cve, MappingProxyType):
            object.__setattr__(self, "by_cve", MappingProxyType(dict(self.by_cve)))

    def techniques_for(self, cve: str | CveId) -> tuple[AttackTechnique, ...]:
        key = str(cve).upper()
        return self.by_cve.get(key, ())

    @property
    def mapped_cves(self) -> int:
        return len(self.by_cve)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "version": self.version,
            "attack_version": self.attack_version,
            "created": self.created.isoformat() if self.created else None,
            "mapped_cves": self.mapped_cves,
        }


@dataclass(frozen=True)
class TechniqueCorrelation:
    """What ATT&CK says about one CVE — and, explicitly, what it does not say."""

    cve: str
    techniques: tuple[AttackTechnique, ...]
    #: ``True`` only when a mapping dataset was actually consulted.  ``False``
    #: means "we did not look", which must never be rendered as "no techniques".
    consulted: bool
    source: str | None = None

    @property
    def mapped(self) -> bool:
        return bool(self.techniques)

    @property
    def externally_reachable(self) -> bool | None:
        """Whether an ATT&CK exploitation technique says the flaw is internet-facing.

        ``None`` when unmapped or unconsulted: unknown is not ``False``, because
        "we have no evidence it is reachable" and "we have evidence it is not" lead
        to different decisions.
        """
        if not self.consulted:
            return None
        if not self.techniques:
            return None
        return any(
            t.technique_id == "T1190" and t.is_exploitation for t in self.techniques
        )

    def as_dict(self) -> dict[str, Any]:
        reachability = self.externally_reachable
        return {
            "cve": self.cve,
            "consulted": self.consulted,
            "source": self.source,
            "mapped": self.mapped,
            "externally_reachable": reachability,
            "techniques": [t.as_dict() for t in self.techniques],
        }


def _techniques_of(entry: Mapping[str, Any]) -> AttackTechnique | None:
    """Build one technique from one mapping object, or ``None`` if unusable."""
    technique_id = entry.get("attack_object_id")
    if not isinstance(technique_id, str) or not technique_id.strip():
        return None
    name = entry.get("attack_object_name")
    mapping_type = entry.get("mapping_type")
    comment = entry.get("comments")
    return AttackTechnique(
        technique_id=technique_id.strip().upper(),
        name=name.strip() if isinstance(name, str) and name.strip() else "unknown",
        mapping_type=mapping_type
        if isinstance(mapping_type, str) and mapping_type in MAPPING_TYPES
        else "uncategorized",
        comment=comment.strip() if isinstance(comment, str) and comment.strip() else None,
    )


def load_ctid_mapping(
    document: Mapping[str, Any],
    *,
    source: str = "mitre-ctid/mappings-explorer",
) -> CveTechniqueMap:
    """Build a :class:`CveTechniqueMap` from a CTID Mappings Explorer document.

    The document shape is ``{"metadata": {...}, "mapping_objects": [...]}``; each
    object carries ``capability_id`` (a CVE), ``attack_object_id`` (a technique),
    ``mapping_type`` and an optional ``comments`` justification.

    Malformed entries are skipped rather than raising: a single bad row in a
    1,000-row third-party dataset must not make the whole enrichment unavailable.
    The count of skipped rows is not silently dropped — callers can compare
    ``len(mapping_objects)`` with the number of techniques they received.
    """
    if not isinstance(document, Mapping):
        raise ValidationError("mapping document must be an object", field="document")
    raw_objects = document.get("mapping_objects")
    if not isinstance(raw_objects, list):
        raise ValidationError(
            "mapping document has no 'mapping_objects' list", field="mapping_objects"
        )

    grouped: dict[str, list[AttackTechnique]] = {}
    for entry in raw_objects:
        if not isinstance(entry, Mapping):
            continue
        raw_cve = entry.get("capability_id")
        if not isinstance(raw_cve, str):
            continue
        try:
            cve = str(CveId.parse(raw_cve))
        except ValidationError:
            # Not a CVE (some frameworks key on other capability ids); ignore it.
            continue
        technique = _techniques_of(entry)
        if technique is None:
            continue
        bucket = grouped.setdefault(cve, [])
        # The dataset can repeat a (cve, technique) pair across mapping types; the
        # pair is kept once per type but never duplicated within a type.
        if any(
            existing.technique_id == technique.technique_id
            and existing.mapping_type == technique.mapping_type
            for existing in bucket
        ):
            continue
        bucket.append(technique)

    metadata = document.get("metadata")
    meta = metadata if isinstance(metadata, Mapping) else {}
    created = None
    raw_created = meta.get("creation_date")
    if isinstance(raw_created, str):
        for fmt in ("%m/%d/%Y", "%Y-%m-%d"):
            try:
                created = datetime.strptime(raw_created.strip(), fmt)
                break
            except ValueError:
                continue

    attack_version = meta.get("attack_version")
    return CveTechniqueMap(
        source=source,
        version=str(meta.get("mapping_framework_version") or "unknown"),
        attack_version=attack_version if isinstance(attack_version, str) else None,
        created=created,
        by_cve={
            cve: tuple(sorted(techniques, key=lambda t: (t.mapping_type, t.technique_id)))
            for cve, techniques in grouped.items()
        },
    )


def correlate_techniques(
    records: Iterable[NormalizedVulnerability],
    mapping: CveTechniqueMap | None,
) -> tuple[TechniqueCorrelation, ...]:
    """Correlate records against a mapping dataset.

    Passing ``mapping=None`` is meaningful and supported: every result is then
    ``consulted=False``, which lets a caller render "ATT&CK correlation was not
    configured" instead of implying no techniques exist.
    """
    out: list[TechniqueCorrelation] = []
    for record in records:
        key = str(record.cve)
        techniques = mapping.techniques_for(key) if mapping is not None else ()
        out.append(
            TechniqueCorrelation(
                cve=key,
                techniques=techniques,
                consulted=mapping is not None,
                source=mapping.source if mapping is not None else None,
            )
        )
    return tuple(out)


@dataclass(frozen=True)
class TechniqueRollup:
    """Techniques ranked by how many of *our* CVEs they touch.

    This is the artifact threat intelligence consumes: it answers "which adversary
    behaviours are relevant to my current vulnerability load", which is the
    question an ATT&CK heatmap cannot answer on its own.
    """

    total_cves: int
    by_technique: Mapping[str, tuple[str, ...]]
    names: Mapping[str, str]
    consulted: bool

    @property
    def techniques(self) -> tuple[str, ...]:
        return tuple(self.by_technique)

    def as_dict(self) -> dict[str, Any]:
        return {
            "consulted": self.consulted,
            "total_cves": self.total_cves,
            "techniques": [
                {
                    "technique_id": tid,
                    "name": self.names.get(tid, "unknown"),
                    "cve_count": len(cves),
                    "cves": list(cves),
                }
                for tid, cves in self.by_technique.items()
            ],
        }


def technique_rollup(correlations: Iterable[TechniqueCorrelation]) -> TechniqueRollup:
    """Fold per-CVE correlations into a technique-indexed view.

    Only exploitation techniques count towards the rollup by default: a
    *consequence* technique (``primary_impact``, e.g. "Data from Local System") says
    what happens after exploitation, which is not the same as how the flaw is
    reached. Mixing them would let a data-theft impact outrank the exposure that
    made it possible.
    """
    per_technique: dict[str, list[str]] = {}
    names: dict[str, str] = {}
    consulted = False
    cves: set[str] = set()
    for correlation in correlations:
        cves.add(correlation.cve)
        consulted = consulted or correlation.consulted
        for technique in correlation.techniques:
            if not technique.is_exploitation:
                continue
            bucket = per_technique.setdefault(technique.technique_id, [])
            if correlation.cve not in bucket:
                bucket.append(correlation.cve)
            names.setdefault(technique.technique_id, technique.name)
    ordered = sorted(per_technique.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    return TechniqueRollup(
        total_cves=len(cves),
        by_technique={tid: tuple(sorted(cves_list)) for tid, cves_list in ordered},
        names=names,
        consulted=consulted,
    )
