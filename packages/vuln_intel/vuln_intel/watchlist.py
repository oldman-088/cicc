"""Dependency inventory, watchlist matching and exposure analysis.

An advisory feed tells you what is already known.  The more useful question is
"which of *our* dependencies is this advisory about, and how bad is it for us?"
That requires an inventory, and it requires matching to be conservative:
a false positive wastes patch effort, a false negative leaves a vulnerable
package installed.

Matching rules, stated because they decide the answer:

* a dependency matches when **both** ecosystem and name agree, after the
  normalisation PyPI and npm themselves apply (case-insensitive, ``_`` == ``-``);
* a PURL, when present, is authoritative and overrides the name;
* an advisory with no ``affected`` entries matches nothing — it cannot;
* a dependency whose version cannot be ordered is reported as **exposed but
  unverifiable**, never silently dropped, because "we could not tell" is the
  state an operator most needs to see.

Everything here is pure: no I/O, no network, no hidden state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Sequence

from .affected import AffectedAssessment, Verdict, assess_affected, normalize_ecosystem
from .schema import NormalizedVulnerability, RecordStatus

__all__ = [
    "Dependency",
    "ExposureReport",
    "Inventory",
    "PackageMatch",
    "Watchlist",
    "analyse_exposure",
    "dependency_from_purl",
]


def _normalize_name(name: str) -> str:
    return name.strip().lower().replace("_", "-")


@dataclass(frozen=True)
class Dependency:
    """One installed package, as reported by an inventory scan."""

    ecosystem: str
    name: str
    version: str
    purl: str | None = None
    #: Free-form: which service, image or repository the dependency belongs to.
    asset: str | None = None
    direct: bool = True
    environment: str | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("dependency name must not be empty")
        if not self.ecosystem.strip():
            raise ValueError("dependency ecosystem must not be empty")

    @property
    def canonical_ecosystem(self) -> str:
        return normalize_ecosystem(self.ecosystem) or self.ecosystem.strip().lower()

    @property
    def canonical_name(self) -> str:
        return _normalize_name(self.name)


def dependency_from_purl(purl: str, *, asset: str | None = None) -> Dependency | None:
    """Parse a package URL (``pkg:npm/lodash@4.17.20``).

    Returns ``None`` for input this parser does not understand rather than
    producing a half-populated dependency.
    """
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    body = purl[len("pkg:") :]
    type_part, _, rest = body.partition("/")
    if not type_part or not rest:
        return None
    rest = rest.split("#", 1)[0].split("?", 1)[0]
    name_part, _, version = rest.rpartition("@")
    if not name_part:
        name_part, version = rest, ""
    if not name_part or not version:
        return None
    ecosystem = {
        "npm": "npm",
        "pypi": "pypi",
        "golang": "go",
        "maven": "maven",
        "cargo": "crates.io",
        "gem": "rubygems",
        "nuget": "nuget",
        "composer": "packagist",
        "deb": "debian",
        "rpm": "rpm",
    }.get(type_part.lower(), type_part)
    return Dependency(
        ecosystem=ecosystem,
        name=name_part,
        version=version,
        purl=purl,
        asset=asset,
    )


@dataclass(frozen=True)
class Inventory:
    """A set of installed dependencies, indexable by package."""

    dependencies: tuple[Dependency, ...] = ()

    def __post_init__(self) -> None:
        index: dict[tuple[str, str], list[Dependency]] = {}
        for dep in self.dependencies:
            index.setdefault((dep.canonical_ecosystem, dep.canonical_name), []).append(dep)
        object.__setattr__(self, "_index", index)

    @classmethod
    def from_purls(
        cls, purls: Iterable[str], *, asset: str | None = None
    ) -> Inventory:
        parsed = [dependency_from_purl(p, asset=asset) for p in purls]
        return cls(dependencies=tuple(d for d in parsed if d is not None))

    def for_package(self, ecosystem: str, name: str) -> tuple[Dependency, ...]:
        key = (normalize_ecosystem(ecosystem) or ecosystem.lower(), _normalize_name(name))
        return tuple(getattr(self, "_index", {}).get(key, ()))

    def __len__(self) -> int:
        return len(self.dependencies)

    def as_dict(self) -> dict[str, object]:
        return {
            "dependencies": len(self.dependencies),
            "ecosystems": sorted({d.canonical_ecosystem for d in self.dependencies}),
            "assets": sorted({d.asset for d in self.dependencies if d.asset}),
        }


@dataclass(frozen=True)
class PackageMatch:
    """One (advisory, dependency) pair with its verdict.

    ``record_status`` is the advisory's *standing* — whether the claim itself is
    published, disputed or withdrawn. It is carried alongside the verdict rather than
    folded into it, because the two answer different questions and both are needed:
    a withdrawn advisory still has a version range, so it still produces an
    ``AFFECTED`` verdict on a matching version, and the range is not wrong. What is
    wrong is presenting that verdict without saying the claim was retracted.

    Dropping it entirely — which is what happened before — is worse than either
    option: the VEX and SARIF adapters then describe a withdrawn CVE as
    ``affected``/``exploitable``, while the CTIS adapter, reading the same record,
    calls it ``false_positive``. Two exports of one record disagreeing about whether
    the vulnerability is real is not a nuance a consumer can resolve.
    """

    cve: str
    dependency: Dependency
    assessment: AffectedAssessment
    advisory_fixed: str | None
    sources: tuple[str, ...]
    #: The advisory's standing at merge time. ``None`` means no source said anything,
    #: which is not the same as ``PUBLISHED`` and must not be rendered as such.
    record_status: RecordStatus | None = None

    @property
    def retracted(self) -> bool:
        """True when the advisory itself was withdrawn or rejected.

        Deliberately narrower than "not published": a *disputed* advisory is still a
        live claim that someone contests, so it must stay in the queue with a note.
        A *rejected* one is not a claim at all, and treating it as one spends effort
        on something the vendor says does not exist.
        """
        return self.record_status is RecordStatus.REJECTED

    @property
    def verifiable(self) -> bool:
        return self.assessment.verdict is not Verdict.UNKNOWN

    def as_dict(self) -> dict[str, object]:
        return {
            "cve": self.cve,
            "asset": self.dependency.asset,
            "package": self.dependency.name,
            "ecosystem": self.dependency.canonical_ecosystem,
            "version": self.dependency.version,
            "direct": self.dependency.direct,
            "verdict": self.assessment.verdict.value,
            "record_status": self.record_status.value if self.record_status else None,
            "retracted": self.retracted,
            "fixed_version": self.assessment.fixed_version or self.advisory_fixed,
            "remediation": self.assessment.remediation,
            "reasons": list(self.assessment.reasons),
            "sources": list(self.sources),
        }


@dataclass(frozen=True)
class ExposureReport:
    """Everything the inventory is exposed to, plus what could not be checked."""

    matches: tuple[PackageMatch, ...] = ()
    #: Advisories that name a package we run, but whose version could not be
    #: evaluated.  Kept separate so "unknown" is never buried inside "affected".
    unverified: tuple[PackageMatch, ...] = ()
    #: (advisory, dependency) pairs proven NOT inside any affected range.  Kept
    #: explicitly because a ``not_affected`` verdict is the one statement that
    #: removes work from a downstream consumer's queue (VEX export relies on it);
    #: dropping it would make "safe" indistinguishable from "not evaluated".
    not_affected: tuple[PackageMatch, ...] = ()
    #: Advisories with no ``affected`` data, which cannot be matched at all.
    unexplorable: tuple[str, ...] = ()
    advisories_considered: int = 0
    assets_at_risk: tuple[str, ...] = ()

    @property
    def affected(self) -> tuple[PackageMatch, ...]:
        return tuple(m for m in self.matches if m.assessment.verdict is Verdict.AFFECTED)

    @property
    def clean(self) -> bool:
        """True only when nothing is affected *and* nothing is unverified."""
        return not self.affected and not self.unverified

    def for_asset(self, asset: str) -> tuple[PackageMatch, ...]:
        return tuple(m for m in self.affected if m.dependency.asset == asset)

    def as_dict(self) -> dict[str, object]:
        return {
            "advisories_considered": self.advisories_considered,
            "affected": len(self.affected),
            "unverified": len(self.unverified),
            "not_affected": len(self.not_affected),
            "unexplorable": list(self.unexplorable),
            "clean": self.clean,
            "assets_at_risk": list(self.assets_at_risk),
            "matches": [m.as_dict() for m in self.matches],
        }


def _purl_matches(purl: str | None, ecosystem: str, name: str) -> bool:
    if not purl:
        return True
    parsed = dependency_from_purl(purl)
    if parsed is None:
        return False
    return (
        parsed.canonical_ecosystem == ecosystem and parsed.canonical_name == _normalize_name(name)
    )


def analyse_exposure(
    inventory: Inventory,
    advisories: Iterable[NormalizedVulnerability],
) -> ExposureReport:
    """Cross an inventory with advisories.

    Complexity is O(advisories x affected-entries), not
    O(advisories x dependencies): the inventory is indexed by package, so a large
    inventory does not slow the analysis down.
    """
    matches: list[PackageMatch] = []
    unverified: list[PackageMatch] = []
    not_affected: list[PackageMatch] = []
    unexplorable: list[str] = []
    considered = 0
    assets: set[str] = set()

    for advisory in advisories:
        considered += 1
        if not advisory.affected:
            unexplorable.append(str(advisory.cve))
            continue
        for entry in advisory.affected:
            if not _purl_matches(entry.purl, normalize_ecosystem(entry.ecosystem) or "", entry.name):
                continue
            installed = inventory.for_package(entry.ecosystem, entry.name)
            for dependency in installed:
                assessment = assess_affected(
                    advisory.affected,
                    ecosystem=dependency.canonical_ecosystem,
                    name=dependency.canonical_name,
                    version=dependency.version,
                    purl=dependency.purl,
                )
                match = PackageMatch(
                    cve=str(advisory.cve),
                    dependency=dependency,
                    assessment=assessment,
                    advisory_fixed=entry.fixed,
                    sources=advisory.sources,
                    record_status=advisory.record_status,
                )
                if assessment.verdict is Verdict.AFFECTED:
                    matches.append(match)
                    if dependency.asset:
                        assets.add(dependency.asset)
                elif assessment.verdict is Verdict.UNKNOWN:
                    unverified.append(match)
                else:
                    not_affected.append(match)

    # One dependency can be matched by several affected-entries of one advisory;
    # report each (advisory, dependency) pair once.
    return ExposureReport(
        matches=_dedupe(matches),
        unverified=_dedupe(unverified),
        not_affected=_dedupe(not_affected),
        unexplorable=tuple(unexplorable),
        advisories_considered=considered,
        assets_at_risk=tuple(sorted(assets)),
    )


def _dedupe(items: Sequence[PackageMatch]) -> tuple[PackageMatch, ...]:
    seen: set[tuple[str, str, str, str | None]] = set()
    out: list[PackageMatch] = []
    for item in items:
        key = (
            item.cve,
            item.dependency.canonical_ecosystem,
            item.dependency.canonical_name,
            item.dependency.asset,
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    out.sort(key=lambda m: (m.cve, m.dependency.canonical_name))
    return tuple(out)


@dataclass
class Watchlist:
    """Packages worth collecting advisories about, derived from the inventory."""

    packages: set[tuple[str, str]] = field(default_factory=set)

    def add(self, ecosystem: str, name: str) -> None:
        eco = normalize_ecosystem(ecosystem) or ecosystem.strip().lower()
        self.packages.add((eco, _normalize_name(name)))

    def add_inventory(self, inventory: Inventory) -> None:
        for dependency in inventory.dependencies:
            self.add(dependency.canonical_ecosystem, dependency.canonical_name)

    def covers(self, ecosystem: str, name: str) -> bool:
        eco = normalize_ecosystem(ecosystem) or ecosystem.strip().lower()
        return (eco, _normalize_name(name)) in self.packages

    def as_osv_queries(self, inventory: Inventory) -> list[dict[str, object]]:
        """Build OSV ``/v1/query`` bodies, de-duplicated by package.

        One query per (ecosystem, name) with every installed version, because OSV
        answers per version and re-querying the same package wastes quota.
        """
        grouped: dict[tuple[str, str], set[str]] = {}
        for dependency in inventory.dependencies:
            grouped.setdefault(
                (dependency.canonical_ecosystem, dependency.canonical_name), set()
            ).add(dependency.version)
        queries: list[dict[str, object]] = []
        for (ecosystem, name), versions in sorted(grouped.items()):
            for version in sorted(versions):
                queries.append(
                    {"package": {"ecosystem": ecosystem, "name": name}, "version": version}
                )
        return queries

    def __len__(self) -> int:
        return len(self.packages)
