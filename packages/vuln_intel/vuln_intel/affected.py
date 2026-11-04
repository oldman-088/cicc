"""Affected-version evaluation: the answer to "is *this* install vulnerable?".

A normalized advisory is not an answer.  ``{"introduced": "0", "fixed":
"4.17.21"}`` becomes an answer only when it is matched against a concrete
installed version, and that match is a three-valued decision:

* ``AFFECTED``   — the installed version is inside a published affected range;
* ``NOT_AFFECTED`` — every range that constrains this package excludes it, and
  there was at least one range that could be evaluated;
* ``UNKNOWN``    — nothing could be decided (no range for this package, an
  unorderable version, a GIT range, a withdrawn advisory).

``UNKNOWN`` is the default and the honest answer.  It is deliberately **not**
collapsed into ``NOT_AFFECTED``: reporting "we are not affected" because the
platform could not parse a version is the single most dangerous failure mode in
this domain.

Range semantics follow OSV:

* ``introduced`` is inclusive, ``fixed`` exclusive;
* ``last_affected`` is inclusive and mutually exclusive with ``fixed``;
* an OSV range is a list of *events* forming intervals; several intervals may
  exist in one range, and several ranges may exist for one package;
* a ``limit`` event bounds a range but does not close a vulnerable interval;
* ``GIT`` ranges are commit-graph searches, not version comparisons, and are
  never evaluated here;
* a bare ``versions`` list means exactly those versions.

Explicit versions always win over ranges: if a ``versions`` list contains the
installed version the verdict is ``AFFECTED`` even when a range appears to
exclude it.  When ranges contradict each other, the *affected* verdict wins —
an advisory is a warning, not a proof of safety.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Sequence

from .schema import AffectedPackage
from .versions import VersionScheme, compare, scheme_for_ecosystem

__all__ = [
    "AffectedAssessment",
    "Verdict",
    "VersionRange",
    "assess_affected",
    "normalize_ecosystem",
    "verdict_for",
]


class Verdict(str, Enum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNKNOWN = "unknown"

    @property
    def is_positive(self) -> bool:
        return self is Verdict.AFFECTED


_ECOSYSTEM_ALIASES = {
    "pypi": "pypi",
    "python": "pypi",
    "npm": "npm",
    "node": "npm",
    "nodejs": "npm",
    "node.js": "npm",
    "javascript": "npm",
    "go": "go",
    "golang": "go",
    "maven": "maven",
    "java": "maven",
    "gradle": "maven",
    "debian": "debian",
    "ubuntu": "ubuntu",
    "alpine": "alpine",
    "rpm": "rpm",
    "red hat": "red hat",
    "redhat": "red hat",
    "nuget": "nuget",
    "cargo": "crates.io",
    "crates.io": "crates.io",
    "rust": "crates.io",
    "rubygems": "rubygems",
    "gem": "rubygems",
    "composer": "composer",
    "packagist": "packagist",
    "hex": "hex",
    "pub": "pub",
}


def normalize_ecosystem(value: str | None) -> str | None:
    """Map the many spellings of an ecosystem onto OSV's vocabulary."""
    if not value:
        return None
    key = value.strip().lower()
    return _ECOSYSTEM_ALIASES.get(key, key)


@dataclass(frozen=True)
class VersionRange:
    """One OSV range, parsed into intervals this module can reason about."""

    kind: str  # SEMVER | ECOSYSTEM | GIT
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    limit: str | None = None
    intervals: tuple[tuple[str | None, str | None, str | None], ...] = ()

    @property
    def is_version_comparable(self) -> bool:
        return self.kind.upper() in ("SEMVER", "ECOSYSTEM")


_RANGE_LIKE_KEYS = ("introduced", "fixed", "last_affected", "limit")


def _build_intervals(
    events: Sequence[tuple[str, str]],
) -> tuple[tuple[str | None, str | None, str | None], ...]:
    """Fold an OSV event list into ``(introduced, fixed, last_affected)`` triples.

    ``limit`` is intentionally dropped: it bounds the *range document*, it does
    not declare the versions below it safe, so ignoring it can only make the
    evaluator more cautious.
    """
    intervals: list[tuple[str | None, str | None, str | None]] = []
    current_introduced: str | None = None
    opened = False
    for kind, value in events:
        if kind == "introduced":
            if opened:
                # An "introduced" without an intervening close opens an unbounded
                # tail of the previous interval; keep it rather than discard it.
                intervals.append((current_introduced, None, None))
            current_introduced, opened = value, True
        elif kind == "fixed":
            if opened:
                intervals.append((current_introduced, value, None))
            else:
                # `fixed` with no `introduced` means "everything below this".
                intervals.append((None, value, None))
            opened = False
        elif kind == "last_affected":
            if opened:
                intervals.append((current_introduced, None, value))
            opened = False
    if opened:
        intervals.append((current_introduced, None, None))
    return tuple(intervals)


def _range_from_package(pkg: AffectedPackage) -> list[VersionRange]:
    """Recover range objects from a normalized :class:`AffectedPackage`.

    The normalized model stores ``introduced``/``fixed`` plus the raw event list
    in ``versions``-adjacent metadata when the connector preserved it.  When it
    did not, a single interval is reconstructed — which is why the OSV connector
    now keeps every interval explicitly.
    """
    kind = getattr(pkg, "range_type", None) or "ECOSYSTEM"
    events = getattr(pkg, "events", None) or ()
    if events:
        by_range: dict[int, list[tuple[str, str]]] = {}
        for index, ekind, evalue in events:
            by_range.setdefault(index, []).append((ekind, evalue))
        return [
            VersionRange(kind=kind, intervals=_build_intervals(evs))
            for _, evs in sorted(by_range.items())
        ]
    if pkg.introduced is None and pkg.fixed is None:
        return []
    return [
        VersionRange(
            kind=kind,
            introduced=pkg.introduced,
            fixed=pkg.fixed,
            last_affected=getattr(pkg, "last_affected", None),
            intervals=((pkg.introduced, pkg.fixed, getattr(pkg, "last_affected", None)),),
        )
    ]


def _in_interval(
    version: str,
    introduced: str | None,
    fixed: str | None,
    last_affected: str | None,
    scheme: VersionScheme,
) -> bool | None:
    """``True``/``False`` when decidable, ``None`` when the interval can't be read."""
    # OSV uses the literal "0" for "since the beginning of time"; no ecosystem
    # has a real version below it, so the lower bound is treated as open.
    if introduced is not None and introduced not in ("0", ""):
        cmp_intro = compare(version, introduced, scheme)
        if cmp_intro is None:
            return None
        if cmp_intro < 0:
            return False
    if fixed is not None:
        cmp_fixed = compare(version, fixed, scheme)
        if cmp_fixed is None:
            return None
        if cmp_fixed >= 0:
            return False
    if last_affected is not None:
        cmp_last = compare(version, last_affected, scheme)
        if cmp_last is None:
            return None
        if cmp_last > 0:
            return False
    return True


@dataclass(frozen=True)
class AffectedAssessment:
    """A verdict plus the reasoning that produced it — never a bare boolean."""

    verdict: Verdict
    package: str | None
    ecosystem: str | None
    installed_version: str | None
    scheme: str
    matched_range: str | None
    fixed_version: str | None
    reasons: tuple[str, ...]
    advisory_ids: tuple[str, ...] = ()

    @property
    def remediation(self) -> str | None:
        """Action an operator can take, when the data supports one."""
        if self.verdict is not Verdict.AFFECTED:
            return None
        if self.fixed_version:
            return f"upgrade {self.package} to {self.fixed_version} or later"
        return f"no fixed version published for {self.package}: apply mitigations"

    def as_dict(self) -> dict[str, object]:
        return {
            "verdict": self.verdict.value,
            "package": self.package,
            "ecosystem": self.ecosystem,
            "installed_version": self.installed_version,
            "scheme": self.scheme,
            "matched_range": self.matched_range,
            "fixed_version": self.fixed_version,
            "remediation": self.remediation,
            "reasons": list(self.reasons),
            "advisory_ids": list(self.advisory_ids),
        }


def _describe(
    introduced: str | None, fixed: str | None, last_affected: str | None
) -> str:
    lower = "any version" if introduced in (None, "", "0") else f">= {introduced}"
    if fixed is not None:
        upper = f"< {fixed}"
    elif last_affected is not None:
        upper = f"<= {last_affected}"
    else:
        upper = "(no upper bound)"
    return f"{lower} {upper}"


def _match_package(pkg: AffectedPackage, ecosystem: str, name: str) -> bool:
    pkg_eco = normalize_ecosystem(pkg.ecosystem)
    if pkg_eco is None or pkg_eco != ecosystem:
        return False
    return _normalize_name(pkg.name) == _normalize_name(name)


def _normalize_name(name: str) -> str:
    # npm and PyPI both treat these as equivalent; GitHub advisories do too.
    return name.strip().lower().replace("_", "-")


def assess_affected(
    packages: Iterable[AffectedPackage],
    *,
    ecosystem: str | None,
    name: str | None = None,
    version: str | None = None,
    purl: str | None = None,
) -> AffectedAssessment:
    """Decide whether ``version`` of ``name`` in ``ecosystem`` is affected.

    Every degraded input path yields ``UNKNOWN`` together with the reason, so a
    caller can distinguish "we checked and you are safe" from "we could not
    check".
    """
    eco = normalize_ecosystem(ecosystem)
    reasons: list[str] = []
    if eco is None:
        return AffectedAssessment(
            Verdict.UNKNOWN, name, ecosystem, version, "unknown", None, None,
            ("no ecosystem supplied: affected versions cannot be interpreted",),
        )
    if not name:
        return AffectedAssessment(
            Verdict.UNKNOWN, name, eco, version, "unknown", None, None,
            ("no package name supplied",),
        )
    if not version:
        return AffectedAssessment(
            Verdict.UNKNOWN, name, eco, version, "unknown", None, None,
            ("no installed version supplied: cannot evaluate ranges",),
        )

    scheme = scheme_for_ecosystem(eco)
    items = [p for p in packages if _match_package(p, eco, name)]
    if not items:
        return AffectedAssessment(
            Verdict.UNKNOWN, name, eco, version, scheme.value, None, None,
            (f"no affected entry for {name} in {eco}: advisory does not cover this package",),
        )
    if scheme is VersionScheme.OPAQUE and not any(p.versions for p in items):
        return AffectedAssessment(
            Verdict.UNKNOWN, name, eco, version, scheme.value, None, None,
            (
                f"no version ordering is defined for ecosystem '{eco}'; "
                "refusing to guess",
            ),
        )

    saw_decidable = False
    fixed_version: str | None = None
    for pkg in items:
        if pkg.versions and _explicit_match(pkg.versions, version):
            fixed = pkg.fixed
            return AffectedAssessment(
                Verdict.AFFECTED, name, eco, version, scheme.value,
                "explicit version list", fixed,
                (f"{version} is listed explicitly as affected",),
            )
        for version_range in _range_from_package(pkg):
            if not version_range.is_version_comparable:
                reasons.append(
                    f"{version_range.kind} range is not comparable to a version; ignored"
                )
                continue
            for introduced, fixed, last_affected in version_range.intervals:
                outcome = _in_interval(
                    version, introduced, fixed, last_affected, scheme
                )
                if outcome is None:
                    reasons.append(
                        f"could not order {version!r} against "
                        f"{_describe(introduced, fixed, last_affected)} "
                        f"as {scheme.value}"
                    )
                    continue
                saw_decidable = True
                if outcome:
                    return AffectedAssessment(
                        Verdict.AFFECTED, name, eco, version, scheme.value,
                        _describe(introduced, fixed, last_affected),
                        fixed or pkg.fixed,
                        (f"{version} falls in {_describe(introduced, fixed, last_affected)}",),
                    )
                if fixed:
                    fixed_version = fixed

    if not saw_decidable:
        return AffectedAssessment(
            Verdict.UNKNOWN, name, eco, version, scheme.value, None, None,
            tuple(reasons[-4:]) or ("no usable version range",),
        )
    return AffectedAssessment(
        Verdict.NOT_AFFECTED, name, eco, version, scheme.value, None, fixed_version,
        ("outside every published affected range", *reasons[-2:]),
    )


def _explicit_match(listed: Sequence[str], version: str) -> bool:
    target = version.strip()
    for entry in listed:
        if not isinstance(entry, str):
            continue
        if entry.strip() == target:
            return True
    return False


_VERSION_HINT = re.compile(r"^[vV]?\d")


def verdict_for(*, packages: Sequence[AffectedPackage], **kwargs: object) -> Verdict:
    """Convenience wrapper returning just the verdict."""
    return assess_affected(packages, **kwargs).verdict  # type: ignore[arg-type]
