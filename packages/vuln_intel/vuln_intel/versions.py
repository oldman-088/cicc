"""Ecosystem-aware version ordering — the foundation of affected-version logic.

Why this module exists
----------------------
Saying "this CVE affects ``lodash`` below 4.17.21" is only useful if the platform
can compare ``4.17.20`` with ``4.17.21``, and it is only *safe* if the platform
refuses to guess when the ordering is ambiguous.  Previously the package kept
version strings opaque, which meant it could never answer the one question an
asset owner actually asks.

Ordering rules are not universal, so the scheme is chosen explicitly:

==================  ==========================================================
scheme              ordering basis
==================  ==========================================================
``semver``          numeric components, then pre-release identifiers
``pep440``          Python packaging epoch / release / pre / post / dev
``debian``          ``[epoch:]upstream[-revision]``, epoch dominates
``rpm``             like Debian but ``~`` sorts *before* everything
``maven``           numeric qualifier ranking (``SNAPSHOT``/``alpha``/``rc``…)
``go``              ``vMAJOR.MINOR.PATCH`` plus pseudo-version timestamps
``rubygems``        canonical segments; a letter segment is a prerelease
``opaque``          no ordering — never compared, always reported as unknown
==================  ==========================================================

Guarantees
----------
* :func:`compare` returns ``None`` rather than a wrong answer.  A caller that
  receives ``None`` must report *unknown*, not *not affected*.
* Parsing never raises: malformed input yields ``None``.
* No third-party imports (the package stays stdlib-only).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

__all__ = [
    "SCHEME_BY_ECOSYSTEM",
    "ParsedVersion",
    "VersionScheme",
    "compare",
    "compare_required",
    "parse",
    "scheme_for_ecosystem",
]


class VersionScheme(str, Enum):
    SEMVER = "semver"
    PEP440 = "pep440"
    DEBIAN = "debian"
    RPM = "rpm"
    MAVEN = "maven"
    GO = "go"
    RUBYGEMS = "rubygems"
    OPAQUE = "opaque"


#: OSV ecosystem -> ordering scheme.  Ecosystems absent from this map are
#: treated as ``opaque``: the platform will not pretend to order them.
SCHEME_BY_ECOSYSTEM: dict[str, VersionScheme] = {
    "npm": VersionScheme.SEMVER,
    "crates.io": VersionScheme.SEMVER,
    "nuget": VersionScheme.SEMVER,
    "packagist": VersionScheme.SEMVER,
    "hex": VersionScheme.SEMVER,
    "pub": VersionScheme.SEMVER,
    "github actions": VersionScheme.SEMVER,
    "swifturl": VersionScheme.SEMVER,
    "conan": VersionScheme.SEMVER,
    "bitnami": VersionScheme.SEMVER,
    "pypi": VersionScheme.PEP440,
    "debian": VersionScheme.DEBIAN,
    "ubuntu": VersionScheme.DEBIAN,
    "alpine": VersionScheme.DEBIAN,
    "maven": VersionScheme.MAVEN,
    "gradle": VersionScheme.MAVEN,
    "go": VersionScheme.GO,
    "rubygems": VersionScheme.RUBYGEMS,
    # CocoaPods vendors RubyGems' Gem::Version (Pod::Vendor::Gem::Version) and adds
    # head/`1.0.0.head` handling on top, so the segment comparison is the same.
    "cocoapods": VersionScheme.RUBYGEMS,
    "composer": VersionScheme.OPAQUE,
    "oss-fuzz": VersionScheme.OPAQUE,
    "linux": VersionScheme.DEBIAN,
    "red hat": VersionScheme.RPM,
    "rocky linux": VersionScheme.RPM,
    "almalinux": VersionScheme.RPM,
    "opensuse": VersionScheme.RPM,
    "suse": VersionScheme.RPM,
    "mageia": VersionScheme.RPM,
    "wolfi": VersionScheme.DEBIAN,
    "chainguard": VersionScheme.DEBIAN,
}


def scheme_for_ecosystem(ecosystem: str | None) -> VersionScheme:
    if not ecosystem:
        return VersionScheme.OPAQUE
    return SCHEME_BY_ECOSYSTEM.get(ecosystem.strip().lower(), VersionScheme.OPAQUE)


_PEP440 = re.compile(
    r"""^v?
    (?:(?P<epoch>\d+)!)?
    (?P<release>\d+(?:\.\d+)*)
    (?:[-_.]?(?P<pre_l>a|alpha|b|beta|c|rc|pre|preview)[-_.]?(?P<pre_n>\d+)?)?
    (?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n>\d+)?)?
    (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    $""",
    re.VERBOSE | re.IGNORECASE,
)

_PRE_ORDER = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}

#: End-of-version sentinel.  Version comparison is not "longer wins": dpkg and
#: Maven both give the end of a string a *rank*, which is what makes
#: ``1.0~rc1 < 1.0``, ``1.0 < 1.0.1`` and ``1.0-alpha < 1.0`` all true.
#: Class order below the sentinel is "sorts earlier", above is "sorts later".
_END: tuple[int, int, str] = (1, 0, "")

#: Maven qualifier ranks on the same scale as "2 x numeric value", so that a
#: missing component (rank 0) compares equal to numeric zero and to the release
#: qualifier, above every pre-release qualifier and below ``sp``.  This mirrors
#: Maven's ComparableVersion, where ``1.0-alpha < 1.0 == 1.0.0 < 1.0.1 < 1.0-sp1``.
_MAVEN_QUALIFIERS = {
    "alpha": -8,
    "a": -8,
    "beta": -6,
    "b": -6,
    "milestone": -4,
    "m": -4,
    "cr": -3,
    "rc": -3,
    "snapshot": -1,
    "": 0,
    "ga": 0,
    "final": 0,
    "release": 0,
    "sp": 1,
}

#: Unknown qualifiers rank below everything except alpha, as in Maven.
_MAVEN_UNKNOWN_QUALIFIER = -9


@dataclass(frozen=True)
class ParsedVersion:
    """A version string plus the comparison key derived from its scheme."""

    raw: str
    scheme: VersionScheme
    key: tuple[object, ...]
    is_prerelease: bool = False


def _numeric_chunks(text: str) -> tuple[int, ...] | None:
    if not text:
        return None
    parts = text.split(".")
    out: list[int] = []
    for part in parts:
        if not part.isdigit():
            return None
        out.append(int(part))
    return tuple(out)


def _parse_semver(raw: str) -> ParsedVersion | None:
    text = raw.strip()
    if text[:1] in ("v", "V"):
        text = text[1:]
    # Drop build metadata: it never participates in precedence.
    text = text.split("+", 1)[0]
    core, _, pre = text.partition("-")
    numbers = _numeric_chunks(core)
    if numbers is None:
        return None
    padded = numbers + (0,) * (3 - len(numbers)) if len(numbers) < 3 else numbers
    if pre:
        # Semver: a pre-release sorts *before* the release.
        pre_key: tuple[object, ...] = (0, tuple(_pre_identifiers(pre)))
        return ParsedVersion(raw, VersionScheme.SEMVER, (1, padded, pre_key), True)
    return ParsedVersion(raw, VersionScheme.SEMVER, (1, padded, (1,)), False)


def _pre_identifiers(pre: str) -> list[tuple[int, object]]:
    """Semver pre-release ordering: numeric ids numerically, others lexically."""
    out: list[tuple[int, object]] = []
    for ident in pre.split("."):
        if ident.isdigit():
            out.append((0, int(ident)))
        else:
            out.append((1, ident))
    return out


def _parse_pep440(raw: str) -> ParsedVersion | None:
    match = _PEP440.match(raw.strip())
    if match is None:
        return None
    release = tuple(int(p) for p in match.group("release").split("."))
    # PEP 440 compares with zero padding, so 1.2.0 and 1.2 are equal; strip
    # trailing zeros to make that hold under tuple comparison.
    while len(release) > 1 and release[-1] == 0:
        release = release[:-1]
    epoch = int(match.group("epoch") or 0)
    pre_l = (match.group("pre_l") or "").lower()
    pre_n = int(match.group("pre_n") or 0)
    post_n = int(match.group("post_n") or 0) if match.group("post_l") else None
    dev_n = int(match.group("dev_n") or 0) if match.group("dev_l") else None
    is_pre = bool(pre_l) or dev_n is not None
    # PEP 440 ordering: dev < pre < release < post.  Encode as discrete phases.
    if dev_n is not None and not pre_l:
        phase = (0, 0, -dev_n)
    elif pre_l:
        phase = (1, _PRE_ORDER.get(pre_l, 2) * 1000 + pre_n, 0)
    elif post_n is not None:
        phase = (3, post_n, 0)
    else:
        phase = (2, 0, 0)
    return ParsedVersion(raw, VersionScheme.PEP440, (epoch, release, phase), is_pre)


def _parse_debian(raw: str, *, scheme: VersionScheme) -> ParsedVersion | None:
    text = raw.strip()
    if not text:
        return None
    epoch = 0
    if ":" in text:
        head, _, tail = text.partition(":")
        if not head.isdigit():
            return None
        epoch = int(head)
        text = tail
    revision = ""
    if "-" in text:
        text, _, revision = text.rpartition("-")
    upstream = _debian_key(text)
    if upstream is None:
        return None
    pre = "-" in raw and re.search(r"(alpha|beta|rc|pre)", raw, re.IGNORECASE) is not None
    rev_key = _debian_key(revision) or (_END,)
    return ParsedVersion(raw, scheme, (epoch, upstream, rev_key), bool(pre))


_DEBIAN_CHUNK = re.compile(r"\d+|[A-Za-z]+|~")


def _debian_key(text: str) -> tuple[object, ...] | None:
    """Split into ranked chunks the way dpkg does.

    ``~`` ranks below the end of the string (so ``1.0~rc1 < 1.0``); letters rank
    between ``~`` and the sentinel, digits above it.  ``.``, ``+`` and ``-`` are
    separators and carry no rank.
    """
    out: list[object] = []
    for chunk in _DEBIAN_CHUNK.findall(text):
        if chunk == "~":
            out.append((0, 0, ""))
        elif chunk.isdigit():
            out.append((3, int(chunk), ""))
        else:
            out.append((2, 0, chunk.lower()))
    if not out:
        # Nothing rankable (e.g. "!!!", "---"): refuse instead of producing a key
        # that compares equal to every other empty version.
        return None
    out.append(_END)
    return tuple(out)


def _parse_maven(raw: str) -> ParsedVersion | None:
    text = raw.strip().lower()
    if not text:
        return None
    tokens = [t for t in re.split(r"[._\-+]", text) if t]
    out: list[int] = []
    for token in tokens:
        for sub in re.findall(r"\d+|[a-z]+", token):
            if sub.isdigit():
                out.append(int(sub) * 2)
            else:
                out.append(_MAVEN_QUALIFIERS.get(sub, _MAVEN_UNKNOWN_QUALIFIER))
    if not out:
        return None
    return ParsedVersion(
        raw, VersionScheme.MAVEN, tuple(out), any(q == "snapshot" for q in tokens)
    )


_GO_PSEUDO = re.compile(r"^\d{14}-[0-9a-f]{12}$")


def _parse_go(raw: str) -> ParsedVersion | None:
    text = raw.strip()
    if text[:1] in ("v", "V"):
        text = text[1:]
    core, _, pseudo = text.partition("-")
    numbers = _numeric_chunks(core)
    if numbers is None:
        return None
    padded = numbers + (0,) * (3 - len(numbers)) if len(numbers) < 3 else numbers
    if pseudo and _GO_PSEUDO.match(pseudo):
        return ParsedVersion(raw, VersionScheme.GO, (padded, 1, pseudo), False)
    return ParsedVersion(raw, VersionScheme.GO, (padded, 0, ""), bool(pseudo))


#: RubyGems accepts a leading numeric segment then dotted alphanumerics, with an
#: optional ``-suffix`` build tail that it rewrites to ``.pre.``.  Anything else is
#: not a gem version, so it is refused rather than approximated.
_RUBYGEMS_PATTERN = re.compile(
    r"^[0-9]+(?:\.[0-9a-zA-Z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)

#: RubyGems compares ``String < Numeric`` at each position, so the string tag must
#: sort below the numeric one.
_RUBYGEMS_STRING = 0
_RUBYGEMS_NUMERIC = 1

#: Segment separators in a canonicalised gem version.
_RUBYGEMS_SEGMENT = re.compile(r"[.\-]|(?<=[0-9])(?=[a-zA-Z])|(?<=[a-zA-Z])(?=[0-9])")


def _parse_rubygems(raw: str) -> ParsedVersion | None:
    """Parse a gem version into canonical segments, per RubyGems' ``Gem::Version``.

    The algorithm, taken from RubyGems' own documentation and ``canonical_segments``:

    * a ``-`` is read as ``.pre.``, so SemVer-style ``1.0.0-rc1`` becomes
      ``1.0.0.pre.rc1``;
    * segments are split at dots *and* at digit/letter boundaries, so ``beta10``
      becomes ``"beta"``, ``10``;
    * trailing zero segments are dropped, so ``1.0`` and ``1.0.0`` are the same
      version;
    * the version is a prerelease if it contains any letter.

    Comparison then uses canonical segments where **a string segment always sorts
    before a numeric one**, and missing segments read as ``0``.  That single rule is
    what makes every prerelease sort below the release it leads up to::

        1.0.0.alpha < 1.0.0.beta2 < 1.0.0.rc1 < 1.0.0 < 1.0.1 < 1.1.0.beta < 2.0.0

    Keys are self-delimiting and tagged *string=0, numeric=1*, because RubyGems
    orders ``String < Numeric`` at each position.  The tag alone therefore encodes
    that rule, and a numeric segment still compares numerically inside its tag, so
    ``1.0.10`` (``(1,10)``) correctly exceeds ``1.0.9`` (``(1,9)``).
    :func:`_cmp_keys` then pads a missing tail with ``0`` to reproduce RubyGems'
    ``lhs[i] || 0`` rule.
    """
    text = raw.strip()
    if not text or _RUBYGEMS_PATTERN.match(text) is None:
        return None
    if text.endswith("-") or text.startswith("-"):
        return None
    normalised = text.replace("-", ".pre.")
    # Drop trailing zero segments, as canonical_segments does.  Anchored at the end
    # so an internal "0" (as in 1.0.5) is never touched.
    while True:
        trimmed = re.sub(r"\.0+$", "", normalised)
        if trimmed == normalised or "." not in trimmed:
            normalised = trimmed
            break
        normalised = trimmed
    parts = [part for part in _RUBYGEMS_SEGMENT.split(normalised) if part]
    if not parts:
        return None
    segments: list[tuple[int, object]] = []
    for part in parts:
        if part.isdigit():
            segments.append((_RUBYGEMS_NUMERIC, int(part)))
        else:
            segments.append((_RUBYGEMS_STRING, part.lower()))
    while segments and segments[-1] == (_RUBYGEMS_NUMERIC, 0):
        # Trailing zeros never affect ordering, and removing them makes "1.0" and
        # "1.0.0" produce the same key rather than relying on the zero padding.
        segments.pop()
    prerelease = any(tag == _RUBYGEMS_STRING for tag, _ in segments)
    # The key is right-padded with numeric zeros to a fixed width so that a missing
    # segment always compares *below* a present one.  This is what makes a
    # prerelease sort under its release: RubyGems compares `lhs[i] || 0`, and 0 is
    # numeric while a prerelease segment is a string, so the string loses.
    padded = tuple(segments) + ((_RUBYGEMS_NUMERIC, 0),) * (8 - len(segments))
    return ParsedVersion(raw, VersionScheme.RUBYGEMS, padded, prerelease)


def parse(raw: str | None, scheme: VersionScheme) -> ParsedVersion | None:
    """Parse ``raw`` under ``scheme``; ``None`` means "cannot be ordered"."""
    if raw is None:
        return None
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text:
        return None
    if scheme is VersionScheme.OPAQUE:
        return None
    try:
        if scheme is VersionScheme.SEMVER:
            return _parse_semver(text)
        if scheme is VersionScheme.PEP440:
            return _parse_pep440(text)
        if scheme in (VersionScheme.DEBIAN, VersionScheme.RPM):
            return _parse_debian(text, scheme=scheme)
        if scheme is VersionScheme.MAVEN:
            return _parse_maven(text)
        if scheme is VersionScheme.GO:
            return _parse_go(text)
        if scheme is VersionScheme.RUBYGEMS:
            return _parse_rubygems(text)
    except (ValueError, TypeError):  # pragma: no cover - defensive
        return None
    return None


#: What a missing Maven component compares as: numeric zero / the release qualifier.
_MAVEN_PAD = 0


def _maven_compare(a: tuple[object, ...], b: tuple[object, ...]) -> int:
    """Maven's ComparableVersion rule: pad the shorter token list with zero."""
    width = max(len(a), len(b))
    for index in range(width):
        left = a[index] if index < len(a) else _MAVEN_PAD
        right = b[index] if index < len(b) else _MAVEN_PAD
        result = (left > right) - (left < right)  # type: ignore[operator]
        if result:
            return result
    return 0


def compare(left: str | None, right: str | None, scheme: VersionScheme) -> int | None:
    """Return ``-1``/``0``/``1``, or ``None`` when the pair cannot be ordered.

    ``None`` is a first-class answer, not an error: callers must surface it as
    "unknown", never as "equal" or "not affected".
    """
    a = parse(left, scheme)
    b = parse(right, scheme)
    if a is None or b is None:
        return None
    if scheme is VersionScheme.MAVEN:
        return _maven_compare(a.key, b.key)
    return _cmp_keys(a.key, b.key)


def compare_required(left: str, right: str, scheme: VersionScheme) -> int:
    """Like :func:`compare`, but raises ``ValueError`` instead of returning None."""
    result = compare(left, right, scheme)
    if result is None:
        raise ValueError(f"cannot order {left!r} against {right!r} as {scheme.value}")
    return result


def _cmp_keys(a: object, b: object) -> int:
    """Total order over the tuple keys, tolerant of mixed shapes in one slot."""
    if isinstance(a, tuple) and isinstance(b, tuple):
        for a_item, b_item in zip(a, b, strict=False):
            result = _cmp_keys(a_item, b_item)
            if result:
                return result
        return (len(a) > len(b)) - (len(a) < len(b))
    a_is_tuple, b_is_tuple = isinstance(a, tuple), isinstance(b, tuple)
    if a_is_tuple != b_is_tuple:
        # Deterministic tie-break rather than a TypeError; only reachable when a
        # source mixes shapes inside one slot, which the parsers do not produce.
        return 1 if a_is_tuple else -1
    if type(a) is type(b):
        return (a > b) - (a < b)  # type: ignore[operator]
    return (type(a).__name__ > type(b).__name__) - (type(a).__name__ < type(b).__name__)
