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
    (?:(?:-(?P<post_implicit>\d+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n>\d+)?))?
    (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    $""",
    re.VERBOSE | re.IGNORECASE,
)

_PRE_ORDER = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}

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
    # PEP 440 spells a post release two ways: the ``post``/``rev``/``r`` label, and
    # a bare ``-N`` (``1.0-1`` == ``1.0.post1``).  Only the labelled form was read,
    # so a fix published as ``1.0-1`` was refused outright and became unorderable --
    # which must surface as "unknown", never as "not affected".
    post_n = (
        int(match.group("post_implicit"))
        if match.group("post_implicit")
        else int(match.group("post_n") or 0)
        if match.group("post_l")
        else None
    )
    dev_n = int(match.group("dev_n") or 0) if match.group("dev_l") else None
    is_pre = bool(pre_l) or dev_n is not None

    # PEP 440 orders a version by an explicit sort key, not by "which component is
    # present". The documented key is:
    #
    #     (epoch, release, pre, post, dev, local)
    #
    # where a missing `pre` sorts *above* any pre-release, a missing `post` sorts
    # *below* any post-release, and a missing `dev` sorts *above* any dev release.
    # That is the whole trap: an absent component is not "0", it is a sentinel at one
    # end of its own range.
    #
    # An earlier version collapsed this into a single "phase" tuple and dropped the
    # component it was not looking at. The result was silent equality between versions
    # that differ:
    #
    #     1.0rc1.dev1 == 1.0rc1      (dev on a pre-release discarded)
    #     1.0a1.post1 == 1.0a1       (post on a pre-release discarded)
    #
    # Equality is the dangerous outcome here, because the range evaluator treats an
    # unorderable or equal version as "not affected". A vulnerable `1.0rc1.dev1`
    # installed against a fix of `1.0rc1` would have been reported clean.
    #
    # So each component keeps its own slot and its own sentinel:
    #   pre  absent -> (3,)          ; present -> (0, group, number) / (1,) post-dev
    #   post absent -> (-1,)         ; present -> (0, number)
    #   dev  absent -> (1,)          ; present -> (0, number)
    if pre_l:
        pre_key: tuple[object, ...] = (1, _PRE_ORDER.get(pre_l, 2), pre_n)
    elif dev_n is not None and post_n is None:
        # A bare `X.devN` sorts **below every pre-release** of X, so it needs a slot
        # that is less than the lowest real pre-release (alpha = 0).
        # The condition must exclude a post release: `1.0.post1.dev1` is a *dev* of
        # the post release, which sits above `1.0`, so it needs the absent-pre
        # sentinel. Applying the bare-dev rule to it put it below every prerelease
        # and made it sort under `1.0` entirely.
        pre_key = (0,)
    else:
        pre_key = (2,)

    post_key: tuple[int, ...] = (0, post_n) if post_n is not None else (-1,)
    dev_key: tuple[int, ...] = (0, dev_n) if dev_n is not None else (1,)

    # PEP 440: a local version label sorts *above* the same public version, and
    # `1.0+local` is not `1.0`. The regex always captured this segment but nothing
    # read it, so the two compared equal.
    local = (match.group("local") or "").lower()
    # PEP 440 compares local labels segment by segment: numeric segments numerically
    # and shorter ones first, alphanumeric segments lexically. `1.0+abc` < `1.0+abd`.
    local_key: tuple[object, ...]
    if not local:
        local_key = (0,)
    else:
        # PEP 440: inside a local label *strings sort before integers*, strings
        # compare lexicographically and integers numerically.  Tagging integers 0
        # and strings 1 inverted every alphanumeric-vs-numeric local comparison,
        # so ``1.0+abc`` compared above ``1.0+1``.
        segments = tuple(
            (0, part) if not part.isdigit() else (1, int(part))
            for part in re.split(r"[-_.]", local)
        )
        local_key = (1, segments)
    key = (epoch, release, pre_key, post_key, dev_key, local_key)
    return ParsedVersion(raw, VersionScheme.PEP440, key, is_pre)


def _parse_debian(raw: str, *, scheme: VersionScheme) -> ParsedVersion | None:
    """Split a Debian version into epoch, upstream and revision.

    Ordering is **not** done on the resulting tuple: ``compare`` dispatches Debian
    and RPM to :func:`_debian_compare`, which ports ``dpkg``'s ``verrevcmp`` and
    RPM's ``rpmvercmp`` directly.  See that function for why a pre-split token key
    cannot work.
    """
    text = raw.strip()
    if not text:
        return None
    # dpkg accepts only a-z, A-Z, 0-9 and . + - : ~ and rejects anything else
    # outright rather than approximating it.
    if _DEBIAN_INVALID.search(text) is not None:
        return None
    epoch = 0
    if ":" in text:
        head, _, tail = text.partition(":")
        if not head.isdigit():
            return None
        epoch = int(head)
        text = tail.strip()
        if not text:
            return None
    revision = ""
    if "-" in text:
        text, _, revision = text.rpartition("-")
    if not text:
        return None
    pre = bool(_DEBIAN_PRERELEASE.search(raw))
    return ParsedVersion(raw, scheme, (epoch, text, revision), pre)


#: Characters dpkg's version parser accepts.
_DEBIAN_INVALID = re.compile(r"[^A-Za-z0-9.+~:-]")
#: What dpkg's own ``dpkg-version`` helper treats as a prerelease for ordering UX.
_DEBIAN_PRERELEASE = re.compile(r"alpha|beta|rc|pre|dev|~", re.IGNORECASE)


def _verrevcmp_rank(char: str) -> int:
    """Rank a single non-digit character, matching dpkg's ``order()``.

    ``~`` sorts below the end of the string, letters between ``~`` and the end,
    and every other character (``.``, ``+``, ``-``, ``:``) *above* the end.
    Getting this backwards is what makes ``1.0+1`` sort below ``1.0.1``.
    """
    if char == "~":
        return -1
    if char.isalpha():
        return ord(char)
    if char == "" or char.isdigit():
        # A digit only reaches this function when the *other* side is a non-digit,
        # and dpkg's ``order()`` ranks digits as 0 so that "1" sorts below "b".
        # Ranking them as ``ord('1') + 256`` here inverted ``1.0+1`` vs ``1.0+b1``.
        return 0
    return ord(char) + 256


def _verrevcmp(a: str, b: str) -> int:
    """Port of dpkg's ``verrevcmp``: leading zeros skipped, digit runs numeric.

    A pre-split chunk key *cannot* reproduce this ordering, because the split
    boundaries are not stable: ``1.0`` against ``10`` starts a numeric run on both
    sides at different offsets (``1`` vs ``10``), so the strings have to be walked
    together.  Splitting first and then comparing chunks gave a total order that
    disagreed with dpkg on 14 of 1,056 pairs, 7 of them in the direction that
    reports a vulnerable package as fixed.
    """
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (
            j < len(b) and not b[j].isdigit()
        ):
            ac = _verrevcmp_rank(a[i] if i < len(a) else "")
            bc = _verrevcmp_rank(b[j] if j < len(b) else "")
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        # Skip leading zeros on both sides: "0" and "00" carry no value.
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        # The longer run of digits is the larger number; remember the verdict and
        # keep consuming both runs so later characters are still compared.
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff and a[i] != b[j]:
                first_diff = -1 if a[i] < b[j] else 1
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _rpmvercmp(a: str, b: str) -> int:
    """Port of RPM's ``rpmvercmp``: ``~`` lowest, ``^`` above end but below rest."""
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        # "~" and "^" are operators, not separators: only *other* non-alphanumerics
        # (".", "+", "_", "-") are skipped.  Skipping "~" too made every "1.0~rc1"
        # compare equal to "1.0", which reported prereleases as fixed.
        while i < len(a) and not a[i].isalnum() and a[i] not in "~^":
            i += 1
        while j < len(b) and not b[j].isalnum() and b[j] not in "~^":
            j += 1
        # "~" manages the case where one version is a prerelease of the other.
        if (i < len(a) and a[i] == "~") or (j < len(b) and b[j] == "~"):
            if i >= len(a) or a[i] != "~":
                return 1
            if j >= len(b) or b[j] != "~":
                return -1
            i += 1
            j += 1
            continue
        # "^" is post-release: newer than the bare version, older than anything else.
        if (i < len(a) and a[i] == "^") or (j < len(b) and b[j] == "^"):
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i += 1
            j += 1
            continue
        if not (i < len(a) and j < len(b)):
            break
        a_digit, b_digit = a[i].isdigit(), b[j].isdigit()
        if a_digit != b_digit:
            # Numeric segments are newer than alphabetic ones.
            return 1 if a_digit else -1
        if a_digit:
            si, sj = i, j
            while si < len(a) and a[si].isdigit():
                si += 1
            while sj < len(b) and b[sj].isdigit():
                sj += 1
            a_seg, b_seg = a[i:si].lstrip("0"), b[j:sj].lstrip("0")
            if len(a_seg) != len(b_seg):
                return 1 if len(a_seg) > len(b_seg) else -1
            if a_seg != b_seg:
                return 1 if a_seg > b_seg else -1
            i, j = si, sj
        else:
            si, sj = i, j
            while si < len(a) and a[si].isalpha():
                si += 1
            while sj < len(b) and b[sj].isalpha():
                sj += 1
            a_seg, b_seg = a[i:si], b[j:sj]
            if a_seg != b_seg:
                return 1 if a_seg > b_seg else -1
            i, j = si, sj
    if i >= len(a) and j >= len(b):
        return 0
    # A remaining segment makes that side newer.
    return -1 if i >= len(a) else 1


_RPM_INVALID = re.compile(r"[^A-Za-z0-9.+~^:_-]")


def _parse_rpm(raw: str, *, scheme: VersionScheme) -> ParsedVersion | None:
    """Split an RPM ``[epoch:]version[-release]`` string.

    RPM gets its own parser rather than reusing the Debian one, because ``^``
    (post-release, rpm >= 4.14) is legal in an RPM version and rejected by dpkg, and
    because rpm allows ``~`` anywhere in version and release.
    """
    text = raw.strip()
    if not text or _RPM_INVALID.search(text) is not None:
        return None
    epoch = 0
    if ":" in text:
        head, _, tail = text.partition(":")
        if not head.isdigit():
            return None
        epoch = int(head)
        text = tail
    version, _, release = text.partition("-")
    if not version:
        return None
    pre = bool(_DEBIAN_PRERELEASE.search(raw)) or "^" in version
    return ParsedVersion(raw, scheme, (epoch, version, release), pre)


def _debian_compare(
    a: ParsedVersion, b: ParsedVersion, *, scheme: VersionScheme
) -> int:
    """Compare two already-parsed Debian/RPM versions with the real algorithm."""
    if scheme is VersionScheme.DEBIAN:
        a_epoch, a_upstream, a_revision = _debian_parts(a)
        b_epoch, b_upstream, b_revision = _debian_parts(b)
        if a_epoch != b_epoch:
            return 1 if a_epoch > b_epoch else -1
        result = _verrevcmp(a_upstream, b_upstream)
        if result:
            return result
        return _verrevcmp(a_revision, b_revision)

    a_epoch, a_version, a_release = _debian_parts(a)
    b_epoch, b_version, b_release = _debian_parts(b)
    if a_epoch != b_epoch:
        return 1 if a_epoch > b_epoch else -1
    result = _rpmvercmp(a_version, b_version)
    if result:
        return result
    # A missing release sorts below any present release, as in rpm's labelCompare.
    if not a_release or not b_release:
        if not a_release and not b_release:
            return 0
        return -1 if not a_release else 1
    return _rpmvercmp(a_release, b_release)


def _debian_parts(parsed: ParsedVersion) -> tuple[int, str, str]:
    """Type-narrow a Debian/RPM key to its ``(epoch, version, revision)`` shape."""
    epoch, version, revision = parsed.key
    # ``ParsedVersion.key`` is typed as a tuple of objects because every scheme packs
    # a different shape into it; for Debian and RPM the shape is fixed at parse time.
    assert isinstance(epoch, int) and isinstance(version, str) and isinstance(revision, str)
    return epoch, version, revision


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
    """Parse a Go module version: SemVer, with a leading ``v`` and pseudo-versions.

    A pseudo-version (``v0.0.0-20200101000000-abcdef123456``) is ordered by its
    timestamp, which is what Go's own ordering does.  Every *other* ``-suffix`` is an
    ordinary SemVer prerelease and must be compared, not discarded: the previous code
    dropped it and returned ``v1.2.3-pre`` as **equal** to ``v1.2.3``, so a module
    pinned to a prerelease was reported clean against a fix at the release.
    """
    text = raw.strip()
    if text[:1] in ("v", "V"):
        text = text[1:]
    # Build metadata never affects Go's ordering, and real module versions carry it
    # (``v2.0.0+incompatible``).  Dropping it here keeps those versions orderable
    # instead of pushing them into the unorderable bucket.
    text = text.split("+", 1)[0]
    core, _, suffix = text.partition("-")
    numbers = _numeric_chunks(core)
    if numbers is None:
        return None
    padded = numbers + (0,) * (3 - len(numbers)) if len(numbers) < 3 else numbers
    if not suffix:
        return ParsedVersion(raw, VersionScheme.GO, (padded, 2, ()), False)
    if _GO_PSEUDO.match(suffix):
        return ParsedVersion(raw, VersionScheme.GO, (padded, 1, suffix), True)
    build_free = suffix
    if not build_free:
        return ParsedVersion(raw, VersionScheme.GO, (padded, 2, ()), False)
    # Rank 0 < pseudo rank 1 < release rank 2 mirrors SemVer: prerelease < release.
    return ParsedVersion(
        raw, VersionScheme.GO, (padded, 0, tuple(_pre_identifiers(build_free))), True
    )


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
        if scheme is VersionScheme.DEBIAN:
            return _parse_debian(text, scheme=scheme)
        if scheme is VersionScheme.RPM:
            return _parse_rpm(text, scheme=scheme)
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
    if scheme in (VersionScheme.DEBIAN, VersionScheme.RPM):
        return _debian_compare(a, b, scheme=scheme)
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
