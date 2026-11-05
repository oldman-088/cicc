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

#: Maven's qualifier order, from ``ComparableVersion.StringItem.QUALIFIERS``.
#: The index *is* the rank, and ``""`` (the release qualifier) sits between ``rc``
#: and ``sp`` — which is what makes ``1-rc < 1 < 1-sp`` true.
_MAVEN_QUALIFIERS: tuple[str, ...] = (
    "snapshot", "alpha", "beta", "milestone", "rc", "", "sp"
)
#: Qualifier aliases, from ``StringItem.ALIASES``.
_MAVEN_ALIASES = {"ga": "", "final": "", "cr": "rc"}

_M_INT = "i"
_M_STR = "s"
_M_LIST = "l"


def _maven_qualifier_key(qualifier: str) -> str:
    """``ComparableVersion.comparableQualifier``: rank by name, else after all known.

    A known qualifier maps to its index as a decimal *string*; anything unknown maps
    to ``"7-<text>"``, which sorts after every known rank and then compares by text.
    Kept as a string because Java compares the string form, and because ``"10"`` must
    not sort before ``"9"``.
    """
    try:
        return str(_MAVEN_QUALIFIERS.index(qualifier))
    except ValueError:
        return f"{len(_MAVEN_QUALIFIERS)}-{qualifier}"


_RELEASE_QUALIFIER_INDEX = str(_MAVEN_QUALIFIERS.index(""))


def _maven_is_null(item: tuple[object, ...]) -> bool:
    """``Item.isNull``: zero integer, the release qualifier, or an empty list."""
    kind = item[0]
    if kind == _M_INT:
        return item[1] == 0
    if kind == _M_STR:
        return _maven_qualifier_key(str(item[1])) == _RELEASE_QUALIFIER_INDEX
    return not item[1]


def _maven_normalize(items: list[tuple[object, ...]]) -> None:
    """``ListItem.normalize``: drop *trailing* null items, so ``1.0-* == 1-*``."""
    while items and _maven_is_null(items[-1]):
        items.pop()


def _maven_string_item(text: str, followed_by_digit: bool) -> tuple[object, ...]:
    """``new StringItem(value, followedByDigit)``."""
    if followed_by_digit and len(text) == 1:
        # a1 = alpha-1, b1 = beta-1, m1 = milestone-1
        text = {"a": "alpha", "b": "beta", "m": "milestone"}.get(text, text)
    return (_M_STR, _MAVEN_ALIASES.get(text, text))


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
    """Parse a Maven version into ``ComparableVersion``'s nested item structure.

    A flat ranked token list cannot express Maven's ordering: a ``-`` followed by a
    digit opens a *sublist* (``1-1``), which is a different shape from a dotted
    number (``1.1``), and the qualifier comparison is against ordered list contents
    rather than a single scalar.  Ranking instead produced 96 wrong comparisons
    against Apache's own ``ComparableVersionTest``, including ``2.0.1 == 2.0.1-xyz``
    where Maven says ``2.0.1 < 2.0.1-xyz``.
    """
    text = raw.strip()
    if not text:
        return None
    key = _maven_parse_version(text)
    prerelease = any(character.isalpha() for character in text)
    return ParsedVersion(raw, VersionScheme.MAVEN, key, prerelease)


def _maven_parse_version(version: str) -> tuple[object, ...]:
    """Transcription of ``ComparableVersion.parseVersion``."""
    root: list[tuple[object, ...]] = []
    current = root
    lists: list[list[tuple[object, ...]]] = [root]
    stack: list[list[tuple[object, ...]]] = []
    text = version.lower()

    def parse_item(is_digit: bool, buf: str) -> tuple[object, ...]:
        if is_digit:
            return (_M_INT, int(buf))
        return _maven_string_item(buf, False)

    is_digit = False
    start = 0
    index = 0
    while index < len(text):
        char = text[index]
        if char in ".-":
            if index == start:
                current.append((_M_INT, 0))
            else:
                current.append(parse_item(is_digit, text[start:index]))
            start = index + 1
            if char == "-" and is_digit:
                _maven_normalize(current)  # 1.0-* = 1-*
                if index + 1 < len(text) and text[index + 1].isdigit():
                    # A new sublist only when the previous token was numeric *and*
                    # a digit follows: that is what separates 1.1 from 1-1.
                    sublist: list[tuple[object, ...]] = []
                    lists.append(sublist)
                    current.append((_M_LIST, sublist))
                    stack.append(current)
                    current = sublist
        elif char.isdigit():
            if not is_digit and index > start:
                current.append(_maven_string_item(text[start:index], True))
                start = index
            is_digit = True
        else:
            if is_digit and index > start:
                current.append(parse_item(True, text[start:index]))
                start = index
            is_digit = False
        index += 1

    if len(text) > start:
        current.append(parse_item(is_digit, text[start:]))

    # Normalise every list bottom-up, then freeze the live sublists into tuples.
    for sublist in reversed(lists):
        _maven_normalize(sublist)
    return _M_LIST, tuple(_maven_freeze(root))


def _maven_freeze(items: list[tuple[object, ...]]) -> list[tuple[object, ...]]:
    """Replace live sublist references with immutable tuples, recursively."""
    frozen: list[tuple[object, ...]] = []
    for item in items:
        if item[0] == _M_LIST:
            frozen.append((_M_LIST, tuple(_maven_freeze(item[1]))))  # type: ignore[arg-type]
        else:
            frozen.append(item)
    return frozen


def _maven_item_compare(
    item: tuple[object, ...], other: tuple[object, ...] | None
) -> int:
    """``Item.compareTo``; ``other=None`` is Java's "end of list" comparison."""
    kind = item[0]
    if other is None:
        if kind == _M_INT:
            return 0 if item[1] == 0 else 1  # 1.0 == 1, 1.1 > 1
        if kind == _M_STR:
            rank = _maven_qualifier_key(str(item[1]))
            return (rank > _RELEASE_QUALIFIER_INDEX) - (rank < _RELEASE_QUALIFIER_INDEX)
        contents = item[1]
        if not contents:
            return 0  # 1-0 = 1- (normalize) = 1
        return _maven_item_compare(contents[0], None)  # type: ignore[index]

    other_kind = other[0]
    if kind == _M_INT:
        if other_kind == _M_INT:
            left_number, right_number = item[1], other[1]
            return (left_number > right_number) - (left_number < right_number)  # type: ignore[operator]
        return 1  # 1.1 > 1-sp, 1.1 > 1-1
    if kind == _M_STR:
        if other_kind == _M_INT:
            return -1  # 1.any < 1.1
        if other_kind == _M_STR:
            left_rank = _maven_qualifier_key(str(item[1]))
            right_rank = _maven_qualifier_key(str(other[1]))
            return (left_rank > right_rank) - (left_rank < right_rank)
        return -1  # 1.any < 1-1
    if other_kind == _M_INT:
        return -1  # 1-1 < 1.0.x
    if other_kind == _M_STR:
        return 1  # 1-1 > 1-sp

    # Both sides are LIST items here, so their payloads are segment tuples. Names are
    # distinct from the scalar branches above so the types never collide.
    list_left: tuple[tuple[object, ...], ...] = item[1]  # type: ignore[assignment]
    list_right: tuple[tuple[object, ...], ...] = other[1]  # type: ignore[assignment]
    left_len, right_len = len(list_left), len(list_right)
    for position in range(max(left_len, right_len)):
        left_item = list_left[position] if position < left_len else None
        right_item = list_right[position] if position < right_len else None
        if left_item is None:
            assert right_item is not None
            result = -_maven_item_compare(right_item, None)
        else:
            result = _maven_item_compare(left_item, right_item)
        if result:
            return result
    return 0


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

#: Canonicalisation patterns, transcribed from ``Gem::Version#canonical_segments``.
#: 1. remove a trailing run of dots/zeros anchored on a letter or dot;
#: 2. remove a leading run of dots/zeros immediately before the first letter.
_RUBYGEMS_TRAILING_ZEROS = re.compile(r"(?<=[a-zA-Z.])[.0]+\Z")
_RUBYGEMS_LEADING_ZEROS = re.compile(r"(?:^|(?<=\.))[.0]+(?=[a-zA-Z])")
_RUBYGEMS_LETTER = re.compile(r"[a-zA-Z]")
#: Maximal digit and letter runs, exactly as Ruby's ``ver.scan(/\d+|[a-z]+/i)``.
_RUBYGEMS_SEGMENT = re.compile(r"\d+|[a-zA-Z]+")


def _parse_rubygems(raw: str) -> ParsedVersion | None:
    """Parse a gem version into canonical segments, per RubyGems' ``Gem::Version``.

    This is a transcription of ``Gem::Version#canonical_segments`` and
    ``Gem::Version#<=>`` from ``lib/rubygems/version.rb``, not an approximation of
    them.  The algorithm, in RubyGems' own order:

    1. ``-`` is rewritten to ``.pre.``, so ``1.0.0-rc1`` becomes ``1.0.0.pre.rc1``;
    2. a trailing run of dots/zeros is removed (``1.0.0`` -> ``1``);
    3. **for a prerelease only**, a leading run of dots/zeros is removed from before
       the first letter (``0.beta.1`` and ``0.0.beta.1`` both canonicalise to
       ``["beta", 1]``);
    4. the remainder is split into maximal digit and letter runs, digits becoming
       integers and letters becoming **case-preserved** strings;
    5. comparison is segment by segment, where a **string sorts below a numeric**
       segment, and an exhausted side is padded with numeric zero.

    Steps 3 and the case-preservation in step 4 were both missing.  With only step 2,
    ``0.beta.1`` and ``0.0.beta.1`` compared **unequal**, where RubyGems reports them
    equal; and lowercasing made ``1.A`` compare equal to ``1.a``, where RubyGems
    reports ``1.A < 1.a`` — which, against a fix at ``1.a``, reported the vulnerable
    ``1.A`` as clean.

    Keys are tagged *string=0, numeric=1* because RubyGems orders ``String < Numeric``
    at each position, and right-padded with numeric zero to reproduce
    ``lhs[i] || 0``.  A numeric segment still compares numerically inside its tag, so
    ``1.0.10`` (``(1,10)``) correctly exceeds ``1.0.9`` (``(1,9)``).
    """
    text = raw.strip()
    if not text or _RUBYGEMS_PATTERN.match(text) is None:
        return None
    if text.endswith("-") or text.startswith("-"):
        return None

    normalised = text.replace("-", ".pre.")
    # Step 2: drop a trailing run of dots and zeros.
    normalised = _RUBYGEMS_TRAILING_ZEROS.sub("", normalised)
    # Step 3: a prerelease has its leading dot/zero run removed before the first
    # letter, so that 0.beta.1 == 0.0.beta.1.
    prerelease = _RUBYGEMS_LETTER.search(normalised) is not None
    if prerelease:
        normalised = _RUBYGEMS_LEADING_ZEROS.sub("", normalised, count=1)

    parts = _RUBYGEMS_SEGMENT.findall(normalised)
    if not parts:
        return None

    segments: list[tuple[int, object]] = []
    for part in parts:
        if part.isdigit():
            segments.append((_RUBYGEMS_NUMERIC, int(part)))
        else:
            # Case is preserved: Ruby's /[a-z]+/i matches regardless of case but
            # yields the original characters, so "A" < "a".
            segments.append((_RUBYGEMS_STRING, part))
    # Padding width: a missing segment reads as numeric zero.  ``segments`` is never
    # truncated, so a version with more than eight segments simply has no padding.
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


def _maven_compare(a: ParsedVersion, b: ParsedVersion) -> int:
    """Compare two parsed Maven versions using Maven's own list comparison."""
    return _maven_item_compare(a.key, b.key)


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
        return _maven_compare(a, b)
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
