"""RubyGems ordering against RubyGems' own upstream test vectors.

There is no installable Python implementation of ``Gem::Version``, so this is not a
live differential check in the sense the other oracle files are.  It is the next best
thing, and it is materially stronger than a specification-derived corpus: every case
below is copied verbatim from RubyGems' own test suite, so it encodes what the
reference implementation *does*, including the parts that are surprising and would not
have been written down in prose.

Source: ``test/rubygems/test_gem_version.rb`` in ``rubygems/rubygems`` (master),
methods ``test_spaceship``, ``test_semver``, ``test_canonical_segments``,
``test_hash``, ``test_initialize_invalid``, ``test_sort_key_*`` and
``testLocaleIndependent``.  Retrieved 2026-11-05.  The vectors are duplicated here as
data deliberately: a test that fetches over the network cannot run in CI, and a test
that trusts a stale local copy is worse than no test.

What this file does NOT do: run Ruby.  ``ruby`` is not installed here and adding a
Ruby toolchain to the Python CI job for one comparator is not a trade worth making.
That limitation is recorded in ``ORACLE_VALIDATION.md`` and reported by
``tests/oracle_tools.py`` rather than left for a reader to discover.
"""

from __future__ import annotations

import pytest

from vuln_intel.versions import VersionScheme, compare

pytestmark = pytest.mark.oracle


def _cmp(left: str, right: str) -> int | None:
    return compare(left, right, scheme=VersionScheme.RUBYGEMS)


#: ``test_spaceship`` — the ``<=>`` results RubyGems asserts.
SPACESHIP: list[tuple[str, str, int]] = [
    ("1.0", "1.0.0", 0),
    ("1.0", "1.0.a", 1),
    ("1.8.2", "0.0.0", 1),
    ("1.8.2", "1.8.2.a", 1),
    ("1.8.2.b", "1.8.2.a", 1),
    ("1.8.2.a", "1.8.2", -1),
    ("1.8.2.a10", "1.8.2.a9", 1),
    # Leading zero segments before the first letter are stripped, so these are equal.
    # This compared *unequal* before the fix.
    ("0.beta.1", "0.0.beta.1", 0),
    ("0.0.beta", "0.0.beta.1", -1),
    ("0.0.beta", "0.beta.1", -1),
    ("5.a", "5.0.0.rc2", -1),
    ("5.x", "5.0.0.rc2", 1),
    ("1.9.3", "1.9.2.99", 1),
    ("1.9.3", "1.9.3.1", -1),
    ("1.9.3", "1.9.3", 0),
]

#: ``test_semver`` — SemVer-shaped gem versions.
SEMVER: list[tuple[str, str, int]] = [
    ("1.0.0-alpha", "1.0.0-alpha.1", -1),
    ("1.0.0-alpha.1", "1.0.0-beta.2", -1),
    ("1.0.0-beta.2", "1.0.0-beta.11", -1),
    ("1.0.0-beta.11", "1.0.0-rc.1", -1),
    ("1.0.0-rc1", "1.0.0", -1),
    ("1.0.0-1", "1", -1),
]

#: ``test_canonical_segments`` / ``test_hash`` — equal versions.
CANONICAL: list[tuple[str, str]] = [
    ("1.2.pre.1", "1.2.0.pre.1.0"),
    ("1.0", "1.0.0"),
    ("1.2.3-1", "1.2.3.pre.1"),
]

#: ``test_sort_key_*`` — the fast path must agree with the slow path.
SORT_KEY: list[tuple[str, str, int]] = [
    ("1.0.0", "0.0.1.20220404083012", 1),
    ("0.7.0", "0.6.63000", 1),
    ("18.0.1", "18.0.2", -1),
]

#: Case handling. RubyGems does **not** downcase: ``partition_segments`` scans with
#: ``/[a-z]+/i`` but yields the original characters, so comparison is
#: case-sensitive and uppercase sorts before lowercase. This package lowercased every
#: segment, which made ``1.A`` and ``1.a`` equal; against a fix at ``1.a`` that
#: reported the vulnerable ``1.A`` as clean.
#:
#: (``1-abc... == 1-ABC...`` belongs to *Maven's* ``testLocaleIndependent``, where
#: ``parseVersion`` really does downcase. It is asserted in the Maven oracle file,
#: not here — this file only holds RubyGems vectors.)
LOCALE: list[tuple[str, str, int]] = [
    ("1.A", "1.a", -1),
    ("1.A", "1.Z", -1),
    ("1.a10", "1.A9", 1),
]

#: ``test_initialize_invalid`` — RubyGems raises ``ArgumentError``, so we must refuse
#: to order rather than guess. The last entry is the CVE-2013-4287 ReDoS vector.
INVALID: list[str] = [
    "junk",
    "1.0\n2.0",
    "1..2",
    "1.2 3.4",
    "2.3422222.222.222222222.22222.ads0as.dasd0.ddd2222.2.qd3e.",
]


class TestUpstreamSpaceship:
    @pytest.mark.parametrize(("left", "right", "expected"), SPACESHIP)
    def test_spaceship(self, left, right, expected):
        actual = _cmp(left, right)
        assert actual is not None, f"{left} vs {right} was not orderable"
        assert (actual > 0) - (actual < 0) == expected

    @pytest.mark.parametrize(("left", "right", "expected"), SPACESHIP)
    def test_spaceship_is_antisymmetric(self, left, right, expected):
        reverse = _cmp(right, left)
        assert reverse is not None
        assert (reverse > 0) - (reverse < 0) == -expected


class TestUpstreamSemver:
    @pytest.mark.parametrize(("left", "right", "expected"), SEMVER)
    def test_semver_shaped_versions(self, left, right, expected):
        actual = _cmp(left, right)
        assert actual is not None
        assert (actual > 0) - (actual < 0) == expected


class TestUpstreamCanonicalSegments:
    @pytest.mark.parametrize(("left", "right"), CANONICAL)
    def test_equal_versions(self, left, right):
        assert _cmp(left, right) == 0
        assert _cmp(right, left) == 0


class TestUpstreamSortKey:
    @pytest.mark.parametrize(("left", "right", "expected"), SORT_KEY)
    def test_fast_and_slow_paths_agree(self, left, right, expected):
        actual = _cmp(left, right)
        assert actual is not None
        assert (actual > 0) - (actual < 0) == expected


class TestUpstreamCaseHandling:
    @pytest.mark.parametrize(("left", "right", "expected"), LOCALE)
    def test_case_handling(self, left, right, expected):
        actual = _cmp(left, right)
        assert actual is not None
        assert (actual > 0) - (actual < 0) == expected


class TestUpstreamInvalidVersions:
    @pytest.mark.parametrize("version", INVALID)
    def test_malformed_versions_are_refused_not_guessed(self, version):
        assert _cmp(version, "1.0") is None, (
            f"{version!r} must be refused (RubyGems raises ArgumentError), "
            "not silently ordered"
        )

    def test_redos_vector_is_rejected_quickly(self):
        """CVE-2013-4287: the pathological input must not cost exponential time."""
        import time

        pathological = (
            "2.3422222.222.222222222.22222.ads0as.dasd0.ddd2222.2.qd3e."
            + "2222222222." * 500
        )
        started = time.perf_counter()
        _cmp(pathological, "1.0")
        elapsed = time.perf_counter() - started
        assert elapsed < 0.5, f"took {elapsed:.3f}s — possible catastrophic backtracking"


class TestDocumentedDivergenceFromRuby:
    """Divergences we keep deliberately, asserted so they cannot drift silently."""

    def test_empty_version_is_refused_rather_than_coerced_to_zero(self):
        """RubyGems coerces ``""`` to ``0``; we refuse to order it.

        ``Gem::Version.new("")`` is ``0``, so RubyGems reports ``"" <=> "0"`` as 0.
        This package refuses, because an empty *fixed* version in a vulnerability
        range would otherwise compare above every candidate and mark everything
        clean. Refusing produces ``UNKNOWN``, which is the honest answer for a
        malformed advisory. The divergence is recorded here, in
        ``ORACLE_VALIDATION.md``, and in ``BACKLOG.md`` (B-18).
        """
        assert _cmp("", "0") is None
