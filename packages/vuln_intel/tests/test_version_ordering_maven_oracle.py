"""Maven ordering against Apache's own ``ComparableVersionTest`` vectors.

Maven has no installable Python reference implementation and no ``mvn``/``java`` in
this environment, so — as with RubyGems — these are the **upstream test vectors**,
copied verbatim from Apache's suite rather than derived from the specification. They
encode what ``ComparableVersion`` actually does, which is a stronger claim than a
spec-derived corpus but a weaker one than running the reference implementation. The
distinction matters and is recorded in ``ORACLE_VALIDATION.md``.

Source: ``ComparableVersionTest.java`` in ``apache/maven-artifact`` (the artifact moved
out of the ``apache/maven`` monorepo), retrieved 2026-11-05. Methods
``testVersionsQualifier``, ``testVersionsNumber``, ``testVersionsEqual``,
``testVersionComparing``, ``testLocaleIndependent``.

Apache's suite asserts *every* pair in an ordered array, not just adjacent ones, so the
two version arrays below are transcribed as chains and compared exhaustively.
"""

from __future__ import annotations

import itertools

import pytest

from vuln_intel.versions import VersionScheme, compare

pytestmark = pytest.mark.oracle


def _cmp(left: str, right: str) -> int | None:
    return compare(left, right, scheme=VersionScheme.MAVEN)


#: ``VERSIONS_QUALIFIER`` — strictly increasing, so every earlier element is less than
#: every later one (``checkVersionsOrder`` compares all i < j, not just neighbours).
VERSIONS_QUALIFIER: list[str] = [
    # Verbatim from ComparableVersionTest at maven-3.9.9, in the source's own order.
    # An earlier transcription here opened the list with "1-SNAPSHOT", which is not
    # where upstream puts it: snapshot ranks *after* rc and immediately before the
    # release. That transcription error matched a matching error in the comparator,
    # so 573 assertions agreed with each other and both were wrong. Corrected against
    # the upstream source; the JVM differential check is what found it.
    "1-alpha2snapshot", "1-alpha2", "1-alpha-123", "1-beta-2",
    "1-beta123", "1-m2", "1-m11", "1-rc", "1-cr2", "1-rc123", "1-SNAPSHOT",
    "1", "1-sp", "1-sp2",
    "1-sp123", "1-abc", "1-def", "1-pom-1", "1-1-snapshot", "1-1", "1-2", "1-123",
]

#: ``VERSIONS_NUMBER`` — strictly increasing, same all-pairs rule.
#:
#: Verbatim from ComparableVersionTest at maven-3.9.9. This list has now been wrong
#: twice, in two different directions, which is worth recording:
#:
#: 1. it previously read ``"2.0", "2-1", "2.0.a", "2.0.0.a", ...`` — the order of
#:    ``2.0.a`` and ``2-1`` was swapped, and ``"2.0.0.a"`` does not appear upstream at
#:    all. The comparator happened to agree with the wrong order, so all 55 tests
#:    passed while both were wrong.
#: 2. correcting the comparator's sublist and normalize rules then failed *this* list,
#:    because the list was the thing that was wrong.
#:
#: The lesson is the same one the SNAPSHOT defect taught: a hand-maintained corpus is
#: only independent of the implementation if it is re-read from upstream. It is now
#: copied character for character.
VERSIONS_NUMBER: list[str] = [
    "2.0", "2.0.a", "2-1", "2.0.2", "2.0.123", "2.1.0", "2.1-a", "2.1b",
    "2.1-c", "2.1-1", "2.1.0.1", "2.2", "2.123", "11.a2", "11.a11", "11.b2",
    "11.b11", "11.m2", "11.m11", "11", "11.a", "11b", "11c", "11m",
]

#: ``testVersionsEqual`` — ``checkVersionsEqual`` also asserts ``hashCode``/``equals``,
#: which for Maven means identical canonical forms. We assert order 0 both ways, which
#: is the property this package's comparator is responsible for.
VERSIONS_EQUAL: list[tuple[str, str]] = [
    ("1", "1"),
    ("1", "1.0"),
    ("1", "1.0.0"),
    ("1.0", "1.0.0"),
    ("1", "1-0"),
    ("1", "1.0-0"),
    ("1.0", "1.0-0"),
    ("1a", "1.a"),
    ("1a", "1-a"),
    ("1a", "1.0-a"),
    ("1a", "1.0.0-a"),
    ("1.0a", "1.0.a"),
    ("1.0.0a", "1.0.0.a"),
    # aliases
    ("1ga", "1"),
    ("1final", "1"),
    ("1cr", "1rc"),
    # special aliases a, b, m
    ("1a1", "1alpha1"),
    ("1b2", "1beta2"),
    ("1m3", "1milestone3"),
    # testLocaleIndependent: parseVersion lowercases with Locale.ENGLISH, so these are
    # equal regardless of the host locale. (RubyGems is the opposite: it preserves
    # case. See the RubyGems oracle file.)
    ("1-abcdefghijklmnopqrstuvwxyz", "1-ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
]

#: ``testVersionComparing`` — explicit ordered pairs.
VERSIONS_ORDER: list[tuple[str, str]] = [
    ("1", "2"),
    ("1.5", "2"),
    ("1", "2.5"),
    ("1.0", "1.1"),
    ("1.1", "1.2"),
    ("1.0.0", "1.1"),
    ("1.0.1", "1.1"),
    ("1.1", "1.2.0"),
    ("1.0-alpha-1", "1.0"),
    ("1.0-alpha-1", "1.0-alpha-2"),
    ("1.0-alpha-1", "1.0-beta-1"),
    # Upstream: checkVersionsOrder("1.0-beta-1", "1.0-SNAPSHOT"). Transcribed backwards
    # the first time, which is how a wrong qualifier order survived its own oracle.
    ("1.0-beta-1", "1.0-SNAPSHOT"),
    ("1.0-SNAPSHOT", "1.0"),
    # Direct qualifier-vs-snapshot pairs. The upstream suite expresses these only
    # through the VERSIONS_QUALIFIER chain, and that is precisely why a wrong snapshot
    # rank survived here: a chain can be mis-transcribed self-consistently, whereas an
    # explicit pair cannot.
    ("1-alpha", "1-snapshot"),
    ("1-beta", "1-snapshot"),
    ("1-milestone", "1-snapshot"),
    ("1-rc", "1-snapshot"),
    ("1", "1-sp"),
    ("1.0-alpha-1-SNAPSHOT", "1.0-alpha-1"),
    ("1.0", "1.0-1"),
    ("1.0-1", "1.0-2"),
    ("1.0.0", "1.0-1"),
    ("2.0-1", "2.0.1"),
    ("2.0.1-klm", "2.0.1-lmn"),
    ("2.0.1", "2.0.1-xyz"),
    ("2.0.1", "2.0.1-123"),
    ("2.0.1-xyz", "2.0.1-123"),
]


class TestUpstreamOrderedChains:
    """Apache asserts every pair in the array, so we do too."""

    @pytest.mark.parametrize(
        ("name", "chain"),
        [("qualifier", VERSIONS_QUALIFIER), ("number", VERSIONS_NUMBER)],
    )
    def test_every_later_version_is_greater(self, name, chain):
        failures = []
        for low_index, low in enumerate(chain):
            for high in chain[low_index + 1:]:
                forward = _cmp(low, high)
                backward = _cmp(high, low)
                if forward is None or forward >= 0:
                    failures.append(f"{low} < {high} expected, got {forward}")
                elif backward is None or backward <= 0:
                    failures.append(f"{high} > {low} expected, got {backward}")
        assert not failures, f"{name}: {len(failures)} wrong, first 5: {failures[:5]}"


class TestParserRulesTheVectorSuiteCannotReach:
    """Rules from ``ComparableVersion.parseVersion`` that no upstream vector covers.

    Every assertion here was established by differential evidence from the runtime
    oracle, not by reading the source and deciding what it "should" do. The source was
    read to find the *rule*; the runtime supplied the *answer*, and where the two
    disagreed the runtime won. That ordering matters and is the point of the class:

    * ``normalize()`` walks from the end and removes every null item, ``break``-ing
      only on a non-null scalar. A non-null sublist does not stop it, so trailing
      zeros in front of a sublist are stripped too.
    * every ``-`` opens a sublist, and so does a string run at the end of the input or
      a digit/letter transition. That is what makes the dotted form equivalent to the
      hyphenated one: ``1.0.0.a`` parses to the same shape as ``1.a``.

    Both rules were missing. Together they accounted for the last nine disagreements
    with Apache's implementation.
    """

    @pytest.mark.parametrize(
        ("left", "right"),
        [
            ("1.0.0.a", "1.a"),
            ("1.0.0.x", "1.x"),
            ("1.0.0.a", "1-a"),
            ("1.a", "1-a"),
            ("1.0a", "1.0.a"),
        ],
    )
    def test_dotted_and_hyphenated_qualifiers_are_the_same_shape(self, left, right):
        """`treat .X as -X for any string qualifier X` — from parseVersion's own comment."""
        assert _cmp(left, right) == 0, f"{left} should equal {right}"

    def test_a_dotted_qualifier_sort_strings_across_the_dot(self):
        """A sublist makes the qualifier a list, and a list sorts below a number."""
        assert _cmp("1.0.0.a", "1-1") == -1
        assert _cmp("1.0.0.x", "1-1") == -1

    def test_qualifiers_compare_lexically_inside_their_sublist(self):
        assert _cmp("5.0.0.rc2", "5.x") == -1
        assert _cmp("5.x", "5.0.0.rc2") == 1

    def test_trailing_zeros_before_a_sublist_are_normalised_away(self):
        """The rule ``normalize()`` implements that the old while-loop did not."""
        assert _cmp("1.0.0.a", "1.a") == 0
        assert _cmp("1.0.0.0.0.a", "1.a") == 0

    @pytest.mark.parametrize(
        ("left", "right", "expected"),
        [
            # Quoted from ComparableVersionTest@maven-3.9.9, checkVersionsEqual.
            ("1a", "1-a", 0),
            ("1a", "1.0-a", 0),
            ("1a", "1.0.0-a", 0),
            ("1x", "1-x", 0),
            ("1x", "1.0-x", 0),
            ("1x", "1.0.0-x", 0),
            ("1.0.0x", "1-x", 0),
            # ... and from checkVersionsOrder in the same file.
            ("2.0-1", "2.0.1", -1),
            ("2.0.1", "2.0.1-xyz", -1),
            ("2.0.1-xyz", "2.0.1-123", -1),
        ],
    )
    def test_upstream_pairs_whose_transcription_drifted(self, left, right, expected):
        assert _cmp(left, right) == expected


class TestUpstreamEquality:
    @pytest.mark.parametrize(("left", "right"), VERSIONS_EQUAL)
    def test_equal_both_ways(self, left, right):
        assert _cmp(left, right) == 0, f"{left} should equal {right}"
        assert _cmp(right, left) == 0, f"{right} should equal {left}"


class TestUpstreamExplicitOrder:
    @pytest.mark.parametrize(("left", "right"), VERSIONS_ORDER)
    def test_ordered_both_ways(self, left, right):
        forward = _cmp(left, right)
        backward = _cmp(right, left)
        assert forward is not None and forward < 0, f"{left} should be < {right}"
        assert backward is not None and backward > 0, f"{right} should be > {left}"


class TestMavenSpecificRules:
    """The rules that are easy to get wrong and are not obvious from the outside."""

    def test_unknown_qualifiers_sort_after_release(self):
        # ComparableVersion: unknown qualifier key is "7-<text>", above the "" rank.
        assert _cmp("1", "1-abc") == -1
        assert _cmp("1-sp", "1-abc") == -1

    def test_known_qualifier_order(self):
        # Upstream ComparableVersionTest: QUALIFIERS is
        # ["alpha","beta","milestone","rc","snapshot","","sp"], so snapshot is the last
        # pre-release before the release.
        chain = ["1-alpha", "1-beta", "1-milestone", "1-rc", "1-snapshot", "1", "1-sp"]
        for low, high in itertools.pairwise(chain):
            assert _cmp(low, high) == -1, f"{low} should be < {high}"

    def test_hyphen_before_digit_creates_a_sublist(self):
        # 1-1 is a sublist, which sorts below the dotted 1.1; Maven's own suite pins
        # 2.0-1 < 2.0.1 for exactly this reason.
        assert _cmp("2.0-1", "2.0.1") == -1
        assert _cmp("1-1", "1.1") == -1  # ListItem vs IntegerItem: 1.1 > 1-1

    def test_numeric_token_sorts_above_qualifier(self):
        assert _cmp("1-sp", "1-1") == -1  # 1-1 > 1-sp
        assert _cmp("1-abc", "1.1") == -1  # Integer sorts above String: 1.1 > 1-abc

    def test_trailing_nulls_are_normalised(self):
        # ListItem.normalize strips trailing nulls, so 1.0-* == 1-*
        assert _cmp("1.0.0", "1") == 0
        assert _cmp("1.0-0", "1") == 0

    def test_single_letter_alias_needs_a_following_digit(self):
        # StringItem(value, followedByDigit): "a1" -> alpha, but a bare "a" stays "a".
        assert _cmp("1a1", "1alpha1") == 0
        assert _cmp("1a", "1alpha") != 0
