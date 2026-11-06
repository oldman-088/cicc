"""Version ordering and affected-version evaluation.

These tests encode *decisions*, not just behaviour: the orderings below are the
ones that change whether an operator is told to patch.  Each case is a documented
rule from the relevant ecosystem specification.
"""

from __future__ import annotations

import pytest

from vuln_intel.affected import (
    ExclusionSide,
    Verdict,
    _range_from_package,
    assess_affected,
    normalize_ecosystem,
)
from vuln_intel.connectors.osv import _parse_affected
from vuln_intel.schema import AffectedPackage, CveId, NormalizedVulnerability, Origin
from vuln_intel.versions import (
    SCHEME_BY_ECOSYSTEM,
    VersionScheme,
    compare,
    parse,
    scheme_for_ecosystem,
)


class TestVersionOrdering:
    @pytest.mark.parametrize(
        ("left", "right", "scheme", "expected"),
        [
            # semver: numeric components, then pre-release before release
            ("1.0.0", "1.0.1", VersionScheme.SEMVER, -1),
            ("1.10.0", "1.9.0", VersionScheme.SEMVER, 1),
            ("1.0.0-rc.1", "1.0.0", VersionScheme.SEMVER, -1),
            ("1.0.0-alpha.1", "1.0.0-alpha.2", VersionScheme.SEMVER, -1),
            ("1.0.0-rc.2", "1.0.0-rc.10", VersionScheme.SEMVER, -1),
            ("2.0.1", "2.0.1+build.5", VersionScheme.SEMVER, 0),
            ("v1.2.3", "1.2.3", VersionScheme.SEMVER, 0),
            # pep440: dev < pre < release < post, epochs dominate
            ("1.2", "1.2.0", VersionScheme.PEP440, 0),
            ("1.0.dev1", "1.0a1", VersionScheme.PEP440, -1),
            ("1.0rc1", "1.0", VersionScheme.PEP440, -1),
            ("1.0.post1", "1.0", VersionScheme.PEP440, 1),
            ("1!1.0", "2.0", VersionScheme.PEP440, 1),
            ("1.0", "0.9", VersionScheme.PEP440, 1),
            # debian: epochs, then dpkg chunk ranking ("~" before end of string)
            ("1:1.0", "2.0", VersionScheme.DEBIAN, 1),
            ("1.0-1", "1.0-2", VersionScheme.DEBIAN, -1),
            ("1.0~rc1", "1.0", VersionScheme.DEBIAN, -1),
            ("1.0", "1.0.1", VersionScheme.DEBIAN, -1),
            ("2.30-1", "2.9-1", VersionScheme.DEBIAN, 1),
            # rpm uses the same chunking
            ("1.0~rc1", "1.0", VersionScheme.RPM, -1),
            # maven: qualifiers rank below the missing component, "sp" above
            ("1.0-alpha", "1.0", VersionScheme.MAVEN, -1),
            ("1.0-SNAPSHOT", "1.0", VersionScheme.MAVEN, -1),
            ("1.0", "1.0.0", VersionScheme.MAVEN, 0),
            ("1.0", "1.0.1", VersionScheme.MAVEN, -1),
            ("1.0-rc1", "1.0.1", VersionScheme.MAVEN, -1),
            ("1.0-sp1", "1.0", VersionScheme.MAVEN, 1),
            ("2.0", "1.9", VersionScheme.MAVEN, 1),
            # go: v-prefix, prereleases and pseudo-versions.
            # A pseudo-version is a *pre-release* of the tag it follows (see
            # go.dev/ref/mod: "Pre-release versions sort before the corresponding
            # release versions", and a pseudo-version is a pre-release "that encodes
            # a revision identifier"), so v0.0.0-... sorts BELOW v0.0.0.  This
            # assertion used to expect +1, which asserted that a commit carrying a
            # fix sorted above that same release tag -- it would have reported the
            # vulnerable pseudo-version as fixed.
            ("v1.2.3", "v1.2.4", VersionScheme.GO, -1),
            ("v0.0.0-20210101120000-abcdef123456", "v0.0.0", VersionScheme.GO, -1),
            ("v1.2.3-pre", "v1.2.3", VersionScheme.GO, -1),
            ("v1.2.3", "v2.0.0+incompatible", VersionScheme.GO, -1),
        ],
    )
    def test_ordering_rules(self, left, right, scheme, expected):
        assert compare(left, right, scheme) == expected

    def test_ordering_is_antisymmetric(self):
        pairs = [("1.0.0", "1.0.1", VersionScheme.SEMVER), ("1.0~rc1", "1.0", VersionScheme.DEBIAN)]
        for left, right, scheme in pairs:
            assert compare(left, right, scheme) == -compare(right, left, scheme)

    def test_unorderable_input_returns_none_not_an_exception(self):
        assert compare("not-a-version", "1.0.0", VersionScheme.SEMVER) is None
        assert compare(None, "1.0.0", VersionScheme.SEMVER) is None
        assert compare("", "1.0.0", VersionScheme.SEMVER) is None

    def test_opaque_scheme_refuses_to_order(self):
        # Composer is still mapped to OPAQUE: its ordering rules are not
        # documented well enough here to implement honestly, so guessing would be
        # wrong.  (RubyGems used to be in this position; it now has a real scheme.)
        assert scheme_for_ecosystem("composer") is VersionScheme.OPAQUE
        assert compare("1.0.0", "1.0.1", VersionScheme.OPAQUE) is None

    def test_rubygems_is_ordered(self):
        """RubyGems is no longer opaque; a gem version can be ordered exactly."""
        assert scheme_for_ecosystem("rubygems") is VersionScheme.RUBYGEMS
        assert compare("1.0.0.rc1", "1.0.0", VersionScheme.RUBYGEMS) == -1

    def test_cocoapods_shares_the_rubygems_algorithm(self):
        """CocoaPods vendors Gem::Version, so it is not a separate implementation."""
        assert scheme_for_ecosystem("cocoapods") is VersionScheme.RUBYGEMS

    def test_parse_does_not_raise_on_garbage(self):
        """Garbage must never raise; whether it is orderable is per-scheme.

        Maven is the surprise: ``ComparableVersion.parseVersion`` turns ``"!!!"`` into
        a single unknown qualifier, which is a *valid* Maven version that sorts above
        the release (unknown qualifiers rank after ``sp``). Java really does accept
        it, so refusing it here would be a divergence from Maven rather than a
        safety measure. dpkg rejects the same string because ``!`` is not in its
        accepted character set.
        """
        for scheme in VersionScheme:
            parse("!!!", scheme)  # must not raise, whatever the answer
        assert parse("!!!", VersionScheme.DEBIAN) is None
        assert parse("!!!", VersionScheme.MAVEN) is not None
        assert parse("", VersionScheme.MAVEN) is None

    def test_every_mapped_scheme_is_a_real_scheme(self):
        assert all(isinstance(s, VersionScheme) for s in SCHEME_BY_ECOSYSTEM.values())

    @pytest.mark.parametrize(
        ("alias", "canonical"),
        [("Python", "pypi"), ("Node.js", "npm"), ("Rust", "crates.io"), ("go", "go")],
    )
    def test_ecosystem_aliases(self, alias, canonical):
        assert normalize_ecosystem(alias) == canonical


def _advisory(affected_doc):
    return _parse_affected(affected_doc)


class TestAffectedEvaluation:
    def test_inside_range(self):
        packages = _advisory(
            [
                {
                    "package": {"ecosystem": "npm", "name": "lodash"},
                    "ranges": [
                        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}
                    ],
                }
            ]
        )
        result = assess_affected(packages, ecosystem="npm", name="lodash", version="4.17.20")
        assert result.verdict is Verdict.AFFECTED
        assert result.fixed_version == "4.17.21"
        assert "4.17.21" in result.remediation

    def test_at_fixed_version_is_not_affected(self):
        # `fixed` is exclusive in OSV: the fixed release itself is safe.
        packages = _advisory(
            [
                {
                    "package": {"ecosystem": "npm", "name": "lodash"},
                    "ranges": [
                        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}
                    ],
                }
            ]
        )
        result = assess_affected(packages, ecosystem="npm", name="lodash", version="4.17.21")
        assert result.verdict is Verdict.NOT_AFFECTED

    def test_reintroduced_range_is_detected(self):
        """A package fixed, reintroduced and fixed again has two windows.

        The previous parser kept only the first (introduced, fixed) pair, so
        5.0.1 was reported safe.  This is the regression guard for that defect.
        """
        packages = _advisory(
            [
                {
                    "package": {"ecosystem": "npm", "name": "lodash"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "4.17.21"},
                                {"introduced": "5.0.0"},
                                {"fixed": "5.0.2"},
                            ],
                        }
                    ],
                }
            ]
        )
        assert assess_affected(
            packages, ecosystem="npm", name="lodash", version="5.0.1"
        ).verdict is Verdict.AFFECTED
        assert assess_affected(
            packages, ecosystem="npm", name="lodash", version="5.0.2"
        ).verdict is Verdict.NOT_AFFECTED

    def test_last_affected_is_inclusive(self):
        packages = _advisory(
            [
                {
                    "package": {"ecosystem": "Debian", "name": "openssl"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "1.0.0"}, {"last_affected": "1.0.9"}],
                        }
                    ],
                }
            ]
        )
        assert assess_affected(
            packages, ecosystem="debian", name="openssl", version="1.0.9"
        ).verdict is Verdict.AFFECTED
        assert assess_affected(
            packages, ecosystem="debian", name="openssl", version="1.0.10"
        ).verdict is Verdict.NOT_AFFECTED

    def test_explicit_version_list_wins(self):
        packages = [
            AffectedPackage(ecosystem="npm", name="pkg", introduced="9.0.0", fixed="9.0.1",
                             versions=("1.0.0",))
        ]
        assert assess_affected(
            packages, ecosystem="npm", name="pkg", version="1.0.0"
        ).verdict is Verdict.AFFECTED

    def test_git_range_yields_unknown_not_safe(self):
        """Commit-SHA ranges cannot be compared to versions; must not read as safe."""
        packages = _advisory(
            [
                {
                    "package": {"ecosystem": "Go", "name": "x/y"},
                    "ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc123"}]}],
                }
            ]
        )
        result = assess_affected(packages, ecosystem="go", name="x/y", version="v1.0.0")
        assert result.verdict is Verdict.UNKNOWN
        assert "GIT" in " ".join(result.reasons)

    def test_unparseable_version_is_unknown(self):
        packages = [
            AffectedPackage(ecosystem="npm", name="pkg", introduced="0", fixed="1.0.0")
        ]
        result = assess_affected(
            packages, ecosystem="npm", name="pkg", version="not-a-version"
        )
        assert result.verdict is Verdict.UNKNOWN
        assert result.verdict is not Verdict.NOT_AFFECTED

    def test_package_not_covered_is_unknown(self):
        packages = [
            AffectedPackage(ecosystem="npm", name="other", introduced="0", fixed="1.0.0")
        ]
        assert assess_affected(
            packages, ecosystem="npm", name="pkg", version="0.5.0"
        ).verdict is Verdict.UNKNOWN

    def test_missing_inputs_are_unknown(self):
        packages = [AffectedPackage(ecosystem="npm", name="pkg", introduced="0", fixed="1.0")]
        assert assess_affected(packages, ecosystem=None, name="pkg", version="0.1").verdict is Verdict.UNKNOWN
        assert assess_affected(packages, ecosystem="npm", name=None, version="0.1").verdict is Verdict.UNKNOWN
        assert assess_affected(packages, ecosystem="npm", name="pkg", version=None).verdict is Verdict.UNKNOWN

    def test_ecosystem_matching_is_case_insensitive(self):
        packages = [
            AffectedPackage(ecosystem="PyPI", name="Django", introduced="0", fixed="4.2.0")
        ]
        assert assess_affected(
            packages, ecosystem="python", name="django", version="4.1.0"
        ).verdict is Verdict.AFFECTED

    def test_name_normalization_matches_pypi_underscores(self):
        packages = [
            AffectedPackage(ecosystem="PyPI", name="some_package", introduced="0", fixed="2.0")
        ]
        assert assess_affected(
            packages, ecosystem="pypi", name="some-package", version="1.0"
        ).verdict is Verdict.AFFECTED

    def test_no_fixed_version_gives_mitigation_advice(self):
        packages = [
            AffectedPackage(ecosystem="npm", name="pkg", introduced="0", fixed=None)
        ]
        result = assess_affected(packages, ecosystem="npm", name="pkg", version="9.9.9")
        assert result.verdict is Verdict.AFFECTED
        assert "mitigations" in (result.remediation or "")

    def test_assessment_serializes_with_reasoning(self):
        packages = [AffectedPackage(ecosystem="npm", name="pkg", introduced="0", fixed="1.0")]
        payload = assess_affected(
            packages, ecosystem="npm", name="pkg", version="0.5"
        ).as_dict()
        assert payload["verdict"] == "affected"
        assert payload["reasons"]
        assert payload["remediation"].startswith("upgrade")

    def test_unknown_verdict_has_no_remediation(self):
        result = assess_affected([], ecosystem="npm", name="pkg", version="1.0")
        assert result.remediation is None


class TestWatchlistAndExposure:
    """Exposure analysis: which of *our* packages an advisory actually hits."""

    def test_affected_dependency_is_reported_with_its_asset(self):
        from vuln_intel.watchlist import Dependency, Inventory, analyse_exposure

        inventory = Inventory(
            dependencies=(
                Dependency(ecosystem="npm", name="lodash", version="4.17.20", asset="web"),
                Dependency(ecosystem="npm", name="lodash", version="4.17.21", asset="api"),
            )
        )
        advisory = NormalizedVulnerability(
            cve=CveId.parse("CVE-2019-10744"),
            origin=Origin.LIVE,
            affected=(
                AffectedPackage(
                    ecosystem="npm", name="lodash", range_type="SEMVER",
                    introduced="0", fixed="4.17.21",
                ),
            ),
            sources=("osv",),
        )
        report = analyse_exposure(inventory, [advisory])
        assert len(report.affected) == 1
        assert report.affected[0].dependency.asset == "web"
        assert report.assets_at_risk == ("web",)
        assert report.clean is False

    def test_clean_inventory_with_no_advisories(self):
        from vuln_intel.watchlist import Inventory, analyse_exposure

        report = analyse_exposure(Inventory(), [])
        assert report.clean is True
        assert report.advisories_considered == 0

    def test_advisory_without_affected_data_is_unexplorable_not_clean(self):
        from vuln_intel.watchlist import Inventory, analyse_exposure

        advisory = NormalizedVulnerability(
            cve=CveId.parse("CVE-2024-1000"), origin=Origin.LIVE, affected=(), sources=("nvd",)
        )
        report = analyse_exposure(Inventory(), [advisory])
        assert report.unexplorable == ("CVE-2024-1000",)
        # Nothing is known to be affected, and that is stated explicitly.
        assert report.as_dict()["unexplorable"] == ["CVE-2024-1000"]

    def test_unorderable_version_is_unverified_not_silently_dropped(self):
        from vuln_intel.watchlist import Dependency, Inventory, analyse_exposure

        inventory = Inventory(
            dependencies=(Dependency(ecosystem="npm", name="pkg", version="not-a-version"),)
        )
        advisory = NormalizedVulnerability(
            cve=CveId.parse("CVE-2024-1001"),
            origin=Origin.LIVE,
            affected=(AffectedPackage(ecosystem="npm", name="pkg", introduced="0", fixed="1.0"),),
            sources=("osv",),
        )
        report = analyse_exposure(inventory, [advisory])
        assert report.affected == ()
        assert len(report.unverified) == 1
        assert report.clean is False

    def test_package_name_normalisation(self):
        from vuln_intel.watchlist import Dependency, Inventory, analyse_exposure

        inventory = Inventory(
            dependencies=(Dependency(ecosystem="PyPI", name="some_package", version="1.0"),)
        )
        advisory = NormalizedVulnerability(
            cve=CveId.parse("CVE-2024-1002"),
            origin=Origin.LIVE,
            affected=(
                AffectedPackage(ecosystem="pypi", name="some-package", introduced="0", fixed="2.0"),
            ),
            sources=("osv",),
        )
        assert len(analyse_exposure(inventory, [advisory]).affected) == 1

    def test_purl_parsing(self):
        from vuln_intel.watchlist import dependency_from_purl

        dep = dependency_from_purl("pkg:npm/lodash@4.17.20", asset="web")
        assert dep is not None
        assert (dep.ecosystem, dep.name, dep.version, dep.asset) == (
            "npm", "lodash", "4.17.20", "web",
        )

    def test_malformed_purl_returns_none(self):
        from vuln_intel.watchlist import dependency_from_purl

        assert dependency_from_purl("lodash@1.0") is None
        assert dependency_from_purl("pkg:npm/lodash") is None
        assert dependency_from_purl("") is None

    def test_watchlist_builds_deduplicated_osv_queries(self):
        from vuln_intel.watchlist import Dependency, Inventory, Watchlist

        inventory = Inventory(
            dependencies=(
                Dependency(ecosystem="npm", name="lodash", version="4.17.20"),
                Dependency(ecosystem="npm", name="lodash", version="4.17.20"),
                Dependency(ecosystem="npm", name="lodash", version="4.17.21"),
            )
        )
        watchlist = Watchlist()
        watchlist.add_inventory(inventory)
        queries = watchlist.as_osv_queries(inventory)
        assert len(queries) == 2
        assert len(watchlist) == 1
        assert watchlist.covers("node", "Lodash")

    def test_empty_dependency_is_rejected(self):
        from vuln_intel.watchlist import Dependency

        with pytest.raises(ValueError):
            Dependency(ecosystem="npm", name="  ", version="1.0")


class TestRangeLimitEvent:
    """OSV ``limit`` bounds the range *document*, it does not assert a fix.

    The risk in both directions is real: folding it into ``fixed`` publishes a
    remedy version no source claimed, while ignoring it loses a documented upper
    bound.  The chosen behaviour is to record it and never interpret it as a fix.
    """

    ENTRY = {
        "package": {"ecosystem": "npm", "name": "left-pad"},
        "ranges": [
            {"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"limit": "2.0.0"}]}
        ],
    }

    def packages(self):
        return _parse_affected([self.ENTRY])

    def test_limit_is_preserved_in_the_event_list(self) -> None:
        assert ("limit", "2.0.0") in {
            (kind, value) for _, kind, value in self.packages()[0].events
        }

    def test_limit_is_exposed_on_the_version_range(self) -> None:
        limit = _range_from_package(self.packages()[0])[0].limit
        assert limit == "2.0.0"

    def test_limit_does_not_become_a_fixed_boundary(self) -> None:
        (package,) = self.packages()
        assert package.fixed is None

    def test_version_below_limit_is_affected(self) -> None:
        result = assess_affected(
            self.packages(), ecosystem="npm", name="left-pad", version="1.5.0"
        )
        assert result.verdict is Verdict.AFFECTED

    def test_version_above_limit_is_still_affected(self) -> None:
        """Cautious direction: an unbounded interval over-reports, never under-reports."""
        result = assess_affected(
            self.packages(), ecosystem="npm", name="left-pad", version="2.5.0"
        )
        assert result.verdict is Verdict.AFFECTED, (
            "the range document ends at 2.0.0, but that is not evidence the "
            "vulnerability is fixed there"
        )


class TestRubyGemsOrdering:
    """RubyGems' ``Gem::Version`` ordering, reproduced from its documentation.

    This mattered as a correctness gap, not a nicety: while ``rubygems`` was
    OPAQUE every affected-version question about a gem returned ``UNKNOWN``, which
    is honest but useless.  The rules are unusual enough that guessing would have
    produced confident wrong answers — ``1.0.0.rc1`` sorts *below* ``1.0.0``, and a
    letter segment always sorts below a numeric one.
    """

    # The exact list published in the RubyGems versioning guide.
    DOCUMENTED_ORDER = [
        "1.0.0.alpha",
        "1.0.0.beta2",
        "1.0.0.rc1",
        "1.0.0",
        "1.0.1",
        "1.1.0.beta",
        "2.0.0",
    ]

    def test_documented_order_is_reproduced(self) -> None:
        for lower, higher in zip(self.DOCUMENTED_ORDER, self.DOCUMENTED_ORDER[1:], strict=False):
            assert compare(lower, higher, VersionScheme.RUBYGEMS) == -1, (
                f"{lower} must sort below {higher}"
            )

    def test_trailing_zeros_are_ignored(self) -> None:
        assert compare("1.0", "1.0.0", VersionScheme.RUBYGEMS) == 0
        assert compare("2", "2.0.0.0", VersionScheme.RUBYGEMS) == 0

    def test_hyphen_is_read_as_dot_pre(self) -> None:
        # "1.0.0-rc1" is accepted and normalised to "1.0.0.pre.rc1".
        assert compare("1.0.0-rc1", "1.0.0.pre.rc1", VersionScheme.RUBYGEMS) == 0

    def test_letter_digit_boundary_is_a_segment_boundary(self) -> None:
        # beta10 -> "beta", 10, so it must exceed beta9 rather than sort lexically.
        assert compare("1.0.0.beta10", "1.0.0.beta9", VersionScheme.RUBYGEMS) == 1

    def test_multi_digit_segments_compare_numerically(self) -> None:
        assert compare("3.10", "3.2", VersionScheme.RUBYGEMS) == 1

    def test_prerelease_sorts_below_the_release(self) -> None:
        assert compare("1.0.a", "1.0", VersionScheme.RUBYGEMS) == -1

    def test_gem_version_is_flagged_as_prerelease(self) -> None:
        assert parse("1.0.0.rc1", VersionScheme.RUBYGEMS).is_prerelease is True
        assert parse("1.0.0", VersionScheme.RUBYGEMS).is_prerelease is False

    @pytest.mark.parametrize(
        "bad", ["", "not-a-version", "1..0", "-1.0", "1.0-", "1.0 0", "v1.0"]
    )
    def test_malformed_versions_are_refused(self, bad: str) -> None:
        """A refused parse yields ``None``, never a wrong ordering."""
        assert parse(bad, VersionScheme.RUBYGEMS) is None

    def test_range_evaluation_now_answers_for_rubygems(self) -> None:
        """The point of the scheme: a gem verdict is no longer UNKNOWN."""
        packages = [
            AffectedPackage(
                ecosystem="RubyGems", name="rails", introduced="0", fixed="6.1.7.1"
            )
        ]
        affected = assess_affected(
            packages, ecosystem="RubyGems", name="rails", version="6.1.7"
        )
        assert affected.verdict is Verdict.AFFECTED
        safe = assess_affected(
            packages, ecosystem="RubyGems", name="rails", version="7.0.0"
        )
        assert safe.verdict is Verdict.NOT_AFFECTED

    def test_prerelease_below_the_fix_is_still_affected(self) -> None:
        """A release candidate below the fixed version must not be excused."""
        packages = [
            AffectedPackage(ecosystem="RubyGems", name="rails", introduced="0",
                            fixed="6.1.7.1")
        ]
        result = assess_affected(
            packages, ecosystem="RubyGems", name="rails", version="6.1.7.1.rc1"
        )
        assert result.verdict is Verdict.AFFECTED


class TestExclusionSideIsRecorded:
    """Which side of a range excluded a version is a different fact from exclusion.

    It was added for the OpenVEX adapter, which must justify ``not_affected`` from a
    fixed enumeration: "the code was never here" and "the fix is already here" are
    different justifications, and only one of them is available to us in each case.
    """

    def test_below_the_range_is_before(self):
        packages = _advisory(
            [
                {
                    "package": {"ecosystem": "npm", "name": "lodash"},
                    "ranges": [
                        {"type": "SEMVER", "events": [{"introduced": "4.17.0"}, {"fixed": "4.17.21"}]}
                    ],
                }
            ]
        )
        result = assess_affected(packages, ecosystem="npm", name="lodash", version="4.16.0")
        assert result.verdict is Verdict.NOT_AFFECTED
        assert result.excluded_by is ExclusionSide.BEFORE

    def test_at_the_fix_is_after(self):
        packages = _advisory(
            [
                {
                    "package": {"ecosystem": "npm", "name": "lodash"},
                    "ranges": [
                        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}
                    ],
                }
            ]
        )
        result = assess_affected(packages, ecosystem="npm", name="lodash", version="4.17.21")
        assert result.excluded_by is ExclusionSide.AFTER

    def test_affected_has_no_exclusion_side(self):
        packages = _advisory(
            [
                {
                    "package": {"ecosystem": "npm", "name": "lodash"},
                    "ranges": [
                        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}
                    ],
                }
            ]
        )
        result = assess_affected(packages, ecosystem="npm", name="lodash", version="4.17.20")
        assert result.verdict is Verdict.AFFECTED
        assert result.excluded_by is None

    def test_unknown_has_no_exclusion_side(self):
        packages = _advisory(
            [
                {
                    "package": {"ecosystem": "unknown-ecosystem", "name": "thing"},
                    "ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}],
                }
            ]
        )
        result = assess_affected(
            packages, ecosystem="unknown-ecosystem", name="thing", version="1.0"
        )
        assert result.verdict is Verdict.UNKNOWN
        assert result.excluded_by is None

    def test_it_survives_as_dict(self):
        packages = _advisory(
            [
                {
                    "package": {"ecosystem": "npm", "name": "lodash"},
                    "ranges": [
                        {"type": "SEMVER", "events": [{"introduced": "4.17.0"}, {"fixed": "4.17.21"}]}
                    ],
                }
            ]
        )
        result = assess_affected(packages, ecosystem="npm", name="lodash", version="4.16.0")
        assert result.as_dict()["excluded_by"] == "before"
