"""Package-name matching: the difference between "safe" and "we never looked".

A purl writes a Maven package as ``group/artifact``; OSV and GHSA write it as
``group:artifact``; NVD and several advisory feeds write the bare ``artifact``.
All three are the same package. When the inventory and the advisory disagree on
spelling, the comparison finds nothing, the package never reaches the range
check, and the exposure report says nothing about it -- which reads exactly like
"not affected".

These tests pin the rule: the three spellings of one package match each other,
and packages from different groups stay apart where the data distinguishes them.
"""

from __future__ import annotations

from vuln_intel.affected import assess_affected, name_candidates
from vuln_intel.schema import AffectedPackage, CveId, NormalizedVulnerability, Origin
from vuln_intel.watchlist import (
    Dependency,
    Inventory,
    Watchlist,
    analyse_exposure,
    dependency_from_purl,
)

_PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


class TestPurlNamesThePackageTheWayAdvisoriesDo:
    def test_the_group_qualifies_the_artifact_rather_than_prefixing_a_path(self):
        parsed = dependency_from_purl(_PURL)
        assert parsed is not None
        assert parsed.name == "org.apache.logging.log4j:log4j-core"

    def test_the_purl_itself_survives_unchanged(self):
        parsed = dependency_from_purl(_PURL)
        assert parsed is not None
        assert parsed.purl == _PURL

    def test_an_artifact_only_purl_still_parses(self):
        parsed = dependency_from_purl("pkg:maven/log4j-core@2.14.1")
        assert parsed is not None
        assert parsed.name == "log4j-core"

    def test_a_percent_encoded_npm_scope_is_decoded(self):
        # purl path segments are percent-encoded; advisories say `@scope/pkg`.
        parsed = dependency_from_purl("pkg:npm/%40scope/pkg@1.2.3")
        assert parsed is not None
        assert parsed.name == "@scope/pkg"


class TestTheSpellingsAreOnePackage:
    def test_a_qualified_name_offers_the_bare_artifact_as_a_candidate(self):
        assert name_candidates("maven", "org.apache.logging.log4j:log4j-core") == {
            "org.apache.logging.log4j:log4j-core",
            "log4j-core",
        }

    def test_a_bare_name_offers_only_itself(self):
        assert name_candidates("maven", "log4j-core") == {"log4j-core"}

    def test_other_ecosystems_gain_no_candidates(self):
        # npm scoped packages legitimately contain a slash; the Maven rule must
        # not leak into them.
        assert name_candidates("npm", "@scope/pkg") == {"@scope/pkg"}

    def test_a_qualified_name_and_a_bare_name_match(self):
        packages = [
            AffectedPackage(
                ecosystem="maven", name="log4j-core", introduced="2.0.0", fixed="2.15.0"
            )
        ]
        assessment = assess_affected(
            packages, ecosystem="maven", name="org.apache.logging.log4j:log4j-core",
            version="2.14.1",
        )
        assert assessment.verdict.value == "affected"

    def test_two_explicit_groups_stay_apart(self):
        # When both sides name a group, the groups are compared honestly: an
        # advisory about org.apache's log4j-core does not match com.example's.
        assert not name_candidates("maven", "com.example:log4j-core") & name_candidates(
            "maven", "org.apache.logging.log4j:log4j-core"
        ) - {"log4j-core"}

    def test_a_bare_advisory_name_over_reports_rather_than_misses(self):
        # Documented trade-off: NVD sometimes gives only the artefact, so the
        # bare name matches any group's package of that name. An extra match is
        # visible to an analyst; a silent miss is not.
        assert "log4j-core" in name_candidates("maven", "com.example:log4j-core")


class TestTheInventoryLookupFindsEitherSpelling:
    def test_a_purl_inventory_is_found_by_the_bare_advisory_name(self):
        inventory = Inventory.from_purls([_PURL])
        assert inventory.for_package("maven", "log4j-core")

    def test_a_purl_inventory_is_found_by_the_qualified_name(self):
        inventory = Inventory.from_purls([_PURL])
        assert inventory.for_package("maven", "org.apache.logging.log4j:log4j-core")

    def test_a_bare_inventory_is_found_by_a_qualified_lookup(self):
        inventory = Inventory(
            dependencies=(
                Dependency(ecosystem="maven", name="log4j-core", version="2.14.1"),
            )
        )
        assert inventory.for_package("maven", "org.apache.logging.log4j:log4j-core")

    def test_a_dependency_is_not_indexed_under_another_ecosystem(self):
        inventory = Inventory.from_purls([_PURL])
        assert not inventory.for_package("npm", "log4j-core")


class TestAnUnmatchedPackageIsStillReported:
    """The dangerous direction is silence: fix the miss, not the report."""

    def _advisory(self, name: str) -> NormalizedVulnerability:
        return NormalizedVulnerability(
            cve=CveId.parse("CVE-2021-44228"),
            origin=Origin.FIXTURE,
            summary="Log4Shell",
            affected=(
                AffectedPackage(
                    ecosystem="maven", name=name, introduced="2.0.0", fixed="2.15.0"
                ),
            ),
        )

    def test_the_purl_inventory_matches_a_bare_advisory_name(self):
        report = analyse_exposure(
            Inventory.from_purls([_PURL]), [self._advisory("log4j-core")]
        )
        assert len(report.matches) == 1
        assert report.matches[0].assessment.verdict.value == "affected"

    def test_the_purl_inventory_matches_a_qualified_advisory_name(self):
        report = analyse_exposure(
            Inventory.from_purls([_PURL]),
            [self._advisory("org.apache.logging.log4j:log4j-core")],
        )
        assert len(report.matches) == 1

    def test_an_unrelated_package_is_not_reported_as_affected(self):
        report = analyse_exposure(
            Inventory.from_purls([_PURL]), [self._advisory("log4j-api")]
        )
        assert not report.matches


class TestTheWatchlistAnswersInEitherSpelling:
    def test_a_watchlist_built_from_a_purl_covers_the_bare_advisory_name(self):
        watchlist = Watchlist()
        watchlist.add_inventory(Inventory.from_purls([_PURL]))
        assert watchlist.covers("maven", "log4j-core")

    def test_a_watchlist_built_from_a_purl_covers_the_qualified_name(self):
        watchlist = Watchlist()
        watchlist.add_inventory(Inventory.from_purls([_PURL]))
        assert watchlist.covers("maven", "org.apache.logging.log4j:log4j-core")

    def test_an_absent_package_is_still_absent(self):
        watchlist = Watchlist()
        watchlist.add_inventory(Inventory.from_purls([_PURL]))
        assert not watchlist.covers("maven", "log4j-api")
        assert not watchlist.covers("npm", "log4j-core")
