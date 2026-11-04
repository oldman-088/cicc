"""Version ordering and affected-version evaluation.

These tests encode *decisions*, not just behaviour: the orderings below are the
ones that change whether an operator is told to patch.  Each case is a documented
rule from the relevant ecosystem specification.
"""

from __future__ import annotations

import pytest

from vuln_intel.affected import (
    Verdict,
    assess_affected,
    normalize_ecosystem,
)
from vuln_intel.connectors.osv import _parse_affected
from vuln_intel.schema import AffectedPackage
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
            # go: v-prefix and pseudo-versions
            ("v1.2.3", "v1.2.4", VersionScheme.GO, -1),
            (
                "v0.0.0-20210101120000-abcdef123456",
                "v0.0.0",
                VersionScheme.GO,
                1,
            ),
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
        # Rubygems is deliberately mapped to OPAQUE: gem versions like
        # "1.0.0.pre.rc1" do not follow semver, so guessing would be wrong.
        assert scheme_for_ecosystem("rubygems") is VersionScheme.OPAQUE
        assert compare("1.0.0", "1.0.1", VersionScheme.OPAQUE) is None

    def test_parse_does_not_raise_on_garbage(self):
        for scheme in VersionScheme:
            assert parse("!!!", scheme) is None or scheme is VersionScheme.DEBIAN

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
