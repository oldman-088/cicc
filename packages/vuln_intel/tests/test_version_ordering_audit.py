"""Regression tests for the version-ordering audit.

Each test here pins one ordering rule that the audit found to be violated.  They are
written against the *specification*, not against our implementation's output, because
the failure mode in this area is silent: a wrong ordering does not raise, it just
makes :func:`assess_affected` report a vulnerable version as ``not_affected``.

The four defect classes that were found and fixed:

1. PEP 440 dropped components on pre-releases (``dev`` and ``post``).
2. PEP 440 never read the local label (``1.0+local`` compared equal to ``1.0``) and
   ordered its segments backwards (strings must sort *below* integers).
3. PEP 440 refused the implicit ``-N`` post-release spelling (``1.0-1``).
4. Go discarded every non-pseudo pre-release suffix (``v1.2.3-pre`` == ``v1.2.3``).
5. Debian/RPM used a pre-split chunk key, which cannot express ``verrevcmp``/
   ``rpmvercmp`` because digit-run boundaries realign between the two strings.

Oracle-backed cross-checks live in ``tests/test_version_ordering_oracle.py``.
"""

from __future__ import annotations

import pytest

from vuln_intel.affected import assess_affected
from vuln_intel.schema import AffectedPackage
from vuln_intel.versions import VersionScheme, compare


def _cmp(left: str, right: str, scheme: VersionScheme) -> int | None:
    return compare(left, right, scheme=scheme)


class TestPep440ComponentOrdering:
    """PEP 440 orders on (epoch, release, pre, post, dev, local) as separate slots.

    Merging them into a single "phase" tuple loses one of them whenever two are
    present at once, which is exactly what a pre-release of a post-release is.
    """

    @pytest.mark.parametrize(
        ("lower", "higher"),
        [
            # dev sorts below the pre-release it develops towards
            ("1.0rc1.dev1", "1.0rc1"),
            ("1.0a1.dev1", "1.0a1"),
            ("1.0.dev1", "1.0a1"),
            # ... and a bare dev sorts below *every* pre-release
            ("1.0.dev1", "1.0rc1"),
            # post sorts above the release it follows
            ("1.0a1", "1.0a1.post1"),
            ("1.0rc1", "1.0rc1.post1"),
            ("1.0", "1.0.post1"),
            # a dev of a post-release sorts above the plain release, because the
            # post-release it belongs to already sorts above it
            ("1.0", "1.0.post1.dev1"),
            ("1.0.post1.dev1", "1.0.post1"),
            ("1.0.post1.dev1", "1.0.post1.dev2"),
        ],
    )
    def test_pre_post_dev_are_independent_slots(self, lower, higher):
        assert _cmp(lower, higher, VersionScheme.PEP440) == -1, (
            f"{lower} must sort below {higher}"
        )
        assert _cmp(higher, lower, VersionScheme.PEP440) == 1

    @pytest.mark.parametrize(
        ("left", "right"),
        [
            ("1.0", "1.0.0"),
            ("1.0", "1.0.0.0"),
            ("0!1.0", "1.0"),
        ],
    )
    def test_equal_versions_stay_equal(self, left, right):
        assert _cmp(left, right, VersionScheme.PEP440) == 0

    def test_epoch_dominates_everything_else(self):
        assert _cmp("1!0.1", "2.0", VersionScheme.PEP440) == 1

    def test_post_zero_is_above_its_release(self):
        # ``.post0`` is still a post release, so it follows the plain version.
        assert _cmp("1.0.post0", "1.0", VersionScheme.PEP440) == 1


class TestPep440LocalLabels:
    """A local label makes a version distinct and sorts above the same public one."""

    def test_local_label_is_not_equal_to_public_version(self):
        # This compared equal before the fix: the regex captured the local segment
        # and nothing read it.
        assert _cmp("1.0+local", "1.0", VersionScheme.PEP440) == 1
        assert _cmp("1.0", "1.0+local", VersionScheme.PEP440) == -1

    @pytest.mark.parametrize(
        ("lower", "higher"),
        [
            ("1.0+abc", "1.0+abd"),  # lexical
            ("1.0+1", "1.0+2"),  # numeric
            ("1.0+abc", "1.0+1"),  # strings sort BELOW integers
            ("1.0+abc", "1.0+abc.1"),  # shorter prefix first
            ("1.0+abc.1", "1.0+abc.2"),
        ],
    )
    def test_local_segment_ordering(self, lower, higher):
        assert _cmp(lower, higher, VersionScheme.PEP440) == -1, (
            f"{lower} must sort below {higher}"
        )


class TestPep440ImplicitPost:
    """PEP 440 accepts ``1.0-1`` as a second spelling of ``1.0.post1``."""

    def test_implicit_post_release_is_accepted(self):
        assert _cmp("1.0-1", "1.0.post1", VersionScheme.PEP440) == 0
        assert _cmp("1.0-1", "1.0", VersionScheme.PEP440) == 1

    def test_unlabelled_suffixes_are_still_refused(self):
        # `1.0--1` is not a valid post-release spelling in any implementation.
        assert _cmp("1.0--1", "1.0", VersionScheme.PEP440) is None


class TestGoPrereleases:
    """Go versions are SemVer plus a ``v`` prefix, so pre-releases must order."""

    @pytest.mark.parametrize(
        ("lower", "higher"),
        [
            ("v1.2.3-pre", "v1.2.3"),
            ("v1.0.0-alpha", "v1.0.0"),
            ("v1.0.0-alpha.1", "v1.0.0-alpha.2"),
            ("v1.0.0-rc.1", "v1.0.0"),
            # A pseudo-version is a pre-release of the tag it follows.
            ("v0.0.0-20210101120000-abcdef123456", "v0.0.0"),
            ("v1.2.3-0.20200101000000-abcdef123456", "v1.2.3"),
        ],
    )
    def test_prerelease_sorts_below_release(self, lower, higher):
        assert _cmp(lower, higher, VersionScheme.GO) == -1, (
            f"{lower} must sort below {higher}"
        )

    def test_pseudo_versions_order_by_timestamp(self):
        older = "v1.2.3-0.20200101000000-abcdef123456"
        newer = "v1.2.3-0.20210101000000-abcdef123456"
        assert _cmp(older, newer, VersionScheme.GO) == -1

    def test_build_metadata_is_ignored(self):
        assert _cmp("v2.0.0", "v2.0.0+incompatible", VersionScheme.GO) == 0


class TestDebianDpkgSemantics:
    """``dpkg`` compares the upstream and revision strings character by character."""

    @pytest.mark.parametrize(
        ("lower", "higher"),
        [
            ("1.0~~", "1.0~"),
            ("1.0~", "1.0"),
            ("1.0~rc1", "1.0"),
            ("1.0~beta1", "1.0~beta2"),
            ("1.0-1", "1.0-2"),
            ("1.0-1", "1.0-10"),
            ("1.0-1.1", "1.0-2"),
            ("1.0-1~bpo1", "1.0-1"),
            ("1.0+1", "1.0+1.1"),
            ("1.0.1", "1.0.2"),
            ("2.9-1", "2.30-1"),
        ],
    )
    def test_ordering(self, lower, higher):
        assert _cmp(lower, higher, VersionScheme.DEBIAN) == -1, (
            f"{lower} must sort below {higher}"
        )

    @pytest.mark.parametrize(
        ("left", "right"),
        [
            # dpkg strips leading zeros, so an all-zero revision is no revision.
            ("1.0", "1.0-0"),
            ("1.0", "1.0-00"),
            ("1.0-0", "1.0-00"),
            ("1.00", "1.0"),
        ],
    )
    def test_equal_versions(self, left, right):
        assert _cmp(left, right, VersionScheme.DEBIAN) == 0

    def test_epoch_dominates(self):
        assert _cmp("1:0.9", "2.0", VersionScheme.DEBIAN) == 1

    def test_invalid_characters_are_refused_not_approximated(self):
        assert _cmp("1.0 2", "1.0", VersionScheme.DEBIAN) is None


class TestRpmVersionCompare:
    """``rpmvercmp``: ``~`` below everything, ``^`` above the release but below more."""

    @pytest.mark.parametrize(
        ("lower", "higher"),
        [
            ("1.0~rc1", "1.0"),
            ("1.0~rc1", "1.0~rc2"),
            ("1.0~rc1~git123", "1.0~rc1"),
            ("1.0", "1.0^"),
            ("1.0", "1.0^git1"),
            ("1.0^git1", "1.0^git2"),
            ("1.0^git1", "1.01"),
            ("1.0^20160101", "1.0.1"),
            ("1.0.0", "1.0.0-1"),
            ("1.0-1", "1.0-2"),
            ("5.5p1", "5.5p10"),
            ("10xyz", "10.1xyz"),
        ],
    )
    def test_ordering(self, lower, higher):
        assert _cmp(lower, higher, VersionScheme.RPM) == -1, (
            f"{lower} must sort below {higher}"
        )

    def test_caret_versions_are_orderable_under_rpm_only(self):
        """``^`` is legal in RPM and illegal in Debian, so the parsers must differ.

        RPM used to reuse the Debian parser, which rejects ``^``, so every
        post-release-tagged RPM version became unorderable and therefore
        "unknown" rather than "affected".
        """
        assert _cmp("1.0^git1", "1.0", VersionScheme.RPM) == 1
        assert _cmp("1.0^git1", "1.0", VersionScheme.DEBIAN) is None

    def test_missing_release_sorts_below_present_release(self):
        assert _cmp("1.0", "1.0-1", VersionScheme.RPM) == -1
        assert _cmp("1.0-1", "1.0", VersionScheme.RPM) == 1


class TestOrderingIsTotal:
    """Every scheme must be antisymmetric and transitive on its own corpus.

    A non-total order silently breaks interval construction in ``affected.py``,
    because a range is only meaningful if the comparator is consistent.
    """

    CORPUS = {
        VersionScheme.PEP440: [
            "1.0.dev0", "1.0.dev1", "1.0a1", "1.0a1.dev1", "1.0a1.post1",
            "1.0b1", "1.0rc1", "1.0", "1.0+local", "1.0.post1",
            "1.0.post1.dev1", "1.0.1", "2.0", "1!0.1",
        ],
        VersionScheme.DEBIAN: [
            "0.9", "1.0~~", "1.0~rc1", "1.0", "1.0-0", "1.0-1", "1.0-1~bpo1",
            "1.0+b1", "1.0.1", "1:0.9", "2.0",
        ],
        VersionScheme.RPM: [
            "0.9", "1.0~rc1", "1.0", "1.0^git1", "1.0-1", "1.0.1", "1:0.9", "2.0",
        ],
        VersionScheme.SEMVER: [
            "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta", "1.0.0-rc.1", "1.0.0",
            "1.0.1", "1.1.0", "2.0.0", "2.0.0+build",
        ],
        VersionScheme.MAVEN: [
            "1.0-alpha-1", "1.0-beta-1", "1.0-SNAPSHOT", "1.0", "1.0-sp", "1.0-1",
            "1.1", "2.0",
        ],
        VersionScheme.GO: [
            "v0.0.0-20200101000000-abcdef123456", "v0.0.1", "v1.0.0-alpha",
            "v1.0.0", "v1.0.1", "v1.2.3-pre", "v1.2.3", "v2.0.0+incompatible",
        ],
        VersionScheme.RUBYGEMS: [
            "1.0.0.alpha", "1.0.0.beta", "1.0.0.rc1", "1.0.0", "1.0.1", "1.1.0",
        ],
    }

    @pytest.mark.parametrize("scheme", list(CORPUS))
    def test_antisymmetric(self, scheme):
        corpus = self.CORPUS[scheme]
        for left in corpus:
            for right in corpus:
                forward = _cmp(left, right, scheme)
                backward = _cmp(right, left, scheme)
                assert forward is not None and backward is not None
                assert forward == -backward, f"{left} vs {right} under {scheme}"

    @pytest.mark.parametrize("scheme", list(CORPUS))
    def test_transitive(self, scheme):
        corpus = self.CORPUS[scheme]
        for a in corpus:
            for b in corpus:
                if _cmp(a, b, scheme) != -1:
                    continue
                for c in corpus:
                    if _cmp(b, c, scheme) != -1:
                        continue
                    assert _cmp(a, c, scheme) == -1, (
                        f"{a} < {b} < {c} but {a} !< {c} under {scheme}"
                    )

    @pytest.mark.parametrize("scheme", list(CORPUS))
    def test_reflexive(self, scheme):
        for value in self.CORPUS[scheme]:
            assert _cmp(value, value, scheme) == 0


class TestVerdictImpact:
    """The reason these orderings matter: they decide ``affected`` vs clean."""

    def _range(self, **kwargs) -> list[AffectedPackage]:
        ecosystem = kwargs.pop("ecosystem", "PyPI")
        name = kwargs.pop("name", "demo")
        return [AffectedPackage(ecosystem=ecosystem, name=name, **kwargs)]

    def test_dev_prerelease_is_affected_by_fix_at_its_rc(self):
        # Before the fix, `1.0rc1.dev1` compared EQUAL to the fixed version 1.0rc1
        # and was reported `not_affected`.
        packages = self._range(introduced="0", fixed="1.0rc1")
        for version in ("1.0rc1.dev1", "1.0a1.post1"):
            result = assess_affected(
                packages, ecosystem="PyPI", name="demo", version=version
            )
            assert result.verdict.value == "affected", version

    def test_release_at_fixed_version_is_not_affected(self):
        packages = self._range(introduced="0", fixed="1.0rc1")
        for version in ("1.0rc1", "1.0"):
            result = assess_affected(
                packages, ecosystem="PyPI", name="demo", version=version
            )
            assert result.verdict.value == "not_affected", version

    def test_post_release_of_fixed_version_is_not_affected(self):
        packages = self._range(introduced="0", fixed="1.0")
        result = assess_affected(
            packages, ecosystem="PyPI", name="demo", version="1.0.post1"
        )
        assert result.verdict.value == "not_affected"

    def test_implicit_post_fix_still_protects(self):
        packages = self._range(introduced="0", fixed="1.0-1")
        result = assess_affected(packages, ecosystem="PyPI", name="demo", version="1.0")
        assert result.verdict.value == "affected"

    def test_go_prerelease_is_affected_by_fix_at_release(self):
        packages = self._range(ecosystem="Go", name="example.com/mod", introduced="0", fixed="v1.2.3")
        result = assess_affected(
            packages,
            ecosystem="Go",
            name="example.com/mod",
            version="v1.2.3-pre",
        )
        assert result.verdict.value == "affected"

    def test_debian_zero_revision_fix_still_protects(self):
        # `1.0-0` is the same version as `1.0` to dpkg, so a fix at `1.0` covers it.
        packages = self._range(ecosystem="Debian", name="demo", introduced="0", fixed="1.0")
        result = assess_affected(
            packages, ecosystem="Debian", name="demo", version="1.0-0"
        )
        assert result.verdict.value == "not_affected"
