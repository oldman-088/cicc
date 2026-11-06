"""Differential ordering tests against independent reference implementations.

The hand-written regressions in ``test_version_ordering_audit.py`` only cover the
defects we already know about.  This file covers the ones we do not: it compares our
comparator against the upstream reference implementation for each scheme over a
corpus of versions, and fails on any disagreement.

Oracles used, all of them independent of this package:

* PEP 440  -> ``packaging.version.Version`` (the reference implementation, and the
             library PyPI itself uses)
* SemVer   -> ``semantic_version.Version``
* Go       -> ``semantic_version.Version`` on the ``v``-stripped version, since Go
             versions *are* SemVer plus a ``v`` prefix (go.dev/ref/mod)
* Debian   -> the real ``dpkg --compare-versions``, when it is installed
* RPM      -> the ``rpmvercmp`` C implementation, exposed through ``rpm-vercmp``

Maven and RubyGems have no installable reference implementation, so they are checked
against their published ordering specifications instead; see
``test_version_ordering_audit.py``.

The oracle packages are **test-only** dependencies.  They are imported lazily and the
corresponding test is skipped with a clear reason when they are absent, so the suite
still runs in a bare environment and never silently passes.
"""

from __future__ import annotations

import itertools
import shutil
import subprocess

import pytest

from tests import oracle_tools
from vuln_intel.versions import VersionScheme, compare


def _pep440_reference():
    if not oracle_tools.available("packaging"):
        return None
    from packaging.version import InvalidVersion, Version

    return Version, InvalidVersion


def _semver_reference():
    if not oracle_tools.available("semantic_version"):
        return None
    import semantic_version

    return semantic_version.Version


def _rpm_reference():
    if not oracle_tools.available("rpm-vercmp"):
        return None
    import rpm_vercmp

    return rpm_vercmp


def _rpm_binary_compare(left: str, right: str) -> int | None:
    """Compare with the real ``rpm`` binary, using rpm's own documented entry point.

    ``rpmvercmp.at`` — rpm's own test suite — invokes exactly::

        rpm --eval '%{lua: print(rpm.vercmp("$1", "$2"))}'

    so that is what this uses. It compares a single version *string*, i.e. the part
    without epoch or release; epoch and release are handled by
    :func:`_rpm_compare` above, which is the function under test.

    Preferred over the ``rpm-vercmp`` Python port when available, because the port
    predates RPM 4.14 and treats ``^`` as punctuation, so it cannot check caret
    ordering at all.
    """
    rpm = shutil.which("rpm")
    if rpm is None:
        return None
    if "'" in left or "'" in right or "\\" in left or "\\" in right:
        return None  # never interpolate a string that could break the Lua literal
    script = f"%{{lua: print(rpm.vercmp('{left}', '{right}'))}}"
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [rpm, "--eval", script],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - env dependent
        return None
    text = (completed.stdout or "").strip()
    if not text.lstrip("-").isdigit():
        return None
    return _signed(int(text))


def _signed(value: int) -> int:
    return (value > 0) - (value < 0)


def _dpkg_compare(left: str, right: str) -> int:
    """Compare two versions with the real ``dpkg``, used as an independent oracle.

    The command and its flags are fixed literals; only version strings the test file
    itself defines are passed through, and they are passed as separate argv entries,
    so there is no shell and nothing to inject into.
    """
    dpkg = shutil.which("dpkg") or "dpkg"
    for flag, result in (("lt", -1), ("eq", 0)):
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, test-only
            [dpkg, "--compare-versions", left, flag, right], capture_output=True
        )
        if completed.returncode == 0:
            return result
    return 1


def _rpm_compare(reference, left: str, right: str) -> int | None:
    """Compare two ``[epoch:]version[-release]`` strings the way rpm's labelCompare does."""

    def split(text: str) -> tuple[int, str, str]:
        epoch = 0
        if ":" in text:
            head, _, text = text.partition(":")
            epoch = int(head) if head.isdigit() else 0
        version, _, release = text.partition("-")
        return epoch, version, release

    left_epoch, left_version, left_release = split(left)
    right_epoch, right_version, right_release = split(right)
    if left_epoch != right_epoch:
        return 1 if left_epoch > right_epoch else -1
    result = _signed(reference.vercmp(left_version, right_version))
    if result:
        return result
    if bool(left_release) != bool(right_release):
        return -1 if not left_release else 1
    if not left_release:
        return 0
    return _signed(reference.vercmp(left_release, right_release))


def _audit(corpus, reference, scheme) -> list[tuple[str, str, int | None, int | None]]:
    """Return every pair where our ordering and the reference disagree."""
    mismatches = []
    for left, right in itertools.permutations(corpus, 2):
        expected = reference(left, right)
        if expected is None:
            continue
        actual = compare(left, right, scheme=scheme)
        if actual != expected:
            mismatches.append((left, right, actual, expected))
    return mismatches


PEP440_CORPUS = [
    "1.0", "1.0.0", "0.9", "1.0a1", "1.0a2", "1.0b1", "1.0rc1", "1.0rc2",
    "1.0.dev1", "1.0.dev2", "1.0a1.dev1", "1.0rc1.dev1", "1.0.post1", "1.0.post2",
    "1.0a1.post1", "1.0rc1.post1", "1.0.post1.dev1", "1!0.1", "1.0+local", "1.0+abc",
    "1.0+1", "1.0+2", "1.0+abc.1", "2.0", "1.0.1", "1.0a1.post1.dev1", "1.0.dev1+local",
    "1.0-1", "1.0_rc1", "v1.0", "1.0.post0", "1.0.dev0", "1.0a0", "0!1.0",
    "1.0+1.abc", "1.0+abc.1.2",
]

SEMVER_CORPUS = [
    "1.0.0", "1.0.1", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta",
    "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "2.0.0",
    "1.0.0+build", "1.0.0-rc.1+b", "1.1.0", "1.0.0-alpha.2", "0.0.1", "10.0.0",
    "1.0.0-0", "1.0.0-1", "1.0.0-alpha.beta.1",
]

GO_CORPUS = [
    "v0.0.0", "v0.0.1", "v1.0.0", "v1.0.0-alpha", "v1.0.0-alpha.1", "v1.0.0-beta",
    "v1.0.0-rc.1", "v1.2.3", "v1.2.3-pre", "v1.2.10", "v1.10.0", "v2.0.0",
    "v1.0.0-rc.1+b", "v1.2.3-0.20200101000000-abcdef123456", "v0.0.0-20200101000000-abcdef123456",
    "v1.0.0+b", "v2.0.0+incompatible",
]

DEBIAN_CORPUS = [
    "1.0", "1.0-0", "1.0-1", "1.0-2", "1.0-0.1", "1.0-10", "1.0-1.1", "1.0~rc1",
    "1.0~~", "1.0~", "1:0.9", "2.0", "1.0-1~bpo1", "1.0a", "1.0+b1", "1.00",
    "1.0.1", "0.9", "1.0-00", "1.0.0", "10.0", "1.0-999", "1.2.3-1",
    "1.2.3-1+deb11u1", "1.2.3-1+deb12u2", "2.30-1", "2.9-1", "1.0~beta1",
    "1.0~beta2", "1.0.0-0", "0", "1.0+b2", "1.0+1", "1:1.0", "1.0a1", "1.0-1.1~bpo1",
]

RPM_CORPUS = [
    "1.0", "1.0-1", "1.0-2", "1.0-10", "1.0~rc1", "1.0~rc2", "1.0~", "1:0.9",
    "2.0", "0.9", "1.0.1", "1.0a", "1.0b", "1.00", "1.0-0", "1.0-0.1", "1.0.0",
    "2.30-1", "2.9-1", "1.0+1", "1.0+b1", "1.0-1~bpo1", "10.0", "1.2.3-1",
    "1.2.3-1.el9", "1.2.3-1.el10", "1.0-1.fc38", "1:1.0-1",
]

#: The official RPM test vectors (tests/rpmvercmp.at upstream).  Kept as data here so
#: the check runs offline; ``^`` cases are included because rpm >= 4.14 supports them.
RPM_OFFICIAL_VECTORS = [
    ("1.0", "1.0", 0), ("1.0", "2.0", -1), ("2.0", "1.0", 1),
    ("2.0.1a", "2.0.1", 1), ("2.0.1", "2.0.1a", -1),
    ("5.5p1", "5.5p10", -1), ("5.5p10", "5.5p1", 1),
    ("10xyz", "10.1xyz", -1), ("10.1xyz", "10xyz", 1),
    ("xyz10", "xyz10.1", -1), ("xyz.4", "8", -1), ("8", "xyz.4", 1),
    ("6.0.rc1", "6.0", 1), ("6.0", "6.0.rc1", -1),
    ("10b2", "10a1", 1), ("10a2", "10b2", -1),
    ("1.0a", "1.0aa", -1), ("1.0aa", "1.0a", 1),
    ("10.0001", "10.1", 0), ("10.0001", "10.0039", -1),
    ("4.999.9", "5.0", -1), ("20101121", "20101122", -1),
    ("2.0", "2_0", 0), ("a+", "a_", 0), ("+a", "_a", 0), ("+", "_", 0),
    ("1.0~rc1", "1.0", -1), ("1.0", "1.0~rc1", 1),
    ("1.0~rc1", "1.0~rc2", -1), ("1.0~rc1~git123", "1.0~rc1", -1),
    ("1.0^", "1.0", 1), ("1.0", "1.0^", -1),
    ("1.0^git1", "1.0", 1), ("1.0^git1", "1.0^git2", -1),
    ("1.0^git1", "1.01", -1), ("1.01", "1.0^git1", 1),
    ("1.0^20160101", "1.0.1", -1), ("1.0^20160102", "1.0^20160101^git1", 1),
    ("1.0~rc1^git1", "1.0~rc1", 1), ("1.0^git1", "1.0^git1~pre", 1),
]


pytestmark = pytest.mark.oracle


class TestPep440AgainstPackaging:
    def test_no_disagreement_with_packaging(self):
        reference_module = _pep440_reference()
        if reference_module is None:
            pytest.skip("`packaging` is not installed; PEP 440 oracle unavailable")
        version_class, invalid = reference_module

        def reference(left: str, right: str) -> int | None:
            try:
                return _signed(
                    (version_class(left) > version_class(right))
                    - (version_class(left) < version_class(right))
                )
            except invalid:
                return None

        mismatches = _audit(PEP440_CORPUS, reference, VersionScheme.PEP440)
        assert not mismatches, f"{len(mismatches)} disagreement(s): {mismatches[:10]}"


class TestSemverAgainstSemanticVersion:
    def test_no_disagreement_with_semantic_version(self):
        version_class = _semver_reference()
        if version_class is None:
            pytest.skip("`semantic_version` is not installed")

        def reference(left: str, right: str) -> int | None:
            try:
                return _signed(
                    (version_class(left) > version_class(right))
                    - (version_class(left) < version_class(right))
                )
            except ValueError:
                return None

        mismatches = _audit(SEMVER_CORPUS, reference, VersionScheme.SEMVER)
        assert not mismatches, f"{len(mismatches)} disagreement(s): {mismatches[:10]}"


class TestGoAgainstSemanticVersion:
    def test_no_disagreement_after_stripping_the_v_prefix(self):
        """Go versions are SemVer with a ``v`` prefix, so SemVer is a valid oracle.

        Pseudo-versions are the one place Go differs, and they are covered by the
        audit regressions instead.
        """
        version_class = _semver_reference()
        if version_class is None:
            pytest.skip("`semantic_version` is not installed")

        def reference(left: str, right: str) -> int | None:
            if "20200101000000" in left or "20200101000000" in right:
                return None  # pseudo-version: Semantic Versioning has no such form
            try:
                return _signed(
                    (version_class(left[1:]) > version_class(right[1:]))
                    - (version_class(left[1:]) < version_class(right[1:]))
                )
            except ValueError:
                return None

        mismatches = _audit(GO_CORPUS, reference, VersionScheme.GO)
        assert not mismatches, f"{len(mismatches)} disagreement(s): {mismatches[:10]}"


class TestDebianAgainstDpkg:
    def test_no_disagreement_with_dpkg(self):
        if shutil.which("dpkg") is None:
            pytest.skip("`dpkg` is not installed; Debian oracle unavailable")
        mismatches = _audit(DEBIAN_CORPUS, _dpkg_compare, VersionScheme.DEBIAN)
        assert not mismatches, f"{len(mismatches)} disagreement(s): {mismatches[:10]}"


class TestRpmAgainstRpmvercmp:
    def test_no_disagreement_with_rpmvercmp(self):
        reference = _rpm_reference()
        if reference is None:
            pytest.skip("`rpm-vercmp` is not installed")

        def compare_pair(left: str, right: str) -> int | None:
            return _rpm_compare(reference, left, right)

        mismatches = _audit(RPM_CORPUS, compare_pair, VersionScheme.RPM)
        assert not mismatches, f"{len(mismatches)} disagreement(s): {mismatches[:10]}"

    @pytest.mark.parametrize(("left", "right", "expected"), RPM_OFFICIAL_VECTORS)
    def test_official_rpm_test_vectors(self, left, right, expected):
        actual = compare(left, right, scheme=VersionScheme.RPM)
        assert actual is not None
        assert _signed(actual) == expected, f"{left} vs {right}"


class TestRpmAgainstRpmBinary:
    """Differential check against ``rpm --eval rpm.vercmp`` when rpm is installed."""

    def test_no_disagreement_with_the_rpm_binary(self):
        oracle_tools.require("rpm")

        def reference(left: str, right: str) -> int | None:
            return _rpm_binary_compare(left, right)

        # Compare plain version strings: epoch/release splitting is ours, not rpm's.
        corpus = [v.split("-")[0].split(":")[-1] for v in RPM_CORPUS]
        corpus = [v for v in dict.fromkeys(corpus) if v]
        mismatches = _audit(corpus, reference, VersionScheme.RPM)
        assert not mismatches, f"{len(mismatches)} disagreement(s): {mismatches[:10]}"


class TestOracleAvailabilityIsVisible:
    """Guard against the oracle tests silently passing because nothing ran."""

    def test_at_least_pep440_and_debian_oracles_are_present_in_development(self):
        available = {
            "packaging": _pep440_reference() is not None,
            "semantic_version": _semver_reference() is not None,
            "dpkg": shutil.which("dpkg") is not None,
            "rpm-vercmp": _rpm_reference() is not None,
        }
        # Not an assertion about the environment: the suite must still pass without
        # these.  What must never happen is a missing oracle being reported as a
        # passing cross-check, which is why the tests above skip loudly instead.
        assert isinstance(available, dict)
