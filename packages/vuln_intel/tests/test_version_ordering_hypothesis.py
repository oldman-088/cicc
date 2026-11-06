"""B-12: hypothesis-driven ordering laws + oracle cross-checks per ecosystem.

Two distinct claims are tested, and they are NOT the same:

1. **Ordering laws** (reflexivity, antisymmetry, transitivity on sampled
   triples) — internal consistency, generated adversarial inputs included.
2. **Oracle agreement** — comparison against an authoritative upstream
   implementation where one is installed (packaging=PEP 440, semantic_version
   =SemVer/Go, dpkg=Debian). When the oracle is absent the test SKIPS loudly;
   a skip is never reported as a pass.

Malformed/empty inputs must yield ``None`` (unknown), never a confident order —
that is the "no silent false certainty" rule.

Hypothesis is a dev-only dependency; the runtime package stays stdlib-only.
"""

from __future__ import annotations

import pytest

pytest.importorskip("hypothesis", reason="hypothesis is a dev-only dependency")

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from vuln_intel.versions import VersionScheme, compare, parse

# --- version-string generators per scheme (adversarial fragments included) ---

_SEMVER_PARTS = st.one_of(
    st.integers(min_value=0, max_value=999).map(str),
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz-", min_size=1, max_size=8),
)

# `semantic_version` rejects a pre-release that is purely numeric ("1.0.0-01") and
# hyphenated identifiers in the core position, so generated strings are filtered
# through the oracle once at generation time. Filtering here rather than inside the
# test keeps `assume()` from firing on most examples — which fails Hypothesis's
# health check — and keeps the property testing real comparisons.
def _semver_accepted(text: str) -> bool:
    try:
        from semantic_version import Version
    except ImportError:
        return True  # the oracle is absent; the test skips for that reason instead
    try:
        Version(text)
    except Exception:
        return False
    return True


SEMVER_STR = st.builds(
    lambda a, b, c, pre: f"{a}.{b}.{c}" + (f"-{pre}" if pre else ""),
    st.integers(min_value=0, max_value=99).map(str),
    st.integers(min_value=0, max_value=99).map(str),
    st.integers(min_value=0, max_value=99).map(str),
    st.one_of(st.none(), st.sampled_from(["alpha", "beta", "rc1", "1"])),
).filter(_semver_accepted)

PEP440_STR = st.builds(
    lambda a, b, pre, post: f"{a}.{b}" + (pre or "") + (f".post{post}" if post else ""),
    st.integers(min_value=0, max_value=20).map(str),
    st.integers(min_value=0, max_value=20).map(str),
    st.one_of(st.none(), st.just("a1"), st.just("b2"), st.just("rc1")),
    st.one_of(st.none(), st.integers(min_value=0, max_value=9)),
)

DEBIAN_STR = st.builds(
    lambda e, up, rev: (f"{e}:" if e else "") + up + (f"-{rev}" if rev else ""),
    st.one_of(st.none(), st.integers(min_value=0, max_value=3)),
    st.text(alphabet="0123456789abc.~+", min_size=1, max_size=10),
    st.one_of(st.none(), st.text(alphabet="0123456789abc.+~", min_size=1, max_size=6)),
)

RPM_STR = DEBIAN_STR  # same generator shape is fine for law-testing

MAVEN_STR = st.builds(
    lambda a, q: f"{a}" + (f"-{q}" if q else ""),
    st.text(alphabet="0123456789.", min_size=1, max_size=8),
    st.one_of(st.none(), st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=6)),
)

RUBYGEMS_STR = st.builds(
    lambda a, pre: f"{a}" + (f".{pre}" if pre else ""),
    st.text(alphabet="0123456789.", min_size=1, max_size=8),
    st.one_of(st.none(), st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=6)),
)

GO_STR = SEMVER_STR

MALFORMED = st.one_of(st.just(""), st.just("   "), st.just("not a version!!"),
                      st.just(".."), st.just("-"), st.just(":"))

STRATEGIES = {
    VersionScheme.SEMVER: SEMVER_STR,
    VersionScheme.PEP440: PEP440_STR,
    VersionScheme.DEBIAN: DEBIAN_STR,
    VersionScheme.RPM: RPM_STR,
    VersionScheme.MAVEN: MAVEN_STR,
    VersionScheme.RUBYGEMS: RUBYGEMS_STR,
    VersionScheme.GO: GO_STR,
}


@st.composite
def _pairs(draw, scheme):
    gen = STRATEGIES[scheme]
    return draw(gen), draw(gen)


@given(_pairs(VersionScheme.SEMVER), _pairs(VersionScheme.SEMVER))
@settings(max_examples=120)
def test_semver_laws(pair_ab, pair_cd):
    _check_laws(VersionScheme.SEMVER, pair_ab, pair_cd)


@given(_pairs(VersionScheme.PEP440), _pairs(VersionScheme.PEP440))
@settings(max_examples=120)
def test_pep440_laws(pair_ab, pair_cd):
    _check_laws(VersionScheme.PEP440, pair_ab, pair_cd)


@given(_pairs(VersionScheme.DEBIAN), _pairs(VersionScheme.DEBIAN))
@settings(max_examples=120)
def test_debian_laws(pair_ab, pair_cd):
    _check_laws(VersionScheme.DEBIAN, pair_ab, pair_cd)


@given(_pairs(VersionScheme.RPM), _pairs(VersionScheme.RPM))
@settings(max_examples=120)
def test_rpm_laws(pair_ab, pair_cd):
    _check_laws(VersionScheme.RPM, pair_ab, pair_cd)


@given(_pairs(VersionScheme.MAVEN), _pairs(VersionScheme.MAVEN))
@settings(max_examples=120)
def test_maven_laws(pair_ab, pair_cd):
    _check_laws(VersionScheme.MAVEN, pair_ab, pair_cd)


@given(_pairs(VersionScheme.RUBYGEMS), _pairs(VersionScheme.RUBYGEMS))
@settings(max_examples=120)
def test_rubygems_laws(pair_ab, pair_cd):
    _check_laws(VersionScheme.RUBYGEMS, pair_ab, pair_cd)


@given(_pairs(VersionScheme.GO), _pairs(VersionScheme.GO))
@settings(max_examples=120)
def test_go_laws(pair_ab, pair_cd):
    _check_laws(VersionScheme.GO, pair_ab, pair_cd)


def _check_laws(scheme, pair_ab, pair_cd):
    a, b = pair_ab
    c = pair_cd[0]
    ab = compare(a, b, scheme)
    ba = compare(b, a, scheme)
    aa = compare(a, a, scheme)
    # reflexivity: a parses <=> a == a; if unparseable, compare must be None
    if parse(a, scheme) is None:
        assert ab is None and ba is None and aa is None
        return
    assert aa == 0
    # antisymmetry
    if ab is not None:
        assert ba is not None
        assert ab == -ba
    # transitivity on the sampled triple (skip if any link unknown)
    ac = compare(a, c, scheme)
    bc = compare(b, c, scheme)
    if ab is not None and ac is not None and bc is not None:
        if ab <= 0 and bc <= 0:
            assert ac <= 0
        if ab >= 0 and bc >= 0:
            assert ac >= 0


@given(MALFORMED)
@settings(max_examples=40)
def test_malformed_never_orders_confidently(bad):
    for scheme in (VersionScheme.SEMVER, VersionScheme.PEP440, VersionScheme.DEBIAN,
                   VersionScheme.MAVEN, VersionScheme.RUBYGEMS, VersionScheme.GO,
                   VersionScheme.RPM):
        result = compare(bad, "1.0.0", scheme)
        # either None (unknown) — never a confident -1/0/1 for a malformed left side
        assert result is None or parse(bad, scheme) is not None


# --- oracle cross-checks (skip loudly when the oracle is absent) ---

def _oracle_pep440():
    try:
        from packaging.version import Version as PkgVersion
        return PkgVersion
    except ImportError:
        pytest.skip("oracle 'packaging' not installed; cross-check did NOT run")


@given(PEP440_STR, PEP440_STR)
@settings(max_examples=150)
def test_pep440_matches_packaging_oracle(a, b):
    PkgVersion = _oracle_pep440()
    try:
        pa, pb = PkgVersion(a), PkgVersion(b)
    except Exception:
        # `assume`, not `skip`. Inside a Hypothesis test `pytest.skip()` aborts the
        # whole test on the first example the oracle rejects — which is why this
        # cross-check had been reporting a skip instead of running its other 149
        # examples. `assume` discards only the unusable example.
        assume(False)
    expected = (pa > pb) - (pa < pb)
    got = compare(a, b, VersionScheme.PEP440)
    assert got == expected


def _oracle_semver():
    try:
        from semantic_version import Version as SemVer
        return SemVer
    except ImportError:
        pytest.skip("oracle 'semantic_version' not installed; cross-check did NOT run")


@given(SEMVER_STR, SEMVER_STR)
@settings(max_examples=150)
def test_semver_matches_semantic_version_oracle(a, b):
    SemVer = _oracle_semver()
    try:
        sa, sb = SemVer(a), SemVer(b)
    except Exception:
        # See the note above: `skip` here silently disabled the whole cross-check.
        assume(False)
    expected = (sa > sb) - (sa < sb)
    got = compare(a, b, VersionScheme.SEMVER)
    assert got == expected


class TestHypothesisCrossChecksActuallyRun:
    """A `pytest.skip()` inside a `@given` test skips the test, not the example.

    This was a real defect found in M51: `test_semver_matches_semantic_version_oracle`
    called `pytest.skip("generated string rejected by the oracle itself")` when the
    oracle refused one generated string. Inside `@given`, that aborts the *whole* test
    on the first such example — so the cross-check reported "skipped" and its remaining
    149 examples never ran. It looked like an unavailable dependency and was in fact an
    unresolved coverage gap.

    The fix is `assume(False)`, which discards one example. This test guards it: no
    `@given` function in this module may call `pytest.skip`/`skip` for an *example*
    condition. Module-level oracle availability checks remain fine, and they live in
    helper functions outside the `@given` body.
    """

    def test_no_given_test_calls_skip_in_its_body(self):
        import ast
        import pathlib

        source = pathlib.Path(__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)

        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            decorated = {
                getattr(dec, "id", None)
                or getattr(getattr(dec, "func", None), "id", None)
                for dec in node.decorator_list
            }
            if "given" not in decorated:
                continue
            for inner in ast.walk(node):
                if not isinstance(inner, ast.Call):
                    continue
                func = inner.func
                name = getattr(func, "attr", None) or getattr(func, "id", None)
                if name == "skip":
                    offenders.append((node.name, inner.lineno))
        assert not offenders, (
            "these @given tests call skip() inside the test body, which aborts the "
            "whole property on one bad example instead of discarding it: "
            f"{offenders}. Use hypothesis.assume() instead."
        )

    def test_the_oracle_helpers_still_skip_when_the_dependency_is_missing(self):
        """An absent oracle must still skip loudly: that part is correct.

        Checked by calling the helper, not by matching its source text.
        """
        import builtins
        import sys

        saved = {name: sys.modules.pop(name)
                 for name in ("semantic_version", "packaging") if name in sys.modules}
        real_import = builtins.__import__

        def _no_semver(name, *args, **kwargs):
            if name == "semantic_version":
                raise ImportError("simulated absence")
            return real_import(name, *args, **kwargs)

        try:
            builtins.__import__ = _no_semver
            with pytest.raises(pytest.skip.Exception):
                _oracle_semver()
        finally:
            builtins.__import__ = real_import
            sys.modules.update(saved)
