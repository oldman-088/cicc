"""Cross-checks against the *real* Maven and RubyGems implementations, when present.

This is the executable half of B-17 and the only file in the suite that can claim a
true differential result for those two schemes.

Read this before trusting any number from it:

* The vectors in ``tests/fixtures/runtime_vectors.json`` are produced by running
  Apache's ``ComparableVersion`` on a JVM and RubyGems' ``Gem::Version`` on MRI, via
  ``scripts/generate_runtime_vectors.sh``. If that file is absent, **these tests skip**
  and the suite still reports Maven and RubyGems as *vector-verified only*.
* A skip here is not a pass. The banner printed by ``conftest.py`` and the CI
  ``oracle`` job's gate both exist so that a missing file cannot make a green run look
  like a cross-check.
* The file records the java and ruby versions that produced it, so a reader can see
  which runtime the answers came from rather than assuming.

Generating it requires a JDK and a Ruby:

    ./scripts/generate_runtime_vectors.sh
    git add tests/fixtures/runtime_vectors.json

In an environment with both, the CI job ``maven-rubygems-runtime`` runs the generator
and these tests. Where either runtime is missing, ``B-17`` stays open and
``ORACLE_VALIDATION.md`` says so.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from vuln_intel.versions import VersionScheme, compare

VECTOR_FILE = pathlib.Path(__file__).parent / "fixtures" / "runtime_vectors.json"

pytestmark = pytest.mark.oracle

REGENERATE = "run: ./scripts/generate_runtime_vectors.sh"


def _load() -> dict:
    if not VECTOR_FILE.exists():
        pytest.skip(
            f"no runtime vectors at {VECTOR_FILE.name}; {REGENERATE}. "
            "Maven/RubyGems are vector-verified only until this file exists, so this "
            "cross-check did NOT run. This is NOT a pass."
        )
    payload = json.loads(VECTOR_FILE.read_text(encoding="utf-8"))
    if payload.get("schema") != "cicc.vuln_intel.runtime_vectors.v1":
        pytest.fail(
            f"{VECTOR_FILE.name} has schema {payload.get('schema')!r}, expected "
            "cicc.vuln_intel.runtime_vectors.v1; regenerate with " + REGENERATE
        )
    return payload


@pytest.fixture(scope="module")
def vectors() -> dict:
    return _load()


def _diff(scheme: VersionScheme, pairs: list) -> list[str]:
    """Compare our answer with the runtime's for every pair. Returns disagreements."""
    problems: list[str] = []
    for left, right, expected in pairs:
        actual = compare(left, right, scheme=scheme)
        if actual is None:
            problems.append(f"{left!r} vs {right!r}: we returned None, runtime said {expected}")
        elif actual != expected:
            problems.append(f"{left!r} vs {right!r}: we said {actual}, runtime said {expected}")
    if problems:
        # Emit GitHub workflow commands so each disagreement becomes a check annotation.
        # Without this the only copy of the evidence is the job log, and a failure that
        # says "N disagreements" without naming any of them is a failure someone has to
        # reproduce by hand. Annotations are readable from the API, so the evidence
        # travels even when the log does not.
        for problem in problems[:20]:
            print(f"::error title={scheme.value} disagreement::{problem}")
        if len(problems) > 20:
            print(f"::warning::{len(problems) - 20} further disagreement(s) not annotated")
    return problems


class TestVectorFileIsTrustworthy:
    def test_it_records_which_runtimes_produced_it(self, vectors):
        runtimes = vectors.get("runtimes") or {}
        assert runtimes.get("java"), "the file must name the java version: evidence, not assertion"
        assert runtimes.get("ruby"), "the file must name the ruby version"

    def test_it_is_not_empty(self, vectors):
        assert len(vectors["maven"]["pairs"]) > 0
        assert len(vectors["rubygems"]["pairs"]) > 0

    def test_every_answer_is_a_sign(self, vectors):
        """ComparableVersion's raw return is unspecified beyond its sign."""
        for family in ("maven", "rubygems"):
            for left, right, value in vectors[family]["pairs"]:
                assert value in (-1, 0, 1), f"{family} {left} vs {right} -> {value}"


class TestMavenAgainstTheRealComparableVersion:
    def test_every_pair_agrees(self, vectors):
        problems = _diff(VersionScheme.MAVEN, vectors["maven"]["pairs"])
        assert not problems, (
            f"{len(problems)} disagreement(s) with Apache ComparableVersion:\n  "
            + "\n  ".join(problems[:20])
        )


class TestRubyGemsAgainstTheRealGemVersion:
    def test_every_pair_agrees(self, vectors):
        problems = _diff(VersionScheme.RUBYGEMS, vectors["rubygems"]["pairs"])
        assert not problems, (
            f"{len(problems)} disagreement(s) with RubyGems Gem::Version:\n  "
            + "\n  ".join(problems[:20])
        )
