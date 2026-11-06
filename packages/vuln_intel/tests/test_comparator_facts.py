"""Known-truth facts about Maven and RubyGems ordering, enforced on every run.

These come from ``tests/fixtures/comparator_facts.json``, which is also what
``scripts/generate_runtime_vectors.sh`` validates its generated evidence against. Two
consumers, one file, so the harness and the suite cannot drift into disagreeing about
what upstream does.

Why this file exists separately from the two vector suites:

* ``test_version_ordering_maven_oracle.py`` and its RubyGems twin compare us against a
  *hand-transcribed* corpus. That corpus has now been wrong twice (a ``1-SNAPSHOT`` in
  the wrong slot, then ``2.0.a``/``2-1`` swapped plus an entry that does not exist
  upstream), and both times the comparator had been written to match, so the suite
  passed while the behaviour was wrong.
* This module is the opposite shape: a short list of facts quoted from the upstream
  sources, with the ``why`` recorded, that fails if our comparator or the corpus drifts.

It needs no JVM and no Ruby, so it runs in the ordinary ``test`` job on every commit
rather than only in the opt-in runtime job. That is deliberate: the expensive oracle is
advisory and skips when a runtime is absent, and a check that skips is not a check.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from vuln_intel.versions import VersionScheme, compare

FACTS_FILE = pathlib.Path(__file__).parent / "fixtures" / "comparator_facts.json"

_SCHEME = {"maven": VersionScheme.MAVEN, "rubygems": VersionScheme.RUBYGEMS}


def _facts() -> dict:
    payload = json.loads(FACTS_FILE.read_text(encoding="utf-8"))
    assert payload.get("schema") == "cicc.vuln_intel.comparator_facts.v1", (
        f"{FACTS_FILE.name} has an unexpected schema; the generator reads this file too "
        "and a silent shape change would disable both checks at once"
    )
    return payload


def _rows() -> list[tuple[str, str, str, int, str]]:
    out = []
    for family, rows in _facts()["families"].items():
        assert family in _SCHEME, f"unknown family {family!r} in {FACTS_FILE.name}"
        for row in rows:
            out.append((family, row["left"], row["right"], row["expected"], row["why"]))
    return out


class TestTheComparatorMatchesKnownUpstreamTruth:
    @pytest.mark.parametrize(
        ("family", "left", "right", "expected", "why"),
        _rows(),
        ids=[f"{f}:{a}-vs-{b}" for f, a, b, _, _ in _rows()],
    )
    def test_fact(self, family, left, right, expected, why):
        got = compare(left, right, scheme=_SCHEME[family])
        assert got == expected, f"{family}: {left!r} vs {right!r} should be {expected}, got {got} — {why}"

    @pytest.mark.parametrize(
        ("family", "left", "right", "expected", "why"),
        _rows(),
        ids=[f"{f}:{b}-vs-{a}" for f, a, b, _, _ in _rows()],
    )
    def test_fact_is_antisymmetric(self, family, left, right, expected, why):
        """Every ordering fact implies its mirror; a one-way comparator is a defect."""
        got = compare(right, left, scheme=_SCHEME[family])
        assert got == -expected, (
            f"{family}: {right!r} vs {left!r} should be {-expected}, got {got} — {why}"
        )


class TestTheFactsFileIsSelfConsistent:
    def test_both_families_are_covered(self):
        families = _facts()["families"]
        assert set(families) == {"maven", "rubygems"}

    def test_every_fact_records_why_it_is_true(self):
        """A fact without a provenance note cannot be re-verified when it starts failing."""
        for family, left, right, _expected, why in _rows():
            assert why and len(why) > 8, f"{family} {left} vs {right} has no useful 'why'"

    def test_the_two_families_genuinely_disagree_somewhere(self):
        """If they agreed everywhere, a crossed bucket would be undetectable.

        The generator relies on this too: it asserts these pairs in *both* families, so
        one bucket's answers cannot silently stand in for the other's.
        """
        disagreements = [
            (left, right, expected)
            for family, left, right, expected, _ in _rows()
            if family == "maven"
            and compare(left, right, scheme=VersionScheme.RUBYGEMS) not in (None, expected)
        ]
        assert disagreements, (
            "no fact distinguishes Maven from RubyGems, so the generator's bucket-crossing "
            "check cannot fail; add at least one"
        )
