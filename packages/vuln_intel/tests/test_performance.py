"""Performance guardrails.

These are *regression detectors*, not benchmarks: the ceilings are deliberately
generous (an order of magnitude above measured values on a laptop) so they fail
only on accidental complexity, never on a slow CI runner.

Measured on Python 3.11 / 2 vCPU sandbox (recorded 2026-11):

| operation                          | measured      | ceiling here |
|------------------------------------|---------------|--------------|
| build observations, 10k            | 0.17 s        | 5 s          |
| normalize 5k records               | 0.007 s       | 2 s          |
| rank 5k records                    | 0.056 s       | 3 s          |
| sha256 digest of one payload       | 7 µs          | —            |
| payload JSON, per 1000 obs.        | 428 KB        | —            |
| correlate 10k records              | 0.065 s       | 4 s          |
| exposure 5k inventory x 5k adv.    | 0.063 s       | 5 s          |
| affected-version verdict, 1 record  | < 50 µs       | —            |
"""

from __future__ import annotations

import json
import time

import pytest

from vuln_intel.integration.observations import digest_payload, to_observations
from vuln_intel.normalization import normalize_sources
from vuln_intel.priorities import rank_vulnerabilities
from vuln_intel.schema import CveId, CvssScore, NormalizedVulnerability, Origin, Severity

from .conftest import FIXED_NOW

SCALE = 5000


def _affected(name: str):
    """Small helper so the scaling tests describe intent, not construction."""
    from vuln_intel.schema import AffectedPackage

    return (
        AffectedPackage(ecosystem="npm", name=name, introduced="0", fixed="2.0.0"),
    )


def _records(count: int) -> list[NormalizedVulnerability]:
    return [
        NormalizedVulnerability(
            cve=CveId.parse(f"CVE-2026-{i:05d}"),
            origin=Origin.LIVE,
            sources=("nvd", "osv"),
            severity=Severity.HIGH,
            cvss=(CvssScore("3.1", 8.1, Severity.HIGH, vector="v", source="nvd"),),
            epss_score=0.5,
            epss_percentile=0.9,
            kev=i % 10 == 0,
        )
        for i in range(1, count + 1)
    ]


def test_observation_building_scales_linearly() -> None:
    records = _records(SCALE)
    started = time.perf_counter()
    observations = []
    for record in records:
        observations.extend(to_observations(record, tenant_id="t1", collected_at=FIXED_NOW))
    elapsed = time.perf_counter() - started
    assert len(observations) == SCALE * 2
    assert elapsed < 5.0, f"observation building took {elapsed:.2f}s for {SCALE} records"


def test_normalization_and_ranking_are_fast_enough() -> None:
    records = _records(SCALE)

    started = time.perf_counter()
    merged = normalize_sources(records)
    normalize_elapsed = time.perf_counter() - started
    assert len(merged) == SCALE
    assert normalize_elapsed < 2.0

    started = time.perf_counter()
    ranking = rank_vulnerabilities(list(merged.values()))
    rank_elapsed = time.perf_counter() - started
    assert len(ranking) == SCALE
    assert rank_elapsed < 3.0, f"ranking took {rank_elapsed:.2f}s for {SCALE} records"


def test_ranking_is_sorted_at_scale() -> None:
    ranking = rank_vulnerabilities(_records(SCALE))
    scores = [result.score for result in ranking]
    assert scores == sorted(scores, reverse=True)


def test_digest_is_deterministic_and_cheap() -> None:
    payload = {"cve": "CVE-2026-00001", "details": "x" * 500}
    first = digest_payload(payload)
    for _ in range(1000):
        assert digest_payload(payload) == first


def test_payload_size_stays_bounded() -> None:
    """A single observation must stay small enough to store in a JSONB column."""
    record = _records(1)[0]
    observation = to_observations(record, tenant_id="t1", collected_at=FIXED_NOW)[0]
    size = len(json.dumps(observation.payload))
    assert size < 20_000, f"observation payload is {size} bytes; review before storage"


class TestIntelligenceLayerScaling:
    """The intelligence layer must stay near-linear in the number of records.

    A quadratic correlation or exposure pass would make a realistic estate
    (thousands of dependencies) unusable, so the shapes are pinned here.
    """

    def test_correlation_scales_linearly(self):
        from vuln_intel.correlation import correlate

        records = [
            NormalizedVulnerability(
                cve=CveId.parse(f"CVE-2024-{1000 + i}"),
                origin=Origin.LIVE,
                sources=("nvd",),
            )
            for i in range(SCALE * 2)
        ]
        started = time.perf_counter()
        clusters = correlate(records)
        elapsed = time.perf_counter() - started
        assert len(clusters) == SCALE * 2
        assert elapsed < 4.0, f"correlate {len(records)} records took {elapsed:.3f}s"

    def test_exposure_scales_with_inventory_size(self):
        from vuln_intel.watchlist import Dependency, Inventory, analyse_exposure

        inventory = Inventory(
            dependencies=tuple(
                Dependency(
                    ecosystem="npm", name=f"pkg-{i}", version="1.0.0", asset=f"svc-{i % 20}"
                )
                for i in range(SCALE)
            )
        )
        advisories = [
            NormalizedVulnerability(
                cve=CveId.parse(f"CVE-2024-{1000 + i}"),
                origin=Origin.LIVE,
                affected=_affected(f"pkg-{i}"),
                sources=("osv",),
            )
            for i in range(SCALE)
        ]
        started = time.perf_counter()
        report = analyse_exposure(inventory, advisories)
        elapsed = time.perf_counter() - started
        assert len(report.affected) == SCALE
        assert elapsed < 5.0, f"exposure scan took {elapsed:.3f}s"

    def test_affected_verdict_is_cheap_enough_for_per_asset_evaluation(self):
        from vuln_intel.affected import assess_affected

        packages = _affected("pkg")
        started = time.perf_counter()
        for _ in range(2000):
            assess_affected(packages, ecosystem="npm", name="pkg", version="1.0.0")
        elapsed = time.perf_counter() - started
        assert elapsed < 1.0, f"2000 verdicts took {elapsed:.3f}s"


class TestBenchmarkHarness:
    """The benchmark module produces numbers that get pasted into operations docs.

    A benchmark that silently measures the wrong thing is worse than no benchmark:
    it becomes a planning input. `rank_5000` originally built 5,000 records inside
    the timed loop, so dividing by 5,000 reported object construction as ranking
    throughput.
    """

    def test_report_is_json_safe_and_complete(self):
        import json

        from vuln_intel.benchmark import run_all

        report = run_all()
        json.dumps(report)
        assert report["results"]
        for item in report["results"]:
            assert item["median_ms"] > 0
            assert item["per_second"] is not None

    def test_environment_is_recorded(self):
        """A number without its environment is a rumour."""
        from vuln_intel.benchmark import environment

        env = environment()
        assert env["python"]
        assert env["platform"]
        assert env["note"]

    def test_methodology_is_stated(self):
        from vuln_intel.benchmark import METHODOLOGY

        for key in ("timing", "reported", "data", "caveat"):
            assert METHODOLOGY[key]

    def test_derived_throughput_uses_a_prebuilt_input(self):
        """Deriving throughput from a benchmark that constructs its own data would
        report construction cost as ranking cost."""
        from vuln_intel.benchmark import run_all

        report = run_all()
        names = {item["name"] for item in report["results"]}
        assert "rank_prebuilt_5000" in names
        assert report["derived"]["rank_records_per_second"] > 0

    def test_every_benchmark_reports_a_spread(self):
        """Spread is how a reader knows whether to trust a single number."""
        from vuln_intel.benchmark import run_all

        for item in run_all()["results"]:
            assert item["spread_pct"] is not None


class TestCachedPropertiesCannotGoStale:
    """`best_cvss` and `effective_severity` are cached for speed.

    A cache on a mutable object would silently serve an old answer after
    enrichment, which would corrupt every score and ranking downstream. The record
    is frozen, so mutation is impossible — but `dataclasses.replace` is how the
    pipeline builds enriched copies, and it must produce a *fresh* cache.
    """

    def _record(self, score=5.0, version="3.1"):
        from vuln_intel.schema import CveId, CvssScore, NormalizedVulnerability, Origin, Severity

        return NormalizedVulnerability(
            cve=CveId.parse("CVE-2026-0001"),
            origin=Origin.LIVE,
            cvss=(
                CvssScore(
                    version=version, base_score=score, severity=Severity.MEDIUM, assessed=True
                ),
            ),
        )

    def test_replace_does_not_inherit_the_cached_value(self):
        from dataclasses import replace

        original = self._record(5.0, "3.1")
        assert original.best_cvss is not None
        assert original.best_cvss.base_score == 5.0

        enriched = replace(original, kev=True)
        assert enriched.best_cvss is not None
        assert enriched.best_cvss.base_score == 5.0  # unchanged input, unchanged answer

    def test_replace_with_new_cvss_recomputes(self):
        from dataclasses import replace

        from vuln_intel.schema import CvssScore, Severity

        original = self._record(5.0, "3.1")
        assert original.best_cvss is not None  # populate the cache

        upgraded = replace(
            original,
            cvss=(
                CvssScore(
                    version="4.0", base_score=9.8, severity=Severity.CRITICAL, assessed=True
                ),
            ),
        )
        assert upgraded.best_cvss is not None
        assert upgraded.best_cvss.base_score == 9.8
        # And the original is untouched, so a cache cannot leak between records.
        assert original.best_cvss is not None
        assert original.best_cvss.base_score == 5.0

    def test_effective_severity_does_not_stick_after_replace(self):
        from dataclasses import replace

        from vuln_intel.schema import CvssScore, Severity

        original = self._record(5.0, "3.1")
        assert original.effective_severity is Severity.MEDIUM
        raised = replace(
            original,
            cvss=(
                CvssScore(
                    version="4.0", base_score=9.8, severity=Severity.CRITICAL, assessed=True
                ),
            ),
        )
        assert raised.effective_severity is Severity.CRITICAL

    def test_record_is_actually_frozen(self):
        """If this ever becomes mutable, the caches above become a correctness bug."""
        import dataclasses

        from vuln_intel.schema import NormalizedVulnerability

        assert dataclasses.fields(NormalizedVulnerability), "sanity"
        record = self._record()
        try:
            record.kev = True  # type: ignore[misc]
        except dataclasses.FrozenInstanceError:
            return
        raise AssertionError(
            "NormalizedVulnerability is mutable; cached properties are now unsafe"
        )


class TestBenchmarkNormalisation:
    """The harness must divide by the work it actually did.

    A benchmark that reports 5.3 ms for an operation taking 10 us is worse than no
    benchmark: it invites an optimisation project against a number that is wrong by
    two orders of magnitude. Both defects here were found by noticing that the
    reported figures were absurd, not by any test — so these tests exist now.
    """

    def test_items_per_call_divides_the_elapsed_time(self) -> None:
        from vuln_intel.benchmark import Benchmark

        calls = []

        def work():
            calls.append(1)
            return

        single = Benchmark("single", "item", 12, work).measure()
        batch = Benchmark("batch", "item", 12, work, items_per_call=10).measure()
        # Same work per call, so the per-item figure must be ten times smaller.
        assert batch["median_ms"] < single["median_ms"]
        assert single["median_ms"] / batch["median_ms"] == pytest.approx(10, rel=0.4)

    def test_items_per_call_is_reported(self) -> None:
        from vuln_intel.benchmark import Benchmark

        result = Benchmark("x", "item", 2, lambda: None, items_per_call=7).measure()
        assert result["items_per_call"] == 7

    def test_derived_throughput_is_not_double_divided(self) -> None:
        """`median_ms` is already per record; dividing again gave 84M records/s."""
        from vuln_intel.benchmark import _derived

        derived = _derived([{"name": "rank_prebuilt_5000", "median_ms": 0.01}])
        assert derived["rank_records_per_second"] == pytest.approx(100_000, rel=0.01)
        assert derived["rank_ms_per_record"] == pytest.approx(0.01, rel=0.01)

    def test_end_to_end_benchmark_is_not_used_for_throughput(self) -> None:
        """It builds its own records, so it measures construction, not ranking."""
        from vuln_intel.benchmark import _derived

        derived = _derived([{"name": "build_and_rank_5000", "median_ms": 121.0}])
        assert derived == {}
