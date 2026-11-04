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
