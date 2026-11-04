"""Reproducible performance benchmarks.

Run with ``python -m vuln_intel.benchmark`` (or ``--json`` for machine output).

Why this exists: `tests/test_performance.py` guards against *regressions* with
loose ceilings, which is right for CI but useless for capacity planning — it tells
you "not catastrophically slow", not "how many CVEs per second". This harness gives
the actual numbers, records the environment they were measured in, and prints a
single block that can be pasted into an operations document and compared later.

Every measurement is reported with its methodology, because a benchmark without
one is a rumour: see ``METHODOLOGY``.
"""

from __future__ import annotations

import json
import platform
import statistics
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable

__all__ = ["METHODOLOGY", "Benchmark", "environment", "run_all"]

METHODOLOGY = {
    "timing": "perf_counter around a tight loop; warm-up pass discarded",
    "reported": "median of repeats, milliseconds unless stated",
    "single_core": "no thread or process pool; these are per-worker figures",
    "data": "synthetic records built in-process; no network and no disk",
    "caveat": (
        "Synthetic records are simpler than real NVD payloads: no long description, "
        "fewer references. Real-world ingest will be slower per record. These "
        "numbers bound the intelligence layer, not JSON deserialization."
    ),
}


def environment() -> dict[str, Any]:
    """Everything needed to interpret the numbers, including the hardware."""
    import os

    machine = platform.machine()
    # `os.cpu_count()` returns None rather than raising when it cannot determine
    # the value, so there is nothing to catch here.
    cpus = os.cpu_count()
    return {
        "python": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": machine,
        "cpu_count": cpus,
        "note": "container; shared CPU. Absolute numbers vary by host, ratios are stable.",
    }


@dataclass
class Benchmark:
    name: str
    unit: str
    iterations: int
    function: Callable[[], object]
    repeat: int = 3
    samples: list[float] = field(default_factory=list)

    def measure(self) -> dict[str, Any]:
        self.samples.clear()
        # Warm-up: first-call import and attribute caching would otherwise be
        # attributed to the workload.
        self.function()
        for _ in range(self.repeat):
            started = time.perf_counter()
            for _ in range(self.iterations):
                self.function()
            self.samples.append((time.perf_counter() - started) / self.iterations)
        median = statistics.median(self.samples)
        return {
            "name": self.name,
            "unit": self.unit,
            "iterations": self.iterations,
            "median_ms": round(median * 1000, 4),
            "per_second": round(1.0 / median, 1) if median else None,
            "spread_pct": (
                round(
                    100.0
                    * (max(self.samples) - min(self.samples))
                    / statistics.median(self.samples),
                    1,
                )
                if median
                else None
            ),
        }


def _record(index: int):
    from .schema import CveId, CvssScore, NormalizedVulnerability, Origin, Severity

    return NormalizedVulnerability(
        cve=CveId.parse(f"CVE-2026-{index:05d}"),
        origin=Origin.LIVE,
        sources=("nvd", "osv"),
        cvss=(
            CvssScore(
                version="4.0", base_score=7.5, severity=Severity.HIGH, assessed=True
            ),
        ),
    )


def run_all() -> dict[str, Any]:
    """Execute every benchmark and return a JSON-safe report."""
    from .correlation import correlate
    from .cvss import score_vector
    from .cvss40 import score_vector_v4
    from .integration.api import shape_record
    from .priorities import rank_vulnerabilities

    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    v3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    row = {
        "cve": "CVE-2026-0001",
        "entity_id": "entity-tenant-a-CVE-2026-0001",
        "origin": "live",
        "collected_at": None,
        "details": {
            "summary": "synthetic summary",
            "cicc_enrichment": {"severity": "high", "kev": True, "epss": 0.42},
        },
    }

    small = [_record(index) for index in range(500)]
    medium = [_record(index) for index in range(2_000)]
    large = [_record(index) for index in range(5_000)]

    benchmarks = [
        Benchmark("cvss_v4_score", "vector", 2_000, lambda: score_vector_v4(v4)),
        Benchmark("cvss_v3_score", "vector", 2_000, lambda: score_vector(v3)),
        Benchmark("shape_record", "record", 20_000, lambda: shape_record(row)),
        Benchmark("score_vulnerability", "record", 200, lambda: _score_many(small)),
        Benchmark("rank_500", "batch", 5, lambda: rank_vulnerabilities(small)),
        Benchmark("rank_2000", "batch", 3, lambda: rank_vulnerabilities(medium)),
        # Prebuilt list: measures ranking only, not record construction.
        Benchmark(
            "rank_prebuilt_5000", "record", 1, lambda: _rank_prebuilt(large), repeat=5
        ),
        # Kept for visibility: includes building 5,000 records per iteration, so it
        # is an end-to-end ingest-style figure, not a ranking throughput number.
        Benchmark("build_and_rank_5000", "batch", 3, lambda: _build_and_rank(5_000)),
        Benchmark("correlate_500", "batch", 5, lambda: correlate(small)),
        Benchmark("correlate_5000", "batch", 3, lambda: correlate(large)),
    ]

    results = [benchmark.measure() for benchmark in benchmarks]
    return {
        "environment": environment(),
        "methodology": METHODOLOGY,
        "results": results,
        "derived": _derived(results),
    }


def _rank_prebuilt(records):
    """Rank a prebuilt list; reported per record by dividing by its length."""
    from .priorities import rank_vulnerabilities

    rank_vulnerabilities(records)
    return len(records)


def _build_and_rank(count: int):
    from .priorities import rank_vulnerabilities

    return rank_vulnerabilities([_record(index) for index in range(count)])


def _score_many(records):
    from .priorities import score_vulnerability

    for record in records:
        score_vulnerability(record)
    return len(records)


def _derived(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Per-record figures that operators plan with.

    Deliberately *not* computed from ``rank_5000``: those lambdas build five
    thousand record objects on every iteration, so dividing by 5,000 would report
    object construction as ranking throughput. The throughput figure comes from the
    prebuilt-list benchmark instead.
    """
    by_name = {item["name"]: item for item in results}
    out: dict[str, Any] = {}
    per_record_ms = by_name.get("rank_prebuilt_5000", {}).get("median_ms")
    if per_record_ms:
        out["rank_records_per_second"] = round(1_000_000.0 / per_record_ms, 1)
        out["rank_microseconds_per_record"] = round(per_record_ms, 3)
    return out


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    report = run_all()
    if "--json" in args:
        print(json.dumps(report, indent=2))
        return 0
    env = report["environment"]
    print("Vulnerability Intelligence benchmarks")
    print(f"  python {env['python']} on {env['platform']} ({env['machine']}, "
          f"{env['cpu_count']} cpus)")
    print(f"  {env['note']}")
    print()
    print(f"  {'benchmark':<24} {'ms':>10} {'per second':>14} {'spread':>8}")
    for item in report["results"]:
        print(
            f"  {item['name']:<24} {item['median_ms']:>10.4f} "
            f"{item['per_second']!s:>14} {str(item['spread_pct']) + '%':>8}"
        )
    derived = report["derived"]
    if derived:
        print()
        print(f"  ranking throughput: {derived['rank_records_per_second']:,.1f} records/s "
              f"({derived['rank_microseconds_per_record']} us per record, prebuilt input)")
    print()
    print(f"  methodology: {report['methodology']['timing']}; "
          f"{report['methodology']['reported']}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
