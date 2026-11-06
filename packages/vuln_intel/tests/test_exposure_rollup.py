"""B-08 pure rollup: dedup, conflict, freshness and calculated confidence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from vuln_intel.assessment import workflow_for
from vuln_intel.exposure_rollup import rollup_exposures
from vuln_intel.schema import AffectedPackage, CveId, NormalizedVulnerability, Origin
from vuln_intel.watchlist import Dependency, Inventory

T0 = datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc)


def _report(cve="CVE-2026-0001", pkg="log4j-core", version="2.14.1", asset="payments",
            kev=False, run_at=T0, eco="maven", fixed="2.15.0"):
    rec = NormalizedVulnerability(
        cve=CveId.parse(cve), origin=Origin.FIXTURE, kev=kev,
        affected=(AffectedPackage(ecosystem=eco, name=pkg, introduced="1.0", fixed=fixed),),
        sources=("nvd",),
    )
    inv = Inventory(dependencies=(Dependency(ecosystem=eco, name=pkg, version=version,
                                              asset=asset),))
    return workflow_for(records=[rec], inventory=inv, now=lambda: run_at)


class TestRollup:
    def test_affected_asset_appears_with_dedup_across_runs(self):
        r1 = _report(run_at=T0)
        r2 = _report(run_at=T0 + timedelta(hours=1))
        rollup = rollup_exposures([r1, r2], now=T0 + timedelta(hours=2))
        assert rollup.assets_at_risk == ("payments",)
        (asset,) = rollup.assets
        assert asset.affected == (("CVE-2026-0001", "log4j-core", "2.14.1"),)
        assert asset.distinct_cves == 1
        assert asset.confidence == "high"
        assert rollup.newest_input == T0 + timedelta(hours=1)

    def test_kev_flag_propagates_to_kev_affected(self):
        rollup = rollup_exposures([_report(kev=True)], now=T0)
        assert rollup.assets[0].kev_affected == ("CVE-2026-0001",)

    def test_stale_input_lowers_confidence_but_is_kept_and_labelled(self):
        old = _report(run_at=T0 - timedelta(days=30))
        fresh = _report(run_at=T0)
        rollup = rollup_exposures([old, fresh], now=T0, max_age=timedelta(days=7))
        assert rollup.stale_inputs == (T0 - timedelta(days=30),)
        assert rollup.assets[0].confidence == "low"

    def test_conflicting_verdict_keeps_affected_and_flags(self):
        # older run says affected, newer run has a fixed (not_affected) install
        old = _report(version="2.14.1", run_at=T0)
        new = _report(version="2.15.0", run_at=T0 + timedelta(hours=1))
        rollup = rollup_exposures([old, new], now=T0 + timedelta(hours=2))
        # different installed versions -> different triples, no conflict
        assert rollup.assets_at_risk == ("payments",)
        # now the SAME triple with disagreeing verdicts across runs:
        old2 = _report(version="2.14.1", run_at=T0)
        rec_fixed = NormalizedVulnerability(
            cve=CveId.parse("CVE-2026-0001"), origin=Origin.FIXTURE,
            affected=(AffectedPackage(ecosystem="maven", name="log4j-core",
                                      introduced="1.0", fixed="2.14.1"),),  # installed == fixed -> NOT_AFFECTED
            sources=("nvd",),
        )
        inv = Inventory(dependencies=(Dependency(ecosystem="maven", name="log4j-core",
                                                  version="2.14.1", asset="payments"),))
        new2 = workflow_for(records=[rec_fixed], inventory=inv,
                            now=lambda: T0 + timedelta(hours=1))
        rollup2 = rollup_exposures([old2, new2], now=T0 + timedelta(hours=2))
        (asset,) = [a for a in rollup2.assets if a.asset == "payments"]
        assert asset.affected == (("CVE-2026-0001", "log4j-core", "2.14.1"),)
        assert asset.conflicted == (("CVE-2026-0001", "log4j-core", "2.14.1"),)

    def test_empty_input_is_an_empty_rollup_not_an_error(self):
        rollup = rollup_exposures([], now=T0)
        assert rollup.assets == () and rollup.assets_at_risk == ()
        assert rollup.newest_input is None

    def test_serialises(self):
        import json

        rollup = rollup_exposures([_report()], now=T0)
        json.dumps(rollup.as_dict())
