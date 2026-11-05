"""Debian evidence cross-referencing into canonical records (B-04 integration).

Join discipline: CVE id only. TEMP/DSA keys never become CVEs, no text/package
similarity merging, idempotent re-ingestion, conflicts recorded as data.
"""

from __future__ import annotations

from datetime import datetime, timezone

from vuln_intel.connectors.debian import snapshot_from_document
from vuln_intel.crossref import merge_debian_evidence
from vuln_intel.schema import AffectedPackage, CveId, NormalizedVulnerability, Origin

NOW = datetime(2026, 6, 2, tzinfo=timezone.utc)

TRACKER = {
    "log4j-core": {
        "CVE-2021-44228": {
            "description": "Log4Shell",
            "releases": {
                "bookworm": {"status": "resolved", "fixed_version": "2.19.0-2+deb12u1"},
                "bullseye": {"status": "open"},
            },
        },
        "TEMP-9999": {"description": "not a CVE", "releases": {"sid": {"status": "open"}}},
    },
    "openssl": {
        "CVE-2026-1111": {
            "description": "x",
            "releases": {"bookworm": {"status": "resolved", "fixed_version": "3.0.11-1"}},
        }
    },
}


def _snap() -> object:
    return snapshot_from_document(
        TRACKER, fetched_at=NOW, origin=Origin.FIXTURE, transport="unaudited"
    )


def _record(cve="CVE-2021-44228", affected=()) -> NormalizedVulnerability:
    return NormalizedVulnerability(
        cve=CveId.parse(cve), origin=Origin.FIXTURE, sources=("nvd",),
        affected=tuple(affected),
    )


class TestMerge:
    def test_debian_fixed_versions_join_by_cve_only(self):
        (merged, report) = merge_debian_evidence([_record()], _snap())
        assert report.records_matched == 1
        assert report.affected_added == 2  # bookworm resolved + bullseye open
        fixed = {a.fixed for a in merged[0].affected if a.fixed}
        assert "2.19.0-2+deb12u1" in fixed
        assert all(a.ecosystem == "debian" for a in merged[0].affected)
        assert "debian-security-tracker" in merged[0].sources
        assert any(p.source == "debian-security-tracker" for p in merged[0].provenance)

    def test_temp_and_dsa_keys_never_become_cves_or_joins(self):
        records = [_record("CVE-2021-44228")]
        (merged, report) = merge_debian_evidence(records, _snap())
        # TEMP-9999 must not have produced a record or a join
        assert all(str(r.cve).startswith("CVE-") for r in merged)
        assert "TEMP-9999" not in report.unmatched_cves  # it is not a CVE at all

    def test_repeated_ingestion_is_idempotent(self):
        snap = _snap()
        (once, _r1) = merge_debian_evidence([_record()], snap)
        (twice, r2) = merge_debian_evidence(once, snap)
        assert r2.affected_added == 0 and r2.conflicts == 0
        assert twice[0].affected == once[0].affected
        assert len(twice[0].provenance) == len(once[0].provenance)
        assert len(twice[0].sources) == len(once[0].sources)

    def test_conflicting_fixed_version_is_kept_and_recorded(self):
        existing = AffectedPackage(ecosystem="debian", name="log4j-core",
                                   fixed="9.9.9-1")
        (merged, report) = merge_debian_evidence([_record(affected=[existing])], _snap())
        assert report.conflicts == 1
        kept = {a.fixed for a in merged[0].affected if a.name == "log4j-core"}
        assert "9.9.9-1" in kept            # existing value kept
        assert "2.19.0-2+deb12u1" not in kept  # conflicting tracker value discarded
        conflict = merged[0].conflicts[0]
        assert conflict.field == "affected.fixed"
        assert "2.19.0-2+deb12u1" in conflict.discarded
        assert merged[0].conflict_notes  # prose and structured forms agree

    def test_multiple_releases_all_preserved(self):
        (merged, _) = merge_debian_evidence([_record()], _snap())
        names_fixed = {(a.name, a.fixed) for a in merged[0].affected}
        assert ("log4j-core", "2.19.0-2+deb12u1") in names_fixed
        assert ("log4j-core", None) in names_fixed  # bullseye still open

    def test_cve_with_no_canonical_record_is_reported_unmatched(self):
        (_, report) = merge_debian_evidence([_record("CVE-2021-44228")], _snap())
        assert report.unmatched_cves == ("CVE-2026-1111",)

    def test_inputs_are_not_mutated(self):
        original = _record()
        before = original.affected
        merge_debian_evidence([original], _snap())
        assert original.affected == before
