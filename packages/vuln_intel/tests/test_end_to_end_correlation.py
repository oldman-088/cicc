"""End-to-end: Debian + Ubuntu + GHSA evidence -> canonical records -> search.

The full path, not isolated connectors:

    tracker/USN/GHSA documents
      -> snapshots -> to_vulnerability_records -> merge_debian_evidence
      -> correlate (extra_aliases only from source evidence)
      -> affected-version evaluation -> search results
      -> re-ingest -> idempotent
"""

from __future__ import annotations

from datetime import datetime, timezone

from vuln_intel.affected import Verdict, assess_affected
from vuln_intel.connectors.debian import snapshot_from_document as debian_snap
from vuln_intel.connectors.debian import to_vulnerability_records as debian_records
from vuln_intel.connectors.ghsa import snapshot_from_document as ghsa_snap
from vuln_intel.connectors.ghsa import to_vulnerability_records as ghsa_records
from vuln_intel.connectors.ubuntu import snapshot_from_document as usn_snap
from vuln_intel.connectors.ubuntu import to_vulnerability_records as usn_records
from vuln_intel.correlation import correlate
from vuln_intel.crossref import merge_debian_evidence
from vuln_intel.schema import AffectedPackage, CveId, NormalizedVulnerability, Origin
from vuln_intel.search import search_records

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)

DEBIAN_DOC = {
    "log4j-core": {
        "CVE-2021-44228": {
            "description": "Log4Shell",
            "releases": {
                "bookworm": {"status": "resolved", "fixed_version": "2.19.0-2+deb12u1"},
                "bullseye": {"status": "open"},
            },
        },
        "TEMP-1": {"description": "not a cve", "releases": {"sid": {"status": "open"}}},
    }
}

USN_DOC = {
    "USN-6000-1": {
        "title": "log4j vulnerability", "cves": ["CVE-2021-44228"], "severity": "critical",
        "published": "2021-12-10T00:00:00Z",
        "releases": {"jammy": {"sources": {"log4j-core": {
            "status": "released", "fixed_version": "2.17.1-0ubuntu0.1"}}}},
    }
}

GHSA_DOC = [
    {
        "ghsa_id": "GHSA-jfh8-c2jp-5v3q", "cve_id": "CVE-2021-44228",
        "summary": "Log4Shell", "severity": "critical",
        "vulnerabilities": [{"package": {"ecosystem": "Maven", "name": "log4j-core"},
                             "vulnerable_version_range": ">= 2.0, < 2.15.0",
                             "first_patched_version": "2.15.0"}],
        "references": ["https://github.com/advisories/GHSA-jfh8-c2jp-5v3q"],
    },
    {"ghsa_id": "GHSA-only-0001", "cve_id": None, "summary": "no cve", "severity": "low",
     "vulnerabilities": [], "references": []},
]

NVD_REC = NormalizedVulnerability(
    cve=CveId.parse("CVE-2021-44228"), origin=Origin.FIXTURE,
    summary="Log4Shell in log4j", kev=True,
    affected=(AffectedPackage(ecosystem="maven", name="log4j-core",
                              introduced="2.0", fixed="2.15.0"),),
    sources=("nvd",),
)


def _pipeline():
    deb = debian_snap(DEBIAN_DOC, fetched_at=NOW, origin=Origin.FIXTURE, transport="unaudited")
    usn = usn_snap(USN_DOC, fetched_at=NOW, origin=Origin.FIXTURE, transport="unaudited")
    ghsa = ghsa_snap(GHSA_DOC, fetched_at=NOW, origin=Origin.FIXTURE, transport="unaudited")
    records = [
        NVD_REC,
        *debian_records(deb),
        *usn_records(usn),
        *ghsa_records(ghsa),
    ]
    merged, xref = merge_debian_evidence(records, deb)
    # extra_aliases only from source evidence: USN and GHSA ids published against the CVE
    extra = {"CVE-2021-44228": ["USN-6000-1", "GHSA-jfh8-c2jp-5v3q"]}
    clusters = correlate(merged, extra_aliases=extra)
    return clusters, xref, deb, usn, ghsa


class TestEndToEnd:
    def test_all_sources_merge_into_one_cluster(self):
        clusters, _xref, *_ = _pipeline()
        cves = {str(c.merged.cve) for c in clusters}
        assert cves == {"CVE-2021-44228"}  # GHSA-only advisory fabricated nothing
        (cluster,) = clusters
        sources = set(cluster.merged.sources)
        assert {"nvd", "debian-security-tracker", "ubuntu-usn", "github-advisories"} <= sources
        assert "USN-6000-1" in cluster.merged.aliases
        assert "GHSA-jfh8-c2jp-5v3q" in cluster.merged.aliases
        assert "TEMP-1" not in cluster.merged.aliases

    def test_release_specific_evidence_stays_distinct(self):
        clusters, *_ = _pipeline()
        affected = {(a.ecosystem, a.name, a.fixed) for a in clusters[0].merged.affected}
        assert ("debian", "log4j-core", "2.19.0-2+deb12u1") in affected  # debian bookworm
        assert ("debian", "log4j-core", None) in affected                  # debian bullseye open
        assert ("ubuntu", "log4j-core", "2.17.1-0ubuntu0.1") in affected    # ubuntu jammy
        assert ("maven", "log4j-core", "2.15.0") in affected                # ghsa/nvd

    def test_affected_version_evaluation_on_merged_record(self):
        clusters, *_ = _pipeline()
        merged = clusters[0].merged
        v = assess_affected(merged.affected, ecosystem="maven", name="log4j-core",
                            version="2.14.1")
        assert v.verdict is Verdict.AFFECTED
        v2 = assess_affected(merged.affected, ecosystem="maven", name="log4j-core",
                             version="2.15.0")
        assert v2.verdict is Verdict.NOT_AFFECTED

    def test_search_finds_the_merged_record(self):
        clusters, *_ = _pipeline()
        hits = search_records([c.merged for c in clusters], "log4shell")
        assert hits and str(hits[0].record.cve) == "CVE-2021-44228"

    def test_reingestion_is_idempotent(self):
        clusters1, _xref1, deb, *_ = _pipeline()
        merged_again, xref2 = merge_debian_evidence(
            [c.merged for c in clusters1], deb
        )
        assert xref2.affected_added == 0
        clusters2 = correlate(merged_again, extra_aliases={"CVE-2021-44228": ["USN-6000-1", "GHSA-jfh8-c2jp-5v3q"]})
        assert len(clusters2) == len(clusters1)
        # merge order of the affected list is not part of the contract; content is
        assert sorted(map(repr, clusters2[0].merged.affected)) == sorted(map(repr, clusters1[0].merged.affected))

    def test_conflicting_fixed_versions_recorded_not_merged_away(self):
        # GHSA says 2.15.0, a hypothetical second source says 2.17.0 for maven
        other = NormalizedVulnerability(
            cve=CveId.parse("CVE-2021-44228"), origin=Origin.FIXTURE,
            affected=(AffectedPackage(ecosystem="maven", name="log4j-core",
                                      introduced="2.0", fixed="2.17.0"),),
            sources=("osv",),
        )
        deb = debian_snap(DEBIAN_DOC, fetched_at=NOW, origin=Origin.FIXTURE, transport="unaudited")
        records = [NVD_REC, other, *debian_records(deb)]
        merged, _ = merge_debian_evidence(records, deb)
        clusters = correlate(merged)
        assert len(clusters) == 1
        assert clusters[0].merged.conflicts  # disagreement is structured data
