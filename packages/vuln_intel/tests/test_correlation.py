"""Identity, correlation and deduplication.

These cases are the ones where a wrong merge changes a security decision:
double-counting a CVE, collapsing two CVEs into one, or letting a fixture record
inherit a live record's identity.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from vuln_intel.correlation import (
    AdvisoryIdentity,
    ClusterIndex,
    correlate,
    resolve_identity,
)
from vuln_intel.errors import MixedOriginError
from vuln_intel.schema import CveId, NormalizedVulnerability, Origin

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def record(
    cve: str,
    *,
    aliases: tuple[str, ...] = (),
    sources: tuple[str, ...] = ("nvd",),
    origin: Origin = Origin.LIVE,
) -> NormalizedVulnerability:
    return NormalizedVulnerability(
        cve=CveId.parse(cve),
        origin=origin,
        aliases=aliases,
        sources=sources,
        published=NOW,
        modified=NOW,
    )


class TestIdentifierRecognition:
    @pytest.mark.parametrize(
        ("raw", "kind"),
        [
            ("CVE-2024-1234", "cve"),
            ("cve-2024-1234", "cve"),
            ("GHSA-aaaa-bbbb-cccc", "ghsa"),
            ("PYSEC-2024-1", "pysec"),
            ("GO-2024-1234", "go"),
            ("RUSTSEC-2024-0001", "rustsec"),
            ("RHSA-2024:1234", "rhsa"),
            ("USN-6789-1", "usn"),
            ("DSA-5678-1", "debian"),
        ],
    )
    def test_recognised_families(self, raw, kind):
        identity = AdvisoryIdentity.parse(raw)
        assert identity is not None
        assert identity.kind == kind

    @pytest.mark.parametrize("raw", ["", "   ", "not-an-id", "CVE-24-1", "GHSA-1234"])
    def test_unrecognised_input_is_none(self, raw):
        assert AdvisoryIdentity.parse(raw) is None

    def test_identifiers_are_upper_normalised(self):
        assert AdvisoryIdentity.parse("ghsa-aaaa-bbbb-cccc").value == "GHSA-AAAA-BBBB-CCCC"


class TestIdentityResolution:
    def test_cve_is_preferred(self):
        resolution = resolve_identity(cve="CVE-2024-1234", advisory_id="GHSA-aaaa-bbbb-cccc")
        assert resolution.primary == "CVE-2024-1234"
        assert not resolution.unresolved

    def test_advisory_only_is_unresolved_not_invented(self):
        """OSV advisories without a CVE must not be given a synthetic identifier."""
        resolution = resolve_identity(cve=None, advisory_id="GHSA-aaaa-bbbb-cccc")
        assert resolution.primary == "GHSA-AAAA-BBBB-CCCC"
        assert resolution.unresolved is True

    def test_no_identifier_at_all_is_unresolved(self):
        resolution = resolve_identity(cve=None, advisory_id=None)
        assert resolution.unresolved is True
        assert resolution.primary == ""

    def test_aliases_are_merged_without_duplicates(self):
        resolution = resolve_identity(
            cve="CVE-2024-1234",
            aliases=["GHSA-aaaa-bbbb-cccc", "cve-2024-1234", "junk"],
        )
        values = [i.value for i in resolution.identifiers]
        assert values.count("CVE-2024-1234") == 1
        assert "GHSA-AAAA-BBBB-CCCC" in values
        assert any("junk" in reason for reason in resolution.reasons)

    def test_multiple_cves_are_flagged_not_silently_picked(self):
        resolution = resolve_identity(
            cve="CVE-2024-2222", aliases=["CVE-2024-1111"]
        )
        assert any("several CVEs" in reason for reason in resolution.reasons)


class TestCorrelation:
    def test_alias_joins_two_records_into_one_cluster(self):
        clusters = correlate(
            [
                record("CVE-2024-1234", sources=("nvd",)),
                record(
                    "CVE-2024-1234",
                    aliases=("GHSA-aaaa-bbbb-cccc",),
                    sources=("osv", "nvd"),
                ),
            ]
        )
        assert len(clusters) == 1
        assert clusters[0].sources == ("nvd", "osv")
        assert "GHSA-AAAA-BBBB-CCCC" in clusters[0].identifier_map

    def test_distinct_cves_stay_distinct(self):
        clusters = correlate([record("CVE-2024-1111"), record("CVE-2024-2222")])
        assert len(clusters) == 2

    def test_shared_package_name_does_not_merge(self):
        """Two different defects in one package are two findings, not one."""
        left = record("CVE-2024-1111")
        right = record("CVE-2024-2222")
        assert len(correlate([left, right])) == 2

    def test_mixed_origins_are_refused(self):
        with pytest.raises(MixedOriginError):
            correlate(
                [
                    record("CVE-2024-1234", origin=Origin.LIVE),
                    record("CVE-2024-1234", origin=Origin.FIXTURE, sources=("osv",)),
                ]
            )

    def test_caller_supplied_alias_can_join(self):
        clusters = correlate(
            [record("CVE-2024-1111"), record("CVE-2024-2222")],
            extra_aliases={"CVE-2024-2222": ["RHSA-2024:9999"]},
        )
        # A relationship the caller asserts is used, but nothing is guessed.
        assert len(clusters) == 2
        index = ClusterIndex(clusters)
        assert index.find("RHSA-2024:9999").identity == "CVE-2024-2222"

    def test_empty_input(self):
        assert correlate([]) == ()

    def test_cluster_serialization_is_auditable(self):
        clusters = correlate(
            [record("CVE-2024-1234"), record("CVE-2024-1234", aliases=("GHSA-aaaa-bbbb-cccc",))]
        )
        payload = clusters[0].as_dict()
        assert payload["identity"] == "CVE-2024-1234"
        assert payload["record_count"] == 2
        assert payload["identifier_map"]

    def test_merged_view_keeps_origin(self):
        clusters = correlate(
            [record("CVE-2024-1234"), record("CVE-2024-1234", sources=("osv",))]
        )
        assert clusters[0].merged.origin is Origin.LIVE


class TestClusterIndex:
    def test_lookup_by_any_identifier(self):
        index = ClusterIndex(
            correlate(
                [record("CVE-2024-1234", aliases=("GHSA-aaaa-bbbb-cccc",), sources=("osv",))]
            )
        )
        assert index.find("cve-2024-1234") is not None
        assert index.find("ghsa-aaaa-bbbb-cccc") is not None
        assert index.find("CVE-2024-0000") is None

    def test_missing_identifier_is_none(self):
        index = ClusterIndex(correlate([record("CVE-2024-1234")]))
        assert index.find("") is None
