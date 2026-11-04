"""Cross-source normalization: merging, KEV signalling and origin separation."""

from __future__ import annotations

import pytest

from vuln_intel.connectors.epss import EpssScore, parse_epss_response
from vuln_intel.errors import MixedOriginError, ValidationError
from vuln_intel.normalization import (
    KevSignal,
    attach_epss,
    attach_kev,
    corroboration_report,
    index_kev,
    normalize_sources,
)
from vuln_intel.schema import CveId, CvssScore, NormalizedVulnerability, Origin, Severity

from . import fixtures as fx
from .conftest import FIXED_NOW


def rec(cve="CVE-2026-0001", *, origin=Origin.FIXTURE, sources=("nvd",), **kwargs):
    return NormalizedVulnerability(
        cve=CveId.parse(cve), origin=origin, sources=sources, **kwargs
    )


def test_kev_index_uses_catalogue_version_and_dates() -> None:
    index = index_kev(fx.KEV_CATALOG)
    assert set(index) == {"CVE-2026-0001", "CVE-2021-44228"}
    signal = index["CVE-2021-44228"]
    assert signal.listed is True
    assert signal.checked is True
    assert signal.catalog_version == "2026.01.01"
    assert signal.date_added is not None and signal.date_added.year == 2021


def test_kev_index_rejects_broken_catalog() -> None:
    with pytest.raises(ValidationError):
        index_kev({"vulnerabilities": "nope"})
    with pytest.raises(ValidationError):
        index_kev({"vulnerabilities": [{"cveID": "BAD"}]})


def test_kev_not_consulted_stays_unknown() -> None:
    """Absence of KEV data must never be rendered as 'not exploited'."""
    att = attach_kev(rec(), None)
    assert att.kev is None
    assert att.known_exploited is None
    assert any("not consulted" in note for note in att.conflict_notes)


def test_kev_listed_and_unlisted() -> None:
    index = index_kev(fx.KEV_CATALOG)
    listed = attach_kev(rec("CVE-2026-0001"), index["CVE-2026-0001"])
    assert listed.kev is True and listed.known_exploited is True
    assert "cisa-kev" in listed.sources
    assert listed.provenance[-1].source == "cisa-kev"

    unlisted = attach_kev(rec("CVE-2026-0001"), KevSignal(CveId.parse("CVE-2026-0001"), listed=False))
    assert unlisted.kev is False


def test_kev_signal_for_wrong_cve_is_rejected() -> None:
    with pytest.raises(ValidationError):
        attach_kev(rec("CVE-2026-0001"), KevSignal(CveId.parse("CVE-2026-0002"), listed=True))


def test_normalize_groups_and_merges_same_cve() -> None:
    merged = normalize_sources(
        [
            rec(sources=("nvd",), severity=Severity.HIGH),
            rec(sources=("osv",), severity=Severity.CRITICAL),
            rec("CVE-2026-0002", sources=("nvd",)),
        ]
    )
    assert set(merged) == {"CVE-2026-0001", "CVE-2026-0002"}
    combined = merged["CVE-2026-0001"]
    assert combined.sources == ("nvd", "osv")
    assert combined.effective_severity is Severity.CRITICAL
    assert combined.verification == "unverified"


def test_normalize_refuses_to_mix_demo_and_live() -> None:
    with pytest.raises(MixedOriginError):
        normalize_sources([rec(origin=Origin.LIVE), rec(origin=Origin.DEMO, sources=("osv",))])


def test_epss_attachment_respects_origin() -> None:
    live = rec(origin=Origin.LIVE)
    fixture_score = EpssScore(
        cve=CveId.parse("CVE-2026-0001"),
        score=0.9,
        percentile=0.99,
        model_date="2026-01-01",
        observed_at=FIXED_NOW,
        origin="fixture",
    )
    with pytest.raises(MixedOriginError):
        attach_epss(live, fixture_score)

    fixture_record = rec(origin=Origin.FIXTURE)
    attached = attach_epss(fixture_record, fixture_score)
    assert attached.epss_score == pytest.approx(0.9)
    assert "epss" in attached.sources


def test_epss_parsed_fixture_round_trip_through_normalization() -> None:
    scores = parse_epss_response(fx.EPSS_RESPONSE, observed_at=FIXED_NOW, origin="fixture")
    enriched = attach_epss(rec("CVE-2026-0001"), scores["CVE-2026-0001"])
    assert enriched.epss_score == pytest.approx(0.9447)
    assert enriched.epss_model_date == "2026-01-01"


def test_missing_epss_stays_none() -> None:
    assert attach_epss(rec(), None).epss_score is None


def test_corroboration_report_flags_single_source_and_freshness() -> None:
    merged = normalize_sources(
        [
            rec(
                sources=("nvd",),
                modified=FIXED_NOW,
                cvss=(CvssScore("3.1", 9.8, Severity.CRITICAL, vector="v", source="nvd"),),
            )
        ]
    )
    report = corroboration_report(list(merged.values()), now=FIXED_NOW)
    assert report[0]["corroborated"] is False
    assert report[0]["source_count"] == 1
    assert report[0]["freshness"] == "fresh"


def test_corroboration_report_marks_two_sources_as_corroborated() -> None:
    merged = normalize_sources([rec(sources=("nvd",)), rec(sources=("osv",))])
    report = corroboration_report(list(merged.values()), now=FIXED_NOW)
    assert report[0]["corroborated"] is True
    assert report[0]["source_count"] == 2
    assert report[0]["freshness"] == "unknown"  # no timestamps -> unknown, not "fresh"
