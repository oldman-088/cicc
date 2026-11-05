"""Schema invariants: identity validation, explicit origin, conflict-safe merging."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vuln_intel.errors import MixedOriginError, ValidationError
from vuln_intel.schema import (
    CveId,
    CvssScore,
    FieldConflict,
    NormalizedVulnerability,
    Origin,
    RecordStatus,
    Severity,
    compute_freshness,
    merge_records,
    parse_timestamp,
    strictest_status,
)

from .conftest import FIXED_NOW


def record(**overrides):
    base = dict(
        cve=CveId.parse("CVE-2026-0001"),
        origin=Origin.FIXTURE,
        sources=("nvd",),
        severity=Severity.HIGH,
    )
    base.update(overrides)
    return NormalizedVulnerability(**base)


@pytest.mark.parametrize("value", ["CVE-2026-0001", "cve-2026-0001"])
def test_cve_id_parses_and_normalizes(value: str) -> None:
    assert str(CveId.parse(value)) == "CVE-2026-0001"


@pytest.mark.parametrize(
    "value",
    [
        None,
        1234,
        "CVE-99-1",          # year too short
        "CVE-1200-1234",     # year before CVE existed
        "CVE-2026-12",       # number too short
        "CVE-2026-12345678", # number too long
        "GHSA-aaaa-bbbb-cccc",
        " CVE-2026-0001/../",
    ],
)
def test_cve_id_rejects_malformed_values(value: object) -> None:
    with pytest.raises(ValidationError):
        CveId.parse(value)


def test_records_require_explicit_origin() -> None:
    with pytest.raises(ValidationError):
        NormalizedVulnerability(cve=CveId.parse("CVE-2026-0001"), origin="live")  # type: ignore[arg-type]


def test_naive_timestamps_are_rejected() -> None:
    with pytest.raises(ValidationError):
        NormalizedVulnerability(
            cve=CveId.parse("CVE-2026-0001"),
            origin=Origin.LIVE,
            published=datetime(2026, 1, 1),  # naive
        )


def test_parse_timestamp_handles_osv_and_nvd_forms() -> None:
    assert parse_timestamp("2026-01-01T00:00:00Z", field_name="t") == datetime(
        2026, 1, 1, tzinfo=timezone.utc
    )
    # NVD's naive form is documented as UTC.
    assert parse_timestamp("2026-01-01T00:00:00.000", field_name="t") == datetime(
        2026, 1, 1, tzinfo=timezone.utc
    )
    assert parse_timestamp(None, field_name="t") is None
    with pytest.raises(ValidationError):
        parse_timestamp("not-a-date", field_name="t")


def test_mixing_origins_is_refused() -> None:
    with pytest.raises(MixedOriginError):
        merge_records(
            [record(origin=Origin.LIVE), record(origin=Origin.DEMO, sources=("osv",))]
        )


def test_merge_refuses_different_cves() -> None:
    with pytest.raises(ValidationError):
        merge_records([record(), record(cve=CveId.parse("CVE-2026-0002"))])


def test_merge_records_disagreement_is_recorded_not_overwritten() -> None:
    low = record(severity=Severity.MEDIUM, sources=("nvd",))
    high = record(severity=Severity.CRITICAL, sources=("osv",))
    merged = merge_records([low, high])
    # Highest severity is kept (a downgrade must be a human decision)...
    assert merged.effective_severity is Severity.CRITICAL
    # ...and the disagreement is visible.
    assert any("severity disagreement" in note for note in merged.conflict_notes)
    assert merged.sources == ("nvd", "osv")


def test_merge_marks_conflicting_cvss_versions() -> None:
    a = record(cvss=(CvssScore("3.1", 9.8, Severity.CRITICAL, vector="v-a", source="a"),))
    b = record(cvss=(CvssScore("3.1", 7.5, Severity.HIGH, vector="v-b", source="b"),))
    merged = merge_records([a, b])
    assert len(merged.cvss) == 2
    assert any("CVSS 3.1 disagreement" in note for note in merged.conflict_notes)


def test_merge_keeps_verification_conservative() -> None:
    merged = merge_records([record(), record(sources=("osv",))])
    assert merged.verification == "unverified"


def test_merge_keeps_strongest_kev_and_epss_signals() -> None:
    merged = merge_records(
        [
            record(kev=False, epss_score=0.1, epss_percentile=0.5),
            record(kev=True, epss_score=0.9, epss_percentile=0.99, sources=("cisa-kev",)),
        ]
    )
    assert merged.kev is True
    assert merged.epss_score == 0.9
    assert any("CISA KEV" in note for note in merged.conflict_notes)


def test_epss_bounds_are_enforced() -> None:
    with pytest.raises(ValidationError):
        record(epss_score=1.5)
    with pytest.raises(ValidationError):
        record(epss_percentile=-0.1)


def test_best_cvss_ignores_unassessed_and_v2() -> None:
    rec = record(
        cvss=(
            CvssScore("2.0", 10.0, Severity.CRITICAL, assessed=True),
            CvssScore("3.1", 0.0, Severity.UNKNOWN, assessed=False),
            CvssScore("3.1", 6.5, Severity.MEDIUM, vector="v", source="nvd"),
        )
    )
    assert rec.best_cvss is not None
    assert rec.best_cvss.base_score == 6.5


def test_freshness_buckets_and_unknown() -> None:
    assert compute_freshness(None).bucket == "unknown"
    fresh = compute_freshness(FIXED_NOW - timedelta(hours=1), now=FIXED_NOW)
    assert fresh.bucket == "fresh" and not fresh.is_stale
    recent = compute_freshness(FIXED_NOW - timedelta(days=2), now=FIXED_NOW)
    assert recent.bucket == "recent"
    stale = compute_freshness(FIXED_NOW - timedelta(days=20), now=FIXED_NOW)
    assert stale.bucket == "stale" and stale.is_stale
    expired = compute_freshness(FIXED_NOW - timedelta(days=400), now=FIXED_NOW)
    assert expired.bucket == "expired"


def test_as_summary_never_fabricates_scores() -> None:
    summary = record().as_summary()
    assert summary["cvss_base_score"] is None
    assert summary["epss_score"] is None
    assert summary["origin"] == "fixture"


class TestRecordStanding:
    """Disputed, withdrawn and in-analysis records are a different kind of claim.

    The failure this prevents is quiet: a record every source has withdrawn still
    merges, still scores, and still appears in a remediation queue, because nothing
    in the pipeline knew it was no longer a claim.
    """

    @staticmethod
    def _record(**kwargs):
        base = dict(cve=CveId.parse("CVE-2026-5000"), origin=Origin.FIXTURE)
        base.update(kwargs)
        return NormalizedVulnerability(**base)

    def test_default_is_unstated_not_published(self) -> None:
        """Silence must not be promoted to a guarantee."""
        record = self._record()
        assert record.record_status is None
        assert record.is_actionable_claim is None

    def test_rejected_is_not_an_actionable_claim(self) -> None:
        record = self._record(record_status=RecordStatus.REJECTED)
        assert record.is_actionable_claim is False

    def test_published_is_actionable(self) -> None:
        assert self._record(record_status=RecordStatus.PUBLISHED).is_actionable_claim is True

    def test_disputed_is_still_actionable_but_flagged(self) -> None:
        asserted = self._record(record_status=RecordStatus.DISPUTED)
        assert asserted.is_actionable_claim is True

    def test_invalid_status_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            self._record(record_status="probably_fine")  # type: ignore[arg-type]

    def test_strictest_status_prefers_the_cautious_reading(self) -> None:
        assert (
            strictest_status([RecordStatus.PUBLISHED, RecordStatus.DISPUTED])
            is RecordStatus.DISPUTED
        )
        assert (
            strictest_status([RecordStatus.DISPUTED, RecordStatus.REJECTED])
            is RecordStatus.REJECTED
        )

    def test_strictest_status_ignores_unspecified_sources(self) -> None:
        assert strictest_status([None, RecordStatus.PUBLISHED]) is RecordStatus.PUBLISHED
        assert strictest_status([None, None]) is None

    def test_merge_keeps_the_most_cautious_standing(self) -> None:
        merged = merge_records(
            [
                self._record(record_status=RecordStatus.PUBLISHED, sources=("nvd",)),
                self._record(record_status=RecordStatus.REJECTED, sources=("osv",)),
            ]
        )
        assert merged.record_status is RecordStatus.REJECTED
        assert any("standing" in n for n in merged.conflict_notes)

    def test_merge_does_not_invent_standing_from_silence(self) -> None:
        merged = merge_records([self._record(sources=("nvd",)), self._record(sources=("osv",))])
        assert merged.record_status is None

    def test_merge_keeps_the_earliest_withdrawal(self) -> None:
        from datetime import datetime, timezone

        early = datetime(2024, 1, 1, tzinfo=timezone.utc)
        late = datetime(2025, 1, 1, tzinfo=timezone.utc)
        merged = merge_records(
            [
                self._record(withdrawn=late, sources=("osv",)),
                self._record(withdrawn=early, sources=("nvd",)),
            ]
        )
        assert merged.withdrawn == early


class TestMergeKeepsSsvc:
    def test_ssvc_survives_corroboration(self) -> None:
        """Merging used to drop every SSVC input, losing CISA's assessment."""
        inputs = (("automatable", "yes"), ("exploitation", "active"),
                  ("technical_impact", "total"))
        merged = merge_records(
            [
                NormalizedVulnerability(
                    cve=CveId.parse("CVE-2026-5001"), origin=Origin.FIXTURE,
                    ssvc=inputs, sources=("nvd",),
                ),
                NormalizedVulnerability(
                    cve=CveId.parse("CVE-2026-5001"), origin=Origin.FIXTURE,
                    ssvc=inputs, sources=("osv",),
                ),
            ]
        )
        assert dict(merged.ssvc) == {
            "automatable": "yes",
            "exploitation": "active",
            "technical_impact": "total",
        }

    def test_conflicting_ssvc_input_is_dropped_and_reported(self) -> None:
        """A disagreement must not be resolved by whichever record came first."""
        merged = merge_records(
            [
                NormalizedVulnerability(
                    cve=CveId.parse("CVE-2026-5002"), origin=Origin.FIXTURE,
                    ssvc=(("exploitation", "active"), ("automatable", "yes")),
                    sources=("nvd",),
                ),
                NormalizedVulnerability(
                    cve=CveId.parse("CVE-2026-5002"), origin=Origin.FIXTURE,
                    ssvc=(("exploitation", "none"), ("automatable", "yes")),
                    sources=("osv",),
                ),
            ]
        )
        merged_inputs = dict(merged.ssvc)
        assert "exploitation" not in merged_inputs
        assert merged_inputs["automatable"] == "yes"
        assert any("SSVC input 'exploitation' disagrees" in n for n in merged.conflict_notes)


class TestStructuredConflicts:
    """Disagreements are data, not only prose.

    `conflict_notes` said what happened but nothing could *count* it: "how many
    records have a disputed severity?" needed an English parser, and a UI could not
    filter by field. `FieldConflict` is the structured half, generated from the same
    decision so the two views cannot drift.
    """

    @staticmethod
    def _rec(**kwargs):
        base = dict(cve=CveId.parse("CVE-2026-8000"), origin=Origin.FIXTURE)
        base.update(kwargs)
        return NormalizedVulnerability(**base)

    def test_a_conflict_requires_something_discarded(self) -> None:
        """An entry with nothing discarded would describe unanimity."""
        with pytest.raises(ValidationError):
            FieldConflict(field="severity", kept="high", discarded=())

    def test_a_conflict_requires_a_field_name(self) -> None:
        with pytest.raises(ValidationError):
            FieldConflict(field="", kept="high", discarded=("critical",))

    def test_agreement_produces_no_conflict(self) -> None:
        merged = merge_records(
            [
                self._rec(severity=Severity.HIGH, sources=("nvd",)),
                self._rec(severity=Severity.HIGH, sources=("osv",)),
            ]
        )
        assert merged.conflicts == ()

    def test_severity_disagreement_is_structured_with_dissenters(self) -> None:
        merged = merge_records(
            [
                self._rec(severity=Severity.CRITICAL, sources=("nvd",)),
                self._rec(severity=Severity.HIGH, sources=("osv",)),
            ]
        )
        conflict = next(c for c in merged.conflicts if c.field == "severity")
        assert conflict.kept == "critical"
        assert conflict.discarded == ("high",)
        # The source that said "high" disagreed with what was kept.
        assert conflict.dissenters == ("osv",)

    def test_discarded_values_are_retained_not_just_counted(self) -> None:
        """`pick()` kept the earliest and threw the rest away entirely."""
        merged = merge_records(
            [
                self._rec(summary="first", sources=("nvd",)),
                self._rec(summary="second", sources=("osv",)),
                self._rec(summary="third", sources=("ghsa",)),
            ]
        )
        conflict = next(c for c in merged.conflicts if c.field == "summary")
        assert conflict.kept == "first"
        assert conflict.discarded == ("second", "third")
        assert conflict.dissenters == ("ghsa", "osv")

    def test_notes_and_conflicts_describe_the_same_disagreements(self) -> None:
        """The invariant that keeps the two views honest.

        Every structured conflict must have a prose note and vice versa. Without
        this, a future field could get one form and not the other.
        """
        merged = merge_records(
            [
                self._rec(
                    severity=Severity.CRITICAL, summary="a", epss_score=0.9,
                    kev=True, sources=("nvd",),
                ),
                self._rec(
                    severity=Severity.HIGH, summary="b", epss_score=0.2,
                    kev=False, sources=("osv",),
                ),
            ]
        )
        assert merged.conflicts, "expected disagreements"
        assert merged.conflict_notes
        joined = " ".join(merged.conflict_notes).lower()
        for conflict in merged.conflicts:
            root = conflict.field.split(".")[0]
            assert root.lower() in joined, f"{conflict.field} has no note"

    def test_conflict_serialises_for_the_api(self) -> None:
        conflict = FieldConflict(
            field="severity", kept="critical", discarded=("high",), dissenters=("osv",)
        )
        assert conflict.as_dict() == {
            "field": "severity",
            "kept": "critical",
            "discarded": ["high"],
            "dissenters": ["osv"],
        }


class TestMergeHandlesMoreThanTwoSources:
    """Three-source corroboration crashed, and nothing tested it.

    `_merge_cvss(left, right)` was called as `_merge_cvss(*(i.cvss for i in items))`,
    so any CVE confirmed by three sources raised TypeError. Two is the convenient
    number for a test; three is the normal number for a widely-reported CVE.
    """

    def test_three_records_merge(self) -> None:
        merged = merge_records(
            [
                NormalizedVulnerability(
                    cve=CveId.parse("CVE-2026-8100"), origin=Origin.FIXTURE,
                    sources=(name,), summary=name,
                )
                for name in ("nvd", "osv", "ghsa")
            ]
        )
        assert merged.sources == ("ghsa", "nvd", "osv")
        assert merged.cvss == ()

    def test_ten_records_merge(self) -> None:
        merged = merge_records(
            [
                NormalizedVulnerability(
                    cve=CveId.parse("CVE-2026-8101"), origin=Origin.FIXTURE,
                    sources=(f"src{index}",),
                )
                for index in range(10)
            ]
        )
        assert len(merged.sources) == 10

    def test_three_sources_with_three_different_cvss_scores(self) -> None:
        def rec(score, source):
            return NormalizedVulnerability(
                cve=CveId.parse("CVE-2026-8102"), origin=Origin.FIXTURE,
                sources=(source,),
                cvss=(CvssScore(
                    version="3.1", base_score=score, severity=Severity.HIGH,
                    source=source,
                ),),
            )

        merged = merge_records([rec(5.0, "a"), rec(7.5, "b"), rec(9.8, "c")])
        conflict = next(c for c in merged.conflicts if c.field.startswith("cvss"))
        assert conflict.kept == "9.8"
        assert set(conflict.discarded) == {"5.0", "7.5"}
        # Highest is what ranking reads, so it must be what survives.
        assert max(s.base_score for s in merged.cvss) == 9.8


class TestSilentCvssUnderReporting:
    """Two scores differing only by value were collapsed as duplicates.

    Same version, no vector, no source set: the second score was silently dropped, so
    a record could under-report its own severity with no note and no conflict entry.
    """

    @staticmethod
    def _rec(score):
        return NormalizedVulnerability(
            cve=CveId.parse("CVE-2026-8200"), origin=Origin.FIXTURE, sources=("x",),
            cvss=(CvssScore(version="3.1", base_score=score, severity=Severity.HIGH),),
        )

    def test_differing_scores_are_not_collapsed(self) -> None:
        merged = merge_records([self._rec(7.1), self._rec(9.8)])
        assert {s.base_score for s in merged.cvss} == {7.1, 9.8}

    def test_the_disagreement_is_reported(self) -> None:
        merged = merge_records([self._rec(7.1), self._rec(9.8)])
        assert any("CVSS 3.1 disagreement" in n for n in merged.conflict_notes)
        assert any(c.field == "cvss.3.1" for c in merged.conflicts)

    def test_identical_scores_are_still_deduplicated(self) -> None:
        """Deduplication is correct; it was only wrong when values differed."""
        merged = merge_records([self._rec(9.8), self._rec(9.8)])
        assert len(merged.cvss) == 1
        assert merged.conflicts == ()

    def test_the_specification_version_is_not_mistaken_for_a_score(self) -> None:
        """Regression: a regex recovery step put "3.1" among the discarded scores."""
        merged = merge_records([self._rec(7.1), self._rec(9.8)])
        conflict = next(c for c in merged.conflicts if c.field.startswith("cvss"))
        assert conflict.kept == "9.8"
        assert "3.1" not in conflict.discarded
