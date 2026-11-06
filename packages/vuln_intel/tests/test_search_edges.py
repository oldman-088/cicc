"""Search edge cases beyond the core ranking tests."""

from __future__ import annotations

import pytest

from vuln_intel.schema import CveId, NormalizedVulnerability, Origin
from vuln_intel.search import search_records


def _rec(cve: str, summary: str = "", details: str = "", kev: bool | None = None,
         aliases: tuple[str, ...] = ()) -> NormalizedVulnerability:
    return NormalizedVulnerability(
        cve=CveId.parse(cve), origin=Origin.FIXTURE, summary=summary,
        details=details, kev=kev, aliases=aliases, sources=("osv",),
    )


RECS = [
    _rec("CVE-2026-0001", summary="log4shell remote code execution", kev=True,
         aliases=("GHSA-jfh8-c2jp-5v3q",)),
    _rec("CVE-2026-0002", summary="sql injection in login", kev=None),
    _rec("CVE-2026-0003", details="buffer overflow in parser"),
]


class TestSearchEdges:
    def test_punctuation_only_query_returns_nothing(self):
        assert search_records(RECS, "!!! ... ---") == ()

    def test_alias_token_matches_as_identity(self):
        hits = search_records(RECS, "ghsa-jfh8-c2jp-5v3q")
        assert len(hits) == 1 and hits[0].record.cve == CveId.parse("CVE-2026-0001")
        assert "id" in hits[0].matched_fields

    def test_multi_term_scores_accumulate(self):
        hits = search_records(RECS, "log4shell remote code")
        assert hits[0].score >= 30  # 3 summary terms at 10 each

    def test_kev_none_is_excluded_by_kev_only_not_treated_as_false(self):
        hits = search_records(RECS, "sql injection", kev_only=True)
        assert hits == ()  # CVE-2026-0002 has kev=None (not consulted), not False

    def test_limit_boundary(self):
        assert len(search_records(RECS, "a", limit=1)) <= 1
        with pytest.raises(ValueError):
            search_records(RECS, "a", limit=0)

    def test_tie_breaks_on_cve_ascending(self):
        recs = [
            _rec("CVE-2026-0009", summary="shared word"),
            _rec("CVE-2026-0004", summary="shared word"),
        ]
        hits = search_records(recs, "shared")
        assert [str(h.record.cve) for h in hits] == ["CVE-2026-0004", "CVE-2026-0009"]

    def test_kev_bonus_is_disclosed_in_score(self):
        plain = search_records([_rec("CVE-2026-0001", summary="x")], "x")[0].score
        kev = search_records([_rec("CVE-2026-0001", summary="x", kev=True)], "x")[0].score
        assert kev - plain == 5
