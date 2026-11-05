"""Search: exact-token matching, calculated relevance, no false correlations."""

from __future__ import annotations

import pytest

from vuln_intel.schema import CveId, NormalizedVulnerability, Origin
from vuln_intel.search import search_records


def _rec(cve, summary=None, kev=None, aliases=(), details=None):
    return NormalizedVulnerability(
        cve=CveId.parse(cve), origin=Origin.FIXTURE, summary=summary,
        kev=kev, aliases=aliases, details=details,
    )


RECS = [
    _rec("CVE-2021-44228", summary="Log4Shell JNDI lookup in log4j", kev=True),
    _rec("CVE-2026-0001", summary="Heap overflow in libfoo", kev=None),
    _rec("CVE-2026-0002", summary="log4j connector misconfiguration", aliases=("GHSA-xxxx-yyyy-zzzz",)),
]


class TestSearch:
    def test_identity_match_outranks_prose(self):
        hits = search_records(RECS, "CVE-2021-44228")
        assert hits[0].record.cve == CveId.parse("CVE-2021-44228")
        assert "id" in hits[0].matched_fields

    def test_alias_match_is_identity(self):
        hits = search_records(RECS, "ghsa-xxxx-yyyy-zzzz")
        assert str(hits[0].record.cve) == "CVE-2026-0002"
        assert hits[0].score >= 100

    def test_prose_match_scores_lower_than_id(self):
        hits = search_records(RECS, "log4j")
        by_cve = {str(h.record.cve): h for h in hits}
        assert by_cve["CVE-2026-0002"].score < by_cve["CVE-2021-44228"].score or \
            "CVE-2021-44228" not in by_cve  # summary-only vs summary-only
        # both matched summary; kev bonus is explicit and small
        assert by_cve["CVE-2021-44228"].score == by_cve["CVE-2026-0002"].score + 5

    def test_no_fuzzy_matching(self):
        # "log4" is a prefix, not a token: must NOT match "log4j"
        assert search_records(RECS, "log4") == ()

    def test_kev_only_excludes_unconsulted(self):
        hits = search_records(RECS, "overflow", kev_only=True)
        assert hits == ()  # CVE-2026-0001 has kev=None, not True
        hits2 = search_records(RECS, "log4j", kev_only=True)
        assert {str(h.record.cve) for h in hits2} == {"CVE-2021-44228"}

    def test_empty_query_and_bad_limit(self):
        assert search_records(RECS, "") == ()
        with pytest.raises(ValueError):
            search_records(RECS, "log4j", limit=0)

    def test_deterministic_order_and_limit(self):
        hits = search_records(RECS, "log4j", limit=1)
        assert len(hits) == 1
        assert str(hits[0].record.cve) == "CVE-2021-44228"  # higher score first
        d = hits[0].as_dict()
        assert d["score_kind"] == "calculated_relevance"
        assert d["kev"] is True
