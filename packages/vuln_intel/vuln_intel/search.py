"""Keyword search over normalized vulnerability records.

Search is a *presentation* concern, so it lives outside the store protocol: the
host lists rows (already tenant-scoped and paginated) and this module ranks and
filters them in memory. All matching is exact-token, case-insensitive — no
fuzzy matching, because a fuzzy hit on a CVE id is a false correlation.

Ranking keeps source facts separate from calculated relevance: the score is
always labelled calculated, and KEV membership / severity come from the record
itself, never invented by the search.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

from .schema import NormalizedVulnerability, Severity

__all__ = ["SearchHit", "search_records"]

_TOKEN = re.compile(r"[a-z0-9][a-z0-9\-\.:+]*")

_SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.NONE: 1,
    Severity.UNKNOWN: 0,
}


@dataclass(frozen=True)
class SearchHit:
    """One matching record with its calculated relevance."""

    record: NormalizedVulnerability
    score: int
    matched_fields: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "cve": str(self.record.cve),
            "score": self.score,  # calculated relevance, not a source fact
            "score_kind": "calculated_relevance",
            "matched_fields": list(self.matched_fields),
            "severity": self.record.severity.value,
            "kev": self.record.kev,
            "summary": self.record.summary,
        }


def _tokens(text: str | None) -> set[str]:
    if not text:
        return set()
    # lowercase BEFORE tokenizing: the pattern is lowercase-only, so mixed-case
    # words would otherwise split at capitals ("Log4Shell" -> "og4","hell").
    return set(_TOKEN.findall(text.lower()))


def search_records(
    records: Iterable[NormalizedVulnerability],
    query: str,
    *,
    kev_only: bool = False,
    limit: int = 100,
) -> tuple[SearchHit, ...]:
    """Rank records by exact-token overlap with ``query``.

    * CVE/alias/id exact match scores highest (identity beats prose);
    * matches in summary/details score lower;
    * KEV-listed records get a small, explicit bonus — labelled as part of the
      calculated score, not a severity change;
    * ``kev_only`` filters to positively KEV-listed records only (kev=None
      excluded — "not consulted" is not "not exploited");
    * deterministic order: score desc, then CVE asc.
    """
    if limit < 1:
        raise ValueError("limit must be >= 1")
    terms = _tokens(query)
    if not terms:
        return ()
    hits: list[SearchHit] = []
    for record in records:
        if kev_only and record.kev is not True:
            continue
        haystacks = {
            "id": _tokens(str(record.cve)) | {a.lower() for a in record.aliases},
            "summary": _tokens(record.summary),
            "details": _tokens(record.details),
        }
        matched: list[str] = []
        score = 0
        for term in terms:
            if term in haystacks["id"]:
                score += 100
                matched.append("id")
            elif term in haystacks["summary"]:
                score += 10
                matched.append("summary")
            elif term in haystacks["details"]:
                score += 3
                matched.append("details")
        if not matched:
            continue
        if record.kev is True:
            score += 5  # calculated bonus, disclosed in score_kind
        hits.append(
            SearchHit(
                record=record,
                score=score,
                matched_fields=tuple(sorted(set(matched))),
            )
        )
    hits.sort(key=lambda h: (-h.score, str(h.record.cve)))
    return tuple(hits[:limit])
