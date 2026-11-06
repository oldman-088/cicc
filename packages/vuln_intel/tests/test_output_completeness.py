"""Nothing that presents a security report may silently shorten it.

This package had the same defect in five unrelated places, each found by reading
rather than by a failing test:

* the VEX export took one page of the store and dropped the cursor;
* the CTIS adapter sliced CVSS scores, ATT&CK techniques and references without
  recording that it had;
* a prioritisation warning showed three of N conflict notes with no count;
* a remediation plan showed two of N and said nothing about the rest;
* a source-health row showed three of N warnings.

Individually each is small. Together they are the failure mode this project exists
to avoid: a document that is accurate about what it contains and silent about what
it dropped, which a consumer reads as complete.

These tests are grouped by the rule rather than by module, because the rule is the
thing that has to hold across modules.
"""

from __future__ import annotations

import re

import pytest


def _counted(text: str) -> bool:
    """True when a truncated list says how much it did not show."""
    return bool(re.search(r"\+\d+ more|\d+ further|\d+ of \d+|\d+ more\b", text))


class TestCappedWarningsAreCounted:
    def _record_with_conflicts(self, n: int):
        from vuln_intel.schema import (
            CveId,
            FieldConflict,
            NormalizedVulnerability,
            Origin,
        )

        return NormalizedVulnerability(
            cve=CveId.parse("CVE-2026-6001"),
            origin=Origin.FIXTURE,
            summary="many disagreements",
            sources=("nvd", "osv"),
            cvss=(),
            conflicts=tuple(
                FieldConflict(
                    field=f"field-{i}", kept="a", discarded=("b",), dissenters=("osv",)
                )
                for i in range(n)
            ),
            # `conflict_notes` is the prose field the capped warnings read from;
            # `conflicts` is the structured version. Populating only the latter left
            # both call sites with nothing to truncate.
            conflict_notes=tuple(f"field-{i} disagrees" for i in range(n)),
        )

    def test_prioritisation_says_how_many_disagreements_it_did_not_show(self):
        from vuln_intel.priorities import rank_vulnerabilities

        record = self._record_with_conflicts(6)
        ranked = rank_vulnerabilities([record])
        text = " ".join(ranked[0].warnings)
        assert _counted(text), f"a capped list was not counted: {text!r}"

    def test_remediation_says_how_many_disagreements_it_did_not_show(self):
        from vuln_intel.remediation import plan_remediation

        record = self._record_with_conflicts(6)
        plan = plan_remediation(record)
        text = " ".join(plan.warnings)
        assert _counted(text), f"a capped list was not counted: {text!r}"

    def test_health_says_how_many_warnings_it_did_not_show(self):
        from vuln_intel.sync import _summarise_warnings

        assert _summarise_warnings([]) is None
        assert _summarise_warnings(["a"]) == "a"
        assert _summarise_warnings(["a", "b", "c"]) == "a; b; c"
        summary = _summarise_warnings(["a", "b", "c", "d", "e"])
        assert summary is not None and "(+2 more)" in summary

    def test_a_short_list_gains_no_clutter(self):
        """The count only appears when something was actually withheld."""
        from vuln_intel.sync import _summarise_warnings

        assert "more" not in (_summarise_warnings(["a", "b"]) or "")


class TestUnknownCveListsAreCounted:
    def test_a_long_miss_list_states_the_total(self):
        from vuln_intel.assembly import nvd_collector
        from vuln_intel.errors import SourceNotFound

        class _NeverFinds:
            def get_cve(self, cve):
                raise SourceNotFound("not found", source="nvd")

        collector = nvd_collector(
            _NeverFinds(), cve_ids=[f"CVE-2026-{i:04d}" for i in range(12)]
        )
        with pytest.raises(SourceNotFound) as caught:
            collector()
        message = str(caught.value)
        assert "and 7 more" in message, f"the miss list was silently capped: {message!r}"


class TestListPaginationDoesNotLoseRows:
    """Walking the list route to exhaustion must visit every row exactly once.

    The export path was fixed for a single capped page. The list route pages
    properly, but "properly" is only true if a client that follows `next_cursor`
    actually sees the whole set — so this walks it rather than trusting the code.
    """

    def test_every_row_is_seen_exactly_once_across_page_boundaries(self):
        from datetime import datetime, timezone

        from vuln_intel.integration.api import (
            ListVulnerabilitiesRequest,
            VulnerabilityApi,
        )
        from vuln_intel.integration.store import InMemoryVulnerabilityStore

        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        store = InMemoryVulnerabilityStore(allow_fixture=True)
        severities = ["critical", "high", "medium", "low"]
        for index in range(17):
            cve = f"CVE-2026-{7000 + index}"
            severity = severities[index % 4]
            store.upsert(
                tenant_id="tenant-a",
                cve=cve,
                entity={},
                details={"severity": severity, "origin": "fixture"},
                enrichment={"origin": "fixture", "severity": severity},
                provenance={"source": "test"},
                collected_at=now,
                dry_run=False,
            )

        api = VulnerabilityApi(store)
        for order in ("cve", "-cve", "severity", "-severity"):
            seen: list[str] = []
            cursor = None
            for _ in range(50):  # bounded so a cursor loop fails instead of hanging
                page = api.list(
                    ListVulnerabilitiesRequest(
                        tenant_id="tenant-a", limit=3, cursor=cursor, order=order
                    ),
                    now=now,
                ).body
                seen.extend(row["cve"] for row in page["data"])
                cursor = page["page"]["next_cursor"]
                if cursor is None:
                    break
            assert len(seen) == 17, f"order={order} saw {len(seen)} rows: {seen}"
            assert len(set(seen)) == 17, f"order={order} repeated a row: {seen}"

    def test_a_severity_filter_pages_without_skipping_matches(self):
        from datetime import datetime, timezone

        from vuln_intel.integration.api import (
            ListVulnerabilitiesRequest,
            VulnerabilityApi,
        )
        from vuln_intel.integration.store import InMemoryVulnerabilityStore

        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        store = InMemoryVulnerabilityStore(allow_fixture=True)
        for index in range(9):
            cve = f"CVE-2026-{8000 + index}"
            severity = "high" if index % 3 == 0 else "low"
            store.upsert(
                tenant_id="tenant-a",
                cve=cve,
                entity={},
                details={"severity": severity, "origin": "fixture"},
                enrichment={"origin": "fixture", "severity": severity},
                provenance={"source": "test"},
                collected_at=now,
                dry_run=False,
            )

        api = VulnerabilityApi(store)
        seen: list[str] = []
        cursor = None
        for _ in range(50):
            page = api.list(
                ListVulnerabilitiesRequest(
                    tenant_id="tenant-a", limit=1, cursor=cursor, severity="high"
                ),
                now=now,
            ).body
            seen.extend(row["cve"] for row in page["data"])
            cursor = page["page"]["next_cursor"]
            if cursor is None:
                break
        assert len(seen) == 3, f"severity filter lost rows across pages: {seen}"
