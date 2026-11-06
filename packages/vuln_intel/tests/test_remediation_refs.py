"""Remediation deep links: strict validation, source vs calculated separation."""

from __future__ import annotations

from datetime import date, datetime, timezone

import pytest

from vuln_intel.kev import KevEntry
from vuln_intel.remediation_refs import collect_remediation_links, validate_link
from vuln_intel.schema import CveId, NormalizedVulnerability, Origin, Reference

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)


class TestValidateLink:
    @pytest.mark.parametrize("url", [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
        "https://security-tracker.debian.org/tracker/CVE-2021-44228",
    ])
    def test_safe_https_links_pass(self, url):
        assert validate_link(url) == (True, None)

    @pytest.mark.parametrize("url,why", [
        ("javascript:alert(1)", "scheme"),
        ("data:text/html,<script>", "scheme"),
        ("file:///etc/passwd", "scheme"),
        ("http://insecure.example/x", "scheme"),
        ("https://user:pass@example.com/x", "credentials"),
        ("https://example.com/a b", "whitespace"),
        ("https://", "hostname"),
        ("", "empty"),
        (None, "non-string"),
    ])
    def test_unsafe_or_malformed_links_are_rejected(self, url, why):
        ok, reason = validate_link(url)
        assert ok is False and reason


def _record(refs) -> NormalizedVulnerability:
    return NormalizedVulnerability(
        cve=CveId.parse("CVE-2021-44228"), origin=Origin.FIXTURE,
        references=tuple(refs), sources=("nvd",),
    )


def _kev() -> KevEntry:
    return KevEntry(
        cve=CveId.parse("CVE-2021-44228"),
        date_added=datetime(2021, 12, 10, tzinfo=timezone.utc),
        vendor="Apache", product="log4j", name="Log4Shell",
        ransomware_use="Known", due_date=date(2021, 12, 24),
        required_action="Apply updates per vendor instructions.",
    )


class TestCollect:
    def test_source_links_validated_and_typed(self):
        rec = _record([
            Reference(url="https://nvd.nist.gov/vuln/detail/CVE-2021-44228", kind="advisory", source="nvd"),
            Reference(url="https://example.com/patch", kind="patch", source="vendor"),
        ])
        links = collect_remediation_links(rec, kev_entry=_kev())
        kinds = {l.kind for l in links}
        assert "vendor_advisory" in kinds and "vendor_patch" in kinds
        assert any(l.kind == "kev_catalogue" and l.source == "cisa-kev" for l in links)
        assert all(l.valid for l in links)

    def test_invalid_links_kept_visible_not_dropped(self):
        rec = _record([Reference(url="javascript:alert(1)", kind="advisory", source="evil")])
        (link,) = collect_remediation_links(rec)
        assert link.valid is False and "https" in link.reason

    def test_duplicates_collapse_conflicting_kinds_flagged(self):
        rec = _record([
            Reference(url="https://example.com/x", kind="advisory", source="a"),
            Reference(url="https://example.com/x", kind="patch", source="b"),
            Reference(url="https://EXAMPLE.com/x", kind="advisory", source="c"),  # case-dupe
        ])
        links = collect_remediation_links(rec)
        same = [l for l in links if l.url.lower() == "https://example.com/x"]
        # one kept advisory link + one conflict-flagged entry; the case-dupe collapsed
        assert len(same) == 2
        assert sum(1 for l in same if l.reason == "conflicting link kind") == 1
        assert sum(1 for l in same if l.kind == "vendor_advisory") == 1
        assert sum(1 for l in same if l.kind == "vendor_patch") == 1

    def test_missing_references_yield_only_kev_link(self):
        rec = _record([])
        links = collect_remediation_links(rec, kev_entry=_kev())
        assert len(links) == 1 and links[0].kind == "kev_catalogue"

    def test_kev_required_action_is_text_never_a_link(self):
        # the requiredAction prose must not appear as any link URL
        links = collect_remediation_links(_record([]), kev_entry=_kev())
        assert all("Apply updates" not in l.url for l in links)
