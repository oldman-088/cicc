"""B-00: unmodelled OSV fields are named AND their raw evidence is preserved (capped)."""

from __future__ import annotations

from datetime import datetime, timezone

from vuln_intel.connectors.osv import OsvConnector
from vuln_intel.schema import Origin

DOC = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "schema_version": "1.6.0",
    "aliases": ["CVE-2026-1234"],
    "credits": [{"name": "Jane Doe", "contact": ["jane@example.com"]}],
    "upstream": ["CVE-2026-9999"],
    "modified": "2026-01-01T00:00:00Z",
    "published": "2026-01-01T00:00:00Z",
    "summary": "test advisory",
    "affected": [],
}


def test_unmodelled_fields_preserve_raw_evidence_in_notes():
    rec, _ = OsvConnector(origin=Origin.FIXTURE).parse_record(DOC, fetched_at=datetime(2026, 1, 2, tzinfo=timezone.utc))
    assert rec is not None
    joined = " ".join(rec.conflict_notes)
    assert "schema_version" in joined and "1.6.0" in joined
    assert "credits" in joined and "Jane Doe" in joined
    assert "upstream" in joined and "CVE-2026-9999" in joined


def test_long_evidence_is_capped_not_unbounded():
    doc = dict(DOC)
    doc["credits"] = [{"name": "x" * 5000}]
    rec, _ = OsvConnector(origin=Origin.FIXTURE).parse_record(doc, fetched_at=datetime(2026, 1, 2, tzinfo=timezone.utc))
    assert rec is not None
    assert all(len(n) < 600 for n in rec.conflict_notes)
