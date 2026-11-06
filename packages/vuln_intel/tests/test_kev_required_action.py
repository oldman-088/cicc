"""M1 KEV-layer variant: requiredAction preserved verbatim, never blended.

The provider's requiredAction is a SOURCE instruction; our due date is computed
from it. They are stored side by side, labelled, and never merged — and the
owner decision (whether to also surface it on the shared NormalizedVulnerability)
remains OPEN; this implements only the KEV-layer-only option.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from vuln_intel.kev import _catalog_from_document

NOW = datetime(2026, 8, 1, tzinfo=timezone.utc)

DOC = {
    "catalogVersion": "2026.07.01",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "log4j",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "requiredAction": "Apply updates per vendor instructions.",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2026-0001",
            "vendorProject": "Acme",
            "product": "lib",
            "dateAdded": "2026-07-01",
            "dueDate": "2026-07-21",
            # no requiredAction key at all
        },
    ],
}


def _catalog():
    return _catalog_from_document(DOC, fetched_at=NOW, origin="fixture")


class TestRequiredAction:
    def test_verbatim_text_preserved(self):
        entry = _catalog().lookup("CVE-2021-44228")
        assert entry.required_action == "Apply updates per vendor instructions."

    def test_missing_key_stays_none_not_empty(self):
        entry = _catalog().lookup("CVE-2026-0001")
        assert entry.required_action is None
        assert entry.due_date is not None  # computed/stored due date unaffected

    def test_serialization_keeps_source_label_and_null_semantics(self):
        cat = _catalog()
        with_action = cat.lookup("CVE-2021-44228").as_dict()
        without = cat.lookup("CVE-2026-0001").as_dict()
        assert with_action["required_action"] == "Apply updates per vendor instructions."
        assert with_action["required_action_source"] == "cisa-kev"
        assert without["required_action"] is None
        assert without["required_action_source"] is None
        json.dumps([with_action, without])  # JSON-safe

    def test_provider_text_not_rewritten_or_merged_with_due_date(self):
        entry = _catalog().lookup("CVE-2021-44228")
        # the source text is not a date, not truncated, not paraphrased
        assert entry.required_action != entry.due_date.isoformat()
        assert "vendor instructions" in entry.required_action
