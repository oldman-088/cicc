"""Deterministic, hand-written source fixtures.

Every value here is **synthetic** and shaped after the public API documentation
of the respective project (NVD API 2.0, OSV v1, FIRST EPSS, CISA KEV).  No
fixture contains real captured intelligence, and none may be presented as such.

Records are chosen to exercise the awkward cases on purpose:

* ``CVE-2026-0001``  critical, full vector, CWE, references, disputed status
* ``CVE-2026-0002``  published without any CVSS data (severity must stay unknown)
* ``CVE-2026-0003``  vector present but the stated baseScore is *wrong* (conflict)
* ``CVE-2026-0004``  no description, no references (sparse but valid)

``CVE-2021-44228`` appears in the KEV fixture only as a catalogue identifier, to
test indexing; no NVD/OSV record is fabricated for it.
"""

from __future__ import annotations

import copy
from typing import Any

NVD_SINGLE: dict[str, Any] = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2026-01-02T03:04:05.000",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2026-0001",
                "sourceIdentifier": "fixture@example.invalid",
                "published": "2026-01-01T00:00:00.000",
                "lastModified": "2026-01-02T00:00:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {"lang": "es", "value": "Descripcion sintetica de relleno."},
                    {"lang": "en", "value": "Synthetic fixture: remote code execution in a fake component."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "fixture@example.invalid",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            },
                        }
                    ]
                },
                "weaknesses": [
                    {"source": "fixture@example.invalid", "type": "Primary",
                     "description": [{"lang": "en", "value": "CWE-78"}]}
                ],
                "references": [
                    {"url": "https://example.invalid/advisory/1", "tags": ["Patch", "Vendor Advisory"]},
                    {"url": "https://example.invalid/exploit/1", "tags": ["Exploit"]},
                ],
            }
        }
    ],
}

NVD_NO_METRICS: dict[str, Any] = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "timestamp": "2026-01-02T03:04:05.000",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2026-0002",
                "published": "2026-01-01T00:00:00.000",
                "lastModified": "2026-01-01T00:00:00.000",
                "vulnStatus": "Awaiting Analysis",
                "descriptions": [{"lang": "en", "value": "Synthetic fixture without CVSS data."}],
                "references": [],
            }
        }
    ],
}

NVD_WRONG_SCORE: dict[str, Any] = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "timestamp": "2026-01-02T03:04:05.000",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2026-0003",
                "published": "2026-01-01T00:00:00.000",
                "lastModified": "2026-01-03T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Synthetic fixture with an inconsistent score."}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "fixture@example.invalid",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                # Deliberately wrong: the vector implies 9.8.
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                            },
                        }
                    ]
                },
            }
        }
    ],
}

NVD_SPARSE: dict[str, Any] = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "timestamp": "2026-01-02T03:04:05.000",
    "vulnerabilities": [
        {"cve": {"id": "CVE-2026-0004", "published": "2026-01-01T00:00:00.000", "lastModified": "2026-01-01T00:00:00.000"}}
    ],
}

NVD_PAGE: dict[str, Any] = {
    "resultsPerPage": 2,
    "startIndex": 0,
    "totalResults": 3,
    "timestamp": "2026-01-02T03:04:05.000",
    "vulnerabilities": [
        NVD_SINGLE["vulnerabilities"][0],
        NVD_NO_METRICS["vulnerabilities"][0],
    ],
}

NVD_MALFORMED_ENTRY: dict[str, Any] = {
    "resultsPerPage": 2,
    "startIndex": 0,
    "totalResults": 2,
    "timestamp": "2026-01-02T03:04:05.000",
    "vulnerabilities": [
        {"cve": {"id": "CVE-2026-0001", "published": "2026-01-01T00:00:00.000"}},
        {"cve": {"id": "NOT-A-CVE", "published": "2026-01-01T00:00:00.000"}},
    ],
}

NVD_EMPTY: dict[str, Any] = {
    "resultsPerPage": 0,
    "startIndex": 0,
    "totalResults": 0,
    "timestamp": "2026-01-02T03:04:05.000",
    "vulnerabilities": [],
}

NVD_BAD_ENVELOPE: dict[str, Any] = {"timestamp": "2026-01-02T03:04:05.000", "vulnerabilities": "nope"}

OSV_CVE: dict[str, Any] = {
    "schema_version": "1.6.0",
    "id": "GHSA-0000-aaaa-bbbb",
    "modified": "2026-01-02T00:00:00Z",
    "published": "2026-01-01T00:00:00Z",
    "aliases": ["CVE-2026-0001"],
    "summary": "Synthetic fixture advisory with a CVE alias",
    "details": "Synthetic fixture body. Not a real advisory.",
    "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    ],
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "fixture-pkg", "purl": "pkg:npm/fixture-pkg"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.1"}]}],
            "versions": ["1.0.0", "2.0.0"],
        },
        {
            "package": {"ecosystem": "PyPI", "name": "fixture-py"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.2"}, {"fixed": "1.4"}]}],
        },
    ],
    "references": [{"type": "ADVISORY", "url": "https://example.invalid/osv/1"}],
    "database_specific": {"severity": "HIGH"},
}

OSV_ADVISORY_ONLY: dict[str, Any] = {
    "id": "PYSEC-2026-1",
    "modified": "2026-01-02T00:00:00Z",
    "published": "2026-01-01T00:00:00Z",
    "summary": "Synthetic advisory with no CVE alias",
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "fixture-py"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0"}]}],
        }
    ],
}

OSV_WITHDRAWN: dict[str, Any] = {
    "id": "GHSA-1111-cccc-dddd",
    "published": "2026-01-01T00:00:00Z",
    "modified": "2026-01-05T00:00:00Z",
    "withdrawn": "2026-01-05T00:00:00Z",
    "aliases": ["CVE-2026-0002"],
    "summary": "Synthetic withdrawn advisory",
    "affected": [],
}

OSV_ALIAS_ONLY_CVE: dict[str, Any] = {
    "id": "CVE-2026-0004",
    "published": "2026-01-01T00:00:00Z",
    "modified": "2026-01-01T00:00:00Z",
    "summary": "Synthetic record keyed by CVE id",
}

OSV_UNSUPPORTED_VECTOR: dict[str, Any] = {
    "id": "GHSA-2222-eeee-ffff",
    "published": "2026-01-01T00:00:00Z",
    "aliases": ["CVE-2026-0003"],
    "severity": [{"type": "CVSS_V2", "score": "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"}],
}

EPSS_RESPONSE: dict[str, Any] = {
    "status": "OK",
    "status-code": 200,
    "version": "2026.01.01",
    "model": "fixture-model",
    "total": 2,
    "offset": 0,
    "limit": 2,
    "data": [
        {"cve": "CVE-2026-0001", "epss": "0.94470", "percentile": "0.99900", "date": "2026-01-01"},
        {"cve": "CVE-2026-0002", "epss": "0.00043", "percentile": "0.08100", "date": "2026-01-01"},
    ],
}

EPSS_EMPTY: dict[str, Any] = {"status": "OK", "version": "2026.01.01", "data": []}

EPSS_ERROR: dict[str, Any] = {"status": "Error", "status-code": 500, "data": []}

KEV_CATALOG: dict[str, Any] = {
    "title": "Synthetic KEV-shaped catalog (fixture)",
    "catalogVersion": "2026.01.01",
    "dateReleased": "2026-01-01T00:00:00.000Z",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-0001",
            "vendorProject": "Fixture Vendor",
            "product": "Fixture Product",
            "vulnerabilityName": "Synthetic fixture vulnerability",
            "dateAdded": "2026-01-05",
            "shortDescription": "Synthetic fixture description.",
            "requiredAction": "Apply mitigations per vendor instructions.",
            "dueDate": "2026-01-26",
            "knownRansomwareCampaignUse": "Unknown",
        },
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Fixture Vendor",
            "product": "Fixture Product",
            "vulnerabilityName": "Identifier-only fixture entry",
            "dateAdded": "2021-12-10",
            "shortDescription": "Synthetic fixture description.",
            "requiredAction": "Apply mitigations per vendor instructions.",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
        },
    ],
}


def clone(value: T) -> T:  # type: ignore[valid-type]
    """Deep copy so a test cannot mutate shared fixture state."""
    return copy.deepcopy(value)


T = Any
