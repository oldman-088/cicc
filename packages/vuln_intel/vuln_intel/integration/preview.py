"""Generate the integration review artifact.

    python -m vuln_intel.integration.preview

Writes ``INTEGRATION_PREVIEW.json`` (git-ignored, regenerate on demand) containing:

1. the exact payload the host store would receive for one NVD record and one
   OSV record, produced by the dry-run path — so a reviewer can approve the
   contract before any adapter or migration exists;
2. the ranking output with its explanation, to show what the API would serve;
3. an explicit statement of what was *not* verified.

Exit code is non-zero if any separation rule is violated, so CI can enforce it.
"""

from __future__ import annotations

import json
import pathlib
from datetime import datetime, timezone
from typing import Any

from ..connectors.nvd import NvdConnector
from ..connectors.osv import OsvConnector
from ..integration import IngestionPolicy, IngestionService, InMemoryVulnerabilityStore
from ..normalization import attach_kev, index_kev, normalize_sources
from ..priorities import PriorityContext, rank_vulnerabilities
from ..ratelimit import RateGate
from ..retry import RetryPolicy
from ..schema import Origin
from ..transport import TransportResponse

OUTPUT = pathlib.Path(__file__).with_name("INTEGRATION_PREVIEW.json")

NVD_PAYLOAD: dict[str, Any] = {
    "totalResults": 1,
    "timestamp": "2026-01-02T03:04:05.000",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2026-0001",
                "published": "2026-01-01T00:00:00.000",
                "lastModified": "2026-01-02T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Synthetic preview record."}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "preview@example.invalid",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            },
                        }
                    ]
                },
            }
        }
    ],
}

OSV_PAYLOAD: dict[str, Any] = {
    "id": "GHSA-preview-0000-0000",
    "published": "2026-01-01T00:00:00Z",
    "modified": "2026-01-03T00:00:00Z",
    "aliases": ["CVE-2026-0001"],
    "summary": "Synthetic preview advisory",
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "preview-pkg"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
        }
    ],
}

KEV_PAYLOAD = {"catalogVersion": "preview", "vulnerabilities": []}


class _Canned:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload
        self.calls = 0

    def get(self, url: str, *, params=None, headers=None, timeout: float = 30.0):
        self.calls += 1
        return TransportResponse(
            status=200, body=json.dumps(self.payload).encode(), headers={}, url=url
        )


def build() -> dict[str, Any]:
    nvd_transport, osv_transport = _Canned(NVD_PAYLOAD), _Canned(OSV_PAYLOAD)
    nvd = NvdConnector(
        transport=nvd_transport,
        gate=RateGate(min_interval=0.0),
        retry=RetryPolicy(attempts=1),
        origin=Origin.LIVE,  # a *live* shape, fed from a canned transport in preview
    )
    osv = OsvConnector(
        transport=osv_transport,
        gate=RateGate(min_interval=0.0),
        retry=RetryPolicy(attempts=1),
        origin=Origin.LIVE,
    )
    nvd_record = nvd.get_cve("CVE-2026-0001")
    osv_record, _ = osv.get_vulnerability("GHSA-preview-0000-0000")
    # Advisory-only OSV results (record is None) are skipped, never passed on.
    contributions = [nvd_record] + ([osv_record] if osv_record is not None else [])
    merged = normalize_sources(contributions)
    kev = index_kev(KEV_PAYLOAD)
    records = [attach_kev(record, kev.get(cve)) for cve, record in merged.items()]

    service = IngestionService(
        store=InMemoryVulnerabilityStore(allow_fixture=False),
        policy=IngestionPolicy(dry_run=True, allow_fixture=False),
    )
    report = service.import_records(
        records, tenant_id="preview-tenant", collected_at=datetime(2026, 1, 10, tzinfo=timezone.utc)
    )

    ranking = rank_vulnerabilities(
        records,
        context=PriorityContext(exposure=0.5, business_criticality=0.5),
        now=datetime(2026, 1, 10, tzinfo=timezone.utc),
    )

    fixture_service = IngestionService(
        store=InMemoryVulnerabilityStore(allow_fixture=False),
        policy=IngestionPolicy(dry_run=False, allow_fixture=False),
    )
    from dataclasses import replace

    fixture_records = [replace(record, origin=Origin.FIXTURE) for record in records]
    fixture_report = fixture_service.import_records(
        fixture_records, tenant_id="preview-tenant"
    )

    return {
        "notice": (
            "SYNTHETIC PREVIEW. Generated from canned payloads with no network access. "
            "Live NVD/OSV/EPSS connectivity is NOT verified by this artifact."
        ),
        "network_requests": {"nvd": nvd_transport.calls, "osv": osv_transport.calls},
        "store_payload_preview": report.as_dict(),
        "ranking_preview": [result.as_dict() for result in ranking],
        "origin_gate_check": {
            "explanation": (
                "A fixture-origin record was pushed at a store that forbids fixtures: "
                "it must be refused, proving demo data cannot reach production tables."
            ),
            "fixture_import": fixture_report.as_dict(),
        },
    }


def validate(payload: dict[str, Any]) -> list[str]:
    """Separation rules CI enforces on the generated artifact."""
    problems: list[str] = []
    previews = payload["store_payload_preview"]["payloads"]
    if not previews:
        problems.append("no store payloads were produced")
    for item in previews:
        if item.get("origin") != "live":
            problems.append(f"unexpected origin in preview payload: {item.get('origin')}")
        enrichment = item.get("details", {}).get("cicc_enrichment", {})
        if enrichment.get("schema") != "cicc.vuln_intel.v1":
            problems.append("enrichment block missing or wrong schema")
    gate = payload["origin_gate_check"]["fixture_import"]
    if gate["failed"] != len(gate["outcomes"]):
        problems.append("fixture data was not refused by the store")
    if payload["ranking_preview"] and payload["ranking_preview"][0]["origin"] != "live":
        problems.append("ranking preview is not marked live-shaped")
    return problems


def main() -> int:
    payload = build()
    problems = validate(payload)
    if problems:
        print("SEPARATION RULES VIOLATED:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    OUTPUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload["store_payload_preview"], indent=2)[:2000])
    print(f"\nranking: {json.dumps(payload['ranking_preview'], indent=2)[:800]}")
    print(f"\norigin gate: {json.dumps(payload['origin_gate_check']['fixture_import']['outcomes'])}")
    print(f"\nwritten to {OUTPUT}")
    print("all separation rules pass")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
