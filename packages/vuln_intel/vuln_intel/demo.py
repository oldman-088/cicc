"""Offline demonstration: run the whole pipeline on synthetic fixtures.

    python -m vuln_intel.demo

This produces a small review artifact (``DEMO_OUTPUT.json`` next to this file)
showing normalization, KEV/EPSS attachment and ranking.  Every record is marked
``fixture`` origin: nothing here is real intelligence and no network call is
made.  This is the *only* supported way to see output before a live connector is
verified.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

from .connectors.epss import FixtureEpssProvider
from .connectors.nvd import NvdConnector
from .connectors.osv import OsvConnector
from .errors import VulnIntelError
from .normalization import attach_epss, attach_kev, index_kev, normalize_sources
from .priorities import PriorityContext, rank_vulnerabilities
from .ratelimit import RateGate
from .retry import RetryPolicy
from .schema import Origin
from .transport import TransportResponse

OUTPUT = pathlib.Path(__file__).with_name("DEMO_OUTPUT.json")

# Synthetic upstream payloads. Kept minimal and local so the demo has no import
# dependency on the test package.
NVD_PAYLOAD: dict[str, Any] = {
    "totalResults": 1,
    "timestamp": "2026-01-02T03:04:05.000",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2026-0001",
                "published": "2026-01-01T00:00:00.000",
                "lastModified": "2026-01-02T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Synthetic demo record (fixture)."}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "demo@example.invalid",
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
    "id": "GHSA-demo-0000-0000",
    "published": "2026-01-01T00:00:00Z",
    "modified": "2026-01-03T00:00:00Z",
    "aliases": ["CVE-2026-0001"],
    "summary": "Synthetic demo advisory (fixture)",
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "demo-pkg"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
        }
    ],
}

KEV_PAYLOAD: dict[str, Any] = {
    "catalogVersion": "demo-catalog",
    "vulnerabilities": [],
}

EPSS_FIXTURE = {"CVE-2026-0001": (0.42, 0.97, "2026-01-01")}


class _OneShot:
    """Returns one canned payload; records the call count so the demo can prove
    it made zero network requests."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload
        self.calls = 0

    def get(self, url: str, *, params=None, headers=None, timeout: float = 30.0):
        self.calls += 1
        return TransportResponse(
            status=200, body=json.dumps(self.payload).encode(), headers={}, url=url
        )


def build() -> dict[str, Any]:
    nvd_transport = _OneShot(NVD_PAYLOAD)
    osv_transport = _OneShot(OSV_PAYLOAD)

    nvd = NvdConnector(
        transport=nvd_transport,
        gate=RateGate(min_interval=0.0),
        retry=RetryPolicy(attempts=1),
        origin=Origin.FIXTURE,
    )
    osv = OsvConnector(
        transport=osv_transport,
        gate=RateGate(min_interval=0.0),
        retry=RetryPolicy(attempts=1),
        origin=Origin.FIXTURE,
    )

    nvd_record = nvd.get_cve("CVE-2026-0001")
    osv_record, _advisory = osv.get_vulnerability("GHSA-demo-0000-0000")

    # An OSV record without a CVE alias is advisory-only (record is None). It must
    # be skipped explicitly, never forwarded into normalization as None.
    contributions = [nvd_record] + ([osv_record] if osv_record is not None else [])
    merged = normalize_sources(contributions)

    kev = index_kev(KEV_PAYLOAD)
    epss = FixtureEpssProvider(scores=EPSS_FIXTURE)

    enriched = []
    for cve, record in merged.items():
        record = attach_kev(record, kev.get(cve))
        scores = epss.fetch([record.cve])
        record = attach_epss(record, scores.get(cve))
        enriched.append(record)

    ranking = rank_vulnerabilities(
        enriched,
        context=PriorityContext(exposure=0.5, business_criticality=0.5),
    )

    return {
        "notice": (
            "SYNTHETIC FIXTURE OUTPUT. Not real intelligence. No network request was made."
        ),
        "network_requests": {"nvd": nvd_transport.calls, "osv": osv_transport.calls},
        "records": [record.as_summary() for record in enriched],
        "ranking": [result.as_dict() for result in ranking],
        "weights": dict(__import__("vuln_intel.priorities", fromlist=["WEIGHTS"]).WEIGHTS),
    }


def main() -> int:
    try:
        payload = build()
    except VulnIntelError as exc:  # pragma: no cover - defensive demo path
        print(f"demo failed: {exc}")
        return 1
    OUTPUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    print(f"\nwritten to {OUTPUT}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
