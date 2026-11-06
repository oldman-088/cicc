#!/usr/bin/env python3
"""Run the Vulnerability Intelligence API over real HTTP, against a real database file.

This exists because the difference between "the ASGI app passes its tests" and "a client
can fetch a record from it" is a real one, and only the second is the claim this package
wants to make. It is a demonstration harness, not a production server: the tenant
resolver reads a header and trusts it, which is exactly what the real deployment must NOT
do.

Usage
-----
    python scripts/serve_demo.py [--db PATH] [--port PORT] [--seed]

Then:

    curl -s localhost:8000/v1/vulnerabilities -H 'x-demo-tenant: tenant-a'
    curl -s localhost:8000/v1/vulnerabilities/CVE-2021-44228 -H 'x-demo-tenant: tenant-a'
    curl -s localhost:8000/v1/vulnerabilities -H 'x-demo-tenant: tenant-b'   # empty

Requires a development dependency:

    pip install uvicorn

The package itself stays stdlib-only; this harness is the only place that imports a
framework, and it is not imported by the package.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

# Allow running from the package root without installing.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vuln_intel.integration.asgi import build_app
from vuln_intel.integration.sqlite_store import SQLiteVulnerabilityStore
from vuln_intel.schema import Severity, severity_rank


def demo_resolver(scope) -> str:
    """Read a tenant from a header. DEMONSTRATION ONLY.

    A real deployment resolves the tenant from a verified token and never from a header
    a client controls. This function exists so the demo can be run without an identity
    provider, and the mismatch is stated here rather than discovered in production.
    """
    for key, value in scope.get("headers") or []:
        if key.lower() == b"x-demo-tenant":
            return value.decode("latin-1") or "tenant-a"
    return "tenant-a"


_SEED = (
    # (cve, severity, kev, ecosystem, package, fixed)
    ("CVE-2021-44228", "critical", True, "maven", "log4j-core", "2.15.0"),
    ("CVE-2021-45046", "critical", True, "maven", "log4j-core", "2.16.0"),
    ("CVE-2022-22965", "critical", True, "maven", "spring-beans", "5.3.18"),
    ("CVE-2023-44487", "high", True, "go", "golang.org/x/net", "0.17.0"),
    ("CVE-2024-3094", "critical", True, "deb", "xz-utils", "5.6.2"),
    ("CVE-2020-8203", "high", False, "npm", "lodash", "4.17.20"),
    ("CVE-2022-42003", "medium", False, "maven", "jackson-databind", "2.13.4.2"),
    ("CVE-2019-11358", "medium", False, "npm", "jquery", "3.4.0"),
    ("CVE-2023-38545", "high", False, "go", "curl", "8.4.0"),
    ("CVE-2024-6387", "high", True, "deb", "openssh-server", "9.8p1"),
)


def seed(store: SQLiteVulnerabilityStore, *, tenant: str = "tenant-a") -> int:
    """Write a small demo corpus. origin=fixture, so the store must allow fixtures."""
    moment = datetime(2026, 1, 1, tzinfo=timezone.utc)
    written = 0
    for cve, severity, kev, ecosystem, package, fixed in _SEED:
        store.upsert(
            tenant_id=tenant,
            cve=cve,
            entity={},
            details={
                "severity": severity,
                "kev": kev,
                "summary": f"demonstration record for {cve}",
                "ecosystem": ecosystem,
                "package": package,
                "fixed_version": fixed,
            },
            enrichment={
                "origin": "fixture",
                "severity": severity,
                "kev": kev,
                "source_count": 2,
            },
            provenance={"source": "demo-seed", "observed_at": moment.isoformat()},
            collected_at=moment,
            dry_run=False,
        )
        written += 1
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="vuln_intel_demo.db", help="SQLite file path")
    # 0.0.0.0 so the sandbox preview proxy can reach it; a real deployment would
    # bind a single interface behind its own ingress.
    parser.add_argument("--host", default="0.0.0.0", help="bind address")  # noqa: S104
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--seed", action="store_true", help="write demo records first")
    parser.add_argument("--tenant", default="tenant-a")
    args = parser.parse_args()

    try:
        import uvicorn
    except ImportError:
        print(
            "uvicorn is not installed. This harness needs a server:\n"
            "    pip install uvicorn\n"
            "(The package itself is stdlib-only and does not require it.)",
            file=sys.stderr,
        )
        return 2

    store = SQLiteVulnerabilityStore(path=args.db, allow_fixture=True)
    if args.seed:
        count = seed(store, tenant=args.tenant)
        print(f"seeded {count} records into {args.db} for tenant {args.tenant!r}")

    existing = store.record_count(tenant_id=args.tenant)
    app = build_app(store, resolve_tenant=demo_resolver)

    print()
    print(f"  listening on http://{args.host}:{args.port}")
    print(f"  database     {Path(args.db).resolve()}")
    print(f"  records      {existing} for tenant {args.tenant!r}")
    print()
    print("  GET /v1/vulnerabilities")
    print("  GET /v1/vulnerabilities/{cve}")
    print("  header: x-demo-tenant: <tenant>")
    print()
    # Sort the demo corpus the way the API would, so a reader can eyeball the order.
    rows, _ = store.list(tenant_id=args.tenant, limit=10, order="severity")
    if rows:
        print(f"  first page (order=severity, rank {severity_rank(Severity.CRITICAL)} first):")
        for row in rows:
            print(f"    {row['cve']:<18} {row['details'].get('severity'):<9}")
        print()

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
