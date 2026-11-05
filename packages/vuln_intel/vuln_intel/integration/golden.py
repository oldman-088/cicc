"""Generate the golden fixtures the frontend consumes.

**Why generated rather than hand-written.** A hand-written fixture is a second
implementation of the contract, and it drifts the moment the code changes. These are
produced by running the real pipeline over a fixed, deterministic scenario, so a
change in shape is a failing test rather than a surprise in a browser.

Regenerate deliberately, and read the diff:

    python -m vuln_intel.integration.golden --write

The fixtures carry `origin: "fixture"` throughout. That is not cosmetic: the origin
gate exists so synthetic data cannot reach a real store, and a frontend built against
these fixtures must not infer that a production payload will look identical in every
respect.
"""

from __future__ import annotations

import argparse
import json
import pathlib
from datetime import datetime, timedelta, timezone
from typing import Any

from ..assessment import AssessmentWorkflow
from ..interop.vex import to_vex
from ..schema import (
    AffectedPackage,
    CveId,
    CvssScore,
    FieldConflict,
    NormalizedVulnerability,
    Origin,
    RecordStatus,
    Reference,
    Severity,
)
from ..watchlist import Dependency, Inventory

#: Fixed clock. Every timestamp in the fixtures derives from this, so the files are
#: byte-identical between runs — which is what makes them usable as a drift check.
GOLDEN_NOW = datetime(2026, 11, 4, 9, 0, tzinfo=timezone.utc)

# __file__ is <pkg>/vuln_intel/integration/golden.py, so parents[2] is the package
# root (the directory holding pyproject.toml) and the fixtures live under tests/.
# Getting this wrong writes a second fixture tree that no test reads, which is worse
# than writing none: the generated files look authoritative and are never checked.
FIXTURE_DIR = pathlib.Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "handoff"


def _records() -> list[NormalizedVulnerability]:
    """Six records covering the cases the UI has to render."""
    now = GOLDEN_NOW

    def base(cve: str, **kwargs: Any) -> NormalizedVulnerability:
        defaults: dict[str, Any] = {
            "cve": CveId.parse(cve),
            "origin": Origin.FIXTURE,
            "published": now - timedelta(days=40),
            "modified": now - timedelta(days=2),
        }
        defaults.update(kwargs)
        return NormalizedVulnerability(**defaults)

    return [
        # 1. Exploited, corroborated by three sources, every signal present.
        base(
            "CVE-2026-1001",
            summary="Remote code execution in acme-router before 2.4.1",
            severity=Severity.CRITICAL,
            cvss=(
                CvssScore(
                    version="4.0", base_score=9.3, vector="CVSS:4.0/AV:N/AC:L/AT:N",
                    severity=Severity.CRITICAL, source="nvd",
                ),
                CvssScore(
                    version="3.1", base_score=9.8, vector="AV:N/AC:L/PR:N/UI:N",
                    severity=Severity.CRITICAL, source="ghsa",
                ),
            ),
            epss_score=0.94,
            epss_percentile=0.998,
            epss_model_date="2026-11-03",
            kev=True,
            kev_date_added=now - timedelta(days=12),
            cwe=("CWE-78",),
            aliases=("GHSA-aaaa-bbbb-cccc",),
            ssvc=(
                ("exploitation", "active"),
                ("automatable", "yes"),
                ("technical_impact", "total"),
            ),
            affected=(
                AffectedPackage(
                    ecosystem="npm", name="acme-router",
                    introduced="0", fixed="2.4.1",
                ),
            ),
            references=(
                Reference(
                    url="https://example.invalid/advisory/1001",
                    kind="advisory", source="nvd",
                ),
            ),
            sources=("nvd", "ghsa", "cisa-kev"),
            record_status=RecordStatus.PUBLISHED,
            provenance=(),
            verification="unverified",
        ),
        # 2. Sources disagree about severity: the `contested` case.
        base(
            "CVE-2026-1002",
            summary="Authentication bypass in acme-auth",
            severity=Severity.HIGH,
            cvss=(
                CvssScore(
                    version="3.1", base_score=7.5, vector="AV:N/AC:L/PR:N/UI:N",
                    severity=Severity.HIGH, source="nvd",
                ),
            ),
            epss_score=0.31,
            epss_percentile=0.91,
            kev=False,
            affected=(
                AffectedPackage(
                    ecosystem="pypi", name="acme-auth", introduced="1.0.0",
                    fixed="1.4.2",
                ),
            ),
            sources=("nvd", "osv"),
            conflicts=(
                FieldConflict(
                    field="severity", kept="high", discarded=("critical",),
                    dissenters=("osv",),
                ),
            ),
            conflict_notes=(
                "severity disagreement across sources: critical, high (highest kept: high)",
            ),
            record_status=RecordStatus.DISPUTED,
        ),
        # 3. Withdrawn: must render, must not be presented as work to do.
        base(
            "CVE-2026-1003",
            summary="Withdrawn: alleged denial of service in acme-utils",
            severity=Severity.MEDIUM,
            kev=False,
            sources=("osv",),
            record_status=RecordStatus.REJECTED,
            withdrawn=now - timedelta(days=5),
            conflict_notes=("record withdrawn by OSV at 2026-10-30T09:00:00+00:00",),
        ),
        # 4. Awaiting enrichment: severity unknown, no CVSS at all.
        base(
            "CVE-2026-1004",
            summary=None,
            severity=Severity.UNKNOWN,
            sources=("nvd",),
            record_status=RecordStatus.UNDERGOING_ANALYSIS,
        ),
        # 5. Asset-relevant: our inventory runs the affected version.
        base(
            "CVE-2026-1005",
            summary="Prototype pollution in acme-ui",
            severity=Severity.HIGH,
            cvss=(
                CvssScore(
                    version="3.1", base_score=8.1, vector="AV:N/AC:L/PR:L/UI:N",
                    severity=Severity.HIGH, source="nvd",
                ),
            ),
            epss_score=0.12,
            epss_percentile=0.80,
            kev=False,
            affected=(
                AffectedPackage(
                    ecosystem="npm", name="acme-ui", introduced="3.0.0",
                    fixed="3.2.0",
                ),
            ),
            sources=("nvd", "osv"),
            record_status=RecordStatus.PUBLISHED,
        ),
    ]


def _inventory() -> Inventory:
    """Three dependencies: two vulnerable, one already on the fixed version.

    The third is deliberate. A fixture where every dependency is vulnerable cannot
    show a frontend what "clean" looks like, and "clean" is the state most packages
    are in.
    """
    return Inventory(
        dependencies=(
            Dependency(
                ecosystem="npm", name="acme-router", version="2.3.0",
                asset="web-frontend",
            ),
            Dependency(
                ecosystem="npm", name="acme-ui", version="3.0.5",
                asset="web-frontend",
            ),
            Dependency(
                ecosystem="pypi", name="acme-auth", version="1.4.2",
                asset="auth-service",
            ),
        )
    )


def build() -> dict[str, Any]:
    """Run the real workflow and return the fixtures keyed by file name."""
    from .api import GetVulnerabilityRequest, ListVulnerabilitiesRequest, VulnerabilityApi
    from .service import IngestionPolicy, IngestionService
    from .store import InMemoryVulnerabilityStore

    records = _records()
    tenant = "tenant-demo"

    # The API fixtures come from the real store and the real contract methods, so
    # they cannot describe a shape the read path would not actually produce.
    # The origin gate is enforced twice - in the ingestion service and again in the
    # store - so both must opt in. That redundancy is deliberate: opting out of
    # synthetic data should take two deliberate acts, not one forgotten default.
    store = InMemoryVulnerabilityStore(allow_fixture=True)
    service = IngestionService(
        store=store, policy=IngestionPolicy(allow_fixture=True, dry_run=False)
    )
    report_in = service.import_records(records, tenant_id=tenant, collected_at=GOLDEN_NOW)
    if any(outcome.outcome != "created" for outcome in report_in.outcomes):
        # A fixture generator that silently ingests nothing produces a beautiful,
        # empty golden file. Fail loudly instead.
        raise RuntimeError(
            "golden fixtures did not ingest cleanly: "
            + ", ".join(f"{o.cve}={o.outcome}({o.reason})" for o in report_in.outcomes)
        )

    api = VulnerabilityApi(store)
    listing = api.list(
        ListVulnerabilitiesRequest(tenant_id=tenant, limit=50, order="cve")
    ).body
    detail = api.get(
        GetVulnerabilityRequest(tenant_id=tenant, cve="CVE-2026-1001")
    ).body

    workflow = AssessmentWorkflow(
        collectors={"fixture": lambda: records},
        inventory=_inventory(),
        now=lambda: GOLDEN_NOW,
    )
    report = workflow.run(today=GOLDEN_NOW.date())

    vex = to_vex(report, generated_at=GOLDEN_NOW)

    return {
        "assessment_report.json": report.as_dict(),
        "vex_export.json": vex.document,
        "api_get.json": detail,
        "api_list.json": listing,
        "api_error_not_found.json": _not_found(tenant),
    }


def _not_found(tenant: str) -> dict[str, Any]:
    """The documented error envelope, produced by the contract rather than typed out."""
    from .api import ApiError, GetVulnerabilityRequest, VulnerabilityApi
    from .store import InMemoryVulnerabilityStore

    api = VulnerabilityApi(InMemoryVulnerabilityStore())
    try:
        api.get(GetVulnerabilityRequest(tenant_id=tenant, cve="CVE-2026-9999"))
    except ApiError as exc:
        return {"status": exc.status, "body": exc.as_dict()}
    raise AssertionError("an empty store must not resolve a CVE")  # pragma: no cover


def _serialise(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n"


def write(directory: pathlib.Path = FIXTURE_DIR) -> list[pathlib.Path]:
    directory.mkdir(parents=True, exist_ok=True)
    written: list[pathlib.Path] = []
    for name, payload in build().items():
        path = directory / name
        path.write_text(_serialise(payload))
        written.append(path)
    return written


def render() -> dict[str, str]:
    """The expected fixture text, for the drift test to compare against."""
    return {name: _serialise(payload) for name, payload in build().items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the frontend handoff fixtures")
    parser.add_argument("--write", action="store_true", help="rewrite the fixtures")
    parser.add_argument("--dir", default=str(FIXTURE_DIR))
    args = parser.parse_args(argv)

    if args.write:
        paths = write(pathlib.Path(args.dir))
        for path in paths:
            print(f"wrote {path}")
        return 0

    for name, text in render().items():
        print(f"=== {name} ===")
        print(text)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
