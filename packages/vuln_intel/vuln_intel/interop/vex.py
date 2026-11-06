"""Emit assessment verdicts as a CycloneDX VEX document.

Why VEX and not a bespoke format
--------------------------------
A ``not_affected`` verdict is the one statement that *removes work* from a
downstream consumer's queue, and VEX (Vulnerability Exploitability eXchange) is
the CycloneDX standard built around exactly those verdicts. Emitting it lets
supply-chain tooling (Dependency-Track, OWASP, ArgoCD policies) consume our
analysis instead of re-deriving it, and it gives us an external schema to
validate against - the same reason the CTIS adapter exists.

Mapping discipline
------------------
Our three-valued :class:`~vuln_intel.affected.Verdict` maps onto VEX ``analysis.state``
as follows, and nothing is ever promoted:

* ``AFFECTED`` + KEV-listed  -> ``exploitable`` (CISA says it is exploited in the wild)
* ``AFFECTED``               -> ``affected``
* ``NOT_AFFECTED``           -> ``not_affected``
* ``UNKNOWN``                -> ``under_investigation`` - never ``not_affected``,
  because "we could not decide" must not read as "we are safe".

Verdicts come from the exposure report, so a record with no inventory match
produces **no analysis entry**; the count of such records is reported in
``VexExport.unassessed`` rather than silently omitted.

This module performs no I/O and imports nothing third-party; the package stays
stdlib-only.
"""

from __future__ import annotations

import hashlib
import json
import uuid

#: Stable namespace for the content-derived serialNumber (uuid5 over the SHA-256
#: of the canonical document JSON) — identical logical inputs give an identical
#: serial across runs, so golden fixtures do not flap.
_CICC_NAMESPACE = uuid.NAMESPACE_URL
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..affected import Verdict
from ..assessment import AssessmentReport
from ..schema import SEVERITY_ORDER, Severity
from ..watchlist import PackageMatch

__all__ = [
    "VEX_SPEC_VERSION",
    "VexExport",
    "to_vex",
    "vex_state_for",
]

#: CycloneDX spec version this adapter targets.
VEX_SPEC_VERSION = "1.6"

#: VEX analysis states we are allowed to emit. Anything outside this set would
#: be a verdict we cannot defend.
_ALLOWED_STATES = frozenset(
    {"affected", "exploitable", "not_affected", "under_investigation"}
)

#: CVSS version -> CycloneDX rating method. CVSS v4.0 is also a legal CycloneDX
#: method, but our v4 scores are stored under version "4.0" and are forwarded
#: as "CVSSv40" when present.
_CVSS_METHOD = {"3.0": "CVSSv30", "3.1": "CVSSv31", "4.0": "CVSSv40"}

#: Shared with the API and the store; see ``schema.SEVERITY_ORDER``. It used to be a
#: private copy here, which is how the store ended up sorting severities by name.
_SEVERITY_ORDER = SEVERITY_ORDER


def vex_state_for(verdict: Verdict, *, kev: bool | None = None) -> str:
    """Map one verdict onto a VEX ``analysis.state``.

    ``UNKNOWN`` maps to ``under_investigation``: the single most important rule
    of this adapter is that an undecided verdict is never exported as safe.
    ``AFFECTED`` with a positive KEV membership maps to ``exploitable``, because
    CISA listing is a statement about real-world exploitation, which in VEX
    vocabulary is strictly stronger than ``affected``. ``kev=None`` (not
    consulted) stays plain ``affected``.
    """
    if verdict is Verdict.AFFECTED:
        return "exploitable" if kev is True else "affected"
    if verdict is Verdict.NOT_AFFECTED:
        return "not_affected"
    return "under_investigation"


@dataclass(frozen=True)
class VexExport:
    """A VEX document plus an honest account of what it does not cover."""

    document: dict[str, Any]
    #: CVEs that had no exposure evaluation (no inventory supplied or no match),
    #: so they carry ratings but no ``analysis``. Empty means everything was
    #: assessed - a real statement, not an absence.
    unassessed: tuple[str, ...] = ()
    #: (CVE, package) pairs whose verdict was UNKNOWN and therefore exported as
    #: ``under_investigation``. Listed so a consumer can see what is undecided
    #: without parsing states.
    under_investigation: tuple[str, ...] = ()
    #: Fields of our model with no VEX counterpart (kept explicit, per the CTIS
    #: adapter's convention).
    lost: tuple[str, ...] = field(default_factory=tuple)

    def to_json(self) -> str:
        import json

        return json.dumps(self.document, indent=2, sort_keys=True)


def _package_ref(match: PackageMatch) -> str:
    """A stable bom-ref for the affected package instance."""
    dep = match.dependency
    if dep.purl:
        return dep.purl
    return f"cicc-pkg:{dep.canonical_ecosystem}/{dep.canonical_name}@{dep.version}"


def _vulnerability_entry(
    cve: str,
    record: Any,
    *,
    bom_ref: str,
) -> dict[str, Any]:
    entry: dict[str, Any] = {"bom-ref": bom_ref, "id": cve}
    source = record.sources[0] if record.sources else None
    if source:
        entry["source"] = {"name": source}
    if record.summary:
        entry["description"] = record.summary
    references = [
        {"id": str(ref.url), "source": {"name": ref.source or "unknown"}}
        for ref in record.references
    ]
    if references:
        entry["references"] = references
    ratings = []
    for score in record.cvss:
        if not score.assessed:
            continue
        method = _CVSS_METHOD.get(score.version, f"CVSSv{score.version}")
        rating: dict[str, Any] = {
            "source": {"name": score.source or source or "unknown"},
            "score": score.base_score,
            "severity": score.severity.value,
            "method": method,
        }
        if score.vector:
            rating["vector"] = score.vector
        ratings.append(rating)
    if ratings:
        # Highest severity first; ties broken by score, then source name, so the
        # document is deterministic.
        ratings.sort(
            key=lambda r: (
                _SEVERITY_ORDER.get(Severity(r["severity"]), 99),
                -float(r["score"]),
                r["source"]["name"],
            )
        )
        entry["ratings"] = ratings
    return entry


def _analysis_entry(match: PackageMatch, *, state: str, kev: bool | None) -> dict[str, Any]:
    detail_parts = [f"verdict: {match.assessment.verdict.value}"]
    if match.assessment.reasons:
        detail_parts.append("; ".join(match.assessment.reasons))
    fixed = match.assessment.fixed_version or match.advisory_fixed
    if fixed:
        detail_parts.append(f"first fixed version: {fixed}")
    if kev is not None:
        detail_parts.append(f"cisa_kev: {'listed' if kev else 'not listed'}")
    return {
        "bom-ref": f"analysis:{match.cve}:{match.dependency.canonical_ecosystem}/{match.dependency.canonical_name}",
        "state": state,
        "detail": ". ".join(detail_parts),
    }


def to_vex(
    report: AssessmentReport,
    *,
    generated_at: datetime | None = None,
    tool: str = "cicc-vuln-intel",
    tool_version: str = "0.1.0",
) -> VexExport:
    """Build a CycloneDX VEX document from an :class:`AssessmentReport`.

    One vulnerability entry is emitted per (CVE, installed package) exposure
    match, because VEX ``analysis`` is per vulnerability entry and our verdicts
    are per package. Records without an exposure match are emitted with their
    ratings and references but no ``analysis``, and are listed in
    ``VexExport.unassessed``.
    """
    moment = generated_at or datetime.now(tz=timezone.utc)
    if moment.tzinfo is None:
        raise ValueError("generated_at must be timezone-aware")

    kev_by_cve: dict[str, bool | None] = {}
    for cluster in report.clusters:
        kev_by_cve[str(cluster.merged.cve)] = cluster.merged.kev

    vulnerabilities: list[dict[str, Any]] = []
    components: list[dict[str, Any]] = []
    seen_components: set[str] = set()
    under_investigation: list[str] = []

    assessed_cves: set[str] = set()
    if report.exposure is not None:
        for match in (
            *report.exposure.matches,
            *report.exposure.unverified,
            *report.exposure.not_affected,
        ):
            kev = kev_by_cve.get(match.cve)
            state = vex_state_for(match.assessment.verdict, kev=kev)
            if state not in _ALLOWED_STATES:  # defensive; vex_state_for cannot produce others
                raise ValueError(f"illegal VEX state: {state}")
            cve = match.cve
            assessed_cves.add(cve)
            pkg_ref = _package_ref(match)
            if pkg_ref not in seen_components:
                seen_components.add(pkg_ref)
                components.append(
                    {
                        "bom-ref": pkg_ref,
                        "type": "library",
                        "name": match.dependency.canonical_name,
                        "version": match.dependency.version,
                        "purl": match.dependency.purl,
                        "properties": [
                            {
                                "name": "cicc:ecosystem",
                                "value": match.dependency.canonical_ecosystem,
                            },
                            {
                                "name": "cicc:asset",
                                "value": match.dependency.asset or "unknown",
                            },
                        ],
                    }
                )
            entry = _vulnerability_entry(
                cve,
                _record_for(report, cve),
                bom_ref=f"{cve}|{pkg_ref}",
            )
            entry["affects"] = [{"ref": pkg_ref}]
            entry["analysis"] = _analysis_entry(match, state=state, kev=kev)
            if state == "under_investigation":
                under_investigation.append(f"{cve} {pkg_ref}")
            vulnerabilities.append(entry)

    # Records with no exposure evaluation still belong in the document (a VEX
    # consumer needs the vulnerability, not only our verdicts), but carry no
    # analysis - reported via `unassessed`, never silently dropped.
    unassessed: list[str] = []
    for cluster in report.clusters:
        cve = str(cluster.merged.cve)
        if cve in assessed_cves:
            continue
        unassessed.append(cve)
        vulnerabilities.append(
            _vulnerability_entry(cve, cluster.merged, bom_ref=cve)
        )

    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": VEX_SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": moment.astimezone(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "cicc",
                    "name": tool,
                    "version": tool_version,
                }
            ],
            "properties": [
                {"name": "cicc:origin", "value": report.origin.value},
                {
                    "name": "cicc:live_verified",
                    "value": "true" if report.live_verified else "false",
                },
                {"name": "cicc:notice", "value": report_notice(report)},
            ],
        },
        "vulnerabilities": vulnerabilities,
    }
    # The serialNumber is derived from the document CONTENT (canonical JSON hash),
    # not from the wall clock: identical logical inputs produce an identical BOM
    # serial across runs, which is what makes golden fixtures reproducible. The
    # generation timestamp still lives in metadata.timestamp (a fact about the
    # run, not part of the identity).
    hashable = {k: v for k, v in document.items() if k != "serialNumber"}
    hashable["metadata"] = {k: v for k, v in hashable["metadata"].items()
                            if k != "timestamp"}  # run fact, not document identity
    canonical = json.dumps(hashable, sort_keys=True, default=str)
    document["serialNumber"] = (
        f"urn:uuid:{uuid.uuid5(_CICC_NAMESPACE, hashlib.sha256(canonical.encode()).hexdigest())}"
    )
    if components:
        document["components"] = components

    return VexExport(
        document=document,
        unassessed=tuple(sorted(unassessed)),
        under_investigation=tuple(sorted(under_investigation)),
        lost=(
            "kev_due_date",
            "epss_score",
            "ssvc",
            "conflicts",
            "provenance",
        ),
    )


def _record_for(report: AssessmentReport, cve: str) -> Any:
    for cluster in report.clusters:
        if str(cluster.merged.cve) == cve:
            return cluster.merged
    raise KeyError(f"no record for {cve} in report")


def report_notice(report: AssessmentReport) -> str:
    """The honesty notice embedded in the document metadata."""
    from ..assessment import REPORT_NOTICE

    return REPORT_NOTICE
