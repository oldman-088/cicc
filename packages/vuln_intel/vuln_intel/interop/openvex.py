"""Emit assessment verdicts as an OpenVEX document.

Why a second VEX dialect
------------------------
``interop.vex`` emits CycloneDX VEX, which is what CycloneDX-native tools (Dependency-
Track, OWASP) ingest. OpenVEX is the other dialect in real use, and it is the one that
several scanners and policy engines accept natively; a consumer that speaks only OpenVEX
cannot read a CycloneDX document at all. Emitting both costs a small adapter and removes
a schema translation from every downstream team that uses the other one.

The interesting part is not the JSON shape — it is that OpenVEX *forces* an honesty this
package had been glossing over.

``not_affected`` requires a ``justification`` from a fixed enumeration. That means the
document cannot simply say "we are not affected"; it has to say **why**, and different
whys are not interchangeable:

``vulnerable_code_not_in_execute_path``  the vulnerable code is present but unreachable
``vulnerable_code_cannot_be_controlled_by_adversary``  an attacker cannot influence it
``inline_mitigations_already_exist``  a mitigation is in place

CycloneDX VEX lets a bare ``not_affected`` through, so nothing had forced the question of
what we actually know. We do **not** know reachability — that needs call-graph analysis
we do not perform. What we do know is where the installed version sits relative to the
advisory's ranges, which is why :class:`~vuln_intel.affected.ExclusionSide` exists.

Mapping discipline
------------------
* ``AFFECTED`` + KEV     -> ``affected`` (with the KEV flag in ``status_notes``)
* ``AFFECTED``           -> ``affected``
* ``NOT_AFFECTED``, version below the range -> ``not_affected`` with
  ``justification: vulnerable_code_not_present``, because that release predates the
  vulnerable code entirely.
* ``NOT_AFFECTED``, version at/above the fix -> ``not_affected`` with **no**
  justification, only a ``status_note``. This is deliberate. The package *does* contain
  the vulnerable code path; it simply already carries the patch. Emitting
  ``vulnerable_code_not_present`` there would be a false statement, and emitting
  ``inline_mitigations_already_exist`` would misdescribe a version bump as a mitigation.
  OpenVEX makes ``justification`` optional, so omitting it is the accurate choice: the
  status is ``not_affected`` and the note says the fix is present.
* ``UNKNOWN``            -> ``under_investigation``. Never ``not_affected``.

A consumer that treats a missing justification as malformed is told the truth by the
``status_notes`` field rather than by a fabricated enum value. That trade is recorded in
``lost`` so it is visible rather than silent.

Like the CycloneDX adapter this module performs no I/O and imports nothing third-party.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..affected import ExclusionSide, Verdict
from ..assessment import AssessmentReport
from ..watchlist import PackageMatch

__all__ = [
    "OPENVEX_SPEC_VERSION",
    "OpenVexExport",
    "openvex_status_for",
    "to_openvex",
]

#: OpenVEX spec version this adapter targets.
OPENVEX_SPEC_VERSION = "0.2.0"

#: The spec's ``@context``. Fixed by the standard; not ours to choose.
_CONTEXT = "https://openvex.dev/ns/v0.2.0"

#: The only statuses OpenVEX defines.
ALLOWED_STATUSES = frozenset({"not_affected", "affected", "fixed", "under_investigation"})

#: The only justifications OpenVEX defines. Anything outside this set is a schema
#: violation, so a new one can never be invented at a call site.
ALLOWED_JUSTIFICATIONS = frozenset(
    {
        "component_not_present",
        "vulnerable_code_not_present",
        "vulnerable_code_not_in_execute_path",
        "vulnerable_code_cannot_be_controlled_by_adversary",
        "inline_mitigations_already_exist",
    }
)

#: Justification used when the installed version predates the affected range. The code
#: the advisory describes did not exist in that release.
_PREDATES_JUSTIFICATION = "vulnerable_code_not_present"


@dataclass(frozen=True)
class OpenVexExport:
    """An OpenVEX document plus an honest account of what it does not cover."""

    document: dict[str, Any]
    #: CVEs with ratings but no exposure evaluation, so no statement could be made.
    unassessed: tuple[str, ...] = ()
    #: ``"CVE pkg@version"`` for every statement emitted as ``under_investigation``.
    under_investigation: tuple[str, ...] = ()
    #: ``not_affected`` statements emitted with no justification, and why. A consumer
    #: that requires one needs to know these exist rather than discover it downstream.
    unjustified_not_affected: tuple[str, ...] = ()
    #: Our model's fields with no OpenVEX counterpart.
    lost: tuple[str, ...] = field(default_factory=tuple)

    def to_json(self) -> str:
        return json.dumps(self.document, indent=2, sort_keys=True)

    @property
    def statements(self) -> list[dict[str, Any]]:
        return list(self.document.get("statements") or [])


def openvex_status_for(
    verdict: Verdict, *, kev: bool | None = None, excluded_by: ExclusionSide | None = None
) -> tuple[str, str | None]:
    """Map our verdict to ``(status, justification)``.

    ``justification`` is ``None`` when the spec permits omitting it and emitting one
    would be a false statement about the package.
    """
    if verdict is Verdict.AFFECTED:
        return "affected", None
    if verdict is Verdict.NOT_AFFECTED:
        if excluded_by is ExclusionSide.BEFORE:
            return "not_affected", _PREDATES_JUSTIFICATION
        # AFTER (patch present) and UNKNOWN/None (unusable range) both get no
        # justification: the first because the code is present, the second because we
        # cannot describe why we are not affected.
        return "not_affected", None
    # UNKNOWN, and anything new that is not explicitly handled, must never read as safe.
    return "under_investigation", None


def _product(match: PackageMatch) -> dict[str, Any]:
    """An OpenVEX ``product``.

    OpenVEX identifies a product by ``@id``, a URI or purl. The human-readable
    name/version pair is kept in ``identifiers`` because a purl is not always available
    and a consumer diffing two documents by name is a real case.
    """
    purl = getattr(match.dependency, "purl", None)
    identity = str(purl) if purl else (
        f"pkg:{match.dependency.canonical_ecosystem}/{match.dependency.canonical_name}"
        f"@{match.dependency.version}"
    )
    return {
        "@id": identity,
        "identifiers": {
            "purl": identity if identity.startswith("pkg:") else "",
            "name": match.dependency.canonical_name,
            "version": match.dependency.version,
        },
    }


def _status_note(match: PackageMatch, *, status: str, kev: bool | None) -> str:
    parts = [f"cicc verdict: {match.assessment.verdict.value}"]
    # The status below comes from our version-ranges verdict. The advisory's standing
    # is a different fact and has to ride along, or this document says `affected`
    # about a CVE the vendor has retracted while our own CTIS export says
    # `false_positive` about the same record.
    if match.record_status is not None:
        parts.append(f"advisory standing: {match.record_status.value}")
    if match.assessment.reasons:
        parts.extend(match.assessment.reasons)
    fixed = match.assessment.fixed_version or match.advisory_fixed
    if fixed and status == "affected":
        parts.append(f"first fixed version: {fixed}")
    if status == "not_affected":
        if match.assessment.excluded_by is ExclusionSide.AFTER and fixed:
            parts.append(f"installed version already contains the fix published as {fixed}")
        elif match.assessment.excluded_by is ExclusionSide.AFTER:
            parts.append("installed version is above the affected range")
        elif match.assessment.excluded_by is ExclusionSide.BEFORE:
            parts.append("installed version predates the affected range")
        else:
            parts.append("excluded by a range that could not be compared to a version")
    if kev is not None:
        parts.append(f"cisa_kev: {'listed' if kev else 'not listed'}")
    return "; ".join(parts)


def _statement_id(*parts: str) -> str:
    """Deterministic identifier, so identical inputs give an identical document."""
    seed = uuid.uuid5(uuid.NAMESPACE_URL, "\x1f".join(parts))
    return f"https://cicc.example/vex/{seed}"


def to_openvex(
    report: AssessmentReport,
    *,
    generated_at: datetime | None = None,
    tool: str = "cicc-vuln-intel",
    tool_version: str = "0.1.0",
    author: str = "cicc-vuln-intel",
) -> OpenVexExport:
    """Build an OpenVEX document from an :class:`AssessmentReport`."""
    moment = generated_at or datetime.now(tz=timezone.utc)
    if moment.tzinfo is None:
        raise ValueError("generated_at must be timezone-aware")
    stamp = moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    kev_by_cve: dict[str, bool | None] = {}
    for cluster in report.clusters:
        kev_by_cve[str(cluster.merged.cve)] = cluster.merged.kev

    statements: list[dict[str, Any]] = []
    unassessed_cves: list[str] = []
    assessed: set[str] = set()
    under_investigation: list[str] = []
    unjustified: list[str] = []

    if report.exposure is not None:
        for match in (
            *report.exposure.matches,
            *report.exposure.unverified,
            *report.exposure.not_affected,
        ):
            kev = kev_by_cve.get(match.cve)
            status, justification = openvex_status_for(
                match.assessment.verdict,
                kev=kev,
                excluded_by=match.assessment.excluded_by,
            )
            if status not in ALLOWED_STATUSES:  # pragma: no cover - defensive
                raise ValueError(f"illegal OpenVEX status: {status}")
            if justification is not None and justification not in ALLOWED_JUSTIFICATIONS:
                raise ValueError(f"illegal OpenVEX justification: {justification}")

            assessed.add(match.cve)
            label = f"{match.cve} {match.dependency.canonical_name}@{match.dependency.version}"
            statement: dict[str, Any] = {
                "vulnerability": {"name": match.cve},
                "products": [_product(match)],
                "status": status,
                "status_notes": _status_note(match, status=status, kev=kev),
                "timestamp": stamp,
                "@id": _statement_id(match.cve, match.dependency.canonical_name, match.dependency.version),
            }
            if justification is not None:
                statement["justification"] = justification
            elif status == "not_affected":
                unjustified.append(label)
            if status == "under_investigation":
                under_investigation.append(label)
            statements.append(statement)

    for cluster in report.clusters:
        cve = str(cluster.merged.cve)
        if cve not in assessed:
            unassessed_cves.append(cve)

    document = {
        "@context": _CONTEXT,
        "@id": _statement_id(
            "document",
            stamp,
            *sorted(assessed),
        ),
        "author": author,
        "timestamp": stamp,
        "version": 1,
        "statements": statements,
        "tooling": f"{tool} {tool_version}",
    }

    lost = (
        "CVSS ratings: OpenVEX carries no scoring, so severities are in the CycloneDX VEX "
        "export only",
        "fixed version: expressed here as a status note, not a machine-readable field",
        "KEV listing: a status note, not a field",
    )
    return OpenVexExport(
        document=document,
        unassessed=tuple(unassessed_cves),
        under_investigation=tuple(under_investigation),
        unjustified_not_affected=tuple(unjustified),
        lost=lost,
    )
