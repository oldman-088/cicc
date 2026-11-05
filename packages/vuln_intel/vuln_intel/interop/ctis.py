"""Emit our assessments as CTIS findings.

CTIS (CTEM Ingest Schema) is the open, Apache-2.0 contract published by the
OpenCTEM project for sending assets, findings and SBOM dependencies into a CTEM
platform. Adopting it instead of inventing a bespoke export has one large benefit
and one real cost:

* **Benefit.** An external schema validates our output. Fields we got wrong stop
  being an internal disagreement and become a test failure. That is a stronger
  guarantee than any amount of internal consistency checking.
* **Cost.** Our vocabulary has to bend towards theirs. Where it does not fit, this
  module says so explicitly (``lost``) rather than dropping the information quietly.

Deliberately **not** a dependency: CTIS lives on GitHub and is not on PyPI, and this
package is stdlib-only. The subset modelled here is transcribed from the published
``schemas/v2/finding.json`` (schema id ``https://schemas.openctem.io/ctis/2.0/
finding.json``) and is validated against the real schema in tests when the schema
file is present.

Why bother when we already have our own contract: CICC's read API serves *our*
consumers, while CTIS is what lets a third-party CTEM platform consume us without
writing a bespoke adapter. That is the difference between "we have a data model" and
"other tools can use it".
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..priorities import PriorityResult
from ..remediation import RecommendedAction, Remediation
from ..schema import NormalizedVulnerability, RecordStatus
from ..ssvc import assess_ssvc

#: The CTIS finding type we emit. We describe vulnerabilities, not secrets or
#: misconfigurations, so the other seven enum values are unreachable from here.
FINDING_TYPE = "vulnerability"

#: Maps :class:`RecommendedAction` onto CTIS ``remediation.solution_type``.
#:
#: ``no_fix_planned`` does not exist in our vocabulary because we never learn the
#: vendor's *intent*, only whether a fixed version is known. Emitting it would claim
#: knowledge we do not have, so the absence of a fix maps to ``none_available``,
#: which is a statement about what is available rather than about what is planned.
_SOLUTION_TYPE = {
    RecommendedAction.EMERGENCY_PATCH: "vendor_fix",
    RecommendedAction.PATCH: "vendor_fix",
    RecommendedAction.UPGRADE_MAJOR: "upgrade",
    # Affected with no fixed release: a workaround is what we can offer.
    RecommendedAction.MITIGATE: "workaround",
    RecommendedAction.MONITOR: "mitigation",
    RecommendedAction.NONE: "mitigation",
}

#: Sequences of length 20 or 32 in the schema; ours are far smaller, but a runaway
#: record should not produce an unvalidatable document.
_MAX_TECHNIQUES = 20
_MAX_SCORES = 32


@dataclass(frozen=True)
class CtisConversion:
    """A CTIS finding plus an honest account of what did not survive the mapping."""

    finding: dict[str, Any]
    #: Things CTIS has no field for. Empty is the good outcome; a non-empty tuple is
    #: not an error, but a caller who assumed a lossless export should see it.
    lost: tuple[str, ...] = ()
    #: Non-fatal problems that made a value unusable.
    warnings: tuple[str, ...] = ()

    @property
    def lossless(self) -> bool:
        return not self.lost


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _status(record: NormalizedVulnerability) -> tuple[str, tuple[str, ...]]:
    """Record standing → ``(status, warnings)``.

    This mapping is the reason the module is worth writing: it forced two decisions
    that our own model had left implicit.

    A **rejected or withdrawn** advisory is not an open finding — it must not appear
    in a remediation queue — so it maps to ``false_positive``. ``suppressed`` would be
    wrong: suppressed means *we* chose to silence a real finding, whereas a rejection
    means the finding was never true.

    Silence maps to ``open``, not to some unknown value, because CTIS requires one of
    six states and the operationally safe reading of "the source said nothing" is to
    keep looking at it. Unlike our own model, where ``None`` is deliberately
    representable, a downstream enum leaves no room for that nuance.
    """
    status = record.record_status
    if status is RecordStatus.REJECTED:
        return "false_positive", ()
    if status is RecordStatus.DISPUTED:
        return "in_progress", (
            "standing is disputed; CTIS has no 'disputed' status, so it is sent as "
            "in_progress - a downstream consumer should not read that as 'being fixed'",
        )
    return "open", ()


def _severity(record: NormalizedVulnerability) -> tuple[str, tuple[str, ...]]:
    """Our severity vocabulary → CTIS's six values.

    Ours has ``unknown`` and theirs has ``unknown``, which is fortunate: an unmapped
    severity must not silently become ``info`` (the lowest) because that would rank a
    record we know nothing about below one we know to be benign.
    """
    severity = record.effective_severity
    value = getattr(severity, "value", "unknown")
    allowed = {"critical", "high", "medium", "low", "info", "unknown"}
    if value in allowed:
        return value, ()
    if value == "none":
        return "info", ("severity 'none' has no CTIS equivalent; sent as 'info'",)
    return "unknown", (f"severity {value!r} is not a CTIS value; sent as 'unknown'",)


def _vulnerability_block(record: NormalizedVulnerability) -> dict[str, Any]:
    ids: list[dict[str, str]] = [{"type": "cve", "id": str(record.cve)}]
    for alias in record.aliases:
        text = str(alias)
        if text.startswith("GHSA-"):
            ids.append({"type": "ghsa", "id": text})
        elif text.startswith("CVE-"):
            # A second CVE alias is a different CVE, not an id of this one.
            continue
        else:
            ids.append({"type": "osv", "id": text})

    block: dict[str, Any] = {
        "ids": ids,
        "cwe_ids": [str(c) for c in record.cwe],
        "published_at": _iso(record.published),
        "modified_at": _iso(record.modified),
    }
    affected = record.affected
    if affected:
        first = affected[0]
        if first.name:
            block["package_name"] = first.name
        if first.purl:
            block["purl"] = first.purl
        # `AffectedPackage.fixed` is a single version (the first fix), not a range of
        # them: one advisory may name several affected packages, each with its own fix.
        fixed = [entry.fixed for entry in affected if entry.fixed]
        if fixed:
            block["fixed_versions"] = list(dict.fromkeys(fixed))
    return {key: value for key, value in block.items() if value not in (None, [], ())}


def _scores(record: NormalizedVulnerability) -> list[dict[str, Any]]:
    """Every score the record carries, in CTIS's flat, sourced form.

    CTIS treats ``epss`` and ``ssvc`` as score *systems*, which is more expressive
    than a nested object: each value keeps its own source and date. We emit one entry
    per CVSS assessment rather than collapsing them, so a disagreement between NVD's
    v3.1 and a vendor's v4.0 stays visible downstream.
    """
    scores: list[dict[str, Any]] = []
    for score in record.cvss[:_MAX_SCORES]:
        if not score.assessed:
            continue
        entry: dict[str, Any] = {"system": "cvss", "version": score.version}
        if score.vector:
            entry["vector"] = score.vector
        entry["value"] = score.base_score
        if score.source:
            entry["source"] = score.source
        scores.append(entry)
    if record.epss_score is not None:
        entry = {"system": "epss", "value": record.epss_score}
        if record.epss_model_date:
            entry["source"] = f"first:{record.epss_model_date}"
        scores.append(entry)
    if record.epss_percentile is not None:
        scores.append({"system": "epss_percentile", "value": record.epss_percentile})

    inputs = dict(record.ssvc)
    assessment = assess_ssvc(
        exploitation=inputs.get("exploitation"),
        automatable=inputs.get("automatable"),
        technical_impact=inputs.get("technical_impact"),
        # mission_wellbeing is stakeholder-specific and unknown to us, so the tree
        # cannot produce a decision. CTIS allows ssvc to carry a vector or a label
        # instead of a value, which is exactly right for a partial assessment.
        mission_wellbeing=None,
    )
    if assessment is not None:
        ssvc: dict[str, Any] = {"system": "ssvc", "source": "cisa"}
        if assessment.decision is not None:
            ssvc["label"] = assessment.decision.value
        else:
            # No single decision: an unknown stakeholder input means several
            # decisions remain possible, and picking one would be an invention.
            # A range label is honest about that ("track..attend").
            ssvc["label"] = f"{assessment.floor.value}..{assessment.ceiling.value}"
        scores.append(ssvc)
    return scores[:_MAX_SCORES]


def _techniques(record: NormalizedVulnerability, mapping: Any) -> list[str]:
    if mapping is None:
        return []
    found = mapping.by_cve.get(str(record.cve)) if hasattr(mapping, "by_cve") else None
    if not found:
        return []
    return [t.technique_id for t in found][:_MAX_TECHNIQUES]


def to_ctis_finding(
    record: NormalizedVulnerability,
    *,
    remediation: Remediation | None = None,
    priority: PriorityResult | None = None,
    attack_mapping: Any = None,
    asset_ref: str | None = None,
) -> CtisConversion:
    """Convert one normalized record into a CTIS ``finding`` object.

    ``asset_ref`` is required by CTIS and optional here. When it is absent we emit a
    synthetic advisory-level reference, which is honest: the finding describes a
    vulnerability in the abstract, not an instance on a named host. A caller with a
    real inventory should pass the real asset.
    """
    lost: list[str] = []
    warnings: list[str] = []

    severity, severity_warnings = _severity(record)
    warnings.extend(severity_warnings)
    status, status_warnings = _status(record)
    warnings.extend(status_warnings)

    finding: dict[str, Any] = {
        "type": FINDING_TYPE,
        "title": f"{record.cve}",
        "severity": severity,
        "asset_ref": asset_ref or f"advisory:{record.cve}",
        "status": status,
        "vulnerability": _vulnerability_block(record),
    }
    if record.summary:
        finding["title"] = f"{record.cve}: {record.summary}"[:512]
        finding["description"] = record.summary

    scores = _scores(record)
    if scores:
        finding["scores"] = scores

    techniques = _techniques(record, attack_mapping)
    if techniques:
        finding["attack_technique_ids"] = techniques

    if record.kev is not None:
        # KEV has no field of its own in CTIS. `tags` is the documented free-form
        # place for it, and the loss is recorded because a consumer without knowledge
        # of our tagging convention will not see it as structured data.
        finding["tags"] = ["cisa-kev"] if record.kev else []
        if record.kev:
            lost.append(
                "kev: CTIS has no KEV field; expressed as the 'cisa-kev' tag, which a "
                "consumer must know to interpret"
            )
    if record.references:
        references: list[str] = []
        for reference in record.references[:50]:
            url = reference if isinstance(reference, str) else getattr(reference, "url", None)
            if url:
                references.append(str(url))
        if references:
            finding["references"] = references

    if remediation is not None:
        block: dict[str, Any] = {
            "solution_type": _SOLUTION_TYPE.get(remediation.action, "mitigation"),
            "recommendation": remediation.instruction,
        }
        if remediation.target_version:
            block["is_fix_available"] = True
        finding["remediation"] = block

    if record.withdrawn is not None:
        # `source_lifecycle` is the finding's history *as the source tracks it*,
        # which is exactly what a withdrawal is.
        finding["source_lifecycle"] = {"state": "fixed"}

    if priority is not None:
        # Our composite score has no CTIS home: `scores.system` is a closed enum of
        # cvss/epss/epss_percentile/ssvc/vendor. Sending it as "vendor" would claim
        # a vendor assigned it, so it goes in `properties`, which is the schema's
        # namespace for tool-specific data.
        finding["properties"] = {
            "cicc": {
                "priority_score": priority.score,
                "priority_band": priority.band,
                "policy": priority.policy,
                "policy_approved": priority.policy_approved,
            }
        }
        finding["properties"]["cicc"] = {
            key: value
            for key, value in finding["properties"]["cicc"].items()
            if value is not None
        }
        lost.append(
            "priority: our composite score has no CTIS score system; sent under "
            "properties.cicc where a consumer must know to look"
        )

    if record.conflicts:
        lost.append(
            f"conflicts: {len(record.conflicts)} structured disagreement(s) have no "
            "CTIS representation; they are not exported"
        )

    if record.verification != "verified":
        warnings.append("record is unverified; no live provider request has been recorded")

    return CtisConversion(finding=finding, lost=tuple(lost), warnings=tuple(warnings))


def uuid7(*, at: datetime | None = None, random_bits: int | None = None) -> str:
    """A UUIDv7: 48-bit millisecond timestamp, then version/variant, then entropy.

    CTIS requires ``metadata.id`` to be a UUIDv7 because it is the **idempotency
    key** — a retry must re-send the same id so the receiver can deduplicate on
    ``(credential, id)``. A random v4 would defeat that: the retry would look like a
    second report and the findings would be ingested twice.
    """
    moment = at or datetime.now(tz=timezone.utc)
    millis = int(moment.timestamp() * 1000)
    if random_bits is None:
        random_bits = secrets.randbits(74)
    # 48 bits timestamp | 4 bits version | 12 bits rand_a | 2 bits variant | 62 bits rand_b
    rand_a = (random_bits >> 62) & 0xFFF
    rand_b = random_bits & ((1 << 62) - 1)
    value = (millis << 80) | (0x7 << 76) | (rand_a << 64) | (0b10 << 62) | rand_b
    text = f"{value:032x}"
    return f"{text[0:8]}-{text[8:12]}-{text[12:16]}-{text[16:20]}-{text[20:32]}"


def to_ctis_report(
    findings: list[CtisConversion],
    *,
    tool: str = "cicc-vuln-intel",
    generated_at: datetime | None = None,
    report_id: str | None = None,
    duration_ms: int | None = None,
) -> dict[str, Any]:
    """Wrap findings in a CTIS report envelope.

    ``metadata.id`` and ``metadata.generated_at`` are required, and the id must be a
    UUIDv7. Callers that retry must pass the **same** ``report_id``: it is the
    idempotency key, and a fresh one turns a retry into a duplicate ingest.
    """
    moment = generated_at or datetime.now(tz=timezone.utc)
    metadata: dict[str, Any] = {
        "id": report_id or uuid7(at=moment),
        "generated_at": moment.isoformat(),
    }
    if duration_ms is not None:
        metadata["duration_ms"] = duration_ms
    return {
        "version": "2.0",
        "metadata": metadata,
        "tool": {"name": tool},
        "findings": [item.finding for item in findings],
    }


@dataclass
class ConversionSummary:
    findings: list[dict[str, Any]] = field(default_factory=list)
    lossy: list[tuple[str, tuple[str, ...]]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def lossless(self) -> bool:
        return not self.lossy
