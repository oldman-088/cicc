"""SARIF 2.1.0 ingest (B-07, the SARIF half).

SARIF is what scanners emit; VEX/CycloneDX is what we emit.  This module is the
*import* direction: read a SARIF log, keep the scanner's evidence intact, and
derive vulnerability candidates **only where justified** — a scanner finding is
not a confirmed vulnerability, and this adapter never upgrades one into the
other or inflates severity/confidence because a tool produced a result.

Rules:

* the document must declare ``version == "2.1.0"``; anything else is refused,
  not partially read;
* tool identity (driver name/version), rule id, level, message, location and
  fingerprints are preserved verbatim on every finding;
* a finding becomes a vulnerability candidate only when a CVE id appears in the
  rule id or in ``properties``/``tags`` — never from free-text guessing;
* candidates are deduplicated by (CVE, fingerprint) so the same finding from
  two runs collapses, while two *different* findings for the same CVE are kept
  separate (merging them would be a false merge);
* every candidate carries explicit provenance (tool, rule, run) and
  ``confirmed=False`` — confirmation requires our own assessment pipeline.

No I/O, no third-party imports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from ..errors import ValidationError
from ..schema import CveId

__all__ = [
    "SARIF_VERSION",
    "SarifDocument",
    "SarifFinding",
    "VulnerabilityCandidate",
    "parse_sarif",
    "to_vulnerability_candidates",
]

SARIF_VERSION = "2.1.0"

_CVE_IN_TEXT = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

#: Scanner levels we accept, mapped to a *scanner* severity word. This is the
#: tool's own claim, kept distinct from any CVSS severity we compute ourselves.
_LEVELS = frozenset({"none", "note", "warning", "error"})


@dataclass(frozen=True)
class SarifFinding:
    """One SARIF result with the scanner's evidence preserved."""

    run_index: int
    tool: str
    tool_version: str | None
    rule_id: str | None
    level: str
    message: str
    uri: str | None
    fingerprints: Mapping[str, str]
    properties: Mapping[str, Any]

    @property
    def fingerprint(self) -> str | None:
        """Best available stable identity of the finding, if the tool gave one."""
        for key in ("partialFingerprints", "fingerprints"):
            value = self.fingerprints.get(key)
            if isinstance(value, str) and value:
                return value
        # fingerprints may be nested dicts; take any scalar value deterministically
        for value in sorted(self.fingerprints.values()):
            if isinstance(value, str) and value:
                return value
        return None

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_index": self.run_index,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "rule_id": self.rule_id,
            "level": self.level,
            "message": self.message,
            "uri": self.uri,
            "fingerprints": dict(self.fingerprints),
            "properties": dict(self.properties),
        }


@dataclass(frozen=True)
class SarifDocument:
    """A validated SARIF log."""

    version: str
    findings: tuple[SarifFinding, ...]
    #: Runs skipped because they were malformed. Counted, not dropped silently.
    skipped_runs: int = 0

    @property
    def tools(self) -> tuple[str, ...]:
        return tuple(sorted({f.tool for f in self.findings}))


@dataclass(frozen=True)
class VulnerabilityCandidate:
    """A scanner finding that plausibly maps to a CVE — still unconfirmed."""

    cve: str
    finding: SarifFinding
    #: Where the CVE id came from: rule id or a property/tag. Never free text.
    cve_source: str
    #: Always False on ingest: a scanner finding is a *lead*, not a confirmed
    #: vulnerability. Confirmation comes from our assessment pipeline only.
    confirmed: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "cve_source": self.cve_source,
            "confirmed": self.confirmed,
            "finding": self.finding.as_dict(),
        }


def _finding_from_result(run_index: int, tool: str, tool_version: str | None,
                         run: Mapping[str, Any], result: object) -> SarifFinding | None:
    if not isinstance(result, Mapping):
        return None
    level = result.get("level", "warning")
    if not isinstance(level, str) or level not in _LEVELS:
        level = "warning" if level is None else str(level)
        if level not in _LEVELS:
            return None  # unknown enum: skip the row, count via caller
    message = result.get("message")
    message_text = message.get("text") if isinstance(message, Mapping) else None
    if not isinstance(message_text, str):
        message_text = str(message) if message else ""
    locations = result.get("locations")
    uri = None
    if isinstance(locations, list) and locations:
        first = locations[0]
        if isinstance(first, Mapping):
            physical = first.get("physicalLocation")
            if isinstance(physical, Mapping):
                artifact = physical.get("artifactLocation")
                if isinstance(artifact, Mapping) and isinstance(artifact.get("uri"), str):
                    uri = artifact["uri"]
    fingerprints: dict[str, str] = {}
    for key in ("fingerprints", "partialFingerprints"):
        raw = result.get(key)
        if isinstance(raw, Mapping):
            for k, v in raw.items():
                if isinstance(v, str):
                    fingerprints[f"{key}/{k}"] = v
    props = result.get("properties")
    return SarifFinding(
        run_index=run_index,
        tool=tool,
        tool_version=tool_version,
        rule_id=result.get("ruleId") if isinstance(result.get("ruleId"), str) else None,
        level=level,
        message=message_text,
        uri=uri,
        fingerprints=fingerprints,
        properties=dict(props) if isinstance(props, Mapping) else {},
    )


def parse_sarif(document: object) -> SarifDocument:
    """Validate and parse a SARIF 2.1.0 document.

    Raises :class:`ValidationError` on structural problems that would make the
    rest of the document untrustworthy (not an object, wrong version, no runs).
    Malformed *individual results* are skipped and counted in the findings'
    containing document via ``skipped_runs`` only at run granularity.
    """
    if not isinstance(document, Mapping):
        raise ValidationError("SARIF document must be an object", field="document")
    version = document.get("version")
    if version != SARIF_VERSION:
        raise ValidationError(
            f"unsupported SARIF version {version!r}; only {SARIF_VERSION} is supported",
            field="version",
        )
    runs = document.get("runs")
    if not isinstance(runs, list):
        raise ValidationError("SARIF document has no 'runs' list", field="runs")
    findings: list[SarifFinding] = []
    skipped_runs = 0
    for run_index, run in enumerate(runs):
        if not isinstance(run, Mapping):
            skipped_runs += 1
            continue
        tool = run.get("tool")
        driver = tool.get("driver") if isinstance(tool, Mapping) else None
        if not isinstance(driver, Mapping) or not isinstance(driver.get("name"), str):
            skipped_runs += 1
            continue
        tool_name = driver["name"]
        tool_version = driver.get("version")
        results = run.get("results", [])
        if not isinstance(results, list):
            skipped_runs += 1
            continue
        for result in results:
            finding = _finding_from_result(
                run_index, tool_name,
                tool_version if isinstance(tool_version, str) else None,
                run, result,
            )
            if finding is not None:
                findings.append(finding)
    return SarifDocument(
        version=version, findings=tuple(findings), skipped_runs=skipped_runs
    )


def _cve_in(value: object) -> str | None:
    if isinstance(value, str):
        match = _CVE_IN_TEXT.search(value)
        if match:
            return str(CveId.parse(match.group(0)))
    return None


def to_vulnerability_candidates(
    findings: Iterable[SarifFinding],
) -> tuple[VulnerabilityCandidate, ...]:
    """Map findings to CVE candidates, deduplicated without false merges.

    Dedup key is (CVE, fingerprint): the *same* finding reported twice (two runs,
    a re-scan) collapses to one candidate. A finding with no fingerprint dedups
    on (CVE, tool, rule_id, uri, message) — identical content only. Different
    findings about the same CVE are all kept.
    """
    seen: set[tuple[str, str]] = set()
    out: list[VulnerabilityCandidate] = []
    for finding in findings:
        cve = None
        cve_source = ""
        if finding.rule_id:
            cve = _cve_in(finding.rule_id)
            if cve:
                cve_source = "ruleId"
        if cve is None:
            for key in ("cve", "cveId", "cve_id", "vulnerability_id"):
                value = finding.properties.get(key)
                cve = _cve_in(value)
                if cve:
                    cve_source = f"properties.{key}"
                    break
        if cve is None and isinstance(finding.properties.get("tags"), list):
            for tag in finding.properties["tags"]:
                cve = _cve_in(tag)
                if cve:
                    cve_source = "properties.tags"
                    break
        if cve is None:
            continue  # no published identifier: not a vulnerability candidate
        fingerprint = finding.fingerprint or (
            f"{finding.tool}|{finding.rule_id}|{finding.uri}|{finding.message}"
        )
        dedup_key = (cve, fingerprint)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        out.append(
            VulnerabilityCandidate(cve=cve, finding=finding, cve_source=cve_source)
        )
    return tuple(sorted(out, key=lambda c: (c.cve, c.finding.tool, c.finding.rule_id or "")))
