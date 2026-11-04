"""CVSS v3.0 / v3.1 base-score computation.

Why implement it instead of trusting a number in the feed: sources disagree, and
some only publish the vector.  Computing locally lets the platform compare
"what the source said" against "what the vector implies" and record a conflict
instead of silently picking one.

Scope is deliberately narrow:

* only the **base** metrics of CVSS v3.0 and v3.1 (identical formulas);
* CVSS v2 and v4.0 vectors are reported as *not assessed* — they are never
  guessed with a v3 formula.

References: FIRST CVSS v3.1 specification, sections 7.1 (base equations) and
7.4 (rounding).
"""

from __future__ import annotations

import math
from typing import Mapping

from .errors import UnsupportedVector, ValidationError
from .schema import CvssScore, Severity, severity_from_score

__all__ = ["SUPPORTED_VERSIONS", "cvss_from_source", "parse_vector", "score_vector"]

SUPPORTED_VERSIONS = ("3.0", "3.1")

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def parse_vector(vector: str) -> tuple[str, dict[str, str]]:
    """Split ``CVSS:3.1/AV:N/...`` into ``(version, metrics)``.

    Raises :class:`UnsupportedVector` for versions this module cannot score.
    """
    if not isinstance(vector, str) or not vector.strip():
        raise ValidationError("CVSS vector must be a non-empty string", field="vector")
    text = vector.strip()
    head, separator, tail = text.partition("/")
    if not separator or not head.upper().startswith("CVSS:"):
        raise ValidationError("CVSS vector must start with 'CVSS:<version>/'", field="vector")
    version = head.split(":", 1)[1].strip()
    if version not in SUPPORTED_VERSIONS:
        raise UnsupportedVector(
            f"CVSS version {version!r} is not scored here (supported: "
            + ", ".join(SUPPORTED_VERSIONS)
            + ")",
            field="vector",
        )
    metrics: dict[str, str] = {}
    for part in tail.split("/"):
        if not part:
            continue
        key, separator, value = part.partition(":")
        if not separator:
            raise ValidationError(f"malformed metric {part!r}", field="vector")
        metrics[key.strip().upper()] = value.strip().upper()
    missing = [name for name in _REQUIRED if name not in metrics]
    if missing:
        raise ValidationError(
            "CVSS base vector is missing metrics: " + ", ".join(missing), field="vector"
        )
    return version, metrics


def _roundup(value: float) -> float:
    """CVSS v3.1 Appendix A rounding: round up to one decimal place."""
    integer = round(value * 100000)  # round(float) -> int
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def _metric(table: Mapping[str, float], metrics: Mapping[str, str], name: str) -> float:
    try:
        return table[metrics[name]]
    except KeyError as exc:
        raise ValidationError(f"invalid value for {name}", field="vector") from exc


def score_vector(vector: str, *, source: str | None = None) -> CvssScore:
    """Compute the CVSS v3 base score for ``vector``.

    Raises :class:`UnsupportedVector` (v2/v4) or :class:`ValidationError`
    (malformed vector).  It never returns a fabricated score.
    """
    version, metrics = parse_vector(vector)
    scope_changed = metrics["S"] == "C"
    if metrics["S"] not in ("U", "C"):
        raise ValidationError("invalid value for S", field="vector")

    iss = 1.0 - (
        (1.0 - _metric(_CIA, metrics, "C"))
        * (1.0 - _metric(_CIA, metrics, "I"))
        * (1.0 - _metric(_CIA, metrics, "A"))
    )
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    pr = _metric(_PR_CHANGED if scope_changed else _PR_UNCHANGED, metrics, "PR")
    exploitability = (
        8.22
        * _metric(_AV, metrics, "AV")
        * _metric(_AC, metrics, "AC")
        * pr
        * _metric(_UI, metrics, "UI")
    )

    if impact <= 0:
        base = 0.0
    elif scope_changed:
        base = _roundup(min(1.08 * (impact + exploitability), 10.0))
    else:
        base = _roundup(min(impact + exploitability, 10.0))

    return CvssScore(
        version=version,
        base_score=base,
        severity=severity_from_score(base),
        vector=vector.strip(),
        assessed=True,
        source=source,
    )


def cvss_from_source(
    *,
    version: str | None,
    vector: str | None,
    base_score: float | None,
    source: str | None = None,
) -> CvssScore | None:
    """Build a score from whatever the source published.

    Order of trust:

    1. vector present and supported -> compute locally;
    2. otherwise source base score -> keep it verbatim;
    3. otherwise ``None`` (this source said nothing about severity).

    When both exist and disagree by more than 0.1, the computed value wins and
    the object records ``assessed=True`` — callers can compare via
    :func:`disagreement` to raise a conflict note.
    """
    if vector:
        try:
            computed = score_vector(vector, source=source)
        except UnsupportedVector:
            computed = None
        if computed is not None:
            return computed
    if base_score is not None:
        if not isinstance(base_score, (int, float)) or isinstance(base_score, bool):
            raise ValidationError("CVSS base score must be numeric", field="base_score")
        value = float(base_score)
        return CvssScore(
            version=(version or "unknown"),
            base_score=value,
            severity=severity_from_score(value),
            vector=vector,
            assessed=vector is None,
            source=source,
        )
    if vector:
        # A vector we cannot evaluate is still evidence; keep it unassessed.
        return CvssScore(
            version=version or "unknown",
            base_score=0.0,
            severity=Severity.UNKNOWN,
            vector=vector,
            assessed=False,
            source=source,
        )
    return None


def disagreement(score: CvssScore, stated: float | None) -> str | None:
    """Human-readable note when the source number differs from the computed one."""
    if stated is None or not score.assessed or score.vector is None:
        return None
    if abs(score.base_score - float(stated)) > 0.1:
        return (
            f"source CVSS {float(stated):.1f} disagrees with vector-derived "
            f"{score.base_score:.1f} ({score.version})"
        )
    return None
