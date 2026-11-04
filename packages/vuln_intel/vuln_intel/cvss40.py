"""CVSS v4.0 base + threat + environmental scoring.

Implemented from the FIRST CVSS v4.0 specification (document version 1.2,
section 8) and the official reference implementation
(``FIRSTdotorg/cvss-v4-calculator``, BSD-2-Clause). The macrovector lookup
table and the EQ composition tables are **verbatim** from those sources: they
are normative data, not something to re-derive. The table is reproduced under
the terms of the reference implementation's licence, with attribution below.

Why implement it at all: NVD now publishes ``cvssMetricV40``, and a source that
publishes only a v4 vector would otherwise carry no computed score. Without this
module those records fall back to the source's stated severity with no vector
check, which is exactly the "trust the number" behaviour this package avoids.

Scope: the full CVSS-B, CVSS-BT and CVSS-BTE scores (base, threat and
environmental metrics). Supplemental metrics do not affect the score by
definition and are not modelled.

Correctness notes worth stating:

* **No-impact shortcut.** If every impact metric is ``N`` the score is 0.0,
  before any macrovector lookup. The reference implementation checks this first
  and so does this one.
* **Invalid combinations are rejected,** not defaulted. A vector missing a
  mandatory base metric, repeating a metric, or carrying an unknown value is a
  :class:`ValidationError` for the *assessed* metric groups only — the
  unassessed groups legitimately default (``E=X`` means ``E=A``).
* **Rounding matches the reference:** one decimal place, ``round-half-up`` via
  :func:`decimal`, because Python's built-in ``round`` is banker's rounding and
  would disagree with the calculator on ``x.x5`` values.

Attribution: CVSS is owned by FIRST.Org, Inc. and used by permission. The lookup
table (`_CVSS_LOOKUP`), the EQ maxima (`_MAX_SEVERITY`) and the highest-severity
vector composition (`_MAX_COMPOSED`) are taken from the CVSS v4.0 calculator
reference implementation, Copyright FIRST, Red Hat, and contributors,
BSD-2-Clause.
"""

from __future__ import annotations

from typing import Mapping

from .errors import UnsupportedVector, ValidationError
from .schema import CvssScore, severity_from_score

__all__ = [
    "CVSS40_METRIC_ORDER",
    "REQUIRED_BASE_METRICS",
    "is_v4_vector",
    "score_vector_v4",
]

#: Mandatory base metrics, in the order the specification requires.
REQUIRED_BASE_METRICS = (
    "AV",
    "AC",
    "AT",
    "PR",
    "UI",
    "VC",
    "VI",
    "VA",
    "SC",
    "SI",
    "SA",
)

#: Supplemental metrics: legal in a vector, never part of the score (spec 2.6).
#: Accepting them matters because suppliers publish them (e.g. ``/S:P/V:D``);
#: rejecting such a vector would discard a perfectly good base score.
SUPPLEMENTAL_METRICS = ("S", "AU", "R", "V", "RE", "U")

#: Full metric order: base, then threat, environmental and supplemental.
CVSS40_METRIC_ORDER = REQUIRED_BASE_METRICS + (
    "E",
    "CR",
    "IR",
    "AR",
    "MAV",
    "MAC",
    "MAT",
    "MPR",
    "MUI",
    "MVC",
    "MVI",
    "MVA",
    "MSC",
    "MSI",
    "MSA",
) + SUPPLEMENTAL_METRICS

#: Permitted values per metric, from the specification's metric tables.
_VALUES: Mapping[str, frozenset[str]] = {
    "AV": frozenset("NALP"),
    "AC": frozenset("LH"),
    "AT": frozenset("NP"),
    "PR": frozenset("NLH"),
    "UI": frozenset("NPA"),
    "VC": frozenset("HLN"),
    "VI": frozenset("HLN"),
    "VA": frozenset("HLN"),
    "SC": frozenset("HLN"),
    "SI": frozenset("HLN"),
    "SA": frozenset("HLN"),
    "E": frozenset("XAPU"),
    "CR": frozenset("XHML"),
    "IR": frozenset("XHML"),
    "AR": frozenset("XHML"),
    "MAV": frozenset("XNALP"),
    "MAC": frozenset("XLH"),
    "MAT": frozenset("XNP"),
    "MPR": frozenset("XNLH"),
    "MUI": frozenset("XNPA"),
    "MVC": frozenset("XHLN"),
    "MVI": frozenset("XHLN"),
    "MVA": frozenset("XHLN"),
    "MSC": frozenset("XHLN"),
    "MSI": frozenset("XSHLN"),
    "MSA": frozenset("XSHLN"),
    # Supplemental (validated, then ignored for scoring)
    "S": frozenset("XNP"),
    "AU": frozenset("XNY"),
    "R": frozenset("XAUI"),
    "V": frozenset("XDC"),
    "RE": frozenset("XLMH"),
    "U": frozenset({"X", "Clear", "Green", "Amber", "Red"}),
}

#: Metrics that carry a default of ``X`` (not assessed) rather than being required.
_OPTIONAL = frozenset(CVSS40_METRIC_ORDER) - frozenset(REQUIRED_BASE_METRICS)

#: Severity-distance levels. These encode "how many 0.1 steps worse is this
#: value", which is what the interpolation uses.
_AV = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
_PR = {"N": 0.0, "L": 0.1, "H": 0.2}
_UI = {"N": 0.0, "P": 0.1, "A": 0.2}
_AC = {"L": 0.0, "H": 0.1}
_AT = {"N": 0.0, "P": 0.1}
_V = {"H": 0.0, "L": 0.1, "N": 0.2}
_SC = {"H": 0.1, "L": 0.2, "N": 0.3}
_SI = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
_CR = {"H": 0.0, "M": 0.1, "L": 0.2}
_E = {"A": 0.0, "P": 0.1, "U": 0.2}
_STEP = 0.1

#: Depth of each macrovector (``+1`` of the maximum severity distance), verbatim
#: from ``max_severity.js``.
_MAX_SEVERITY: Mapping[str, Mapping] = {
    "eq1": {0: 1, 1: 4, 2: 5},
    "eq2": {0: 1, 1: 2},
    "eq3eq6": {0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}},
    "eq4": {0: 6, 1: 5, 2: 4},
    "eq5": {0: 1, 1: 1, 2: 1},
}

#: Highest-severity vector fragments per EQ level, verbatim from
#: ``max_composed.js``.
_MAX_COMPOSED: Mapping[str, Mapping] = {
    "eq1": {
        0: ["AV:N/PR:N/UI:N/"],
        1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
        2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
    },
    "eq2": {
        0: ["AC:L/AT:N/"],
        1: ["AC:H/AT:N/", "AC:L/AT:P/"],
    },
    "eq3": {
        0: {
            "0": ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
            "1": ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"],
        },
        1: {
            "0": ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
            "1": [
                "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
                "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
                "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
            ],
        },
        2: {"1": ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]},
    },
    "eq4": {
        0: ["SC:H/SI:S/SA:S/"],
        1: ["SC:H/SI:H/SA:H/"],
        2: ["SC:L/SI:L/SA:L/"],
    },
    "eq5": {
        0: ["E:A/"],
        1: ["E:P/"],
        2: ["E:U/"],
    },
}

#: MacroVector lookup table, verbatim from ``cvss_lookup.js``.
_CVSS_LOOKUP: Mapping[str, float] = {
    "000000": 10, "000001": 9.9, "000010": 9.8, "000011": 9.5, "000020": 9.5,
    "000021": 9.2, "000100": 10, "000101": 9.6, "000110": 9.3, "000111": 8.7,
    "000120": 9.1, "000121": 8.1, "000200": 9.3, "000201": 9, "000210": 8.9,
    "000211": 8, "000220": 8.1, "000221": 6.8, "001000": 9.8, "001001": 9.5,
    "001010": 9.5, "001011": 9.2, "001020": 9, "001021": 8.4, "001100": 9.3,
    "001101": 9.2, "001110": 8.9, "001111": 8.1, "001120": 8.1, "001121": 6.5,
    "001200": 8.8, "001201": 8, "001210": 7.8, "001211": 7, "001220": 6.9,
    "001221": 4.8, "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9,
    "002111": 6.9, "002121": 5, "002201": 6.9, "002211": 5.5, "002221": 2.7,
    "010000": 9.9, "010001": 9.7, "010010": 9.5, "010011": 9.2, "010020": 9.2,
    "010021": 8.5, "010100": 9.5, "010101": 9.1, "010110": 9, "010111": 8.3,
    "010120": 8.4, "010121": 7.1, "010200": 9.2, "010201": 8.1, "010210": 8.2,
    "010211": 7.1, "010220": 7.2, "010221": 5.3, "011000": 9.5, "011001": 9.3,
    "011010": 9.2, "011011": 8.5, "011020": 8.5, "011021": 7.3, "011100": 9.2,
    "011101": 8.2, "011110": 8, "011111": 7.2, "011120": 7, "011121": 5.9,
    "011200": 8.4, "011201": 7, "011210": 7.1, "011211": 5.2, "011220": 5,
    "011221": 3, "012001": 8.6, "012011": 7.5, "012021": 5.2, "012101": 7.1,
    "012111": 5.2, "012121": 2.9, "012201": 6.3, "012211": 2.9, "012221": 1.7,
    "100000": 9.8, "100001": 9.5, "100010": 9.4, "100011": 8.7, "100020": 9.1,
    "100021": 8.1, "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4,
    "100120": 7.7, "100121": 6.4, "100200": 8.7, "100201": 7.5, "100210": 7.4,
    "100211": 6.3, "100220": 6.3, "100221": 4.9, "101000": 9.4, "101001": 8.9,
    "101010": 8.8, "101011": 7.7, "101020": 7.6, "101021": 6.7, "101100": 8.6,
    "101101": 7.6, "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5,
    "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2, "101220": 5.2,
    "101221": 2.5, "102001": 8.3, "102011": 7, "102021": 5.4, "102101": 6.5,
    "102111": 5.8, "102121": 2.6, "102201": 5.3, "102211": 2.1, "102221": 1.3,
    "110000": 9.5, "110001": 9, "110010": 8.8, "110011": 7.6, "110020": 7.6,
    "110021": 7, "110100": 9, "110101": 7.7, "110110": 7.5, "110111": 6.2,
    "110120": 6.1, "110121": 5.3, "110200": 7.7, "110201": 6.6, "110210": 6.8,
    "110211": 5.9, "110220": 5.2, "110221": 3, "111000": 8.9, "111001": 7.8,
    "111010": 7.6, "111011": 6.7, "111020": 6.2, "111021": 5.8, "111100": 7.4,
    "111101": 5.9, "111110": 5.7, "111111": 5.7, "111120": 4.7, "111121": 2.3,
    "111200": 6.1, "111201": 5.2, "111210": 5.7, "111211": 2.9, "111220": 2.4,
    "111221": 1.6, "112001": 7.1, "112011": 5.9, "112021": 3, "112101": 5.8,
    "112111": 2.6, "112121": 1.5, "112201": 2.3, "112211": 1.3, "112221": 0.6,
    "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2, "200020": 7.5,
    "200021": 5.8, "200100": 8.6, "200101": 7.4, "200110": 7.4, "200111": 6.1,
    "200120": 5.6, "200121": 3.4, "200200": 7, "200201": 5.4, "200210": 5.2,
    "200211": 4, "200220": 4, "200221": 2.2, "201000": 8.5, "201001": 7.5,
    "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1, "201100": 7.2,
    "201101": 5.7, "201110": 5.5, "201111": 4.1, "201120": 4.6, "201121": 1.9,
    "201200": 5.3, "201201": 3.6, "201210": 3.4, "201211": 1.9, "201220": 1.9,
    "201221": 0.8, "202001": 6.4, "202011": 5.1, "202021": 2, "202101": 4.7,
    "202111": 2.1, "202121": 1.1, "202201": 2.4, "202211": 0.9, "202221": 0.4,
    "210000": 8.8, "210001": 7.5, "210010": 7.3, "210011": 5.3, "210020": 6,
    "210021": 5, "210100": 7.3, "210101": 5.5, "210110": 5.9, "210111": 4,
    "210120": 4.1, "210121": 2, "210200": 5.4, "210201": 4.3, "210210": 4.5,
    "210211": 2.2, "210220": 2, "210221": 1.1, "211000": 7.5, "211001": 5.5,
    "211010": 5.8, "211011": 4.5, "211020": 4, "211021": 2.1, "211100": 6.1,
    "211101": 5.1, "211110": 4.8, "211111": 1.8, "211120": 2, "211121": 0.9,
    "211200": 4.6, "211201": 1.8, "211210": 1.7, "211211": 0.7, "211220": 0.8,
    "211221": 0.2, "212001": 5.3, "212011": 2.4, "212021": 1.4, "212101": 2.4,
    "212111": 1.2, "212121": 0.5, "212201": 1, "212211": 0.3, "212221": 0.1,
}


def is_v4_vector(vector: str | None) -> bool:
    """``True`` for a ``CVSS:4.0/...`` vector string."""
    return bool(vector) and isinstance(vector, str) and vector.strip().upper().startswith(
        "CVSS:4.0"
    )


def _parse(vector: str) -> dict[str, str]:
    text = vector.strip()
    parts = [p for p in text.split("/") if p]
    if not parts or parts[0].upper() != "CVSS:4.0":
        raise ValidationError("not a CVSS v4.0 vector", field="vector")
    metrics: dict[str, str] = {}
    seen_order: list[str] = []
    for part in parts[1:]:
        key, _, value = part.partition(":")
        if not _ or not key or not value:
            raise ValidationError(f"malformed vector component {part!r}", field="vector")
        key = key.upper()
        if key not in _VALUES:
            raise ValidationError(f"unknown CVSS v4.0 metric {key!r}", field="vector")
        if key in metrics:
            raise ValidationError(f"duplicate metric {key!r} in vector", field="vector")
        if value not in _VALUES[key]:
            raise ValidationError(
                f"invalid value {value!r} for {key}", field="vector"
            )
        metrics[key] = value
        seen_order.append(key)

    missing = [name for name in REQUIRED_BASE_METRICS if name not in metrics]
    if missing:
        raise ValidationError(
            "vector is missing mandatory base metric(s): " + ", ".join(missing),
            field="vector",
        )
    # The specification requires a fixed order; accepting any order would let a
    # malformed vector look valid.
    expected = [name for name in CVSS40_METRIC_ORDER if name in metrics]
    if seen_order != expected:
        raise ValidationError(
            "CVSS v4.0 vector metrics are out of the required order", field="vector"
        )
    for name in _OPTIONAL:
        metrics.setdefault(name, "X")
    return metrics


def _effective(metrics: Mapping[str, str], name: str) -> str:
    """Resolve a metric through its ``M*`` override and its documented default.

    ``E=X`` means "not assessed", which the specification defines as the worst
    case ``E=A``; ``CR/IR/AR=X`` likewise default to ``H``. Every other
    environmental metric defers to the base value.
    """
    modified = metrics.get("M" + name, "X")
    if modified != "X":
        return modified
    value = metrics.get(name, "X")
    if value != "X":
        return value
    if name == "E":
        return "A"
    if name in ("CR", "IR", "AR"):
        return "H"
    return "X"


def _macrovector(metrics: Mapping[str, str]) -> str:
    """Map a vector onto its 6-digit macrovector key (specification Tables 24-30)."""
    av, pr, ui = _effective(metrics, "AV"), _effective(metrics, "PR"), _effective(metrics, "UI")
    ac, at = _effective(metrics, "AC"), _effective(metrics, "AT")
    vc, vi, va = _effective(metrics, "VC"), _effective(metrics, "VI"), _effective(metrics, "VA")
    sc, si, sa = _effective(metrics, "SC"), _effective(metrics, "SI"), _effective(metrics, "SA")
    e = _effective(metrics, "E")
    cr, ir, ar = _effective(metrics, "CR"), _effective(metrics, "IR"), _effective(metrics, "AR")
    msi, msa = _effective(metrics, "MSI"), _effective(metrics, "MSA")

    # EQ1: AV/PR/UI
    if av == "N" and pr == "N" and ui == "N":
        eq1 = 0
    elif (av == "N" or pr == "N" or ui == "N") and not (av == "N" and pr == "N" and ui == "N") and av != "P":
        eq1 = 1
    elif av == "P" or not (av == "N" or pr == "N" or ui == "N"):
        eq1 = 2
    else:  # pragma: no cover - the three branches above are exhaustive
        raise ValidationError("EQ1 not classified", field="vector")

    # EQ2: AC/AT
    eq2 = 0 if (ac == "L" and at == "N") else 1

    # EQ3: VC/VI/VA
    if vc == "H" and vi == "H":
        eq3 = 0
    elif vc == "H" or vi == "H" or va == "H":
        eq3 = 1
    else:
        eq3 = 2

    # EQ4: SC/SI/SA with MSI/MSA scope overrides
    if msi == "S" or msa == "S":
        eq4 = 0
    elif sc == "H" or si == "H" or sa == "H":
        eq4 = 1
    else:
        eq4 = 2

    # EQ5: E
    eq5 = {"A": 0, "P": 1, "U": 2}[e]

    # EQ6: CR/IR/AR against impact
    if (cr == "H" and vc == "H") or (ir == "H" and vi == "H") or (ar == "H" and va == "H"):
        eq6 = 0
    else:
        eq6 = 1

    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def _extract(fragment: str, metric: str) -> str:
    """Pull ``metric``'s value out of a ``A:X/B:Y/`` fragment."""
    for part in fragment.split("/"):
        if ":" not in part:
            continue
        key, _, value = part.partition(":")
        if key == metric:
            return value
    raise ValidationError(f"reference vector is missing {metric}", field="vector")


def _highest_vectors(macro: str) -> list[str]:
    """Compose the highest-severity vectors that belong to ``macro``."""
    eq1, eq2, eq3, eq4, eq5, eq6 = (int(c) for c in macro)
    eq3_maxes = _MAX_COMPOSED["eq3"].get(eq3, {}).get(str(eq6), [])
    out: list[str] = []
    for a in _MAX_COMPOSED["eq1"][eq1]:
        for b in _MAX_COMPOSED["eq2"][eq2]:
            for c in eq3_maxes:
                for d in _MAX_COMPOSED["eq4"][eq4]:
                    for f in _MAX_COMPOSED["eq5"][eq5]:
                        out.append(a + b + c + d + f)
    return out


def _round_half_up(value: float) -> float:
    """One decimal place, round-half-up — matching the reference implementation."""
    from decimal import ROUND_HALF_UP, Decimal

    return float(Decimal(repr(value)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def _score(metrics: Mapping[str, str]) -> float:
    # Specification 8.2: no impact on any system -> 0.0, before any lookup.
    if all(_effective(metrics, name) == "N" for name in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0

    macro = _macrovector(metrics)
    base_value = _CVSS_LOOKUP.get(macro)
    if base_value is None:  # pragma: no cover - every reachable macro is in the table
        raise ValidationError(f"macrovector {macro} is not in the lookup table", field="vector")

    eq1, eq2, eq3, eq4, eq5, eq6 = (int(c) for c in macro)

    # The next-lower macrovector per EQ; a missing entry means "no floor".
    def lower(key: str) -> float | None:
        return _CVSS_LOOKUP.get(key)

    eq1_lower = lower(f"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}")
    eq2_lower = lower(f"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}")

    if eq3 == 0 and eq6 == 0:
        # Two valid directions; the reference takes the higher-scoring one.
        left = lower(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}")
        right = lower(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
        candidates = [c for c in (left, right) if c is not None]
        eq3eq6_lower = max(candidates) if candidates else None
    elif eq3 == 1 and eq6 in (0, 1):
        eq3eq6_lower = lower(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}") if eq6 == 0 else lower(
            f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}"
        )
    elif eq3 == 0 and eq6 == 1:
        eq3eq6_lower = lower(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
    else:  # e.g. 21 -> 32, which does not exist
        eq3eq6_lower = lower(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6 + 1}")

    eq4_lower = lower(f"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}")
    eq5_lower = lower(f"{eq1}{eq2}{eq3}{eq4}{eq5 + 1}{eq6}")

    # Severity distance from the to-be-scored vector to a highest vector.
    distance: dict[str, float] | None = None
    for highest in _highest_vectors(macro):
        parts = {
            name: _effective(metrics, name) for name in
            ("AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR")
        }
        try:
            d = {
                "AV": _AV[parts["AV"]] - _AV[_extract(highest, "AV")],
                "PR": _PR[parts["PR"]] - _PR[_extract(highest, "PR")],
                "UI": _UI[parts["UI"]] - _UI[_extract(highest, "UI")],
                "AC": _AC[parts["AC"]] - _AC[_extract(highest, "AC")],
                "AT": _AT[parts["AT"]] - _AT[_extract(highest, "AT")],
                "VC": _V[parts["VC"]] - _V[_extract(highest, "VC")],
                "VI": _V[parts["VI"]] - _V[_extract(highest, "VI")],
                "VA": _V[parts["VA"]] - _V[_extract(highest, "VA")],
                "SC": _SC[parts["SC"]] - _SC[_extract(highest, "SC")],
                "SI": _SI[parts["SI"]] - _SI[_extract(highest, "SI")],
                "SA": _SI[parts["SA"]] - _SI[_extract(highest, "SA")],
                "CR": _CR[parts["CR"]] - _CR[_extract(highest, "CR")],
                "IR": _CR[parts["IR"]] - _CR[_extract(highest, "IR")],
                "AR": _CR[parts["AR"]] - _CR[_extract(highest, "AR")],
            }
        except KeyError as exc:  # pragma: no cover - table/level mismatch is a bug
            raise ValidationError(f"reference vector unusable: {exc}", field="vector") from exc
        if any(value < 0 for value in d.values()):
            continue
        distance = d
        break
    if distance is None:  # pragma: no cover - a highest vector always qualifies
        raise ValidationError("no applicable highest-severity vector", field="vector")

    dist_eq1 = distance["AV"] + distance["PR"] + distance["UI"]
    dist_eq2 = distance["AC"] + distance["AT"]
    dist_eq3eq6 = (
        distance["VC"] + distance["VI"] + distance["VA"]
        + distance["CR"] + distance["IR"] + distance["AR"]
    )
    dist_eq4 = distance["SC"] + distance["SI"] + distance["SA"]
    dist_eq5 = 0.0

    depth_eq1 = _MAX_SEVERITY["eq1"][eq1] * _STEP
    depth_eq2 = _MAX_SEVERITY["eq2"][eq2] * _STEP
    depth_eq3eq6 = _MAX_SEVERITY["eq3eq6"][eq3][eq6] * _STEP
    depth_eq4 = _MAX_SEVERITY["eq4"][eq4] * _STEP

    normalized: list[float] = []
    for available, span, dist in (
        (base_value - eq1_lower if eq1_lower is not None else None, depth_eq1, dist_eq1),
        (base_value - eq2_lower if eq2_lower is not None else None, depth_eq2, dist_eq2),
        (
            base_value - eq3eq6_lower if eq3eq6_lower is not None else None,
            depth_eq3eq6,
            dist_eq3eq6,
        ),
        (base_value - eq4_lower if eq4_lower is not None else None, depth_eq4, dist_eq4),
        # EQ5 contributes a distance of 0 by definition, so it never moves the score.
        (base_value - eq5_lower if eq5_lower is not None else None, None, dist_eq5),
    ):
        if available is None:
            continue
        if span in (None, 0):
            normalized.append(0.0)
            continue
        normalized.append(available * (dist / span))

    value = base_value - (sum(normalized) / len(normalized) if normalized else 0.0)
    value = min(10.0, max(0.0, value))
    return _round_half_up(value)


def score_vector_v4(vector: str, *, source: str | None = None) -> CvssScore:
    """Compute a CVSS v4.0 score (CVSS-B / CVSS-BT / CVSS-BTE).

    Raises :class:`ValidationError` for a malformed vector and
    :class:`UnsupportedVector` for a vector of a different major version.
    """
    if not is_v4_vector(vector):
        raise UnsupportedVector(
            "only CVSS v4.0 vectors are accepted by score_vector_v4", field="vector"
        )
    metrics = _parse(vector)
    score = _score(metrics)
    return CvssScore(
        version="4.0",
        base_score=score,
        severity=severity_from_score(score),
        vector=vector.strip(),
        assessed=True,
        source=source,
    )

