"""CVSS v3 scoring must match the published FIRST specification values."""

from __future__ import annotations

import pytest

from vuln_intel.cvss import cvss_from_source, parse_vector, score_vector
from vuln_intel.errors import UnsupportedVector, ValidationError
from vuln_intel.schema import Severity, severity_from_score


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        # Canonical examples from the CVSS v3.1 specification / FIRST calculator.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_base_scores_match_specification(vector: str, expected: float) -> None:
    score = score_vector(vector)
    assert score.base_score == pytest.approx(expected)
    assert score.assessed is True
    assert score.vector == vector


def test_severity_bands_follow_specification() -> None:
    assert severity_from_score(0.0) is Severity.NONE
    assert severity_from_score(3.9) is Severity.LOW
    assert severity_from_score(4.0) is Severity.MEDIUM
    assert severity_from_score(6.9) is Severity.MEDIUM
    assert severity_from_score(7.0) is Severity.HIGH
    assert severity_from_score(8.9) is Severity.HIGH
    assert severity_from_score(9.0) is Severity.CRITICAL
    assert severity_from_score(10.0) is Severity.CRITICAL


def test_parse_vector_rejects_version_two_and_four() -> None:
    with pytest.raises(UnsupportedVector):
        parse_vector("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P")
    with pytest.raises(UnsupportedVector):
        parse_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # no CVSS: prefix
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # missing metric
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:Z",  # invalid value
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H",  # invalid scope
    ],
)
def test_malformed_vectors_raise_validation_error(vector: str) -> None:
    with pytest.raises(ValidationError):
        score_vector(vector)


def test_source_score_is_kept_verbatim_when_no_vector() -> None:
    score = cvss_from_source(version="3.1", vector=None, base_score=7.5, source="nvd")
    assert score is not None
    assert score.base_score == 7.5
    assert score.severity is Severity.HIGH
    assert score.assessed is True


def test_unscorable_vector_is_kept_but_not_assessed() -> None:
    """A CVSS v4 vector must not be silently scored with v3 maths."""
    score = cvss_from_source(
        version="4.0",
        vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
        base_score=None,
    )
    assert score is not None
    assert score.assessed is False
    assert score.severity is Severity.UNKNOWN
    assert score.base_score == 0.0  # placeholder only; ``assessed`` gates use


def test_no_data_yields_none_not_zero() -> None:
    assert cvss_from_source(version=None, vector=None, base_score=None) is None


def test_vector_wins_over_stated_score() -> None:
    score = cvss_from_source(
        version="3.1",
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        base_score=7.5,
    )
    assert score is not None
    assert score.base_score == 9.8  # computed from the vector, not the claim
