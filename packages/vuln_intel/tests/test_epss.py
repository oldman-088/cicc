"""EPSS interface: strict parsing, honest unavailable state, no silent zeroes."""

from __future__ import annotations

import pytest

from vuln_intel.connectors.epss import (
    LIVE_PROVIDER_AVAILABLE,
    EpssScore,
    FixtureEpssProvider,
    InMemoryEpssCache,
    UnavailableEpssProvider,
    parse_epss_response,
)
from vuln_intel.errors import SourceError, SourceResponseError, ValidationError
from vuln_intel.schema import CveId
from vuln_intel.transport import Transport

from . import fixtures as fx
from .conftest import FIXED_NOW


def test_live_provider_is_declared_unavailable() -> None:
    """The flag must stay False until a real fetch is recorded."""
    assert LIVE_PROVIDER_AVAILABLE is False


def test_parse_documented_payload() -> None:
    scores = parse_epss_response(fx.EPSS_RESPONSE, observed_at=FIXED_NOW, origin="fixture")
    assert set(scores) == {"CVE-2026-0001", "CVE-2026-0002"}
    first = scores["CVE-2026-0001"]
    assert first.score == pytest.approx(0.9447)
    assert first.percentile == pytest.approx(0.999)
    assert first.model_date == "2026-01-01"
    assert first.model_version == "2026.01.01"
    assert first.origin == "fixture"
    assert first.as_dict()["cve"] == "CVE-2026-0001"


def test_empty_success_payload_means_unscored_not_failed() -> None:
    assert parse_epss_response(fx.EPSS_EMPTY, observed_at=FIXED_NOW) == {}


def test_error_status_raises() -> None:
    with pytest.raises(SourceResponseError):
        parse_epss_response(fx.EPSS_ERROR, observed_at=FIXED_NOW)


@pytest.mark.parametrize(
    "entry",
    [
        {"cve": "CVE-2026-0001", "epss": "2.0", "percentile": "0.5", "date": "2026-01-01"},
        {"cve": "CVE-2026-0001", "epss": "0.5", "percentile": "-0.1", "date": "2026-01-01"},
        {"cve": "CVE-2026-0001", "epss": "abc", "percentile": "0.5", "date": "2026-01-01"},
        {"cve": "CVE-2026-0001", "percentile": "0.5", "date": "2026-01-01"},
        {"cve": "CVE-2026-0001", "epss": "0.5", "percentile": "0.5", "date": "not-a-date"},
        {"cve": "nope", "epss": "0.5", "percentile": "0.5", "date": "2026-01-01"},
    ],
)
def test_bad_rows_fail_visibly(entry: dict) -> None:
    with pytest.raises(ValidationError):
        parse_epss_response(
            {"status": "OK", "data": [entry]}, observed_at=FIXED_NOW, origin="fixture"
        )


def test_unrequested_cve_is_rejected() -> None:
    with pytest.raises(ValidationError):
        parse_epss_response(
            fx.EPSS_RESPONSE,
            observed_at=FIXED_NOW,
            origin="fixture",
            requested=[CveId.parse("CVE-2026-0001")],
        )


def test_unavailable_provider_raises_instead_of_returning_zero() -> None:
    with pytest.raises(SourceResponseError):
        UnavailableEpssProvider().fetch([CveId.parse("CVE-2026-0001")])


def test_fixture_provider_is_stamped_as_fixture() -> None:
    provider = FixtureEpssProvider(scores={"CVE-2026-0001": (0.5, 0.9, "2026-01-01")})
    scores = provider.fetch([CveId.parse("CVE-2026-0001"), CveId.parse("CVE-2026-0009")])
    assert set(scores) == {"CVE-2026-0001"}
    assert scores["CVE-2026-0001"].origin == "fixture"


def test_cache_expires_and_does_not_invent_entries() -> None:
    from datetime import timedelta

    now = {"value": FIXED_NOW}
    cache = InMemoryEpssCache(max_age_seconds=60, clock=lambda: now["value"])
    cve = CveId.parse("CVE-2026-0001")
    assert cache.get(cve) is None  # absence is reported as absence, not a zero score
    cache.put(
        EpssScore(
            cve=cve,
            score=0.5,
            percentile=0.9,
            model_date="2026-01-01",
            observed_at=FIXED_NOW,
            origin="fixture",
        )
    )
    assert cache.get(cve) is not None
    now["value"] = FIXED_NOW + timedelta(seconds=61)
    assert cache.get(cve) is None  # stale entries are dropped, not served


def test_epss_score_requires_aware_timestamp() -> None:
    from datetime import datetime

    with pytest.raises(ValidationError):
        EpssScore(
            cve=CveId.parse("CVE-2026-0001"),
            score=0.5,
            percentile=0.5,
            model_date=None,
            observed_at=datetime(2026, 1, 1),
        )


def test_provider_protocols_are_runtime_checkable() -> None:
    from vuln_intel.connectors.epss import EpssCache, EpssProvider

    assert isinstance(FixtureEpssProvider(), EpssProvider)
    assert isinstance(InMemoryEpssCache(), EpssCache)
    assert isinstance(UnavailableEpssProvider(), EpssProvider)


def test_errors_are_source_errors() -> None:
    with pytest.raises(SourceError):
        UnavailableEpssProvider().fetch([])


def test_transport_protocol_is_satisfied_by_the_fake() -> None:
    from .conftest import FakeTransport

    assert isinstance(FakeTransport(), Transport)
