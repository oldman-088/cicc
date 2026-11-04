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


class TestEpssConnector:
    """The live client. Implemented and offline-tested; NOT live-verified.

    `LIVE_PROVIDER_AVAILABLE` must stay False until an authorized real fetch has
    succeeded and been recorded, so these tests assert the flag stays down even
    though the happy path works.
    """

    PAYLOAD = {
        "status": "OK",
        "status-code": 200,
        "version": "2025.03.14",
        "total": 1,
        "offset": 0,
        "limit": 100,
        "data": [
            {
                "cve": "CVE-2024-1234",
                "epss": "0.97228",
                "percentile": "0.99966",
                "date": "2025-03-14",
            }
        ],
    }

    def _connector(self, *script, **kwargs):
        from tests.conftest import FakeTransport, no_wait
        from vuln_intel.connectors.epss import EpssConnector
        from vuln_intel.ratelimit import RateGate
        from vuln_intel.retry import RetryPolicy

        transport = FakeTransport(script=list(script))
        connector = EpssConnector(
            transport=transport,
            gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
            retry=RetryPolicy(attempts=1),
            sleep=no_wait,
            origin="fixture",
            **kwargs,
        )
        return connector, transport

    def _cve(self, value="CVE-2024-1234"):
        from vuln_intel.schema import CveId

        return CveId.parse(value)

    def test_parses_a_published_score(self):
        from tests.conftest import response

        connector, transport = self._connector(response(self.PAYLOAD))
        scores = connector.fetch([self._cve()])
        assert scores["CVE-2024-1234"].score == 0.97228
        assert scores["CVE-2024-1234"].percentile == 0.99966
        assert scores["CVE-2024-1234"].model_date == "2025-03-14"
        assert scores["CVE-2024-1234"].model_version == "2025.03.14"
        # The documented query shape.
        assert transport.calls[0]["params"]["cve"] == "CVE-2024-1234"
        assert transport.calls[0]["params"]["envelope"] == "true"

    def test_unscored_cve_is_absent_not_zero(self):
        """A zero would be the strongest possible claim of "not exploited"."""
        from tests.conftest import response

        connector, _ = self._connector(response(self.PAYLOAD))
        scores = connector.fetch([self._cve(), self._cve("CVE-2024-9999")])
        assert "CVE-2024-9999" not in scores

    def test_no_transport_raises_rather_than_returning_empty(self):
        from vuln_intel.connectors.epss import EpssConnector
        from vuln_intel.errors import SourceResponseError

        connector = EpssConnector(transport=None)
        try:
            connector.fetch([self._cve()])
        except SourceResponseError:
            pass
        else:  # pragma: no cover
            raise AssertionError("missing transport must raise, not report no scores")

    def test_http_error_raises(self):
        from tests.conftest import response
        from vuln_intel.errors import SourceError

        connector, _ = self._connector(response({"message": "boom"}, status=503))
        with pytest.raises(SourceError):
            connector.fetch([self._cve()])

    def test_non_ok_envelope_raises(self):
        from tests.conftest import response
        from vuln_intel.errors import SourceResponseError

        bad = dict(self.PAYLOAD, status="ERROR")
        connector, _ = self._connector(response(bad))
        with pytest.raises(SourceResponseError):
            connector.fetch([self._cve()])

    def test_unrequested_cve_in_the_response_raises(self):
        """Guards against attributing a score to the wrong identifier."""
        from tests.conftest import response
        from vuln_intel.errors import ValidationError

        wrong = dict(
            self.PAYLOAD,
            data=[dict(self.PAYLOAD["data"][0], cve="CVE-2024-0000")],
        )
        connector, _ = self._connector(response(wrong))
        with pytest.raises(ValidationError):
            connector.fetch([self._cve()])

    def test_large_request_is_split_into_bounded_batches(self):
        from tests.conftest import response

        connector, transport = self._connector(
            response(dict(self.PAYLOAD, data=[])),
            response(dict(self.PAYLOAD, data=[])),
            max_cves_per_request=2,
        )
        connector.fetch([self._cve(f"CVE-2024-{i:04d}") for i in range(4)])
        assert len(transport.calls) == 2
        for call in transport.calls:
            assert len(call["params"]["cve"].split(",")) <= 2

    def test_duplicate_cves_produce_one_request_entry(self):
        from tests.conftest import response

        connector, transport = self._connector(response(self.PAYLOAD))
        connector.fetch([self._cve(), self._cve()])
        assert transport.calls[0]["params"]["cve"] == "CVE-2024-1234"

    def test_empty_request_makes_no_call(self):
        connector, transport = self._connector()
        assert connector.fetch([]) == {}
        assert transport.calls == []

    def test_live_provider_flag_stays_false(self):
        """A working code path is not evidence of a live connection."""
        from vuln_intel.connectors import epss

        assert epss.LIVE_PROVIDER_AVAILABLE is False
