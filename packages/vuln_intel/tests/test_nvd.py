"""NVD connector, exercised entirely against synthetic fixtures.

No test in this file touches the network.  That fact is itself asserted: the
connector must refuse to produce data without an injected transport.
"""

from __future__ import annotations

import pytest

from vuln_intel.connectors.nvd import LAST_VERIFIED_LIVE, NVD_API, NvdConnector
from vuln_intel.errors import (
    SourceNotFound,
    SourceRateLimited,
    SourceResponseError,
    ValidationError,
)
from vuln_intel.ratelimit import RateGate
from vuln_intel.retry import RetryPolicy
from vuln_intel.schema import CollectionStatus, Origin, Severity

from . import fixtures as fx
from .conftest import FakeTransport, no_wait, response


def connector(script, **kwargs) -> NvdConnector:
    return NvdConnector(
        transport=FakeTransport(script=list(script)),
        gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
        retry=RetryPolicy(attempts=1),
        sleep=no_wait,
        origin=Origin.FIXTURE,
        **kwargs,
    )


def test_no_transport_reports_error_instead_of_data() -> None:
    """Without an injected transport the connector must fail loudly."""
    nvd = NvdConnector(transport=None, gate=RateGate(min_interval=0.0), sleep=no_wait)
    with pytest.raises(SourceResponseError):
        nvd.get_cve("CVE-2026-0001")
    result = nvd.search()
    assert result.state.status is CollectionStatus.FAILED
    assert result.records == ()
    assert result.state.error


def test_last_verified_live_is_none_until_a_real_fetch_happens() -> None:
    """Guards against silently claiming a verified live integration."""
    assert LAST_VERIFIED_LIVE is None


def test_get_cve_normalizes_a_full_record() -> None:
    nvd = connector([response(fx.NVD_SINGLE)])
    record = nvd.get_cve("CVE-2026-0001")

    assert str(record.cve) == "CVE-2026-0001"
    assert record.origin is Origin.FIXTURE
    assert record.severity is Severity.CRITICAL
    assert record.best_cvss is not None and record.best_cvss.base_score == 9.8
    assert record.details and record.details.startswith("Synthetic fixture")
    # English description is preferred over the Spanish one.
    assert "Descripcion" not in (record.details or "")
    assert record.cwe == ("CWE-78",)
    assert {r.kind for r in record.references} == {"patch", "exploit"}
    assert record.sources == ("nvd",)
    assert record.verification == "unverified"
    assert record.provenance[0].source_ref == "2026-01-02T03:04:05.000"


def test_get_cve_without_metrics_keeps_severity_unknown() -> None:
    record = connector([response(fx.NVD_NO_METRICS)]).get_cve("CVE-2026-0002")
    assert record.cvss == ()
    assert record.severity is Severity.UNKNOWN
    assert record.effective_severity is Severity.UNKNOWN
    assert record.best_cvss is None


def test_inconsistent_source_score_is_flagged_against_the_vector() -> None:
    record = connector([response(fx.NVD_WRONG_SCORE)]).get_cve("CVE-2026-0003")
    assert record.best_cvss is not None
    assert record.best_cvss.base_score == 9.8  # recomputed from the vector
    assert any("disagrees" in note for note in record.conflict_notes)


def test_sparse_record_is_accepted_without_invention() -> None:
    record = connector([response(fx.NVD_SPARSE)]).get_cve("CVE-2026-0004")
    assert record.details is None
    assert record.references == ()
    assert record.cwe == ()
    assert record.published is not None


def test_404_raises_not_found() -> None:
    nvd = connector([response({"message": "not found"}, status=404)])
    with pytest.raises(SourceNotFound):
        nvd.get_cve("CVE-2026-0001")


def test_empty_result_set_is_reported_as_not_found() -> None:
    with pytest.raises(SourceNotFound):
        connector([response(fx.NVD_EMPTY)]).get_cve("CVE-2026-0001")


def test_malformed_envelope_is_an_error_not_an_empty_result() -> None:
    with pytest.raises(SourceResponseError):
        connector([response(fx.NVD_BAD_ENVELOPE)]).get_cve("CVE-2026-0001")


def test_invalid_json_body_is_an_error() -> None:
    with pytest.raises(SourceResponseError):
        connector([response(b"<html>gateway error</html>")]).get_cve("CVE-2026-0001")


def test_malformed_records_downgrade_to_partial_and_are_reported() -> None:
    result = connector([response(fx.NVD_MALFORMED_ENTRY)]).search()
    assert result.state.status is CollectionStatus.PARTIAL
    assert len(result.records) == 1
    assert any("NOT-A-CVE" in warning or "malformed" in warning for warning in result.warnings)


def test_search_page_success() -> None:
    result = connector([response(fx.NVD_PAGE)]).search()
    assert result.state.status is CollectionStatus.OK
    assert [str(r.cve) for r in result.records] == ["CVE-2026-0001", "CVE-2026-0002"]
    assert result.state.records == 2


def test_api_key_is_sent_in_a_header_never_the_url() -> None:
    transport = FakeTransport(script=[response(fx.NVD_SINGLE)])
    nvd = NvdConnector(
        transport=transport,
        api_key="fixture-key",
        gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
        retry=RetryPolicy(attempts=1),
        sleep=no_wait,
    )
    nvd.get_cve("CVE-2026-0001")
    header_calls = [c for c in transport.calls if "headers" in c]
    url_calls = [c for c in transport.calls if "url" in c]
    assert any(c["headers"].get("apiKey") == "fixture-key" for c in header_calls)
    assert all("fixture-key" not in c["url"] for c in url_calls)
    assert url_calls[0]["url"] == NVD_API
    assert all("apiKey" not in (c.get("params") or {}) for c in url_calls)


def test_rate_limit_is_retried_then_succeeds() -> None:
    transport = FakeTransport(
        script=[
            response({"message": "slow down"}, status=429, headers={"retry-after": "0"}),
            response(fx.NVD_SINGLE),
        ]
    )
    nvd = NvdConnector(
        transport=transport,
        gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
        retry=RetryPolicy(attempts=3, base_delay=0.0, max_delay=0.0),
        sleep=no_wait,
        origin=Origin.FIXTURE,
    )
    assert str(nvd.get_cve("CVE-2026-0001").cve) == "CVE-2026-0001"


def test_exhausted_rate_limit_fails_visibly() -> None:
    slow = response({"message": "slow down"}, status=429, headers={"retry-after": "120"})
    nvd = NvdConnector(
        transport=FakeTransport(script=[slow]),
        gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
        retry=RetryPolicy(attempts=3, base_delay=0.0, max_delay=0.0, max_retry_after=60),
        sleep=no_wait,
    )
    with pytest.raises(SourceRateLimited):
        nvd.get_cve("CVE-2026-0001")

    result = nvd.search()
    assert result.state.status is CollectionStatus.FAILED
    assert result.state.retry_after == 120.0
    assert result.records == ()


def test_server_error_is_not_swallowed() -> None:
    result = connector([response({"message": "oops"}, status=503)]).search()
    assert result.state.status is CollectionStatus.FAILED
    assert "503" in (result.state.error or "")


def test_search_all_is_bounded_and_says_so() -> None:
    # The replay transport serves this page for every request, standing in for
    # "NVD holds far more than we are willing to page through".
    full_page = response({**fx.NVD_PAGE, "totalResults": 100})
    nvd = connector([full_page], page_size=2, max_pages=3)
    result = nvd.search_all()
    assert len(result.records) == 6
    assert result.state.status is CollectionStatus.PARTIAL
    assert any("bounded window" in warning for warning in result.warnings)


def test_search_all_stops_on_short_page() -> None:
    nvd = connector(
        [response({**fx.NVD_PAGE, "totalResults": 100}), response(fx.NVD_EMPTY)],
        page_size=2,
        max_pages=5,
    )
    result = nvd.search_all()
    assert len(result.records) == 2
    assert not any("bounded window" in warning for warning in result.warnings)


def test_search_all_keeps_earlier_pages_when_a_later_page_fails() -> None:
    nvd = connector(
        [response({**fx.NVD_PAGE, "totalResults": 100}), response({"message": "boom"}, status=503)],
        page_size=2,
        max_pages=3,
    )
    result = nvd.search_all()
    assert len(result.records) == 2
    assert any("page 1 failed" in warning for warning in result.warnings)


def test_invalid_cve_identifier_is_rejected_before_any_call() -> None:
    transport = FakeTransport(script=[response(fx.NVD_SINGLE)])
    nvd = NvdConnector(transport=transport, gate=RateGate(0.0), sleep=no_wait)
    with pytest.raises(ValidationError):
        nvd.get_cve("CVE-99-1")
    assert transport.calls == [] or all("url" not in c for c in transport.calls)


@pytest.mark.parametrize("size", [0, 2001])
def test_page_size_bounds(size: int) -> None:
    with pytest.raises(ValueError):
        NvdConnector(transport=FakeTransport(), page_size=size)


def test_truncated_page_is_reported_not_paged_forever() -> None:
    """NVD can claim more results than it returns (proxy truncation, partial write).

    Silently paging on would loop on the same short page, and reporting OK would
    claim a complete collection that never happened.
    """
    truncated = {**fx.NVD_PAGE, "totalResults": 10}
    result = connector([response(truncated)]).search()
    assert result.state.status is CollectionStatus.PARTIAL
    assert any("short page" in warning for warning in result.warnings)
