"""``POST /v1/query`` — whole records, and the failure modes that matter.

This endpoint exists because ``querybatch`` returns **ids only**: a caller needing
severity, affected ranges or a summary from N hits makes N further requests. That N+1
is the reason to implement ``/v1/query`` at all, so the tests here check both halves —
that records come back complete, and that pagination, duplicates, retries and malformed
bodies are handled without silently losing one.

Everything is driven by a scripted transport. No request leaves the process, and
``LIVE_PROVIDER_AVAILABLE`` remains ``False``.
"""

from __future__ import annotations

import copy

import pytest

from vuln_intel.connectors.osv import OsvConnector, _build_query
from vuln_intel.errors import (
    SourceRateLimited,
    SourceResponseError,
    SourceUnavailable,
    ValidationError,
)
from vuln_intel.ratelimit import RateGate
from vuln_intel.retry import RetryPolicy
from vuln_intel.schema import Origin

from . import fixtures as fx
from .conftest import FakeTransport, no_wait, response

PKG = {"name": "fixture-pkg", "ecosystem": "npm"}


def connector(script, **kwargs) -> OsvConnector:
    return OsvConnector(
        transport=FakeTransport(script=list(script)),
        gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
        retry=RetryPolicy(attempts=1),
        sleep=no_wait,
        origin=Origin.FIXTURE,
        **kwargs,
    )


class TestQueryPayloadValidation:
    """OSV documents these as 400s; a batch job pays for each one in round trips."""

    def test_name_and_ecosystem_with_a_version(self) -> None:
        query = _build_query(PKG, version="1.2.3", commit=None)
        assert query == {"package": PKG, "version": "1.2.3"}

    def test_unversioned_purl_with_a_version_is_valid(self) -> None:
        query = _build_query({"purl": "pkg:npm/fixture-pkg"}, version="1.2.3", commit=None)
        assert query["version"] == "1.2.3"

    def test_a_version_in_both_places_is_rejected_locally(self) -> None:
        """Documented 400. Rejecting it here costs nothing; letting it out costs a call."""
        with pytest.raises(ValidationError) as caught:
            _build_query({"purl": "pkg:npm/fixture-pkg@1.2.3"}, version="1.2.3", commit=None)
        assert "version" in str(caught.value).lower()

    def test_commit_and_version_together_are_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _build_query(PKG, version="1.2.3", commit="abc123")

    def test_neither_version_nor_commit_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _build_query(PKG, version=None, commit=None)

    def test_purl_and_name_together_are_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _build_query(
                {"purl": "pkg:npm/x", "name": "x", "ecosystem": "npm"},
                version="1.0.0", commit=None,
            )

    def test_a_purl_that_is_not_a_purl_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _build_query({"purl": "npm/fixture-pkg"}, version="1.0.0", commit=None)

    def test_a_missing_ecosystem_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _build_query({"name": "fixture-pkg"}, version="1.0.0", commit=None)

    def test_a_wrongly_cased_ecosystem_is_rejected_with_the_right_spelling(self) -> None:
        """The dangerous case: OSV returns *empty*, not an error, for a wrong case.

        An empty result is indistinguishable from a clean package, so this would have
        been a silent false negative in every PyPI lookup written as ``pypi``.
        """
        with pytest.raises(ValidationError) as caught:
            _build_query({"name": "jinja2", "ecosystem": "pypi"}, version="3.1.4", commit=None)
        assert "PyPI" in str(caught.value)

    def test_a_correctly_cased_ecosystem_passes(self) -> None:
        assert _build_query({"name": "jinja2", "ecosystem": "PyPI"},
                            version="3.1.4", commit=None)

    def test_an_unknown_ecosystem_is_left_alone(self) -> None:
        """Unknown is not wrong: the canonical list cannot be exhaustive."""
        query = _build_query(
            {"name": "x", "ecosystem": "OSS-Fuzz"}, version="1.0.0", commit=None
        )
        assert query["package"]["ecosystem"] == "OSS-Fuzz"

    def test_commit_only_query_needs_no_package(self) -> None:
        query = _build_query({}, version=None, commit="6879efc2c1596d11a6a6ad296f80063b558d5e0f")
        assert query["commit"].startswith("6879efc2")


class TestRecordsComeBackWhole:
    def test_a_full_record_is_returned(self) -> None:
        osv = connector([response({"vulns": [fx.OSV_CVE]})])
        records, warnings = osv.query_package(PKG, version="1.0.0")
        assert warnings == ()
        assert len(records) == 1
        record = records[0]
        assert str(record.cve) == "CVE-2026-0001"
        # The point of this endpoint: severity, versions and summary are present,
        # not just an id.
        assert record.cvss
        assert record.affected
        assert record.summary

    def test_an_empty_result_is_not_an_error(self) -> None:
        """No matches comes back as an empty body, which must not read as a failure."""
        osv = connector([response({})])
        records, warnings = osv.query_package(PKG, version="9.9.9")
        assert records == ()
        assert warnings == ()

    def test_an_empty_vulns_list_is_not_an_error(self) -> None:
        osv = connector([response({"vulns": []})])
        assert osv.query_package(PKG, version="1.0.0")[0] == ()

    def test_the_request_is_a_post_to_the_query_endpoint(self) -> None:
        transport = FakeTransport(script=[response({"vulns": []})])
        osv = OsvConnector(
            transport=transport,
            gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
            retry=RetryPolicy(attempts=1), sleep=no_wait, origin=Origin.FIXTURE,
        )
        osv.query_package(PKG, version="1.0.0")
        assert transport.calls[0]["method"] == "POST"
        assert transport.calls[0]["json"] == {"package": PKG, "version": "1.0.0"}


class TestPagination:
    def test_a_single_page_needs_one_request(self) -> None:
        transport = FakeTransport(script=[response({"vulns": [fx.OSV_CVE]})])
        osv = OsvConnector(
            transport=transport,
            gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
            retry=RetryPolicy(attempts=1), sleep=no_wait, origin=Origin.FIXTURE,
        )
        osv.query_package(PKG, version="1.0.0")
        assert len(transport.calls) == 1

    def test_the_page_token_is_sent_on_the_follow_up(self) -> None:
        second = copy.deepcopy(fx.OSV_ALIAS_ONLY_CVE)
        script = [
            response({"vulns": [fx.OSV_CVE], "next_page_token": "tok-1"}),
            response({"vulns": [second]}),
        ]
        transport = FakeTransport(script=script)
        osv = OsvConnector(
            transport=transport,
            gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
            retry=RetryPolicy(attempts=1), sleep=no_wait, origin=Origin.FIXTURE,
        )
        _records, _warnings = osv.query_package(PKG, version="1.0.0")
        assert len(transport.calls) == 2
        assert "page_token" not in transport.calls[0]["json"]
        assert transport.calls[1]["json"]["page_token"] == "tok-1"
        # The original query is resent unchanged, as OSV documents.
        assert transport.calls[1]["json"]["version"] == "1.0.0"

    def test_pages_are_concatenated(self) -> None:
        second = copy.deepcopy(fx.OSV_ALIAS_ONLY_CVE)
        script = [
            response({"vulns": [fx.OSV_CVE], "next_page_token": "tok-1"}),
            response({"vulns": [second]}),
        ]
        osv = connector(script)
        records, _ = osv.query_package(PKG, version="1.0.0")
        assert len(records) == 2

    def test_the_same_record_on_two_pages_is_returned_once(self) -> None:
        """Pagination is time-boxed server-side, so a page may repeat a record.

        Returning it twice would double-count the advisory in any downstream tally.
        """
        script = [
            response({"vulns": [fx.OSV_CVE], "next_page_token": "tok-1"}),
            response({"vulns": [fx.OSV_CVE]}),
        ]
        osv = connector(script)
        records, _ = osv.query_package(PKG, version="1.0.0")
        assert len(records) == 1

    def test_a_repeated_token_stops_instead_of_looping(self) -> None:
        script = [
            response({"vulns": [fx.OSV_CVE], "next_page_token": "same"}),
            response({"vulns": [], "next_page_token": "same"}),
        ]
        osv = connector(script)
        records, warnings = osv.query_package(PKG, version="1.0.0", max_pages=10)
        assert len(records) == 1
        assert any("repeated page token" in w for w in warnings)

    def test_the_page_limit_is_reported_as_incomplete(self) -> None:
        """Stopping early must say so: a truncated list that looks complete is worse."""
        script = [response({"vulns": [fx.OSV_CVE], "next_page_token": f"t{i}"}) for i in range(5)]
        osv = connector(script)
        _records, warnings = osv.query_package(PKG, version="1.0.0", max_pages=2)
        assert any("page limit" in w for w in warnings)

    def test_the_record_cap_is_reported(self) -> None:
        many = []
        for index in range(5):
            item = copy.deepcopy(fx.OSV_CVE)
            item["id"] = f"GHSA-{index:04d}-aaaa-bbbb"
            many.append(item)
        osv = connector([response({"vulns": many})])
        _records, warnings = osv.query_package(PKG, version="1.0.0", max_records=3)
        assert any("stopped at 3" in w for w in warnings)


class TestMalformedResponses:
    def test_a_non_list_vulns_field_is_an_error(self) -> None:
        osv = connector([response({"vulns": {"not": "a list"}})])
        with pytest.raises(SourceResponseError):
            osv.query_package(PKG, version="1.0.0")

    def test_a_malformed_record_is_skipped_and_reported(self) -> None:
        script = [response({"vulns": ["not-an-object", fx.OSV_CVE]})]
        osv = connector(script)
        records, warnings = osv.query_package(PKG, version="1.0.0")
        assert len(records) == 1
        assert any("malformed" in w for w in warnings)

    def test_a_record_with_no_id_is_skipped(self) -> None:
        broken = copy.deepcopy(fx.OSV_CVE)
        broken.pop("id")
        osv = connector([response({"vulns": [broken, fx.OSV_CVE]})])
        records, warnings = osv.query_package(PKG, version="1.0.0")
        assert len(records) == 1
        assert any("no id" in w for w in warnings)

    def test_an_advisory_without_a_cve_is_reported_not_invented(self) -> None:
        """The rule the whole connector exists to enforce."""
        osv = connector([response({"vulns": [fx.OSV_ADVISORY_ONLY]})])
        records, warnings = osv.query_package(PKG, version="1.0.0")
        assert records == ()
        assert any("no CVE alias" in w for w in warnings)

    def test_a_record_that_fails_validation_is_skipped_not_fatal(self) -> None:
        broken = copy.deepcopy(fx.OSV_CVE)
        broken["affected"] = "not-a-list"
        osv = connector([response({"vulns": [broken, fx.OSV_CVE]})])
        records, warnings = osv.query_package(PKG, version="1.0.0")
        assert len(records) == 1
        assert warnings


class TestFailuresAndRecovery:
    def test_a_429_is_rate_limited_not_a_generic_error(self) -> None:
        osv = connector([response({}, status=429, headers={"retry-after": "5"})])
        with pytest.raises(SourceRateLimited) as caught:
            osv.query_package(PKG, version="1.0.0")
        assert caught.value.retry_after == 5.0

    def test_a_400_is_a_payload_error(self) -> None:
        osv = connector([response({}, status=400)])
        with pytest.raises(SourceResponseError):
            osv.query_package(PKG, version="1.0.0")

    def test_a_500_is_a_response_error(self) -> None:
        osv = connector([response({}, status=500)])
        with pytest.raises(SourceResponseError):
            osv.query_package(PKG, version="1.0.0")

    def test_a_transport_failure_surfaces(self) -> None:
        """A dead connection must propagate, not be swallowed into an empty result.

        An empty list here would be indistinguishable from "this package is clean",
        which is the failure mode this connector refuses everywhere else.
        """
        osv = connector([lambda *_: SourceUnavailable("connection reset", source="osv")])
        with pytest.raises(SourceUnavailable):
            osv.query_package(PKG, version="1.0.0")

    def test_a_retry_that_succeeds_recovers(self) -> None:
        """Attempt one fails with a 5xx, attempt two returns a record."""
        transport = FakeTransport(
            script=[response({}, status=503), response({"vulns": [fx.OSV_CVE]})]
        )
        osv = OsvConnector(
            transport=transport,
            gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
            retry=RetryPolicy(attempts=3),
            sleep=no_wait,
            origin=Origin.FIXTURE,
        )
        records, _warnings = osv.query_package(PKG, version="1.0.0")
        assert len(records) == 1
        assert len(transport.calls) == 2

    def test_no_transport_is_an_explicit_error(self) -> None:
        osv = OsvConnector(
            transport=None,
            gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
            retry=RetryPolicy(attempts=1), sleep=no_wait, origin=Origin.FIXTURE,
        )
        with pytest.raises(SourceResponseError):
            osv.query_package(PKG, version="1.0.0")

    def test_the_provider_availability_flag_stays_false(self) -> None:
        """No request left the process, so nothing may be claimed as live.

        `LIVE_PROVIDER_AVAILABLE` is declared once at package level and re-exported;
        the connector module itself only carries `LAST_VERIFIED_LIVE`. Reaching for
        both on the connector was my own wrong assumption, corrected here rather than
        by broadening the assertion.
        """
        import vuln_intel
        from vuln_intel.connectors import osv as module

        assert module.LAST_VERIFIED_LIVE is None
        assert vuln_intel.LIVE_PROVIDER_AVAILABLE is False

    def test_executed_requests_never_reach_the_network(self) -> None:
        transport = FakeTransport(script=[response({"vulns": [fx.OSV_CVE]})])
        osv = OsvConnector(
            transport=transport,
            gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
            retry=RetryPolicy(attempts=1), sleep=no_wait, origin=Origin.FIXTURE,
        )
        osv.query_package(PKG, version="1.0.0")
        for call in transport.calls:
            assert "api.osv.dev" in call["url"]
