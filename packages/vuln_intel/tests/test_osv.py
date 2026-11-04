"""OSV connector, from synthetic fixtures only.

The critical behaviour under test is the *refusal* to invent a CVE for an
advisory-only record, and the preservation of withdrawn status.
"""

from __future__ import annotations

import pytest

from vuln_intel.connectors.osv import LAST_VERIFIED_LIVE, OSV_API, OsvConnector
from vuln_intel.errors import (
    SourceNotFound,
    SourceResponseError,
    ValidationError,
)
from vuln_intel.ratelimit import RateGate
from vuln_intel.retry import RetryPolicy
from vuln_intel.schema import CollectionStatus, Origin, Severity

from . import fixtures as fx
from .conftest import FakeTransport, no_wait, response


def connector(script, **kwargs) -> OsvConnector:
    return OsvConnector(
        transport=FakeTransport(script=list(script)),
        gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
        retry=RetryPolicy(attempts=1),
        sleep=no_wait,
        origin=Origin.FIXTURE,
        **kwargs,
    )


def test_last_verified_live_is_none() -> None:
    assert LAST_VERIFIED_LIVE is None


def test_no_transport_is_an_explicit_error() -> None:
    with pytest.raises(SourceResponseError):
        OsvConnector(transport=None, gate=RateGate(0.0)).get_vulnerability("GHSA-0000-aaaa-bbbb")


def test_record_with_cve_alias_is_normalized() -> None:
    record, advisory = connector([response(fx.OSV_CVE)]).get_vulnerability("GHSA-0000-aaaa-bbbb")
    assert record is not None
    assert str(record.cve) == "CVE-2026-0001"
    assert "GHSA-0000-AAAA-BBBB" in record.aliases
    assert record.origin is Origin.FIXTURE
    assert record.best_cvss is not None and record.best_cvss.base_score == 9.8
    assert record.severity is Severity.HIGH  # from database_specific, not CSS
    assert record.sources == ("osv",)
    assert {a.ecosystem for a in record.affected} == {"npm", "PyPI"}
    npm = next(a for a in record.affected if a.ecosystem == "npm")
    assert npm.fixed == "2.0.1"
    assert npm.introduced == "0"
    assert npm.purl == "pkg:npm/fixture-pkg"
    # The advisory view is always returned alongside, never instead of, the record.
    assert advisory.advisory_id == "GHSA-0000-aaaa-bbbb"


def test_advisory_without_cve_alias_does_not_invent_a_cve() -> None:
    record, advisory = connector([response(fx.OSV_ADVISORY_ONLY)]).get_vulnerability("PYSEC-2026-1")
    assert record is None
    assert advisory.advisory_id == "PYSEC-2026-1"
    assert advisory.affected[0].fixed == "3.0"
    summary = advisory.as_summary()
    assert summary["advisory_id"] == "PYSEC-2026-1"


def test_withdrawn_record_is_surfaced_not_deleted() -> None:
    record, _ = connector([response(fx.OSV_WITHDRAWN)]).get_vulnerability("GHSA-1111-cccc-dddd")
    assert record is not None
    assert any("withdrawn" in note for note in record.conflict_notes)


def test_record_keyed_by_cve_id_is_accepted() -> None:
    record, _advisory = connector([response(fx.OSV_ALIAS_ONLY_CVE)]).get_vulnerability("CVE-2026-0004")
    assert record is not None
    assert str(record.cve) == "CVE-2026-0004"


def test_unsupported_vector_is_noted_not_guessed() -> None:
    record, _ = connector([response(fx.OSV_UNSUPPORTED_VECTOR)]).get_vulnerability(
        "GHSA-2222-eeee-ffff"
    )
    assert record is not None
    assert record.cvss == ()
    assert any("not assessed" in note for note in record.conflict_notes)


def test_lookup_cve_rejects_a_mismatched_record() -> None:
    """OSV must not silently answer about a different CVE than was requested."""
    with pytest.raises(ValidationError):
        connector([response(fx.OSV_CVE)]).lookup_cve("CVE-2026-0002")


def test_404_is_not_found() -> None:
    with pytest.raises(SourceNotFound):
        connector([response({"error": "nope"}, status=404)]).get_vulnerability("GHSA-xxxx")


def test_illegal_identifier_is_rejected_locally() -> None:
    with pytest.raises(ValidationError):
        connector([response(fx.OSV_CVE)]).get_vulnerability("GHSA/../../etc/passwd")


def test_collect_accumulates_partial_failures() -> None:
    transport = FakeTransport(
        script=[
            response(fx.OSV_CVE),
            response({"error": "nope"}, status=404),
            response(fx.OSV_ADVISORY_ONLY),
        ]
    )
    osv = OsvConnector(
        transport=transport,
        gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
        retry=RetryPolicy(attempts=1),
        sleep=no_wait,
        origin=Origin.FIXTURE,
    )
    result = osv.collect(["GHSA-0000-aaaa-bbbb", "GHSA-missing", "PYSEC-2026-1"])
    assert result.state.status is CollectionStatus.PARTIAL
    assert len(result.records) == 1
    assert len(result.advisories) == 1
    assert any("not found" in warning for warning in result.warnings)


def test_collect_total_failure_is_failed_not_empty() -> None:
    osv = connector([response({"error": "nope"}, status=404)])
    result = osv.collect(["GHSA-missing"])
    assert result.state.status is CollectionStatus.FAILED
    assert result.records == () and result.advisories == ()
    assert result.state.error


def test_collect_success_reports_ok() -> None:
    result = connector([response(fx.OSV_CVE)]).collect(["GHSA-0000-aaaa-bbbb"])
    assert result.state.status is CollectionStatus.OK
    assert result.warnings == ()


def test_query_uses_the_documented_endpoint() -> None:
    transport = FakeTransport(script=[response(fx.OSV_CVE)])
    osv = OsvConnector(
        transport=transport,
        gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
        retry=RetryPolicy(attempts=1),
        sleep=no_wait,
        origin=Origin.FIXTURE,
    )
    osv.get_vulnerability("GHSA-0000-aaaa-bbbb")
    urls = [c["url"] for c in transport.calls if "url" in c]
    assert urls == [f"{OSV_API}/vulns/GHSA-0000-aaaa-bbbb"]


class TestQueryBatch:
    """`POST /v1/querybatch` — documented at
    https://google.github.io/osv.dev/post-v1-querybatch/.

    The endpoint returns ids and a `modified` timestamp only. Two documented
    properties are load-bearing: results are ordered to match the input, and
    pagination is *per query* — only entries carrying a `next_page_token` need a
    follow-up, and the follow-up must resend the same query with the token added.
    """

    QUERY = {"package": {"ecosystem": "PyPI", "name": "jinja2"}, "version": "2.4.1"}

    def _batch(self, *payloads: dict):
        """Build a connector scripted with the given raw JSON payloads."""
        return connector([response(p) for p in payloads])

    def test_ids_are_returned_per_query(self):
        body = {
            "results": [
                {"vulns": [{"id": "GHSA-a", "modified": "2026-01-01T00:00:00Z"}]},
                {"vulns": []},
            ]
        }
        groups, warnings = self._batch(body).query_batch([self.QUERY, self.QUERY])
        assert groups[0] == (("GHSA-a", "2026-01-01T00:00:00Z"),)
        assert groups[1] == ()
        assert warnings == ()

    def test_posts_to_the_batch_endpoint(self):
        transport = FakeTransport(
            script=[response({"results": [{"vulns": []}]})]
        )
        osv = OsvConnector(
            transport=transport,
            gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
            retry=RetryPolicy(attempts=1),
            sleep=no_wait,
            origin=Origin.FIXTURE,
        )
        osv.query_batch([self.QUERY])
        assert transport.calls[0]["method"] == "POST"
        assert transport.calls[0]["json"] == {"queries": [self.QUERY]}

    def test_per_query_pagination_resends_only_the_paginated_query(self):
        """Requesting page two for every query would refetch complete results."""
        transport = FakeTransport(
            script=[
                response(
                    {
                        "results": [
                            {"vulns": [{"id": "GHSA-a"}], "next_page_token": "tok-a"},
                            {"vulns": [{"id": "GHSA-b"}]},
                        ]
                    }
                ),
                response({"results": [{"vulns": [{"id": "GHSA-c"}]}]}),
            ]
        )
        osv = OsvConnector(
            transport=transport,
            gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
            retry=RetryPolicy(attempts=1),
            sleep=no_wait,
            origin=Origin.FIXTURE,
        )
        groups, warnings = osv.query_batch([self.QUERY, self.QUERY])
        assert groups[0] == (("GHSA-a", None), ("GHSA-c", None))
        assert groups[1] == (("GHSA-b", None),)
        assert warnings == ()
        # The follow-up carries exactly one query, and it is the paginated one.
        second = transport.calls[1]["json"]["queries"]
        assert len(second) == 1
        assert second[0]["page_token"] == "tok-a"

    def test_result_count_mismatch_is_refused(self):
        """Misattributing ids to the wrong package is worse than failing."""
        body = {"results": [{"vulns": [{"id": "GHSA-a"}]}]}  # 1 result for 2 queries
        with pytest.raises(SourceResponseError):
            self._batch(body).query_batch([self.QUERY, self.QUERY])

    def test_page_budget_exhaustion_is_reported(self):
        paginated = {
            "results": [{"vulns": [{"id": "GHSA-a"}], "next_page_token": "tok"}]
        }
        _groups, warnings = self._batch(paginated, paginated).query_batch(
            [self.QUERY], max_pages=2
        )
        assert any("incomplete" in warning for warning in warnings)

    def test_missing_post_on_transport_is_explicit(self):
        """A GET-only transport must fail loudly, not silently return nothing."""

        class GetOnly:
            def get(self, url, **kwargs):
                return response({})

        osv = OsvConnector(
            transport=GetOnly(),
            gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
            retry=RetryPolicy(attempts=1),
            sleep=no_wait,
            origin=Origin.FIXTURE,
        )
        with pytest.raises(SourceResponseError):
            osv.query_batch([self.QUERY])

    def test_empty_query_list_makes_no_request(self):
        transport = FakeTransport(script=[])
        osv = OsvConnector(
            transport=transport,
            gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
            retry=RetryPolicy(attempts=1),
            sleep=no_wait,
            origin=Origin.FIXTURE,
        )
        assert osv.query_batch([]) == ((), ())
        assert transport.calls == []

    def test_batch_ids_are_not_treated_as_full_records(self):
        """A batch hit carries no summary, versions or severity."""
        body = {"results": [{"vulns": [{"id": "GHSA-a", "modified": "2026-01-01"}]}]}
        groups, _ = self._batch(body).query_batch([self.QUERY])
        (identifier, modified), = groups[0]
        assert identifier == "GHSA-a"
        assert modified == "2026-01-01"
