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


# --- OSV id charset: the schema's contract, not a hand-picked blocklist --------
#
# The connector used to reject only ids containing "/" or "?".  Every earlier SSRF
# probe happened to contain one of those, so the check looked correct while most of
# the unsafe charset was still accepted.  The schema guarantees ids match
# ^[a-zA-Z0-9:_.-]+$, so that pattern is now enforced verbatim.

_ILLEGAL_ID_CHARS = [
    "/",           # path separator
    "\\",          # Windows separator; also an escape in some URL builders
    "?",           # query injection
    "#",           # fragment injection
    "%",           # pre-encoded percent: "%2e%2e" traverses without a "/"
    " ",           # space
    "\t",          # control whitespace
    "\n",          # header/line injection
    "\x00",        # NUL truncation
    "@",           # authority injection ("osv.dev@evil.example")
    "&",           # parameter smuggling
    "+",           # decodes to a space in form encoding
    "(", ")", "!",
    "\u202e",      # right-to-left override: renders "gpj.exe" as "exe.jpg"
]


@pytest.mark.parametrize("illegal", _ILLEGAL_ID_CHARS, ids=repr)
def test_every_illegal_id_character_is_rejected(illegal: str) -> None:
    # A scripted response is supplied so that a *missed* validation would surface as
    # an unexpected parse result rather than being masked by an empty script.
    with pytest.raises(ValidationError):
        connector([response(fx.OSV_CVE)]).get_vulnerability(f"GHSA-abcd{illegal}1234")


@pytest.mark.parametrize(
    "legal",
    ["GHSA-xxxx-yyyy-zzzz", "CVE-2021-44228", "PYSEC-2021-1", "OSV-2020-111",
     "RUSTSEC-2020-0001", "GO-2023-1234", "x_local:db.entry_1", "DEBIAN-CVE-2019--1"],
)
def test_legal_ids_are_accepted(legal: str) -> None:
    # Guards against over-tightening: a stricter check that also rejects real ids
    # would break collection silently, which is worse than the original bug.
    record, _advisory = connector([response(fx.OSV_CVE)]).get_vulnerability(legal)
    assert record is not None


def test_traversal_without_slash_is_rejected() -> None:
    # The specific case the old "/"-and-"?" check missed.
    for probe in ("%2e%2e", "a\\b"):
        with pytest.raises(ValidationError):
            connector([response(fx.OSV_CVE)]).get_vulnerability(probe)


# --- ranges[].events: `fixed` with no `introduced` must not be dropped ---------


def _range_record(events: list[dict[str, str]]) -> dict:
    return {
        "id": "GHSA-rang-0000-0001",
        "modified": "2026-01-01T00:00:00Z",
        "summary": "range folding",
        # Without a CVE alias the connector returns record=None by design (it will
        # not invent an identifier), so the range would never be observable here.
        "aliases": ["CVE-2026-7777"],
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "left-pad"},
                "ranges": [{"type": "SEMVER", "events": events}],
            }
        ],
    }


def test_fixed_without_introduced_opens_at_zero() -> None:
    script = [response(_range_record([{"fixed": "1.2.0"}]))]
    record, _advisory = connector(script).get_vulnerability("GHSA-rang-0000-0001")
    package = record.affected[0]
    assert package.introduced == "0", (
        "a `fixed` event with no preceding `introduced` means 'everything below "
        "this version'; dropping it reports an affected package as unaffected"
    )
    assert package.fixed == "1.2.0"


def test_limit_event_does_not_become_a_fix() -> None:
    # `limit` bounds the range document; it does not assert that a fix exists.
    # Folding it into `fixed` would publish a remedy version the source never
    # claimed, so the interval must stay open.
    script = [response(_range_record([{"introduced": "1.0.0"}, {"limit": "2.0.0"}]))]
    record, _advisory = connector(script).get_vulnerability("GHSA-rang-0000-0001")
    package = record.affected[0]
    assert package.fixed is None
    assert package.introduced == "1.0.0"
    # The raw event is still preserved for consumers that need the boundary.
    assert ("limit", "2.0.0") in {(kind, value) for _, kind, value in package.events}


# --- forward compatibility and schema fidelity --------------------------------


def test_unknown_fields_are_ignored_not_rejected() -> None:
    """The schema guarantees new fields appear in minor versions, so ignore them."""
    body = dict(fx.OSV_CVE)
    body["x_some_future_field"] = {"nested": ["value"]}
    record, _advisory = connector([response(body)]).get_vulnerability("CVE-2026-0002")
    assert record is not None
    assert not any("x_some_future_field" in note for note in record.conflict_notes)


def test_unmodelled_fields_are_reported_rather_than_silently_dropped() -> None:
    body = dict(fx.OSV_CVE)
    body["credits"] = [{"name": "A. Researcher", "type": "FINDER"}]
    body["schema_version"] = "1.9.2"
    record, _advisory = connector([response(body)]).get_vulnerability("CVE-2026-0002")
    notes = " ".join(record.conflict_notes)
    assert "'credits'" in notes
    assert "'schema_version'" in notes


def test_top_level_and_affected_severity_together_is_reported() -> None:
    """The schema forbids setting both; a malformed record must not be resolved silently."""
    body = dict(fx.OSV_CVE)
    affected = [dict(entry) for entry in body["affected"]]
    affected[0]["severity"] = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    body["affected"] = affected
    assert body.get("severity"), "fixture must carry a top-level severity for this test"
    record, _advisory = connector([response(body)]).get_vulnerability("CVE-2026-0002")
    assert any("top-level" in note and "affected[].severity" in note
               for note in record.conflict_notes)
