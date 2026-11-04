"""HTTP contract for vulnerability intelligence.

The security-critical property here is tenant isolation: a client must never be
able to read another tenant's intelligence by passing a different tenant
identifier. Everything else in this module exists to make the contract
implementable by a host framework without re-deriving the rules.
"""

from __future__ import annotations

import pytest

from vuln_intel.errors import ValidationError
from vuln_intel.integration.api import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    ApiError,
    ApiResponse,
    GetVulnerabilityRequest,
    ListVulnerabilitiesRequest,
    VulnerabilityApi,
    asgi_handler,
    shape_record,
)
from vuln_intel.integration.service import IngestionPolicy, IngestionService
from vuln_intel.integration.store import InMemoryVulnerabilityStore

from . import fixtures as fx
from .conftest import FakeTransport, no_wait, response


def _record(osv_id: str = "GHSA-0000-aaaa-bbbb"):
    from vuln_intel.connectors.osv import OsvConnector
    from vuln_intel.ratelimit import RateGate
    from vuln_intel.retry import RetryPolicy
    from vuln_intel.schema import Origin

    connector = OsvConnector(
        transport=FakeTransport(script=[response(fx.OSV_CVE)]),
        gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
        retry=RetryPolicy(attempts=1),
        sleep=no_wait,
        origin=Origin.FIXTURE,
    )
    record, _advisory = connector.get_vulnerability(osv_id)
    assert record is not None
    return record


def _store_with(tenant: str = "tenant-a", **store_kwargs):
    store = InMemoryVulnerabilityStore(allow_fixture=True, **store_kwargs)
    service = IngestionService(
        store=store, policy=IngestionPolicy(allow_fixture=True, dry_run=False)
    )
    service.import_records([_record()], tenant_id=tenant)
    return store


def _tenant(tenant: str = "tenant-a"):
    return lambda query, path: tenant


class TestTenantIsolation:
    """The single most important property of this surface."""

    def test_another_tenant_cannot_read_the_record(self):
        store = _store_with("tenant-a")
        api = VulnerabilityApi(store)
        with pytest.raises(ApiError) as caught:
            api.get(GetVulnerabilityRequest(tenant_id="tenant-b", cve="CVE-2026-0001"))
        assert caught.value.status == 404

    def test_another_tenant_sees_an_empty_list_not_a_shared_one(self):
        store = _store_with("tenant-a")
        api = VulnerabilityApi(store)
        response_obj = api.list(ListVulnerabilitiesRequest(tenant_id="tenant-b"))
        assert response_obj.body["data"] == []
        assert response_obj.body["page"]["has_more"] is False

    def test_tenant_cannot_be_supplied_by_the_client(self):
        """A tenant in the query string must be ignored in favour of the resolver."""
        store = _store_with("tenant-a")
        handler = asgi_handler(VulnerabilityApi(store), resolve_tenant=_tenant("tenant-b"))
        result = handler(
            "GET",
            "/v1/vulnerabilities/CVE-2026-0001",
            {"tenant_id": "tenant-a"},  # attacker-supplied, must be ignored
        )
        assert result.status == 404

    def test_blank_tenant_is_rejected_not_treated_as_wildcard(self):
        with pytest.raises(ApiError) as caught:
            GetVulnerabilityRequest(tenant_id="   ", cve="CVE-2026-0001")
        assert caught.value.code == "unauthorized"

    def test_resolver_failure_surfaces_as_unauthorized(self):
        store = _store_with()

        def deny(_query, _path):
            raise ApiError("unauthorized", "missing bearer token")

        handler = asgi_handler(VulnerabilityApi(store), resolve_tenant=deny)
        result = handler("GET", "/v1/vulnerabilities", {})
        assert result.status == 401
        assert result.body["error"]["code"] == "unauthorized"


class TestGetVulnerability:
    def test_returns_the_documented_shape(self):
        api = VulnerabilityApi(_store_with())
        body = api.get(
            GetVulnerabilityRequest(tenant_id="tenant-a", cve="CVE-2026-0001")
        ).body
        data = body["data"]
        for key in (
            "cve",
            "entity_id",
            "origin",
            "collected_at",
            "severity",
            "kev",
            "epss",
            "sources",
            "freshness",
        ):
            assert key in data
        assert data["cve"] == "CVE-2026-0001"
        assert data["origin"] == "fixture"

    def test_unknown_cve_is_404(self):
        api = VulnerabilityApi(_store_with())
        with pytest.raises(ApiError) as caught:
            api.get(GetVulnerabilityRequest(tenant_id="tenant-a", cve="CVE-2026-9999"))
        assert caught.value.status == 404

    def test_malformed_cve_is_rejected_before_reaching_storage(self):
        with pytest.raises(ValidationError):
            GetVulnerabilityRequest(tenant_id="tenant-a", cve="not-a-cve")

    def test_cve_is_normalized(self):
        request = GetVulnerabilityRequest(
            tenant_id="tenant-a", cve="cve-2026-0001"
        )
        assert request.cve == "CVE-2026-0001"

    def test_store_failure_is_503_not_a_stack_trace(self):
        class Broken:
            def find(self, **_kwargs):
                raise RuntimeError("connection refused")

            def list(self, **_kwargs):
                raise RuntimeError("connection refused")

        api = VulnerabilityApi(Broken())  # type: ignore[arg-type]
        with pytest.raises(ApiError) as caught:
            api.get(GetVulnerabilityRequest(tenant_id="tenant-a", cve="CVE-2026-0001"))
        assert caught.value.status == 503
        # The message names the failure type but never the driver's internals.
        assert "connection refused" not in caught.value.message


class TestListVulnerabilities:
    def _many(self, count: int):
        store = InMemoryVulnerabilityStore(allow_fixture=True)
        service = IngestionService(
            store=store, policy=IngestionPolicy(allow_fixture=True, dry_run=False)
        )
        records = []
        for index in range(count):
            record = _record()
            records.append(
                record.__class__(**{**_as_kwargs(record), "cve": _cve(f"CVE-2026-{index:04d}")})
            )
        service.import_records(records, tenant_id="tenant-a")
        return store

    def test_pagination_walks_every_row_exactly_once(self):
        store = self._many(5)
        api = VulnerabilityApi(store)
        seen: list[str] = []
        cursor = None
        for _ in range(10):
            body = api.list(
                ListVulnerabilitiesRequest(
                    tenant_id="tenant-a", limit=2, cursor=cursor
                )
            ).body
            seen.extend(row["cve"] for row in body["data"])
            cursor = body["page"]["next_cursor"]
            if cursor is None:
                break
        assert len(seen) == 5
        assert len(set(seen)) == 5, "a row was repeated or skipped across pages"

    def test_limit_is_bounded(self):
        with pytest.raises(ApiError) as caught:
            ListVulnerabilitiesRequest(tenant_id="tenant-a", limit=MAX_PAGE_SIZE + 1)
        assert caught.value.code == "invalid_request"

    def test_zero_limit_is_rejected(self):
        with pytest.raises(ApiError):
            ListVulnerabilitiesRequest(tenant_id="tenant-a", limit=0)

    def test_default_limit(self):
        assert ListVulnerabilitiesRequest(tenant_id="tenant-a").limit == DEFAULT_PAGE_SIZE

    def test_unknown_order_is_rejected(self):
        with pytest.raises(ApiError):
            ListVulnerabilitiesRequest(tenant_id="tenant-a", order="random")

    def test_unknown_severity_is_rejected(self):
        with pytest.raises(ApiError):
            ListVulnerabilitiesRequest(tenant_id="tenant-a", severity="apocalyptic")

    def test_query_parsing_rejects_non_integer_limit(self):
        with pytest.raises(ApiError) as caught:
            ListVulnerabilitiesRequest.from_query({"limit": "abc"}, tenant_id="tenant-a")
        assert caught.value.field_name == "limit"

    def test_query_parsing_rejects_bad_boolean(self):
        with pytest.raises(ApiError):
            ListVulnerabilitiesRequest.from_query(
                {"kev_only": "yes-please"}, tenant_id="tenant-a"
            )

    def test_query_parsing_accepts_documented_booleans(self):
        assert (
            ListVulnerabilitiesRequest.from_query(
                {"kev_only": "true"}, tenant_id="tenant-a"
            ).kev_only
            is True
        )
        assert (
            ListVulnerabilitiesRequest.from_query(
                {"kev_only": "0"}, tenant_id="tenant-a"
            ).kev_only
            is False
        )


class TestResponseHonesty:
    def test_missing_kev_is_null_not_false(self):
        """`false` would assert the catalogue was checked and the CVE is absent."""
        row = {
            "cve": "CVE-2026-0001",
            "entity_id": "e1",
            "origin": "live",
            "collected_at": None,
            "details": {"cicc_enrichment": {"severity": "high"}},
        }
        shaped = shape_record(row)
        assert shaped["kev"] is None
        assert shaped["epss"] is None

    def test_empty_record_does_not_invent_fields(self):
        shaped = shape_record({"cve": "CVE-2026-0001", "details": {}})
        assert shaped["sources"] == []
        assert shaped["severity"] is None


class TestAsgiBinding:
    """The dependency-free binding proves the contract is implementable."""

    def _handler(self, store=None, tenant: str = "tenant-a"):
        return asgi_handler(
            VulnerabilityApi(store or _store_with()), resolve_tenant=_tenant(tenant)
        )

    def test_get_route(self):
        result = self._handler()("GET", "/v1/vulnerabilities/CVE-2026-0001", {})
        assert result.status == 200
        assert result.body["data"]["cve"] == "CVE-2026-0001"

    def test_list_route(self):
        result = self._handler()("GET", "/v1/vulnerabilities", {"limit": "5"})
        assert result.status == 200
        assert result.body["page"]["limit"] == 5

    def test_unknown_route_is_404(self):
        assert self._handler()("GET", "/v1/unknown", {}).status == 404
        assert self._handler()("GET", "/v1/vulnerabilities/CVE-2026-0001/extra", {}).status == 404

    def test_non_get_is_rejected(self):
        assert self._handler()("POST", "/v1/vulnerabilities", {}).status == 400

    def test_errors_are_shaped_not_raised(self):
        result = self._handler()("GET", "/v1/vulnerabilities/CVE-2026-9999", {})
        assert isinstance(result, ApiResponse)
        assert result.status == 404
        assert result.body["error"]["code"] == "not_found"

    def test_invalid_cve_is_400_not_500(self):
        result = self._handler()("GET", "/v1/vulnerabilities/garbage", {})
        assert result.status == 400
        assert result.body["error"]["code"] == "invalid_request"

    def test_unexpected_failure_does_not_leak_internals(self):
        class Exploding:
            def find(self, **_kwargs):
                raise RuntimeError("secret dsn=postgres://user:pw@host/db")

            def list(self, **_kwargs):
                raise RuntimeError("secret dsn=postgres://user:pw@host/db")

        handler = asgi_handler(
            VulnerabilityApi(Exploding()),  # type: ignore[arg-type]
            resolve_tenant=_tenant(),
        )
        result = handler("GET", "/v1/vulnerabilities/CVE-2026-0001", {})
        assert result.status == 503
        assert "postgres://" not in str(result.body)
        assert "pw@" not in str(result.body)


# ---------------------------------------------------------------------------
# helpers used by the pagination test
# ---------------------------------------------------------------------------
def _as_kwargs(record):
    """Field values of a NormalizedVulnerability, for lightweight cloning."""
    import dataclasses

    return {f.name: getattr(record, f.name) for f in dataclasses.fields(record)}


def _cve(value: str):
    from vuln_intel.schema import CveId

    return CveId.parse(value)


class TestDocumentedBindingStaysTrue:
    """API.md tells other agents how to integrate. If it drifts from the code, the
    integration breaks in someone else's repository, where our tests cannot see it.
    """

    def _doc(self):
        import pathlib

        root = pathlib.Path(__file__).resolve().parents[3]
        return (root / "docs" / "vulnerability-intelligence" / "API.md").read_text()

    def test_documented_symbols_exist(self):
        import re

        from vuln_intel.integration import api as module

        documented = set(
            re.findall(
                r"\b(ApiError|ApiResponse|GetVulnerabilityRequest|"
                r"ListVulnerabilitiesRequest|VulnerabilityApi|asgi_handler)\b",
                self._doc(),
            )
        )
        assert documented, "expected the doc to reference the public contract"
        for name in documented:
            assert hasattr(module, name), f"API.md documents a missing symbol: {name}"

    def test_documented_python_blocks_parse(self):
        import ast
        import re

        blocks = re.findall(r"```python\n(.*?)```", self._doc(), re.S)
        assert blocks, "expected at least one documented binding"
        for block in blocks:
            ast.parse(block)  # a syntax error means we shipped a broken recipe

    def test_documented_error_codes_match_implementation(self):
        from vuln_intel.integration.api import ERROR_CODES

        doc = self._doc()
        for code in ERROR_CODES:
            assert code in doc, f"error code {code!r} is not documented"


class TestProjectStateFile:
    """PROJECT_STATE.json is consumed by Agent 1's dashboard.

    A machine-readable state file that drifts from the code is worse than none: it
    reports a capability as ready while the flag that gates it says otherwise.
    """

    def _state(self):
        import json
        import pathlib

        root = pathlib.Path(__file__).resolve().parents[3]
        return json.loads(
            (root / "docs" / "vulnerability-intelligence" / "PROJECT_STATE.json").read_text()
        )

    def test_is_valid_json_with_required_keys(self):
        state = self._state()
        for key in (
            "schema_version",
            "subsystem",
            "maturity",
            "capabilities",
            "honesty_invariants",
            "owner_approvals_pending",
        ):
            assert key in state, f"PROJECT_STATE.json is missing {key!r}"

    def test_honesty_invariants_match_the_code(self):
        from vuln_intel import kev
        from vuln_intel.connectors import epss, nvd, osv

        state = self._state()["honesty_invariants"]
        assert state["nvd_last_verified_live"] is nvd.LAST_VERIFIED_LIVE
        assert state["osv_last_verified_live"] is osv.LAST_VERIFIED_LIVE
        assert state["kev_last_verified_live"] is kev.LAST_VERIFIED_LIVE
        assert state["epss_live_provider_available"] is epss.LIVE_PROVIDER_AVAILABLE

    def test_no_capability_claims_live_verification(self):
        """Nothing here has ever made a real provider request."""
        for capability in self._state()["capabilities"]:
            assert capability["live_verified"] is False, capability["name"]

    def test_declared_test_count_is_plausible(self):
        """Catches a stale number without hard-coding the exact count in two places."""
        state = self._state()
        assert state["quality_gates"]["tests_passed"] >= 600
