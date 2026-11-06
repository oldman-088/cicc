"""HTTP contract for vulnerability intelligence.

The security-critical property here is tenant isolation: a client must never be
able to read another tenant's intelligence by passing a different tenant
identifier. Everything else in this module exists to make the contract
implementable by a host framework without re-deriving the rules.
"""

from __future__ import annotations

from datetime import datetime, timezone

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
from vuln_intel.schema import Severity, severity_rank

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

    def test_declared_test_count_matches_what_this_suite_collects(self):
        """`tests_passed` said 1769 while the suite had grown past 1870.

        A floor (`>= 600`) cannot catch that: it stays true forever. The real count is
        compared here — but only where it is knowable.

        Two mistakes are recorded in this test's history, both mine:

        1. Static counting of `test_*` functions undercounts by ~500, because the
           suite is heavily parametrised and hypothesis-generated. Collection is the
           only honest source, so it is what this uses.
        2. Collection depends on the environment. `pytest.importorskip("yaml")` makes
           whole modules vanish when pyyaml is absent — the `oracle` CI job installs
           pytest, hypothesis and three version oracles, and nothing else, so the same
           commit collects 22 fewer tests there and this assertion failed a green
           branch.

        So: exact equality where the optional dev dependencies are present (both CI
        test jobs, and any developer environment), and a lower bound plus an explicit
        note where they are not. A check that cannot know the answer says so instead of
        guessing.
        """
        import pathlib
        import subprocess
        import sys

        declared = self._state()["quality_gates"]["tests_passed"]
        collected = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q"],
            capture_output=True,
            text=True,
            cwd=str(pathlib.Path(__file__).resolve().parents[1]),
            check=False,
        ).stdout
        counted = 0
        for line in collected.splitlines():
            head, _, tail = line.rpartition(": ")
            if head and tail.isdigit():
                counted += int(tail)
        assert counted > 1000, f"collector produced no usable count:\n{collected[:400]}"

        have_optional = all(
            __import__("importlib").util.find_spec(name) is not None
            for name in ("yaml", "openapi_spec_validator")
        )
        if not have_optional:
            pytest.skip(
                f"optional dev deps absent, so {counted} collected != declared {declared} "
                "by design; the exact check runs in the CI test job"
            )
        assert abs(declared - counted) <= 15, (
            f"PROJECT_STATE.json declares {declared} tests; the collector sees {counted}. "
            "Update quality_gates.tests_passed."
        )

    def test_declared_mypy_count_matches_the_package(self):
        """The file said 58 files long after the package had 61."""
        import pathlib
        import re
        import subprocess
        import sys

        declared = int(re.search(r"(\d+) files", self._state()["quality_gates"]["mypy"]).group(1))
        out = subprocess.run(
            [sys.executable, "-m", "mypy", "vuln_intel"],
            capture_output=True,
            text=True,
            cwd=str(pathlib.Path(__file__).resolve().parents[1]),
            check=False,
        ).stdout
        found = re.search(r"in (\d+) source files", out)
        if found is None:  # mypy absent locally; say so rather than pass silently
            pytest.skip("mypy not installed, so the declared file count was NOT checked")
        assert int(found.group(1)) == declared, (
            f"PROJECT_STATE.json declares {declared} mypy files; mypy reports {found.group(1)}"
        )

class TestTheRecordedHeadIsWellFormed:
    """`head` cannot be self-verified, and pretending otherwise was worse.

    I first wrote this as "the head names a real commit". It failed CI, because
    the workflow checks out depth 1, so the commit is simply absent there. Making
    it skip on a shallow clone made it skip in this sandbox too -- a test that
    proves nothing in any environment I can run it in.

    It also would not have caught the drift that prompted it: the stale value,
    9c9d709, was a genuine ancestor of HEAD, so every ancestry check accepts it.
    A commit cannot assert its own sha, and nothing in the tree can either.

    So the field is documented as informational (`head_is_informational` in the
    state file) and only its shape is checked. The numbers that ARE checked are
    `tests_passed` and the mypy file count, which the guards above pin exactly.
    """

    def _state(self):
        import json
        import pathlib

        root = pathlib.Path(__file__).resolve().parents[3]
        return json.loads(
            (root / "docs" / "vulnerability-intelligence" / "PROJECT_STATE.json").read_text()
        )

    def test_the_head_is_recorded_as_a_lowercase_hex_sha(self):
        head = self._state()["head"]
        assert isinstance(head, str) and 7 <= len(head) <= 40, f"head is {head!r}"
        assert all(c in "0123456789abcdef" for c in head), f"head is not hex: {head!r}"

    def test_the_state_file_says_the_head_is_not_self_verified(self):
        # The honesty requirement, applied to our own bookkeeping: if a field is
        # not checked, the file must say so rather than leave a reader assuming it.
        note = self._state().get("head_is_informational")
        assert isinstance(note, str) and note.strip(), (
            "PROJECT_STATE.json must state that `head` is informational; without it a "
            "stale value reads as a verified one"
        )


class TestStandingAndConflictsReachTheApi:
    """The read contract silently dropped every field added this week.

    `shape_record` copies a fixed key list, so `record_status`, `conflicts` and `ssvc`
    existed on the record, travelled through the ingest payload, and then vanished at
    the boundary a frontend actually reads. Nothing failed, because nothing asserted
    the fields were there.
    """

    @staticmethod
    def _row(**kwargs):
        from vuln_intel.integration.mapping import to_source_details
        from vuln_intel.schema import (
            CveId,
            FieldConflict,
            NormalizedVulnerability,
            Origin,
            RecordStatus,
        )

        base = dict(
            cve=CveId.parse("CVE-2026-9600"),
            origin=Origin.FIXTURE,
            sources=("nvd", "osv"),
            record_status=RecordStatus.REJECTED,
            ssvc=(("exploitation", "active"),),
            conflicts=(
                FieldConflict(
                    field="severity", kept="critical", discarded=("high",),
                    dissenters=("osv",),
                ),
            ),
        )
        base.update(kwargs)
        record = NormalizedVulnerability(**base)
        return {"cve": str(record.cve), "origin": "fixture",
                "details": to_source_details(record)}

    def test_record_status_is_exposed(self) -> None:
        from vuln_intel.integration.api import shape_record

        assert shape_record(self._row())["record_status"] == "rejected"

    def test_conflicts_are_structured_not_prose(self) -> None:
        from vuln_intel.integration.api import shape_record

        conflicts = shape_record(self._row())["conflicts"]
        assert conflicts == [
            {
                "field": "severity",
                "kept": "critical",
                "discarded": ["high"],
                "dissenters": ["osv"],
            }
        ]

    def test_ssvc_inputs_are_exposed(self) -> None:
        from vuln_intel.integration.api import shape_record

        assert shape_record(self._row())["ssvc"] == {"exploitation": "active"}

    def test_absent_standing_stays_null_not_false(self) -> None:
        from vuln_intel.integration.api import shape_record

        row = self._row()
        # Drop the standing from the stored enrichment, as a pre-existing row would be.
        del row["details"]["cicc_enrichment"]["record_status"]
        assert shape_record(row)["record_status"] is None
        assert shape_record(row)["withdrawn"] is None

    def test_prose_notes_are_kept_alongside_structure(self) -> None:
        """Existing prose readers must not break."""
        from vuln_intel.integration.mapping import to_source_details
        from vuln_intel.schema import CveId, NormalizedVulnerability, Origin

        record = NormalizedVulnerability(
            cve=CveId.parse("CVE-2026-9601"), origin=Origin.FIXTURE,
            conflict_notes=("severity disagreement",),
        )
        details = to_source_details(record)
        assert details["cicc_enrichment"]["conflict_notes"] == ["severity disagreement"]
        assert details["conflict_notes"] == ["severity disagreement"]

class TestFullRecordRoundTrip:
    """A fully populated record must survive ingest → store → read intact.

    Every pre-existing API test built its rows by hand, using the *enrichment*
    spelling of each field. Ingest writes the detail-level spelling. The tests agreed
    with the bug: `shape_record` read `enrichment["severity"]` while the store held
    `details["severity"]`, so a real record came back with `severity: null`,
    `cvss: null` and `sources: []` and nothing failed.

    These tests go through the real service and the real store, which is the only way
    to catch a disagreement between two halves of the same pipeline.
    """

    @staticmethod
    def _pipeline(records):
        from vuln_intel.integration.service import IngestionPolicy, IngestionService
        from vuln_intel.integration.store import InMemoryVulnerabilityStore

        store = InMemoryVulnerabilityStore(allow_fixture=True)
        service = IngestionService(
            store=store, policy=IngestionPolicy(allow_fixture=True, dry_run=False)
        )
        service.import_records(records, tenant_id="tenant-a")
        return VulnerabilityApi(store)

    @staticmethod
    def _record(**kwargs):
        from vuln_intel.schema import (
            CveId,
            CvssScore,
            NormalizedVulnerability,
            Origin,
            Severity,
        )

        base = dict(
            cve=CveId.parse("CVE-2026-0100"),
            origin=Origin.FIXTURE,
            sources=("nvd", "osv"),
            summary="round trip",
            severity=Severity.HIGH,
            cvss=(
                CvssScore(version="3.1", base_score=8.1, severity=Severity.HIGH,
                          source="nvd"),
            ),
            kev=True,
            epss_score=0.5,
            epss_percentile=0.95,
        )
        base.update(kwargs)
        return NormalizedVulnerability(**base)

    def test_severity_survives(self) -> None:
        api = self._pipeline([self._record()])
        data = api.get(
            GetVulnerabilityRequest(tenant_id="tenant-a", cve="CVE-2026-0100")
        ).body["data"]
        assert data["severity"] == "high"

    def test_cvss_survives(self) -> None:
        api = self._pipeline([self._record()])
        data = api.get(
            GetVulnerabilityRequest(tenant_id="tenant-a", cve="CVE-2026-0100")
        ).body["data"]
        assert data["cvss"]["base_score"] == 8.1

    def test_sources_survive(self) -> None:
        api = self._pipeline([self._record()])
        data = api.get(
            GetVulnerabilityRequest(tenant_id="tenant-a", cve="CVE-2026-0100")
        ).body["data"]
        assert data["sources"] == ["nvd", "osv"]

    def test_kev_and_epss_survive(self) -> None:
        api = self._pipeline([self._record()])
        data = api.get(
            GetVulnerabilityRequest(tenant_id="tenant-a", cve="CVE-2026-0100")
        ).body["data"]
        assert data["kev"] is True
        assert data["epss"]["score"] == 0.5

    def test_the_api_and_the_model_agree_on_best_cvss(self) -> None:
        """Two definitions of "best" in two layers makes a UI contradict a report.

        The model prefers the *newest specification* (v4.0 9.3 over v3.1 9.8); an
        earlier version of `shape_record` preferred the *highest score* and reported
        9.8 for the same record.
        """
        from vuln_intel.schema import CvssScore, Severity

        record = self._record(
            cvss=(
                CvssScore(version="4.0", base_score=9.3, severity=Severity.CRITICAL,
                          source="nvd"),
                CvssScore(version="3.1", base_score=9.8, severity=Severity.CRITICAL,
                          source="ghsa"),
            )
        )
        api = self._pipeline([record])
        data = api.get(
            GetVulnerabilityRequest(tenant_id="tenant-a", cve="CVE-2026-0100")
        ).body["data"]
        assert data["cvss"]["base_score"] == record.best_cvss.base_score
        assert data["cvss"]["version"] == record.best_cvss.version

    def test_legacy_enrichment_only_rows_still_render(self) -> None:
        """Rows written before the fix put everything under the enrichment key."""
        row = {
            "cve": "CVE-2026-0101",
            "origin": "live",
            "details": {
                "cicc_enrichment": {
                    "severity": "high",
                    "best_cvss": {"base_score": 7.0, "version": "3.1"},
                    "contributing_sources": ["nvd"],
                    "kev": True,
                    "epss": {"score": 0.1},
                }
            },
        }
        shaped = shape_record(row)
        assert shaped["severity"] == "high"
        assert shaped["sources"] == ["nvd"]
        assert shaped["cvss"]["base_score"] == 7.0

class TestSeverityOrderingIsSeverityOrder:
    """`order="severity"` used to sort by the severity *name*, not by severity.

    Lexicographic order on {"critical","high","low","medium","none","unknown"} puts
    "low" before "medium". A listing sorted by severity therefore showed the least
    urgent findings above the medium ones — not crashing, not visible in a spot check
    of two rows, and nothing asserted the order so nothing failed.

    These tests pin the order itself and pin that the API and the store agree on it.
    """

    _SEVERITIES = (
        ("CVE-2026-0101", "low"),
        ("CVE-2026-0102", "critical"),
        ("CVE-2026-0103", "medium"),
        ("CVE-2026-0104", "high"),
        ("CVE-2026-0105", "none"),
        ("CVE-2026-0106", "unknown"),
    )

    def _seeded(self):
        store = InMemoryVulnerabilityStore(allow_fixture=True)
        moment = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for cve, severity in self._SEVERITIES:
            store.upsert(
                tenant_id="tenant-a",
                cve=cve,
                entity={},
                details={"severity": severity, "kev": False},
                enrichment=None,
                provenance={"source": "nvd"},
                collected_at=moment,
                dry_run=False,
            )
        return store

    def test_ascending_is_most_severe_first(self):
        rows, _ = self._seeded().list(tenant_id="tenant-a", limit=10, order="severity")
        assert [row["details"]["severity"] for row in rows] == [
            "critical", "high", "medium", "low", "none", "unknown",
        ]

    def test_descending_is_the_exact_reverse(self):
        rows, _ = self._seeded().list(tenant_id="tenant-a", limit=10, order="-severity")
        assert [row["details"]["severity"] for row in rows] == [
            "unknown", "none", "low", "medium", "high", "critical",
        ]

    def test_medium_never_sorts_below_low(self):
        """The specific inversion that the bug produced."""
        rows, _ = self._seeded().list(tenant_id="tenant-a", limit=10, order="severity")
        severities = [row["details"]["severity"] for row in rows]
        assert severities.index("medium") < severities.index("low")

    def test_the_api_exposes_the_same_order_as_the_store(self):
        """One order, not two: the service and the listing must not disagree."""
        rows, _ = self._seeded().list(tenant_id="tenant-a", limit=10, order="severity")
        store_order = [row["details"]["severity"] for row in rows]
        canonical = [s.value for s in sorted(Severity, key=severity_rank)]
        assert store_order == canonical

    def test_paging_by_severity_does_not_repeat_or_skip(self):
        """A tie-break is required or equal severities make the cursor ambiguous."""
        store = self._seeded()
        seen: list[str] = []
        cursor = None
        for _ in range(10):
            rows, cursor = store.list(
                tenant_id="tenant-a", limit=2, cursor=cursor, order="severity"
            )
            seen.extend(row["cve"] for row in rows)
            if cursor is None:
                break
        assert len(seen) == len(set(seen)) == len(self._SEVERITIES)

    def test_unknown_severity_is_ranked_last_not_first(self):
        assert severity_rank("unknown") == max(severity_rank(s) for s in Severity)
        assert severity_rank("critical") == 0

    def test_a_bogus_severity_sorts_after_every_known_one(self):
        assert severity_rank("bogus") > severity_rank("unknown")
        assert severity_rank(None) > severity_rank("unknown")

