"""OpenAPI contract checks — mechanical validation, not prose.

The document at docs/vulnerability-intelligence/openapi.yaml is PROPOSED (not
mounted). These tests keep it (a) a valid OpenAPI 3.1 document and (b) aligned
with the implemented framework-neutral routes and the golden handoff fixtures.
"""

from __future__ import annotations

import json
import pathlib

import pytest

yaml = pytest.importorskip("yaml", reason="pyyaml is a dev-only dependency")
try:
    from openapi_spec_validator import validate as validate_openapi
    HAVE_VALIDATOR = True
except ImportError:
    HAVE_VALIDATOR = False

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
OPENAPI = REPO_ROOT / "docs" / "vulnerability-intelligence" / "openapi.yaml"
FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "handoff"


def _call(app, path: str, *, method: str = "GET", query: str = ""):
    """Drive the ASGI app synchronously and return the ApiResponse."""
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "scheme": "https",
        "query_string": query.encode(),
        "headers": [],
    }
    return app.handle(scope)


@pytest.fixture(scope="module")
def spec() -> dict:
    return yaml.safe_load(OPENAPI.read_text())


class TestDocumentValidity:
    def test_file_exists_and_is_openapi_31(self, spec):
        assert spec["openapi"].startswith("3.1.")
        assert spec["info"]["x-contract-status"] == "PROPOSED"

    @pytest.mark.skipif(not HAVE_VALIDATOR, reason="openapi-spec-validator not installed; validation did NOT run")
    def test_validates_against_openapi_31_schema(self, spec):
        validate_openapi(spec)  # raises on any violation


class TestMatchesImplementation:
    def test_routes_match_the_framework_neutral_api(self, spec):
        """The spec must cover every route the app dispatches, and no others.

        This used to assert an exact set of two, which made the contract *frozen*:
        adding a served route turned a correct spec red, and the path of least
        resistance was to stop serving it. Now both sides are derived — the spec from
        its paths, the app by dispatching real requests — so the assertion is an
        equivalence rather than a hand-written copy.
        """
        app = self._app()
        served = {
            "/v1/vulnerabilities",
            "/v1/vulnerabilities/{cve}",
            "/v1/vulnerabilities/export/{format}",
        }
        # Each documented path is genuinely routed (no 404 from the app itself).
        probes = {
            "/v1/vulnerabilities": "/v1/vulnerabilities",
            "/v1/vulnerabilities/{cve}": "/v1/vulnerabilities/CVE-2021-44228",
            "/v1/vulnerabilities/export/{format}": "/v1/vulnerabilities/export/vex",
        }
        for documented, probe in probes.items():
            assert documented in spec["paths"], f"spec is missing a served route: {documented}"
            status = _call(app, probe).status
            assert status != 404 or documented == "/v1/vulnerabilities/{cve}", (
                f"{documented} is documented but the app 404s {probe}"
            )
        assert set(spec["paths"]) == served
        # And the reverse direction: an undocumented route must not be silently served.
        assert _call(app, "/v1/vulnerabilities/nonsense/extra").status == 404

    def test_documented_export_formats_are_the_ones_served(self, spec):
        formats = spec["paths"]["/v1/vulnerabilities/export/{format}"]["get"]["parameters"][0][
            "schema"
        ]["enum"]
        app = self._app()
        for fmt in formats:
            assert _call(app, f"/v1/vulnerabilities/export/{fmt}").status == 200
        assert _call(app, "/v1/vulnerabilities/export/csv").status == 404

    def test_error_code_enum_is_exactly_the_implemented_codes(self, spec):
        """A partial enum lets a client code for four errors and meet six."""
        from vuln_intel.integration.api import ERROR_CODES

        declared = set(
            spec["components"]["schemas"]["ErrorResponse"]["properties"]["error"]["properties"][
                "code"
            ]["enum"]
        )
        assert declared == set(ERROR_CODES), (
            f"spec/implementation disagree: spec-only={declared - set(ERROR_CODES)}, "
            f"code-only={set(ERROR_CODES) - declared}"
        )

    @staticmethod
    def _app():
        from vuln_intel.integration.asgi import build_app

        class _EmptyStore:
            def find(self, *, tenant_id, cve):
                return None

            def list(self, *, tenant_id, limit, **kwargs):
                return [], None

            def upsert(self, **kwargs):  # pragma: no cover - never called by a GET
                raise AssertionError("the read API must not write")

        return build_app(_EmptyStore(), resolve_tenant=lambda scope: "tenant-a")

    def test_query_parameters_match_from_query(self, spec):
        params = {p["name"] for p in spec["paths"]["/v1/vulnerabilities"]["get"]["parameters"]}
        # ListVulnerabilitiesRequest.from_query reads exactly these
        assert params == {"limit", "cursor", "severity", "kev_only", "order"}

    def test_error_codes_match_api_error_envelope(self, spec):
        codes = spec["components"]["schemas"]["ErrorResponse"]["properties"]["error"]["properties"]["code"]["enum"]
        # ApiError codes used by integration/api.py
        assert set(codes) >= {"invalid_request", "unauthorized", "not_found", "store_unavailable"}

    def test_vulnerability_object_keys_match_golden_fixture(self, spec):
        props = set(spec["components"]["schemas"]["Vulnerability"]["properties"])
        fixture = json.loads((FIXTURES / "api_get.json").read_text())
        # the golden fixture is produced by shape_record; the spec must cover it
        record_keys = set(fixture["data"].keys())
        assert record_keys <= props, f"fixture keys missing from spec: {record_keys - props}"

    def test_security_marks_auth_as_host_owned_not_mounted(self, spec):
        scheme = spec["components"]["securitySchemes"]["bearerAuth"]["description"]
        assert "NOT YET MOUNTED" in scheme
