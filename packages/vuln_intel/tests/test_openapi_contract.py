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
        paths = set(spec["paths"])
        # integration/api.py serves exactly these two routes
        assert "/v1/vulnerabilities" in paths
        assert "/v1/vulnerabilities/{cve}" in paths
        assert set(paths) == {"/v1/vulnerabilities", "/v1/vulnerabilities/{cve}"}

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
