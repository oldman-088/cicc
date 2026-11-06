"""The SBOM import contract, tested without a route existing.

The task is explicit that no upload endpoint may be claimed until one is implemented and
exercised. This file is how the contract is exercised *before* that: every check a route
must perform that does not need a principal or a database is tested here against the
handler the host would mount.

What is deliberately **not** here: authentication, tenant resolution, rate limiting,
storage and audit. Those are host concerns, and a test that faked them would be a
synthetic-host test dressed as an acceptance test.
"""

from __future__ import annotations

import json

import pytest

from vuln_intel.integration.sbom_handler import (
    ALLOWED_ORIGINS,
    MIN_SUPPORTED_HOST_CONTRACT,
    SbomImportRequest,
    handle_sbom_import,
    shape_for_downstream,
)
from vuln_intel.sbom import MAX_DOCUMENT_BYTES

_TENANT = "00000000-0000-0000-0000-00000000000a"


def _cdx(*components, spec="1.5"):
    return json.dumps(
        {"bomFormat": "CycloneDX", "specVersion": spec, "components": list(components)}
    ).encode()


_LOG4J = {
    "bom-ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
    "name": "log4j-core",
    "version": "2.14.1",
    "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
    "licenses": [{"license": {"id": "Apache-2.0"}}],
}


def _request(body=None, **overrides):
    fields = {
        "body": _cdx(_LOG4J) if body is None else body,
        "tenant_id": _TENANT,
        "actor_id": "user-1",
        "origin": "live",
    }
    fields.update(overrides)
    return SbomImportRequest(**fields)


class TestASuccessfulImport:
    def test_a_valid_document_returns_200_and_an_inventory_summary(self):
        response = handle_sbom_import(_request())
        assert response.status == 200
        assert response.ok
        result = response.body["result"]
        assert result["format"] == "cyclonedx-json"
        assert result["components"] == 1
        assert result["complete"] is True

    def test_the_response_carries_the_tenant_it_was_given(self):
        assert handle_sbom_import(_request()).body["tenant_id"] == _TENANT

    def test_the_response_carries_a_document_digest(self):
        import hashlib

        body = _cdx(_LOG4J)
        response = handle_sbom_import(_request(body=body))
        assert response.body["result"]["source_sha256"] == hashlib.sha256(body).hexdigest()

    def test_the_body_is_json_serialisable(self):
        body = handle_sbom_import(_request()).as_dict()
        assert json.loads(json.dumps(body))["ok"] is True

    def test_a_partial_inventory_says_so(self):
        """A component that cannot be matched must not look like a clean import."""
        unmatchable = {"bom-ref": "r1", "name": "mystery", "version": "1.0"}
        response = handle_sbom_import(_request(body=_cdx(unmatchable)))
        assert response.status == 200
        result = response.body["result"]
        assert result["complete"] is False
        assert result["skipped"]
        assert result["components"] == 0

    def test_licences_are_carried_through(self):
        """Keyed by the normalised `ecosystem:name`, not the bare package name.

        The normalised form is what the vulnerability matcher uses; keying the licence
        map differently would make a consumer join two dictionaries by hand.
        """
        result = handle_sbom_import(_request()).body["result"]
        assert result["licenses"] == {
            "org.apache.logging.log4j:log4j-core": ["Apache-2.0"]
        }


class TestTheTenantCannotComeFromTheDocument:
    """The property that matters most: a caller must not choose their own tenant."""

    def test_a_document_naming_another_tenant_is_ignored(self):
        body = json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "tenant_id": "00000000-0000-0000-0000-0000000000ff",
                "components": [_LOG4J],
            }
        ).encode()
        response = handle_sbom_import(_request(body=body))
        assert response.body["tenant_id"] == _TENANT
        assert "00000000-0000-0000-0000-0000000000ff" not in json.dumps(response.body)

    def test_a_missing_tenant_is_refused_rather_than_defaulted(self):
        response = handle_sbom_import(_request(tenant_id=""))
        assert response.status == 403
        assert response.body["error"]["code"] == "tenant_required"

    def test_a_none_tenant_is_refused(self):
        response = handle_sbom_import(_request(tenant_id=None))
        assert response.status == 403


class TestRejectionsAre4xxNotExceptions:
    @pytest.mark.parametrize(
        "body,code,status",
        [
            (b"", "empty_body", 400),
            (b"<<<not json>>>", "unreadable_sbom", 400),
            (b"[]", "unreadable_sbom", 400),
            (b'{"bomFormat":"SomethingElse"}', "unreadable_sbom", 400),
            (b'{"bomFormat":"CycloneDX","specVersion":"9.9","components":[]}',
             "unreadable_sbom", 400),
        ],
    )
    def test_bad_input_returns_a_4xx_with_a_code(self, body, code, status):
        response = handle_sbom_import(_request(body=body))
        assert response.status == status
        assert response.body["ok"] is False
        assert response.body["error"]["code"] == code
        assert response.body["result"] is None

    def test_an_oversized_document_is_413_before_parsing(self):
        body = b"x" * (MAX_DOCUMENT_BYTES + 1)
        response = handle_sbom_import(_request(body=body))
        assert response.status == 413
        assert response.body["error"]["code"] == "too_large"

    def test_a_non_bytes_body_is_refused(self):
        response = handle_sbom_import(_request(body="not bytes"))  # type: ignore[arg-type]
        assert response.status == 400
        assert response.body["error"]["code"] == "invalid_body"

    def test_an_unknown_origin_is_refused(self):
        response = handle_sbom_import(_request(origin="production"))
        assert response.status == 400
        assert response.body["error"]["code"] == "invalid_origin"

    def test_every_failure_has_the_same_shape(self):
        """A client must be able to rely on the keys existing on failure too."""
        for body in (b"", b"<<<", b"[]"):
            response = handle_sbom_import(_request(body=body))
            assert set(response.body) == {"ok", "tenant_id", "error", "result"}
            assert set(response.body["error"]) == {"code", "message"}

    def test_a_rejection_never_returns_a_partial_inventory(self):
        """A failed parse must not be reported as 'nothing is installed'."""
        response = handle_sbom_import(_request(body=b"<<<"))
        assert response.body["result"] is None


class TestTheFixtureGuard:
    def test_fixture_origin_is_accepted_because_tests_need_it(self):
        assert handle_sbom_import(_request(origin="fixture")).status == 200

    @pytest.mark.parametrize("origin", ALLOWED_ORIGINS)
    def test_every_allowed_origin_is_accepted(self, origin):
        assert handle_sbom_import(_request(origin=origin)).status == 200


class TestItDoesNotDoTheHostsWork:
    """The boundary, asserted rather than described.

    A handler that resolved tenants or wrote audit records would be a second entry
    point to data the host is supposed to protect. This checks it does neither.
    """

    def test_the_module_imports_no_database_or_session_machinery(self):
        import pathlib

        import vuln_intel.integration.sbom_handler as module

        source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
        for banned in ("sqlite3", "psycopg", "sqlalchemy", "Session", "INSERT",
                       "UPDATE", "DELETE"):
            assert banned not in source, f"sbom_handler.py references {banned}"

    def test_it_exposes_no_route_decorator(self):
        import pathlib

        import vuln_intel.integration.sbom_handler as module

        source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
        for banned in ("@app.", "@router.", "add_route", "mount("):
            assert banned not in source

    def test_the_declared_host_contract_names_every_host_owned_concern(self):
        for concern in ("authentication", "authorisation", "tenant_resolution",
                        "request_limit", "storage", "audit"):
            assert concern in MIN_SUPPORTED_HOST_CONTRACT


class TestTheDownstreamShape:
    def test_it_extracts_only_parsed_evidence(self):
        response = handle_sbom_import(_request())
        shaped = shape_for_downstream(response.body)
        assert shaped["tenant_id"] == _TENANT
        assert shaped["source_sha256"] == response.body["result"]["source_sha256"]
        assert shaped["components"] == 1
        assert shaped["complete"] is True

    def test_it_survives_a_failure_body(self):
        shaped = shape_for_downstream(handle_sbom_import(_request(body=b"")).body)
        assert shaped["source_sha256"] is None
        assert shaped["complete"] is False
        assert shaped["components"] == 0

    def test_it_drops_transport_fields(self):
        shaped = shape_for_downstream(handle_sbom_import(_request()).body)
        for absent in ("ok", "error", "result"):
            assert absent not in shaped
