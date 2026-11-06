"""The SBOM import handler the host would mount — validation only, no route.

**This is not an endpoint.** Nothing here is served. It exists so the contract can be
tested and reviewed *before* a route is published, which is the only order in which
publishing a parser behind an HTTP boundary is safe.

What it does
------------
Turns raw request bytes into a response body, applying every check a route must apply
that can be applied without a database or a principal:

1. size, before parsing (``MAX_DOCUMENT_BYTES``);
2. format detection and parsing, with the parser's own limits;
3. tenant scoping, **required as an argument and never read from the document**;
4. origin enforcement, so a fixture SBOM cannot masquerade as live;
5. a deterministic response body of a fixed shape.

What the host must do, and this module deliberately does not
-----------------------------------------------------------
Authentication, authorisation, tenant *resolution* (deciding which tenant the caller
belongs to), rate limiting, storage of the raw bytes, and the audit record. Those are
all host concerns; a handler that did them would be a second, unauthorised entry point
to data the host is supposed to protect.

The tenant is an argument, not a field
--------------------------------------
``tenant_id`` is passed *in*, never extracted from the document. If it were read from
the body, a caller could upload an SBOM naming someone else's tenant and the import
would be attributed to them. A test asserts the document cannot influence it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from ..sbom import MAX_DOCUMENT_BYTES, SbomError, SbomIngestResult, inventory_from_sbom

__all__ = [
    "MIN_SUPPORTED_HOST_CONTRACT",
    "SbomImportRequest",
    "SbomImportResponse",
    "handle_sbom_import",
]

#: Origins a route may accept, mapped to the response's own vocabulary. ``fixture`` and
#: ``demo`` are for tests and previews; a route that accepts them in production would
#: let synthetic data into a real tenant's inventory.
ALLOWED_ORIGINS = ("live", "fixture", "demo")

#: The minimum the host must provide for this handler to be mountable. Stated as data
#: so a reviewer can diff it against the host's actual behaviour, and so a test can
#: assert this module does not quietly start doing any of it itself.
MIN_SUPPORTED_HOST_CONTRACT = {
    "authentication": "host-owned; this handler receives an authenticated request only",
    "authorisation": "host-owned; the caller must hold a permission to import SBOMs",
    "tenant_resolution": "host-owned; the tenant is an argument to this handler",
    "request_limit": f"{MAX_DOCUMENT_BYTES} bytes, enforced here before parsing",
    "storage": "host-owned; this handler never persists a document",
    "audit": "host-owned; the host records the import against the principal",
}


@dataclass(frozen=True)
class SbomImportRequest:
    """What the host hands to the handler once it has done its own work."""

    #: Raw request body. Parsed here so the digest covers exactly these bytes.
    body: bytes
    #: Resolved by the host from the authenticated principal. Never from the body.
    tenant_id: str
    #: Actor for the audit record. The handler does not write audit; it echoes the id.
    actor_id: str | None = None
    #: Optional asset label the caller associates with the document.
    asset: str | None = None
    #: Declared origin. The host decides what it will accept, typically by deployment.
    origin: str = "live"


@dataclass(frozen=True)
class SbomImportResponse:
    """A fixed-shape body. Callers get the same keys whether or not parsing succeeded."""

    status: int
    body: dict[str, Any]

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def as_dict(self) -> dict[str, Any]:
        return dict(self.body)


def _error(status: int, code: str, message: str, *, tenant_id: str | None = None) -> SbomImportResponse:
    return SbomImportResponse(
        status=status,
        body={
            "ok": False,
            "tenant_id": tenant_id,
            "error": {"code": code, "message": message},
            # Present and null on every failure, so a client can rely on the shape.
            "result": None,
        },
    )


def _result_body(tenant_id: str, actor_id: str | None, result: SbomIngestResult) -> dict[str, Any]:
    """The response body's contract, independent of the parser's internals.

    A host route must not expose ``inventory.as_dict()`` wholesale: that shape is a
    persistence detail and it changes when the inventory model does. This is the part
    a client and the frontend can rely on.
    """
    return {
        "ok": True,
        "tenant_id": tenant_id,
        "actor_id": actor_id,
        "error": None,
        "result": {
            "format": result.format,
            "spec_version": result.spec_version,
            "document_name": result.document_name,
            # Ties the result to one exact artefact. Adopted from the sibling parser
            # comparison; without it two documents are indistinguishable in a report.
            "source_sha256": result.source_sha256,
            "components": result.component_count,
            "relationships": len(result.relationships),
            "duplicates": result.duplicates,
            # A caller must be able to tell a complete inventory from a partial one.
            "complete": result.complete,
            "skipped": [dict(entry) for entry in result.skipped],
            "licenses": {name: list(ids) for name, ids in sorted(result.licenses.items())},
            "warnings": list(result.warnings),
        },
    }


def handle_sbom_import(request: SbomImportRequest) -> SbomImportResponse:
    """Validate and parse one SBOM. Returns a status and a body; never raises.

    Returning rather than raising is deliberate: a route must translate every parse
    failure into a 4xx, and an exception escaping here would become a 500 for what is
    a bad request. The one thing this function will not do is report success for a
    document it could not read.
    """
    if not request.tenant_id or not isinstance(request.tenant_id, str):
        # The host should never call without a tenant. Refusing here means a wiring
        # mistake cannot become a write against no tenant.
        return _error(403, "tenant_required", "a resolved tenant_id is required")

    if request.origin not in ALLOWED_ORIGINS:
        return _error(
            400,
            "invalid_origin",
            f"origin must be one of {', '.join(ALLOWED_ORIGINS)}",
            tenant_id=request.tenant_id,
        )

    if not isinstance(request.body, (bytes, bytearray)):
        return _error(
            400, "invalid_body", "the request body must be bytes", tenant_id=request.tenant_id
        )
    if not request.body:
        return _error(400, "empty_body", "the request body is empty", tenant_id=request.tenant_id)
    # Checked before parsing: the parser's own limit protects the process, this protects
    # the caller from a document that will be rejected anyway.
    if len(request.body) > MAX_DOCUMENT_BYTES:
        return _error(
            413,
            "too_large",
            f"the document exceeds the {MAX_DOCUMENT_BYTES} byte limit",
            tenant_id=request.tenant_id,
        )

    try:
        result = inventory_from_sbom(io_bytes(request.body), asset=request.asset)
    except SbomError as exc:
        return _error(
            400, "unreadable_sbom", str(exc), tenant_id=request.tenant_id
        )

    return SbomImportResponse(
        status=200,
        body=_result_body(request.tenant_id, request.actor_id, result),
    )


def io_bytes(body: bytes | bytearray) -> bytes:
    """Normalise a bytearray to bytes so the digest covers a defined sequence."""
    return bytes(body) if isinstance(body, bytearray) else body


def shape_for_downstream(body: Mapping[str, Any]) -> dict[str, Any]:
    """What the VI quality path needs from a response, without the transport fields.

    Kept separate so downstream code depends on the parsed evidence, not on an HTTP
    envelope it has to unwrap — and so a conflict or quality finding is attributed to
    a tenant and an artefact rather than to a request.
    """
    result = body.get("result") or {}
    return {
        "tenant_id": body.get("tenant_id"),
        "actor_id": body.get("actor_id"),
        "source_sha256": result.get("source_sha256"),
        "format": result.get("format"),
        "complete": result.get("complete", False),
        "components": result.get("components", 0),
        "skipped": list(result.get("skipped") or ()),
    }
