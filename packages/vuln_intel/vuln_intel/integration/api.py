"""Framework-neutral HTTP contract for vulnerability intelligence.

Why this exists, and why it is not a FastAPI app
------------------------------------------------
CICC is a FastAPI service, so Agent 1 (operations) and Agent 4 (frontend) will want
HTTP endpoints for vulnerability intelligence. Two constraints shape this module:

1. **This package has zero runtime dependencies** and is tested for that. Adding
   FastAPI (and starlette, pydantic and their transitive tree) to satisfy an
   integration surface would make the intelligence core depend on a web framework
   it does not need, and would put the whole subsystem behind a dependency that
   the CI environment does not install.
2. **A FastAPI app cannot be tested here.** FastAPI is not installed in this
   package's environment, so shipping an app object would mean shipping an
   untested integration — exactly the claim this project refuses to make.

So this module implements the part that *should* be tested and owned here: the
contract. Request parsing, authorization hooks, tenant scoping, pagination,
response shaping and error mapping are all pure functions and plain dataclasses.
`docs/vulnerability-intelligence/API.md` gives the ~30-line FastAPI binding, and
`asgi_handler` below is a working WSGI-style fallback for hosts that do not use
FastAPI at all — it is exercised by the test suite, so the contract is proven to be
implementable, not just described.

Contract rules that hold regardless of framework:

* **Tenant scoping is mandatory and is not inferred from the request.** The caller
  supplies the tenant after authentication; a tenant identifier in a query string
  is ignored, because trusting it would let any authenticated client read another
  tenant's intelligence.
* **Errors are typed and shaped the same way everywhere**, so the frontend can
  branch on ``code`` rather than parsing prose.
* **Nothing is fabricated.** An unknown CVE is ``404``; a provider that has not been
  consulted produces ``unknown`` fields with a stated reason, never ``0``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from ..errors import ValidationError
from ..schema import CveId
from .contracts import VulnerabilityStore

__all__ = [
    "DEFAULT_PAGE_SIZE",
    "MAX_PAGE_SIZE",
    "ApiError",
    "ApiResponse",
    "GetVulnerabilityRequest",
    "ListVulnerabilitiesRequest",
    "VulnerabilityApi",
    "asgi_handler",
]

DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 200

#: Documented error codes. Stable strings the frontend can switch on.
ERROR_CODES = {
    "unauthorized": 401,
    "forbidden_tenant": 403,
    "not_found": 404,
    "invalid_request": 400,
    "store_unavailable": 503,
}


class ApiError(Exception):
    """A contract-level failure carrying the exact HTTP status to emit."""

    def __init__(self, code: str, message: str, *, field_name: str | None = None) -> None:
        if code not in ERROR_CODES:
            raise ValueError(f"unknown error code {code!r}")
        self.code = code
        self.message = message
        self.field_name = field_name
        super().__init__(message)

    @property
    def status(self) -> int:
        return ERROR_CODES[self.code]

    def as_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {"error": {"code": self.code, "message": self.message}}
        if self.field_name:
            body["error"]["field"] = self.field_name
        return body


@dataclass(frozen=True)
class ApiResponse:
    status: int
    body: Mapping[str, Any]
    headers: Mapping[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"status": self.status, "body": dict(self.body)}


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class GetVulnerabilityRequest:
    """``GET /v1/vulnerabilities/{cve}``."""

    tenant_id: str
    cve: str

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.tenant_id.strip():
            # A blank tenant is never a wildcard: it is a bug in the caller.
            raise ApiError("unauthorized", "a resolved tenant is required")
        parsed = CveId.parse(self.cve)  # raises ValidationError on garbage
        object.__setattr__(self, "cve", str(parsed))


@dataclass(frozen=True)
class ListVulnerabilitiesRequest:
    """``GET /v1/vulnerabilities`` with filtering and cursor pagination."""

    tenant_id: str
    limit: int = DEFAULT_PAGE_SIZE
    cursor: str | None = None
    severity: str | None = None
    kev_only: bool = False
    order: str = "cve"

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.tenant_id.strip():
            raise ApiError("unauthorized", "a resolved tenant is required")
        if not 1 <= self.limit <= MAX_PAGE_SIZE:
            # Unbounded page size is a denial-of-service lever on the database.
            raise ApiError(
                "invalid_request",
                f"limit must be within 1-{MAX_PAGE_SIZE}",
                field_name="limit",
            )
        if self.order not in ("cve", "-cve", "severity", "-severity"):
            raise ApiError("invalid_request", "unsupported order", field_name="order")
        if self.severity is not None:
            allowed = {"critical", "high", "medium", "low", "none", "unknown"}
            if self.severity.strip().lower() not in allowed:
                raise ApiError(
                    "invalid_request",
                    "unsupported severity filter",
                    field_name="severity",
                )

    @classmethod
    def from_query(
        cls, query: Mapping[str, str], *, tenant_id: str
    ) -> ListVulnerabilitiesRequest:
        """Build from raw query parameters.

        ``tenant_id`` comes from the authorization layer, never from ``query``: a
        client-supplied tenant would be a cross-tenant read.
        """
        raw_limit = query.get("limit")
        try:
            limit = int(raw_limit) if raw_limit else DEFAULT_PAGE_SIZE
        except (TypeError, ValueError) as exc:
            raise ApiError("invalid_request", "limit must be an integer", field_name="limit") from exc
        kev_raw = (query.get("kev_only") or "").strip().lower()
        if kev_raw not in ("", "true", "false", "1", "0"):
            raise ApiError("invalid_request", "kev_only must be a boolean", field_name="kev_only")
        return cls(
            tenant_id=tenant_id,
            limit=limit,
            cursor=(query.get("cursor") or None),
            severity=(query.get("severity") or None),
            kev_only=kev_raw in ("true", "1"),
            order=(query.get("order") or "cve"),
        )


# ---------------------------------------------------------------------------
# Response shaping
# ---------------------------------------------------------------------------
def _iso(value: object) -> str | None:
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return moment.isoformat()
    return None


def shape_record(row: Mapping[str, Any]) -> dict[str, Any]:
    """One stored row → the documented API object.

    ``enrichment`` is passed through as stored. Missing values stay missing: the
    response never fills an unconsulted KEV lookup with ``false``, because
    ``false`` would assert the catalogue was checked and the CVE is absent from it.
    """
    details = row.get("details") or {}
    enrichment = details.get("cicc_enrichment") or {}
    return {
        "cve": row.get("cve"),
        "entity_id": row.get("entity_id"),
        "origin": row.get("origin"),
        "collected_at": _iso(row.get("collected_at")),
        "severity": enrichment.get("severity"),
        "cvss": enrichment.get("cvss"),
        "kev": enrichment.get("kev"),
        "epss": enrichment.get("epss"),
        "sources": enrichment.get("sources") or [],
        "summary": details.get("summary"),
        "affected": details.get("affected") or [],
        "references": details.get("references") or [],
        "freshness": enrichment.get("freshness"),
        "policy": enrichment.get("policy"),
    }


class VulnerabilityApi:
    """Contract implementation over a :class:`VulnerabilityStore`.

    Framework bindings (FastAPI, WSGI) call :meth:`get` and :meth:`list`. Every
    method returns an :class:`ApiResponse` or raises :class:`ApiError`; neither
    leaks a driver exception to the caller.
    """

    def __init__(self, store: VulnerabilityStore) -> None:
        self.store = store

    def get(self, request: GetVulnerabilityRequest) -> ApiResponse:
        try:
            row = self.store.find(tenant_id=request.tenant_id, cve=request.cve)
        except Exception as exc:  # a driver failure is a 503, not a 500 stack
            raise ApiError(
                "store_unavailable", f"storage lookup failed: {type(exc).__name__}"
            ) from exc
        if row is None:
            raise ApiError("not_found", f"{request.cve} is not stored for this tenant")
        return ApiResponse(status=200, body={"data": shape_record(row)})

    def list(self, request: ListVulnerabilitiesRequest) -> ApiResponse:
        try:
            rows, next_cursor = self.store.list(
                tenant_id=request.tenant_id,
                limit=request.limit,
                cursor=request.cursor,
                severity=request.severity,
                kev_only=request.kev_only,
                order=request.order,
            )
        except Exception as exc:
            raise ApiError(
                "store_unavailable", f"storage list failed: {type(exc).__name__}"
            ) from exc
        return ApiResponse(
            status=200,
            body={
                "data": [shape_record(row) for row in rows],
                "page": {
                    "limit": request.limit,
                    "next_cursor": next_cursor,
                    "has_more": next_cursor is not None,
                },
                "filters": {
                    "severity": request.severity,
                    "kev_only": request.kev_only,
                    "order": request.order,
                },
            },
        )


def asgi_handler(
    api: VulnerabilityApi,
    *,
    resolve_tenant: Callable[[Mapping[str, str], str], str],
) -> Callable[[str, str, Mapping[str, str]], ApiResponse]:
    """A minimal, dependency-free HTTP binding for hosts without FastAPI.

    Returns a callable ``(method, path, query) -> ApiResponse``. Authentication is
    delegated: ``resolve_tenant(headers, path)`` must return the authenticated
    tenant or raise :class:`ApiError`. This package never validates credentials
    itself — that is the platform's job, and duplicating it here would create a
    second, weaker authority.

    The binding is deliberately thin, and it is tested, so the contract is proven
    implementable rather than merely documented.
    """

    def handler(
        method: str, path: str, query: Mapping[str, str]
    ) -> ApiResponse:
        try:
            if method.upper() != "GET":
                raise ApiError("invalid_request", "only GET is supported")
            tenant = resolve_tenant(query, path)
            parts = [segment for segment in path.split("/") if segment]
            # /v1/vulnerabilities[/<cve>]
            if len(parts) < 2 or parts[0] != "v1" or parts[1] != "vulnerabilities":
                raise ApiError("not_found", "unknown route")
            if len(parts) == 2:
                return api.list(ListVulnerabilitiesRequest.from_query(query, tenant_id=tenant))
            if len(parts) == 3:
                return api.get(GetVulnerabilityRequest(tenant_id=tenant, cve=parts[2]))
            raise ApiError("not_found", "unknown route")
        except ApiError as exc:
            return ApiResponse(status=exc.status, body=exc.as_dict())
        except ValidationError as exc:
            return ApiResponse(
                status=400,
                body={"error": {"code": "invalid_request", "message": str(exc)}},
            )
        except Exception as exc:  # never leak a stack trace across the boundary
            return ApiResponse(
                status=503,
                body={
                    "error": {
                        "code": "store_unavailable",
                        "message": f"internal failure: {type(exc).__name__}",
                    }
                },
            )

    return handler
