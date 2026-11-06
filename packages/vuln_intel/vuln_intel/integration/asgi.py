"""A real ASGI application, so a host can mount this instead of transcribing it.

What was wrong before
---------------------
The module docstring said ``asgi_handler`` was an "ASGI fallback". It is not ASGI. It is
``(method, path, query) -> ApiResponse`` — a pure function, useful for testing the
contract, useless to Starlette or FastAPI, which need ``async def app(scope, receive,
send)``. ``docs/API.md`` in turn told hosts to write a "~30-line FastAPI binding" by
hand.

That combination is the worst of both: the package claimed the binding existed, and every
host would have written its own slightly different copy of the one piece that decides
tenant scoping and error mapping. The contract was tested; the mount was not.

This module is the mount. It is dependency-free ASGI 3, so it works under uvicorn,
hypercorn, Starlette, FastAPI's ``mount``, or a test harness, with no framework installed.

What is deliberately *not* re-implemented
-----------------------------------------
Authentication. ``resolve_tenant(scope)`` is injected and must return the authenticated
tenant or raise :class:`ApiError`. A second, weaker authorization implementation living
here would be a security defect dressed as convenience — the platform already has one,
and two authorities is how the weaker one wins.

Everything else is here and tested: routing, method restriction, query parsing, tenant
scoping, pagination, response shaping, error mapping, and the guarantee that no driver
exception crosses the boundary as a stack trace.

Why the tenant cannot come from the request
-------------------------------------------
The scope's headers and query string are attacker-controlled. ``resolve_tenant`` is given
the scope so it can read a verified token, and its return value is the *only* tenant used.
A ``tenant_id`` query parameter is ignored — see the test that a client-supplied tenant
changes nothing.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Mapping, MutableMapping

from ..errors import ValidationError
from .api import ApiError, ApiResponse, ListVulnerabilitiesRequest, VulnerabilityApi

__all__ = ["TenantResolver", "VulnerabilityAsgiApp", "build_app"]

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Send = Callable[[Message], Awaitable[None]]
Receive = Callable[[], Awaitable[Message]]

#: Returns the authenticated tenant for a request, or raises :class:`ApiError`.
#: It receives the raw ASGI scope so it can inspect headers; it must not trust the
#: query string.
TenantResolver = Callable[[Scope], str]

_METHODS = ("GET", "HEAD")

#: Rows fetched per store call while assembling an export. Small enough to bound memory
#: on a wide tenant, large enough that 500 records is two round trips, not fifty.
_EXPORT_PAGE_SIZE = 200

#: Hard ceiling. Beyond this the request is refused with an explicit message: a
#: truncated export would be indistinguishable from a complete one at the consumer.
_EXPORT_MAX_RECORDS = 5000

_STATUS_TEXT = {
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    404: "Not Found",
    405: "Method Not Allowed",
    503: "Service Unavailable",
}


def _header(scope: Scope, name: str) -> str | None:
    wanted = name.lower().encode("latin-1")
    for key, value in scope.get("headers") or []:
        if key.lower() == wanted:
            return value.decode("latin-1")
    return None


def _query_pairs(scope: Scope) -> list[tuple[str, str]]:
    """Parse the query string, keeping duplicates rather than last-wins.

    ``?limit=1&limit=100`` is ambiguous. Last-wins silently resolves it in the
    attacker's favour when the guard reads the first and the client relies on the
    second. Rejecting duplicates is the only answer that cannot be wrong.
    """
    from urllib.parse import parse_qsl

    raw = (scope.get("query_string") or b"").decode("latin-1")
    return parse_qsl(raw, keep_blank_values=True)


class VulnerabilityAsgiApp:
    """ASGI 3 callable serving ``/v1/vulnerabilities`` over a store."""

    def __init__(
        self,
        api: VulnerabilityApi,
        *,
        resolve_tenant: TenantResolver,
        require_https: bool = False,
    ) -> None:
        self.api = api
        self.resolve_tenant = resolve_tenant
        self.require_https = require_https

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope.get("type") != "http":
            # A WebSocket or unknown scope is not ours; refuse rather than half-serve.
            await self._send_json(send, 404, _error("not_found", "unsupported scope type"))
            return

        response = self.handle(scope)
        await self._send_json(send, response.status, response.body, method=scope.get("method"))

    async def _lifespan(self, receive: Receive, send: Send) -> None:
        """Accept and ignore lifespan events.

        Uvicorn refuses to start an app that raises on ``lifespan.startup``, and a host
        that mounts this may not want to special-case it. No resources are opened here
        because the store opens a connection per operation.
        """
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return

    # -- interop exports -----------------------------------------------------
    def _export(self, fmt: str, *, tenant: str, query: Mapping[str, str]) -> ApiResponse:
        """Serve CycloneDX VEX, OpenVEX or SARIF for this tenant.

        Inventory is optional and is passed as JSON in ``?dependencies=``. Omitting it is
        *not* the same as passing an empty list: no inventory means exposure was never
        evaluated, and the document reports every CVE as unassessed rather than implying
        a clean estate. The response carries that distinction in ``meta``.
        """
        from .exports import ExportUnavailable, export_openvex, export_sarif, export_vex

        builders = {
            "vex": export_vex,
            "openvex": export_openvex,
        }
        if fmt != "sarif" and fmt not in builders:
            raise ApiError(
                "not_found",
                f"unknown export format {fmt!r}; expected one of vex, openvex, sarif",
            )

        raw_dependencies = query.get("dependencies")
        dependencies: list[Mapping[str, Any]] | None = None
        if raw_dependencies is not None:
            try:
                parsed = json.loads(raw_dependencies)
            except json.JSONDecodeError as exc:
                raise ApiError(
                    "invalid_request",
                    "dependencies must be a JSON array of {ecosystem, name, version}",
                    field_name="dependencies",
                ) from exc
            if not isinstance(parsed, list):
                raise ApiError(
                    "invalid_request",
                    "dependencies must be a JSON array",
                    field_name="dependencies",
                )
            dependencies = parsed

        # A VEX document that silently omits records is worse than no document: a
        # consumer reads it as "these are all the vulnerabilities", so a truncated one
        # quietly deletes work from someone's queue. Page to the end instead of taking
        # a single capped page and dropping the cursor.
        rows: list[Mapping[str, Any]] = []
        cursor: str | None = None
        try:
            while True:
                page, cursor = self.api.store.list(
                    tenant_id=tenant, limit=_EXPORT_PAGE_SIZE, cursor=cursor
                )
                rows.extend(page)
                # Checked before the break: a tenant small enough to arrive in one page
                # still has to be under the ceiling, or the guard only ever fires for
                # the case it is least likely to meet.
                if len(rows) > _EXPORT_MAX_RECORDS:
                    # Refuse rather than serve a partial document we cannot mark.
                    raise ApiError(
                        "invalid_request",
                        f"tenant has more than {_EXPORT_MAX_RECORDS} records; "
                        "export a narrower set rather than receive a truncated VEX",
                        field_name="dependencies",
                    )
                if cursor is None or not page:
                    break
        except ApiError:
            raise
        except Exception as exc:
            raise ApiError(
                "store_unavailable", f"storage list failed: {type(exc).__name__}"
            ) from exc

        moment = datetime.now(tz=timezone.utc)
        try:
            if fmt == "sarif":
                export = export_sarif(rows, now=moment, dependencies=dependencies)
                document = export.document
                unassessed: tuple[str, ...] = ()
            else:
                export, _detail = builders[fmt](rows, now=moment, dependencies=dependencies)
                document, unassessed = export.document, export.unassessed
        except ExportUnavailable as exc:
            # A stored row we cannot faithfully rebuild is a 409, not a 500: the request
            # is well formed and the data is the problem, so a client should not retry.
            return ApiResponse(
                status=409,
                body=_error("stored_record_invalid", str(exc)),
            )

        return ApiResponse(
            status=200,
            body={
                "document": document,
                "meta": {
                    "format": fmt,
                    "generated_at": moment.isoformat(),
                    "record_count": export.record_count,
                    "exposure_evaluated": dependencies is not None,
                    "unassessed": list(unassessed),
                    "empty": export.empty,
                },
            },
        )

    # -- synchronous core, so it is testable without an event loop -----------
    def handle(self, scope: Scope) -> ApiResponse:
        """Resolve a request to a response. No I/O, no awaits, no framework."""
        try:
            if self.require_https:
                proto = (
                    _header(scope, "x-forwarded-proto")
                    or scope.get("scheme")
                    or "http"
                )
                if str(proto).lower() != "https":
                    raise ApiError("unauthorized", "HTTPS is required")

            method = str(scope.get("method") or "GET").upper()
            if method not in _METHODS:
                raise ApiError("method_not_allowed", f"method {method} is not allowed")

            path = str(scope.get("path") or "/")
            parts = [segment for segment in path.split("/") if segment]

            # Mounting may prefix the path (/api/vuln-intel/v1/...). Find the route
            # rather than assume the app is mounted at the root, because a host that
            # mounts it under a prefix would otherwise get a 404 for every request.
            try:
                version_index = parts.index("v1")
            except ValueError as exc:
                raise ApiError("not_found", "unknown route") from exc
            route = parts[version_index:]
            if len(route) < 2 or route[1] != "vulnerabilities":
                raise ApiError("not_found", "unknown route")

            pairs = _query_pairs(scope)
            keys = [key for key, _ in pairs]
            duplicates = sorted({key for key in keys if keys.count(key) > 1})
            if duplicates:
                raise ApiError(
                    "invalid_request",
                    f"duplicate query parameter(s): {', '.join(duplicates)}",
                )
            query: Mapping[str, str] = dict(pairs)

            tenant = self.resolve_tenant(scope)
            if not tenant or not str(tenant).strip():
                raise ApiError("unauthorized", "a resolved tenant is required")

            if len(route) == 2:
                return self.api.list(
                    ListVulnerabilitiesRequest.from_query(query, tenant_id=tenant)
                )
            if len(route) == 3:
                from .api import GetVulnerabilityRequest

                return self.api.get(GetVulnerabilityRequest(tenant_id=tenant, cve=route[2]))
            # /v1/vulnerabilities/export/<format> — the interop adapters, served.
            if len(route) == 4 and route[2] == "export":
                return self._export(route[3], tenant=tenant, query=query)
            raise ApiError("not_found", "unknown route")

        except ApiError as exc:
            return ApiResponse(status=exc.status, body=exc.as_dict())
        except ValidationError as exc:
            return ApiResponse(
                status=400,
                body=_error("invalid_request", str(exc)),
            )
        except Exception as exc:  # never leak a stack trace across the boundary
            return ApiResponse(
                status=503,
                body=_error("store_unavailable", f"internal failure: {type(exc).__name__}"),
            )

    async def _send_json(
        self,
        send: Send,
        status: int,
        body: Mapping[str, Any],
        *,
        method: str | None = None,
    ) -> None:
        payload = json.dumps(body, default=str, separators=(",", ":")).encode("utf-8")
        headers = [
            (b"content-type", b"application/json; charset=utf-8"),
            (b"content-length", str(len(payload)).encode("ascii")),
            # A VEX verdict is not cacheable by an intermediary and must not be
            # sniffed into another type.
            (b"cache-control", b"no-store"),
            (b"x-content-type-options", b"nosniff"),
        ]
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": headers,
                "reason": _STATUS_TEXT.get(status, ""),
            }
        )
        # HEAD must carry the headers and no body, per RFC 9110.
        if method and method.upper() == "HEAD":
            await send({"type": "http.response.body", "body": b""})
            return
        await send({"type": "http.response.body", "body": payload})


def _error(code: str, message: str) -> dict[str, Any]:
    return {"error": {"code": code, "message": message}}


def build_app(
    store: Any,
    *,
    resolve_tenant: TenantResolver,
    require_https: bool = False,
) -> VulnerabilityAsgiApp:
    """Convenience constructor: a store becomes a mountable ASGI app."""
    return VulnerabilityAsgiApp(
        VulnerabilityApi(store),
        resolve_tenant=resolve_tenant,
        require_https=require_https,
    )
