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
