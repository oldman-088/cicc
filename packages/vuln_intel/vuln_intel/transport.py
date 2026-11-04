"""HTTP transport abstraction.

The connectors never import a networking library directly.  They accept a
:class:`Transport` so that:

* tests can inject recorded fixtures with zero network access;
* production code can supply a shared, rate-limited client;
* a missing client produces :class:`SourceUnavailable` instead of a fake
  success (rule: never claim a live connection without evidence).

:class:`HttpxTransport` is the only implementation that touches the network and
is exercised **nowhere** in the test suite.
"""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass, field
from typing import Mapping, Protocol, runtime_checkable

from .errors import (
    SourceResponseError,
    SourceTimeout,
    SourceUnavailable,
    sanitize,
)

__all__ = [
    "MAX_RESPONSE_BYTES",
    "Transport",
    "TransportResponse",
    "HttpxTransport",
]

#: Hard ceiling on a decoded source response, enforced regardless of the
#: upstream ``Content-Length`` header.
MAX_RESPONSE_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class TransportResponse:
    """A received response. ``body`` is raw bytes, never pre-parsed."""

    status: int
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)
    #: URL actually requested, recorded for provenance. Query strings are
    #: stripped before being persisted (see :meth:`provenance_url`).
    url: str = ""

    def provenance_url(self) -> str:
        """URL with the query string removed, so API keys never reach storage."""
        cut = self.url.find("?")
        return self.url if cut == -1 else self.url[:cut] + "?<stripped>"

    def json(self) -> object:
        """Parse the body as JSON, mapping failures onto the error taxonomy."""
        if len(self.body) > MAX_RESPONSE_BYTES:
            raise SourceResponseError("response exceeds size limit", status=self.status)
        try:
            return json.loads(self.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SourceResponseError(
                f"invalid JSON body: {exc}", status=self.status
            ) from exc


@runtime_checkable
class Transport(Protocol):
    """Minimal GET contract. Implementations must not follow redirects."""

    def get(
        self,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 30.0,
    ) -> TransportResponse:  # pragma: no cover - protocol definition
        ...


class HttpxTransport:
    """Real network transport.

    Deliberately thin: status mapping, byte ceiling and redirect refusal.
    Retry/backoff and rate limiting belong to the connector so that each source
    can honour its own policy.
    """

    def __init__(self, *, max_bytes: int = MAX_RESPONSE_BYTES) -> None:
        self.max_bytes = max_bytes

    def get(
        self,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 30.0,
    ) -> TransportResponse:
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - dependency present in prod
            raise SourceUnavailable(
                "httpx is not installed; live collection disabled"
            ) from exc

        try:
            with httpx.stream(
                "GET",
                url,
                params=dict(params or {}),
                headers=dict(headers or {}),
                timeout=timeout,
                follow_redirects=False,
            ) as response:
                declared = response.headers.get("content-length", "")
                if declared.isdigit() and int(declared) > self.max_bytes:
                    raise SourceResponseError(
                        "declared response size exceeds limit",
                        status=response.status_code,
                    )
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_bytes(chunk_size=65536):
                    size += len(chunk)
                    if size > self.max_bytes:
                        raise SourceResponseError(
                            "response exceeds size limit",
                            status=response.status_code,
                        )
                    chunks.append(chunk)
                return TransportResponse(
                    status=response.status_code,
                    body=b"".join(chunks),
                    headers={k.lower(): v for k, v in response.headers.items()},
                    url=str(response.request.url),
                )
        except (SourceResponseError, SourceUnavailable):
            raise
        except TimeoutError as exc:
            raise SourceTimeout(sanitize(exc) or "timeout") from exc
        except (socket.timeout, OSError) as exc:
            raise SourceUnavailable(sanitize(exc) or "connection failed") from exc
        except Exception as exc:  # httpx raises its own hierarchy
            name = type(exc).__name__
            if "Timeout" in name:
                raise SourceTimeout(f"{name}: {sanitize(exc)}") from exc
            raise SourceUnavailable(f"{name}: {sanitize(exc)}") from exc
