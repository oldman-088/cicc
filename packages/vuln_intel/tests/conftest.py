"""Test doubles and shared helpers.

``FakeTransport`` is the only way the test suite reaches a connector: there is no
network access, no retry sleeping and no clock dependence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Sequence

from vuln_intel.transport import TransportResponse

FIXED_NOW = datetime(2026, 1, 10, 12, 0, 0, tzinfo=timezone.utc)


def response(
    body: Any,
    *,
    status: int = 200,
    headers: Mapping[str, str] | None = None,
    url: str = "https://example.invalid/api",
) -> TransportResponse:
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    return TransportResponse(
        status=status, body=raw, headers=dict(headers or {}), url=url
    )


@dataclass
class FakeTransport:
    """Scripted transport.

    ``script`` is consumed in order; the last entry repeats once exhausted, so a
    paging test can keep returning a terminal page.  Every call is recorded in
    ``calls`` for assertions.
    """

    script: Sequence[Any] = field(default_factory=tuple)
    calls: list[dict[str, Any]] = field(default_factory=list)
    _index: int = 0

    def _next(self, url: str, params: Mapping[str, str] | None) -> TransportResponse:
        # One entry per call, carrying both the request (method/json/headers) and
        # the address it went to. This used to append here *and* in get/post, so
        # every call produced two entries and `calls[1]` was not the second call —
        # an easy trap for assertions. The *request* url is recorded, not the
        # response's, which is a placeholder in fixtures.
        if self.calls:
            self.calls[-1].setdefault("url", url)
            self.calls[-1].setdefault("params", dict(params or {}))
        if not self.script:
            raise AssertionError("FakeTransport has no scripted responses")
        entry = self.script[min(self._index, len(self.script) - 1)]
        self._index += 1
        if callable(entry):
            result = entry(url, params)
            if isinstance(result, BaseException):
                raise result
            return result
        return entry

    def get(
        self,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 30.0,
    ) -> TransportResponse:
        self.calls.append({"method": "GET", "headers": dict(headers or {})})
        return self._next(url, params)

    def post(
        self,
        url: str,
        *,
        json_body: object | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 30.0,
    ) -> TransportResponse:
        self.calls.append(
            {"method": "POST", "headers": dict(headers or {}), "json": json_body}
        )
        return self._next(url, None)


def no_wait(_: float) -> None:
    """Injectable sleep that never sleeps."""
    return


def zero_gate(*_args: Any, **_kwargs: Any):
    from vuln_intel.ratelimit import RateGate

    return RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait)


class ConstantClock:
    """Monotonic clock that only advances when told to."""

    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, delta: float) -> None:
        self.value += delta


def raises(exc_type: type[BaseException]) -> Callable[[str, Mapping[str, str] | None], BaseException]:
    def _raise(url: str, params: Mapping[str, str] | None) -> BaseException:
        return exc_type("scripted failure")

    return _raise


# ---------------------------------------------------------------------------
# Network denial
# ---------------------------------------------------------------------------
# A grep for "HttpxTransport()" was the original guard, and it was both fragile
# (it flagged a legitimate construction used to assert transport classification)
# and weak (it could not see a request made through another library). This
# fixture enforces the property that actually matters: no test may open a
# socket. Any accidental live call fails loudly instead of passing silently.
import socket as _socket

import pytest as _pytest


@_pytest.fixture(autouse=True)
def _deny_network(monkeypatch: _pytest.MonkeyPatch) -> None:
    def _blocked(*args: object, **kwargs: object):
        raise RuntimeError(
            "network access attempted during an offline test; "
            "inject a scripted transport instead of making a live request"
        )

    monkeypatch.setattr(_socket.socket, "connect", _blocked, raising=True)
    monkeypatch.setattr(_socket.socket, "connect_ex", _blocked, raising=True)
    monkeypatch.setattr(_socket, "create_connection", _blocked, raising=True)
    monkeypatch.setattr(_socket, "getaddrinfo", _blocked, raising=True)
