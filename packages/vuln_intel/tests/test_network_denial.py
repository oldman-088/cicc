"""Proves the network-denial guard is active (so the guard cannot silently rot)."""

from __future__ import annotations

import socket

import pytest


def test_socket_connect_is_blocked() -> None:
    with pytest.raises(RuntimeError, match="network access attempted"):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("1.1.1.1", 443))


def test_dns_resolution_is_blocked() -> None:
    with pytest.raises(RuntimeError, match="network access attempted"):
        socket.getaddrinfo("services.nvd.nist.gov", 443)


def test_create_connection_is_blocked() -> None:
    with pytest.raises(RuntimeError, match="network access attempted"):
        socket.create_connection(("1.1.1.1", 443), timeout=1)


def test_real_transport_cannot_be_used_in_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    """Even the audited transport must fail here — no test may reach a source."""
    from vuln_intel.transport import HttpxTransport

    httpx = pytest.importorskip("httpx", reason="httpx is an optional live extra")
    with pytest.raises(Exception):
        HttpxTransport().get("https://services.nvd.nist.gov/rest/json/cves/2.0")
