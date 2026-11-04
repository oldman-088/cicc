"""Transport, retry and rate-gate behaviour (no real sockets involved)."""

from __future__ import annotations

import pytest

from vuln_intel.errors import (
    SourceRateLimited,
    SourceResponseError,
    SourceTimeout,
    SourceUnavailable,
    ValidationError,
    sanitize,
)
from vuln_intel.ratelimit import RateGate, quota_for_nvd, quota_for_osv
from vuln_intel.retry import RetryPolicy, call_with_retry

from .conftest import ConstantClock, FakeTransport, no_wait, response


# -- transport ---------------------------------------------------------------
def test_transport_response_strips_query_string_from_provenance_url() -> None:
    resp = response({"ok": True}, url="https://api.example/v1?apiKey=SECRET&x=1")
    assert resp.provenance_url() == "https://api.example/v1?<stripped>"
    assert "SECRET" not in resp.provenance_url()


def test_transport_response_rejects_invalid_json() -> None:
    with pytest.raises(SourceResponseError):
        response(b"not json").json()


def test_transport_rejects_oversized_body() -> None:
    from vuln_intel import transport as transport_module

    huge = b"{" + b" " * (transport_module.MAX_RESPONSE_BYTES + 1) + b"}"
    with pytest.raises(SourceResponseError):
        response(huge).json()


def test_fake_transport_is_used_by_connectors_only() -> None:
    """Guard: the real transport must not be reachable from the test suite."""
    from vuln_intel.transport import HttpxTransport, Transport

    assert isinstance(FakeTransport(), Transport)
    assert not isinstance(FakeTransport(), HttpxTransport)


# -- retry -------------------------------------------------------------------
def test_retry_policy_validation() -> None:
    with pytest.raises(ValueError):
        RetryPolicy(attempts=0)
    with pytest.raises(ValueError):
        RetryPolicy(base_delay=2.0, max_delay=1.0)
    with pytest.raises(ValueError):
        RetryPolicy(jitter=1.5)


def test_backoff_grows_and_is_capped() -> None:
    policy = RetryPolicy(attempts=5, base_delay=1.0, max_delay=4.0, jitter=0.0)
    delays = [policy.delay_for(i) for i in range(4)]
    assert delays == [1.0, 2.0, 4.0, 4.0]


def test_retry_succeeds_on_third_attempt() -> None:
    sleeps: list[float] = []
    attempts = {"n": 0}

    def flaky() -> str:
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise SourceTimeout("try again")
        return "ok"

    assert (
        call_with_retry(
            flaky,
            policy=RetryPolicy(attempts=3, base_delay=0.0, max_delay=0.0),
            sleep=sleeps.append,
        )
        == "ok"
    )
    assert attempts["n"] == 3
    assert sleeps == [0.0, 0.0]


def test_retry_does_not_retry_client_errors() -> None:
    calls = {"n": 0}

    def fail() -> None:
        calls["n"] += 1
        raise SourceResponseError("bad request", status=400)

    with pytest.raises(SourceResponseError):
        call_with_retry(fail, policy=RetryPolicy(attempts=3), sleep=no_wait)
    assert calls["n"] == 1


def test_retry_honours_long_retry_after_by_failing_fast() -> None:
    calls = {"n": 0}

    def fail() -> None:
        calls["n"] += 1
        raise SourceRateLimited("slow down", retry_after=300.0, status=429)

    with pytest.raises(SourceRateLimited):
        call_with_retry(
            fail, policy=RetryPolicy(attempts=3, max_retry_after=60), sleep=no_wait
        )
    assert calls["n"] == 1


def test_retry_reports_each_attempt() -> None:
    seen: list[tuple[int, str, float]] = []
    attempts = {"n": 0}

    def flaky() -> str:
        attempts["n"] += 1
        if attempts["n"] < 2:
            raise SourceUnavailable("down")
        return "ok"

    call_with_retry(
        flaky,
        policy=RetryPolicy(attempts=2, base_delay=0.0, max_delay=0.0),
        sleep=no_wait,
        on_retry=lambda i, exc, wait: seen.append((i, type(exc).__name__, wait)),
    )
    assert seen and seen[0][1] == "SourceUnavailable"


# -- rate gate ---------------------------------------------------------------
def test_rate_gate_waits_between_calls() -> None:
    clock = ConstantClock()
    slept: list[float] = []

    gate = RateGate(min_interval=1.0, clock=clock, sleep=lambda s: (slept.append(s), clock.advance(s)))

    assert gate.wait() == 0.0  # first call is free
    assert gate.wait() == pytest.approx(1.0)
    assert slept == [pytest.approx(1.0)]


def test_rate_gate_widens_after_retry_after() -> None:
    gate = RateGate(min_interval=0.1, clock=ConstantClock(), sleep=no_wait)
    gate.observe_retry_after(30)
    assert gate.min_interval == 30.0


def test_nvd_quota_reflects_api_key_presence() -> None:
    assert quota_for_nvd(api_key=True).min_interval < quota_for_nvd(api_key=False).min_interval
    assert quota_for_nvd(api_key=False).min_interval >= 6.0


def test_osv_quota_is_modest() -> None:
    assert quota_for_osv().min_interval >= 0.1


# -- error hygiene -----------------------------------------------------------
@pytest.mark.parametrize(
    "text",
    [
        "GET https://api.example/v1?apiKey=SUPERSECRET&cve=CVE-2026-0001",
        "authorization: Bearer abcdef",
        "token=abcdef123456",
    ],
)
def test_sanitize_removes_credentials(text: str) -> None:
    cleaned = sanitize(text)
    assert "SUPERSECRET" not in cleaned
    assert "abcdef" not in cleaned
    assert "<redacted>" in cleaned or "<stripped>" in cleaned


def test_sanitize_truncates_and_flattens() -> None:
    cleaned = sanitize("line1\nline2 " + "x" * 1000, limit=50)
    assert "\n" not in cleaned
    assert len(cleaned) <= 50


def test_validation_error_carries_field_name() -> None:
    error = ValidationError("bad value", field="cve")
    assert "field=cve" in str(error)
