"""Security regressions: secrets must not leak, origins must not be overstated.

Each test here corresponds to a defect that existed in an earlier commit of this
package. They are kept as permanent guards, not as documentation of intent.
"""

from __future__ import annotations

import io
import logging
import pathlib
import re
import traceback

import pytest

from vuln_intel.connectors.nvd import NvdConnector
from vuln_intel.connectors.osv import OsvConnector
from vuln_intel.errors import SourceRateLimited, SourceResponseError, sanitize
from vuln_intel.ratelimit import RateGate
from vuln_intel.retry import RetryPolicy
from vuln_intel.transport import TransportKind, transport_kind

from . import fixtures as fx
from .conftest import FakeTransport, no_wait, response

SECRET = "NVD-KEY-DO-NOT-LEAK-9f3a7c"
PACKAGE_DIR = pathlib.Path(__file__).resolve().parents[1] / "vuln_intel"


def connector(**kwargs) -> NvdConnector:
    return NvdConnector(
        transport=FakeTransport([response(fx.NVD_SINGLE)]),
        api_key=SECRET,
        gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
        retry=RetryPolicy(attempts=1),
        sleep=no_wait,
        **kwargs,
    )


# -- defect 1: the API key appeared in the dataclass repr ---------------------
def test_api_key_is_absent_from_repr() -> None:
    assert SECRET not in repr(connector())


def test_api_key_is_absent_from_str_and_vars_style_dump() -> None:
    nvd = connector()
    assert SECRET not in str(nvd)
    assert SECRET not in f"{nvd!r}"
    assert SECRET not in f"{nvd}"


def test_api_key_is_absent_from_tracebacks() -> None:
    nvd = connector()
    buffer = io.StringIO()
    try:
        raise RuntimeError(f"op failed while inspecting {nvd!r}")
    except RuntimeError:
        traceback.print_exc(file=buffer)
    assert SECRET not in buffer.getvalue()


def test_api_key_is_absent_from_logs(caplog: pytest.LogCaptureFixture) -> None:
    nvd = connector()
    with caplog.at_level(logging.DEBUG):
        logging.getLogger("vuln_intel").debug("connector=%r", nvd)
        logging.getLogger("vuln_intel").info("connector=%s", nvd)
    assert SECRET not in caplog.text


def test_api_key_still_reaches_the_header(caplog: pytest.LogCaptureFixture) -> None:
    """The fix must not break the actual authentication path."""
    transport = FakeTransport(script=[response(fx.NVD_SINGLE)])
    nvd = NvdConnector(
        transport=transport,
        api_key=SECRET,
        gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
        retry=RetryPolicy(attempts=1),
        sleep=no_wait,
    )
    nvd.get_cve("CVE-2026-0001")
    header_calls = [c for c in transport.calls if "headers" in c]
    assert any(c["headers"].get("apiKey") == SECRET for c in header_calls)
    # ...and it never appears in a URL or query string.
    assert all(SECRET not in c["url"] for c in transport.calls if "url" in c)


def test_provenance_url_never_contains_the_key() -> None:
    """Even if a caller builds a URL with a query, stored provenance is stripped."""
    leaked = response(
        {"ok": True}, url=f"https://services.nvd.nist.gov/rest/json/cves/2.0?apiKey={SECRET}"
    )
    assert SECRET not in leaked.provenance_url()
    assert leaked.provenance_url().endswith("?<stripped>")


def test_rate_limit_errors_do_not_carry_the_key() -> None:
    with pytest.raises(SourceRateLimited) as excinfo:
        connector_with_exhaustion = NvdConnector(
            transport=FakeTransport(
                script=[response({"message": "quota"}, status=429, headers={"retry-after": "999"})]
            ),
            api_key=SECRET,
            gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
            retry=RetryPolicy(attempts=2, base_delay=0.0, max_delay=0.0, max_retry_after=10),
            sleep=no_wait,
        )
        connector_with_exhaustion.get_cve("CVE-2026-0001")
    assert SECRET not in str(excinfo.value)


# -- defect 2: any transport was reported as "live" in provenance -------------
def test_injected_transport_is_recorded_as_unaudited() -> None:
    record = connector().get_cve("CVE-2026-0001")
    assert record.provenance[0].transport == TransportKind.UNAUDITED


def test_osv_injected_transport_is_recorded_as_unaudited() -> None:
    osv = OsvConnector(
        transport=FakeTransport([response(fx.OSV_CVE)]),
        gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
        retry=RetryPolicy(attempts=1),
        sleep=no_wait,
    )
    record, _ = osv.get_vulnerability("GHSA-0000-aaaa-bbbb")
    assert record is not None
    assert record.provenance[0].transport == TransportKind.UNAUDITED


def test_missing_transport_is_recorded_as_none() -> None:
    assert transport_kind(None) == TransportKind.NONE


def test_only_the_package_transport_earns_audited_live() -> None:
    from vuln_intel.transport import HttpxTransport

    assert transport_kind(HttpxTransport()) == TransportKind.AUDITED_LIVE
    assert transport_kind(FakeTransport()) == TransportKind.UNAUDITED
    # A structural look-alike must not be trusted either.
    class LookAlike:
        def get(self, *args, **kwargs):
            return response({"ok": True})

    assert transport_kind(LookAlike()) == TransportKind.UNAUDITED


# -- static secret scanning ---------------------------------------------------
_SECRET_PATTERNS = (
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),          # Google
    re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"),      # GitHub
    re.compile(r"sk-[A-Za-z0-9]{20,}"),             # generic LLM keys
    re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),  # long UUID-ish
)


def test_no_credential_shaped_literals_in_the_package() -> None:
    """Fixture identifiers are CVE/GHSA shaped; anything else is suspicious."""
    offenders: list[str] = []
    for path in PACKAGE_DIR.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for pattern in _SECRET_PATTERNS:
            for match in pattern.finditer(text):
                # 40-hex git blob ids legitimately appear in provenance fixtures.
                if re.fullmatch(r"[0-9a-f]{40}", match.group(0)):
                    continue
                offenders.append(f"{path.name}: {match.group(0)[:12]}…")
    assert offenders == []


def test_sanitize_is_applied_to_every_error_message() -> None:
    """Errors are constructed through the taxonomy, which sanitizes by default."""
    error = SourceResponseError(f"failed https://api.example/v1?apiKey={SECRET}&x=1")
    assert SECRET not in str(error)
    assert sanitize(error) == sanitize(str(error))


class TestAssembledConnectorSecrets:
    """The assembly layer is the one place the key stops being masked.

    A key that reaches a URL, a query parameter, an exception message or a repr is
    a credential disclosure: URLs and params land in provider logs, and exception
    text lands in ours.
    """

    KEY = "SUPERSECRET-NVD-KEY-0123456789"

    def _bundle(self, script):
        from tests.conftest import FakeTransport
        from vuln_intel.assembly import build_connectors
        from vuln_intel.config import Settings

        transport = FakeTransport(script=script)
        settings = Settings.from_env(
            {
                "CICC_VULN_LIVE_COLLECTION": "true",
                "CICC_VULN_NVD_API_KEY": self.KEY,
                "CICC_VULN_NVD_MAX_PAGES": "1",
            },
            strict=True,
        )
        return build_connectors(settings, transport_factory=lambda: transport), transport

    def test_key_travels_in_a_header_only(self):
        from tests.conftest import response

        empty = {
            "resultsPerPage": 0,
            "startIndex": 0,
            "totalResults": 0,
            "vulnerabilities": [],
        }
        bundle, transport = self._bundle([response(empty)])
        from vuln_intel.assembly import nvd_collector

        nvd_collector(bundle.nvd)()
        assert transport.calls, "expected at least one request"
        for call in transport.calls:
            assert self.KEY not in call.get("url", "")
            assert "apiKey" not in repr(call.get("params") or {})
        assert any(
            call.get("headers", {}).get("apiKey") == self.KEY for call in transport.calls
        )

    def test_provider_error_text_does_not_echo_the_key(self):
        from tests.conftest import response

        bundle, _transport = self._bundle(
            [response({"message": f"forbidden {self.KEY}"}, status=403)]
        )
        from vuln_intel.assembly import nvd_collector

        try:
            nvd_collector(bundle.nvd)()
        except Exception as exc:  # the collector must raise on a failed page
            assert self.KEY not in str(exc)
        else:  # pragma: no cover - the raise above is the expected path
            raise AssertionError("a 403 must not be reported as an empty result")

    def test_bundle_description_does_not_contain_the_key(self):
        bundle, _transport = self._bundle([])
        assert self.KEY not in repr(bundle.describe())
        assert self.KEY not in repr(bundle)
