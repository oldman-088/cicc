"""``Retry-After`` parsing must never crash and never silently drop a value.

The original implementation used ``str.isdigit()``, which discarded fractional
values such as ``Retry-After: 1.5`` and negative or malformed headers without any
signal. All three connectors now share a defensive parser; this locks it down.
"""

from __future__ import annotations

import pytest

from vuln_intel import kev as kev_module
from vuln_intel.connectors import nvd as nvd_module
from vuln_intel.connectors import osv as osv_module
from vuln_intel.connectors.nvd import NvdConnector
from vuln_intel.connectors.osv import OsvConnector
from vuln_intel.errors import SourceRateLimited
from vuln_intel.kev import KevConnector
from vuln_intel.ratelimit import RateGate
from vuln_intel.retry import RetryPolicy

from .conftest import FakeTransport, no_wait, response

PARSERS = [
    pytest.param(nvd_module.NvdConnector._retry_after, id="nvd"),
    pytest.param(osv_module._retry_after, id="osv"),
    pytest.param(kev_module._retry_after, id="kev"),
]


@pytest.mark.parametrize("parse", PARSERS)
@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ({"retry-after": "30"}, 30.0),
        ({"retry-after": "1.5"}, 1.5),      # was silently dropped before
        ({"retry-after": "0"}, None),       # zero is not a meaningful pause
        ({"retry-after": "-5"}, None),
        ({"retry-after": "soon"}, None),
        ({"retry-after": ""}, None),
        ({}, None),
    ],
)
def test_retry_after_parsing(parse, header: dict, expected: float | None) -> None:
    assert parse(header) == expected


def test_rate_limited_nvd_reports_the_percentage_value() -> None:
    nvd = NvdConnector(
        transport=FakeTransport(
            script=[response({"m": "quota"}, status=429, headers={"retry-after": "1.5"})]
        ),
        gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
        retry=RetryPolicy(attempts=1),
        sleep=no_wait,
    )
    with pytest.raises(SourceRateLimited) as excinfo:
        nvd.get_cve("CVE-2026-0001")
    assert excinfo.value.retry_after == pytest.approx(1.5)


def test_osv_and_kev_also_surface_retry_after() -> None:
    osv = OsvConnector(
        transport=FakeTransport(
            script=[response({"m": "quota"}, status=429, headers={"retry-after": "2.5"})]
        ),
        gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
        retry=RetryPolicy(attempts=1),
        sleep=no_wait,
    )
    with pytest.raises(SourceRateLimited) as osv_exc:
        osv.get_vulnerability("GHSA-0000-aaaa-bbbb")
    assert osv_exc.value.retry_after == pytest.approx(2.5)

    kev = KevConnector(
        transport=FakeTransport(
            script=[response({"m": "quota"}, status=429, headers={"retry-after": "3.5"})]
        ),
        gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
        retry=RetryPolicy(attempts=1),
        sleep=no_wait,
    )
    with pytest.raises(SourceRateLimited) as kev_exc:
        kev.fetch()
    assert kev_exc.value.retry_after == pytest.approx(3.5)
