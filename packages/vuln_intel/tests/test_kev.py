"""CISA KEV connector and cache: membership answers must never be accidental."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vuln_intel.errors import ValidationError
from vuln_intel.kev import (
    LAST_VERIFIED_LIVE,
    CachedKevCatalog,

    KevConnector,
)
from vuln_intel.ratelimit import RateGate
from vuln_intel.retry import RetryPolicy

from . import fixtures as fx
from .conftest import FakeTransport, no_wait, response


def kev(script=None) -> KevConnector:
    return KevConnector(
        transport=FakeTransport(script=list(script or [])),
        gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
        retry=RetryPolicy(attempts=1),
        sleep=no_wait,
    )


def test_live_flag_is_none() -> None:
    assert LAST_VERIFIED_LIVE is None


def test_fetch_indexes_the_catalogue() -> None:
    catalog = kev([response(fx.KEV_CATALOG)]).fetch()
    assert catalog.size == 2
    assert catalog.catalog_version == "2026.01.01"
    assert catalog.contains("CVE-2021-44228")
    entry = catalog.lookup("CVE-2021-44228")
    assert entry is not None
    assert entry.date_added is not None and entry.date_added.year == 2021
    assert entry.vendor == "Fixture Vendor"
    assert catalog.released_at is not None


def test_unknown_ransomware_use_is_not_false() -> None:
    catalog = kev([response(fx.KEV_CATALOG)]).fetch()
    entry = catalog.lookup("CVE-2026-0001")
    assert entry is not None
    assert entry.ransomware_use == "Unknown"
    assert entry.known_ransomware is None  # not coerced to False equivalent
    known = catalog.lookup("CVE-2021-44228")
    assert known is not None and known.known_ransomware is True


def test_no_transport_fails_instead_of_returning_an_empty_catalogue() -> None:
    """An empty catalogue would read as 'nothing is exploited' — forbidden."""
    with pytest.raises(Exception):
        KevConnector(transport=None).fetch()


def test_truncated_catalogue_is_rejected() -> None:
    truncated = dict(fx.KEV_CATALOG)
    truncated["count"] = 99  # declared rows do not match
    with pytest.raises(ValidationError):
        kev().parse(truncated)


def test_duplicate_entries_are_rejected() -> None:
    duplicated = dict(fx.KEV_CATALOG)
    duplicated["vulnerabilities"] = [
        fx.KEV_CATALOG["vulnerabilities"][0],
        fx.KEV_CATALOG["vulnerabilities"][0],
    ]
    duplicated["count"] = 2
    with pytest.raises(ValidationError):
        kev().parse(duplicated)


def test_malformed_cve_is_rejected() -> None:
    broken = dict(fx.KEV_CATALOG)
    broken["vulnerabilities"] = [
        {"cveID": "CVE-99-1", "vendorProject": "x", "product": "y", "vulnerabilityName": "z",
         "dateAdded": "2026-01-01", "shortDescription": "d", "requiredAction": "a", "dueDate": "2026-01-02",
         "knownRansomwareCampaignUse": "Unknown"}
    ]
    broken["count"] = 1
    with pytest.raises(ValidationError):
        kev().parse(broken)


def test_invalid_json_is_a_source_error() -> None:
    with pytest.raises(Exception):
        kev([response(b"<html>not json</html>")]).fetch()


def test_cache_reports_stale_and_preserves_last_good_snapshot() -> None:
    now = {"value": datetime(2026, 1, 10, tzinfo=timezone.utc)}
    connector = kev([response(fx.KEV_CATALOG)])
    cache = CachedKevCatalog(connector=connector, max_age=timedelta(days=2), clock=lambda: now["value"])

    catalog, age, stale = cache.get()
    assert catalog is None and age is None and stale is True

    catalog, used_stale, error = cache.refresh()
    assert catalog is not None and catalog.size == 2
    assert used_stale is False and error is None

    # Advance past the TTL: the snapshot is kept but flagged stale.
    now["value"] += timedelta(days=3)
    catalog, age, stale = cache.get()
    assert catalog is not None and catalog.size == 2
    assert stale is True and age is not None


def test_failed_refresh_keeps_previous_snapshot_and_reports_error() -> None:
    good = kev([response(fx.KEV_CATALOG)])
    cache = CachedKevCatalog(connector=good)
    cache.refresh()

    failing = KevConnector(
        transport=FakeTransport(script=[response({"oops": "gateway"}, status=503)]),
        gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=no_wait),
        retry=RetryPolicy(attempts=1),
        sleep=no_wait,
    )
    cache.connector = failing
    catalog, used_stale, error = cache.refresh()
    assert catalog is not None and catalog.size == 2  # knowledge survives the outage
    assert used_stale is True
    assert error and "503" in error
    assert cache.last_error == error
