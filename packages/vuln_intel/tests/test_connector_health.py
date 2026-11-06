"""Health projection for whole-document vendor connectors."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from vuln_intel.health import ComponentHealth, connector_health
from vuln_intel.schema import SourceKind

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)


class TestConnectorHealth:
    def test_never_attempted_is_not_configured(self):
        h = connector_health(SourceKind.DEBIAN_TRACKER, last_attempt=None,
                             last_success=None, now=NOW)
        assert h.health is ComponentHealth.NOT_CONFIGURED

    def test_attempt_and_success_together_is_ok(self):
        h = connector_health(SourceKind.GHSA, last_attempt=NOW, last_success=NOW, now=NOW)
        assert h.health is ComponentHealth.OK

    def test_failed_after_good_data_is_degraded_not_unavailable(self):
        h = connector_health(
            SourceKind.UBUNTU_USN,
            last_attempt=NOW, last_success=NOW - timedelta(days=3),
            error="500", now=NOW,
        )
        assert h.health is ComponentHealth.DEGRADED
        assert "serving previously collected data" in h.detail

    def test_failed_with_no_prior_success_is_unavailable(self):
        h = connector_health(SourceKind.DEBIAN_TRACKER, last_attempt=NOW,
                             last_success=None, error="500", now=NOW)
        assert h.health is ComponentHealth.UNAVAILABLE

    def test_stale_success_is_degraded(self):
        h = connector_health(SourceKind.GHSA, last_attempt=NOW - timedelta(days=10),
                             last_success=NOW - timedelta(days=10), now=NOW,
                             fresh_within=timedelta(days=2))
        assert h.health is ComponentHealth.DEGRADED
        assert "stale" in h.detail
