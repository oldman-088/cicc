"""Assembly wiring for the vendor connectors (debian/ubuntu/ghsa) + GHSA token masking."""

from __future__ import annotations

from tests.conftest import FakeTransport, response
from vuln_intel.assembly import build_connectors
from vuln_intel.config import Settings


def _settings(**kw) -> Settings:
    return Settings(origin=__import__("vuln_intel.schema", fromlist=["Origin"]).Origin.FIXTURE, **kw)


class TestBundle:
    def test_offline_bundle_carries_all_connectors_without_transport(self):
        bundle = build_connectors(_settings())
        assert bundle.live is False
        assert bundle.debian is not None and bundle.debian.transport is None
        assert bundle.ubuntu is not None and bundle.ubuntu.transport is None
        assert bundle.ghsa is not None and bundle.ghsa.transport is None
        described = bundle.describe()
        assert described["debian_tracker"] is True
        assert described["ubuntu_usn"] is True
        assert described["ghsa"] is True
        assert described["ghsa_token"] == "absent"

    def test_live_bundle_installs_transport_per_connector(self):
        bundle = build_connectors(
            Settings(live_collection=True),  # origin defaults to LIVE
            transport_factory=lambda: FakeTransport(script=[response([])]),
        )
        assert bundle.live is True
        assert bundle.debian.transport is not None
        assert bundle.ubuntu.transport is not None
        assert bundle.ghsa.transport is not None
        # per-connector transports: not the same object
        assert bundle.debian.transport is not bundle.ubuntu.transport

    def test_live_without_transport_is_refused(self):
        import pytest

        from vuln_intel.errors import ValidationError

        with pytest.raises(ValidationError, match="no HTTP transport"):
            build_connectors(Settings(live_collection=True))


class TestGhsaToken:
    def test_token_masked_in_describe_and_repr(self):
        s = Settings(ghsa_token=__import__("vuln_intel.config", fromlist=["Secret"]).Secret("ghp_secret123"))
        d = s.describe()
        assert d["ghsa_token"] == "***" or "ghp_secret123" not in str(d)
        assert "ghp_secret123" not in repr(s)
        bundle = build_connectors(s, transport=FakeTransport(script=[response([])]))
        assert bundle.describe()["ghsa_token"] == "configured"
        assert "ghp_secret123" not in repr(bundle.describe())
