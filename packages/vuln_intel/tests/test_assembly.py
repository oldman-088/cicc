"""Connector assembly from configuration.

The behaviour under test is not "does a dataclass hold a value" — it is that
configuration genuinely reaches the connector that acts on it, and that the
failure modes stay loud. Configuration that parses cleanly and changes nothing is
the defect this module exists to prevent, so most of these tests assert against a
connector attribute rather than against the settings object.
"""

from __future__ import annotations

import pytest

from vuln_intel.assembly import build_connectors, startup_report
from vuln_intel.config import Settings
from vuln_intel.errors import SourceResponseError, ValidationError
from vuln_intel.schema import Origin

from .conftest import FakeTransport, response

SECRET = "abcdef0123456789-nvd-key"


def settings(**env) -> Settings:
    base = {"CICC_VULN_ORIGIN": "live"}
    base.update(env)
    return Settings.from_env(base)


class TestConfigurationReachesConnectors:
    def test_nvd_page_size_is_wired(self):
        bundle = build_connectors(settings(CICC_VULN_NVD_PAGE_SIZE="500"))
        assert bundle.nvd.page_size == 500

    def test_nvd_max_pages_is_wired(self):
        bundle = build_connectors(settings(CICC_VULN_NVD_MAX_PAGES="50"))
        assert bundle.nvd.max_pages == 50

    def test_timeout_is_wired(self):
        bundle = build_connectors(settings(CICC_VULN_HTTP_TIMEOUT="12.5"))
        assert bundle.nvd.timeout == 12.5
        assert bundle.osv.timeout == 12.5

    def test_kev_max_age_is_wired(self):
        bundle = build_connectors(settings(CICC_VULN_KEV_MAX_AGE_DAYS="7"))
        assert bundle.kev_cache.max_age.days == 7

    def test_api_key_reaches_the_connector(self):
        bundle = build_connectors(settings(CICC_VULN_NVD_API_KEY=SECRET))
        assert bundle.nvd.api_key == SECRET

    def test_absent_key_stays_absent(self):
        bundle = build_connectors(settings())
        assert bundle.nvd.api_key is None


class TestNoCredentialLeakage:
    """A key that reaches a log line, a repr or an error message is a finding."""

    def test_describe_does_not_contain_the_key(self):
        bundle = build_connectors(settings(CICC_VULN_NVD_API_KEY=SECRET))
        assert SECRET not in repr(bundle.describe())

    def test_startup_report_does_not_contain_the_key(self):
        report = startup_report(settings(CICC_VULN_NVD_API_KEY=SECRET))
        assert SECRET not in repr(report)

    def test_nvd_connector_repr_does_not_contain_the_key(self):
        """The connector takes a plain str, so this asserts the dataclass field is
        declared repr=False rather than trusting it."""
        bundle = build_connectors(settings(CICC_VULN_NVD_API_KEY=SECRET))
        assert SECRET not in repr(bundle.nvd)

    def test_settings_repr_does_not_contain_the_key(self):
        assert SECRET not in repr(settings(CICC_VULN_NVD_API_KEY=SECRET))

    def test_short_key_is_rejected_rather_than_used(self):
        with pytest.raises(ValidationError):
            build_connectors(settings(CICC_VULN_NVD_API_KEY="abc"))


class TestLiveOptIn:
    def test_live_disabled_installs_no_transport(self):
        bundle = build_connectors(settings(), transport=FakeTransport(script=[]))
        assert bundle.live is False
        assert bundle.nvd.transport is None

    def test_live_disabled_ignores_a_supplied_factory(self):
        called = []

        def factory():
            called.append(1)
            return FakeTransport(script=[])

        bundle = build_connectors(settings(), transport_factory=factory)
        assert bundle.live is False
        assert called == []  # never even constructed

    def test_live_enabled_without_transport_is_an_error(self):
        """Otherwise every call returns NOT_CONFIGURED and the run "succeeds"
        while collecting nothing."""
        with pytest.raises(ValidationError):
            build_connectors(settings(CICC_VULN_LIVE_COLLECTION="true"))

    def test_live_enabled_with_transport_is_live(self):
        bundle = build_connectors(
            settings(CICC_VULN_LIVE_COLLECTION="true"),
            transport_factory=lambda: FakeTransport(script=[response({})]),
        )
        assert bundle.live is True
        assert bundle.nvd.transport is not None

    def test_factory_gives_each_connector_its_own_transport(self):
        """Sharing one transport would couple providers' breaker/pool state."""
        bundle = build_connectors(
            settings(CICC_VULN_LIVE_COLLECTION="true"),
            transport_factory=lambda: FakeTransport(script=[response({})]),
        )
        assert bundle.nvd.transport is not bundle.osv.transport
        assert bundle.nvd.transport is not bundle.kev.transport

    def test_live_collection_cannot_be_combined_with_fixture_origin(self):
        with pytest.raises(ValidationError):
            build_connectors(
                settings(
                    CICC_VULN_LIVE_COLLECTION="true", CICC_VULN_ORIGIN="fixture"
                ),
                transport_factory=lambda: FakeTransport(script=[]),
            )


class TestDeclaredBehaviourMatchesObservation:
    def test_notes_state_that_no_request_can_be_made(self):
        bundle = build_connectors(settings())
        assert any("cannot make requests" in note for note in bundle.notes)

    def test_epss_stays_unavailable_even_when_enabled(self):
        """Configuration must not conjure a provider that does not exist."""
        bundle = build_connectors(settings(CICC_VULN_EPSS_ENABLED="true"))
        assert any("unavailable" in note for note in bundle.notes)
        # Must raise, not return 0.0: a zero EPSS score is a *claim* that
        # exploitation is unlikely, and this provider has no evidence at all.
        with pytest.raises(SourceResponseError):
            bundle.epss.fetch([])

    def test_bundle_reports_origin_truthfully(self):
        bundle = build_connectors(settings(CICC_VULN_ORIGIN="fixture"))
        assert bundle.nvd.origin is Origin.FIXTURE
        assert bundle.describe()["origin"] == "fixture"


class TestStartupReport:
    def test_includes_configuration_warnings(self):
        report = startup_report(settings())
        assert any("live collection is disabled" in w for w in report["warnings"])

    def test_declares_live_transport_unavailable(self):
        report = startup_report(settings())
        assert report["live_transport_available"] is False

    def test_reports_unknown_variables(self):
        report = startup_report(settings(CICC_VULN_TYPO_HERE="1"))
        assert "CICC_VULN_TYPO_HERE" in report["unknown_variables"]


class TestAssemblyFailureModes:
    """Failure cases, not just the happy path."""

    def test_factory_returning_none_is_rejected(self):
        """A `live=True` bundle with no transport collects nothing silently."""
        with pytest.raises(ValidationError):
            build_connectors(
                settings(CICC_VULN_LIVE_COLLECTION="true"),
                transport_factory=lambda: None,
            )

    def test_factory_exception_propagates_to_the_caller(self):
        def boom():
            raise RuntimeError("transport construction failed")

        with pytest.raises(RuntimeError):
            build_connectors(
                settings(CICC_VULN_LIVE_COLLECTION="true"), transport_factory=boom
            )

    def test_live_bundle_always_has_transports(self):
        bundle = build_connectors(
            settings(CICC_VULN_LIVE_COLLECTION="true"),
            transport_factory=lambda: FakeTransport(script=[response({})]),
        )
        assert bundle.live is True
        for connector in (bundle.nvd, bundle.osv, bundle.kev):
            assert connector.transport is not None

    def test_non_live_bundle_never_has_transports(self):
        bundle = build_connectors(
            settings(), transport=FakeTransport(script=[response({})])
        )
        for connector in (bundle.nvd, bundle.osv, bundle.kev):
            assert connector.transport is None


class TestCollectors:
    """Collectors must keep "failed" and "empty" distinct.

    The pipeline maps an exception to FAILED-with-error and an empty list to
    "an empty answer, not a failure". A collector that swallows a provider error
    and returns [] therefore converts an outage into a claim that the provider has
    nothing to report.
    """

    def _nvd(self, script):
        from vuln_intel.connectors.nvd import NvdConnector
        from vuln_intel.ratelimit import RateGate
        from vuln_intel.retry import RetryPolicy

        return NvdConnector(
            transport=FakeTransport(script=list(script)),
            gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=lambda _s: None),
            retry=RetryPolicy(attempts=1),
            sleep=lambda _s: None,
            origin=Origin.FIXTURE,
        )

    def test_provider_failure_raises_instead_of_looking_empty(self):
        from vuln_intel.assembly import nvd_collector
        from vuln_intel.errors import SourceError

        connector = self._nvd([response({"message": "forbidden"}, status=403)])
        collector = nvd_collector(connector)
        with pytest.raises(SourceError):
            collector()

    def test_unknown_cve_is_a_miss_not_a_crash(self):
        from vuln_intel.assembly import nvd_collector
        from vuln_intel.errors import SourceNotFound

        empty = {"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "vulnerabilities": []}
        connector = self._nvd([response(empty)])
        collector = nvd_collector(connector, cve_ids=["CVE-2026-9999"])
        # Every requested CVE is unknown: reported as not-found, not as [].
        with pytest.raises(SourceNotFound):
            collector()

    def test_osv_failure_raises(self):
        from vuln_intel.assembly import osv_collector
        from vuln_intel.connectors.osv import OsvConnector
        from vuln_intel.errors import SourceError
        from vuln_intel.ratelimit import RateGate
        from vuln_intel.retry import RetryPolicy

        connector = OsvConnector(
            transport=FakeTransport(script=[response({"message": "nope"}, status=500)]),
            gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=lambda _s: None),
            retry=RetryPolicy(attempts=1),
            sleep=lambda _s: None,
            origin=Origin.FIXTURE,
        )
        with pytest.raises(SourceError):
            osv_collector(connector, ["GHSA-0000-aaaa-bbbb"])()

    def test_osv_success_returns_records(self):
        from tests import fixtures as fx
        from vuln_intel.assembly import osv_collector
        from vuln_intel.connectors.osv import OsvConnector
        from vuln_intel.ratelimit import RateGate
        from vuln_intel.retry import RetryPolicy

        connector = OsvConnector(
            transport=FakeTransport(script=[response(fx.OSV_CVE)]),
            gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=lambda _s: None),
            retry=RetryPolicy(attempts=1),
            sleep=lambda _s: None,
            origin=Origin.FIXTURE,
        )
        records = osv_collector(connector, ["GHSA-0000-aaaa-bbbb"])()
        assert len(records) == 1
        assert str(records[0].cve) == "CVE-2026-0001"

    def test_collector_feeds_the_pipeline(self):
        """End to end: an assembled collector drives a real pipeline run."""
        from tests import fixtures as fx
        from vuln_intel.assembly import osv_collector
        from vuln_intel.connectors.osv import OsvConnector
        from vuln_intel.pipeline import EnrichmentPipeline
        from vuln_intel.ratelimit import RateGate
        from vuln_intel.retry import RetryPolicy

        connector = OsvConnector(
            transport=FakeTransport(script=[response(fx.OSV_CVE)]),
            gate=RateGate(min_interval=0.0, clock=lambda: 0.0, sleep=lambda _s: None),
            retry=RetryPolicy(attempts=1),
            sleep=lambda _s: None,
            origin=Origin.FIXTURE,
        )
        report = EnrichmentPipeline().run(
            {"osv": osv_collector(connector, ["GHSA-0000-aaaa-bbbb"])}
        )
        assert report.outcomes[0].status.value in ("ok", "partial")
        assert report.outcomes[0].records == 1
