"""Assemble connectors from validated configuration.

The gap this closes: :mod:`vuln_intel.config` parsed and validated environment
variables, and nothing read them. An operator could set
``CICC_VULN_NVD_MAX_PAGES=50``, see it reflected in a startup log, and get
behaviour governed entirely by defaults baked into the connector. Silent
divergence between documented configuration and actual behaviour is worse than no
configuration, because it makes every operational runbook wrong in a way that only
shows up under load.

Design constraints:

* **No I/O.** Building a connector must never contact a provider. Everything here
  is construction; the first request happens when the caller issues one.
* **Explicit opt-in.** A live transport is only installed when
  ``settings.live_collection`` is true. Turning on a key alone changes nothing.
* **No credential leakage.** ``Settings.nvd_api_key`` is a :class:`Secret`; the
  connectors take a plain ``str``. The unwrap happens here, in one place, and the
  result is never placed in a log line, a repr, or an exception message.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Sequence

from .config import ENV_PREFIX, Secret, Settings
from .connectors.epss import UnavailableEpssProvider
from .connectors.nvd import NvdConnector
from .connectors.osv import OsvConnector
from .errors import SourceError, SourceNotFound, SourceResponseError, ValidationError
from .kev import CachedKevCatalog, KevConnector
from .schema import CollectionStatus, NormalizedVulnerability, Origin
from .sync import SyncWindow, WindowFetcher
from .transport import Transport

#: Marker kept on every bundle so health/summary output can state, truthfully,
#: whether anything here is able to make a real request.
LIVE_TRANSPORT_INSTALLED = False


@dataclass
class ConnectorBundle:
    """The connectors described by one :class:`Settings`, ready but inert."""

    nvd: NvdConnector
    osv: OsvConnector
    kev: KevConnector
    epss: UnavailableEpssProvider
    kev_cache: CachedKevCatalog
    #: True only when a live transport was actually supplied.
    live: bool = False
    #: Human-readable notes about the assembly, safe to log.
    notes: tuple[str, ...] = ()

    def describe(self) -> dict[str, object]:
        """JSON-safe summary. Contains no credential material."""
        return {
            "live": self.live,
            "origin": self.nvd.origin.value,
            "nvd_page_size": self.nvd.page_size,
            "nvd_max_pages": self.nvd.max_pages,
            "nvd_api_key": "configured" if self.nvd.api_key else "absent",
            "http_timeout": self.nvd.timeout,
            "kev_max_age_days": self.kev_cache.max_age.days,
            "epss": "unavailable",
            "notes": list(self.notes),
        }


def build_connectors(
    settings: Settings,
    *,
    transport: Transport | None = None,
    transport_factory: Callable[[], Transport] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> ConnectorBundle:
    """Build the connector set described by ``settings``.

    ``transport`` / ``transport_factory`` are injected for tests and for hosts that
    own their own HTTP stack; a factory is preferred so each connector gets its
    own transport (connection pools and breakers are per-connector state, and
    sharing them couples one provider's failures to another's).

    Raises :class:`ValidationError` when live collection is requested without a
    transport. That combination previously produced a connector whose every call
    returned ``NOT_CONFIGURED`` — the collection run looked successful and
    collected nothing, which is the failure mode this package is most careful to
    avoid elsewhere.
    """
    notes: list[str] = []
    live = False

    if settings.live_collection:
        settings.require_live()
        if transport is None and transport_factory is None:
            raise ValidationError(
                "live collection is enabled but no HTTP transport was supplied; "
                "refusing to build connectors that would report NOT_CONFIGURED "
                "for every call",
                field="LIVE_COLLECTION",
            )
        live = True
        notes.append("live transport installed: collection will make real requests")
    else:
        if transport is not None or transport_factory is not None:
            notes.append(
                "live collection is disabled; the supplied transport is ignored "
                "so that no request can be made"
            )
            transport = None
            transport_factory = None
        notes.append("no transport installed: connectors cannot make requests")

    if settings.origin is not Origin.LIVE and settings.origin is not Origin.FIXTURE:
        notes.append(f"origin={settings.origin.value}: data must never be served as live")

    def _one(provider: str) -> Transport | None:
        """One transport per connector, and never a silent ``None`` when live.

        A factory is allowed to fail (its exception propagates — the caller needs
        to see it) but it is not allowed to return ``None``: that produced a
        bundle flagged ``live=True`` whose every call returned ``NOT_CONFIGURED``,
        which is the exact "run succeeds, collects nothing" failure this module
        exists to prevent.
        """
        if transport_factory is not None:
            built = transport_factory()
            if built is None:
                raise ValidationError(
                    f"transport_factory returned None for {provider} while live "
                    "collection is enabled",
                    field="LIVE_COLLECTION",
                )
            return built
        return transport

    api_key = _unwrap_key(settings.nvd_api_key)
    if settings.live_collection and api_key is None:
        notes.append(
            "no NVD API key configured: NVD's lower unauthenticated rate limit applies"
        )

    nvd = NvdConnector(
        transport=_one("nvd"),
        api_key=api_key,
        timeout=settings.http_timeout,
        page_size=settings.nvd_page_size,
        max_pages=settings.nvd_max_pages,
        sleep=sleep,
        origin=settings.origin,
    )
    osv = OsvConnector(
        transport=_one("osv"),
        timeout=settings.http_timeout,
        sleep=sleep,
        origin=settings.origin,
    )
    kev = KevConnector(
        transport=_one("kev"),
        timeout=max(settings.http_timeout, 30.0),
        sleep=sleep,
        origin=settings.origin.value,
    )

    if settings.epss_enabled:
        # Deliberately still unavailable: no live EPSS client exists, and returning
        # zeros would be a false claim that exploitation is unlikely.
        notes.append(
            "EPSS is enabled in configuration but no live client exists; provider "
            "remains unavailable rather than reporting zero"
        )

    return ConnectorBundle(
        nvd=nvd,
        osv=osv,
        kev=kev,
        epss=UnavailableEpssProvider(),
        kev_cache=CachedKevCatalog(connector=kev, max_age=settings.kev_max_age),
        live=live,
        notes=tuple(notes),
    )


def _unwrap_key(secret: Secret) -> str | None:
    """Return the raw API key for the connector, or ``None``.

    The only place in the package where the secret stops being masked. Kept
    deliberately tiny and never logged: the connectors accept a plain ``str``
    because they predate :class:`Secret`, and changing their signature would break
    callers outside this package.
    """
    if not secret:
        return None
    key = secret.reveal()
    if len(key) < 8:
        raise ValidationError(
            f"{ENV_PREFIX}NVD_API_KEY is too short to be a valid key", field="NVD_API_KEY"
        )
    return key


def startup_report(settings: Settings) -> dict[str, object]:
    """Everything an operator needs at startup, with no credential material.

    Intended for a health endpoint or a startup log line. Combines the masked
    settings view with configuration warnings so a misconfiguration is visible
    before the first collection run rather than after it.
    """
    described = settings.describe()
    described["warnings"] = list(settings.warnings())
    described["live_transport_available"] = LIVE_TRANSPORT_INSTALLED
    return described


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------
def nvd_collector(
    connector: NvdConnector,
    *,
    cve_ids: Sequence[str] | None = None,
) -> Callable[[], Sequence[NormalizedVulnerability]]:
    """A pipeline collector over NVD.

    With ``cve_ids`` it fetches exactly those; without, it walks NVD's window up
    to the configured page budget.

    A failed collection **raises** instead of returning an empty list. The
    pipeline distinguishes the two: an exception becomes ``FAILED`` with the
    provider's error, while an empty list is recorded as "an empty answer, not a
    failure". Returning ``[]`` from a 403 would therefore turn an outage into a
    statement that NVD has nothing to report — the precise confusion this package
    refuses elsewhere.
    """

    def collect() -> Sequence[NormalizedVulnerability]:
        if cve_ids is None:
            result = connector.search_all()
            if not result.ok and not result.records:
                raise SourceResponseError(
                    result.state.error or "NVD collection failed without an error message",
                    source="nvd",
                )
            return result.records

        records: list[NormalizedVulnerability] = []
        misses: list[str] = []
        for raw in cve_ids:
            try:
                records.append(connector.get_cve(raw))
            except SourceNotFound:
                # Not an error: the CVE is simply unknown to NVD. Recorded so the
                # absence is visible rather than silently equal to "no data".
                misses.append(str(raw))
            except SourceError:
                raise
        if not records and misses:
            raise SourceNotFound(
                "none of the requested CVEs are known to NVD: " + ", ".join(misses[:5]),
                source="nvd",
            )
        return records

    return collect


def osv_collector(
    connector: OsvConnector,
    osv_ids: Sequence[str],
) -> Callable[[], Sequence[NormalizedVulnerability]]:
    """A pipeline collector over a fixed set of OSV ids.

    Advisory-only records (no CVE alias) are excluded here, not dropped silently:
    they are the caller's *advisory* stream and are surfaced by
    :meth:`OsvConnector.collect` on the result object.
    """

    def collect() -> Sequence[NormalizedVulnerability]:
        result = connector.collect(osv_ids)
        if not result.records and result.state.status is CollectionStatus.FAILED:
            raise SourceResponseError(
                result.state.error or "OSV collection failed without an error message",
                source="osv",
            )
        return result.records

    return collect


def nvd_window_fetcher(connector: NvdConnector) -> WindowFetcher:
    """Adapt :meth:`NvdConnector.search` to :class:`sync.WindowFetcher`.

    This is what makes real incremental coverage possible: ``search_all()`` is a
    bounded window of the *current* catalogue, whereas a fetcher driven by
    :class:`sync.IncrementalSync` walks ``lastModStartDate``/``lastModEndDate``
    windows from a persisted watermark, so repeated runs converge on a complete
    local view instead of re-reading the same first N pages.

    The translation matters: ``search`` returns a ``CollectionResult`` that reports
    failure *in the result* rather than raising, while the fetcher contract
    returns ``(records, exhausted, error)``. A failed page must surface as
    ``error`` — returning ``([], False, None)`` for a 403 would look like an empty
    window and let the checkpoint advance over data that was never read.
    """

    def fetch(
        window: SyncWindow, *, start_index: int, page_size: int
    ) -> tuple[Sequence[NormalizedVulnerability], bool, str | None]:
        result = connector.search(
            start_index=start_index,
            results_per_page=page_size,
            modified_window=window.params(),
        )
        if not result.ok:
            state = result.state
            return (), False, state.error or "NVD window page failed without an error message"
        # A short page means the window is exhausted. NVD's totalResults is the
        # authority, but a short page is the condition the sync engine can act on
        # without trusting a counter that changed between requests.
        exhausted = len(result.records) < page_size
        return result.records, exhausted, None

    return fetch
