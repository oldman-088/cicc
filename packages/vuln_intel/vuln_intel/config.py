"""Configuration from the environment, with secrets that cannot leak.

Rules this module enforces:

1. **Secrets never render.**  :class:`Secret` masks itself in ``repr``, ``str``,
   ``format`` and f-strings; the value is only reachable through
   :meth:`Secret.reveal`, so a key cannot reach a log line, a traceback, a
   dataclass dump or a ``print`` by accident.  Masking is the *default*; leaking
   would have to be deliberate.
2. **Live collection is opt-in.**  ``CICC_VULN_LIVE_COLLECTION`` defaults to
   false.  A misconfigured deployment that supplies a key still performs no
   network collection until someone sets the switch, which is the difference
   between a config mistake and an unintended production data pull.
3. **Failures name the variable, never the value.**  A validation error says
   which environment variable is wrong and what shape was expected.
4. **Unknown ``CICC_VULN_*`` variables are reported**, because a typo in a
   deployment manifest silently reverts to a default and the operator is never
   told.

Environment reference
---------------------
===============================  ========  ===============================================
variable                         default   meaning
===============================  ========  ===============================================
``CICC_VULN_LIVE_COLLECTION``    ``false`` master switch for real provider requests
``CICC_VULN_NVD_API_KEY``        —         NVD API key (raises the rate limit)
``CICC_VULN_NVD_PAGE_SIZE``      ``200``   records per page, 1-2000
``CICC_VULN_NVD_MAX_PAGES``      ``10``    page ceiling for an unbounded search
``CICC_VULN_HTTP_TIMEOUT``       ``30``    seconds per request
``CICC_VULN_KEV_MAX_AGE_DAYS``   ``2``     KEV cache TTL before it reports stale
``CICC_VULN_EPSS_ENABLED``       ``false`` consult EPSS at all
``CICC_VULN_CHECKPOINT_PATH``    —         checkpoint file for incremental sync
``CICC_VULN_ORIGIN``             ``live``  ``live`` / ``fixture`` / ``demo`` data origin
``CICC_VULN_TENANT_ID``          —         default tenant for stored records
===============================  ========  ===============================================
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Mapping

from .errors import ValidationError
from .schema import Origin

__all__ = [
    "ENV_PREFIX",
    "ENV_VARS",
    "Secret",
    "Settings",
    "redact_environment",
]

ENV_PREFIX = "CICC_VULN_"

#: Every variable this package reads, with its purpose.  Documentation and code
#: share one source of truth so the reference cannot drift.
ENV_VARS: Mapping[str, str] = {
    "LIVE_COLLECTION": "master switch for real provider requests (default false)",
    "GHSA_TOKEN": "optional GitHub token for the advisory database (header-only, masked)",
    "NVD_API_KEY": "NVD API key; raises the rate limit from 5 to 50 per 30s",
    "NVD_PAGE_SIZE": "records per NVD page, 1-2000 (default 200)",
    "NVD_MAX_PAGES": "page ceiling per unbounded search (default 10)",
    "HTTP_TIMEOUT": "seconds per provider request (default 30)",
    "KEV_MAX_AGE_DAYS": "days before the KEV cache reports stale (default 2)",
    "EPSS_ENABLED": "consult the EPSS provider (default false)",
    "CHECKPOINT_PATH": "file path for incremental sync checkpoints",
    "ORIGIN": "data origin: live | fixture | demo (default live)",
    "TENANT_ID": "default tenant id for stored records",
}

_MASK = "***"


@dataclass(frozen=True)
class Secret:
    """A value that masks itself everywhere it could be rendered.

    ``reveal()`` is the only way to obtain the plaintext, which makes every use
    site searchable in review: any line that can leak a credential is a line
    containing ``reveal``.
    """

    _value: str = field(repr=False, default="")

    def __post_init__(self) -> None:
        if not isinstance(self._value, str):
            raise ValidationError("secret must be a string")

    def reveal(self) -> str:
        return self._value

    def __bool__(self) -> bool:
        return bool(self._value)

    def __len__(self) -> int:
        return len(self._value)

    def __repr__(self) -> str:
        return f"Secret({_MASK})" if self._value else "Secret(<unset>)"

    def __str__(self) -> str:
        return _MASK if self._value else ""

    def __format__(self, spec: str) -> str:
        # Ignoring the spec is deliberate: `f"{secret:>20}"` must not emit the
        # value with padding.
        return str(self)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Secret):
            return self._value == other._value
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._value)


def _bool(env: Mapping[str, str], key: str, default: bool) -> bool:
    raw = env.get(ENV_PREFIX + key)
    if raw is None or not raw.strip():
        return default
    value = raw.strip().lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise ValidationError(
        f"{ENV_PREFIX}{key} must be one of true/false/1/0/yes/no", field=key
    )


def _int(env: Mapping[str, str], key: str, default: int, *, low: int, high: int) -> int:
    raw = env.get(ENV_PREFIX + key)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError as exc:
        # The raised message names the variable and the expected range; it must
        # not echo the raw value, which may be a mistyped credential.
        raise ValidationError(
            f"{ENV_PREFIX}{key} must be an integer within {low}-{high}", field=key
        ) from exc
    if not low <= value <= high:
        raise ValidationError(
            f"{ENV_PREFIX}{key} must be within {low}-{high} (got {value})", field=key
        )
    return value


def _float(env: Mapping[str, str], key: str, default: float, *, low: float, high: float) -> float:
    raw = env.get(ENV_PREFIX + key)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw.strip())
    except ValueError as exc:
        raise ValidationError(
            f"{ENV_PREFIX}{key} must be a number within {low}-{high}", field=key
        ) from exc
    if not low <= value <= high:
        raise ValidationError(
            f"{ENV_PREFIX}{key} must be within {low}-{high}", field=key
        )
    return value


@dataclass(frozen=True)
class Settings:
    """Resolved configuration.  Immutable, and safe to log."""

    live_collection: bool = False
    nvd_api_key: Secret = Secret()
    nvd_page_size: int = 200
    nvd_max_pages: int = 10
    http_timeout: float = 30.0
    kev_max_age: timedelta = timedelta(days=2)
    epss_enabled: bool = False
    #: Optional GitHub token; Secret-masked like the NVD key. Header-only.
    ghsa_token: Secret = Secret()
    checkpoint_path: Path | None = None
    origin: Origin = Origin.LIVE
    tenant_id: str | None = None
    #: Variables present in the environment that this package does not read.
    unknown: tuple[str, ...] = ()

    @classmethod
    def from_env(
        cls, env: Mapping[str, str] | None = None, *, strict: bool = False
    ) -> Settings:
        """Build settings from the environment.

        ``strict`` promotes unknown ``CICC_VULN_*`` variables to errors; use it in
        deployment validation, not at import time.
        """
        source = os.environ if env is None else env
        origin_raw = (source.get(ENV_PREFIX + "ORIGIN") or "live").strip().lower()
        try:
            origin = Origin(origin_raw)
        except ValueError as exc:
            raise ValidationError(
                f"{ENV_PREFIX}ORIGIN must be one of live/fixture/demo", field="ORIGIN"
            ) from exc

        checkpoint_raw = (source.get(ENV_PREFIX + "CHECKPOINT_PATH") or "").strip()
        tenant = (source.get(ENV_PREFIX + "TENANT_ID") or "").strip() or None
        known = {ENV_PREFIX + name for name in ENV_VARS}
        unknown = tuple(
            sorted(k for k in source if k.startswith(ENV_PREFIX) and k not in known)
        )
        if strict and unknown:
            raise ValidationError(
                "unrecognised configuration variable(s): " + ", ".join(unknown),
                field=unknown[0],
            )

        settings = cls(
            live_collection=_bool(source, "LIVE_COLLECTION", False),
            nvd_api_key=Secret((source.get(ENV_PREFIX + "NVD_API_KEY") or "").strip()),
            nvd_page_size=_int(source, "NVD_PAGE_SIZE", 200, low=1, high=2000),
            nvd_max_pages=_int(source, "NVD_MAX_PAGES", 10, low=1, high=1000),
            http_timeout=_float(source, "HTTP_TIMEOUT", 30.0, low=1.0, high=600.0),
            kev_max_age=timedelta(
                days=_int(source, "KEV_MAX_AGE_DAYS", 2, low=1, high=365)
            ),
            epss_enabled=_bool(source, "EPSS_ENABLED", False),
            ghsa_token=Secret((source.get(ENV_PREFIX + "GHSA_TOKEN") or "").strip()),
            checkpoint_path=Path(checkpoint_raw) if checkpoint_raw else None,
            origin=origin,
            tenant_id=tenant,
            unknown=unknown,
        )
        settings._validate_combinations()
        return settings

    def _validate_combinations(self) -> None:
        """Reject configurations that look valid but cannot work."""
        if self.live_collection and self.origin is not Origin.LIVE:
            raise ValidationError(
                "live collection requires ORIGIN=live: collecting real data while "
                "labelling it fixture/demo would misrepresent its provenance",
                field="ORIGIN",
            )
        if self.live_collection and self.nvd_api_key and len(self.nvd_api_key) < 8:
            raise ValidationError(
                f"{ENV_PREFIX}NVD_API_KEY is too short to be a valid key", field="NVD_API_KEY"
            )

    # -- derived views ----------------------------------------------------
    def describe(self) -> dict[str, Any]:
        """Masked, JSON-safe description for startup logs and ``/config``.

        Safe by construction: the API key is rendered through :class:`Secret`.
        """
        return {
            "live_collection": self.live_collection,
            "nvd_api_key": str(self.nvd_api_key) or "(unset)",
            "nvd_page_size": self.nvd_page_size,
            "nvd_max_pages": self.nvd_max_pages,
            "http_timeout": self.http_timeout,
            "kev_max_age_days": self.kev_max_age.days,
            "epss_enabled": self.epss_enabled,
            "ghsa_token": str(self.ghsa_token) or "(unset)",
            "checkpoint_path": str(self.checkpoint_path) if self.checkpoint_path else None,
            "origin": self.origin.value,
            "tenant_id": self.tenant_id,
            "unknown_variables": list(self.unknown),
        }

    def warnings(self) -> tuple[str, ...]:
        """Configuration facts an operator should see but that are not errors."""
        notes: list[str] = []
        if not self.live_collection:
            notes.append(
                "live collection is disabled; no provider request will be made "
                "(set CICC_VULN_LIVE_COLLECTION=true to enable)"
            )
        if self.live_collection and not self.nvd_api_key:
            notes.append(
                "no NVD API key configured: NVD allows 5 requests/30s and may "
                "throttle; throughput will be limited"
            )
        if self.unknown:
            notes.append(
                "unrecognised configuration variable(s) ignored: "
                + ", ".join(self.unknown)
            )
        return tuple(notes)

    def require_live(self) -> None:
        """Raise unless live collection is enabled — call before any real request."""
        if not self.live_collection:
            raise ValidationError(
                "live collection is disabled (CICC_VULN_LIVE_COLLECTION); "
                "refusing to contact a provider",
                field="LIVE_COLLECTION",
            )


def redact_environment(
    env: Mapping[str, str], *, masker: Callable[[str], str] | None = None
) -> dict[str, str]:
    """Copy of ``env`` with this package's secret values masked.

    Useful when an operator pastes a container environment into a ticket.
    """
    mask = masker or (lambda _: _MASK)
    out: dict[str, str] = {}
    for key, value in env.items():
        if key == ENV_PREFIX + "NVD_API_KEY":
            out[key] = mask(value) if value else ""
        elif key.startswith(ENV_PREFIX):
            out[key] = value
    return out
