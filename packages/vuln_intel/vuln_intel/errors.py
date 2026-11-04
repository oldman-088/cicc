"""Error taxonomy for the CICC vulnerability-intelligence layer.

Design rules encoded here:

* Errors never carry credentials, request headers or full URLs with query
  strings.  ``sanitize`` is applied to any text that may reach a log, an audit
  record or an API response.
* A failed collection is always a distinct error class, never an empty result.
  "No data" and "collection failed" must stay distinguishable (see
  ``SourceState`` in :mod:`vuln_intel.schema`).
"""

from __future__ import annotations

__all__ = [
    "VulnIntelError",
    "ValidationError",
    "UnsupportedVector",
    "MixedOriginError",
    "SourceError",
    "SourceUnavailable",
    "SourceTimeout",
    "SourceResponseError",
    "SourceRateLimited",
    "SourceNotFound",
    "sanitize",
]

_MAX_MESSAGE = 400
_REDACTED = "<redacted>"


#: Case-insensitive markers after which *everything on the line* is secret.
#: Redacting to end-of-line (not to the next space) is intentional: values such
#: as ``Authorization: Bearer <token>`` contain a space before the secret.
_SECRET_MARKERS = (
    "apikey=",
    "api_key=",
    "api-key=",
    "apikey:",
    "authorization:",
    "token=",
    "token:",
    "secret=",
    "password=",
)


def sanitize(text: object, limit: int = _MAX_MESSAGE) -> str:
    """Return a log-safe single-line summary of ``text``.

    Strips anything that looks like a query string, an authorization header or
    an API key, collapses whitespace and truncates.
    """
    if text is None:
        return ""
    cleaned_lines: list[str] = []
    for line in str(text).replace("\r", "\n").split("\n"):
        lowered = line.lower()
        cut_at = len(line)
        for marker in _SECRET_MARKERS:
            index = lowered.find(marker)
            if index != -1:
                cut_at = min(cut_at, index)
        if cut_at < len(line):
            line = line[:cut_at] + _REDACTED
        query = line.find("?")
        if query != -1:
            line = line[:query] + "?<stripped>"
        cleaned_lines.append(line)
    value = " ".join(" ".join(cleaned_lines).split())
    if len(value) > limit:
        value = value[: limit - 3] + "..."
    return value


class VulnIntelError(Exception):
    """Base class for every error raised by this package."""


class ValidationError(VulnIntelError):
    """Source data did not match the documented schema.

    Raised instead of silently skipping malformed records, so that a broken
    upstream contract is visible rather than being reported as "no data".
    """

    def __init__(self, message: str, *, field: str | None = None) -> None:
        self.field = field
        suffix = f" (field={field})" if field else ""
        super().__init__(sanitize(message) + suffix)


class UnsupportedVector(ValidationError):
    """A CVSS vector was supplied that this package cannot score.

    Never guessed: only CVSS v3.0/v3.1 base metrics are computed.
    """


class MixedOriginError(VulnIntelError):
    """Attempted to combine fixture/demo data with live or cached data."""


class SourceError(VulnIntelError):
    """Base class for collection failures. ``source`` names the origin."""

    source = "unknown"

    def __init__(self, message: str, *, source: str | None = None) -> None:
        self.message = sanitize(message)
        if source:
            self.source = source
        super().__init__(f"[{self.source}] {self.message}")


class SourceUnavailable(SourceError):
    """The source could not be reached at all (network blocked, no client)."""


class SourceTimeout(SourceUnavailable):
    """The source did not answer within the configured timeout."""


class SourceResponseError(SourceError):
    """The source answered, but with an unusable status or body."""

    def __init__(self, message: str, *, status: int | None = None, source: str | None = None) -> None:
        self.status = status
        super().__init__(message, source=source)


class SourceRateLimited(SourceResponseError):
    """The source refused the request because of a rate limit or quota."""

    def __init__(
        self,
        message: str = "rate limited",
        *,
        retry_after: float | None = None,
        status: int | None = None,
        source: str | None = None,
    ) -> None:
        self.retry_after = retry_after
        super().__init__(message, status=status, source=source)


class SourceNotFound(SourceResponseError):
    """The requested record does not exist at this source (a fact, not a fault)."""
