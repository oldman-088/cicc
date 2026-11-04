"""EPSS integration interface — designed now, network intentionally not wired.

EPSS (Exploit Prediction Scoring System, FIRST) publishes a *probability* that a
CVE will be exploited in the next 30 days, plus a percentile, together with the
model version that produced it:

    GET https://api.first.org/data/v1/epss?cve=CVE-2024-1234
    {"status":"OK","status-code":200,"version":"2025.03.14","model":"...",
     "total":1,"offset":0,"limit":1,
     "data":[{"cve":"CVE-2024-1234","epss":"0.97228","percentile":"0.99966",
              "date":"2025-03-14"}]}

Scope decision (deliberate, documented):

* **The HTTP call is not implemented.**  EPSS lives behind a host this
  environment cannot reach, and shipping an untested integration would violate
  the project rule against claiming unverified connections.  Instead this module
  ships the parts that are safe to build and test offline:
  a typed normalization layer, a strict response parser, a cache protocol and a
  provider protocol.
* These seams are what the ranking module consumes, so swapping in a live
  provider later requires **no** change to scoring code.
* EPSS is a prediction, never a definition of exploitability.  A missing score
  is ``None``; it is never coerced to ``0.0`` (which would read as "safe").

To wire it later: implement :class:`EpssProvider` with the existing
:class:`~vuln_intel.transport.Transport`, reuse :func:`parse_epss_response`, and
flip ``LIVE_PROVIDER_AVAILABLE`` only when a real fetch has been recorded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any, Callable, Mapping, Protocol, Sequence, runtime_checkable

from ..errors import SourceResponseError, ValidationError
from ..schema import CveId, coerce_text, mapping_list, utcnow

__all__ = [
    "EPSS_API",
    "LIVE_PROVIDER_AVAILABLE",
    "EpssCache",
    "EpssProvider",
    "EpssScore",
    "FixtureEpssProvider",
    "InMemoryEpssCache",
    "UnavailableEpssProvider",
    "parse_epss_response",
]

EPSS_API = "https://api.first.org/data/v1/epss"

#: ``False`` until an authorized, executed live fetch exists.  Code paths that
#: consult this must degrade to "EPSS unavailable", never to a silent zero.
LIVE_PROVIDER_AVAILABLE = False


@dataclass(frozen=True)
class EpssScore:
    """One EPSS observation.

    ``stale`` is computed by the caller-supplied policy, not guessed here.
    """

    cve: CveId
    score: float
    percentile: float
    model_date: str | None
    observed_at: datetime
    model_version: str | None = None
    origin: str = "live"
    stale: bool = False

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValidationError("EPSS score must be within 0.0-1.0", field="epss")
        if not 0.0 <= self.percentile <= 1.0:
            raise ValidationError("EPSS percentile must be within 0.0-1.0", field="percentile")
        if self.observed_at.tzinfo is None:
            raise ValidationError("observed_at must be timezone-aware", field="observed_at")
        if self.origin not in ("live", "fixture", "demo", "cached"):
            raise ValidationError("unknown EPSS origin", field="origin")

    def as_dict(self) -> dict[str, Any]:
        return {
            "cve": str(self.cve),
            "epss": self.score,
            "percentile": self.percentile,
            "model_date": self.model_date,
            "model_version": self.model_version,
            "observed_at": self.observed_at.isoformat(),
            "origin": self.origin,
            "stale": self.stale,
        }


@runtime_checkable
class EpssProvider(Protocol):
    """Contract for an EPSS source of truth.

    Implementations MUST raise :class:`~vuln_intel.errors.SourceError` when they
    cannot answer, so "unavailable" never masquerades as "score = 0".
    """

    name: str

    def fetch(self, cves: Sequence[CveId]) -> Mapping[str, EpssScore]:  # pragma: no cover
        ...


@runtime_checkable
class EpssCache(Protocol):
    """Cache seam: a DB-backed implementation can be added without touching scoring."""

    def get(self, cve: CveId) -> EpssScore | None:  # pragma: no cover
        ...

    def put(self, score: EpssScore) -> None:  # pragma: no cover
        ...


@dataclass
class InMemoryEpssCache:
    """Process-local cache; explicitly *not* durable and not multi-tenant.

    ``clock`` is injectable so expiry behaviour is testable without sleeping.
    """

    max_age_seconds: float = 24 * 3600
    clock: Callable[[], datetime] = utcnow
    _items: dict[str, EpssScore] = field(default_factory=dict, repr=False)

    def get(self, cve: CveId) -> EpssScore | None:
        score = self._items.get(str(cve))
        if score is None:
            return None
        age = (self.clock() - score.observed_at).total_seconds()
        if age > self.max_age_seconds:
            return None
        return score

    def put(self, score: EpssScore) -> None:
        self._items[str(score.cve)] = score


@dataclass
class FixtureEpssProvider:
    """Deterministic provider for **fixture/demo** runs.

    Records are stamped ``origin="fixture"`` so they can never be merged into
    live intelligence (see :func:`vuln_intel.schema.merge_records`).
    """

    scores: Mapping[str, tuple[float, float, str | None]] = field(default_factory=dict)
    model_version: str = "fixture"
    name: str = "fixture-epss"

    def fetch(self, cves: Sequence[CveId]) -> Mapping[str, EpssScore]:
        out: dict[str, EpssScore] = {}
        for cve in cves:
            entry = self.scores.get(str(cve))
            if entry is None:
                continue
            score, percentile, model_date = entry
            out[str(cve)] = EpssScore(
                cve=cve,
                score=score,
                percentile=percentile,
                model_date=model_date,
                observed_at=utcnow(),
                model_version=self.model_version,
                origin="fixture",
            )
        return out


@dataclass
class UnavailableEpssProvider:
    """Default provider while the live call is not implemented/verified."""

    reason: str = (
        "EPSS live provider is not implemented or verified in this build; "
        "scores are unavailable, not zero"
    )
    name: str = "unavailable-epss"

    def fetch(self, cves: Sequence[CveId]) -> Mapping[str, EpssScore]:
        raise SourceResponseError(self.reason, source="epss")


def _ratio(value: object, *, field_name: str) -> float:
    """EPSS numbers arrive as strings such as ``"0.97228"``."""
    if isinstance(value, bool):
        raise ValidationError("expected a numeric string", field=field_name)
    if isinstance(value, (int, float)):
        number = float(value)
    elif isinstance(value, str) and value.strip():
        try:
            number = float(value.strip())
        except ValueError as exc:
            raise ValidationError(f"unparseable {field_name}: {value!r}", field=field_name) from exc
    else:
        raise ValidationError(f"missing {field_name}", field=field_name)
    if not 0.0 <= number <= 1.0:
        raise ValidationError(f"{field_name} outside 0.0-1.0", field=field_name)
    return number


def _model_date(value: object) -> str | None:
    text = coerce_text(value, field_name="date", limit=40)
    if text is None:
        return None
    try:
        date.fromisoformat(text)
    except ValueError as exc:
        raise ValidationError(f"unparseable EPSS date: {text!r}", field="date") from exc
    return text


def parse_epss_response(
    body: Mapping[str, Any],
    *,
    observed_at: datetime | None = None,
    origin: str = "live",
    requested: Sequence[CveId] = (),
) -> Mapping[str, EpssScore]:
    """Strictly parse an EPSS API payload.

    * non-``OK`` status raises instead of returning an empty mapping;
    * each entry is validated independently — one bad row fails the parse
      visibly rather than being dropped silently;
    * CVEs absent from a successful response are genuinely unscored and are
      simply not present in the result (callers must render "no EPSS").
    """
    if not isinstance(body, Mapping):
        raise SourceResponseError("EPSS body is not an object", source="epss")
    status = body.get("status")
    if status is not None and str(status).upper() != "OK":
        raise SourceResponseError(
            f"EPSS returned status {status!r}", source="epss"
        )
    observed = observed_at or utcnow()
    if observed.tzinfo is None:
        raise ValidationError("observed_at must be aware", field="observed_at")
    model_version = coerce_text(body.get("version"), field_name="version", limit=40)
    scores: dict[str, EpssScore] = {}
    for entry in mapping_list(body.get("data"), field_name="data"):
        cve = CveId.parse(entry.get("cve"))
        if requested and str(cve) not in {str(item) for item in requested}:
            # The provider answered about a CVE we did not ask for.
            raise ValidationError(
                "EPSS returned an unrequested CVE", field="cve"
            )
        scores[str(cve)] = EpssScore(
            cve=cve,
            score=_ratio(entry.get("epss"), field_name="epss"),
            percentile=_ratio(entry.get("percentile"), field_name="percentile"),
            model_date=_model_date(entry.get("date")),
            observed_at=observed.astimezone(timezone.utc),
            model_version=model_version,
            origin=origin,
        )
    return scores
