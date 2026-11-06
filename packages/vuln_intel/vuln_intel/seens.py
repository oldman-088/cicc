"""First-seen and last-seen semantics for vulnerability observations.

Master Prompt §7 requires every record to carry "First seen" and "Last seen". The
record type does not have those fields and must not gain them: ``NormalizedVulnerability``
is the *normalized output of one collection*, and "seen" is an accumulation across many
collections. Putting an accumulation on the per-fetch record would mean inventing a
value at construction time, which is the exact failure mode the integrity rules forbid.

So the semantics live here, in a tracker that owns a set of observations and derives
the two timestamps from them. The distinction this module exists to keep:

``published`` / ``modified``
    What the *provider* says about the advisory. These are 2019 dates on a CVE
    published in 2019, no matter when we first collected it.

``first_seen`` / ``last_seen``
    What *this system* observed. A CVE published in 2019 and first collected today has
    ``first_seen`` = today. Only these tell an operator whether the feed is working.

Conflating them is not a cosmetic error: it makes a newly-broken feed look healthy
(everything was "laid to rest in 2019") and makes a healthy feed look like it has
ancient data.

Design rules, each enforced by a test:

1. ``first_seen`` is **monotonic**. A later observation never moves it, and a
   back-dated observation (older than the recorded first sighting, e.g. replayed from
   an archive) is recorded as such rather than rewriting history.
2. ``last_seen`` advances only on a **valid** observation. A duplicate does not move it:
   re-ingesting the same payload is not new evidence, and treating it as such would let
   a retry loop manufacture the appearance of a live, advancing feed.
3. Out-of-order arrivals are handled: an observation older than ``last_seen`` updates
   nothing but is still counted, because "we saw this historical record again" is a
   fact worth counting even though it is not a new sighting.
4. Refused observations (fixture data in a live tracker) change nothing at all.

Persistence is JSON, additive, and versioned, so a restart resumes the same semantics.
Nothing here touches the host or a shared contract: it is a self-contained port with an
in-memory implementation and a JSON file implementation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol, Sequence

from .schema import Origin, utcnow

__all__ = [
    "SEEN_SCHEMA",
    "InMemorySeenStore",
    "JsonSeenStore",
    "ObservationStatus",
    "SeenRecord",
    "SeenStore",
    "SightingTracker",
]

#: Bumped when the persisted shape changes incompatibly. Written into every payload so
#: a future reader can refuse a file it does not understand instead of misreading it.
SEEN_SCHEMA = "cicc.vuln_intel.seen.v1"


class ObservationStatus:
    """Outcomes of one ``record()`` call, as data rather than as a boolean.

    A caller needs to distinguish "advanced the sighting" from "already knew this" from
    "refused", because the first is evidence of a working feed and the other two are
    not. Returning ``bool`` would collapse them.
    """

    ADVANCED = "advanced"
    UNCHANGED = "unchanged"
    DUPLICATE = "duplicate"
    STALE = "stale"
    REFUSED = "refused"


@dataclass(frozen=True)
class SeenRecord:
    """The two timestamps for one CVE, plus the evidence behind them.

    ``first_seen`` and ``last_seen`` are the facts the Master Prompt asks for. The
    remaining fields exist so the numbers can be audited rather than taken on trust:
    ``observations`` counts *valid* sightings (duplicates excluded), and
    ``sources_seen`` records which sources contributed, so a last_seen that came from
    only one flaky source is distinguishable from one corroborated by several.
    """

    cve: str
    first_seen: str  # ISO 8601, UTC
    last_seen: str
    observations: int = 1
    sources_seen: tuple[str, ...] = ()
    origin: str = Origin.LIVE.value
    #: Set when an observation arrived with a timestamp *older* than ``first_seen``.
    #: Kept rather than dropped: it means the tracker is receiving back-dated data
    #: (archive replay, provider correction) and an operator should know.
    backdated_observations: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "observations": self.observations,
            "sources_seen": list(self.sources_seen),
            "origin": self.origin,
            "backdated_observations": self.backdated_observations,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> SeenRecord:
        cve = payload.get("cve")
        first = payload.get("first_seen")
        last = payload.get("last_seen")
        if not isinstance(cve, str) or not cve:
            raise ValueError("seen record needs a cve")
        if not isinstance(first, str) or not isinstance(last, str):
            raise ValueError("seen record needs first_seen and last_seen")
        sources = payload.get("sources_seen") or []
        if not isinstance(sources, (list, tuple)):
            sources = []
        observations = payload.get("observations", 1)
        backdated = payload.get("backdated_observations", 0)
        return cls(
            cve=cve,
            first_seen=first,
            last_seen=last,
            observations=int(observations) if isinstance(observations, int) else 1,
            sources_seen=tuple(str(s) for s in sources),
            origin=str(payload.get("origin") or Origin.LIVE.value),
            backdated_observations=(
                int(backdated) if isinstance(backdated, int) else 0
            ),
        )


class SeenStore(Protocol):
    """Persistence port. A real adapter belongs in the host, behind an approval."""

    def load(self) -> Mapping[str, SeenRecord]:  # pragma: no cover - protocol
        ...

    def save(self, records: Mapping[str, SeenRecord]) -> None:  # pragma: no cover
        ...


@dataclass
class InMemorySeenStore:
    """Non-persistent store, for tests and dry runs. Survives nothing, by design."""

    records: dict[str, SeenRecord] = field(default_factory=dict, repr=False)

    def load(self) -> Mapping[str, SeenRecord]:
        return dict(self.records)

    def save(self, records: Mapping[str, SeenRecord]) -> None:
        self.records = dict(records)


@dataclass
class JsonSeenStore:
    """JSON-file store, written atomically.

    Uses ``os.replace`` via ``Path.replace`` so a crash mid-write cannot leave a
    truncated file. That matters more here than for a checkpoint: a corrupt checkpoint
    costs one re-sync, whereas a corrupt seen-file costs *history* — and silently
    resetting ``first_seen`` to "now" is exactly the misleading timestamp this module
    exists to prevent.
    """

    path: Path
    allow_fixture: bool = False

    def load(self) -> Mapping[str, SeenRecord]:
        if not self.path.exists():
            return {}
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(payload, Mapping):
            return {}
        if payload.get("schema") != SEEN_SCHEMA:
            # Refuse rather than guess. A shape we do not recognise could mean
            # timestamps in a different unit or timezone, and misreading those would
            # corrupt first_seen permanently.
            return {}
        records = payload.get("records")
        if not isinstance(records, Mapping):
            return {}
        loaded: dict[str, SeenRecord] = {}
        for key, entry in records.items():
            if not isinstance(entry, Mapping):
                continue
            try:
                loaded[str(key)] = SeenRecord.from_dict(entry)
            except (ValueError, TypeError):
                continue
        return loaded

    def save(self, records: Mapping[str, SeenRecord]) -> None:
        payload = {
            "schema": SEEN_SCHEMA,
            "records": {k: v.as_dict() for k, v in sorted(records.items())},
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        tmp.replace(self.path)


class SightingTracker:
    """Owns first-seen/last-seen semantics for a set of CVEs.

    Instantiate with a store; call :meth:`record` once per observation and
    :meth:`record_many` for a batch. Timestamps come from ``clock`` so every test is
    deterministic and no behaviour depends on the wall clock.
    """

    def __init__(
        self,
        *,
        store: SeenStore | None = None,
        clock: Any = None,
        allow_fixture: bool = False,
        persist_every: bool = True,
    ) -> None:
        self.store = store if store is not None else InMemorySeenStore()
        self._clock = clock or utcnow
        self.allow_fixture = allow_fixture
        self.persist_every = persist_every
        self._records: dict[str, SeenRecord] = dict(self.store.load())
        #: Refusals are kept, not swallowed: a fixture record offered to a live
        #: tracker is a bug in the caller and should be visible.
        self.refusals: list[dict[str, str]] = []

    # -- read side --------------------------------------------------------
    def get(self, cve: str) -> SeenRecord | None:
        return self._records.get(str(cve))

    def all(self) -> Mapping[str, SeenRecord]:
        return dict(self._records)

    def __len__(self) -> int:
        return len(self._records)

    # -- write side -------------------------------------------------------
    def record(
        self,
        cve: object,
        *,
        source: str,
        observed_at: Any = None,
        origin: Origin | str = Origin.LIVE,
    ) -> str:
        """Record one sighting. Returns an :class:`ObservationStatus` value.

        ``observed_at`` is *when the observation was collected*. Passing ``None``
        means "now". An observation carrying a collection time older than the recorded
        ``last_seen`` is **stale**: it does not move ``last_seen`` backwards, because a
        timestamp that can go backwards is not a watermark.
        """
        key = str(cve)
        if not key:
            raise ValueError("cannot record a sighting without a CVE")

        origin_value = origin.value if isinstance(origin, Origin) else str(origin)
        if origin_value != Origin.LIVE.value and not self.allow_fixture:
            self.refusals.append(
                {"cve": key, "source": source, "reason": f"origin={origin_value}"}
            )
            return ObservationStatus.REFUSED

        moment = observed_at or self._clock()
        is_aware = getattr(moment, "tzinfo", None) is not None
        if not is_aware:
            raise ValueError("observed_at must be timezone-aware")
        stamp = moment.isoformat()

        existing = self._records.get(key)
        if existing is None:
            self._records[key] = SeenRecord(
                cve=key,
                first_seen=stamp,
                last_seen=stamp,
                observations=1,
                sources_seen=(source,),
                origin=origin_value,
            )
            self._flush()
            return ObservationStatus.ADVANCED

        # A sighting with no new information is not new evidence. Returning early
        # keeps last_seen where it is, so a retry loop cannot simulate a live feed.
        if stamp == existing.last_seen and source in existing.sources_seen:
            return ObservationStatus.DUPLICATE

        result = ObservationStatus.ADVANCED
        backdated = existing.backdated_observations
        if stamp > existing.last_seen:
            last_seen = stamp
        elif stamp == existing.last_seen:
            last_seen = existing.last_seen
        else:
            # Older than the newest sighting. Not advanced, but counted: we did see it.
            last_seen = existing.last_seen
            result = ObservationStatus.STALE
            if stamp < existing.first_seen:
                backdated += 1

        sources = tuple(sorted({*existing.sources_seen, source}))
        self._records[key] = replace(
            existing,
            last_seen=last_seen,
            observations=existing.observations + 1,
            sources_seen=sources,
            backdated_observations=backdated,
        )
        self._flush()
        return result

    def record_many(
        self,
        items: Iterable[tuple[object, str, Any, Origin | str]],
    ) -> Mapping[str, int]:
        """Record ``(cve, source, observed_at, origin)`` tuples; return counts.

        Returns a status histogram rather than a single number, because "12 recorded"
        does not say whether the tracker advanced or merely re-saw duplicates.
        """
        counts: dict[str, int] = {}
        for cve, source, observed_at, origin in items:
            status = self.record(
                cve, source=source, observed_at=observed_at, origin=origin
            )
            counts[status] = counts.get(status, 0) + 1
        return counts

    # -- persistence ------------------------------------------------------
    def _flush(self) -> None:
        if self.persist_every:
            self.store.save(self._records)

    def persist(self) -> None:
        self.store.save(self._records)

    def load(self) -> None:
        """Re-read from the store, discarding in-memory state.

        Separate from ``__init__`` so a long-lived tracker can be reloaded without
        being rebuilt, and so a test can prove that a restart preserves history.
        """
        self._records = dict(self.store.load())

    # -- reporting --------------------------------------------------------
    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SEEN_SCHEMA,
            "records": {k: v.as_dict() for k, v in sorted(self._records.items())},
            "refusals": list(self.refusals),
        }

    def summary(self) -> dict[str, Any]:
        """Aggregate view for a health report."""
        if not self._records:
            return {
                "tracked": 0,
                "never_observed": None,
                "earliest_first_seen": None,
                "latest_last_seen": None,
                "backdated": 0,
            }
        firsts: Sequence[str] = [r.first_seen for r in self._records.values()]
        lasts: Sequence[str] = [r.last_seen for r in self._records.values()]
        return {
            "tracked": len(self._records),
            "earliest_first_seen": min(firsts),
            "latest_last_seen": max(lasts),
            "backdated": sum(r.backdated_observations for r in self._records.values()),
        }
