# ruff: noqa: S608
#
# S608 flags "SQL built from a string". Every statement in this module is assembled
# from constant fragments: the only interpolated parts are the placeholder character
# for the driver's paramstyle (`?` or `%s`), fixed column names, a clause chosen from
# ``_ORDERS``, and fixed boolean keywords. No value from input is ever interpolated —
# values are always bound parameters. ``test_dbapi_store.py`` proves that by storing a
# CVE id containing a SQL injection payload and reading it back.

"""A store adapter over any DB-API 2.0 connection, so deployment needs no migration.

The problem this solves
-----------------------
The package ships two stores: an in-memory one for tests and a SQLite one that
proves the SQL. Both are honest about what they are, but neither can hold
production data, and the documented way forward was "a host migration". That
placed the entire persistence path behind a shared-architecture change owned by
somebody else — so an otherwise finished domain could not store a single record
without a decision it had no authority to take.

A DB-API 2.0 adapter removes that dependency. ``psycopg``, ``psycopg2`` and
``sqlite3`` all implement the same small interface (``connect`` → ``cursor`` →
``execute``/``fetchone``/``commit``), and the driver itself is injected as a
callable. The package therefore still imports no database library, keeps its
dependency-free guarantee, and can nonetheless write to a real PostgreSQL
database on day one.

What is deliberately *not* done here
------------------------------------
* **No schema is created.** ``ensure_schema=False`` is the default and there is no
  ``CREATE TABLE`` anywhere in this module. Creating tables in the host's database
  is the shared-architecture change this adapter exists to avoid needing. The DDL
  it expects is published as :data:`SCHEMA` so a host *can* adopt it deliberately,
  but a store that silently issues DDL against somebody else's database is exactly
  the kind of surprise that makes integrations untrustworthy.
* **No placeholder guessing.** ``?`` and ``%s`` are different dialects. Rather than
  sniff the driver, the placeholder is explicit (`paramstyle`), because a silent
  wrong guess produces a syntax error at the first write — or, worse, a query that
  appears to succeed.
* **No SQL injection surface.** Every statement is a constant in this module with
  bound parameters. No identifier or fragment is ever built from input.

Every invariant the in-memory store enforces is enforced here, in SQL, so the two
cannot disagree about what the rules are:

* tenant scoping on every read and write;
* one row per ``(tenant_id, cve)``;
* an older observation never overwrites a newer one;
* provenance is recorded exactly when content changes — not on a timestamp-only
  refresh, and not on a dry run;
* a dry run writes nothing at all, including on the create path.

The tests run this adapter against real SQLite and, when a server is configured,
against PostgreSQL. A store tested only against an in-memory double is the thing
this module was written to replace.
"""

from __future__ import annotations

import builtins
import json
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, List, Mapping, Protocol, Sequence

from ..schema import severity_rank
from .contracts import UpsertOutcome, UpsertResult
from .mapping import ENRICHMENT_KEY, assert_persistable, event_types

__all__ = [
    "POSTGRES_SCHEMA",
    "SQLITE_SCHEMA",
    "DBAPIVulnerabilityStore",
    "UnsupportedParamStyle",
]

#: Placeholder styles this adapter knows how to emit.
_PARAM_STYLES = {"qmark": "?", "format": "%s"}

#: How a JSON document reaches the driver. See ``DBAPIVulnerabilityStore.json_mode``.
_JSON_MODES = {"text", "native", "json_wrapper"}


class UnsupportedParamStyle(ValueError):
    """Raised rather than guessing a placeholder dialect."""


def _qmark(style: str) -> str:
    try:
        return _PARAM_STYLES[style]
    except KeyError:  # pragma: no cover - guarded by __post_init__
        raise UnsupportedParamStyle(
            f"unsupported paramstyle {style!r}; known: {sorted(_PARAM_STYLES)}"
        ) from None


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: datetime) -> str:
    """UTC ISO-8601 with an explicit offset.

    Same reason as the SQLite store: when the column is text the ordering that
    matters is lexicographic, and that only holds if the offset never varies.
    """
    return _aware(value).astimezone(timezone.utc).isoformat()


def _parse_stamp(value: Any) -> datetime:
    """Accept a datetime from a real date column, or an ISO string from a text one."""
    if isinstance(value, datetime):
        return _aware(value)
    return _aware(datetime.fromisoformat(str(value)))


#: The shape this adapter reads and writes. Two dialects because a host adopting
#: this into a migration needs DDL that runs on its own server; sharing one string
#: and hoping is how a migration lookup succeeds against the wrong engine.
SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS vulnerability_record (
    tenant_id     TEXT NOT NULL,
    cve           TEXT NOT NULL,
    entity_id     TEXT NOT NULL,
    details       TEXT NOT NULL,
    origin        TEXT NOT NULL
                  CHECK (origin IN ('live', 'fixture', 'demo', 'unknown')),
    collected_at  TEXT NOT NULL,
    severity_rank INTEGER NOT NULL DEFAULT 99,
    kev           INTEGER NOT NULL DEFAULT 0 CHECK (kev IN (0, 1)),
    PRIMARY KEY (tenant_id, cve)
);
CREATE INDEX IF NOT EXISTS ix_record_tenant_severity
    ON vulnerability_record (tenant_id, severity_rank, cve);
CREATE INDEX IF NOT EXISTS ix_record_tenant_kev
    ON vulnerability_record (tenant_id, kev, cve);
CREATE TABLE IF NOT EXISTS provenance_event (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT NOT NULL,
    cve         TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    source      TEXT,
    observed_at TEXT,
    payload     TEXT NOT NULL,
    FOREIGN KEY (tenant_id, cve)
        REFERENCES vulnerability_record (tenant_id, cve) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_provenance_tenant_cve
    ON provenance_event (tenant_id, cve, id);
"""

POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS vulnerability_record (
    tenant_id     UUID NOT NULL,
    cve           TEXT NOT NULL,
    entity_id     UUID NOT NULL,
    details       JSONB NOT NULL,
    origin        TEXT NOT NULL
                  CHECK (origin IN ('live', 'fixture', 'demo', 'unknown')),
    collected_at  TIMESTAMPTZ NOT NULL,
    severity_rank INTEGER NOT NULL DEFAULT 99,
    kev           BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (tenant_id, cve)
);
CREATE INDEX IF NOT EXISTS ix_record_tenant_severity
    ON vulnerability_record (tenant_id, severity_rank, cve);
CREATE INDEX IF NOT EXISTS ix_record_tenant_kev
    ON vulnerability_record (tenant_id, kev, cve);
CREATE TABLE IF NOT EXISTS provenance_event (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   UUID NOT NULL,
    cve         TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    source      TEXT,
    observed_at TIMESTAMPTZ,
    payload     JSONB NOT NULL,
    FOREIGN KEY (tenant_id, cve)
        REFERENCES vulnerability_record (tenant_id, cve) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_provenance_tenant_cve
    ON provenance_event (tenant_id, cve, id);
"""

_ORDERS = {
    "cve": ("cve ASC", "cve", False),
    "-cve": ("cve DESC", "cve", True),
    "severity": ("severity_rank ASC, cve ASC", "cve", False),
    "-severity": ("severity_rank DESC, cve DESC", "cve", True),
}


class _Cursor(Protocol):
    def execute(self, sql: str, params: Sequence[Any] = ...) -> Any: ...
    def fetchone(self) -> Any: ...
    def fetchall(self) -> Any: ...


class _Connection(Protocol):
    def cursor(self) -> _Cursor: ...
    def commit(self) -> None: ...
    def rollback(self) -> None: ...
    def close(self) -> None: ...


@dataclass
class DBAPIVulnerabilityStore:
    """Tenant-scoped store over an injected DB-API 2.0 connection factory.

    ``connect`` is called once per operation and the connection is closed
    afterwards, so the store is safe to share across threads and the host's own
    pooling (if it has any) is not bypassed — pass whatever its drivers expect.

    ``row_factory`` exists because drivers disagree about the shape of a row:
    ``sqlite3`` returns tuples unless told otherwise, ``psycopg`` returns tuples,
    and a dict row factory returns mappings. ``_as_mapping`` handles both, so a
    caller does not have to care which driver it supplied.
    """

    #: e.g. ``lambda: psycopg.connect(dsn)`` or ``lambda: sqlite3.connect(path)``
    connect: Callable[[], _Connection]
    #: ``"qmark"`` for sqlite3/psycopg2-style ``?``, ``"format"`` for ``%s``.
    paramstyle: str = "qmark"
    #: How to hand JSON to the driver. Three modes, because "text or not" is not
    #: enough to describe what drivers actually do:
    #:
    #: ``"text"``
    #:     ``json.dumps`` the document. SQLite has no JSON type, so this is right.
    #: ``"native"``
    #:     Pass the mapping through. Correct when the driver adapts dicts itself —
    #:     ``psycopg2`` does for JSONB, and psycopg3 does once an adapter is
    #:     registered by the caller.
    #: ``"json_wrapper"``
    #:     Wrap in a JSON string cast to the right type with ``:jsonb``/``:json``.
    #:     This is what ``psycopg3`` needs out of the box: it refuses a bare dict
    #:     ("cannot adapt type 'dict'"), and registering an adapter would mean the
    #:     package importing the driver, which it must not do.
    json_mode: str = "text"
    #: Whether the ``kev`` column is a real BOOLEAN. SQLite has no boolean type and
    #: its schema uses ``INTEGER``; PostgreSQL rejects ``0`` for a ``BOOLEAN``
    #: column outright, so passing the wrong one is a hard error rather than a
    #: silent coercion — which is why this is explicit and tested on both engines.
    boolean_kev: bool = False
    allow_fixture: bool = False
    #: Rows written by this instance. Not a substitute for querying the database;
    #: it is a local counter for tests and for the sync report.
    writes: int = 0
    _rows_written: builtins.list[str] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        if self.paramstyle not in _PARAM_STYLES:
            raise UnsupportedParamStyle(
                f"unsupported paramstyle {self.paramstyle!r}; "
                f"known: {sorted(_PARAM_STYLES)}"
            )
        if self.json_mode not in _JSON_MODES:
            raise UnsupportedParamStyle(
                f"unsupported json_mode {self.json_mode!r}; known: {sorted(_JSON_MODES)}"
            )

    # -- plumbing --------------------------------------------------------
    @property
    def _p(self) -> str:
        return _qmark(self.paramstyle)

    def _json(self, value: Any) -> Any:
        """Encode a document for the configured driver, without importing it.

        In ``json_wrapper`` mode the cast must be visible to the driver *as text*
        in the statement, so it is appended by :meth:`_param` instead of here.
        """
        if self.json_mode == "native":
            return value
        return json.dumps(value, default=str)

    def _param(self, value: Any) -> str:
        """The placeholder for one bind, honouring the JSON wrapper mode."""
        return f"{self._p}::jsonb" if self.json_mode == "json_wrapper" else self._p

    def _decode(self, value: Any) -> Any:
        return json.loads(value) if isinstance(value, (str, bytes)) else value

    @staticmethod
    def _as_mapping(row: Any, columns: Sequence[str]) -> Mapping[str, Any]:
        if isinstance(row, Mapping):
            return row
        return dict(zip(columns, row, strict=False))

    @contextmanager
    def connection(self) -> Iterator[_Connection]:
        conn = self.connect()
        try:
            yield conn
        finally:
            conn.close()

    # -- read port -------------------------------------------------------
    def find(self, *, tenant_id: str, cve: str) -> Mapping[str, Any] | None:
        p = self._p
        with self.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT cve, entity_id, details, origin, collected_at "
                f"FROM vulnerability_record WHERE tenant_id = {p} AND cve = {p}",
                (tenant_id, cve),
            )
            row = cur.fetchone()
        if row is None:
            return None
        cols = ("cve", "entity_id", "details", "origin", "collected_at")
        m = self._as_mapping(row, cols)
        # `cve` is part of the read contract: a caller that fetched by identifier
        # must not have to remember which identifier it asked for.
        return {
            "cve": m["cve"],
            "entity_id": str(m["entity_id"]),
            "details": self._decode(m["details"]),
            "collected_at": _parse_stamp(m["collected_at"]),
            "origin": m["origin"],
        }

    def list(
        self,
        *,
        tenant_id: str,
        limit: int,
        cursor: str | None = None,
        severity: str | None = None,
        kev_only: bool = False,
        order: str = "cve",
    ) -> tuple[list[Mapping[str, Any]], str | None]:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        if order not in _ORDERS:
            raise ValueError("unsupported order")
        order_clause, cursor_column, descending = _ORDERS[order]
        p = self._p

        where = [f"tenant_id = {p}"]
        params: list[Any] = [tenant_id]
        if severity is not None:
            where.append(f"severity_rank = {p}")
            params.append(severity_rank(severity.strip().lower()))
        if kev_only:
            # `kev = 1` is a type error on a BOOLEAN column, and the error reads as
            # "operator does not exist", not as "you passed the wrong constant".
            where.append("kev = TRUE" if self.boolean_kev else "kev = 1")
        if cursor is not None:
            # Seek, not offset: the cursor is the last key emitted, so an insert
            # between pages cannot shift the window and skip or repeat a row.
            comparator = "<" if descending else ">"
            where.append(f"{cursor_column} {comparator} {p}")
            params.append(cursor)

        sql = (
            "SELECT cve, entity_id, details, origin, collected_at, severity_rank "
            "FROM vulnerability_record WHERE " + " AND ".join(where)
            + f" ORDER BY {order_clause} LIMIT {p}"
        )
        params.append(limit + 1)

        with self.connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()

        cols = ("cve", "entity_id", "details", "origin", "collected_at", "severity_rank")
        mapped = [self._as_mapping(r, cols) for r in rows]
        has_more = len(mapped) > limit
        page = mapped[:limit]
        # The cursor is the CVE, unique within a tenant. A cursor on the severity
        # rank would not be: several rows share a rank, and a page boundary there
        # repeats or skips rows.
        next_cursor = str(page[-1][cursor_column]) if has_more and page else None
        return (
            [
                {
                    "cve": m["cve"],
                    "entity_id": str(m["entity_id"]),
                    "details": self._decode(m["details"]),
                    "collected_at": _parse_stamp(m["collected_at"]),
                    "origin": m["origin"],
                }
                for m in page
            ],
            next_cursor,
        )

    def record_count(self, *, tenant_id: str) -> int:
        p = self._p
        with self.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                f"SELECT COUNT(*) AS n FROM vulnerability_record WHERE tenant_id = {p}",
                (tenant_id,),
            )
            row = cur.fetchone()
        if row is None:  # pragma: no cover - COUNT always returns a row
            return 0
        return int(self._as_mapping(row, ("n",))["n"])

    def provenance_for(self, *, tenant_id: str, cve: str) -> List[dict[str, Any]]:  # noqa: UP006
        p = self._p
        with self.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT event_type, payload FROM provenance_event "
                f"WHERE tenant_id = {p} AND cve = {p} ORDER BY id",
                (tenant_id, cve),
            )
            rows = cur.fetchall()
        cols = ("event_type", "payload")
        return [
            {"event_type": m["event_type"], **self._decode(m["payload"])}
            for m in (self._as_mapping(r, cols) for r in rows)
        ]

    # -- write port ------------------------------------------------------
    def upsert(
        self,
        *,
        tenant_id: str,
        cve: str,
        entity: Mapping[str, Any],
        details: Mapping[str, Any],
        enrichment: Mapping[str, Any] | None,
        provenance: Mapping[str, Any],
        collected_at: datetime,
        dry_run: bool,
    ) -> UpsertResult:
        payload = {"origin": (enrichment or {}).get("origin", "live"), "cve": cve}
        assert_persistable(payload, allow_fixture=self.allow_fixture)

        merged = dict(details)
        if enrichment is not None:
            merged[ENRICHMENT_KEY] = dict(enrichment)
        else:
            merged.setdefault(ENRICHMENT_KEY, {})
        origin = str(payload["origin"])
        incoming = _aware(collected_at)
        sev_rank, kev = self._sort_keys(merged)
        p = self._p

        with self.connection() as conn:
            cur = conn.cursor()
            try:
                cur.execute(
                    "SELECT entity_id, details, collected_at FROM vulnerability_record "
                    f"WHERE tenant_id = {p} AND cve = {p}",
                    (tenant_id, cve),
                )
                existing_row = cur.fetchone()
                existing = None
                if existing_row is not None:
                    existing = self._as_mapping(
                        existing_row, ("entity_id", "details", "collected_at")
                    )
                    # A driver whose row factory returns the wrong arity produces a
                    # KeyError two lines later, which reads like a bug in the store
                    # rather than a misconfigured connection. Say which it is.
                    missing = {"entity_id", "details", "collected_at"} - set(existing)
                    if missing:
                        raise ValueError(
                            "the connection returned a row without "
                            f"{sorted(missing)}; check the driver's row factory "
                            f"(got {type(existing_row).__name__} of length "
                            f"{len(existing_row)})"
                        )

                if existing is None:
                    if dry_run:
                        # Nothing written, including on the create path. Accepting a
                        # flag and ignoring it is worse than not having one.
                        conn.rollback()
                        return UpsertResult(
                            UpsertOutcome.PREVIEWED, reason="dry run: nothing was written"
                        )
                    entity_id = str(entity.get("id") or f"entity-{cve}")
                    cur.execute(
                        "INSERT INTO vulnerability_record "
                        "(tenant_id, cve, entity_id, details, origin, collected_at, "
                        f" severity_rank, kev) VALUES ({p}, {p}, {p}, {self._param(None)}, "
                        f"{p}, {p}, {p}, {p})",
                        (
                            tenant_id, cve, entity_id, self._json(merged), origin,
                            _iso(incoming), sev_rank, self._kev_value(kev),
                        ),
                    )
                    event_type, _ = event_types(created=True)
                    self._record_provenance(conn, tenant_id, cve, event_type, provenance)
                    conn.commit()
                    self.writes += 1
                    self._rows_written.append(cve)
                    return UpsertResult(
                        UpsertOutcome.CREATED, entity_id=entity_id, provenance_id=event_type
                    )

                if incoming < _parse_stamp(existing["collected_at"]):
                    # Mirrors the host importer: an older observation never wins.
                    conn.rollback()
                    return UpsertResult(
                        UpsertOutcome.SKIPPED,
                        entity_id=str(existing["entity_id"]),
                        reason="older observation cannot overwrite a newer one",
                    )

                if dry_run:
                    conn.rollback()
                    return UpsertResult(
                        UpsertOutcome.PREVIEWED,
                        entity_id=str(existing["entity_id"]),
                        reason="dry run: nothing was written",
                    )

                if self._decode(existing["details"]) != merged:
                    cur.execute(
                        "UPDATE vulnerability_record SET details = "
                        f"{self._param(None)}, origin = {p}, collected_at = {p}, "
                        f"severity_rank = {p}, kev = {p} "
                        f"WHERE tenant_id = {p} AND cve = {p}",
                        (
                            self._json(merged), origin, _iso(incoming), sev_rank,
                            self._kev_value(kev), tenant_id, cve,
                        ),
                    )
                    event_type, _ = event_types(created=False)
                    self._record_provenance(conn, tenant_id, cve, event_type, provenance)
                    conn.commit()
                    self.writes += 1
                    self._rows_written.append(cve)
                    return UpsertResult(
                        UpsertOutcome.UPDATED,
                        entity_id=str(existing["entity_id"]),
                        provenance_id=event_type,
                    )

                # Same body: refresh the stamp only. No new evidence, so no event.
                cur.execute(
                    "UPDATE vulnerability_record SET collected_at = "
                    f"{p} WHERE tenant_id = {p} AND cve = {p}",
                    (_iso(incoming), tenant_id, cve),
                )
                conn.commit()
                return UpsertResult(UpsertOutcome.UNCHANGED, entity_id=str(existing["entity_id"]))
            except Exception:
                conn.rollback()
                raise

    def _kev_value(self, kev: int) -> Any:
        return bool(kev) if self.boolean_kev else kev

    @staticmethod
    def _sort_keys(merged: Mapping[str, Any]) -> tuple[int, int]:
        """Materialised sort keys, with the enrichment block as fallback.

        ``ORDER BY`` on the raw severity name sorts alphabetically, which puts
        "low" above "medium". The rank is the ordering this package defines, and
        the dual read matches ``shape_record``'s rule so the API and the sort agree.
        """
        sev = merged.get("severity")
        if sev is None:
            sev = (merged.get(ENRICHMENT_KEY) or {}).get("severity")
        kev = merged.get("kev")
        if kev is None:
            kev = (merged.get(ENRICHMENT_KEY) or {}).get("kev")
        return severity_rank(sev if isinstance(sev, str) else None), (1 if kev else 0)

    def _record_provenance(
        self,
        conn: _Connection,
        tenant_id: str,
        cve: str,
        event_type: str,
        provenance: Mapping[str, Any],
    ) -> None:
        p = self._p
        cur = conn.cursor()
        observed = provenance.get("observed_at")
        cur.execute(
            "INSERT INTO provenance_event "
            "(tenant_id, cve, event_type, source, observed_at, payload) "
            f"VALUES ({p}, {p}, {p}, {p}, {p}, {self._param(None)})",
            (
                tenant_id,
                cve,
                event_type,
                (str(provenance.get("source") or "") or None),
                (_iso(_parse_stamp(observed)) if observed else None),
                self._json(dict(provenance)),
            ),
        )
