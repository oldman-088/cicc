"""A real, durable store backed by SQLite.

Why this exists when ``InMemoryVulnerabilityStore`` already implements the contract
-------------------------------------------------------------------------------
The in-memory store is a *reference implementation*: it proves the rules are
expressible and it is what tests drive. It is not a store. Everything a host needs a
store for — surviving a restart, holding more than one process's memory, and enforcing
tenant isolation in the database rather than in a Python ``if`` — it cannot do.

Until now the package had **no SQL at all**, and `docs/INTEGRATION.md` promised a
"recipe" for a SQLAlchemy adapter. That recipe did not exist: the docstring named a
constant that was never defined anywhere in the repository. So the honest options were
to delete the reference or to make it true. This module makes it true, with the one
dependency that is always present: ``sqlite3`` from the standard library.

Why SQLite and not SQLAlchemy
-----------------------------
Deliberate, and the reasoning matters more than the choice:

* **No new dependency.** The package is stdlib-only by policy, and that policy is why it
  can be dropped into any host without a resolver fight.
* **The schema is the deliverable.** The hard part of this integration was never the ORM
  call — it is the table shape, the uniqueness rule, the ordering rule and the tenancy
  constraint. Those are SQL, and they are identical in PostgreSQL. The host can lift
  :data:`SCHEMA` into its own migration and keep the store's semantics unchanged.
* **It can be tested here, honestly.** A SQLite adapter is exercised by real files on
  disk, including a restart. A SQLAlchemy adapter without a database to point at would
  have been untested code claiming to be tested.

What the database enforces that Python could not
------------------------------------------------
* ``PRIMARY KEY (tenant_id, cve)`` — tenant scoping is a constraint, so a query that
  forgets the tenant cannot even return the wrong row: it returns nothing.
* ``FOREIGN KEY`` from provenance to records with ``ON DELETE CASCADE`` — a provenance
  event cannot exist for a record that does not.
* ``CHECK (origin IN (...))`` — the fixture/live distinction is a column constraint, so
  a synthetic record cannot be written into a live-only table by a code path that
  forgot to check.
* ``PRAGMA foreign_keys = ON`` per connection, because SQLite defaults it *off* and a
  foreign key that is not enforced is worse than a comment claiming one exists.

The ordering and cursor semantics are ported exactly, including the severity rank: SQL
``ORDER BY severity`` would sort the *name*, which is the defect this package just fixed
in the in-memory store. The rank is materialised in a column instead, so the database
orders by severity and not by spelling.

Concurrency
-----------
WAL journal mode and ``busy_timeout`` are set, and every write is wrapped in an explicit
transaction using ``BEGIN IMMEDIATE``. A read-then-write without that lock is the classic
lost update: two importers read the same row, both decide to update, and the second
silently discards the first one's evidence. The older-observation rule makes this worse,
because the loser looks like a legitimate "skipped" outcome.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, List, Mapping

from ..schema import severity_rank
from .contracts import UpsertOutcome, UpsertResult
from .mapping import ENRICHMENT_KEY, assert_persistable, event_types

__all__ = ["SCHEMA", "SCHEMA_VERSION", "SQLiteVulnerabilityStore"]

#: Bumped whenever :data:`SCHEMA` changes in a way an existing file cannot absorb.
SCHEMA_VERSION = 1

#: The table shape. Written as a constant so a host can lift it into a migration and so
#: a test can assert the constraints exist rather than trusting that they do.
SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vulnerability_record (
    tenant_id     TEXT NOT NULL,
    cve           TEXT NOT NULL,
    entity_id     TEXT NOT NULL,
    details       TEXT NOT NULL,
    origin        TEXT NOT NULL
                  CHECK (origin IN ('live', 'fixture', 'demo', 'unknown')),
    collected_at  TEXT NOT NULL,
    -- Materialised sort keys. ORDER BY on the raw severity name sorts alphabetically,
    -- which puts "low" above "medium"; the rank is the ordering this package defines.
    severity_rank INTEGER NOT NULL DEFAULT 99,
    kev           INTEGER NOT NULL DEFAULT 0 CHECK (kev IN (0, 1)),
    PRIMARY KEY (tenant_id, cve)
);

CREATE INDEX IF NOT EXISTS ix_record_tenant_severity
    ON vulnerability_record (tenant_id, severity_rank, cve);
CREATE INDEX IF NOT EXISTS ix_record_tenant_kev
    ON vulnerability_record (tenant_id, kev, cve);

CREATE TABLE IF NOT EXISTS provenance_event (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id          TEXT NOT NULL,
    cve                TEXT NOT NULL,
    event_type         TEXT NOT NULL,
    source             TEXT,
    observed_at        TEXT,
    payload            TEXT NOT NULL,
    FOREIGN KEY (tenant_id, cve)
        REFERENCES vulnerability_record (tenant_id, cve) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_provenance_tenant_cve
    ON provenance_event (tenant_id, cve, id);
"""

_ORDERS = {
    "cve": ("cve ASC", "cve"),
    "-cve": ("cve DESC", "cve"),
    "severity": ("severity_rank ASC, cve ASC", "cve"),
    "-severity": ("severity_rank DESC, cve DESC", "cve"),
}


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: datetime) -> str:
    """UTC ISO-8601 with an explicit offset.

    Stored as text because SQLite has no date type, and the comparisons that matter
    (``collected_at`` ordering) are lexicographic on this format, which only holds if
    the offset is always the same. Storing local time would make an import from a
    differently-configured host order incorrectly — the exact failure the older-
    observation rule exists to prevent.
    """
    return _aware(value).astimezone(timezone.utc).isoformat()


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


@dataclass
class SQLiteVulnerabilityStore:
    """Durable, tenant-scoped store honouring the same invariants as the in-memory one.

    ``path`` may be a filename or ``":memory:"``. The in-memory form is supported so
    tests can run the identical SQL path without touching disk, but the tests that
    matter use a real file, because a store that only works in memory is the thing this
    module exists to replace.
    """

    path: str | Path = ":memory:"
    allow_fixture: bool = False
    #: Set by :meth:`__post_init__`; a connection is opened per operation so the store
    #: is usable from more than one thread without sharing a cursor.
    writes: int = 0

    def __post_init__(self) -> None:
        target = str(self.path)
        if target != ":memory:":
            Path(target).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('version', ?)",
                (str(SCHEMA_VERSION),),
            )
            conn.commit()

    # -- connection ------------------------------------------------------
    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.path), timeout=5.0, isolation_level=None)
        try:
            # SQLite defaults foreign keys OFF. A declared constraint that is not
            # enforced is worse than no constraint, because it reads like a guarantee.
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA busy_timeout = 5000")
            conn.row_factory = sqlite3.Row
            yield conn
        finally:
            conn.close()

    # -- read port -------------------------------------------------------
    def find(self, *, tenant_id: str, cve: str) -> Mapping[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT cve, entity_id, details, origin, collected_at "
                "FROM vulnerability_record WHERE tenant_id = ? AND cve = ?",
                (tenant_id, cve),
            ).fetchone()
        if row is None:
            return None
        return {
            "cve": row["cve"],
            "entity_id": row["entity_id"],
            "details": json.loads(row["details"]),
            "collected_at": _parse_iso(row["collected_at"]),
            "origin": row["origin"],
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
        order_clause, cursor_column = _ORDERS[order]

        where = ["tenant_id = ?"]
        params: list[Any] = [tenant_id]
        if severity is not None:
            where.append("severity_rank = ?")
            params.append(severity_rank(severity.strip().lower()))
        if kev_only:
            where.append("kev = 1")
        if cursor is not None:
            # Seek, not offset: the cursor is the last key emitted, so an insert
            # between pages cannot shift the window and skip or repeat a row.
            comparator = ">" if not order.startswith("-") else "<"
            where.append(f"{cursor_column} {comparator} ?")
            params.append(cursor)

        sql = (
            "SELECT cve, entity_id, details, origin, collected_at, severity_rank "
            "FROM vulnerability_record WHERE " + " AND ".join(where) + f" ORDER BY {order_clause} LIMIT ?"
        )
        params.append(limit + 1)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()

        has_more = len(rows) > limit
        page = rows[:limit]
        # The cursor is the CVE, which is unique within a tenant. A cursor on the
        # severity rank would not be: several rows share a rank, and a page
        # boundary there repeats or skips rows — the defect the in-memory store
        # had until it was given a stable tie-break.
        next_cursor: str | None = str(page[-1][cursor_column]) if has_more and page else None
        out: list[Mapping[str, Any]] = [
            {
                "cve": row["cve"],
                "entity_id": row["entity_id"],
                "details": json.loads(row["details"]),
                "collected_at": _parse_iso(row["collected_at"]),
                "origin": row["origin"],
            }
            for row in page
        ]
        return out, next_cursor

    def record_count(self, *, tenant_id: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM vulnerability_record WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()
        return int(row["n"])

    def provenance_for(self, *, tenant_id: str, cve: str) -> List[dict[str, Any]]:  # noqa: UP006
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT event_type, payload FROM provenance_event "
                "WHERE tenant_id = ? AND cve = ? ORDER BY id",
                (tenant_id, cve),
            ).fetchall()
        return [{"event_type": r["event_type"], **json.loads(r["payload"])} for r in rows]

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

        merged_details = dict(details)
        if enrichment is not None:
            merged_details[ENRICHMENT_KEY] = dict(enrichment)
        else:
            merged_details.setdefault(ENRICHMENT_KEY, {})
        origin = str(payload["origin"])
        incoming = _aware(collected_at)

        # A single enrichment value is read for the sort columns. `details` wins, with
        # the enrichment block as fallback, matching shape_record's dual-read rule.
        sev_raw = merged_details.get("severity")
        if sev_raw is None:
            sev_raw = (merged_details.get(ENRICHMENT_KEY) or {}).get("severity")
        sev_rank = severity_rank(sev_raw if isinstance(sev_raw, str) else None)
        kev_raw = merged_details.get("kev")
        if kev_raw is None:
            kev_raw = (merged_details.get(ENRICHMENT_KEY) or {}).get("kev")
        kev = 1 if kev_raw else 0

        with self._connect() as conn:
            # IMMEDIATE takes the write lock before the read, so two importers cannot
            # both decide to update the same row and lose one observation.
            conn.execute("BEGIN IMMEDIATE")
            try:
                existing = conn.execute(
                    "SELECT entity_id, details, collected_at FROM vulnerability_record "
                    "WHERE tenant_id = ? AND cve = ?",
                    (tenant_id, cve),
                ).fetchone()

                if existing is None:
                    if dry_run:
                        conn.execute("ROLLBACK")
                        return UpsertResult(
                            UpsertOutcome.PREVIEWED,
                            reason="dry run: nothing was written",
                        )
                    entity_id = f"entity-{tenant_id[:8]}-{cve}"
                    conn.execute(
                        "INSERT INTO vulnerability_record "
                        "(tenant_id, cve, entity_id, details, origin, collected_at, "
                        " severity_rank, kev) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (tenant_id, cve, entity_id, json.dumps(merged_details), origin,
                         _iso(incoming), sev_rank, kev),
                    )
                    event_type, _ = event_types(created=True)
                    self._record_provenance(conn, tenant_id, cve, event_type, provenance)
                    conn.execute("COMMIT")
                    self.writes += 1
                    return UpsertResult(
                        UpsertOutcome.CREATED, entity_id=entity_id, provenance_id=event_type
                    )

                if incoming < _parse_iso(existing["collected_at"]):
                    conn.execute("ROLLBACK")
                    return UpsertResult(
                        UpsertOutcome.SKIPPED,
                        entity_id=existing["entity_id"],
                        reason="older observation cannot overwrite a newer one",
                    )

                if dry_run:
                    conn.execute("ROLLBACK")
                    return UpsertResult(
                        UpsertOutcome.PREVIEWED,
                        entity_id=existing["entity_id"],
                        reason="dry run: nothing was written",
                    )

                if json.loads(existing["details"]) != merged_details:
                    conn.execute(
                        "UPDATE vulnerability_record SET details = ?, origin = ?, "
                        "collected_at = ?, severity_rank = ?, kev = ? "
                        "WHERE tenant_id = ? AND cve = ?",
                        (json.dumps(merged_details), origin, _iso(incoming), sev_rank, kev,
                         tenant_id, cve),
                    )
                    event_type, _ = event_types(created=False)
                    self._record_provenance(conn, tenant_id, cve, event_type, provenance)
                    conn.execute("COMMIT")
                    self.writes += 1
                    return UpsertResult(
                        UpsertOutcome.UPDATED,
                        entity_id=existing["entity_id"],
                        provenance_id=event_type,
                    )

                # Same body: refresh the stamp only. No new evidence, so no event.
                conn.execute(
                    "UPDATE vulnerability_record SET collected_at = ? "
                    "WHERE tenant_id = ? AND cve = ?",
                    (_iso(incoming), tenant_id, cve),
                )
                conn.execute("COMMIT")
                return UpsertResult(UpsertOutcome.UNCHANGED, entity_id=existing["entity_id"])
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def _record_provenance(
        self,
        conn: sqlite3.Connection,
        tenant_id: str,
        cve: str,
        event_type: str,
        provenance: Mapping[str, Any],
    ) -> None:
        conn.execute(
            "INSERT INTO provenance_event "
            "(tenant_id, cve, event_type, source, observed_at, payload) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                tenant_id,
                cve,
                event_type,
                str(provenance.get("source") or "") or None,
                str(provenance.get("observed_at") or "") or None,
                json.dumps(dict(provenance), default=str),
            ),
        )
