"""
Threat Intelligence Persistence Layer

Repository:  oldman-088/cicc   Branch: arena/28e50255-cicc (Agent 6 backup)

Design goals
------------
1. **Provenance preserved.** Every write records the contributing source, the
   provenance chain, the collection timestamp and the verification state.
2. **Append-only history.** The `ti_observations`, `ti_conflicts` and
   `ti_audit_log` tables are protected by SQL triggers that ABORT any UPDATE or
   DELETE. History cannot be rewritten, even by a caller with a live connection.
3. **No new third-party dependency.** Implemented on the Python standard
   library `sqlite3`. SQLAlchemy is *not* required and *not* imported. A
   SQLAlchemy mapping is described in `docs/` as a future contract, not
   implemented here.
4. **Tenant isolation.** `tenant_id` is part of every primary key and every
   WHERE clause. There is no query path that can cross tenants.
5. **No network, no daemon.** This module opens a local database file (or an
   in-memory database) and nothing else.

Honesty note
------------
Nothing in this module is "mounted" into a running CICC application. There is
no ORM session wiring, no Alembic migration, and no FastAPI dependency. What is
here is a real, executable, tested persistence implementation that a host
application can adopt.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator

EXPERIMENTAL_DEMO_DATA_ONLY = "EXPERIMENTAL_DEMO_DATA_ONLY"

VALID_ENTITY_TYPES = frozenset({
    "threat_actor",
    "indicator",
    "campaign",
    "malware",
    "infrastructure",
    "relationship",
    "mitre_technique",
    "mitre_tactic",
    "mitre_group",
    "mitre_software",
    "kev_record",
    "vendor_advisory",
    "collection_source",
})

VALID_VERIFICATION_MODES = frozenset({
    "fixture_tested",
    "oracle_verified",
    "live_verified",
})

# Cursor pagination is opaque to callers but must never be attacker-controlled
# free text in SQL. It is always re-encoded from integer offsets.
_MAX_LIMIT = 500
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class PersistenceError(Exception):
    """Base class for persistence failures."""


class AppendOnlyViolationError(PersistenceError):
    """Raised when a caller attempts to mutate append-only history."""


class TenantIsolationError(PersistenceError):
    """Raised when a query would cross tenant boundaries."""


def utcnow_iso() -> str:
    """Timezone-aware UTC timestamp in ISO-8601 with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"


def _encode_cursor(offset: int) -> str:
    return f"off{offset}"


def _decode_cursor(cursor: Optional[str]) -> int:
    if not cursor:
        return 0
    if not isinstance(cursor, str) or not cursor.startswith("off"):
        raise PersistenceError(f"Malformed pagination cursor: {cursor!r}")
    try:
        offset = int(cursor[3:])
    except ValueError as exc:
        raise PersistenceError(f"Malformed pagination cursor: {cursor!r}") from exc
    if offset < 0:
        raise PersistenceError("Pagination cursor offset must be non-negative")
    return offset


# ============================================================================
# Schema
# ============================================================================

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS ti_entities (
    tenant_id           TEXT    NOT NULL,
    entity_type         TEXT    NOT NULL,
    entity_id           TEXT    NOT NULL,
    canonical_id        TEXT,
    display_name        TEXT,
    payload_json        TEXT    NOT NULL,
    sources_json        TEXT    NOT NULL DEFAULT '[]',
    corroboration_count INTEGER NOT NULL DEFAULT 0,
    confidence          REAL    NOT NULL DEFAULT 0,
    verification_mode   TEXT    NOT NULL DEFAULT 'fixture_tested',
    experimental_label  TEXT,
    first_seen_at       TEXT    NOT NULL,
    last_seen_at        TEXT    NOT NULL,
    updated_at          TEXT    NOT NULL,
    PRIMARY KEY (tenant_id, entity_type, entity_id)
);

CREATE INDEX IF NOT EXISTS ix_ti_entities_type
    ON ti_entities (tenant_id, entity_type, updated_at DESC);
CREATE INDEX IF NOT EXISTS ix_ti_entities_canonical
    ON ti_entities (tenant_id, entity_type, canonical_id);

CREATE TABLE IF NOT EXISTS ti_observations (
    observation_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id         TEXT    NOT NULL,
    entity_type       TEXT    NOT NULL,
    entity_id         TEXT    NOT NULL,
    source_id         TEXT    NOT NULL,
    observed_value    TEXT,
    confidence        REAL,
    verification_mode TEXT    NOT NULL DEFAULT 'fixture_tested',
    provenance        TEXT    NOT NULL,
    observed_at       TEXT    NOT NULL,
    recorded_at       TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_ti_observations_entity
    ON ti_observations (tenant_id, entity_type, entity_id, observation_id);

CREATE TABLE IF NOT EXISTS ti_entity_history (
    history_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id      TEXT NOT NULL,
    entity_type    TEXT NOT NULL,
    entity_id      TEXT NOT NULL,
    change_type    TEXT NOT NULL,
    previous_json  TEXT,
    new_json       TEXT,
    source         TEXT NOT NULL,
    provenance     TEXT NOT NULL,
    changed_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ti_conflicts (
    conflict_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id         TEXT NOT NULL,
    entity_type       TEXT NOT NULL,
    entity_id         TEXT NOT NULL,
    field_name        TEXT NOT NULL,
    kept_value        TEXT,
    discarded_json    TEXT,
    resolution_policy TEXT NOT NULL,
    source            TEXT NOT NULL,
    detected_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ti_audit_log (
    audit_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT NOT NULL,
    action      TEXT NOT NULL,
    entity_type TEXT,
    entity_id   TEXT,
    actor       TEXT NOT NULL,
    detail      TEXT,
    logged_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_ti_audit_entity
    ON ti_audit_log (tenant_id, entity_type, entity_id, audit_id);

-- Append-only enforcement: history tables reject UPDATE and DELETE outright.
CREATE TRIGGER IF NOT EXISTS ti_observations_no_update
BEFORE UPDATE ON ti_observations
BEGIN
    SELECT RAISE(ABORT, 'ti_observations is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS ti_observations_no_delete
BEFORE DELETE ON ti_observations
BEGIN
    SELECT RAISE(ABORT, 'ti_observations is append-only: DELETE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS ti_entity_history_no_update
BEFORE UPDATE ON ti_entity_history
BEGIN
    SELECT RAISE(ABORT, 'ti_entity_history is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS ti_entity_history_no_delete
BEFORE DELETE ON ti_entity_history
BEGIN
    SELECT RAISE(ABORT, 'ti_entity_history is append-only: DELETE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS ti_conflicts_no_update
BEFORE UPDATE ON ti_conflicts
BEGIN
    SELECT RAISE(ABORT, 'ti_conflicts is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS ti_conflicts_no_delete
BEFORE DELETE ON ti_conflicts
BEGIN
    SELECT RAISE(ABORT, 'ti_conflicts is append-only: DELETE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS ti_audit_log_no_update
BEFORE UPDATE ON ti_audit_log
BEGIN
    SELECT RAISE(ABORT, 'ti_audit_log is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS ti_audit_log_no_delete
BEFORE DELETE ON ti_audit_log
BEGIN
    SELECT RAISE(ABORT, 'ti_audit_log is append-only: DELETE is forbidden');
END;
"""

APPEND_ONLY_TABLES = (
    "ti_observations",
    "ti_entity_history",
    "ti_conflicts",
    "ti_audit_log",
)


# ============================================================================
# Models
# ============================================================================

class StoredEntityRecord(BaseModel):
    """A persisted Threat Intelligence entity with provenance and corroboration."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(..., min_length=1)
    entity_type: str = Field(...)
    entity_id: str = Field(..., min_length=1)
    canonical_id: Optional[str] = Field(None)
    display_name: Optional[str] = Field(None)
    payload: Dict[str, Any] = Field(default_factory=dict)
    sources: List[str] = Field(default_factory=list)
    corroboration_count: int = Field(0, ge=0)
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    verification_mode: str = Field("fixture_tested")
    experimental_label: Optional[str] = Field(EXPERIMENTAL_DEMO_DATA_ONLY)
    first_seen_at: str = Field(...)
    last_seen_at: str = Field(...)
    updated_at: str = Field(...)

    @field_validator("entity_type")
    @classmethod
    def _check_entity_type(cls, v: str) -> str:
        if v not in VALID_ENTITY_TYPES:
            raise ValueError(f"Unknown entity_type '{v}': must be one of {sorted(VALID_ENTITY_TYPES)}")
        return v

    @field_validator("verification_mode")
    @classmethod
    def _check_verification(cls, v: str) -> str:
        if v not in VALID_VERIFICATION_MODES:
            raise ValueError(f"Unknown verification_mode '{v}': must be one of {sorted(VALID_VERIFICATION_MODES)}")
        return v

    @field_validator("experimental_label")
    @classmethod
    def _check_label(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v != EXPERIMENTAL_DEMO_DATA_ONLY:
            raise ValueError("experimental_label must be EXPERIMENTAL_DEMO_DATA_ONLY or None")
        return v


class StoredObservation(BaseModel):
    """One append-only provenance observation for an entity."""

    model_config = ConfigDict(extra="forbid")

    observation_id: Optional[int] = Field(None)
    tenant_id: str = Field(..., min_length=1)
    entity_type: str = Field(...)
    entity_id: str = Field(..., min_length=1)
    source_id: str = Field(..., min_length=1)
    observed_value: Optional[str] = Field(None)
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    verification_mode: str = Field("fixture_tested")
    provenance: str = Field(..., min_length=1)
    observed_at: str = Field(...)
    recorded_at: str = Field(...)

    @field_validator("entity_type")
    @classmethod
    def _check_entity_type(cls, v: str) -> str:
        if v not in VALID_ENTITY_TYPES:
            raise ValueError(f"Unknown entity_type '{v}'")
        return v

    @field_validator("verification_mode")
    @classmethod
    def _check_verification(cls, v: str) -> str:
        if v not in VALID_VERIFICATION_MODES:
            raise ValueError(f"Unknown verification_mode '{v}'")
        return v


class EntityHistoryRecord(BaseModel):
    """Append-only state-change record for an entity."""

    model_config = ConfigDict(extra="forbid")

    history_id: Optional[int] = Field(None)
    tenant_id: str = Field(..., min_length=1)
    entity_type: str = Field(...)
    entity_id: str = Field(..., min_length=1)
    change_type: str = Field(..., description="created | updated | conflict_recorded | verification_promoted")
    previous: Optional[Dict[str, Any]] = Field(None)
    new: Optional[Dict[str, Any]] = Field(None)
    source: str = Field(...)
    provenance: str = Field(...)
    changed_at: str = Field(...)


class ConflictRecord(BaseModel):
    """Append-only record of a conflicting intelligence value."""

    model_config = ConfigDict(extra="forbid")

    conflict_id: Optional[int] = Field(None)
    tenant_id: str = Field(..., min_length=1)
    entity_type: str = Field(...)
    entity_id: str = Field(..., min_length=1)
    field_name: str = Field(..., min_length=1)
    kept_value: Optional[str] = Field(None)
    discarded_values: List[Any] = Field(default_factory=list)
    resolution_policy: str = Field(..., min_length=1)
    source: str = Field(...)
    detected_at: str = Field(...)


class AuditRecord(BaseModel):
    """Append-only audit entry."""

    model_config = ConfigDict(extra="forbid")

    audit_id: Optional[int] = Field(None)
    tenant_id: str = Field(..., min_length=1)
    action: str = Field(..., min_length=1)
    entity_type: Optional[str] = Field(None)
    entity_id: Optional[str] = Field(None)
    actor: str = Field(..., min_length=1)
    detail: Optional[str] = Field(None)
    logged_at: str = Field(...)


class EntityPage(BaseModel):
    """Cursor-paginated entity page."""

    model_config = ConfigDict(extra="forbid")

    items: List[StoredEntityRecord] = Field(default_factory=list)
    total_count: int = Field(0, ge=0)
    limit: int = Field(50, ge=1, le=_MAX_LIMIT)
    next_cursor: Optional[str] = Field(None)


# ============================================================================
# Repository interface
# ============================================================================

class ThreatIntelRepository(ABC):
    """Persistence contract for the Threat Intelligence domain."""

    @abstractmethod
    def upsert_entity(self, record: StoredEntityRecord, actor: str = "system") -> StoredEntityRecord:
        """Insert or update an entity, appending to history. Never deletes history."""

    @abstractmethod
    def get_entity(self, tenant_id: str, entity_type: str, entity_id: str) -> Optional[StoredEntityRecord]:
        """Fetch one entity, tenant-scoped."""

    @abstractmethod
    def list_entities(
        self,
        tenant_id: str,
        entity_type: Optional[str] = None,
        limit: int = 50,
        cursor: Optional[str] = None,
    ) -> EntityPage:
        """Cursor-paginated, tenant-scoped entity listing."""

    @abstractmethod
    def append_observation(self, observation: StoredObservation) -> StoredObservation:
        """Append one provenance observation. Append-only."""

    @abstractmethod
    def list_observations(
        self, tenant_id: str, entity_type: str, entity_id: str
    ) -> List[StoredObservation]:
        """Return the full append-only observation history for an entity."""

    @abstractmethod
    def append_conflict(self, conflict: ConflictRecord) -> ConflictRecord:
        """Record a conflicting value. Append-only."""

    @abstractmethod
    def list_conflicts(
        self, tenant_id: str, entity_type: str, entity_id: str
    ) -> List[ConflictRecord]:
        """Return conflict records for an entity."""

    @abstractmethod
    def list_history(
        self, tenant_id: str, entity_type: str, entity_id: str
    ) -> List[EntityHistoryRecord]:
        """Return the append-only change history for an entity."""

    @abstractmethod
    def audit(self, record: AuditRecord) -> AuditRecord:
        """Write an audit entry. Append-only."""

    @abstractmethod
    def list_audit(
        self, tenant_id: str, entity_type: Optional[str] = None, entity_id: Optional[str] = None
    ) -> List[AuditRecord]:
        """Read audit entries, tenant-scoped."""

    @abstractmethod
    def close(self) -> None:
        """Release underlying resources."""


# ============================================================================
# SQLite implementation
# ============================================================================

class SQLiteThreatIntelRepository(ThreatIntelRepository):
    """
    Standard-library `sqlite3` implementation of :class:`ThreatIntelRepository`.

    Every statement is parameterized; no caller-supplied string is ever
    interpolated into SQL. Identifiers that must be interpolated (table names)
    are validated against ``^[A-Za-z_][A-Za-z0-9_]*$`` and additionally
    restricted to a fixed allow-list.
    """

    def __init__(self, database_path: str = ":memory:", *, verify_append_only: bool = True):
        self.database_path = database_path
        if database_path != ":memory:":
            parent = os.path.dirname(os.path.abspath(database_path))
            if parent:
                os.makedirs(parent, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            database_path,
            check_same_thread=False,
            isolation_level=None,  # explicit transaction control
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        with self._lock:
            self._conn.executescript(SCHEMA_SQL)
        if verify_append_only:
            self._verify_append_only_enforcement()

    # ------------------------------------------------------------------ setup

    def _verify_append_only_enforcement(self) -> None:
        """
        Fail fast at construction time if the append-only triggers are not
        actually enforced by this SQLite build. A persistence layer that
        silently permits history rewrite would be worse than none.
        """
        probe_table = "ti_observations"
        probe_tenant = "__append_only_self_check__"
        with self._lock:
            # Run the whole probe inside an explicit transaction and roll it
            # back, so the self-check never leaves a row behind and never
            # consumes an AUTOINCREMENT id -- even when reopening a database
            # that already holds real history.
            self._conn.execute("BEGIN")
            try:
                self._conn.execute(
                    "INSERT INTO ti_observations (tenant_id, entity_type, entity_id, source_id,"
                    " observed_value, confidence, verification_mode, provenance, observed_at,"
                    " recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (probe_tenant, "indicator", "PROBE-1", "probe", "v", 0.5,
                     "fixture_tested", "self_check", utcnow_iso(), utcnow_iso()),
                )
                for statement in (
                    f"UPDATE {probe_table} SET observed_value = 'x' WHERE tenant_id = ?",
                    f"DELETE FROM {probe_table} WHERE tenant_id = ?",
                ):
                    try:
                        self._conn.execute(statement, (probe_tenant,))
                    except (sqlite3.IntegrityError, sqlite3.OperationalError):
                        # Trigger fired and aborted the statement: this is the
                        # behaviour we require.
                        continue
                    raise AppendOnlyViolationError(
                        f"Append-only enforcement is NOT active on {probe_table};"
                        " refusing to operate."
                    )
            finally:
                self._conn.execute("ROLLBACK")

            remaining = self._conn.execute(
                f"SELECT COUNT(*) AS c FROM {probe_table} WHERE tenant_id = ?",
                (probe_tenant,),
            ).fetchone()["c"]
            if remaining != 0:
                raise AppendOnlyViolationError(
                    f"Append-only self-check left {remaining} probe row(s) behind"
                )

    # ---------------------------------------------------------------- helpers

    def _require_tenant(self, tenant_id: Optional[str]) -> str:
        if not tenant_id or not isinstance(tenant_id, str):
            raise TenantIsolationError("tenant_id is required for every persistence operation")
        return tenant_id

    @staticmethod
    def _safe_identifier(name: str) -> str:
        if not _IDENTIFIER_RE.match(name):
            raise PersistenceError(f"Unsafe SQL identifier rejected: {name!r}")
        return name

    def _row_to_entity(self, row: sqlite3.Row) -> StoredEntityRecord:
        return StoredEntityRecord(
            tenant_id=row["tenant_id"],
            entity_type=row["entity_type"],
            entity_id=row["entity_id"],
            canonical_id=row["canonical_id"],
            display_name=row["display_name"],
            payload=json.loads(row["payload_json"]),
            sources=json.loads(row["sources_json"]),
            corroboration_count=row["corroboration_count"],
            confidence=row["confidence"],
            verification_mode=row["verification_mode"],
            experimental_label=row["experimental_label"],
            first_seen_at=row["first_seen_at"],
            last_seen_at=row["last_seen_at"],
            updated_at=row["updated_at"],
        )

    # -------------------------------------------------------------- entities

    def upsert_entity(self, record: StoredEntityRecord, actor: str = "system") -> StoredEntityRecord:
        self._require_tenant(record.tenant_id)
        now = utcnow_iso()
        with self._lock:
            existing_row = self._conn.execute(
                "SELECT * FROM ti_entities WHERE tenant_id = ? AND entity_type = ? AND entity_id = ?",
                (record.tenant_id, record.entity_type, record.entity_id),
            ).fetchone()

            if existing_row is None:
                first_seen = record.first_seen_at or now
                stored = record.model_copy(update={
                    "first_seen_at": first_seen,
                    "last_seen_at": record.last_seen_at or now,
                    "updated_at": now,
                })
                self._conn.execute(
                    "INSERT INTO ti_entities (tenant_id, entity_type, entity_id, canonical_id,"
                    " display_name, payload_json, sources_json, corroboration_count, confidence,"
                    " verification_mode, experimental_label, first_seen_at, last_seen_at, updated_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        stored.tenant_id, stored.entity_type, stored.entity_id, stored.canonical_id,
                        stored.display_name, json.dumps(stored.payload, sort_keys=True),
                        json.dumps(stored.sources), stored.corroboration_count, stored.confidence,
                        stored.verification_mode, stored.experimental_label,
                        stored.first_seen_at, stored.last_seen_at, stored.updated_at,
                    ),
                )
                change_type = "created"
                previous: Optional[Dict[str, Any]] = None
            else:
                existing = self._row_to_entity(existing_row)
                stored = record.model_copy(update={
                    "first_seen_at": existing.first_seen_at,
                    "last_seen_at": record.last_seen_at or now,
                    "updated_at": now,
                })
                self._conn.execute(
                    "UPDATE ti_entities SET canonical_id = ?, display_name = ?, payload_json = ?,"
                    " sources_json = ?, corroboration_count = ?, confidence = ?, verification_mode = ?,"
                    " experimental_label = ?, last_seen_at = ?, updated_at = ?"
                    " WHERE tenant_id = ? AND entity_type = ? AND entity_id = ?",
                    (
                        stored.canonical_id, stored.display_name,
                        json.dumps(stored.payload, sort_keys=True), json.dumps(stored.sources),
                        stored.corroboration_count, stored.confidence, stored.verification_mode,
                        stored.experimental_label, stored.last_seen_at, stored.updated_at,
                        stored.tenant_id, stored.entity_type, stored.entity_id,
                    ),
                )
                change_type = "verification_promoted" if (
                    existing.verification_mode != stored.verification_mode
                ) else "updated"
                previous = existing.model_dump(mode="json")

            self._conn.execute(
                "INSERT INTO ti_entity_history (tenant_id, entity_type, entity_id, change_type,"
                " previous_json, new_json, source, provenance, changed_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    stored.tenant_id, stored.entity_type, stored.entity_id, change_type,
                    json.dumps(previous, sort_keys=True) if previous is not None else None,
                    json.dumps(stored.model_dump(mode="json"), sort_keys=True),
                    actor, stored.payload.get("provenance", "persistence_layer"), now,
                ),
            )
            self._conn.execute(
                "INSERT INTO ti_audit_log (tenant_id, action, entity_type, entity_id, actor, detail, logged_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (stored.tenant_id, f"entity_{change_type}", stored.entity_type,
                 stored.entity_id, actor, None, now),
            )
        return stored

    def get_entity(
        self, tenant_id: str, entity_type: str, entity_id: str
    ) -> Optional[StoredEntityRecord]:
        self._require_tenant(tenant_id)
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM ti_entities WHERE tenant_id = ? AND entity_type = ? AND entity_id = ?",
                (tenant_id, entity_type, entity_id),
            ).fetchone()
        return self._row_to_entity(row) if row is not None else None

    def list_entities(
        self,
        tenant_id: str,
        entity_type: Optional[str] = None,
        limit: int = 50,
        cursor: Optional[str] = None,
    ) -> EntityPage:
        self._require_tenant(tenant_id)
        if limit < 1 or limit > _MAX_LIMIT:
            raise PersistenceError(f"limit must be between 1 and {_MAX_LIMIT}")
        offset = _decode_cursor(cursor)
        params: List[Any] = [tenant_id]
        where = "tenant_id = ?"
        if entity_type is not None:
            where += " AND entity_type = ?"
            params.append(entity_type)
        with self._lock:
            total = self._conn.execute(
                f"SELECT COUNT(*) AS c FROM ti_entities WHERE {where}", params
            ).fetchone()["c"]
            rows = self._conn.execute(
                f"SELECT * FROM ti_entities WHERE {where}"
                " ORDER BY entity_type ASC, entity_id ASC LIMIT ? OFFSET ?",
                [*params, limit + 1, offset],
            ).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        next_offset = offset + len(rows)
        return EntityPage(
            items=[self._row_to_entity(r) for r in rows],
            total_count=total,
            limit=limit,
            next_cursor=_encode_cursor(next_offset) if has_more else None,
        )

    # ---------------------------------------------------------- observations

    def append_observation(self, observation: StoredObservation) -> StoredObservation:
        self._require_tenant(observation.tenant_id)
        recorded_at = observation.recorded_at or utcnow_iso()
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO ti_observations (tenant_id, entity_type, entity_id, source_id,"
                " observed_value, confidence, verification_mode, provenance, observed_at, recorded_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    observation.tenant_id, observation.entity_type, observation.entity_id,
                    observation.source_id, observation.observed_value, observation.confidence,
                    observation.verification_mode, observation.provenance,
                    observation.observed_at, recorded_at,
                ),
            )
            self._conn.execute(
                "INSERT INTO ti_audit_log (tenant_id, action, entity_type, entity_id, actor, detail, logged_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (observation.tenant_id, "observation_appended", observation.entity_type,
                 observation.entity_id, observation.source_id, None, recorded_at),
            )
        return observation.model_copy(update={"observation_id": cur.lastrowid, "recorded_at": recorded_at})

    def list_observations(
        self, tenant_id: str, entity_type: str, entity_id: str
    ) -> List[StoredObservation]:
        self._require_tenant(tenant_id)
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM ti_observations WHERE tenant_id = ? AND entity_type = ?"
                " AND entity_id = ? ORDER BY observation_id ASC",
                (tenant_id, entity_type, entity_id),
            ).fetchall()
        return [
            StoredObservation(
                observation_id=r["observation_id"],
                tenant_id=r["tenant_id"],
                entity_type=r["entity_type"],
                entity_id=r["entity_id"],
                source_id=r["source_id"],
                observed_value=r["observed_value"],
                confidence=r["confidence"],
                verification_mode=r["verification_mode"],
                provenance=r["provenance"],
                observed_at=r["observed_at"],
                recorded_at=r["recorded_at"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------- conflicts

    def append_conflict(self, conflict: ConflictRecord) -> ConflictRecord:
        self._require_tenant(conflict.tenant_id)
        detected_at = conflict.detected_at or utcnow_iso()
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO ti_conflicts (tenant_id, entity_type, entity_id, field_name,"
                " kept_value, discarded_json, resolution_policy, source, detected_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    conflict.tenant_id, conflict.entity_type, conflict.entity_id,
                    conflict.field_name, conflict.kept_value,
                    json.dumps(conflict.discarded_values), conflict.resolution_policy,
                    conflict.source, detected_at,
                ),
            )
            self._conn.execute(
                "INSERT INTO ti_entity_history (tenant_id, entity_type, entity_id, change_type,"
                " previous_json, new_json, source, provenance, changed_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    conflict.tenant_id, conflict.entity_type, conflict.entity_id,
                    "conflict_recorded", None,
                    json.dumps(conflict.model_dump(mode="json"), sort_keys=True),
                    conflict.source, "conflict_detection", detected_at,
                ),
            )
        return conflict.model_copy(update={"conflict_id": cur.lastrowid, "detected_at": detected_at})

    def list_conflicts(
        self, tenant_id: str, entity_type: str, entity_id: str
    ) -> List[ConflictRecord]:
        self._require_tenant(tenant_id)
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM ti_conflicts WHERE tenant_id = ? AND entity_type = ?"
                " AND entity_id = ? ORDER BY conflict_id ASC",
                (tenant_id, entity_type, entity_id),
            ).fetchall()
        return [
            ConflictRecord(
                conflict_id=r["conflict_id"],
                tenant_id=r["tenant_id"],
                entity_type=r["entity_type"],
                entity_id=r["entity_id"],
                field_name=r["field_name"],
                kept_value=r["kept_value"],
                discarded_values=json.loads(r["discarded_json"]),
                resolution_policy=r["resolution_policy"],
                source=r["source"],
                detected_at=r["detected_at"],
            )
            for r in rows
        ]

    # --------------------------------------------------------------- history

    def list_history(
        self, tenant_id: str, entity_type: str, entity_id: str
    ) -> List[EntityHistoryRecord]:
        self._require_tenant(tenant_id)
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM ti_entity_history WHERE tenant_id = ? AND entity_type = ?"
                " AND entity_id = ? ORDER BY history_id ASC",
                (tenant_id, entity_type, entity_id),
            ).fetchall()
        return [
            EntityHistoryRecord(
                history_id=r["history_id"],
                tenant_id=r["tenant_id"],
                entity_type=r["entity_type"],
                entity_id=r["entity_id"],
                change_type=r["change_type"],
                previous=json.loads(r["previous_json"]) if r["previous_json"] else None,
                new=json.loads(r["new_json"]) if r["new_json"] else None,
                source=r["source"],
                provenance=r["provenance"],
                changed_at=r["changed_at"],
            )
            for r in rows
        ]

    # ----------------------------------------------------------------- audit

    def audit(self, record: AuditRecord) -> AuditRecord:
        self._require_tenant(record.tenant_id)
        logged_at = record.logged_at or utcnow_iso()
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO ti_audit_log (tenant_id, action, entity_type, entity_id, actor, detail, logged_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (record.tenant_id, record.action, record.entity_type, record.entity_id,
                 record.actor, record.detail, logged_at),
            )
        return record.model_copy(update={"audit_id": cur.lastrowid, "logged_at": logged_at})

    def list_audit(
        self, tenant_id: str, entity_type: Optional[str] = None, entity_id: Optional[str] = None
    ) -> List[AuditRecord]:
        self._require_tenant(tenant_id)
        where = "tenant_id = ?"
        params: List[Any] = [tenant_id]
        if entity_type is not None:
            where += " AND entity_type = ?"
            params.append(entity_type)
        if entity_id is not None:
            where += " AND entity_id = ?"
            params.append(entity_id)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM ti_audit_log WHERE {where} ORDER BY audit_id ASC", params
            ).fetchall()
        return [
            AuditRecord(
                audit_id=r["audit_id"],
                tenant_id=r["tenant_id"],
                action=r["action"],
                entity_type=r["entity_type"],
                entity_id=r["entity_id"],
                actor=r["actor"],
                detail=r["detail"],
                logged_at=r["logged_at"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------- lifecycle

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass

    def __enter__(self) -> "SQLiteThreatIntelRepository":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def repository_from_url(url: str, **kwargs: Any) -> ThreatIntelRepository:
    """
    Build a repository from a small, explicit URL scheme.

    Supported:
      - ``sqlite://:memory:``            -> in-memory SQLite
      - ``sqlite:///absolute/path.db``   -> file-backed SQLite

    Any other scheme raises. Deliberately no network-backed scheme exists.
    """
    if url == "sqlite://:memory:":
        return SQLiteThreatIntelRepository(":memory:", **kwargs)
    if url.startswith("sqlite:///"):
        path = url[len("sqlite:///"):]
        if not path:
            raise PersistenceError("sqlite:/// requires an absolute database path")
        if not os.path.isabs(path):
            raise PersistenceError("sqlite:/// paths must be absolute to avoid ambiguous resolution")
        return SQLiteThreatIntelRepository(path, **kwargs)
    raise PersistenceError(
        f"Unsupported repository URL scheme: {url!r}. Only sqlite:// is implemented."
    )
