"""Operational registry, health checks and metrics logic.

Honesty rules enforced here:
- Service statuses come from *live* checks (e.g. a real database round
  trip), never from assumptions.
- Module statuses are explicit (e.g. "not_implemented") when the module
  does not exist in this build.
- Metrics are real COUNT/MAX queries against the operations database.
  No synthetic numbers, no fabricated CVEs/campaigns/events.
"""
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from app import models
from app.db import SessionLocal, engine

# Modules of the full CICC platform. Statuses are truthful for THIS build:
# only what is actually implemented may report "ok".
MODULE_REGISTRY = [
    {
        "key": "threat_intelligence",
        "kind": "module",
        "name": "Threat Intelligence",
        "status": "not_implemented",
        "detail": "Module not implemented in this build; no intelligence source is connected.",
    },
    {
        "key": "vulnerability_intelligence",
        "kind": "module",
        "name": "Vulnerability Intelligence",
        "status": "not_implemented",
        "detail": "Module not implemented in this build; no CVE/NVD feed is connected.",
    },
    {
        "key": "command_theater_3d",
        "kind": "module",
        "name": "3D Command Theater",
        "status": "not_implemented",
        "detail": "3D theater not implemented in this build.",
    },
    {
        "key": "investigations",
        "kind": "module",
        "name": "Investigations",
        "status": "not_implemented",
        "detail": "Investigation workspace not implemented in this build.",
    },
    {
        "key": "ingestion_pipeline",
        "kind": "module",
        "name": "Intelligence Ingestion",
        "status": "not_configured",
        "detail": "No external source connector is configured; outbound access is restricted to package registries and GitHub.",
    },
    {
        "key": "system_health_ops",
        "kind": "module",
        "name": "System Health & Operations",
        "status": "ok",
        "detail": "This dashboard and its operations API are live.",
    },
]

SEVERITY = {"ok": 0, "not_configured": 1, "not_implemented": 1, "degraded": 2, "down": 3}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def compute_overall(statuses: list[str]) -> str:
    """Aggregate component statuses into an overall system status."""
    if not statuses:
        return "unknown"
    sev = max(SEVERITY.get(s, 4) for s in statuses)
    if sev == 0:
        return "ok"
    if sev == 3:
        return "down"
    if sev >= 4:
        return "unknown"
    return "degraded"


def init_db() -> None:
    """Create tables and seed the (truthful) module registry."""
    models.Base.metadata.create_all(bind=engine)
    with SessionLocal() as s:
        for entry in MODULE_REGISTRY:
            row = s.execute(
                select(models.Component).where(models.Component.key == entry["key"])
            ).scalar_one_or_none()
            if row is None:
                s.add(models.Component(**entry))
        s.commit()


def record_event(level: str, source: str, message: str) -> None:
    """Record a real event in the operations database."""
    with SessionLocal() as s:
        s.add(models.Event(level=level, source=source, message=message))
        s.commit()


def check_database() -> dict:
    """Perform a REAL database health check (round trip SELECT 1)."""
    started = utcnow()
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        latency_ms = round((utcnow() - started).total_seconds() * 1000, 2)
        return {
            "status": "ok",
            "detail": engine.url.render_as_string(hide_password=True),
            "latency_ms": latency_ms,
        }
    except Exception as exc:  # noqa: BLE001 - report any failure honestly
        return {"status": "down", "detail": f"connection failed: {type(exc).__name__}"}


def _iso(dt) -> str | None:
    return dt.isoformat() if dt else None


def _component_dict(row: models.Component) -> dict:
    return {
        "key": row.key,
        "kind": row.kind,
        "name": row.name,
        "status": row.status,
        "detail": row.detail or "",
        "last_check_at": _iso(row.last_check_at),
    }


def _module_rows(s) -> list[dict]:
    rows = (
        s.execute(
            select(models.Component)
            .where(models.Component.kind == "module")
            .order_by(models.Component.key)
        )
        .scalars()
        .all()
    )
    return [_component_dict(r) for r in rows]


def _metrics(s) -> dict:
    entities = s.execute(select(func.count(models.Entity.id))).scalar_one()
    vulnerabilities = s.execute(select(func.count(models.Vulnerability.id))).scalar_one()
    campaigns = s.execute(
        select(func.count(models.Campaign.id)).where(models.Campaign.status == "active")
    ).scalar_one()
    cutoff = utcnow() - timedelta(hours=24)
    recent_entities = s.execute(
        select(func.count(models.Entity.id)).where(models.Entity.created_at >= cutoff)
    ).scalar_one()
    recent_vulns = s.execute(
        select(func.count(models.Vulnerability.id)).where(models.Vulnerability.created_at >= cutoff)
    ).scalar_one()
    last_sync = s.execute(
        select(func.max(models.SyncAttempt.finished_at)).where(models.SyncAttempt.status == "success")
    ).scalar_one()
    return {
        "entities": int(entities),
        "vulnerabilities": int(vulnerabilities),
        "campaigns": int(campaigns),
        "recent_updates_24h": int(recent_entities) + int(recent_vulns),
        "last_successful_sync": _iso(last_sync),
    }


def _activity(s, limit: int) -> list[dict]:
    rows = (
        s.execute(
            select(models.Event)
            .order_by(models.Event.ts.desc(), models.Event.id.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return [
        {
            "id": r.id,
            "ts": _iso(r.ts),
            "level": r.level,
            "source": r.source,
            "message": r.message,
        }
        for r in rows
    ]


def build_overview(limit: int = 50) -> dict:
    db_check = check_database()
    with SessionLocal() as s:
        modules = _module_rows(s)
        metrics = _metrics(s)
        activity = _activity(s, limit)
    services = [
        {
            "key": "api",
            "kind": "service",
            "name": "CICC API Service",
            "status": "ok",
            "detail": "responding to requests",
            "last_check_at": _iso(utcnow()),
        },
        {
            "key": "database",
            "kind": "service",
            "name": "Database",
            "status": db_check["status"],
            "detail": db_check["detail"],
            "last_check_at": _iso(utcnow()),
        },
    ]
    overall = compute_overall([svc["status"] for svc in services])
    return {
        "generated_at": utcnow().isoformat(),
        "overall_status": overall,
        "services": services,
        "modules": modules,
        "metrics": metrics,
        "activity": activity,
        "data_source": "live-ops-database",
    }


def build_components() -> dict:
    db_check = check_database()
    with SessionLocal() as s:
        modules = _module_rows(s)
    services = [
        {
            "key": "api",
            "kind": "service",
            "name": "CICC API Service",
            "status": "ok",
            "detail": "responding to requests",
            "last_check_at": _iso(utcnow()),
        },
        {
            "key": "database",
            "kind": "service",
            "name": "Database",
            "status": db_check["status"],
            "detail": db_check["detail"],
            "last_check_at": _iso(utcnow()),
        },
    ]
    return {"services": services, "modules": modules}


def build_metrics() -> dict:
    with SessionLocal() as s:
        return _metrics(s)


def build_activity(limit: int) -> list[dict]:
    with SessionLocal() as s:
        return _activity(s, limit)
