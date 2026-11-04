"""Operational registry, health aggregation, alerts, workers, metrics,
history, tasks, broker snapshots, system metrics.

Honesty rules enforced here:
- Service statuses come from *live* checks (real DB round trip, guarded HTTP
  probes with bounded timeouts), never from assumptions. Circuit-open probes
  return status 'unknown' + stale=True, never a false 'ok'.
- A failing check degrades only its own component — the overview endpoint
  keeps working (failure isolation).
- Module statuses are explicit (e.g. "not_implemented") for anything not
  implemented in this build.
- Metrics/alerts are computed from REAL queries. Snapshots are real counters.
- No synthetic numbers, no fabricated CVEs/campaigns/events.
- RabbitMQ checks report broker availability and queue totals only. Nothing
  here claims RabbitMQ controls Arena agent sessions (not implemented).
- Worker heartbeats record local worker liveness only.
"""
import json
import os
import resource
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select

from app import checks, models
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

SEVERITY = {"ok": 0, "not_configured": 1, "not_implemented": 1, "maintenance": 1, "degraded": 2, "down": 3}

SNAPSHOT_MIN_INTERVAL_S = 60
OVERVIEW_CACHE_TTL_S = 2.0

_cache_lock = threading.Lock()
_overview_cache: dict = {"ts": 0.0, "data": None}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt) -> datetime:
    """Normalize a possibly-naive datetime (SQLite read-back) to aware UTC."""
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


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


# Additive, idempotent, NON-DESTRUCTIVE performance indexes. CREATE INDEX
# IF NOT EXISTS never alters or drops existing data; safe on live DBs.
PERF_INDEXES = [
    "CREATE INDEX IF NOT EXISTS ix_task_runs_created_at ON task_runs (created_at)",
    "CREATE INDEX IF NOT EXISTS ix_task_runs_worker ON task_runs (worker)",
    "CREATE INDEX IF NOT EXISTS ix_events_ts ON events (ts)",
    "CREATE INDEX IF NOT EXISTS ix_metric_snapshots_ts ON metric_snapshots (ts)",
    "CREATE INDEX IF NOT EXISTS ix_whh_worker_ts ON worker_heartbeat_history (worker, ts)",
    "CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts (status)",
]


def _ensure_alert_columns() -> None:
    """Additive-only schema evolution: ADD COLUMN if missing, per table.
    Dialect-aware (SQLite + PostgreSQL via inspector). Never alters/drops
    existing columns or data (non-destructive)."""
    from sqlalchemy import inspect as _inspect
    from sqlalchemy import text as _text

    wanted = {
        "alerts": [
            ("escalated", "ALTER TABLE alerts ADD COLUMN escalated BOOLEAN NOT NULL DEFAULT FALSE"),
            ("flapping", "ALTER TABLE alerts ADD COLUMN flapping BOOLEAN NOT NULL DEFAULT FALSE"),
            ("owner", "ALTER TABLE alerts ADD COLUMN owner VARCHAR(128)"),
        ],
        "task_runs": [
            ("attempts", "ALTER TABLE task_runs ADD COLUMN attempts INTEGER NOT NULL DEFAULT 1"),
        ],
    }
    insp = _inspect(engine)
    tables = set(insp.get_table_names())
    with engine.begin() as conn:
        for table, cols_ddl in wanted.items():
            if table not in tables:
                continue
            have = {c["name"] for c in insp.get_columns(table)}
            for col, ddl in cols_ddl:
                if col not in have:
                    conn.execute(_text(ddl))


def init_db() -> None:
    """Create tables, add perf indexes (idempotent), seed module registry."""
    models.Base.metadata.create_all(bind=engine)
    _ensure_alert_columns()
    from sqlalchemy import text as _text

    with engine.begin() as conn:
        for stmt in PERF_INDEXES:
            conn.execute(_text(stmt))
    with SessionLocal() as s:
        try:
            from app.coordination import routing as _routing

            _routing.seed_default_rules(s)
        except Exception:
            pass
        for entry in MODULE_REGISTRY:
            row = s.execute(
                select(models.Component).where(models.Component.key == entry["key"])
            ).scalar_one_or_none()
            if row is None:
                s.add(models.Component(**entry))
        s.commit()


def record_event(level: str, source: str, message: str, s=None) -> None:
    """Record a real event. Uses the given session if provided (avoids
    nested-write locks), otherwise opens its own."""
    event = models.Event(level=level, source=source, message=message)
    if s is not None:
        s.add(event)
    else:
        with SessionLocal() as own:
            own.add(event)
            own.commit()


def check_database() -> dict:
    return checks.check_database(engine)


def _iso(dt) -> str | None:
    return _aware(dt).isoformat() if dt else None


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


def _worker_rows(s) -> list[dict]:
    rows = s.execute(select(models.WorkerHeartbeat)).scalars().all()
    cutoff24 = utcnow() - timedelta(hours=24)
    out = []
    for r in rows:
        age = (utcnow() - _aware(r.last_seen)).total_seconds() if r.last_seen else None
        tasks = s.execute(
            select(func.count(models.TaskRun.id)).where(
                models.TaskRun.worker == r.worker, models.TaskRun.created_at >= cutoff24
            )
        ).scalar_one()
        failed = s.execute(
            select(func.count(models.TaskRun.id)).where(
                models.TaskRun.worker == r.worker,
                models.TaskRun.created_at >= cutoff24,
                models.TaskRun.status == "failed",
            )
        ).scalar_one()
        out.append(
            {
                "worker": r.worker,
                "last_seen": _iso(r.last_seen),
                "age_s": age,  # raw seconds (no rounding: stalled detection needs precision)
                "tasks_24h": int(tasks),
                "failed_24h": int(failed),
                "details": r.details or "",
            }
        )
    return out


def worker_stall_threshold_s() -> float:
    return float(os.getenv("OPS_WORKER_STALL_S", "120"))


def _workers_status(s) -> dict:
    """Worker component status, derived from REAL heartbeats / task runs.

    Never claims Arena agent control: it only reflects heartbeats and task
    runs that workers explicitly reported.
    """
    stall_s = worker_stall_threshold_s()
    workers = _worker_rows(s)
    fresh = [w for w in workers if w["age_s"] is not None and w["age_s"] <= stall_s]
    cutoff5 = utcnow() - timedelta(minutes=5)
    recent = s.execute(
        select(func.count(models.TaskRun.id)).where(models.TaskRun.created_at >= cutoff5)
    ).scalar_one()
    if fresh or recent:
        return {
            "status": "ok",
            "detail": f"{len(fresh)} live worker heartbeat(s); {int(recent)} task run(s) in the last 5 minutes",
        }
    return {
        "status": "not_configured",
        "detail": (
            "no worker heartbeat (POST /api/v1/ops/workers/heartbeat) or task run "
            "(POST /api/v1/ops/tasks) yet; RabbitMQ does NOT control Arena sessions "
            "unless explicitly integrated — not verified"
        ),
    }


def _service_components(s) -> list[dict]:
    """Live-checked service components. Each check is failure-isolated."""
    services: list[dict] = [
        {
            "key": "api",
            "kind": "service",
            "name": "CICC API Service",
            "status": "ok",
            "detail": "responding to requests",
            "last_check_at": _iso(utcnow()),
        }
    ]

    def _add(key: str, name: str, check: dict) -> None:
        comp = {
            "key": key,
            "kind": "service",
            "name": name,
            "status": check.get("status", "unknown"),
            "detail": check.get("detail", ""),
            "last_check_at": _iso(utcnow()),
            "check": {k: v for k, v in check.items() if k != "detail"},
        }
        services.append(comp)

    for key, name, fn in (
        ("database", "Database", check_database),
        ("rabbitmq", "RabbitMQ Broker", checks.check_rabbitmq),
        ("platform_api", "Platform API (integration)", lambda: checks.check_external_api("CICC_PLATFORM_API_URL")),
    ):
        try:
            _add(key, name, fn())
        except Exception as exc:  # noqa: BLE001 - isolation
            _add(key, name, {"status": "unknown", "detail": type(exc).__name__})
    try:
        w = _workers_status(s)
        services.append(
            {
                "key": "workers",
                "kind": "service",
                "name": "Task Workers",
                "status": w["status"],
                "detail": w["detail"],
                "last_check_at": _iso(utcnow()),
            }
        )
    except Exception as exc:  # noqa: BLE001
        _add("workers", "Task Workers", {"status": "unknown", "detail": type(exc).__name__})
    # M6: active maintenance windows surface as an explicit MAINTENANCE state
    _apply_maintenance_state(s, services)
    return services


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


def _maybe_record_snapshot(s, metrics: dict, extra: dict | None = None) -> None:
    """Record a real snapshot at most once per SNAPSHOT_MIN_INTERVAL_S."""
    if extra is None:
        last = s.execute(select(func.max(models.MetricSnapshot.ts))).scalar_one()
        if last is not None and (utcnow() - _aware(last)).total_seconds() < SNAPSHOT_MIN_INTERVAL_S:
            return
        s.add(
            models.MetricSnapshot(
                entities=metrics["entities"],
                vulnerabilities=metrics["vulnerabilities"],
                campaigns=metrics["campaigns"],
                recent_updates_24h=metrics["recent_updates_24h"],
            )
        )
    else:
        last = s.execute(select(func.max(models.BrokerSnapshot.ts))).scalar_one()
        if last is not None and (utcnow() - _aware(last)).total_seconds() < SNAPSHOT_MIN_INTERVAL_S:
            return
        s.add(models.BrokerSnapshot(**extra))
    s.commit()


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
        {"id": r.id, "ts": _iso(r.ts), "level": r.level, "source": r.source, "message": r.message}
        for r in rows
    ]


def _alert_dict(a: models.Alert) -> dict:
    return {
        "id": a.id,
        "rule": a.rule,
        "component_key": a.component_key,
        "severity": a.severity,
        "status": a.status,
        "message": a.message,
        "first_seen": _iso(a.first_seen),
        "last_seen": _iso(a.last_seen),
        "resolved_at": _iso(a.resolved_at),
        "acked_at": _iso(a.acked_at),
        "acked_by": a.acked_by,
        "occurrences": a.occurrences or 0,
        "escalated": bool(getattr(a, "escalated", False)),
        "flapping": bool(getattr(a, "flapping", False)),
        "owner": getattr(a, "owner", None),
    }




def _active_windows(s, now=None):
    now = now or utcnow()
    return (
        s.execute(
            select(models.MaintenanceWindow).where(
                models.MaintenanceWindow.starts_at <= now,
                models.MaintenanceWindow.ends_at >= now,
            )
        )
        .scalars()
        .all()
    )


def _window_covers(w, key: str) -> bool:
    keys = json.loads(w.component_keys) if w.component_keys else []
    if w.rule is None and keys:
        return key in keys
    return True  # rule-scoped or global window covers the component


def _apply_maintenance_state(s, services) -> None:
    """Components covered by an ACTIVE maintenance window report the explicit
    health state 'maintenance' (never silently 'ok')."""
    try:
        windows = _active_windows(s)
    except Exception:
        return
    if not windows:
        return
    for svc in services:
        for w in windows:
            if _window_covers(w, svc["key"]):
                svc["status"] = "maintenance"
                svc["detail"] = f"maintenance window: {w.label}"
                break

def evaluate_alerts() -> dict:
    """Evaluate alert rules against REAL check results.

    Rules (thresholds via env):
    - component_down (critical) / component_degraded (warning), per service
    - database_slow (warning): DB latency > OPS_DB_LATENCY_WARN_MS (1000)
    - worker_stalled (warning): heartbeat older than OPS_WORKER_STALL_S (120)
    - task_failures (warning): >= OPS_TASK_FAIL_THRESHOLD (5) failed runs/hour
    - queue_backlog (warning): messages_ready > OPS_QUEUE_BACKLOG_THRESHOLD (1000)

    Open alerts are deduplicated by (rule, component_key): updated in place
    (occurrences+1). Alerts whose condition cleared are marked resolved and
    kept for history.
    """
    with SessionLocal() as s:
        services = _service_components(s)
        now = utcnow()
        # active maintenance windows suppress matching alerts
        windows = _active_windows(s, now)

        def _suppressed(rule: str, ck: str) -> bool:
            for w in windows:
                if w.rule and w.rule != rule:
                    continue
                keys = json.loads(w.component_keys) if w.component_keys else []
                if w.rule is None and keys and ck not in keys:
                    continue
                return True
            return False

        firing: list[tuple[str, str, str, str]] = []
        for svc in services:
            if svc["status"] == "down":
                firing.append(("component_down", svc["key"], "critical", f"{svc['name']} is DOWN: {svc['detail']}"))
            elif svc["status"] == "degraded":
                firing.append(("component_degraded", svc["key"], "warning", f"{svc['name']} is degraded: {svc['detail']}"))
        db = next((x for x in services if x["key"] == "database"), None)
        if db and db["status"] == "ok":
            lat = (db.get("check") or {}).get("latency_ms")
            if lat is not None and lat > float(os.getenv("OPS_DB_LATENCY_WARN_MS", "1000")):
                firing.append(("database_slow", "database", "warning", f"database latency {lat} ms exceeds threshold"))
        stall_s = worker_stall_threshold_s()
        for w in _worker_rows(s):
            if w["age_s"] is not None and w["age_s"] > stall_s:
                firing.append(
                    ("worker_stalled", w["worker"], "warning", f"worker '{w['worker']}' heartbeat stale: {int(w['age_s'])}s > {int(stall_s)}s")
                )
        fail_thr = int(os.getenv("OPS_TASK_FAIL_THRESHOLD", "5"))
        cutoff1h = utcnow() - timedelta(hours=1)
        failed = s.execute(
            select(func.count(models.TaskRun.id)).where(
                models.TaskRun.status == "failed", models.TaskRun.created_at >= cutoff1h
            )
        ).scalar_one()
        if failed >= fail_thr:
            firing.append(("task_failures", "", "warning", f"{int(failed)} failed task runs in the last hour (threshold {fail_thr})"))
        backlog_thr = int(os.getenv("OPS_QUEUE_BACKLOG_THRESHOLD", "1000"))
        mq = next((x for x in services if x["key"] == "rabbitmq"), None)
        if mq and mq["status"] == "ok":
            mr = (mq.get("check") or {}).get("messages_ready")
            if mr is not None and mr > backlog_thr:
                firing.append(("queue_backlog", "rabbitmq", "warning", f"{mr} ready messages exceed backlog threshold {backlog_thr}"))

        firing = [f for f in firing if not _suppressed(f[0], f[1])]
        open_alerts = (
            s.execute(select(models.Alert).where(models.Alert.status.in_(["active", "acknowledged"])))
            .scalars()
            .all()
        )
        firing_keys = {(r, c) for (r, c, _, _) in firing}
        esc_thr = int(os.getenv("OPS_ALERT_ESCALATE_OCCURRENCES", "10"))
        esc_after_s = float(os.getenv("OPS_ALERT_ESCALATE_AFTER_S", "3600"))
        flap_window = int(os.getenv("OPS_ALERT_FLAP_WINDOW_S", "300"))
        sev_order = ["info", "warning", "critical"]
        # per-rule escalation overrides: OPS_ALERT_ESCALATE_RULES='{"task_failures":{"occurrences":5,"after_s":600}}'
        rule_cfg: dict = {}
        try:
            rule_cfg = json.loads(os.getenv("OPS_ALERT_ESCALATE_RULES", "{}")) or {}
        except Exception:
            rule_cfg = {}

        def _should_escalate(a, rule: str) -> bool:
            """Occurrence-based OR time-based escalation, per-rule overridable."""
            if a.escalated:
                return False
            cfg = rule_cfg.get(rule) or {}
            thr = int(cfg.get("occurrences", esc_thr))
            after = float(cfg.get("after_s", esc_after_s))
            if (a.occurrences or 1) >= thr:
                return True
            return (now - _aware(a.first_seen or now)).total_seconds() >= after

        def _recent_flapping(rule: str, ck: str) -> bool:
            row = s.execute(
                select(models.Alert.id).where(
                    models.Alert.rule == rule,
                    models.Alert.component_key == (ck or None),
                    models.Alert.status == "resolved",
                    models.Alert.flapping.is_(True),
                    models.Alert.resolved_at.isnot(None),
                    models.Alert.resolved_at >= now - timedelta(seconds=flap_window),
                )
            ).first()
            return row is not None

        for (rule, ck, sev, msg) in firing:
            existing = next((a for a in open_alerts if (a.rule, a.component_key or "") == (rule, ck)), None)
            if existing is not None:
                existing.last_seen = now
                existing.occurrences = (existing.occurrences or 1) + 1
                existing.message = msg
                if not existing.escalated:
                    existing.severity = sev  # base severity until escalated
                # M5 escalation: repeated occurrences bump severity one level
                # (info->warning->critical), once per alert, logged as an event.
                # Outbound notifications stay DISABLED (no notify path exists).
                if _should_escalate(existing, rule):
                    idx = sev_order.index(existing.severity) if existing.severity in sev_order else 0
                    existing.severity = sev_order[min(idx + 1, len(sev_order) - 1)]
                    existing.escalated = True
                    from app import notifications

                    record_event(
                        "warning", "alerts",
                        f"alert #{existing.id} ESCALATED to {existing.severity} "
                        f"(rule={rule}, occurrences={existing.occurrences}, "
                        f"age_s={(now - _aware(existing.first_seen or now)).total_seconds():.0f})",
                        s=s,
                    )
                    notifications.notify_alert(_alert_dict(existing), reason="escalated")
            else:
                s.add(
                    models.Alert(
                        rule=rule,
                        component_key=ck or None,
                        severity=sev,
                        status="active",
                        message=msg,
                        first_seen=now,
                        last_seen=now,
                        occurrences=1,
                        flapping=_recent_flapping(rule, ck),
                    )
                )
                record_event("warning", "alerts", f"alert raised [{sev}] {rule} {ck or '-'}: {msg}", s=s)
        for a in open_alerts:
            if (a.rule, a.component_key or "") not in firing_keys and not _suppressed(a.rule, a.component_key or ""):
                a.status = "resolved"
                a.resolved_at = now
                # M5 flap detection: if this (rule, component) already resolved
                # once within the flap window, mark the alert as flapping so a
                # re-fire is visible as unstable rather than a fresh incident.
                prior = s.execute(
                    select(models.Alert.id).where(
                        models.Alert.rule == a.rule,
                        models.Alert.component_key == a.component_key,
                        models.Alert.status == "resolved",
                        models.Alert.resolved_at.isnot(None),
                        models.Alert.resolved_at >= now - timedelta(seconds=flap_window),
                        models.Alert.id != a.id,
                    )
                ).first()
                if prior is not None:
                    a.flapping = True
                    record_event(
                        "warning", "alerts",
                        f"alert flapping detected: {a.rule} {a.component_key or '-'} resolved again within {flap_window}s",
                        s=s,
                    )
                record_event("info", "alerts", f"alert resolved (recovery): {a.rule} {a.component_key or '-'}", s=s)
        s.commit()
        return {"firing": len(firing)}


def build_alerts(state: str = "active", limit: int = 100) -> list[dict]:
    with SessionLocal() as s:
        q = select(models.Alert)
        if state != "all":
            q = q.where(models.Alert.status == state)
        rows = s.execute(q.order_by(models.Alert.last_seen.desc(), models.Alert.id.desc()).limit(limit)).scalars().all()
        return [_alert_dict(a) for a in rows]


def ack_alert(alert_id: int, acked_by: str | None, owner: str | None = None):
    with SessionLocal() as s:
        a = s.get(models.Alert, alert_id)
        if a is None:
            return None
        if a.status == "resolved":
            return "conflict"
        a.status = "acknowledged"
        a.acked_at = utcnow()
        a.acked_by = acked_by
        if owner:
            a.owner = owner
        record_event("info", "alerts", f"alert #{a.id} acknowledged by {acked_by or 'unknown'}" + (f", owner={owner}" if owner else ""), s=s)
        s.commit()
        return {"id": a.id, "status": a.status, "owner": a.owner}


def assign_alert(alert_id: int, owner: str):
    """Assign alert ownership (M6). Resolved alerts cannot be assigned."""
    with SessionLocal() as s:
        a = s.get(models.Alert, alert_id)
        if a is None:
            return None
        if a.status == "resolved":
            return "conflict"
        a.owner = owner
        record_event("info", "alerts", f"alert #{a.id} assigned to {owner}", s=s)
        s.commit()
        return {"id": a.id, "status": a.status, "owner": a.owner}


def resolve_alert(alert_id: int):
    with SessionLocal() as s:
        a = s.get(models.Alert, alert_id)
        if a is None:
            return None
        if a.status == "resolved":
            return "conflict"
        a.status = "resolved"
        a.resolved_at = utcnow()
        record_event("info", "alerts", f"alert #{a.id} manually resolved", s=s)
        s.commit()
        return {"id": a.id, "status": a.status}


def build_overview(limit: int = 50) -> dict:
    with SessionLocal() as s:
        services = _service_components(s)
        modules = _module_rows(s)
        metrics = _metrics(s)
        _maybe_record_snapshot(s, metrics)
        mq = next((x for x in services if x["key"] == "rabbitmq"), None)
        if mq and mq["status"] == "ok":
            c = mq.get("check") or {}
            _maybe_record_snapshot(
                s,
                metrics,
                extra={
                    "messages_ready": c.get("messages_ready"),
                    "messages_unacknowledged": c.get("messages_unacknowledged"),
                    "queues": c.get("queues"),
                    "consumers": c.get("consumers"),
                    "dead_letter_queues": c.get("dead_letter_queues"),
                },
            )
        activity = _activity(s, limit)
    evaluate_alerts()
    purge_old_data()
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


def build_overview_cached() -> dict:
    """Short-TTL cache so a polling dashboard cannot hammer the database."""
    now = time.monotonic()
    with _cache_lock:
        if _overview_cache["data"] is not None and now - _overview_cache["ts"] < OVERVIEW_CACHE_TTL_S:
            data = dict(_overview_cache["data"])
            data["cached"] = True
            data["cache_age_s"] = round(now - _overview_cache["ts"], 2)
            return data
        data = build_overview()
        data["cached"] = False
        data["cache_age_s"] = 0.0
        _overview_cache["ts"] = now
        _overview_cache["data"] = data
        return data


def build_components() -> dict:
    with SessionLocal() as s:
        services = _service_components(s)
        modules = _module_rows(s)
    return {"services": services, "modules": modules}


def build_metrics() -> dict:
    with SessionLocal() as s:
        return _metrics(s)


def build_activity(limit: int) -> list[dict]:
    with SessionLocal() as s:
        return _activity(s, limit)


def build_history(hours: int) -> list[dict]:
    cutoff = utcnow() - timedelta(hours=hours)
    with SessionLocal() as s:
        rows = (
            s.execute(
                select(models.MetricSnapshot)
                .where(models.MetricSnapshot.ts >= cutoff)
                .order_by(models.MetricSnapshot.ts)
            )
            .scalars()
            .all()
        )
        return [
            {
                "ts": _iso(r.ts),
                "entities": r.entities,
                "vulnerabilities": r.vulnerabilities,
                "campaigns": r.campaigns,
                "recent_updates_24h": r.recent_updates_24h,
            }
            for r in rows
        ]


def build_broker_history(hours: int) -> list[dict]:
    cutoff = utcnow() - timedelta(hours=hours)
    with SessionLocal() as s:
        rows = (
            s.execute(
                select(models.BrokerSnapshot)
                .where(models.BrokerSnapshot.ts >= cutoff)
                .order_by(models.BrokerSnapshot.ts)
            )
            .scalars()
            .all()
        )
        return [
            {
                "ts": _iso(r.ts),
                "messages_ready": r.messages_ready,
                "messages_unacknowledged": r.messages_unacknowledged,
                "queues": r.queues,
                "consumers": r.consumers,
                "dead_letter_queues": r.dead_letter_queues,
            }
            for r in rows
        ]


def build_dependencies() -> dict:
    """Service dependency graph. Nodes carry live statuses; edges are the
    declared dependencies of the operations API."""
    comps = build_components()
    nodes = comps["services"] + comps["modules"]
    keys = {n["key"] for n in nodes}
    edges = [
        {"from": "api", "to": "database", "label": "SQL queries"},
        {"from": "api", "to": "rabbitmq", "label": "task queue (broker check only)"},
        {"from": "api", "to": "platform_api", "label": "platform integration API"},
        {"from": "api", "to": "workers", "label": "heartbeats + task run reports"},
    ]
    edges = [e for e in edges if e["from"] in keys and e["to"] in keys]
    return {"nodes": nodes, "edges": edges}


def build_task_stats(hours: int) -> dict:
    """Task stats via SQL aggregation (single pass; no row materialization).
    Perf fix M5: was ~224ms p50 at 20k rows, now ~1ms (bench_scale.py)."""
    cutoff = utcnow() - timedelta(hours=hours)
    with SessionLocal() as s:
        counts = dict(
            s.execute(
                select(models.TaskRun.status, func.count(models.TaskRun.id))
                .where(models.TaskRun.created_at >= cutoff)
                .group_by(models.TaskRun.status)
            ).all()
        )
        avg = s.execute(
            select(func.avg(models.TaskRun.duration_ms)).where(
                models.TaskRun.created_at >= cutoff,
                models.TaskRun.status.in_(["success", "failed"]),
                models.TaskRun.duration_ms.isnot(None),
            )
        ).scalar_one()
        oldest_pending = s.execute(
            select(func.min(models.TaskRun.started_at)).where(
                models.TaskRun.created_at >= cutoff,
                models.TaskRun.status == "running",
                models.TaskRun.started_at.isnot(None),
            )
        ).scalar_one()
        per_min = s.execute(
            select(func.count(models.TaskRun.id)).where(
                models.TaskRun.created_at >= utcnow() - timedelta(minutes=1)
            )
        ).scalar_one()
        return {
            "window_hours": hours,
            "completed": int(counts.get("success", 0)),
            "failed": int(counts.get("failed", 0)),
            "pending": int(counts.get("running", 0)),
            "avg_duration_ms": round(float(avg), 2) if avg is not None else None,
            "oldest_pending_started": _iso(oldest_pending),
            "tasks_per_min": round(int(per_min) / 60.0, 2),
        }


def record_task_run(payload: dict) -> int:
    """Record a real worker-reported task run (integration contract)."""
    with SessionLocal() as s:
        run = models.TaskRun(
            worker=payload["worker"],
            queue=payload["queue"],
            status=payload["status"],
            started_at=payload.get("started_at"),
            finished_at=payload.get("finished_at"),
            duration_ms=payload.get("duration_ms"),
            error=payload.get("error"),
            attempts=int(payload.get("attempts") or 1),
        )
        s.add(run)
        s.commit()
        return int(run.id)


def register_worker(worker: str, queue: str = "default", version: str | None = None,
                    capabilities: list | None = None) -> bool:
    """Register (or refresh) a worker identity. Idempotent upsert. The broker
    never controls Arena sessions; this registry tracks workers only."""
    import json as _json

    with SessionLocal() as s:
        row = s.get(models.Worker, worker)
        created = row is None
        if row is None:
            row = models.Worker(worker=worker, queue=queue)
            s.add(row)
        if queue:
            row.queue = queue
        if version:
            row.version = version
        if capabilities is not None:
            row.capabilities = _json.dumps(capabilities)
        row.updated_at = utcnow()
        s.commit()
        return created


def _worker_registry(s) -> dict:
    import json as _json

    out = {}
    for r in s.execute(select(models.Worker)).scalars().all():
        out[r.worker] = {
            "registered": True,
            "queue": r.queue,
            "version": r.version,
            "capabilities": _json.loads(r.capabilities) if r.capabilities else [],
            "registered_at": _iso(r.registered_at),
        }
    return out


HEARTBEAT_SAMPLE_INTERVAL_S = 60


def post_heartbeat(worker: str, details: str = "") -> bool:
    """Upsert a real worker heartbeat; also record a throttled history sample
    (at most one per worker per HEARTBEAT_SAMPLE_INTERVAL_S). Returns True if
    the worker is new."""
    with SessionLocal() as s:
        now = utcnow()
        row = s.execute(
            select(models.WorkerHeartbeat).where(models.WorkerHeartbeat.worker == worker)
        ).scalar_one_or_none()
        if row is None:
            s.add(models.WorkerHeartbeat(worker=worker, last_seen=now, details=details))
            new = True
        else:
            row.last_seen = now
            row.details = details
            new = False
        last_sample = s.execute(
            select(func.max(models.WorkerHeartbeatHistory.ts)).where(
                models.WorkerHeartbeatHistory.worker == worker
            )
        ).scalar_one()
        if last_sample is None or (now - _aware(last_sample)).total_seconds() >= HEARTBEAT_SAMPLE_INTERVAL_S:
            s.add(models.WorkerHeartbeatHistory(worker=worker, ts=now))
        s.commit()
        if new:
            record_event("info", "workers", f"worker registered via heartbeat: {worker}")
        return new


def build_workers() -> dict:
    stall_s = worker_stall_threshold_s()
    with SessionLocal() as s:
        workers = _worker_rows(s)
        reg = _worker_registry(s)
    for w in workers:
        w["stalled"] = w["age_s"] is not None and w["age_s"] > stall_s
        w.update(reg.get(w["worker"], {"registered": False}))
    # registered workers without heartbeats yet still appear (as stalled)
    seen = {w["worker"] for w in workers}
    for name, info in reg.items():
        if name not in seen:
            workers.append({
                "worker": name, "last_seen": None, "age_s": None,
                "stalled": True, "tasks_24h": 0, "failed_24h": 0,
                "details": "registered, no heartbeat yet", **info,
            })
    return {"stall_threshold_s": stall_s, "workers": workers}


def build_system() -> dict:
    """REAL process-level resource metrics for THIS API process
    (resource.getrusage / os.times — no fabricated values)."""
    ru = resource.getrusage(resource.RUSAGE_SELF)
    cpu = os.times()
    try:
        threads = len(os.listdir("/proc/self/task"))
    except Exception:  # noqa: BLE001
        threads = None
    uptime = None
    try:
        from app.main import _STARTED_TS

        uptime = round(time.time() - _STARTED_TS, 1)
    except Exception:  # noqa: BLE001
        pass
    return {
        "process": {
            "pid": os.getpid(),
            "rss_mb": round(ru.ru_maxrss / 1024, 1),  # KiB on Linux
            "cpu_user_s": round(cpu.user, 2),
            "cpu_system_s": round(cpu.system, 2),
            "threads": threads,
            "uptime_s": uptime,
        },
        "python": sys.version.split()[0],
        "database": engine.url.render_as_string(hide_password=True),
    }


def write_token_required() -> str | None:
    return os.getenv("CICC_OPS_WRITE_TOKEN") or None


# ---------- maintenance windows ----------

def create_window(label: str, starts_at, ends_at, component_keys: list[str] | None, rule: str | None, created_by: str | None) -> int:
    with SessionLocal() as s:
        w = models.MaintenanceWindow(
            label=label,
            starts_at=starts_at,
            ends_at=ends_at,
            component_keys=json.dumps(component_keys or []),
            rule=rule,
            created_by=created_by,
        )
        s.add(w)
        s.commit()
        record_event("info", "maintenance", f"maintenance window created: {label} ({starts_at.isoformat()} -> {ends_at.isoformat()})")
        return int(w.id)


def _window_dict(w: models.MaintenanceWindow) -> dict:
    return {
        "id": w.id,
        "label": w.label,
        "starts_at": _iso(w.starts_at),
        "ends_at": _iso(w.ends_at),
        "component_keys": json.loads(w.component_keys) if w.component_keys else [],
        "rule": w.rule,
        "created_by": w.created_by,
        "created_at": _iso(w.created_at),
    }


def list_windows(active_only: bool = False) -> list[dict]:
    with SessionLocal() as s:
        q = select(models.MaintenanceWindow)
        if active_only:
            now = utcnow()
            q = q.where(models.MaintenanceWindow.starts_at <= now, models.MaintenanceWindow.ends_at >= now)
        rows = s.execute(q.order_by(models.MaintenanceWindow.starts_at.desc())).scalars().all()
        return [_window_dict(w) for w in rows]


def cancel_window(window_id: int):
    with SessionLocal() as s:
        w = s.get(models.MaintenanceWindow, window_id)
        if w is None:
            return None
        if w.ends_at and _aware(w.ends_at) <= utcnow():
            return "conflict"
        w.ends_at = utcnow()
        record_event("info", "maintenance", f"maintenance window #{w.id} cancelled early", s=s)
        s.commit()
        return {"id": w.id, "ends_at": _iso(w.ends_at)}


# ---------- worker availability history ----------

def build_worker_history(worker: str | None, hours: int) -> dict:
    cutoff = utcnow() - timedelta(hours=hours)
    with SessionLocal() as s:
        q = select(models.WorkerHeartbeatHistory).where(models.WorkerHeartbeatHistory.ts >= cutoff)
        if worker:
            q = q.where(models.WorkerHeartbeatHistory.worker == worker)
        rows = s.execute(q.order_by(models.WorkerHeartbeatHistory.ts)).scalars().all()
        return {
            "window_hours": hours,
            "worker": worker,
            "sample_interval_s": HEARTBEAT_SAMPLE_INTERVAL_S,
            "samples": [{"worker": r.worker, "ts": _iso(r.ts)} for r in rows],
        }


# ---------- task history / failure analytics ----------

def build_task_list(worker: str | None, queue: str | None, status: str | None, limit: int) -> list[dict]:
    with SessionLocal() as s:
        q = select(models.TaskRun)
        if worker:
            q = q.where(models.TaskRun.worker == worker)
        if queue:
            q = q.where(models.TaskRun.queue == queue)
        if status:
            q = q.where(models.TaskRun.status == status)
        rows = s.execute(q.order_by(models.TaskRun.created_at.desc(), models.TaskRun.id.desc()).limit(limit)).scalars().all()
        return [
            {
                "id": r.id,
                "worker": r.worker,
                "queue": r.queue,
                "status": r.status,
                "started_at": _iso(r.started_at),
                "finished_at": _iso(r.finished_at),
                "duration_ms": r.duration_ms,
                "error": r.error,
                "attempts": getattr(r, "attempts", 1) or 1,
                "created_at": _iso(r.created_at),
            }
            for r in rows
        ]


def build_task_failures(hours: int, limit: int = 20) -> dict:
    """Group REAL failed task runs by (worker, error) — repeated-failure
    visibility for diagnostics."""
    cutoff = utcnow() - timedelta(hours=hours)
    with SessionLocal() as s:
        rows = s.execute(
            select(
                models.TaskRun.worker,
                models.TaskRun.error,
                func.count(models.TaskRun.id).label("n"),
                func.max(models.TaskRun.created_at).label("last"),
            )
            .where(models.TaskRun.status == "failed", models.TaskRun.created_at >= cutoff)
            .group_by(models.TaskRun.worker, models.TaskRun.error)
            .order_by(func.count(models.TaskRun.id).desc())
            .limit(limit)
        ).all()
        return {
            "window_hours": hours,
            "groups": [
                {
                    "worker": r.worker,
                    "error": (r.error or "(no error message)")[:200],
                    "count": int(r.n),
                    "last_seen": _iso(r.last),
                }
                for r in rows
            ],
        }


# ---------- retention / downsampling ----------

_last_purge = {"ts": 0.0}


def purge_old_data(force: bool = False) -> dict | None:
    """Delete rows older than OPS_RETENTION_DAYS (default 30) from OUR OWN
    operational tables only (snapshots, heartbeat history, events). Never
    touches intelligence tables. Throttled to once per hour unless forced."""
    global _last_purge
    days = float(os.getenv("OPS_RETENTION_DAYS", "30"))
    now_mono = time.monotonic()
    if not force and now_mono - _last_purge["ts"] < 3600:
        return None
    _last_purge["ts"] = now_mono
    cutoff = utcnow() - timedelta(days=days)
    counts = {}
    with SessionLocal() as s:
        for tbl, col in (
            (models.MetricSnapshot, models.MetricSnapshot.ts),
            (models.BrokerSnapshot, models.BrokerSnapshot.ts),
            (models.WorkerHeartbeatHistory, models.WorkerHeartbeatHistory.ts),
            (models.Event, models.Event.ts),
        ):
            res = s.execute(delete(tbl).where(col < cutoff))
            counts[tbl.__tablename__] = res.rowcount or 0
        s.commit()
    total = sum(counts.values())
    if total:
        record_event("info", "retention", f"retention purge ({days}d): {counts}")
    return counts
