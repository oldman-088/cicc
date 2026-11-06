"""REAL disposable PostgreSQL integration tests via pgserver (pypi package
embedding actual PostgreSQL binaries). Skipped automatically if pgserver is
not installed. These tests run the ops schema and logic against a real
PostgreSQL server — not SQLite, not mocks."""
import pytest

pgserver = pytest.importorskip("pgserver")

from sqlalchemy import create_engine, select  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app import models, ops  # noqa: E402


@pytest.fixture()
def pg_engine(monkeypatch, tmp_path):
    server = pgserver.get_server(str(tmp_path / "pgdata"))
    url = server.get_uri().replace("postgresql://", "postgresql+psycopg2://", 1)
    engine = create_engine(url, pool_pre_ping=True)
    models.Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    monkeypatch.setattr(ops, "engine", engine)
    monkeypatch.setattr(ops, "SessionLocal", Session)
    monkeypatch.setattr(ops, "SNAPSHOT_MIN_INTERVAL_S", 0)
    ops._overview_cache["data"] = None
    yield engine
    engine.dispose()


def test_pg_real_connectivity_check(pg_engine):
    result = ops.check_database()
    assert result["status"] == "ok"
    assert result["latency_ms"] >= 0
    assert "postgres" in result["detail"]


def test_pg_schema_init_and_registry(pg_engine):
    ops.init_db()
    with ops.SessionLocal() as s:
        rows = s.execute(select(models.Component)).scalars().all()
        keys = {r.key for r in rows}
        assert "threat_intelligence" in keys
        assert "system_health_ops" in keys


def test_pg_overview_and_metrics(pg_engine):
    ops.init_db()
    ov = ops.build_overview()
    assert ov["data_source"] == "live-ops-database"
    services = {s["key"]: s for s in ov["services"]}
    assert services["database"]["status"] == "ok"  # real PG round trip
    assert ov["metrics"]["entities"] == 0  # real zero, not fabricated


def test_pg_task_runs_heartbeats_alerts_snapshots(pg_engine):
    ops.init_db()
    ops.post_heartbeat("pg-w1", "pg test worker")
    ops.record_task_run({"worker": "pg-w1", "queue": "q", "status": "success", "duration_ms": 7})
    ops.record_task_run({"worker": "pg-w1", "queue": "q", "status": "failed", "error": "x"})
    stats = ops.build_task_stats(24)
    assert stats["completed"] == 1 and stats["failed"] == 1 and stats["avg_duration_ms"] == 7.0
    workers = ops.build_workers()["workers"]
    assert any(w["worker"] == "pg-w1" and w["tasks_24h"] == 2 for w in workers)
    # alerts evaluated on PG: db is ok -> no component_down for database
    ops.evaluate_alerts()
    alerts = ops.build_alerts("all", 100)
    assert not any(a["rule"] == "component_down" and a["component_key"] == "database" for a in alerts)
    # real snapshot recorded on PG and readable via history
    ops.build_overview()
    history = ops.build_history(1)
    assert len(history) >= 1
    assert history[0]["entities"] == 0


def test_pg_aware_timestamps_roundtrip(pg_engine):
    ops.init_db()
    ops.record_event("info", "test", "pg timestamp roundtrip")
    events = ops.build_activity(10)
    assert events[0]["ts"].endswith("+00:00")  # timestamptz round trip


def test_pg_concurrent_task_writes(pg_engine):
    """REAL concurrency test on PostgreSQL: 8 threads x 10 task runs each;
    all 80 rows must be visible afterwards (transactional integrity)."""
    import threading

    ops.init_db()
    errors = []

    def worker_fn(tid):
        try:
            for i in range(10):
                ops.record_task_run({"worker": f"t{tid}", "queue": "pg-conc", "status": "success", "duration_ms": i})
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker_fn, args=(t,)) for t in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, f"concurrent write errors: {errors}"
    stats = ops.build_task_stats(24)
    assert stats["completed"] == 80
    with ops.SessionLocal() as s:
        from sqlalchemy import func, select
        n = s.execute(select(func.count(models.TaskRun.id)).where(models.TaskRun.queue == "pg-conc")).scalar_one()
        assert n == 80


def test_pg_connection_failure_reported_as_down(pg_engine):
    """Readiness semantics on PG: a dead engine reports down, not ok."""
    from sqlalchemy import create_engine

    dead = create_engine("postgresql+psycopg2://postgres@127.0.0.1:1/postgres", connect_args={"connect_timeout": 1})
    result = ops.check_database.__wrapped__ if hasattr(ops.check_database, "__wrapped__") else None
    from app import checks

    r = checks.check_database(dead)
    assert r["status"] == "down"
    assert "connection failed" in r["detail"]
