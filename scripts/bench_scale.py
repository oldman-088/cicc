#!/usr/bin/env python3
"""Scale benchmark for the ops subsystem (run ad-hoc; uses a throwaway DB).

Inserts a large synthetic-but-structurally-real operational dataset into a
temporary SQLite DB (20k task runs, 5k events, 2k metric snapshots, 1k
heartbeat samples) and measures endpoint-logic latency. The dataset is
generated only inside the temp DB and never committed.

Usage:  cd apps/api && . .venv/bin/activate && python ../../scripts/bench_scale.py
"""
import os
import statistics
import sys
import tempfile
import time
from datetime import timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

tmp = tempfile.mkdtemp(prefix="cicc-bench-")
os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(tmp, "bench.db")

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app import models, ops  # noqa: E402

engine = create_engine(os.environ["DATABASE_URL"], connect_args={"check_same_thread": False})
models.Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
ops.engine = engine
ops.SessionLocal = Session
ops.init_db()

now = ops.utcnow()
with Session() as s:
    s.add_all(
        [
            models.TaskRun(worker=f"w{i % 50}", queue=f"q{i % 5}", status="success" if i % 10 else "failed",
                           duration_ms=i % 500, error=None if i % 10 else f"err{i % 7}",
                           created_at=now - timedelta(minutes=i % 1440))
            for i in range(20000)
        ]
    )
    s.add_all([models.Event(level="info", source="bench", message=f"event {i}", ts=now - timedelta(minutes=i % 1440)) for i in range(5000)])
    s.add_all([models.MetricSnapshot(ts=now - timedelta(minutes=i), entities=i % 100, vulnerabilities=i % 20, campaigns=i % 5, recent_updates_24h=i % 10) for i in range(2000)])
    s.add_all([models.WorkerHeartbeatHistory(worker=f"w{i % 50}", ts=now - timedelta(minutes=i)) for i in range(1000)])
    s.commit()
print(f"seeded 20k task runs / 5k events / 2k snapshots / 1k heartbeat samples into {tmp}")


def bench(label, fn, n=30):
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000)
    times.sort()
    print(f"{label:34s} n={n} p50={times[len(times)//2]:7.2f}ms p95={times[int(len(times)*0.95)]:7.2f}ms max={times[-1]:7.2f}ms")


bench("build_task_stats(168h, 20k rows)", lambda: ops.build_task_stats(168))
bench("build_task_list(limit=100)", lambda: ops.build_task_list(None, None, "failed", 100))
bench("build_task_failures(24h)", lambda: ops.build_task_failures(24))
bench("build_activity(limit=100, 5k)", lambda: ops.build_activity(100))
bench("build_history(168h, 2k snaps)", lambda: ops.build_history(168))
bench("build_worker_history(24h)", lambda: ops.build_worker_history(None, 24))
bench("build_workers()", ops.build_workers)
bench("evaluate_alerts()", ops.evaluate_alerts)
bench("build_overview() full", ops.build_overview)
bench("purge_old_data(force)", lambda: ops.purge_old_data(force=True), n=5)
print("BENCH DONE")
