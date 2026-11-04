import os
import tempfile

# Default DATABASE_URL for import-time engine creation (per-test isolation
# below rebinds ops.engine/ops.SessionLocal to a fresh SQLite DB per test).
os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="cicc-test-"), "test_ops.db")

import pytest  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app import checks, models, ops, ratelimit  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_db(monkeypatch, tmp_path):
    """Every test gets a fresh, empty operations database (per-test isolation
    so task runs / heartbeats / alerts never leak between tests)."""
    engine = create_engine(
        "sqlite:///" + str(tmp_path / "test.db"),
        connect_args={"check_same_thread": False},
    )
    models.Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    monkeypatch.setattr(ops, "engine", engine)
    monkeypatch.setattr(ops, "SessionLocal", Session)
    ops.init_db()
    ops._overview_cache["data"] = None
    ops._overview_cache["ts"] = 0.0
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    checks.reset_circuit_breakers()
    yield
    engine.dispose()


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c
