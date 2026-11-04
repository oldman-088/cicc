import os
import tempfile

# Use an isolated throwaway SQLite database for the test suite BEFORE the
# application modules are imported (db.py reads DATABASE_URL at import time).
os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(tempfile.mkdtemp(prefix="cicc-test-"), "test_ops.db")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c
