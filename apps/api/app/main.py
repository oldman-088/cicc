"""CICC Operations API — System Health & Operations backend.

Exposes REAL health checks and operational metrics:
- /live   — liveness: the process is up (always 200 while running)
- /ready  — readiness: core dependencies (database) are actually usable
- /health — liveness + detailed check results (informational)

Never claims a service is healthy without performing an actual check,
and never serves synthetic data as live intelligence.
"""
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import ops
from app.routers import ops as ops_router
from app.schemas import HealthResponse

__version__ = "0.2.0"

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("cicc.ops")

_STARTED = datetime.now(timezone.utc)
_STARTED_TS = _STARTED.timestamp()


@asynccontextmanager
async def lifespan(app: FastAPI):
    ops.init_db()
    ops.record_event("info", "api", "CICC operations service started")
    logger.info("operations service started")
    yield
    ops.record_event("info", "api", "CICC operations service stopped")
    logger.info("operations service stopped")


app = FastAPI(title="CICC Operations API", version=__version__, lifespan=lifespan)

_origins = os.getenv(
    "CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"
).split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _origins if o.strip()],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(ops_router.router)


@app.get("/")
def root():
    return {"service": "cicc-operations-api", "version": __version__, "docs": "/docs"}


@app.get("/live")
def live():
    """Liveness probe: 200 iff the process is running. Not rate limited."""
    return {"status": "alive", "service": "cicc-api", "version": __version__}


@app.get("/ready")
def ready():
    """Readiness probe: 200 only if the database check actually passes."""
    db = ops.check_database()
    if db["status"] == "ok":
        return {"status": "ready", "checks": {"database": db}}
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=503,
        content={"status": "not_ready", "checks": {"database": db}},
    )


@app.get("/health", response_model=HealthResponse)
def health():
    """Liveness + informational checks. The database check is a real round
    trip; /health never claims health without performing the check."""
    db = ops.check_database()
    return {
        "status": "ok" if db["status"] == "ok" else "degraded",
        "service": "cicc-api",
        "version": __version__,
        "started_at": _STARTED.isoformat(),
        "uptime_seconds": round(time.time() - _STARTED_TS, 3),
        "checks": {"database": db},
    }
