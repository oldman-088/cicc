"""CICC Operations API — System Health & Operations backend.

Exposes REAL health checks and operational metrics:
- /live   — liveness: the process is up (always 200 while running)
- /ready  — readiness: core dependencies (database) are actually usable
- /health — liveness + detailed check results (informational)

Never claims a service is healthy without performing an actual check,
never serves synthetic data as live intelligence, never leaks internals:
unhandled errors return a generic 500 and are logged server-side only.
POST bodies are size-limited (413 beyond 16 KiB).
"""
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import ops
from app.checks import MAX_BODY_BYTES
from app.routers import ops as ops_router
from app.schemas import HealthResponse

__version__ = "0.3.0"

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("cicc.ops")

_STARTED = datetime.now(timezone.utc)
_STARTED_TS = _STARTED.timestamp()


@asynccontextmanager
async def lifespan(app: FastAPI):
    ops.init_db()
    ops.record_event("info", "api", "CICC operations service started")
    # M45: restore persisted domain evidence at startup so health/status/metrics
    # are correct immediately after a restart (circuit state itself stays
    # process-local fail-safe — documented in DOMAIN_STATUS_CONTRACT.md)
    from app.coordination.router import _load_persisted_stats as _coord_load
    with ops.SessionLocal() as _s:
        _coord_load(_s, include_unmounted=True)  # M45: persisted history of all kinds visible after restart
    logger.info("operations service started")
    yield
    ops.record_event("info", "api", "CICC operations service stopping — disposing DB engine (safe shutdown)")
    logger.info("operations service stopping — disposing DB engine")
    try:
        ops.engine.dispose()
    except Exception as e:
        logger.warning("engine dispose during shutdown failed: %s", type(e).__name__)
    ops.record_event("info", "api", "CICC operations service stopped")
    logger.info("operations service stopped")


app = FastAPI(title="CICC Operations API", version=__version__, lifespan=lifespan)


@app.middleware("http")
async def limit_request_body(request: Request, call_next):
    """Reject oversized bodies early (413) — protects write endpoints."""
    if request.method in ("POST", "PUT", "PATCH"):
        cl = request.headers.get("content-length")
        try:
            if cl and int(cl) > MAX_BODY_BYTES:
                return JSONResponse({"detail": "payload_too_large"}, status_code=413)
        except ValueError:
            return JSONResponse({"detail": "invalid_content_length"}, status_code=400)
    return await call_next(request)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Generic 500 — details are logged server-side, never sent to clients."""
    logger.exception("unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse({"detail": "internal_error"}, status_code=500)


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
from app.coordination.router import router as coordination_router

app.include_router(coordination_router)


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
