"""CICC Operations API — System Health & Operations backend.

Exposes REAL health checks and operational metrics. It never claims a
service is healthy without performing an actual check, and never serves
synthetic data as live intelligence.
"""
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import ops
from app.routers import ops as ops_router
from app.schemas import HealthResponse

__version__ = "0.1.0"

_STARTED = datetime.now(timezone.utc)
_STARTED_TS = _STARTED.timestamp()


@asynccontextmanager
async def lifespan(app: FastAPI):
    ops.init_db()
    ops.record_event("info", "api", "CICC operations service started")
    yield


app = FastAPI(title="CICC Operations API", version=__version__, lifespan=lifespan)

_origins = os.getenv(
    "CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"
).split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _origins if o.strip()],
    allow_methods=["GET"],
    allow_headers=["*"],
)

app.include_router(ops_router.router)


@app.get("/")
def root():
    return {"service": "cicc-operations-api", "version": __version__, "docs": "/docs"}


@app.get("/health", response_model=HealthResponse)
def health():
    """Real health check: this endpoint responding means the API is up;
    the database check performs an actual round trip."""
    db = ops.check_database()
    return {
        "status": "ok" if db["status"] == "ok" else "degraded",
        "service": "cicc-api",
        "version": __version__,
        "started_at": _STARTED.isoformat(),
        "uptime_seconds": round(time.time() - _STARTED_TS, 3),
        "checks": {"database": db},
    }
