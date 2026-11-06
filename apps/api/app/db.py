"""Database engine/session setup for the CICC operations service.

Defaults to a local SQLite file so the service runs without external
infrastructure. Set DATABASE_URL (e.g. postgresql+psycopg://...) to use
PostgreSQL in real deployments.
"""
import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/ops.db")

connect_args: dict = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False
    if DATABASE_URL not in ("sqlite://", "sqlite:///:memory:"):
        db_path = DATABASE_URL.split("///", 1)[1]
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()
