"""Migrations require an explicit database URL; never silently select a database."""
import os
from alembic import context
from sqlalchemy import create_engine, pool
from app.models import Base

url = os.environ.get("DATABASE_URL")
if not url:
    raise RuntimeError("DATABASE_URL must explicitly identify the migration database")

def run_migrations_offline():
    context.configure(url=url, target_metadata=Base.metadata, literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    engine = create_engine(url, poolclass=pool.NullPool)
    try:
        with engine.connect() as connection:
            context.configure(connection=connection, target_metadata=Base.metadata)
            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
