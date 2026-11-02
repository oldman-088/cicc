"""Explicit opt-in; do not silently mount insecure or partially configured routes."""
import base64
import binascii
from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .protected_api import protected_router

def configure_experimental(app: FastAPI, environ) -> None:
    value = environ.get('CICC_EXPERIMENTAL_AUTH', 'false').lower()
    if value == 'false':
        return
    if value != 'true':
        raise RuntimeError('CICC_EXPERIMENTAL_AUTH must be true or false')
    database_url = environ.get('DATABASE_URL')
    key = environ.get('CICC_RATE_LIMIT_KEY_BASE64')
    if not database_url or not key:
        raise RuntimeError('Experimental auth requires DATABASE_URL and CICC_RATE_LIMIT_KEY_BASE64')
    try:
        secret = base64.b64decode(key, validate=True)
    except (ValueError, binascii.Error):
        raise RuntimeError('Invalid rate-limit key encoding') from None
    if len(secret) < 32:
        raise RuntimeError('Rate-limit key must be at least 32 bytes')
    engine = create_engine(database_url, hide_parameters=True, pool_pre_ping=True)
    # SQLite is not an approved deployment target for this API. Tests inject their own factory.
    if engine.dialect.name != 'postgresql':
        engine.dispose()
        raise RuntimeError('Experimental API requires PostgreSQL')
    app.include_router(protected_router(sessionmaker(engine, expire_on_commit=False), secret))
    @app.on_event('shutdown')
    def dispose_engine():
        engine.dispose()
