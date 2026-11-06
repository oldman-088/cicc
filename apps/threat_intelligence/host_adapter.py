"""Host-owned authenticated mounting adapter for the controlled TI router.

This module does not authenticate users, deploy roles or invent host contracts.
The host must supply verified principal resolution, a per-actor PostgreSQL pool,
a security-event sink and an optional gateway trace link. All state is per app
or per request; no caller-supplied tenant or actor is accepted as identity.
"""
from __future__ import annotations

import asyncio
import inspect
import math
from typing import Callable
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.engine import Engine
from starlette.concurrency import run_in_threadpool

from .relationship_api import Principal, get_audit, get_principal, get_store, router
from .relationship_storage import TrustedWritePostgresRelationshipStore


async def _invoke(fn, *args):
    if inspect.iscoroutinefunction(fn):
        return await fn(*args)
    result = await run_in_threadpool(fn, *args)
    return await result if inspect.isawaitable(result) else result


def _synchronous_audit(callback, event):
    result = callback(event)
    if inspect.isawaitable(result):
        if inspect.iscoroutine(result):
            result.close()
        raise RuntimeError('security audit must complete synchronously')


class _SecurityEvents:
    """Emit only trusted metadata for rejected/failed subapplication calls."""
    def __init__(self, app, callback):
        self.app, self.callback = app, callback

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        scope.setdefault('state', {})['ti_verified_identity'] = None
        rejected = False
        started = False
        async def wrapped(message):
            nonlocal rejected, started
            if rejected:
                return
            if message['type'] == 'http.response.start':
                status = message['status']
                if status in (401,403,422) or status >= 500:
                    event = {'action':'host.security.response', 'status':status}
                    identity = scope['state'].get('ti_verified_identity')
                    if isinstance(identity, tuple) and len(identity) == 2:
                        event['subject'], event['tenant_id'] = identity
                    correlations = [v for k, v in message.get('headers', []) if k.lower() == b'x-correlation-id']
                    if len(correlations) == 1:
                        try:
                            event['correlation_id'] = str(UUID(correlations[0].decode('ascii')))
                        except (ValueError, UnicodeError):
                            pass
                    try:
                        await run_in_threadpool(_synchronous_audit, self.callback, event)
                    except Exception:
                        rejected = True
                        started = True
                        headers = [(b'content-type',b'application/json')]
                        if 'correlation_id' in event:
                            headers.append((b'x-correlation-id', event['correlation_id'].encode('ascii')))
                        await send({'type':'http.response.start','status':503, 'headers':headers})
                        await send({'type':'http.response.body','body':b'{"detail":"Security audit unavailable"}'})
                        return
            if message['type'] == 'http.response.start':
                started = True
            await send(message)
        try:
            return await self.app(scope, receive, wrapped)
        except Exception:
            if started:
                raise
            await wrapped({'type':'http.response.start','status':500,
                           'headers':[(b'content-type',b'application/json')]})
            await wrapped({'type':'http.response.body','body':b'{"detail":"Internal server error"}'})


class _TraceLink:
    """Link DB-generated correlation to the host's trusted request context.

    The callback gets *only* a DB-generated UUID. The host resolves its task
    context server-side (e.g. a ContextVar) and never from an unverified header.
    A link failure returns 503, but the DB operation may already be committed.
    """
    def __init__(self, app, callback, timeout):
        self.app, self.callback, self.timeout = app, callback, timeout

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        failed = False
        async def wrapped(message):
            nonlocal failed
            if failed:
                return
            if message['type'] == 'http.response.start':
                values = [v for k, v in message.get('headers', []) if k.lower() == b'x-correlation-id']
                if values:
                    correlation = None
                    try:
                        if len(values) != 1:
                            raise ValueError('invalid correlation')
                        correlation = UUID(values[0].decode('ascii'))
                        await asyncio.wait_for(_invoke(self.callback, correlation), timeout=self.timeout)
                    except Exception:
                        # Operation may have committed; create retries require the
                        # original idempotency key. Never expose exception details.
                        failed = True
                        headers = [(b'content-type',b'application/json')]
                        if correlation is not None:
                            headers.append((b'x-correlation-id', str(correlation).encode('ascii')))
                        await send({'type':'http.response.start','status':503, 'headers':headers})
                        await send({'type':'http.response.body','body':b'{"detail":"Trace integration unavailable"}'})
                        return
            await send(message)
        return await self.app(scope, receive, wrapped)


def create_host_application(*, resolve_principal: Callable, engine_for_principal: Callable,
                            security_audit: Callable, link_trace: Callable, trace_timeout_seconds: float = 2.0) -> FastAPI:
    """Create an isolated ASGI subapplication to mount after owner approval.

    resolve_principal(request) returns a verified Principal or None. It MUST
    authenticate and authorize the host request using trusted server-side state,
    never a payload tenant/actor. engine_for_principal(principal) returns the
    already-provisioned actor/tenant-bound SQLAlchemy PostgreSQL Engine. The
    host owns pool lifetimes and security audit outside this subapplication.
    security_audit(event) is synchronous and receives metadata-only attempts
    and failed/auth/validation response events generated by this subapplication.
    link_trace(UUID) binds a DB correlation to the authenticated gateway task
    via host-controlled context; it must not read untrusted IDs. The callback
    must be idempotent: a timed-out synchronous callback may finish later.
    """
    if not all(callable(x) for x in (resolve_principal, engine_for_principal, security_audit)):
        raise TypeError('host principal, database pool and audit callbacks are required')
    if inspect.iscoroutinefunction(security_audit):
        raise TypeError('security audit callback must be synchronous')
    if not callable(link_trace):
        raise TypeError('trace callback must be callable')
    if (isinstance(trace_timeout_seconds, bool) or not isinstance(trace_timeout_seconds, (float, int))
            or not math.isfinite(trace_timeout_seconds) or not 0 < trace_timeout_seconds <= 30):
        raise ValueError('invalid trace timeout')
    application = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    async def verified_principal(request: Request) -> Principal:
        try:
            principal = await _invoke(resolve_principal, request)
            if principal is None:
                raise HTTPException(status_code=401)
            if not isinstance(principal, Principal):
                raise TypeError('verified Principal required')
            verified = Principal.model_validate(principal.model_dump())
            request.scope['state']['ti_verified_identity'] = (verified.subject, verified.tenant_id)
            return verified
        except HTTPException as exc:
            if exc.status_code in (401, 403):
                raise HTTPException(status_code=exc.status_code, detail='Unauthorized' if exc.status_code == 401 else 'Forbidden') from None
            raise HTTPException(status_code=503, detail='Authentication unavailable') from None
        except Exception:
            raise HTTPException(status_code=503, detail='Authentication unavailable') from None

    async def verified_store(principal: Principal = Depends(get_principal)):
        try:
            engine = await _invoke(engine_for_principal, principal)
            if not isinstance(engine, Engine):
                raise TypeError('PostgreSQL Engine required')
            return TrustedWritePostgresRelationshipStore(engine)
        except Exception:
            raise HTTPException(status_code=503, detail='Relationship storage unavailable') from None

    def audit_callback():
        def emit_event(event):
            _synchronous_audit(security_audit, event)
        return emit_event

    application.dependency_overrides[get_principal] = verified_principal
    application.dependency_overrides[get_store] = verified_store
    application.dependency_overrides[get_audit] = audit_callback
    application.include_router(router)

    @application.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        return JSONResponse(status_code=422, content={'detail':'Invalid request'})

    @application.exception_handler(Exception)
    async def internal_error(request: Request, exc: Exception):
        return JSONResponse(status_code=500, content={'detail':'Internal server error'})

    application.add_middleware(_TraceLink, callback=link_trace, timeout=trace_timeout_seconds)
    application.add_middleware(_SecurityEvents, callback=security_audit)
    return application
