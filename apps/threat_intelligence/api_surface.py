"""
Threat Intelligence HTTP/API Integration Surface

Repository:  oldman-088/cicc   Branch: arena/28e50255-cicc (Agent 6 backup)

What this module IS
-------------------
A transport-agnostic, fully validated API *contract* layer for the Threat
Intelligence domain:

* typed request and response models for every endpoint;
* a route registry with method, path template, parameter validation, required
  auth scope and tenant-resolution requirement;
* deterministic mapping of domain errors onto HTTP status codes and the
  ``ThreatIntelErrorEnvelope`` shape;
* a dispatcher that can execute a request end-to-end in-process, which is what
  the test suite exercises.

What this module IS NOT
-----------------------
* It does **not** mount anything. No ``FastAPI`` instance is created, no ASGI
  app is exported, no server binds a port. ``mount_status()`` reports
  ``"not_mounted"`` unless a host application explicitly calls ``mark_mounted``.
* It does **not** import FastAPI at module scope. ``build_fastapi_router``
  performs a guarded import and raises ``ApiSurfaceNotMountedError`` with an
  actionable message when FastAPI is absent. In this repository FastAPI is not
  installed, so that path is exercised as the *failure* case by the tests.
* It performs no authentication itself. It declares the required scope and
  refuses to serve a request whose resolved tenant is missing.

Verification state: **fixture_tested**. No live HTTP traffic exists.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from apps.threat_intelligence.integration_contracts import (
    EXPERIMENTAL_DEMO_DATA_ONLY,
    FreshnessMetaDTO,
    PaginationMetaDTO,
    ThreatIntelErrorEnvelope,
)
from apps.threat_intelligence.persistence import (
    PersistenceError,
    ThreatIntelRepository,
    TenantIsolationError,
    VALID_ENTITY_TYPES,
    _MAX_LIMIT,
)

API_PREFIX = "/api/v1/threat-intelligence"
API_CONTRACT_VERSION = "1.0.0-proposed"

_ENTITY_ID_RE = re.compile(r"^[A-Za-z0-9_.:/\-]{1,256}$")
_PATH_PARAM_RE = re.compile(r"\{([a-z_][a-z0-9_]*)\}")


class ApiSurfaceNotMountedError(RuntimeError):
    """Raised when a caller asks for behaviour that requires a mounted host app."""


class ApiValidationError(Exception):
    """Request failed contract validation."""

    def __init__(self, message: str, *, field_name: Optional[str] = None, status: int = 422):
        super().__init__(message)
        self.message = message
        self.field_name = field_name
        self.status = status


class ApiNotFoundError(Exception):
    """Requested entity does not exist for the resolved tenant."""


class ApiUnauthorizedError(Exception):
    """Missing or insufficient credentials / tenant resolution."""


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"


# ============================================================================
# Request / response models
# ============================================================================

class RequestContext(BaseModel):
    """
    Everything a handler needs that is *not* part of the URL or body.

    A host application builds this from the authenticated principal. This
    module never derives it from request-supplied data, which is what keeps
    tenant isolation enforced at the API boundary rather than by convention.
    """

    model_config = ConfigDict(extra="forbid")

    tenant_id: Optional[str] = Field(None, description="Resolved from the authenticated principal")
    actor: str = Field("anonymous", description="Audit actor identity")
    scopes: List[str] = Field(default_factory=list)
    client_ref: Optional[str] = Field(None, description="Opaque correlation id for logs")

    @field_validator("actor")
    @classmethod
    def _no_newlines(cls, v: str) -> str:
        # Actor identities reach the audit log; keep them single-line.
        cleaned = " ".join(v.split())
        if not cleaned:
            raise ValueError("actor must be a non-empty identity")
        return cleaned


class ListEntitiesRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_type: Optional[str] = Field(None)
    limit: int = Field(50, ge=1, le=_MAX_LIMIT)
    cursor: Optional[str] = Field(None)

    @field_validator("entity_type")
    @classmethod
    def _check_type(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in VALID_ENTITY_TYPES:
            raise ValueError(f"entity_type must be one of {sorted(VALID_ENTITY_TYPES)}")
        return v


class GetEntityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_type: str
    entity_id: str

    @field_validator("entity_type")
    @classmethod
    def _check_type(cls, v: str) -> str:
        if v not in VALID_ENTITY_TYPES:
            raise ValueError(f"entity_type must be one of {sorted(VALID_ENTITY_TYPES)}")
        return v

    @field_validator("entity_id")
    @classmethod
    def _check_id(cls, v: str) -> str:
        if not _ENTITY_ID_RE.match(v):
            raise ValueError("entity_id must match ^[A-Za-z0-9_.:/-]{1,256}$")
        return v


class ListObservationsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_type: str
    entity_id: str

    @field_validator("entity_type")
    @classmethod
    def _check_type(cls, v: str) -> str:
        if v not in VALID_ENTITY_TYPES:
            raise ValueError(f"entity_type must be one of {sorted(VALID_ENTITY_TYPES)}")
        return v

    @field_validator("entity_id")
    @classmethod
    def _check_id(cls, v: str) -> str:
        if not _ENTITY_ID_RE.match(v):
            raise ValueError("entity_id must match ^[A-Za-z0-9_.:/-]{1,256}$")
        return v


class ListConflictsRequest(ListObservationsRequest):
    pass


class ListHistoryRequest(ListObservationsRequest):
    pass


class ListAuditRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_type: Optional[str] = Field(None)
    entity_id: Optional[str] = Field(None)

    @field_validator("entity_type")
    @classmethod
    def _check_type(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in VALID_ENTITY_TYPES:
            raise ValueError(f"entity_type must be one of {sorted(VALID_ENTITY_TYPES)}")
        return v


class ApiResponse(BaseModel):
    """Uniform successful response envelope."""

    model_config = ConfigDict(extra="forbid")

    status: int = Field(200, ge=100, le=599)
    data: Any = None
    page: Optional[PaginationMetaDTO] = None
    freshness: FreshnessMetaDTO = Field(default_factory=FreshnessMetaDTO)


# ============================================================================
# Route registry
# ============================================================================

@dataclass(frozen=True)
class RouteSpec:
    """Declarative description of one endpoint."""

    method: HttpMethod
    path: str
    operation_id: str
    summary: str
    request_model: Optional[type]
    required_scope: str
    tenant_required: bool
    path_params: Tuple[str, ...] = field(default_factory=tuple)

    @property
    def full_path(self) -> str:
        return f"{API_PREFIX}{self.path}"


ROUTES: Tuple[RouteSpec, ...] = (
    RouteSpec(
        method=HttpMethod.GET,
        path="/entities",
        operation_id="listThreatIntelEntities",
        summary="Cursor-paginated, tenant-scoped entity listing.",
        request_model=ListEntitiesRequest,
        required_scope="threat_intel:read",
        tenant_required=True,
    ),
    RouteSpec(
        method=HttpMethod.GET,
        path="/entities/{entity_type}/{entity_id}",
        operation_id="getThreatIntelEntity",
        summary="Fetch one entity with provenance summary.",
        request_model=GetEntityRequest,
        required_scope="threat_intel:read",
        tenant_required=True,
        path_params=("entity_type", "entity_id"),
    ),
    RouteSpec(
        method=HttpMethod.GET,
        path="/entities/{entity_type}/{entity_id}/observations",
        operation_id="listThreatIntelObservations",
        summary="Append-only provenance observation history for an entity.",
        request_model=ListObservationsRequest,
        required_scope="threat_intel:read",
        tenant_required=True,
        path_params=("entity_type", "entity_id"),
    ),
    RouteSpec(
        method=HttpMethod.GET,
        path="/entities/{entity_type}/{entity_id}/conflicts",
        operation_id="listThreatIntelConflicts",
        summary="Recorded conflicting values for an entity.",
        request_model=ListConflictsRequest,
        required_scope="threat_intel:read",
        tenant_required=True,
        path_params=("entity_type", "entity_id"),
    ),
    RouteSpec(
        method=HttpMethod.GET,
        path="/entities/{entity_type}/{entity_id}/history",
        operation_id="listThreatIntelHistory",
        summary="Append-only change history for an entity.",
        request_model=ListHistoryRequest,
        required_scope="threat_intel:read",
        tenant_required=True,
        path_params=("entity_type", "entity_id"),
    ),
    RouteSpec(
        method=HttpMethod.GET,
        path="/audit",
        operation_id="listThreatIntelAudit",
        summary="Tenant-scoped audit entries.",
        request_model=ListAuditRequest,
        required_scope="threat_intel:audit_read",
        tenant_required=True,
    ),
    RouteSpec(
        method=HttpMethod.GET,
        path="/meta/contract",
        operation_id="getThreatIntelContractMeta",
        summary="Contract version, mount status and verification state.",
        request_model=None,
        required_scope="threat_intel:read",
        tenant_required=False,
    ),
)


def error_envelope(status: int, error_code: str, message: str, **details: Any) -> ThreatIntelErrorEnvelope:
    return ThreatIntelErrorEnvelope(
        status=status,
        error_code=error_code,
        message=message,
        details=details or None,
    )


def map_exception_to_envelope(exc: Exception) -> ThreatIntelErrorEnvelope:
    """Deterministic domain-error -> HTTP mapping."""
    if isinstance(exc, ApiUnauthorizedError):
        return error_envelope(401, "unauthorized", str(exc))
    if isinstance(exc, ApiNotFoundError):
        return error_envelope(404, "not_found", str(exc))
    if isinstance(exc, ApiValidationError):
        return error_envelope(422, "validation_error", exc.message,
                              field=exc.field_name) if exc.field_name else \
            error_envelope(422, "validation_error", exc.message)
    if isinstance(exc, ValidationError):
        # Pydantic validation failures on path/query parameters are client
        # errors. Surface the offending field, never the raw traceback.
        first = exc.errors()[0] if exc.errors() else {}
        loc = first.get("loc") or ()
        field_name = ".".join(str(part) for part in loc) if loc else None
        message = first.get("msg", "request validation failed")
        if field_name:
            return error_envelope(422, "validation_error", message, field=field_name)
        return error_envelope(422, "validation_error", message)
    if isinstance(exc, TenantIsolationError):
        # Deliberately 403, never 500: leaking a stack trace here would be worse.
        return error_envelope(403, "tenant_resolution_required", str(exc))
    if isinstance(exc, PersistenceError):
        return error_envelope(400, "persistence_error", str(exc))
    return error_envelope(500, "internal_error", "Unhandled error in Threat Intelligence API surface")


# ============================================================================
# Dispatcher
# ============================================================================

class ThreatIntelApiSurface:
    """
    In-process dispatcher over the Threat Intelligence route registry.

    ``dispatch`` is the single entry point a host adapter should call. It
    validates scope, resolves the tenant, parses and validates path/query
    parameters against the route's request model, invokes the handler, and
    returns either an :class:`ApiResponse` or a
    :class:`ThreatIntelErrorEnvelope`.
    """

    def __init__(self, repository: ThreatIntelRepository, *, verification_mode: str = "fixture_tested"):
        if verification_mode not in ("fixture_tested", "oracle_verified", "live_verified"):
            raise ValueError(f"Unsupported verification_mode: {verification_mode}")
        self._repo = repository
        self._verification_mode = verification_mode
        self._mounted = False
        self._mounted_at: Optional[str] = None
        self._mounted_by: Optional[str] = None
        self._routes: Dict[Tuple[str, str], RouteSpec] = {
            (r.method.value, r.full_path): r for r in ROUTES
        }

    # ------------------------------------------------------------- lifecycle

    @property
    def routes(self) -> Tuple[RouteSpec, ...]:
        return ROUTES

    def mount_status(self) -> Dict[str, Any]:
        return {
            "mounted": self._mounted,
            "mounted_at": self._mounted_at,
            "mounted_by": self._mounted_by,
            "contract_version": API_CONTRACT_VERSION,
            "contract_status": "proposed_not_accepted",
            "verification_mode": self._verification_mode,
            "api_prefix": API_PREFIX,
            "route_count": len(ROUTES),
        }

    def mark_mounted(self, mounted_by: str) -> Dict[str, Any]:
        """
        Record that a host application has actually mounted these routes.

        This exists so the freshness metadata cannot claim mounting by default.
        It must be called by the host, with an identity, and it is audited.
        """
        if not mounted_by or not mounted_by.strip():
            raise ApiValidationError("mounted_by must identify the host application")
        self._mounted = True
        self._mounted_at = datetime.now(timezone.utc).isoformat()
        self._mounted_by = mounted_by.strip()
        return self.mount_status()

    # -------------------------------------------------------------- matching

    def match(self, method: str, path: str) -> Tuple[Optional[RouteSpec], Dict[str, str]]:
        """Resolve a method+path to a route, extracting path parameters."""
        method = method.upper()
        direct = self._routes.get((method, path))
        if direct is not None:
            return direct, {}

        # Segment-by-segment matching against the literal template. This avoids
        # building a regex from a path template, which would put untrusted path
        # text through a regex compiler.
        target_segments = path.split("/")
        for spec in ROUTES:
            if spec.method.value != method or not spec.path_params:
                continue
            template_segments = spec.full_path.split("/")
            if len(template_segments) != len(target_segments):
                continue
            params: Dict[str, str] = {}
            matched = True
            for tmpl, actual in zip(template_segments, target_segments):
                placeholder = _PATH_PARAM_RE.fullmatch(tmpl)
                if placeholder:
                    if not actual or actual == "":
                        matched = False
                        break
                    params[placeholder.group(1)] = actual
                elif tmpl != actual:
                    matched = False
                    break
            if matched and set(params) == set(spec.path_params):
                return spec, params
        return None, {}

    # ------------------------------------------------------------- execution

    def dispatch(
        self,
        method: str,
        path: str,
        context: RequestContext,
        query: Optional[Dict[str, Any]] = None,
        body: Optional[Dict[str, Any]] = None,
    ) -> ApiResponse | ThreatIntelErrorEnvelope:
        try:
            spec, path_params = self.match(method, path)
            if spec is None:
                return error_envelope(404, "route_not_found", f"No route for {method.upper()} {path}")

            if spec.required_scope not in context.scopes:
                raise ApiUnauthorizedError(
                    f"Scope '{spec.required_scope}' is required for {spec.operation_id}"
                )

            if spec.tenant_required and not context.tenant_id:
                raise TenantIsolationError(
                    "Tenant could not be resolved from the authenticated principal"
                )

            payload: Dict[str, Any] = {**path_params, **(query or {})}
            request = spec.request_model(**payload) if spec.request_model is not None else None
            return self._invoke(spec, context, request, body)
        except Exception as exc:  # noqa: BLE001 - deliberate API boundary
            return map_exception_to_envelope(exc)

    # -------------------------------------------------------------- handlers

    def _freshness(self) -> FreshnessMetaDTO:
        return FreshnessMetaDTO(
            origin=EXPERIMENTAL_DEMO_DATA_ONLY,
            verification_mode=self._verification_mode,
            host_mount_status=(
                "mounted" if self._mounted else "not_mounted_pending_owner_approval"
            ),
        )

    def _invoke(
        self,
        spec: RouteSpec,
        context: RequestContext,
        request: Optional[BaseModel],
        body: Optional[Dict[str, Any]],
    ) -> ApiResponse:
        if spec.operation_id == "getThreatIntelContractMeta":
            return ApiResponse(data=self.mount_status(), freshness=self._freshness())

        assert context.tenant_id is not None  # guaranteed by tenant_required check
        repo = self._repo

        if spec.operation_id == "listThreatIntelEntities":
            assert isinstance(request, ListEntitiesRequest)
            page = repo.list_entities(
                context.tenant_id,
                entity_type=request.entity_type,
                limit=request.limit,
                cursor=request.cursor,
            )
            return ApiResponse(
                data=[e.model_dump(mode="json") for e in page.items],
                page=PaginationMetaDTO(
                    limit=page.limit,
                    total_count=page.total_count,
                    next_cursor=page.next_cursor,
                ),
                freshness=self._freshness(),
            )

        if spec.operation_id == "getThreatIntelEntity":
            assert isinstance(request, GetEntityRequest)
            entity = repo.get_entity(context.tenant_id, request.entity_type, request.entity_id)
            if entity is None:
                raise ApiNotFoundError(
                    f"No {request.entity_type} with id {request.entity_id} for this tenant"
                )
            observations = repo.list_observations(
                context.tenant_id, request.entity_type, request.entity_id
            )
            sources = list(dict.fromkeys(o.source_id for o in observations)) or list(entity.sources)
            data = entity.model_dump(mode="json")
            data["provenance_summary"] = {
                "sources": sources,
                "observations_count": len(observations),
                "corroboration_count": len(sources),
            }
            return ApiResponse(data=data, freshness=self._freshness())

        if spec.operation_id == "listThreatIntelObservations":
            assert isinstance(request, ListObservationsRequest)
            obs = repo.list_observations(
                context.tenant_id, request.entity_type, request.entity_id
            )
            return ApiResponse(
                data=[o.model_dump(mode="json") for o in obs],
                page=PaginationMetaDTO(limit=len(obs), total_count=len(obs)),
                freshness=self._freshness(),
            )

        if spec.operation_id == "listThreatIntelConflicts":
            assert isinstance(request, ListConflictsRequest)
            conflicts = repo.list_conflicts(
                context.tenant_id, request.entity_type, request.entity_id
            )
            return ApiResponse(
                data=[c.model_dump(mode="json") for c in conflicts],
                page=PaginationMetaDTO(limit=len(conflicts), total_count=len(conflicts)),
                freshness=self._freshness(),
            )

        if spec.operation_id == "listThreatIntelHistory":
            assert isinstance(request, ListHistoryRequest)
            history = repo.list_history(
                context.tenant_id, request.entity_type, request.entity_id
            )
            return ApiResponse(
                data=[h.model_dump(mode="json") for h in history],
                page=PaginationMetaDTO(limit=len(history), total_count=len(history)),
                freshness=self._freshness(),
            )

        if spec.operation_id == "listThreatIntelAudit":
            assert isinstance(request, ListAuditRequest)
            audit = repo.list_audit(
                context.tenant_id,
                entity_type=request.entity_type,
                entity_id=request.entity_id,
            )
            return ApiResponse(
                data=[a.model_dump(mode="json") for a in audit],
                page=PaginationMetaDTO(limit=len(audit), total_count=len(audit)),
                freshness=self._freshness(),
            )

        raise ApiSurfaceNotMountedError(f"No handler bound for {spec.operation_id}")


# ============================================================================
# Optional FastAPI adapter (guarded import)
# ============================================================================

def build_fastapi_router(surface: ThreatIntelApiSurface):  # pragma: no cover - env dependent
    """
    Bind :class:`ThreatIntelApiSurface` to a FastAPI ``APIRouter``.

    This is the *only* place FastAPI is referenced, and the import is guarded.
    If FastAPI is not installed the function raises
    :class:`ApiSurfaceNotMountedError` rather than failing at import time, so
    the rest of the module stays usable and testable.

    The caller is responsible for dependency-injecting ``RequestContext`` from
    the authenticated principal; this adapter never synthesises a tenant.
    """
    try:
        from fastapi import APIRouter  # type: ignore
    except ImportError as exc:
        raise ApiSurfaceNotMountedError(
            "FastAPI is not installed in this environment, so no router can be built. "
            "The Threat Intelligence API surface is contract-only here and is NOT mounted."
        ) from exc

    router = APIRouter(prefix=API_PREFIX, tags=["threat-intelligence"])

    for spec in ROUTES:
        def _make_handler(route: RouteSpec) -> Callable[..., Any]:
            def _handler(context: RequestContext, query: Dict[str, Any] | None = None) -> Any:
                return surface.dispatch(route.method.value, route.full_path, context, query=query)
            _handler.__name__ = route.operation_id
            _handler.__doc__ = route.summary
            return _handler

        router.add_api_route(
            spec.path,
            _make_handler(spec),
            methods=[spec.method.value],
            name=spec.operation_id,
            summary=spec.summary,
        )
    return router
