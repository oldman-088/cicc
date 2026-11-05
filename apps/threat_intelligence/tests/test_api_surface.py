"""
Unit tests for the Threat Intelligence HTTP/API integration surface.

These tests exercise the dispatcher in-process. They do NOT prove that an HTTP
server exists: no socket is bound and no ASGI app is created. The mount-status
tests assert the opposite -- that the surface reports itself as unmounted by
default and that building a real router fails loudly when FastAPI is absent.
"""

import pytest
from pydantic import ValidationError

from apps.threat_intelligence.api_surface import (
    API_CONTRACT_VERSION,
    API_PREFIX,
    ROUTES,
    ApiSurfaceNotMountedError,
    ApiValidationError,
    HttpMethod,
    ListEntitiesRequest,
    RequestContext,
    ThreatIntelApiSurface,
    build_fastapi_router,
    error_envelope,
    map_exception_to_envelope,
)
from apps.threat_intelligence.integration_contracts import HostMountStatus
from apps.threat_intelligence.persistence import (
    ConflictRecord,
    PersistenceError,
    SQLiteThreatIntelRepository,
    StoredEntityRecord,
    StoredObservation,
    TenantIsolationError,
    utcnow_iso,
)

READ_SCOPES = ["threat_intel:read", "threat_intel:audit_read"]


@pytest.fixture
def repo():
    r = SQLiteThreatIntelRepository(":memory:")
    yield r
    r.close()


@pytest.fixture
def surface(repo):
    return ThreatIntelApiSurface(repo)


def _seed(repo, tenant="t1", entity_id="IOC-1", entity_type="indicator"):
    now = utcnow_iso()
    repo.upsert_entity(
        StoredEntityRecord(
            tenant_id=tenant, entity_type=entity_type, entity_id=entity_id,
            display_name="192.0.2.10", payload={"provenance": "fixture_pipeline"},
            sources=["source-a"], corroboration_count=1, confidence=0.8,
            first_seen_at=now, last_seen_at=now, updated_at=now,
        ),
        actor="tester",
    )
    repo.append_observation(StoredObservation(
        tenant_id=tenant, entity_type=entity_type, entity_id=entity_id,
        source_id="source-a", observed_value="192.0.2.10", confidence=0.8,
        verification_mode="fixture_tested", provenance="fixture_pipeline",
        observed_at=now, recorded_at=now,
    ))


def _ctx(tenant="t1", scopes=None, actor="analyst"):
    return RequestContext(
        tenant_id=tenant,
        actor=actor,
        scopes=list(READ_SCOPES if scopes is None else scopes),
    )


class TestRouteRegistry:
    """The declared contract must be internally consistent."""

    def test_every_route_has_unique_operation_id_and_path(self):
        ids = [r.operation_id for r in ROUTES]
        assert len(ids) == len(set(ids))
        paths = [(r.method.value, r.full_path) for r in ROUTES]
        assert len(paths) == len(set(paths))

    def test_all_routes_live_under_the_versioned_prefix(self):
        for r in ROUTES:
            assert r.full_path.startswith(API_PREFIX)
            assert r.path.startswith("/")

    def test_path_params_declared_match_template_placeholders(self):
        import re
        for r in ROUTES:
            found = tuple(re.findall(r"\{([a-z_][a-z0-9_]*)\}", r.path))
            assert set(found) == set(r.path_params), f"{r.operation_id}: {found} != {r.path_params}"

    def test_every_route_declares_a_required_scope(self):
        for r in ROUTES:
            assert r.required_scope, f"{r.operation_id} has no required scope"

    def test_methods_are_from_the_declared_enum(self):
        for r in ROUTES:
            assert isinstance(r.method, HttpMethod)


class TestMatching:
    def test_static_and_templatedRoute_matching(self, surface):
        spec, params = surface.match("GET", f"{API_PREFIX}/entities")
        assert spec is not None and spec.operation_id == "listThreatIntelEntities"
        assert params == {}

        spec, params = surface.match("get", f"{API_PREFIX}/entities/indicator/IOC-1")
        assert spec.operation_id == "getThreatIntelEntity"
        assert params == {"entity_type": "indicator", "entity_id": "IOC-1"}

        spec, params = surface.match("GET", f"{API_PREFIX}/entities/indicator/IOC-1/history")
        assert spec.operation_id == "listThreatIntelHistory"

    def test_unknown_route_returns_none(self, surface):
        spec, params = surface.match("GET", f"{API_PREFIX}/does-not-exist")
        assert spec is None and params == {}

    def test_wrong_method_does_not_match(self, surface):
        spec, _ = surface.match("POST", f"{API_PREFIX}/entities")
        assert spec is None

    def test_segment_count_mismatch_does_not_over_match(self, surface):
        spec, _ = surface.match("GET", f"{API_PREFIX}/entities/indicator")
        assert spec is None

    def test_empty_path_segment_is_not_a_valid_parameter(self, surface):
        spec, _ = surface.match("GET", f"{API_PREFIX}/entities//IOC-1")
        assert spec is None

    def test_path_text_is_never_compiled_as_regex(self, surface):
        """A regex metacharacter in the path must not change matching behaviour."""
        spec, params = surface.match("GET", f"{API_PREFIX}/entities/indicator/a.*b(c)")
        assert spec is not None
        assert params["entity_id"] == "a.*b(c)"


class TestAuthorizationAndTenancy:
    def test_missing_scope_is_401(self, surface):
        _seed(surface._repo)
        res = surface.dispatch("GET", f"{API_PREFIX}/entities", _ctx(scopes=[]))
        assert res.status == 401 and res.error.code == "unauthorized"

    def test_unresolved_tenant_is_403_not_500(self, surface):
        res = surface.dispatch(
            "GET", f"{API_PREFIX}/entities", _ctx(tenant=None, scopes=["threat_intel:read"])
        )
        assert res.status == 403
        assert res.error.code == "tenant_resolution_required"

    def test_audit_route_requires_the_audit_scope(self, surface):
        _seed(surface._repo)
        res = surface.dispatch(
            "GET", f"{API_PREFIX}/audit", _ctx(scopes=["threat_intel:read"])
        )
        assert res.status == 401

        res = surface.dispatch("GET", f"{API_PREFIX}/audit", _ctx())
        assert res.status == 200

    def test_contract_meta_route_needs_no_tenant(self, surface):
        res = surface.dispatch(
            "GET", f"{API_PREFIX}/meta/contract", _ctx(tenant=None, scopes=["threat_intel:read"])
        )
        assert res.status == 200
        assert res.data["contract_version"] == API_CONTRACT_VERSION

    def test_context_rejects_blank_actor(self):
        with pytest.raises(ValidationError):
            RequestContext(tenant_id="t1", actor="   ", scopes=[])

    def test_context_collapses_control_whitespace_in_actor(self):
        """Newlines/tabs are collapsed to single spaces so the audit log stays one line."""
        ctx = RequestContext(tenant_id="t1", actor="ana\nlyst\t one", scopes=[])
        assert ctx.actor == "ana lyst one"
        assert "\n" not in ctx.actor and "\t" not in ctx.actor
        assert RequestContext(tenant_id="t1", actor="  spaced  ", scopes=[]).actor == "spaced"


class TestValidationMapping:
    def test_invalid_path_entity_type_is_422_with_field(self, surface):
        res = surface.dispatch("GET", f"{API_PREFIX}/entities/not_a_type/X", _ctx())
        assert res.status == 422
        assert res.error.code == "validation_error"
        assert res.error.details["field"] == "entity_type"

    def test_invalid_query_entity_type_is_422(self, surface):
        res = surface.dispatch(
            "GET", f"{API_PREFIX}/entities", _ctx(), query={"entity_type": "nope"}
        )
        assert res.status == 422 and res.error.code == "validation_error"

    def test_out_of_range_limit_is_422(self, surface):
        res = surface.dispatch("GET", f"{API_PREFIX}/entities", _ctx(), query={"limit": 9999})
        assert res.status == 422

    def test_unknown_route_is_404_route_not_found(self, surface):
        res = surface.dispatch("GET", f"{API_PREFIX}/nope", _ctx())
        assert res.status == 404 and res.error.code == "route_not_found"

    def test_missing_entity_is_404_not_found(self, surface):
        res = surface.dispatch("GET", f"{API_PREFIX}/entities/indicator/NOPE", _ctx())
        assert res.status == 404 and res.error.code == "not_found"

    def test_persistence_error_maps_to_400(self):
        env = map_exception_to_envelope(PersistenceError("bad cursor"))
        assert env.status == 400 and env.error.code == "persistence_error"

    def test_tenant_error_maps_to_403(self):
        env = map_exception_to_envelope(TenantIsolationError("no tenant"))
        assert env.status == 403

    def test_unexpected_error_is_500_without_leaking_detail(self):
        env = map_exception_to_envelope(RuntimeError("secret internal detail"))
        assert env.status == 500
        assert env.error.code == "internal_error"
        assert "secret internal detail" not in env.error.message

    def test_error_envelope_rejects_non_error_status(self):
        with pytest.raises(ValidationError):
            error_envelope(200, "ok", "not an error")


class TestHandlers:
    def test_list_entities_returns_page_metadata(self, surface):
        _seed(surface._repo, entity_id="IOC-1")
        _seed(surface._repo, entity_id="IOC-2")
        res = surface.dispatch("GET", f"{API_PREFIX}/entities", _ctx())
        assert res.status == 200
        assert res.page.total_count == 2
        assert len(res.data) == 2

    def test_detail_includes_provenance_summary(self, surface):
        _seed(surface._repo)
        res = surface.dispatch("GET", f"{API_PREFIX}/entities/indicator/IOC-1", _ctx())
        assert res.status == 200
        summary = res.data["provenance_summary"]
        assert summary["sources"] == ["source-a"]
        assert summary["observations_count"] == 1
        assert summary["corroboration_count"] == 1
        assert summary["observations_count"] >= len(summary["sources"])

    def test_observations_conflicts_and_history_endpoints(self, surface):
        _seed(surface._repo)
        surface._repo.append_conflict(ConflictRecord(
            tenant_id="t1", entity_type="indicator", entity_id="IOC-1",
            field_name="confidence", kept_value="0.9", discarded_values=[0.4],
            resolution_policy="highest_confidence_wins", source="source-low",
            detected_at=utcnow_iso(),
        ))
        obs = surface.dispatch("GET", f"{API_PREFIX}/entities/indicator/IOC-1/observations", _ctx())
        conf = surface.dispatch("GET", f"{API_PREFIX}/entities/indicator/IOC-1/conflicts", _ctx())
        hist = surface.dispatch("GET", f"{API_PREFIX}/entities/indicator/IOC-1/history", _ctx())
        assert obs.status == conf.status == hist.status == 200
        assert len(obs.data) == 1
        assert len(conf.data) == 1
        assert len(hist.data) >= 2  # created + conflict_recorded

    def test_cursor_pagination_round_trip_through_the_api(self, surface):
        for i in range(12):
            _seed(surface._repo, entity_id=f"IOC-{i:03d}")
        seen, cursor = [], None
        while True:
            query = {"limit": 5}
            if cursor:
                query["cursor"] = cursor
            res = surface.dispatch("GET", f"{API_PREFIX}/entities", _ctx(), query=query)
            assert res.status == 200
            seen.extend(e["entity_id"] for e in res.data)
            if res.page.next_cursor is None:
                break
            cursor = res.page.next_cursor
        assert len(seen) == 12 and len(set(seen)) == 12

    def test_tenant_isolation_through_the_api(self, surface):
        _seed(surface._repo, tenant="t1", entity_id="IOC-1")
        _seed(surface._repo, tenant="t2", entity_id="IOC-1")
        r1 = surface.dispatch("GET", f"{API_PREFIX}/entities/indicator/IOC-1", _ctx(tenant="t1"))
        assert r1.status == 200 and r1.data["tenant_id"] == "t1"
        r3 = surface.dispatch("GET", f"{API_PREFIX}/entities/indicator/IOC-1", _ctx(tenant="t3"))
        assert r3.status == 404


class TestFreshnessAndMountHonesty:
    def test_default_state_reports_unmounted_and_fixture_tested(self, surface):
        status = surface.mount_status()
        assert status["mounted"] is False
        assert status["contract_status"] == "proposed_not_accepted"
        assert status["verification_mode"] == "fixture_tested"

        _seed(surface._repo)
        res = surface.dispatch("GET", f"{API_PREFIX}/entities/indicator/IOC-1", _ctx())
        assert res.freshness.host_mount_status is HostMountStatus.NOT_MOUNTED_PENDING_OWNER_APPROVAL
        assert res.freshness.verification_mode == "fixture_tested"
        assert res.freshness.origin == "EXPERIMENTAL_DEMO_DATA_ONLY"

    def test_mark_mounted_requires_an_identity_and_is_reflected(self, surface):
        with pytest.raises(ApiValidationError):
            surface.mark_mounted("   ")
        assert surface.mount_status()["mounted"] is False

        surface.mark_mounted("cicc-main-app")
        status = surface.mount_status()
        assert status["mounted"] is True
        assert status["mounted_by"] == "cicc-main-app"
        assert status["mounted_at"] is not None

        _seed(surface._repo)
        res = surface.dispatch("GET", f"{API_PREFIX}/entities/indicator/IOC-1", _ctx())
        assert res.freshness.host_mount_status is HostMountStatus.MOUNTED_BY_HOST

    def test_verification_mode_is_validated_at_construction(self, repo):
        with pytest.raises(ValueError):
            ThreatIntelApiSurface(repo, verification_mode="live_verified_by_vibes")

    def test_build_fastapi_router_fails_loudly_without_fastapi(self, surface):
        """
        FastAPI is not installed in this repository. The adapter must raise a
        clear, actionable error rather than silently pretending to mount.
        """
        try:
            import fastapi  # noqa: F401
            pytest.skip("FastAPI is installed; the guarded-import failure path does not apply")
        except ImportError:
            pass
        with pytest.raises(ApiSurfaceNotMountedError) as exc:
            build_fastapi_router(surface)
        assert "NOT mounted" in str(exc.value)

    def test_request_model_rejects_unknown_fields(self):
        with pytest.raises(ValidationError):
            ListEntitiesRequest(entity_type="indicator", surprise="x")
