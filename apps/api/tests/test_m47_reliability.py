"""M47 regressions: expiring breaker leases, mount-generation callbacks, and GET purity."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import threading
import time

import pytest
from sqlalchemy import event

from app import ops, ratelimit
from app.coordination import domains

W = {"Authorization": "Bearer w", "Content-Type": "application/json"}
R = {"Authorization": "Bearer r"}


@pytest.fixture(autouse=True)
def _m47_clean(monkeypatch):
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r")
    monkeypatch.setenv("CICC_DOMAIN_INVOKE_TIMEOUT_S", "2")
    monkeypatch.setenv("CICC_DOMAIN_INVOKE_RETRIES", "0")
    monkeypatch.setenv("CICC_DOMAIN_CIRCUIT_FAILURES", "3")
    monkeypatch.setenv("CICC_DOMAIN_CIRCUIT_COOLDOWN_S", "0.3")
    monkeypatch.setenv("CICC_DOMAIN_CIRCUIT_PROBE_LEASE_S", "30")
    for kind in list(domains._REGISTRY):
        domains.unregister_domain(kind)
    domains._STATS.clear()
    domains._CIRCUIT.clear()
    yield
    for kind in list(domains._REGISTRY):
        domains.unregister_domain(kind)
    domains._STATS.clear()
    domains._CIRCUIT.clear()
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


def _ok_handler(payload, task):
    return {"result": {"ok": True}, "provenance": {
        "source": "m47-fixture", "produced_at": datetime.now(timezone.utc).isoformat(),
        "freshness_s": 0,
    }}


def _call(client, kind, task_id):
    return client.post(
        f"/api/v1/coordination/domains/{kind}/invoke",
        json={"task_id": task_id, "idempotency_key": task_id,
              "payload": {"test": True}},
        headers=W)


def test_expired_half_open_lease_is_reclaimed_and_old_callback_cannot_close_new_lease(monkeypatch):
    monkeypatch.setenv("CICC_DOMAIN_CIRCUIT_PROBE_LEASE_S", "0.05")
    domains.register_domain("lease", _ok_handler, version="1", source_ref="fixture")
    domains._STATS["lease"]["consecutive_failures"] = 3
    domains._STATS["lease"]["circuit_opens"] = 1
    domains._CIRCUIT["lease"] = {
        "open": True, "opened_at": time.time() - 1, "probe_inflight": False,
        "probe_lease_id": None, "probe_lease_expires_at": None,
    }

    first = {}
    assert domains._begin_invoke("lease", first) is True
    first_lease = first["probe_lease_id"]
    assert first_lease and first["half_open_probe"] is True
    assert domains._begin_invoke("lease", {}) is False

    time.sleep(0.07)
    second = {}
    assert domains._begin_invoke("lease", second) is True
    second_lease = second["probe_lease_id"]
    assert second["lease_expired"] is True
    assert second_lease and second_lease != first_lease
    assert domains._STATS["lease"]["probe_lease_expirations"] == 1

    stale_outcome = {}
    assert domains.record_outcome(
        "lease", True, mount_id=first["mount_id"], probe_lease_id=first_lease,
        outcome_state=stale_outcome) is True
    assert stale_outcome["accepted"] is True
    assert "transition" not in stale_outcome
    assert domains._CIRCUIT["lease"]["open"] is True
    assert domains._CIRCUIT["lease"]["probe_lease_id"] == second_lease
    assert domains._STATS["lease"]["circuit_closes"] == 0

    current_outcome = {}
    assert domains.record_outcome(
        "lease", True, mount_id=second["mount_id"], probe_lease_id=second_lease,
        outcome_state=current_outcome) is True
    assert current_outcome["transition"] == "CLOSED"
    assert domains._CIRCUIT["lease"]["open"] is False
    metrics = domains.domain_metrics()["domains"]["lease"]["circuit"]
    assert metrics["probe_lease_expirations"] == 1
    assert metrics["probe_inflight"] is False


def test_success_callback_from_replaced_handler_is_discarded_by_http_gateway(client):
    entered = threading.Event()
    release = threading.Event()

    def old_handler(payload, task):
        entered.set()
        assert release.wait(timeout=2)
        return _ok_handler(payload, task)

    domains.register_domain("race_remount", old_handler, version="old", source_ref="fixture-old")
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(_call, client, "race_remount", "m47-remount-success")
        assert entered.wait(timeout=2)
        domains.register_domain("race_remount", _ok_handler, version="new", source_ref="fixture-new")
        release.set()
        response = pending.result(timeout=4)

    assert response.status_code == 409 and response.json()["detail"] == "domain_mount_changed"
    state = domains._STATS["race_remount"]
    assert state["invokes"] == 0 and state["successes"] == 0
    assert domains.domain_status("race_remount") == domains.AVAILABLE
    trace = client.get("/api/v1/coordination/tasks/m47-remount-success/trace", headers=R).json()
    kinds = [e["kind"] for e in trace["events"]]
    assert "domain_mount_changed" in kinds and "domain_result" not in kinds


def test_failure_callback_after_deregister_does_not_recreate_stats_or_alert(client):
    entered = threading.Event()
    release = threading.Event()

    def old_handler(payload, task):
        entered.set()
        assert release.wait(timeout=2)
        raise RuntimeError("stale handler failure must not surface")

    domains.register_domain("race_deregister", old_handler, version="old", source_ref="fixture-old")
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(_call, client, "race_deregister", "m47-deregister-failure")
        assert entered.wait(timeout=2)
        assert domains.unregister_domain("race_deregister") is True
        release.set()
        response = pending.result(timeout=4)

    assert response.status_code == 409 and response.json()["detail"] == "domain_mount_changed"
    assert "race_deregister" not in domains._STATS
    trace = client.get("/api/v1/coordination/tasks/m47-deregister-failure/trace", headers=R).json()
    kinds = [e["kind"] for e in trace["events"]]
    assert "domain_mount_changed" in kinds and "domain_error" not in kinds
    alerts = client.get("/api/v1/ops/alerts/history?rule=domain_status", headers=R).json()["alerts"]
    assert not [a for a in alerts if a.get("component_key") == "race_deregister"]


def test_domain_diagnostics_and_metrics_gets_do_not_write_database(client, monkeypatch):
    monkeypatch.setenv("CICC_BUILD_SHA", "m47-test-build-sha")
    domains.register_domain("read_only", _ok_handler, version="1", source_ref="fixture")
    response = _call(client, "read_only", "m47-read-only-seed")
    assert response.status_code == 201

    dml = []

    def capture_dml(conn, cursor, statement, parameters, context, executemany):
        normalized = statement.lstrip().upper()
        if normalized.startswith(("INSERT", "UPDATE", "DELETE", "REPLACE")):
            dml.append(statement)

    event.listen(ops.engine, "before_cursor_execute", capture_dml)
    try:
        checks = [
            client.get("/api/v1/coordination/domains", headers=R),
            client.get("/api/v1/coordination/domains/read_only/status", headers=R),
            client.get("/api/v1/coordination/domains/metrics", headers=R),
            client.get("/api/v1/coordination/diagnostics", headers=R),
            client.get("/api/v1/coordination/health", headers=R),
        ]
    finally:
        event.remove(ops.engine, "before_cursor_execute", capture_dml)

    assert all(r.status_code == 200 for r in checks)
    assert checks[3].json()["build_commit"] == "m47-test-build-sha"
    assert dml == []


def test_persisted_stats_restore_is_idempotent_across_repeated_reads(client):
    domains.register_domain("restore", _ok_handler, version="1", source_ref="fixture")
    assert _call(client, "restore", "m47-restore-seed").status_code == 201
    domains._STATS.clear()

    from app.coordination.router import _load_persisted_stats
    for _ in range(3):
        with ops.SessionLocal() as session:
            _load_persisted_stats(session, include_unmounted=True)

    restored = domains._STATS["restore"]
    assert restored["invokes"] == 1 and restored["successes"] == 1
    assert restored["probe_lease_expirations"] == 0
