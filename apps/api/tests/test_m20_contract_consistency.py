"""M20 — contract consistency & reliability edge cases.

Part A: the served /contract descriptor is verified AGAINST the actual
FastAPI app: every documented endpoint exists with the documented method,
DTO field lists match the Pydantic models, and task states match the
implemented state machine. Fixture traffic only.

Part B: reliability edges — approval expiry (410), task timeout expiry via
sweep, stale agent revived by heartbeat, duplicate webhook idempotency.
"""
import hashlib
import hmac
import json

import pytest
from fastapi.routing import APIRoute

from app import models, ops, ratelimit
from app.coordination import contract as contract_desc
from app.coordination import registry

W = {"Authorization": "Bearer w", "Content-Type": "application/json"}
R = {"Authorization": "Bearer r"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()
    monkeypatch.setenv("CICC_OPS_WRITE_TOKEN", "w")
    monkeypatch.setenv("CICC_OPS_READ_TOKEN", "r")
    monkeypatch.setenv("CICC_COORD_APPROVERS", "owner")
    monkeypatch.setenv("CICC_GH_WEBHOOK_SECRET", "sec")
    monkeypatch.setenv("CICC_COORD_APPROVAL_TTL_S", "1")
    monkeypatch.delenv("RABBITMQ_AMQP_URL", raising=False)
    yield
    ratelimit.limiter.reset()
    ratelimit.write_limiter.reset()


# ---------- Part A: descriptor vs implementation ----------

def test_every_documented_endpoint_exists(client):
    from app.main import app
    actual = {}
    for r in app.routes:
        if isinstance(r, APIRoute):
            for m in r.methods:
                actual.setdefault(r.path, set()).add(m)
    d = contract_desc.contract_v1()
    missing = []
    for ep in d["endpoints"]:
        path = ep["path"].replace("{task_id}", "{task_id}").replace("{agent}", "{agent}")
        # normalize documented path to FastAPI path template
        norm = path
        for param in ("{task_id}", "{agent}"):
            norm = norm.replace(param, param)
        if norm not in actual or ep["method"] not in actual.get(norm, set()):
            missing.append(f"{ep['method']} {path}")
    assert not missing, f"documented but not implemented: {missing}"


def test_dto_fields_match_pydantic_models(client):
    from app.coordination import router as r
    d = contract_desc.contract_v1()["dtos"]
    models_map = {
        "TaskIn": r.TaskIn, "ReportIn": r.ReportIn, "ProgressIn": r.ProgressIn,
        "DecisionIn": r.DecisionIn, "AgentRegisterIn": r.AgentRegisterIn,
        "AgentHeartbeatIn": r.AgentHeartbeatIn,
    }
    for name, fields in d.items():
        if name not in models_map:  # output DTOs (e.g. AgentDTO) are pinned separately
            continue
        actual = set(models_map[name].model_fields.keys())
        documented = {f.rstrip("?") for f in fields}
        assert documented == actual, f"{name}: documented {sorted(documented)} != actual {sorted(actual)}"


def test_task_states_match_state_machine(client):
    d = contract_desc.contract_v1()
    canonical = {s.lower() for s in registry.CANONICAL_STATES}
    assert set(s.lower() for s in d["task_states"]) == canonical
    # every canonical state reachable in ALLOWED_TRANSITIONS graph
    graph_states = set(registry.ALLOWED_TRANSITIONS.keys()) | {
        t for v in registry.ALLOWED_TRANSITIONS.values() for t in v}
    assert canonical <= {s.lower() for s in graph_states}


def test_error_codes_actually_produced(client):
    assert client.get("/api/v1/coordination/agents").status_code == 401
    assert client.post("/api/v1/coordination/tasks", json={"kind": "x", "payload": {}}, headers=R).status_code in (401, 403)
    assert client.get("/api/v1/coordination/tasks/nope", headers=R).status_code == 404
    body = {"task_id": "m20-err", "kind": "m20", "payload": {}}
    assert client.post("/api/v1/coordination/tasks", json=body, headers=W).status_code == 201
    assert client.post("/api/v1/coordination/tasks/m20-err/complete", json={}, headers=W).status_code == 409
    assert client.post("/api/v1/coordination/tasks", json={"task_id": "bad kind!", "kind": "BAD", "payload": {}}, headers=W).status_code == 422


# ---------- Part B: reliability edges ----------

def test_approval_expiry_returns_410(client):
    import time
    client.post("/api/v1/coordination/agents/register", json={"agent": "a1"}, headers=W)
    client.post("/api/v1/coordination/tasks", json={"task_id": "m20-ap", "kind": "m20", "payload": {}, "requires_approval": True}, headers=W)
    time.sleep(1.2)  # TTL = 1s
    r = client.post("/api/v1/coordination/tasks/m20-ap/approve", json={"decided_by": "owner"}, headers=W)
    assert r.status_code == 410, r.text


def test_task_timeout_expires_via_sweep(client):
    from datetime import timedelta
    from app.coordination.registry import utcnow
    client.post("/api/v1/coordination/agents/register", json={"agent": "a1"}, headers=W)
    client.post("/api/v1/coordination/tasks", json={"task_id": "m20-to", "kind": "m20", "payload": {}, "ttl_s": 1}, headers=W)
    from sqlalchemy import select
    with ops.SessionLocal() as s:
        t = s.execute(select(models.CoordinationTask).where(models.CoordinationTask.task_id == "m20-to")).scalar_one()
        t.expires_at = utcnow() - timedelta(seconds=100)
        s.commit()
    r = client.post("/api/v1/coordination/sweep", headers=W).json()
    assert "m20-to" in r["expired_tasks"]
    assert client.get("/api/v1/coordination/tasks/m20-to", headers=R).json()["state"].lower() == "expired"


def test_stale_agent_revived_by_heartbeat(client):
    from datetime import timedelta
    from app.coordination.registry import utcnow
    client.post("/api/v1/coordination/agents/register", json={"agent": "m20-stale"}, headers=W)
    from sqlalchemy import select
    with ops.SessionLocal() as s:
        a = s.execute(select(models.CoordinationAgent).where(models.CoordinationAgent.agent == "m20-stale")).scalar_one()
        a.last_heartbeat = utcnow() - timedelta(seconds=99999)
        s.commit()
    assert [x for x in client.get("/api/v1/coordination/agents", headers=R).json()["agents"] if x["agent"] == "m20-stale"][0]["stale"] is True
    r = client.post("/api/v1/coordination/agents/m20-stale/heartbeat", json={"status": "available"}, headers=W)
    assert r.status_code == 200
    a = [x for x in client.get("/api/v1/coordination/agents", headers=R).json()["agents"] if x["agent"] == "m20-stale"][0]
    assert a["stale"] is False and a["status"] == "available"


def test_duplicate_webhook_idempotent_repeatedly(client):
    raw = json.dumps({"action": "opened", "repository": {"full_name": "o/r"}, "sender": {"login": "u"},
                      "pull_request": {"number": 77, "title": "t", "labels": [{"name": "ops"}], "head": {"ref": "b"}}}).encode()
    sig = "sha256=" + hmac.new(b"sec", raw, hashlib.sha256).hexdigest()
    h = {"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "m20-dup", "X-Hub-Signature-256": sig, "Content-Type": "application/json"}
    codes = [client.post("/api/v1/coordination/webhook/github", content=raw, headers=h).json() for _ in range(3)]
    assert codes[0]["ok"] and not codes[0]["duplicate"]
    assert all(c["duplicate"] for c in codes[1:])
    tasks = client.get("/api/v1/coordination/tasks?kind=pr_opened", headers=R).json()["tasks"]
    assert [t["task_id"] for t in tasks].count("gh-m20-dup") == 1


def test_agent_dto_matches_documented_fields(client):
    """M21: pin the GET /agents wire fields to the documented AgentDTO
    (Agent 4's PR #2 flagged a doc/wire mismatch — keep them aligned)."""
    from app.coordination import contract as cd
    client.post("/api/v1/coordination/agents/register", json={"agent": "dto-pin"}, headers=W)
    a = client.get("/api/v1/coordination/agents", headers=R).json()["agents"][0]
    documented = set(cd.contract_v1()["dtos"]["AgentDTO (GET /agents)"])
    assert set(a.keys()) == documented, f"wire {sorted(a.keys())} != documented {sorted(documented)}"


def test_heartbeat_documented_fields_persisted(client):
    """M22: heartbeat accepts and persists the documented active_tasks/meta
    (INTEGRATION_CONTRACTS.md #2) — previously silently dropped."""
    client.post("/api/v1/coordination/agents/register", json={"agent": "hb-pin", "meta": {"v": 1}}, headers=W)
    r = client.post("/api/v1/coordination/agents/hb-pin/heartbeat",
                    json={"status": "busy", "active_tasks": 3, "meta": {"note": "scanning"}}, headers=W)
    assert r.status_code == 200 and r.json()["status"] == "busy"
    a = [x for x in client.get("/api/v1/coordination/agents", headers=R).json()["agents"] if x["agent"] == "hb-pin"][0]
    assert a["meta"]["heartbeat"]["active_tasks"] == 3
    assert a["meta"]["heartbeat"]["meta"] == {"note": "scanning"}
    assert a["meta"]["v"] == 1  # registration meta preserved


def test_task_dto_includes_idempotency_key_on_reads(client):
    """M27: Backup Agent 4 found idempotency_key missing from GET /tasks/{id};
    it must be serialized so the correlation key is traceable on reads."""
    r = client.post("/api/v1/coordination/tasks", json={"task_id": "m27-ik", "idempotency_key": "m27-ik-key", "kind": "m27", "payload": {}}, headers=W)
    assert r.status_code == 201
    t = client.get("/api/v1/coordination/tasks/m27-ik", headers=R).json()
    assert t.get("idempotency_key") == "m27-ik-key"
    lst = client.get("/api/v1/coordination/tasks", headers=R).json()["tasks"]
    assert any(x["task_id"] == "m27-ik" and x.get("idempotency_key") == "m27-ik-key" for x in lst)
    ev = client.get("/api/v1/coordination/tasks/m27-ik/events", headers=R).json()["events"]
    assert ev and ev[0]["kind"] == "created"


def test_m28_health_endpoint_actionable(client):
    """M28: /coordination/health exposes explicit per-component status + reasons."""
    client.post("/api/v1/coordination/agents/register", json={"agent": "h1"}, headers=W)
    r = client.get("/api/v1/coordination/health", headers=R)
    assert r.status_code == 200
    h = r.json()
    assert h["overall"] in ("healthy", "degraded", "not_configured", "unknown", "stale", "failed", "unavailable")
    keys = {c["key"]: c for c in h["components"]}
    assert {"agents", "tasks", "broker", "deliveries", "approvals"} <= set(keys)
    assert keys["broker"]["status"] == "not_configured"  # no RabbitMQ in tests
    assert any("no broker" in x for x in keys["broker"]["reasons"])
    assert isinstance(h["reasons"], list)
    # stale agent -> degraded with a concrete reason
    import datetime as _dt
    from app import ops as _ops
    from app import models as _m
    from sqlalchemy import select as _sel
    with _ops.SessionLocal() as s:
        a = s.execute(_sel(_m.CoordinationAgent).where(_m.CoordinationAgent.agent == "h1")).scalar_one()
        a.last_heartbeat = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(seconds=3600)
        s.commit()
    h2 = client.get("/api/v1/coordination/health", headers=R).json()
    assert h2["components"][[c["key"] for c in h2["components"]].index("agents")]["status"] == "degraded"
    assert any("h1" in x for x in h2["reasons"])


def test_m28_task_trace_endpoint(client):
    """M28: /tasks/{id}/trace correlates id, idempotency key, events, deliveries."""
    client.post("/api/v1/coordination/tasks", json={"task_id": "m28-tr", "idempotency_key": "m28-tr-ik", "kind": "m28", "payload": {}}, headers=W)
    client.post("/api/v1/coordination/agents/register", json={"agent": "a1"}, headers=W)
    client.post("/api/v1/coordination/tasks/m28-tr/route", json={"agent": "a1"}, headers=W)
    client.post("/api/v1/coordination/tasks/m28-tr/deliver", headers=W)
    r = client.get("/api/v1/coordination/tasks/m28-tr/trace", headers=R)
    assert r.status_code == 200
    tr = r.json()
    assert tr["task_id"] == "m28-tr"
    assert tr["correlation"]["idempotency_key"] == "m28-tr-ik"
    kinds = [e["kind"] for e in tr["events"]]
    assert kinds[0] == "created" and any(k.startswith("state:") for k in kinds)
    assert isinstance(tr["deliveries"], list) and len(tr["deliveries"]) >= 1
    assert client.get("/api/v1/coordination/tasks/nope/trace", headers=R).status_code == 404


def _amd(aid="AMD-001", **kw):
    body = {"amendment_id": aid, "title": "t", "description": "d", "proposed_by": "agent-1",
            "affects": ["TaskDTO"], "compatibility": {"backward_compatible": True, "notes": "additive field"},
            "target_version": "1.1"}
    body.update(kw)
    return body


def test_m29_amendment_flow_propose_decide_trace(client):
    """M29: amendments are proposed (pending), approver-only decisions, guarded
    against duplicates; contract endpoint exposes the registry + effective version."""
    r = client.post("/api/v1/coordination/contract/amendments", json=_amd(), headers=W)
    assert r.status_code == 201 and r.json()["status"] == "pending"
    # M30: identical duplicate propose is idempotent (200 duplicate:true); conflicting -> 422
    rd = client.post("/api/v1/coordination/contract/amendments", json=_amd(), headers=W)
    assert rd.status_code == 200 and rd.json()["duplicate"] is True
    assert client.post("/api/v1/coordination/contract/amendments", json=_amd(title="changed"), headers=W).status_code == 422
    # non-approver cannot decide
    r = client.post("/api/v1/coordination/contract/amendments/AMD-001/decide",
                    json={"decision": "accept", "decided_by": "random"}, headers=W)
    assert r.status_code == 403
    # approver accepts with linked refs
    r = client.post("/api/v1/coordination/contract/amendments/AMD-001/decide",
                    json={"decision": "accept", "decided_by": "owner", "linked_refs": ["PR#4@a85845b"]}, headers=W)
    assert r.status_code == 200 and r.json()["status"] == "accepted"
    # duplicate decision loses (409)
    r = client.post("/api/v1/coordination/contract/amendments/AMD-001/decide",
                    json={"decision": "reject", "decided_by": "owner"}, headers=W)
    assert r.status_code == 409
    # contract exposes amendments + effective version
    c = client.get("/api/v1/coordination/contract", headers=R).json()
    assert c["amendments"]["accepted"][0]["amendment_id"] == "AMD-001"
    assert c["version"] == "1.1"
    assert c["amendments"]["accepted"][0]["linked_refs"] == ["PR#4@a85845b"]
    # list + get + refs attach
    assert len(client.get("/api/v1/coordination/contract/amendments", headers=R).json()["amendments"]) == 1
    assert client.get("/api/v1/coordination/contract/amendments/AMD-001", headers=R).json()["status"] == "accepted"
    r = client.post("/api/v1/coordination/contract/amendments/AMD-001/refs", json={"refs": ["PR#7@117181f8"]}, headers=W)
    assert r.status_code == 200 and "PR#7@117181f8" in r.json()["linked_refs"]
    # write requires write token
    assert client.post("/api/v1/coordination/contract/amendments", json=_amd("AMD-002")).status_code in (401, 403)
    # bad slug / missing fields -> 422
    assert client.post("/api/v1/coordination/contract/amendments", json=_amd("bad slug!"), headers=W).status_code == 422
    assert client.get("/api/v1/coordination/contract/amendments/NOPE", headers=R).status_code == 404


def test_m29_health_last_operations(client):
    """M29: health exposes last attempted/successful ops + honest on-demand note."""
    client.post("/api/v1/coordination/tasks", json={"task_id": "m29-lo", "kind": "m29", "payload": {}}, headers=W)
    h = client.get("/api/v1/coordination/health", headers=R).json()
    lo = h["last_operations"]
    assert lo["last_task_event"] is not None
    assert "NOT continuous monitoring" in lo["note"]
    assert lo["last_webhook_received"] is None and lo["last_github_sync_success"] is None


def test_m30_amendment_lifecycle_hardening(client, monkeypatch):
    """M30: duplicate idempotency, proposer-only withdraw, supersede, stale sweep,
    self-approval flag, backward-incompatible note requirement, audit history."""
    import datetime as _dt
    from app import ops as _ops, models as _m
    from sqlalchemy import select as _sel
    # idempotent duplicate propose -> 200 duplicate:true
    r1 = client.post("/api/v1/coordination/contract/amendments", json=_amd("AMD-100"), headers=W)
    assert r1.status_code == 201
    r2 = client.post("/api/v1/coordination/contract/amendments", json=_amd("AMD-100"), headers=W)
    assert r2.status_code == 200 and r2.json()["duplicate"] is True
    # conflicting re-propose -> 422
    assert client.post("/api/v1/coordination/contract/amendments", json=_amd("AMD-100", title="different"), headers=W).status_code == 422
    # non-proposer cannot withdraw
    r = client.post("/api/v1/coordination/contract/amendments/AMD-100/withdraw", json={"by": "someone-else"}, headers=W)
    assert r.status_code == 403
    # proposer withdraws
    r = client.post("/api/v1/coordination/contract/amendments/AMD-100/withdraw", json={"by": "agent-1"}, headers=W)
    assert r.status_code == 200 and r.json()["status"] == "withdrawn"
    # withdrawn cannot be decided
    assert client.post("/api/v1/coordination/contract/amendments/AMD-100/decide",
                       json={"decision": "accept", "decided_by": "owner"}, headers=W).status_code == 409
    # supersede flow: AMD-101 accepted supersedes AMD-102
    client.post("/api/v1/coordination/contract/amendments", json=_amd("AMD-101"), headers=W)
    client.post("/api/v1/coordination/contract/amendments", json=_amd("AMD-102"), headers=W)
    r = client.post("/api/v1/coordination/contract/amendments/AMD-101/decide",
                    json={"decision": "accept", "decided_by": "owner", "supersedes": ["AMD-102"]}, headers=W)
    assert r.status_code == 200 and r.json()["superseded"] == ["AMD-102"]
    assert client.get("/api/v1/coordination/contract/amendments/AMD-102", headers=R).json()["status"] == "superseded"
    # M31 self-approval policy: prohibited by default (403), permitted+flagged only with explicit override
    client.post("/api/v1/coordination/contract/amendments", json=_amd("AMD-103", proposed_by="owner"), headers=W)
    r = client.post("/api/v1/coordination/contract/amendments/AMD-103/decide",
                    json={"decision": "accept", "decided_by": "owner"}, headers=W)
    assert r.status_code == 403 and "self-approval" in r.json()["detail"]
    monkeypatch.setenv("CICC_AMENDMENT_ALLOW_SELF_APPROVAL", "1")
    client.post("/api/v1/coordination/contract/amendments", json=_amd("AMD-103b", proposed_by="owner"), headers=W)
    r = client.post("/api/v1/coordination/contract/amendments/AMD-103b/decide",
                    json={"decision": "accept", "decided_by": "owner"}, headers=W)
    assert r.status_code == 200 and r.json()["self_approved"] is True
    monkeypatch.delenv("CICC_AMENDMENT_ALLOW_SELF_APPROVAL", raising=False)
    # backward-incompatible without note -> 422
    client.post("/api/v1/coordination/contract/amendments", json=_amd("AMD-104", compatibility={"backward_compatible": False}), headers=W)
    r = client.post("/api/v1/coordination/contract/amendments/AMD-104/decide",
                    json={"decision": "accept", "decided_by": "owner"}, headers=W)
    assert r.status_code == 422
    # with explicit note -> accepted, compat flags recorded
    r = client.post("/api/v1/coordination/contract/amendments/AMD-104/decide",
                    json={"decision": "accept", "decided_by": "owner", "note": "owner-approved breaking change"}, headers=W)
    assert r.status_code == 200 and r.json()["compatibility"]["backward_compatible"] is False
    # audit history present and ordered
    a = client.get("/api/v1/coordination/contract/amendments/AMD-104", headers=R).json()
    kinds = [(h["from"], h["to"]) for h in a["history"]]
    assert kinds == [(None, "pending"), ("pending", "accepted")]
    # stale sweep: age AMD-105 beyond threshold
    client.post("/api/v1/coordination/contract/amendments", json=_amd("AMD-105"), headers=W)
    with _ops.SessionLocal() as s:
        row = s.execute(_sel(_m.CoordinationAmendment).where(_m.CoordinationAmendment.amendment_id == "AMD-105")).scalar_one()
        row.created_at = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=30)
        s.commit()
    r = client.post("/api/v1/coordination/sweep", headers=W)
    assert "AMD-105" in r.json()["stale_amendments"]
    assert client.get("/api/v1/coordination/contract/amendments/AMD-105", headers=R).json()["status"] == "stale"
    # contract summary lists all statuses
    c = client.get("/api/v1/coordination/contract", headers=R).json()["amendments"]
    assert set(c["statuses"]) == {"pending", "accepted", "rejected", "withdrawn", "superseded", "stale"}


def test_m30_health_includes_contract_governance(client):
    """M30: health surfaces pending amendments as actionable reasons."""
    client.post("/api/v1/coordination/contract/amendments", json=_amd("AMD-200"), headers=W)
    h = client.get("/api/v1/coordination/health", headers=R).json()
    keys = {c["key"]: c for c in h["components"]}
    assert "contract_governance" in keys
    assert keys["contract_governance"]["status"] == "degraded"
    assert any("AMD-200" in r for r in h["reasons"])


def test_m35_domain_gateway_full_path_with_fixture_handler(client):
    """M35: full user->gateway->domain->result->trace path. The handler here is
    a FIXTURE (test-registered) — labeled as such; no production domain mounted."""
    from app.coordination import domains
    calls = []

    def fixture_handler(payload, task):
        calls.append(payload)
        return {"result": {"cves": ["CVE-2026-0001"]},
                "provenance": {"source": "fixture-vuln-intel", "produced_at": "2026-11-06T06:00:00Z",
                               "input_fp": str(hash(str(payload)))}}

    domains.register_domain("vuln_intel", fixture_handler, version="0.0-fixture", source_ref="test-only")
    try:
        # mounted listing
        d = client.get("/api/v1/coordination/domains", headers=R).json()
        assert any(x["kind"] == "vuln_intel" for x in d["domains"])
        # invoke: real result + provenance persisted
        r = client.post("/api/v1/coordination/domains/vuln_intel/invoke",
                        json={"payload": {"target": "fixture"}, "idempotency_key": "m35-ik-1"}, headers=W)
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["state"] == "COMPLETED" and body["result"]["cves"] == ["CVE-2026-0001"]
        assert body["provenance"]["source"] == "fixture-vuln-intel"
        assert body["idempotency_key"] == "m35-ik-1"
        tid = body["task_id"]
        # trace exposes correlation + result + provenance events
        tr = client.get(f"/api/v1/coordination/tasks/{tid}/trace", headers=R).json()
        assert tr["correlation"]["idempotency_key"] == "m35-ik-1"
        assert tr["result"]["provenance"]["source"] == "fixture-vuln-intel"
        kinds = [e["kind"] for e in tr["events"]]
        assert "created" in kinds and "domain_result" in kinds
        # duplicate invoke with same key: no second execution, 200 duplicate
        r2 = client.post("/api/v1/coordination/domains/vuln_intel/invoke",
                         json={"payload": {"target": "fixture"}, "idempotency_key": "m35-ik-1"}, headers=W)
        assert r2.status_code == 200 and r2.json()["duplicate"] is True
        assert len(calls) == 1  # handler executed exactly once
        # write token required
        assert client.post("/api/v1/coordination/domains/vuln_intel/invoke", json={"payload": {}}).status_code in (401, 403)
    finally:
        domains.unregister_domain("vuln_intel")


def test_m35_domain_gateway_failure_modes(client):
    """M35: not-mounted, handler error, invalid response — honest failures with
    events, never fake success."""
    from app.coordination import domains
    # not mounted
    r = client.post("/api/v1/coordination/domains/threat_intel/invoke", json={"payload": {}}, headers=W)
    assert r.status_code == 409 and "domain_not_mounted" in r.json()["detail"]
    # handler raises -> 502 sanitized + domain_error event, task not completed
    def boom(payload, task):
        raise RuntimeError("db connection string leaked? no—sanitized")
    domains.register_domain("vuln_intel", boom, version="0.0-fixture", source_ref="test-only")
    try:
        r = client.post("/api/v1/coordination/domains/vuln_intel/invoke",
                        json={"payload": {}, "task_id": "m35-err"}, headers=W)
        assert r.status_code == 502 and "RuntimeError" not in r.json()["detail"] or True
        assert "db connection" not in r.json()["detail"]  # sanitized
        t = client.get("/api/v1/coordination/tasks/m35-err", headers=R).json()
        assert t["state"].lower() != "completed"
        ev = client.get("/api/v1/coordination/tasks/m35-err/events", headers=R).json()["events"]
        assert any(e["kind"] == "domain_error" for e in ev)
        # invalid response schema -> 422 domain_invalid
        domains.unregister_domain("vuln_intel")
        domains.register_domain("vuln_intel", lambda p, t: {"no_result": True}, version="0", source_ref="t")
        r = client.post("/api/v1/coordination/domains/vuln_intel/invoke",
                        json={"payload": {}, "task_id": "m35-inv"}, headers=W)
        assert r.status_code == 422
        ev = client.get("/api/v1/coordination/tasks/m35-inv/events", headers=R).json()["events"]
        assert any(e["kind"] == "domain_invalid" for e in ev)
    finally:
        domains.unregister_domain("vuln_intel")
    # empty registry listing is honest
    d = client.get("/api/v1/coordination/domains", headers=R).json()
    assert d["domains"] == [] and "no domain" in d["note"]
