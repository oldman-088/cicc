import { afterEach, describe, expect, it, vi } from "vitest";
import {
  IntegrationApiError,
  parseCoordinationAgents,
  parseCoordinationMetrics,
  parseCoordinationTaskEvents,
  parseCoordinationHealth,
  parseCoordinationTaskTrace,
  coordinationTaskTraceEndpoint,
  parseCoordinationTasks,
  parseOpsOverview,
  readIntegrationResource,
} from "./integration-api";

afterEach(() => {
  vi.unstubAllGlobals();
});

const overviewPayload = {
  generated_at: "2026-11-05T10:00:00Z",
  overall_status: "ok",
  services: [],
  modules: [],
  metrics: {
    entities: 3,
    vulnerabilities: 2,
    campaigns: 1,
    recent_updates_24h: 4,
    last_successful_sync: null,
  },
  activity: [],
  data_source: "live-ops-database",
  cached: true,
  cache_age_s: 0.5,
};

describe("owner-provided API response decoders", () => {
  it("accepts an overview DTO and preserves source/cache metadata", () => {
    expect(parseOpsOverview(overviewPayload)).toMatchObject({
      generated_at: "2026-11-05T10:00:00Z",
      overall_status: "ok",
      data_source: "live-ops-database",
      cached: true,
      cache_age_s: 0.5,
      metrics: { entities: 3, vulnerabilities: 2, campaigns: 1 },
    });
  });

  it("rejects malformed operational fields instead of rendering them", () => {
    expect(() => parseOpsOverview({ ...overviewPayload, services: "healthy" })).toThrow(/Invalid integration response/);
    expect(() => parseOpsOverview({ ...overviewPayload, metrics: { ...overviewPayload.metrics, entities: -1 } })).toThrow(/Invalid integration response/);
  });

  it("accepts only the canonical AgentDTO (PR #4 M21/M23) and rejects obsolete aliases", () => {
    const base = {
      agent: "agent_a",
      specialization: null,
      capabilities: ["triage"],
      status: "available",
      stale: false,
      health: "ACTIVE",
      version: "1.0",
      meta: {},
      last_heartbeat: "2026-11-05T09:55:00Z",
      registered_at: "2026-11-05T09:00:00Z",
      active_tasks: 1,
      completed: 3,
      failed: 0,
      retries: 1,
      by_state: { COMPLETED: 3 },
    };
    expect(parseCoordinationAgents({ agents: [base] }).agents[0]).toMatchObject({
      last_heartbeat: "2026-11-05T09:55:00Z",
      health: "ACTIVE",
      completed: 3,
      failed: 0,
      retries: 1,
      by_state: { COMPLETED: 3 },
    });
    // Obsolete documented aliases are rejected even when values agree with canonical fields.
    for (const obsolete of [{ last_seen: null }, { completed_tasks: 3 }, { failed_tasks: 0 }]) {
      expect(() => parseCoordinationAgents({ agents: [{ ...base, ...obsolete }] })).toThrow(/obsolete alias/);
    }
    // Missing, null, malformed, and numeric-string canonical fields are rejected.
    const { completed: _c, ...missingCompleted } = base;
    expect(() => parseCoordinationAgents({ agents: [missingCompleted] })).toThrow(/completed/);
    expect(() => parseCoordinationAgents({ agents: [{ ...base, completed: null }] })).toThrow(/completed/);
    expect(() => parseCoordinationAgents({ agents: [{ ...base, completed: "3" }] })).toThrow(/completed/);
    expect(() => parseCoordinationAgents({ agents: [{ ...base, completed: -1 }] })).toThrow(/completed/);
    expect(() => parseCoordinationAgents({ agents: [{ ...base, last_heartbeat: 42 }] })).toThrow(/last_heartbeat/);
    expect(() => parseCoordinationAgents({ agents: [{ ...base, health: "healthy" }] })).toThrow(/health/);
    expect(() => parseCoordinationAgents({ agents: [{ ...base, by_state: { COMPLETED: "3" } }] })).toThrow(/by_state/);
    const { health: _h, ...missingHealth } = base;
    expect(() => parseCoordinationAgents({ agents: [missingHealth] })).toThrow(/health/);
  });

  it("validates coordination counts and task identity fields", () => {
    const metrics = parseCoordinationMetrics({
      tasks_total: 2,
      by_state: { RUNNING: 1, COMPLETED: 1 },
      by_kind: { ci_failed: 2 },
      active_by_agent: { agent_a: 1 },
      avg_progress_active: 50,
      dead_lettered: 0,
      deliveries_total: 2,
      deliveries_by_outcome: { published: 1, failed: 1 },
      approvals_pending: 0,
      agents_registered: 1,
      agents_online: 1,
    });
    expect(metrics.by_state.RUNNING).toBe(1);

    const tasks = parseCoordinationTasks({
      tasks: [{
        task_id: "task-1",
        kind: "ci_failed",
        state: "RUNNING",
        priority: 5,
        agent: "agent_a",
        title: "Build check",
        repo: "oldman-088/cicc",
        branch_ref: "main",
        created_at: "2026-11-05T09:00:00Z",
        updated_at: "2026-11-05T09:30:00Z",
        dead_letter: false,
      }],
    });
    expect(tasks.tasks[0]).toMatchObject({ task_id: "task-1", state: "RUNNING", agent: "agent_a" });
    expect(() => parseCoordinationTasks({ tasks: [{
      task_id: "",
      kind: "ci_failed",
      state: "RUNNING",
      priority: 1,
      agent: null,
      title: null,
      repo: null,
      branch_ref: null,
      created_at: null,
      updated_at: null,
      dead_letter: false,
    }] })).toThrow(/tasks\[0\]\.task_id must not be empty/);
  });
});

describe("same-origin integration client", () => {
  it("uses relative URLs, same-origin credentials, and no browser-held token", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(overviewPayload), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);
    const controller = new AbortController();

    const result = await readIntegrationResource(
      "/api/integrations/ops/overview",
      parseOpsOverview,
      controller.signal,
    );

    expect(result.data_source).toBe("live-ops-database");
    expect(fetchMock).toHaveBeenCalledWith("/api/integrations/ops/overview", expect.objectContaining({
      method: "GET",
      cache: "no-store",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    }));
    expect(fetchMock.mock.calls[0][1]?.headers).not.toHaveProperty("Authorization");
  });

  it("distinguishes an unconfigured server adapter from a provider response", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ error: { code: "provider_not_configured" } }),
      { status: 503, headers: { "Content-Type": "application/json" } },
    )));

    await expect(readIntegrationResource(
      "/api/integrations/ops/overview",
      parseOpsOverview,
      new AbortController().signal,
    )).rejects.toMatchObject<Partial<IntegrationApiError>>({ kind: "not_configured", status: 503 });
  });

  it("reports a contract error rather than substituting data for malformed JSON", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ ...overviewPayload, activity: null }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })));

    await expect(readIntegrationResource(
      "/api/integrations/ops/overview",
      parseOpsOverview,
      new AbortController().signal,
    )).rejects.toMatchObject<Partial<IntegrationApiError>>({ kind: "invalid_response" });
  });

  it("decodes M28 coordination health with explicit component statuses and reasons", () => {
    const health = parseCoordinationHealth({
      overall: "degraded",
      components: [
        { key: "agents", status: "degraded", detail: "0 active, 1 stale of 1 registered", reasons: ["agent 'h1' has no fresh heartbeat (stale/unavailable)"] },
        { key: "broker", status: "not_configured", detail: "RABBITMQ_AMQP_URL not set", reasons: ["no broker configured"] },
      ],
      reasons: ["agents: agent 'h1' has no fresh heartbeat (stale/unavailable)"],
      at: "2026-11-05T13:00:00Z",
    });
    expect(health.overall).toBe("degraded");
    expect(health.components[1].status).toBe("not_configured");
    // Unknown statuses fail closed rather than rendering as a generic indicator.
    expect(() => parseCoordinationHealth({ overall: "fine", components: [], reasons: [], at: null })).toThrow(/overall/);
    expect(() => parseCoordinationHealth({ overall: "healthy", components: [{ key: "x", status: "ok", detail: "", reasons: [] }], reasons: [], at: null })).toThrow(/status/);
  });

  it("decodes the M28 task trace: correlation, events, deliveries, approvals", () => {
    const trace = parseCoordinationTaskTrace({
      task_id: "api-1",
      correlation: { idempotency_key: "bff-key-1", event_id: null },
      state: "RUNNING",
      agent: "a1",
      attempts: 1,
      dead_letter: false,
      events: [{ id: 1, at: "2026-11-05T13:00:00Z", kind: "created", detail: null }],
      deliveries: [{ id: 2, channel: "human", queue: null, message_id: "m-1", status: "confirmed", attempt: 1, at: "2026-11-05T13:01:00Z" }],
      approvals: [],
    });
    expect(trace.correlation.idempotency_key).toBe("bff-key-1");
    expect(trace.deliveries[0].status).toBe("confirmed");
    expect(coordinationTaskTraceEndpoint("api 1")).toBe("/api/integrations/coordination/tasks/api%201/trace");
    expect(() => parseCoordinationTaskTrace({ task_id: "api-1" })).toThrow();
    expect(() => parseCoordinationTaskTrace({
      task_id: "api-1", correlation: { idempotency_key: null, event_id: null }, state: "RUNNING",
      agent: null, attempts: -1, dead_letter: false, events: [], deliveries: [], approvals: [],
    })).toThrow(/attempts/);
  });

  it("decodes per-task lifecycle events and the M27 idempotency correlation key", () => {
    expect(parseCoordinationTaskEvents({ task_id: "api-1", events: [{ at: "2026-11-05T12:00:00Z", kind: "created", detail: "kind=frontend_e2e" }] }))
      .toEqual({ task_id: "api-1", events: [{ at: "2026-11-05T12:00:00Z", kind: "created", detail: "kind=frontend_e2e" }] });
    expect(() => parseCoordinationTaskEvents({ task_id: "api-1", events: "created" })).toThrow(/events/);
  });
});
