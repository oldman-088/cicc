import { afterEach, describe, expect, it, vi } from "vitest";
import {
  IntegrationApiError,
  parseCoordinationAgents,
  parseCoordinationHealth,
  parseCoordinationMetrics,
  parseCoordinationTaskTrace,
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

  it("accepts the two explicitly observed agent DTO spellings and exposes the timestamp field", () => {
    const implemented = parseCoordinationAgents({ agents: [{
      agent: "agent_a",
      specialization: null,
      capabilities: ["triage"],
      status: "available",
      stale: false,
      last_heartbeat: "2026-11-05T09:55:00Z",
      active_tasks: 1,
      completed: 3,
      failed: 0,
    }] }).agents[0];
    expect(implemented).toMatchObject({
      last_seen: "2026-11-05T09:55:00Z",
      last_seen_field: "last_heartbeat",
      completed_tasks: 3,
      failed_tasks: 0,
    });

    const documented = parseCoordinationAgents({ agents: [{
      agent: "agent_b",
      specialization: null,
      capabilities: [],
      status: "offline",
      stale: true,
      last_seen: null,
      active_tasks: 0,
      completed_tasks: 2,
      failed_tasks: 1,
    }] }).agents[0];
    expect(documented).toMatchObject({ last_seen_field: "last_seen", completed_tasks: 2, failed_tasks: 1 });

    expect(() => parseCoordinationAgents({ agents: [{
      agent: "agent_c",
      capabilities: [],
      status: "offline",
      stale: true,
      active_tasks: 0,
      completed_tasks: 1,
      completed: 2,
      failed_tasks: 0,
      failed: 0,
    }] })).toThrow(/conflict/);

    expect(() => parseCoordinationAgents({ agents: [{
      agent: "agent_d",
      specialization: null,
      capabilities: [],
      status: "offline",
      stale: false,
      last_seen: null,
      last_heartbeat: "2026-11-05T09:55:00Z",
      active_tasks: 0,
      completed_tasks: 0,
      failed_tasks: 0,
    }] })).toThrow(/last_seen and last_heartbeat conflict/);
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
  it("validates the source-reported health contract and preserves unknown/empty as explicit states", () => {
    const health = parseCoordinationHealth({
      overall: "degraded",
      components: [{ key: "broker", status: "not_configured", detail: "Human-assisted delivery only", reasons: ["No broker configured"] }],
      reasons: ["broker: No broker configured"],
      last_operations: {
        last_webhook_received: null,
        last_github_sync_success: null,
        last_github_sync_attempt: null,
        last_task_event: null,
        checked_at: "2026-11-06T09:00:00Z",
        note: "on-demand check; NOT continuous monitoring (no scheduler running)",
      },
      at: "2026-11-06T09:00:00Z",
    });
    expect(health.overall).toBe("degraded");
    expect(health.components[0]?.status).toBe("not_configured");
    expect(health.last_operations.last_webhook_received).toBeNull();
    expect(() => parseCoordinationHealth({
      overall: "green",
      components: [],
      reasons: [],
      last_operations: { note: "unknown" },
      at: null,
    })).toThrow(/not a documented coordination health status/);
  });

  it("decodes the read-only task trace without coercing missing correlation or lifecycle records", () => {
    const trace = parseCoordinationTaskTrace({
      task_id: "api-task-1",
      correlation: { idempotency_key: null, event_id: "delivery-event-1" },
      state: "RUNNING",
      agent: "agent-a",
      attempts: 2,
      dead_letter: false,
      events: [{ id: 1, at: "2026-11-06T09:00:00Z", kind: "created", detail: "Task accepted" }],
      deliveries: [],
      approvals: [],
    });
    expect(trace.correlation.idempotency_key).toBeNull();
    expect(trace.events[0]).toMatchObject({ kind: "created", detail: "Task accepted" });
    expect(trace.deliveries).toEqual([]);
    expect(() => parseCoordinationTaskTrace({
      task_id: "api-task-1",
      correlation: {},
      state: "RUNNING",
      agent: null,
      attempts: -1,
      dead_letter: false,
      events: [],
      deliveries: [],
      approvals: [],
    })).toThrow(/attempts must be a non-negative integer/);
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
});
