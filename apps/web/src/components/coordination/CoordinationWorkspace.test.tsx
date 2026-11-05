import { fireEvent, render, screen } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CiccApplication } from "../application/CiccApplication";
import { CoordinationWorkspace } from "./CoordinationWorkspace";

function jsonResponse(body: unknown) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function stubProvider() {
  // Synthetic unit-test contract data only; this fixture is never used as a UI fallback.
  const responses: Record<string, unknown> = {
    metrics: {
      tasks_total: 2,
      by_state: { RUNNING: 1, QUEUED: 1 },
      by_kind: { ci_failed: 2 },
      active_by_agent: { agent_a: 1 },
      avg_progress_active: 30,
      dead_lettered: 0,
      deliveries_total: 1,
      deliveries_by_outcome: { published: 1 },
      approvals_pending: 1,
      agents_registered: 1,
      agents_online: 1,
    },
    agents: { agents: [{
      agent: "agent_a",
      specialization: "Build checks",
      capabilities: ["triage"],
      status: "online",
      stale: false,
      last_heartbeat: "2026-11-05T09:55:00Z",
      active_tasks: 1,
      completed: 3,
      failed: 0,
    }] },
    tasks: { tasks: [
      {
        task_id: "task-running",
        kind: "ci_failed",
        state: "RUNNING",
        priority: 5,
        agent: "agent_a",
        title: "Current build check",
        repo: "oldman-088/cicc",
        branch_ref: "feature/read-only",
        created_at: "2026-11-05T09:00:00Z",
        updated_at: "2026-11-05T09:30:00Z",
        dead_letter: false,
      },
      {
        task_id: "task-queued",
        kind: "pr_opened",
        state: "QUEUED",
        priority: 4,
        agent: null,
        title: "Queued review",
        repo: null,
        branch_ref: null,
        created_at: null,
        updated_at: null,
        dead_letter: false,
      },
    ] },
    events: { events: [{
      delivery_id: "delivery-1",
      event: "pull_request",
      received_at: "2026-11-05T09:45:00Z",
      action: "opened",
      repo: "oldman-088/cicc",
      sender: "sample-sender",
      task_id: "task-running",
    }] },
  };
  const fetchMock = vi.fn(async (input: RequestInfo | URL, _options?: RequestInit) => {
    const url = String(input);
    const key = Object.keys(responses).find((candidate) => url.endsWith(`/coordination/${candidate}`));
    return key ? jsonResponse(responses[key]) : new Response("", { status: 404 });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

describe("Agent Coordination workspace", () => {
  it("shows source-backed records, filters only the returned tasks, and stays read-only", async () => {
    const fetchMock = stubProvider();
    render(<CoordinationWorkspace />);

    expect(await screen.findByRole("heading", { name: "agent_a", level: 3 })).toBeInTheDocument();
    expect(screen.getByText("Task counts by state")).toBeInTheDocument();
    expect(screen.getByText("Webhook events received")).toBeInTheDocument();
    expect(screen.getByText("Current build check")).toBeInTheDocument();
    expect(screen.getByText("Queued review")).toBeInTheDocument();
    expect(screen.getByText(/Trusted single-tenant scope/)).toBeInTheDocument();

    fireEvent.change(screen.getByRole("combobox", { name: "Filter loaded tasks by state" }), {
      target: { value: "RUNNING" },
    });
    expect(screen.getByText("Current build check")).toBeInTheDocument();
    expect(screen.queryByText("Queued review")).not.toBeInTheDocument();

    fireEvent.change(screen.getByRole("searchbox", { name: "Search the returned task records" }), {
      target: { value: "not-a-task" },
    });
    expect(screen.getByText("No returned task records match the selected filters.")).toBeInTheDocument();

    expect(fetchMock).toHaveBeenCalledTimes(4);
    for (const [url, options] of fetchMock.mock.calls) {
      expect(String(url)).toMatch(/^\/api\/integrations\/coordination\//);
      expect(options?.method).toBe("GET");
      expect(options?.headers).not.toHaveProperty("Authorization");
    }
  });

  it("preserves Arabic/Persian RTL while isolating agent identifiers in LTR", async () => {
    window.localStorage.clear();
    stubProvider();
    render(<CiccApplication><CoordinationWorkspace /></CiccApplication>);
    const localeSelect = screen.getByRole("combobox", { name: "Interface language" });

    for (const [locale, title] of [
      ["ar", "تنسيق الوكلاء"],
      ["fa", "هماهنگی عامل‌ها"],
    ]) {
      fireEvent.change(localeSelect, { target: { value: locale } });
      const heading = await screen.findByRole("heading", { name: title, level: 1 });
      expect(heading.closest("[lang][dir]")).toHaveAttribute("lang", locale);
      expect(heading.closest("[lang][dir]")).toHaveAttribute("dir", "rtl");
    }

    const agentHeading = screen.getByRole("heading", { name: "agent_a", level: 3 });
    expect(agentHeading.querySelector("bdi")).toHaveAttribute("dir", "ltr");
  });

  it("marks stale agents using the provider flag rather than inferring liveness", async () => {
    const fetchMock = stubProvider();
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      if (String(input).endsWith("/coordination/agents")) {
        return jsonResponse({ agents: [{
          agent: "stale-agent",
          specialization: null,
          capabilities: [],
          status: "busy",
          stale: true,
          last_seen: null,
          active_tasks: 0,
          completed_tasks: 0,
          failed_tasks: 0,
        }] });
      }
      return new Response("", { status: 404 });
    });

    render(<CoordinationWorkspace />);
    expect(await screen.findByText("Stale per provider")).toBeInTheDocument();
    expect(screen.getAllByText("busy")).toHaveLength(2);
  });

  it("passes automated structural axe checks for populated panels (contrast excluded)", async () => {
    stubProvider();
    const { container } = render(<CoordinationWorkspace />);
    expect(await screen.findByText("Current build check")).toBeInTheDocument();
    const canvasContext = vi.spyOn(HTMLCanvasElement.prototype, "getContext")
      .mockImplementation(() => null as never);
    const results = await axe.run(container, {
      rules: { "color-contrast": { enabled: false } },
    }).finally(() => canvasContext.mockRestore());

    expect(results.violations.map((violation) => violation.id)).toEqual([]);
  });
});
