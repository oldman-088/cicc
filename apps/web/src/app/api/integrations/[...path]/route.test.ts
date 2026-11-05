import { afterEach, describe, expect, it, vi } from "vitest";
import { GET, HEAD, POST } from "./route";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

function get(path: string[], query = "", headers?: HeadersInit) {
  return GET(
    new Request(`http://cicc.test/api/integrations/${path.join("/")}${query}`, { headers }),
    { params: Promise.resolve({ path }) },
  );
}

describe("server-side integration adapter", () => {
  it("injects the optional read token server-side and never returns it", async () => {
    vi.stubEnv("API_INTERNAL_URL", "https://api.example.test/internal/");
    vi.stubEnv("WEB_BFF_API_TOKEN", "server-only-secret");
    vi.stubEnv("CICC_OPS_TRUSTED_SINGLE_TENANT", "true");
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ overall_status: "ok" }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);

    const response = await get(["ops", "overview"], "", {
      Authorization: "Bearer browser-controlled-token",
      Cookie: "session=browser-cookie",
      "x-cicc-tenant-id": "untrusted-tenant",
    });
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body).toEqual({ overall_status: "ok" });
    expect(JSON.stringify(body)).not.toContain("server-only-secret");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(url.toString()).toBe("https://api.example.test/internal/api/v1/ops/overview");
    expect(init.method).toBe("GET");
    expect([...new Headers(init.headers).keys()].sort()).toEqual(["accept", "authorization"]);
    expect(new Headers(init.headers).get("authorization")).toBe("Bearer server-only-secret");
  });

  it("requires an explicit trusted single-tenant deployment acknowledgement even with a read token", async () => {
    vi.stubEnv("API_INTERNAL_URL", "http://api.internal:8000");
    vi.stubEnv("WEB_BFF_API_TOKEN", "server-only-secret");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const response = await get(["coordination", "agents"]);
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: { code: "provider_not_configured" } });
    expect(fetchMock).not.toHaveBeenCalled();

    vi.stubEnv("WEB_BFF_API_TOKEN", "");
    vi.stubEnv("CICC_OPS_TRUSTED_SINGLE_TENANT", "true");
    const tokenlessMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ agents: [] }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    vi.stubGlobal("fetch", tokenlessMock);
    const tokenlessResponse = await get(["coordination", "agents"]);
    expect(tokenlessResponse.status).toBe(200);
    const [, init] = tokenlessMock.mock.calls[0] as [URL, RequestInit];
    expect(new Headers(init.headers).has("authorization")).toBe(false);
  });

  it("allows only documented read paths and bounds coordination query parameters", async () => {
    vi.stubEnv("API_INTERNAL_URL", "https://api.example.test");
    vi.stubEnv("WEB_BFF_API_TOKEN", "read-token");
    vi.stubEnv("CICC_OPS_TRUSTED_SINGLE_TENANT", "true");
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ tasks: [] }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);

    const invalidPath = await get(["coordination", "unknown-resource"]);
    expect(invalidPath.status).toBe(404);
    expect(fetchMock).not.toHaveBeenCalled();

    const invalidQuery = await get(["coordination", "tasks"], "?state=MADE_UP&limit=9999");
    expect(invalidQuery.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();

    const valid = await get(["coordination", "tasks"], "?state=RUNNING&kind=threat-intel&limit=100");
    expect(valid.status).toBe(200);
    const [url] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(url.toString()).toBe("https://api.example.test/api/v1/coordination/tasks?state=RUNNING&kind=threat-intel&limit=100");
    fetchMock.mockImplementation(async () => new Response(JSON.stringify({ task_id: "api-123" }), { status: 200, headers: { "Content-Type": "application/json" } }));
    const invalidTaskId = await get(["coordination", "tasks", "bad id!"]);
    expect(invalidTaskId.status).toBe(400);
    const taskById = await get(["coordination", "tasks", "api-123"]);
    expect(taskById.status).toBe(200);
    const taskEvents = await get(["coordination", "tasks", "api-123", "events"]);
    expect(taskEvents.status).toBe(200);
    const taskTrace = await get(["coordination", "tasks", "api-123", "trace"]);
    expect(taskTrace.status).toBe(200);
    const health = await get(["coordination", "health"]);
    expect(health.status).toBe(200);
    const badTraceId = await get(["coordination", "tasks", "bad id!", "trace"]);
    expect(badTraceId.status).toBe(400);
    const unknownSuffix = await get(["coordination", "tasks", "api-123", "deliver"]);
    expect(unknownSuffix.status).toBe(404);
  });

  it("sanitizes upstream rate-limit errors and preserves a safe Retry-After", async () => {
    vi.stubEnv("API_INTERNAL_URL", "https://api.example.test");
    vi.stubEnv("WEB_BFF_API_TOKEN", "read-token");
    vi.stubEnv("CICC_OPS_TRUSTED_SINGLE_TENANT", "true");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("internal detail", {
      status: 429,
      headers: { "Retry-After": "30", "Content-Type": "text/plain" },
    })));

    const response = await get(["ops", "alerts"]);
    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBe("30");
    expect(await response.json()).toEqual({ error: { code: "rate_limited" } });
  });

  it("rejects an oversized upstream JSON body with a streaming byte cap", async () => {
    vi.stubEnv("API_INTERNAL_URL", "https://api.example.test");
    vi.stubEnv("CICC_OPS_TRUSTED_SINGLE_TENANT", "true");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ data: "x".repeat(2_000_001) }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    )));

    const response = await get(["ops", "overview"]);
    expect(response.status).toBe(502);
    expect(await response.json()).toEqual({ error: { code: "invalid_upstream_response" } });
  });

  it("rejects HEAD rather than implicitly proxying it through GET", () => {
    const response = HEAD();
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("GET");
    expect(response.headers.get("cache-control")).toContain("no-store");
  });

  it("rejects cross-site browser requests when same-origin enforcement is enabled", async () => {
    vi.stubEnv("API_INTERNAL_URL", "https://api.example.test");
    vi.stubEnv("WEB_BFF_API_TOKEN", "read-token");
    vi.stubEnv("CICC_OPS_TRUSTED_SINGLE_TENANT", "true");
    vi.stubEnv("WEB_BFF_ENFORCE_SAME_ORIGIN", "1");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const response = await get(["ops", "overview"], "", { "Sec-Fetch-Site": "cross-site" });
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: { code: "cross_site_forbidden" } });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("maps upstream network failure/timeout to a sanitized 503 without leaking details", async () => {
    vi.stubEnv("API_INTERNAL_URL", "https://api.example.test/");
    vi.stubEnv("CICC_OPS_TRUSTED_SINGLE_TENANT", "true");
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("connect ECONNREFUSED secret-internal-host")));
    const response = await get(["coordination", "agents"]);
    expect(response.status).toBe(503);
    const text = await response.text();
    expect(text).toContain("upstream_unavailable");
    expect(text).not.toContain("secret-internal-host");
  });

  it("rejects malformed/non-JSON upstream payloads as invalid_upstream_response", async () => {
    vi.stubEnv("API_INTERNAL_URL", "https://api.example.test/");
    vi.stubEnv("CICC_OPS_TRUSTED_SINGLE_TENANT", "true");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("<html>not json</html>", {
      status: 200, headers: { "Content-Type": "application/json" },
    })));
    const response = await get(["coordination", "agents"]);
    expect(response.status).toBe(502);
    expect(await response.text()).toContain("invalid_upstream_response");
  });

  it("maps upstream 401 to unauthorized without forwarding upstream body", async () => {
    vi.stubEnv("API_INTERNAL_URL", "https://api.example.test/");
    vi.stubEnv("CICC_OPS_TRUSTED_SINGLE_TENANT", "true");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: "invalid or missing read token" }), {
      status: 401, headers: { "Content-Type": "application/json" },
    })));
    const response = await get(["coordination", "agents"]);
    expect(response.status).toBe(401);
    const text = await response.text();
    expect(text).toContain("unauthorized");
    expect(text).not.toContain("read token");
  });

  it("write path: rejects non-tasks POSTs and disabled writes", async () => {
    const res = await POST(new Request("http://cicc.test/api/integrations/ops/overview", { method: "POST" }), { params: Promise.resolve({ path: ["ops", "overview"] }) });
    expect(res.status).toBe(403);
    vi.stubEnv("API_INTERNAL_URL", "https://api.example.test/");
    vi.stubEnv("CICC_OPS_TRUSTED_SINGLE_TENANT", "true");
    vi.stubEnv("WEB_BFF_WRITE_TOKEN", "write-secret");
    const disabled = await POST(new Request("http://cicc.test/api/integrations/coordination/tasks", { method: "POST", body: "{}" }), { params: Promise.resolve({ path: ["coordination", "tasks"] }) });
    expect(disabled.status).toBe(403);
    expect(await disabled.text()).toContain("write_not_enabled");
  });

  it("write path: injects server write token, generates idempotency key, strips browser auth", async () => {
    vi.stubEnv("API_INTERNAL_URL", "https://api.example.test/");
    vi.stubEnv("CICC_OPS_TRUSTED_SINGLE_TENANT", "true");
    vi.stubEnv("WEB_BFF_WRITE_TOKEN", "write-secret");
    vi.stubEnv("WEB_BFF_ALLOW_COORD_WRITE", "1");
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ task_id: "api-1", state: "CREATED", kind: "frontend_e2e" }), { status: 201, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);
    const res = await POST(new Request("http://cicc.test/api/integrations/coordination/tasks", {
      method: "POST", headers: { Authorization: "Bearer browser-token", Cookie: "session=x", "Content-Type": "application/json" },
      body: JSON.stringify({ kind: "frontend_e2e", title: "Verify me" }),
    }), { params: Promise.resolve({ path: ["coordination", "tasks"] }) });
    expect(res.status).toBe(201);
    expect(res.headers.get("x-cicc-idempotency-key")).toMatch(/^bff-/);
    const [url, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(url.toString()).toBe("https://api.example.test/api/v1/coordination/tasks");
    expect(new Headers(init.headers).get("authorization")).toBe("Bearer write-secret");
    const sent = JSON.parse(String(init.body)) as Record<string, unknown>;
    expect(sent.idempotency_key).toMatch(/^bff-/);
    expect(JSON.stringify(sent)).not.toContain("browser-token");
  });

  it("write path: unknown fields and bad kind are 422 without calling upstream", async () => {
    vi.stubEnv("API_INTERNAL_URL", "https://api.example.test/");
    vi.stubEnv("CICC_OPS_TRUSTED_SINGLE_TENANT", "true");
    vi.stubEnv("WEB_BFF_WRITE_TOKEN", "write-secret");
    vi.stubEnv("WEB_BFF_ALLOW_COORD_WRITE", "1");
    const fetchMock = vi.fn(); vi.stubGlobal("fetch", fetchMock);
    for (const body of [{ kind: "frontend_e2e", title: "x", evil: 1 }, { kind: "Bad Kind!", title: "x" }, { kind: "ok_kind", title: "" }]) {
      const res = await POST(new Request("http://cicc.test/api/integrations/coordination/tasks", { method: "POST", body: JSON.stringify(body) }), { params: Promise.resolve({ path: ["coordination", "tasks"] }) });
      expect(res.status).toBe(422);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
