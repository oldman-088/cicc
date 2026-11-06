import { afterEach, describe, expect, it, vi } from "vitest";
import { GET, HEAD } from "./route";

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

    const invalidPath = await get(["coordination", "tasks", "deliver"]);
    expect(invalidPath.status).toBe(404);
    expect(fetchMock).not.toHaveBeenCalled();

    const invalidQuery = await get(["coordination", "tasks"], "?state=MADE_UP&limit=9999");
    expect(invalidQuery.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();

    const valid = await get(["coordination", "tasks"], "?state=RUNNING&kind=threat-intel&limit=100");
    expect(valid.status).toBe(200);
    const [url] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(url.toString()).toBe("https://api.example.test/api/v1/coordination/tasks?state=RUNNING&kind=threat-intel&limit=100");
  });

  it("proxies the source-confirmed health and task-trace GETs without accepting arbitrary task paths", async () => {
    vi.stubEnv("API_INTERNAL_URL", "https://api.example.test/internal/");
    vi.stubEnv("WEB_BFF_API_TOKEN", "read-token");
    vi.stubEnv("CICC_OPS_TRUSTED_SINGLE_TENANT", "true");
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })));
    vi.stubGlobal("fetch", fetchMock);

    const health = await get(["coordination", "health"]);
    expect(health.status).toBe(200);
    expect(fetchMock.mock.calls[0]?.[0]?.toString()).toBe(
      "https://api.example.test/internal/api/v1/coordination/health",
    );

    const trace = await get(["coordination", "task-trace"], "?task_id=api-task-123");
    expect(trace.status).toBe(200);
    expect(fetchMock.mock.calls[1]?.[0]?.toString()).toBe(
      "https://api.example.test/internal/api/v1/coordination/tasks/api-task-123/trace",
    );
    const [, traceInit] = fetchMock.mock.calls[1] as [URL, RequestInit];
    expect(traceInit.method).toBe("GET");
    expect(new Headers(traceInit.headers).get("authorization")).toBe("Bearer read-token");

    const traversal = await get(["coordination", "task-trace"], "?task_id=..%2F..%2Fops");
    expect(traversal.status).toBe(400);
    const malformedId = await get(["coordination", "task-trace"], "?task_id=not%20a%20backend%20id");
    expect(malformedId.status).toBe(400);
    expect(fetchMock).toHaveBeenCalledTimes(2);
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
});
