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

function post(path: string[], body?: unknown, headers?: HeadersInit) {
  const requestHeaders = new Headers(headers);
  if (body !== undefined && !requestHeaders.has("content-type")) {
    requestHeaders.set("Content-Type", "application/json");
  }
  if (!requestHeaders.has("origin")) requestHeaders.set("Origin", "http://cicc.test");
  if (!requestHeaders.has("sec-fetch-site")) requestHeaders.set("Sec-Fetch-Site", "same-origin");
  return POST(
    new Request(`http://cicc.test/api/integrations/${path.join("/")}`, {
      method: "POST",
      headers: requestHeaders,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    }),
    { params: Promise.resolve({ path }) },
  );
}

function configureTaskWrite(routing = false) {
  vi.stubEnv("API_INTERNAL_URL", "https://api.example.test/internal/");
  vi.stubEnv("WEB_BFF_WRITE_TOKEN", "server-write-secret");
  vi.stubEnv("CICC_OPS_TRUSTED_SINGLE_TENANT", "true");
  vi.stubEnv("WEB_BFF_ALLOW_COORD_WRITE", "1");
  vi.stubEnv("WEB_BFF_ALLOW_COORD_ROUTING", routing ? "1" : "0");
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

  it("reports write capability flags without exposing secrets or contacting the provider", async () => {
    vi.stubEnv("API_INTERNAL_URL", "https://api.example.test");
    vi.stubEnv("WEB_BFF_WRITE_TOKEN", "server-write-secret");
    vi.stubEnv("CICC_OPS_TRUSTED_SINGLE_TENANT", "true");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const disabled = await get(["coordination", "write-capabilities"]);
    expect(disabled.status).toBe(200);
    expect(await disabled.json()).toEqual({ task_creation_enabled: false, task_routing_enabled: false });
    expect(fetchMock).not.toHaveBeenCalled();

    vi.stubEnv("WEB_BFF_ALLOW_COORD_WRITE", "1");
    vi.stubEnv("WEB_BFF_ALLOW_COORD_ROUTING", "1");
    const enabled = await get(["coordination", "write-capabilities"]);
    expect(await enabled.json()).toEqual({ task_creation_enabled: true, task_routing_enabled: true });
    expect(enabled.headers.get("cache-control")).toContain("no-store");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("creates a task only through the fixed, gated route with a server-side token and correlation key", async () => {
    configureTaskWrite();
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      task_id: "api-task-7",
      kind: "review",
      state: "CREATED",
      duplicate: false,
    }), { status: 201, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);

    const response = await post(["coordination", "tasks"], {
      kind: "review",
      title: "Review the release",
      priority: 4,
      payload: { labels: ["integration"] },
      requires_approval: false,
    }, {
      Authorization: "Bearer browser-controlled-token",
      Cookie: "session=browser-cookie",
      "x-cicc-tenant-id": "untrusted-tenant",
    });
    const result = await response.json();

    expect(response.status).toBe(201);
    expect(result).toEqual({ task_id: "api-task-7", kind: "review", state: "CREATED", duplicate: false });
    const correlationKey = response.headers.get("x-cicc-idempotency-key");
    expect(correlationKey).toMatch(/^bff-[0-9a-f-]{36}$/);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(url.toString()).toBe("https://api.example.test/internal/api/v1/coordination/tasks");
    expect(init.method).toBe("POST");
    expect([...new Headers(init.headers).keys()].sort()).toEqual(["accept", "authorization", "content-type"]);
    expect(new Headers(init.headers).get("authorization")).toBe("Bearer server-write-secret");
    const forwarded = JSON.parse(String(init.body)) as Record<string, unknown>;
    expect(forwarded).toMatchObject({ kind: "review", priority: 4, title: "Review the release", payload: { labels: ["integration"] } });
    expect(forwarded.idempotency_key).toBe(correlationKey);
    expect("task_id" in forwarded).toBe(false);
  });

  it("fails closed for create and route writes unless their separate server flags are enabled", async () => {
    vi.stubEnv("API_INTERNAL_URL", "https://api.example.test");
    vi.stubEnv("WEB_BFF_WRITE_TOKEN", "server-write-secret");
    vi.stubEnv("CICC_OPS_TRUSTED_SINGLE_TENANT", "true");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const createResponse = await post(["coordination", "tasks"], { kind: "review" });
    const routeResponse = await post(["coordination", "tasks", "task-7", "route"]);
    expect(createResponse.status).toBe(503);
    expect(routeResponse.status).toBe(503);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("routes one validated task path through the separately gated source-confirmed action", async () => {
    configureTaskWrite(true);
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      task_id: "task-42",
      agent: "agent_one",
      state: "QUEUED",
      explanation: { via: "score", score: 92, candidates: 1, reasons: ["specialization match"] },
    }), { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);

    const response = await post(["coordination", "tasks", "task-42", "route"], undefined, {
      Authorization: "Bearer browser-controlled-token",
      Cookie: "session=browser-cookie",
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ task_id: "task-42", agent: "agent_one", state: "QUEUED" });
    const [url, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(url.toString()).toBe("https://api.example.test/internal/api/v1/coordination/tasks/task-42/route");
    expect(init.method).toBe("POST");
    expect(init.body).toBeUndefined();
    expect([...new Headers(init.headers).keys()].sort()).toEqual(["accept", "authorization"]);
    expect(new Headers(init.headers).get("authorization")).toBe("Bearer server-write-secret");
  });

  it("rejects cross-origin, unsafe task IDs, browser-supplied idempotency, and extra write fields", async () => {
    configureTaskWrite(true);
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const crossSite = await post(["coordination", "tasks"], { kind: "review" }, {
      Origin: "https://attacker.example",
      "Sec-Fetch-Site": "cross-site",
    });
    expect(crossSite.status).toBe(403);

    const unsafeTaskId = await post(["coordination", "tasks", "../ops", "route"]);
    expect(unsafeTaskId.status).toBe(400);

    const clientKey = await post(["coordination", "tasks"], { kind: "review", idempotency_key: "client-key" });
    expect(clientKey.status).toBe(422);
    const overlongPullRequestRef = await post(["coordination", "tasks"], { kind: "review", pr_ref: "x".repeat(101) });
    expect(overlongPullRequestRef.status).toBe(422);
    const extraWrite = await post(["coordination", "tasks"], { kind: "review", route: true });
    expect(extraWrite.status).toBe(422);
    expect(fetchMock).not.toHaveBeenCalled();
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
