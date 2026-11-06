import { randomUUID } from "node:crypto";

type QueryRule = {
  defaultValue?: string;
  validate: (value: string) => boolean;
};

type UpstreamRoute = {
  path: string;
  pathFromQuery?: (query: URLSearchParams) => string;
  query?: Record<string, QueryRule>;
};

const canonicalTaskStates = new Set([
  "CREATED",
  "VALIDATING",
  "QUEUED",
  "ASSIGNED",
  "DELIVERING",
  "ACKNOWLEDGED",
  "RUNNING",
  "WAITING_FOR_APPROVAL",
  "COMPLETED",
  "FAILED",
  "RETRYING",
  "BLOCKED",
  "CANCELLED",
  "EXPIRED",
]);

const integerInRange = (min: number, max: number) => (value: string) => {
  if (!/^\d+$/.test(value)) return false;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= min && parsed <= max;
};

const safeTaskId = (value: string) =>
  value.length > 0 &&
  value.length <= 128 &&
  value !== "." &&
  value !== ".." &&
  /^[A-Za-z0-9_.:-]+$/.test(value);

const routes: Record<string, UpstreamRoute> = {
  "ops/overview": { path: "api/v1/ops/overview" },
  "ops/alerts": {
    path: "api/v1/ops/alerts",
    query: {
      state: {
        defaultValue: "active",
        validate: (value) => ["active", "acknowledged", "resolved", "all"].includes(value),
      },
      limit: { defaultValue: "100", validate: integerInRange(1, 500) },
    },
  },
  "ops/workers": { path: "api/v1/ops/workers" },
  "coordination/agents": { path: "api/v1/coordination/agents" },
  "coordination/health": { path: "api/v1/coordination/health" },
  "coordination/task-trace": {
    path: "api/v1/coordination/tasks",
    pathFromQuery: (query) =>
      `api/v1/coordination/tasks/${encodeURIComponent(query.get("task_id") ?? "")}/trace`,
    query: { task_id: { defaultValue: "", validate: safeTaskId } },
  },
  "coordination/tasks": {
    path: "api/v1/coordination/tasks",
    query: {
      state: { validate: (value) => canonicalTaskStates.has(value) },
      agent: { validate: (value) => value.length > 0 && value.length <= 64 && !/[\u0000-\u001f\u007f]/.test(value) },
      kind: { validate: (value) => value.length > 0 && value.length <= 64 && !/[\u0000-\u001f\u007f]/.test(value) },
      dead_letter: { validate: (value) => value === "true" || value === "false" },
      limit: { defaultValue: "100", validate: integerInRange(1, 500) },
    },
  },
  "coordination/metrics": { path: "api/v1/coordination/metrics" },
  "coordination/events": {
    path: "api/v1/coordination/events",
    query: { limit: { defaultValue: "100", validate: integerInRange(1, 500) } },
  },
};

const noStoreHeaders = { "Cache-Control": "no-store, max-age=0" };

function json(body: unknown, status: number, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...noStoreHeaders,
      "Content-Type": "application/json; charset=utf-8",
      ...extraHeaders,
    },
  });
}

function problem(code: string, status: number, extraHeaders: Record<string, string> = {}): Response {
  return json({ error: { code } }, status, extraHeaders);
}

function makeQuery(requestUrl: URL, spec: UpstreamRoute): URLSearchParams | null {
  const rules = spec.query ?? {};
  const suppliedKeys = new Set(requestUrl.searchParams.keys());
  for (const key of suppliedKeys) {
    if (!(key in rules) || requestUrl.searchParams.getAll(key).length !== 1) return null;
  }

  const output = new URLSearchParams();
  for (const [key, rule] of Object.entries(rules)) {
    const supplied = requestUrl.searchParams.get(key);
    const value = supplied ?? rule.defaultValue;
    if (value === undefined) continue;
    if (!rule.validate(value)) return null;
    output.set(key, value);
  }
  return output;
}

function getUpstreamBase(): URL | null {
  const configured = process.env.API_INTERNAL_URL?.trim();
  if (!configured) return null;
  try {
    const base = new URL(configured);
    if (
      !["http:", "https:"].includes(base.protocol) ||
      base.username.length > 0 ||
      base.password.length > 0 ||
      base.search.length > 0 ||
      base.hash.length > 0
    ) return null;
    base.pathname = `${base.pathname.replace(/\/+$/, "")}/`;
    return base;
  } catch {
    return null;
  }
}

function sameOriginAllowed(request: Request): boolean {
  if (process.env.WEB_BFF_ENFORCE_SAME_ORIGIN !== "1") return true;
  const fetchSite = request.headers.get("sec-fetch-site");
  if (!fetchSite) return true;
  return ["same-origin", "same-site", "none"].includes(fetchSite);
}

function mapUpstreamFailure(status: number): { code: string; status: number } {
  if (status === 401) return { code: "unauthorized", status };
  if (status === 403) return { code: "forbidden", status };
  if (status === 404) return { code: "not_found", status };
  if (status === 409) return { code: "conflict", status };
  if (status === 410) return { code: "expired", status };
  if (status === 413) return { code: "payload_too_large", status };
  if (status === 422) return { code: "invalid_request", status };
  if (status === 429) return { code: "rate_limited", status };
  if (status >= 500) return { code: "upstream_unavailable", status: 503 };
  return { code: "upstream_unavailable", status: 502 };
}

const maxResponseBytes = 2_000_000;

async function readJsonWithinLimit(response: Response): Promise<{ ok: true; value: unknown } | { ok: false }> {
  if (!response.body) return { ok: false };
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxResponseBytes) {
        void reader.cancel().catch(() => undefined);
        return { ok: false };
      }
      chunks.push(value);
    }

    const bytes = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    void reader.cancel().catch(() => undefined);
    return { ok: false };
  } finally {
    reader.releaseLock();
  }
}

const maxWriteRequestBytes = 256_000;
const safeCoordinationIdPattern = /^[A-Za-z0-9_.:-]{1,200}$/;
const safePullRequestRefPattern = /^[A-Za-z0-9_.:-]{1,100}$/;
const coordinationKindPattern = /^[a-z0-9_]{1,64}$/;
const allowedCreateTaskFields = new Set([
  "kind",
  "priority",
  "title",
  "payload",
  "repo",
  "pr_ref",
  "branch_ref",
  "owner",
  "depends_on",
  "timeout_s",
  "ttl_s",
  "requires_approval",
]);

function coordinationWriteToken(): string | null {
  const token = process.env.WEB_BFF_WRITE_TOKEN?.trim() ?? "";
  return token && !/[\r\n]/.test(token) ? token : null;
}

function coordinationWritePrerequisitesMet(): boolean {
  return Boolean(
    getUpstreamBase() &&
    process.env.CICC_OPS_TRUSTED_SINGLE_TENANT === "true" &&
    coordinationWriteToken(),
  );
}

function coordinationWriteCapabilities(): { task_creation_enabled: boolean; task_routing_enabled: boolean } {
  const configured = coordinationWritePrerequisitesMet();
  return {
    task_creation_enabled: configured && process.env.WEB_BFF_ALLOW_COORD_WRITE === "1",
    task_routing_enabled: configured && process.env.WEB_BFF_ALLOW_COORD_ROUTING === "1",
  };
}

function sameOriginWriteAllowed(request: Request): boolean {
  const originHeader = request.headers.get("origin");
  if (!originHeader) return false;

  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite !== null && fetchSite !== "same-origin") return false;

  const requestUrl = new URL(request.url);
  const forwardedHost = request.headers.get("x-forwarded-host")?.split(",")[0]?.trim();
  const forwardedProtocol = request.headers.get("x-forwarded-proto")?.split(",")[0]?.trim().toLowerCase();
  const host = forwardedHost || request.headers.get("host") || requestUrl.host;
  const protocol = forwardedProtocol || requestUrl.protocol.slice(0, -1);
  if (!host || !/^(http|https)$/.test(protocol)) return false;

  try {
    const expectedOrigin = new URL(`${protocol}://${host}`).origin;
    return new URL(originHeader).origin === expectedOrigin;
  } catch {
    return false;
  }
}

async function readRequestJsonWithinLimit(
  request: Request,
): Promise<{ ok: true; value: unknown } | { ok: false; tooLarge: boolean }> {
  const declaredLength = request.headers.get("content-length");
  if (declaredLength && /^\d+$/.test(declaredLength) && Number(declaredLength) > maxWriteRequestBytes) {
    return { ok: false, tooLarge: true };
  }
  if (!request.body) return { ok: false, tooLarge: false };

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxWriteRequestBytes) {
        void reader.cancel().catch(() => undefined);
        return { ok: false, tooLarge: true };
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    void reader.cancel().catch(() => undefined);
    return { ok: false, tooLarge: false };
  } finally {
    reader.releaseLock();
  }
}

type CreateTaskValidation =
  | { ok: true; value: Record<string, unknown>; idempotencyKey: string }
  | { ok: false };

function validateCreateTaskBody(value: unknown): CreateTaskValidation {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return { ok: false };
  const input = value as Record<string, unknown>;
  if (Object.keys(input).some((key) => !allowedCreateTaskFields.has(key))) return { ok: false };
  if (typeof input.kind !== "string" || !coordinationKindPattern.test(input.kind)) return { ok: false };
  if (
    input.payload !== undefined &&
    (typeof input.payload !== "object" || input.payload === null || Array.isArray(input.payload))
  ) return { ok: false };

  const output: Record<string, unknown> = { kind: input.kind, payload: input.payload ?? {} };
  if (input.priority !== undefined) {
    if (!Number.isInteger(input.priority) || (input.priority as number) < 1 || (input.priority as number) > 10) return { ok: false };
    output.priority = input.priority;
  }
  if (input.title !== undefined) {
    if (typeof input.title !== "string" || input.title.length > 500) return { ok: false };
    output.title = input.title;
  }
  for (const field of ["repo", "owner"] as const) {
    if (input[field] !== undefined) {
      if (typeof input[field] !== "string" || input[field].length > 200) return { ok: false };
      output[field] = input[field];
    }
  }
  for (const field of ["pr_ref", "branch_ref"] as const) {
    if (input[field] !== undefined) {
      const pattern = field === "pr_ref" ? safePullRequestRefPattern : safeCoordinationIdPattern;
      if (typeof input[field] !== "string" || !pattern.test(input[field])) return { ok: false };
      output[field] = input[field];
    }
  }
  if (input.depends_on !== undefined) {
    if (
      !Array.isArray(input.depends_on) ||
      input.depends_on.length > 50 ||
      !input.depends_on.every((id) => typeof id === "string" && safeCoordinationIdPattern.test(id))
    ) return { ok: false };
    output.depends_on = input.depends_on;
  }
  for (const field of ["timeout_s", "ttl_s"] as const) {
    if (input[field] !== undefined) {
      if (!Number.isInteger(input[field]) || (input[field] as number) < 1 || (input[field] as number) > 86400 * 30) return { ok: false };
      output[field] = input[field];
    }
  }
  if (input.requires_approval !== undefined) {
    if (typeof input.requires_approval !== "boolean") return { ok: false };
    output.requires_approval = input.requires_approval;
  }

  const idempotencyKey = `bff-${randomUUID()}`;
  output.idempotency_key = idempotencyKey;
  return { ok: true, value: output, idempotencyKey };
}

function isTaskCreateResponse(value: unknown): value is {
  task_id: string;
  state: string;
  kind: string;
  duplicate: boolean;
} {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const item = value as Record<string, unknown>;
  return typeof item.task_id === "string" && item.task_id.trim().length > 0 &&
    typeof item.state === "string" && item.state.trim().length > 0 &&
    typeof item.kind === "string" && item.kind.trim().length > 0 &&
    typeof item.duplicate === "boolean";
}

function isTaskRouteResponse(value: unknown, expectedTaskId: string): boolean {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const item = value as Record<string, unknown>;
  if (
    item.task_id !== expectedTaskId ||
    (item.agent !== null && (typeof item.agent !== "string" || item.agent.trim().length === 0)) ||
    typeof item.state !== "string" ||
    !canonicalTaskStates.has(item.state) ||
    typeof item.explanation !== "object" || item.explanation === null || Array.isArray(item.explanation)
  ) return false;
  const explanation = item.explanation as Record<string, unknown>;
  return typeof explanation.via === "string" && explanation.via.trim().length > 0 &&
    (explanation.rule === undefined || explanation.rule === null || typeof explanation.rule === "string") &&
    (explanation.score === undefined || explanation.score === null || (typeof explanation.score === "number" && Number.isFinite(explanation.score))) &&
    (explanation.candidates === undefined || explanation.candidates === null || (Number.isSafeInteger(explanation.candidates) && (explanation.candidates as number) >= 0)) &&
    (explanation.reasons === undefined || (Array.isArray(explanation.reasons) && explanation.reasons.every((reason) => typeof reason === "string")));
}

async function requestHasEmptyBody(request: Request): Promise<boolean> {
  const declaredLength = request.headers.get("content-length");
  if (declaredLength && /^\d+$/.test(declaredLength) && Number(declaredLength) > 0) return false;
  if (!request.body) return true;
  const reader = request.body.getReader();
  try {
    const first = await reader.read();
    if (!first.done) {
      void reader.cancel().catch(() => undefined);
      return false;
    }
    return true;
  } catch {
    void reader.cancel().catch(() => undefined);
    return false;
  } finally {
    reader.releaseLock();
  }
}

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const revalidate = 0;

export function HEAD(): Response {
  return new Response(null, { status: 405, headers: { ...noStoreHeaders, Allow: "GET" } });
}

export async function GET(
  request: Request,
  context: { params: Promise<{ path: string[] }> },
): Promise<Response> {
  const { path } = await context.params;
  const routeKey = path.join("/");
  if (routeKey === "coordination/write-capabilities") {
    if (!sameOriginAllowed(request)) return problem("cross_site_forbidden", 403);
    if (new URL(request.url).search) return problem("invalid_request", 400);
    return json(coordinationWriteCapabilities(), 200);
  }
  const spec = routes[routeKey];
  if (!spec) return problem("not_found", 404);
  if (!sameOriginAllowed(request)) return problem("cross_site_forbidden", 403);

  const requestUrl = new URL(request.url);
  const query = makeQuery(requestUrl, spec);
  if (query === null) return problem("invalid_request", 400);

  const base = getUpstreamBase();
  if (!base) return problem("provider_not_configured", 503);

  const bffToken = process.env.WEB_BFF_API_TOKEN?.trim();
  const trustedSingleTenant = process.env.CICC_OPS_TRUSTED_SINGLE_TENANT === "true";
  if (!trustedSingleTenant) return problem("provider_not_configured", 503);
  if (bffToken && /[\r\n]/.test(bffToken)) return problem("provider_not_configured", 503);

  const upstreamUrl = new URL(spec.pathFromQuery?.(query) ?? spec.path, base);
  if (!spec.pathFromQuery) upstreamUrl.search = query.toString();
  const headers: Record<string, string> = { Accept: "application/json" };
  if (bffToken) headers.Authorization = `Bearer ${bffToken}`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);
  try {
    const upstream = await fetch(upstreamUrl, {
      method: "GET",
      headers,
      cache: "no-store",
      redirect: "error",
      signal: controller.signal,
    });

    if (!upstream.ok) {
      void upstream.body?.cancel().catch(() => undefined);
      const mapped = mapUpstreamFailure(upstream.status);
      const retryAfter = upstream.headers.get("retry-after");
      const safeRetryAfter = retryAfter && /^\d{1,5}$/.test(retryAfter) ? retryAfter : undefined;
      return problem(
        mapped.code,
        mapped.status,
        mapped.code === "rate_limited" && safeRetryAfter ? { "Retry-After": safeRetryAfter } : {},
      );
    }

    const contentType = upstream.headers.get("content-type") ?? "";
    const declaredLength = upstream.headers.get("content-length");
    const declaredTooLarge = declaredLength !== null && /^\d+$/.test(declaredLength) && Number(declaredLength) > maxResponseBytes;
    if (!/^application\/json\b/i.test(contentType) || declaredTooLarge) {
      void upstream.body?.cancel().catch(() => undefined);
      return problem("invalid_upstream_response", 502);
    }

    const parsed = await readJsonWithinLimit(upstream);
    if (!parsed.ok) return problem("invalid_upstream_response", 502);
    return json(parsed.value, 200);
  } catch {
    return problem("upstream_unavailable", 503);
  } finally {
    clearTimeout(timeout);
  }
}

export async function POST(
  request: Request,
  context: { params: Promise<{ path: string[] }> },
): Promise<Response> {
  const { path } = await context.params;
  const createTaskRoute = path.length === 2 && path[0] === "coordination" && path[1] === "tasks";
  const routeTaskCandidate = path.length === 4 && path[0] === "coordination" && path[1] === "tasks" && path[3] === "route";
  const taskId = routeTaskCandidate ? path[2] : undefined;
  const routeTask = routeTaskCandidate && taskId !== undefined && safeTaskId(taskId);
  if (!createTaskRoute && !routeTaskCandidate) return problem("not_found", 404);
  if (!sameOriginWriteAllowed(request)) return problem("cross_site_forbidden", 403);

  if (routeTaskCandidate && !routeTask) return problem("invalid_request", 400);
  const capabilities = coordinationWriteCapabilities();
  if (createTaskRoute && !capabilities.task_creation_enabled) return problem("provider_not_configured", 503);
  if (routeTask && !capabilities.task_routing_enabled) return problem("provider_not_configured", 503);

  const base = getUpstreamBase();
  const writeToken = coordinationWriteToken();
  if (!base || !writeToken) return problem("provider_not_configured", 503);

  let upstreamUrl: URL;
  let body: string | undefined;
  let expectedStatus: number;
  let idempotencyKey: string | undefined;
  if (createTaskRoute) {
    const contentType = request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase();
    if (contentType !== "application/json") return problem("invalid_request", 415);
    const parsedBody = await readRequestJsonWithinLimit(request);
    if (!parsedBody.ok) {
      return parsedBody.tooLarge ? problem("payload_too_large", 413) : problem("invalid_request", 422);
    }
    const validation = validateCreateTaskBody(parsedBody.value);
    if (!validation.ok) return problem("invalid_request", 422);
    upstreamUrl = new URL("api/v1/coordination/tasks", base);
    body = JSON.stringify(validation.value);
    idempotencyKey = validation.idempotencyKey;
    expectedStatus = 201;
  } else {
    if (!routeTask || taskId === undefined) return problem("invalid_request", 400);
    if (!(await requestHasEmptyBody(request))) return problem("invalid_request", 422);
    upstreamUrl = new URL(`api/v1/coordination/tasks/${encodeURIComponent(taskId)}/route`, base);
    expectedStatus = 200;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  try {
    const upstream = await fetch(upstreamUrl, {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${writeToken}`,
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      ...(body === undefined ? {} : { body }),
      cache: "no-store",
      redirect: "error",
      signal: controller.signal,
    });

    if (!upstream.ok) {
      void upstream.body?.cancel().catch(() => undefined);
      const mapped = mapUpstreamFailure(upstream.status);
      const retryAfter = upstream.headers.get("retry-after");
      const safeRetryAfter = retryAfter && /^\d{1,5}$/.test(retryAfter) ? retryAfter : undefined;
      return problem(
        mapped.code,
        mapped.status,
        mapped.code === "rate_limited" && safeRetryAfter ? { "Retry-After": safeRetryAfter } : {},
      );
    }

    const contentType = upstream.headers.get("content-type") ?? "";
    const declaredLength = upstream.headers.get("content-length");
    const declaredTooLarge = declaredLength !== null && /^\d+$/.test(declaredLength) && Number(declaredLength) > maxResponseBytes;
    if (upstream.status !== expectedStatus || !/^application\/json\b/i.test(contentType) || declaredTooLarge) {
      void upstream.body?.cancel().catch(() => undefined);
      return problem("invalid_upstream_response", 502);
    }
    const parsed = await readJsonWithinLimit(upstream);
    if (!parsed.ok) return problem("invalid_upstream_response", 502);

    if (createTaskRoute) {
      if (!isTaskCreateResponse(parsed.value) || !idempotencyKey) return problem("invalid_upstream_response", 502);
      return json(parsed.value, 201, { "X-CICC-Idempotency-Key": idempotencyKey });
    }
    if (!taskId || !isTaskRouteResponse(parsed.value, taskId)) return problem("invalid_upstream_response", 502);
    return json(parsed.value, 200);
  } catch {
    return problem("upstream_unavailable", 503);
  } finally {
    clearTimeout(timeout);
  }
}
