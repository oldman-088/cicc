type QueryRule = {
  defaultValue?: string;
  validate: (value: string) => boolean;
};

type UpstreamRoute = {
  path: string;
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
  // Canonical per-task reads confirmed by Agent 1 (PR #4 M26):
  // GET /api/v1/coordination/tasks/{id} and /tasks/{id}/events.
  let spec = routes[path.join("/")];
  if (!spec && path[0] === "coordination" && path[1] === "tasks" && (path.length === 3 || (path.length === 4 && path[3] === "events"))) {
    if (!/^[A-Za-z0-9_.:-]{1,128}$/.test(path[2])) return problem("invalid_request", 400);
    spec = { path: `api/v1/coordination/tasks/${encodeURIComponent(path[2])}${path.length === 4 ? "/events" : ""}` };
  }
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

  const upstreamUrl = new URL(spec.path, base);
  upstreamUrl.search = query.toString();
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

// ---------------------------------------------------------------------------
// Approved write path (Agent 1 ACCEPT, PR #4 M26). Exactly one fixed route:
// POST coordination/tasks -> POST api/v1/coordination/tasks. Everything else
// stays GET-only. Server-only write token, server-generated idempotency key
// (the correlation key persisted on the task), strict DTO allowlist.
// ---------------------------------------------------------------------------

const WRITE_FIELDS = new Set(["kind", "title", "priority", "payload", "depends_on", "timeout_s", "ttl_s", "requires_approval", "repo", "branch_ref", "agent", "idempotency_key"]);
const TASK_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function validateCoordTaskBody(body: unknown): { ok: true; value: Record<string, unknown> } | { ok: false } {
  if (!isPlainObject(body)) return { ok: false };
  for (const key of Object.keys(body)) if (!WRITE_FIELDS.has(key)) return { ok: false };
  const kind = body.kind;
  if (typeof kind !== "string" || !/^[a-z0-9_]{1,64}$/.test(kind)) return { ok: false };
  const title = body.title;
  if (typeof title !== "string" || title.trim().length === 0 || title.length > 500) return { ok: false };
  const priority = body.priority ?? 5;
  if (typeof priority !== "number" || !Number.isSafeInteger(priority) || priority < 1 || priority > 10) return { ok: false };
  const payload = body.payload ?? {};
  if (!isPlainObject(payload)) return { ok: false };
  const dependsOn = body.depends_on ?? [];
  if (!Array.isArray(dependsOn) || dependsOn.length > 50 || dependsOn.some((d) => typeof d !== "string" || !TASK_ID_PATTERN.test(d))) return { ok: false };
  for (const key of ["timeout_s", "ttl_s"] as const) {
    const v = body[key];
    if (v !== undefined && (typeof v !== "number" || !Number.isSafeInteger(v) || v < 1 || v > 2_592_000)) return { ok: false };
  }
  if (body.requires_approval !== undefined && typeof body.requires_approval !== "boolean") return { ok: false };
  for (const key of ["repo", "branch_ref", "agent"] as const) {
    const v = body[key];
    if (v !== undefined && (typeof v !== "string" || v.length === 0 || v.length > 256)) return { ok: false };
  }
  const suppliedKey = body.idempotency_key;
  const validKey = typeof suppliedKey === "string" && /^[A-Za-z0-9_.:-]{8,128}$/.test(suppliedKey);
  return { ok: true, value: { ...body, priority, payload, depends_on: dependsOn, idempotency_key: validKey ? suppliedKey : `bff-${crypto.randomUUID()}` } };
}

export async function POST(
  request: Request,
  context: { params: Promise<{ path: string[] }> },
): Promise<Response> {
  const { path } = await context.params;
  if (path.join("/") !== "coordination/tasks") return problem("method_not_allowed_via_bff", 403);
  if (!sameOriginAllowed(request)) return problem("cross_site_forbidden", 403);
  if (process.env.WEB_BFF_ALLOW_COORD_WRITE !== "1") return problem("write_not_enabled", 403);

  const base = getUpstreamBase();
  const writeToken = process.env.WEB_BFF_WRITE_TOKEN?.trim();
  if (!base || process.env.CICC_OPS_TRUSTED_SINGLE_TENANT !== "true" || !writeToken || /[\r\n]/.test(writeToken)) {
    return problem("provider_not_configured", 503);
  }

  const raw = await request.text();
  if (new TextEncoder().encode(raw).byteLength > 256 * 1024) return problem("payload_too_large", 413);
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { return problem("invalid_request", 422); }
  const validated = validateCoordTaskBody(parsed);
  if (!validated.ok) return problem("invalid_request", 422);
  const idempotencyKey = validated.value.idempotency_key as string;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);
  try {
    const upstream = await fetch(new URL("api/v1/coordination/tasks", base), {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json", Authorization: `Bearer ${writeToken}` },
      body: JSON.stringify(validated.value),
      cache: "no-store",
      redirect: "error",
      signal: controller.signal,
    });
    if (!upstream.ok) {
      void upstream.body?.cancel().catch(() => undefined);
      const mapped = mapUpstreamFailure(upstream.status);
      const retryAfter = upstream.headers.get("retry-after");
      const safeRetryAfter = retryAfter && /^\d{1,5}$/.test(retryAfter) ? retryAfter : undefined;
      return problem(mapped.code, mapped.status, mapped.code === "rate_limited" && safeRetryAfter ? { "Retry-After": safeRetryAfter } : {});
    }
    const body = await readJsonWithinLimit(upstream);
    if (!body.ok) return problem("invalid_upstream_response", 502);
    return json(body.value, upstream.status, { "x-cicc-idempotency-key": idempotencyKey });
  } catch {
    return problem("upstream_unavailable", 503);
  } finally {
    clearTimeout(timeout);
  }
}
