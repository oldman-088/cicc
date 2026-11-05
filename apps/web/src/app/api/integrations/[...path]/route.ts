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
  const spec = routes[path.join("/")];
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
