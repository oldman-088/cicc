// Server-side BFF (backend-for-frontend) security logic for the /api/* proxy.
// Pure functions — unit-tested in tests/bff.test.mjs without next/server.
//
// Security invariants (M14-03):
//  1. API tokens NEVER reach browser JavaScript (no NEXT_PUBLIC_ vars; token
//     lives only in server env WEB_BFF_API_TOKEN and is injected here).
//  2. Nothing secret is stored in local/session storage (locale pref only).
//  3. Client-provided Authorization / Cookie / x-cicc-* headers are STRIPPED
//     and never forwarded — a leaked or attacker-set browser token cannot be
//     used through the BFF, and the BFF never forwards arbitrary credentials.
//  4. Tokens are never logged (this module never logs; the route handler logs
//     only method, path, and status code).
//  5. Writes are denied unless WEB_BFF_ALLOW_WRITES=1 (dashboard is read-only).
//  6. If WEB_BFF_ENFORCE_SAME_ORIGIN=1, requests whose Sec-Fetch-Site header
//     is cross-site are rejected (browser-enforced CSRF mitigation).

export const HOP_BY_HOP = new Set([
  "authorization",
  "cookie",
  "host",
  "content-length",
  "connection",
  "transfer-encoding",
  "x-cicc-token",
]);

export function buildUpstreamHeaders(clientHeaders, env) {
  const out = new Headers();
  for (const [k, v] of clientHeaders.entries()) {
    const lk = k.toLowerCase();
    if (HOP_BY_HOP.has(lk) || lk.startsWith("x-cicc-")) continue;
    out.set(k, v);
  }
  const token = env.WEB_BFF_API_TOKEN || "";
  if (token) out.set("Authorization", `Bearer ${token}`); // server-only secret
  return out;
}

export function isWriteAllowed(method, env) {
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") return true;
  return env.WEB_BFF_ALLOW_WRITES === "1";
}

// ---- M26: single fixed, allowlisted write route (approved write path) ----
// Only POST /api/v1/coordination/tasks is permitted, and only when BOTH
// WEB_BFF_ALLOW_COORD_WRITE=1 and a separate server-only WEB_BFF_WRITE_TOKEN
// are set. Everything else stays 403. The browser never supplies either.
export const COORD_WRITE_ROUTE = { method: "POST", segments: ["v1", "coordination", "tasks"] };
export const MAX_WRITE_BODY_BYTES = 256 * 1024;

export function isCoordWriteRoute(method, pathSegments) {
  return (
    method === COORD_WRITE_ROUTE.method &&
    pathSegments.length === COORD_WRITE_ROUTE.segments.length &&
    COORD_WRITE_ROUTE.segments.every((seg, i) => pathSegments[i] === seg)
  );
}

export function isCoordWriteAllowed(method, pathSegments, env) {
  if (!isCoordWriteRoute(method, pathSegments)) return false;
  return env.WEB_BFF_ALLOW_COORD_WRITE === "1" && Boolean((env.WEB_BFF_WRITE_TOKEN || "").trim());
}

const KIND_RE = /^[a-z0-9_]{1,64}$/;
const ID_RE = /^[A-Za-z0-9_.:-]{1,200}$/;

// Strict DTO allowlist for POST /api/v1/coordination/tasks (server-side).
// Returns { ok, value, error }; `value` is the sanitized body to forward.
export function validateCoordTaskBody(obj, genId) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return { ok: false, error: "body must be an object" };
  const allowed = new Set(["task_id", "idempotency_key", "kind", "priority", "title", "payload", "repo", "pr_ref", "branch_ref", "owner", "depends_on", "timeout_s", "ttl_s", "requires_approval"]);
  for (const k of Object.keys(obj)) if (!allowed.has(k)) return { ok: false, error: `field not allowed: ${k}` };
  if (typeof obj.kind !== "string" || !KIND_RE.test(obj.kind)) return { ok: false, error: "kind invalid" };
  if (obj.payload !== undefined && (typeof obj.payload !== "object" || obj.payload === null || Array.isArray(obj.payload))) return { ok: false, error: "payload must be an object" };
  const out = { kind: obj.kind, payload: obj.payload ?? {} };
  if (obj.priority !== undefined) {
    if (!Number.isInteger(obj.priority) || obj.priority < 1 || obj.priority > 10) return { ok: false, error: "priority must be int 1-10" };
    out.priority = obj.priority;
  }
  if (obj.title !== undefined) {
    if (typeof obj.title !== "string" || obj.title.length > 500) return { ok: false, error: "title invalid" };
    out.title = obj.title;
  }
  for (const f of ["task_id", "repo", "pr_ref", "branch_ref", "owner"]) {  // idempotency_key handled below (regenerated if invalid)
    if (obj[f] !== undefined) {
      if (typeof obj[f] !== "string" || !ID_RE.test(obj[f]) && f !== "repo" && f !== "owner") return { ok: false, error: `${f} invalid` };
      if (f === "repo" || f === "owner") { if (typeof obj[f] !== "string" || obj[f].length > 200) return { ok: false, error: `${f} invalid` }; }
      out[f] = obj[f];
    }
  }
  if (obj.depends_on !== undefined) {
    if (!Array.isArray(obj.depends_on) || obj.depends_on.length > 50 || !obj.depends_on.every((d) => typeof d === "string" && ID_RE.test(d))) return { ok: false, error: "depends_on invalid" };
    out.depends_on = obj.depends_on;
  }
  for (const f of ["timeout_s", "ttl_s"]) {
    if (obj[f] !== undefined) {
      if (!Number.isInteger(obj[f]) || obj[f] < 1 || obj[f] > 86400 * 30) return { ok: false, error: `${f} invalid` };
      out[f] = obj[f];
    }
  }
  if (obj.requires_approval !== undefined) {
    if (typeof obj.requires_approval !== "boolean") return { ok: false, error: "requires_approval invalid" };
    out.requires_approval = obj.requires_approval;
  }
  // server-generated idempotency key = the correlation key for the execution
  out.idempotency_key = (typeof obj.idempotency_key === "string" && ID_RE.test(obj.idempotency_key) && obj.idempotency_key.length <= 300) ? obj.idempotency_key : genId();
  return { ok: true, value: out };
}

export function coordWriteToken(env) {
  return (env.WEB_BFF_WRITE_TOKEN || "").trim();
}

export function sameOriginOk(headers, env) {
  if (env.WEB_BFF_ENFORCE_SAME_ORIGIN !== "1") return true;
  const sfs = headers.get("sec-fetch-site");
  if (!sfs) return true; // non-browser clients have no Sec-Fetch-Site
  return sfs === "same-origin" || sfs === "same-site" || sfs === "none";
}

export function buildUpstreamUrl(apiInternalUrl, pathSegments, search) {
  const base = (apiInternalUrl || "http://127.0.0.1:8000").replace(/\/$/, "");
  const p = (pathSegments || []).map(encodeURIComponent).join("/");
  return `${base}/api/${p}${search || ""}`;
}

export function safeLogFields(method, path, status) {
  // Explicit allowlist — tokens/headers are never logged.
  return { method, path, status };
}
