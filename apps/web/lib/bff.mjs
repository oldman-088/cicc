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
