import test from "node:test";
import assert from "node:assert/strict";
import {
  buildUpstreamHeaders,
  buildUpstreamUrl,
  isWriteAllowed,
  isCoordWriteAllowed,
  isCoordWriteRoute,
  validateCoordTaskBody,
  coordWriteToken,
  sameOriginOk,
  safeLogFields,
} from "../lib/bff.mjs";

const envWithToken = { WEB_BFF_API_TOKEN: "server-secret-token" };

test("BFF injects server token and strips client Authorization/Cookie", () => {
  const client = new Headers();
  client.set("Authorization", "Bearer leaked-browser-token");
  client.set("Cookie", "session=abc");
  client.set("X-CICC-Custom", "x");
  client.set("Accept", "application/json");
  const out = buildUpstreamHeaders(client, envWithToken);
  assert.equal(out.get("Authorization"), "Bearer server-secret-token");
  assert.equal(out.get("Cookie"), null);
  assert.equal(out.get("X-CICC-Custom"), null);
  assert.equal(out.get("Accept"), "application/json");
});

test("BFF without configured token sends no Authorization at all", () => {
  const out = buildUpstreamHeaders(new Headers(), {});
  assert.equal(out.get("Authorization"), null);
});

test("writes denied unless explicitly enabled; reads allowed", () => {
  assert.equal(isWriteAllowed("GET", {}), true);
  assert.equal(isWriteAllowed("HEAD", {}), true);
  assert.equal(isWriteAllowed("POST", {}), false);
  assert.equal(isWriteAllowed("POST", { WEB_BFF_ALLOW_WRITES: "1" }), true);
});

test("same-origin enforcement rejects cross-site browser requests only", () => {
  const h = new Headers();
  h.set("Sec-Fetch-Site", "cross-site");
  assert.equal(sameOriginOk(h, { WEB_BFF_ENFORCE_SAME_ORIGIN: "1" }), false);
  h.set("Sec-Fetch-Site", "same-origin");
  assert.equal(sameOriginOk(h, { WEB_BFF_ENFORCE_SAME_ORIGIN: "1" }), true);
  assert.equal(sameOriginOk(new Headers(), { WEB_BFF_ENFORCE_SAME_ORIGIN: "1" }), true);
  // disabled -> everything passes
  assert.equal(sameOriginOk(h, {}), true);
});

test("upstream URL is built under /api/ with encoded segments and search", () => {
  assert.equal(
    buildUpstreamUrl("http://127.0.0.1:8000", ["v1", "coordination", "tasks"], "?limit=5"),
    "http://127.0.0.1:8000/api/v1/coordination/tasks?limit=5"
  );
  assert.equal(
    buildUpstreamUrl("http://x:1/", ["a b"], ""),
    "http://x:1/api/a%20b"
  );
});

test("log fields never include tokens or headers", () => {
  const f = safeLogFields("GET", "v1/ops/overview", 200);
  assert.deepEqual(f, { method: "GET", path: "v1/ops/overview", status: 200 });
  assert.ok(!JSON.stringify(f).includes("token"));
});

// ---- M26 approved write path (single fixed route, server-only write token) ----

test("M26: coord write route detection", () => {
  assert.equal(isCoordWriteRoute("POST", ["v1", "coordination", "tasks"]), true);
  assert.equal(isCoordWriteRoute("POST", ["v1", "coordination", "agents"]), false);
  assert.equal(isCoordWriteRoute("GET", ["v1", "coordination", "tasks"]), false);
  assert.equal(isCoordWriteRoute("POST", ["v1", "coordination", "tasks", "x"]), false);
});

test("M26: coord write requires BOTH flag and separate write token", () => {
  const seg = ["v1", "coordination", "tasks"];
  assert.equal(isCoordWriteAllowed("POST", seg, {}), false);
  assert.equal(isCoordWriteAllowed("POST", seg, { WEB_BFF_ALLOW_COORD_WRITE: "1" }), false);
  assert.equal(isCoordWriteAllowed("POST", seg, { WEB_BFF_WRITE_TOKEN: "w" }), false);
  assert.equal(isCoordWriteAllowed("POST", seg, { WEB_BFF_ALLOW_COORD_WRITE: "1", WEB_BFF_WRITE_TOKEN: "w" }), true);
  // other writes still blocked even with the flag
  assert.equal(isCoordWriteAllowed("POST", ["v1", "ops", "alerts"], { WEB_BFF_ALLOW_COORD_WRITE: "1", WEB_BFF_WRITE_TOKEN: "w" }), false);
  assert.equal(isWriteAllowed("POST", { WEB_BFF_ALLOW_COORD_WRITE: "1", WEB_BFF_WRITE_TOKEN: "w" }), false);
});

test("M26: write DTO allowlist — rejects unknown fields, bad kind/priority, oversized title", () => {
  let n = 0; const gen = () => `gen-${++n}`;
  assert.equal(validateCoordTaskBody({ kind: "threat_intel", payload: { a: 1 } }, gen).ok, true);
  assert.equal(validateCoordTaskBody({ kind: "BAD KIND" }, gen).ok, false);
  assert.equal(validateCoordTaskBody({ kind: "x", evil: 1 }, gen).ok, false);
  assert.equal(validateCoordTaskBody({ kind: "x", priority: 99 }, gen).ok, false);
  assert.equal(validateCoordTaskBody({ kind: "x", title: "t".repeat(501) }, gen).ok, false);
  assert.equal(validateCoordTaskBody({ kind: "x", depends_on: ["ok_1", "bad id!"] }, gen).ok, false);
  assert.equal(validateCoordTaskBody([1, 2], gen).ok, false);
});

test("M26: idempotency_key is server-generated when absent/invalid, preserved when valid", () => {
  let n = 0; const gen = () => `srv-${++n}`;
  const a = validateCoordTaskBody({ kind: "x" }, gen);
  assert.equal(a.value.idempotency_key, "srv-1");
  const b = validateCoordTaskBody({ kind: "x", idempotency_key: "client-key-1" }, gen);
  assert.equal(b.value.idempotency_key, "client-key-1");
  const c = validateCoordTaskBody({ kind: "x", idempotency_key: "bad key with spaces" }, gen);
  assert.equal(c.value.idempotency_key, "srv-2");
});

test("M26: client Authorization header is stripped; write token comes from env only", () => {
  const h = new Headers({ Authorization: "Bearer browser-leaked", "Content-Type": "application/json" });
  const out = buildUpstreamHeaders(h, { WEB_BFF_API_TOKEN: "read-tok" });
  assert.equal(out.get("Authorization"), "Bearer read-tok");
  assert.equal(coordWriteToken({ WEB_BFF_WRITE_TOKEN: "  w-tok " }), "w-tok");
  assert.equal(coordWriteToken({}), "");
});

// ---- M27: write-boundary hardening ----

test("M27: path/method variations of the write route are rejected", () => {
  const env = { WEB_BFF_ALLOW_COORD_WRITE: "1", WEB_BFF_WRITE_TOKEN: "w" };
  // exact route only
  assert.equal(isCoordWriteAllowed("POST", ["v1", "coordination", "tasks"], env), true);
  assert.equal(isCoordWriteAllowed("PUT", ["v1", "coordination", "tasks"], env), false);
  assert.equal(isCoordWriteAllowed("DELETE", ["v1", "coordination", "tasks"], env), false);
  assert.equal(isCoordWriteAllowed("POST", ["v1", "coordination", "tasks", "extra"], env), false);
  assert.equal(isCoordWriteAllowed("POST", ["v1", "coordination", "tasks/"], env), false);
  assert.equal(isCoordWriteAllowed("POST", ["v1", "coordination"], env), false);
  assert.equal(isCoordWriteAllowed("POST", ["v1", "coordination", "Tasks"], env), false); // case-sensitive
  assert.equal(isCoordWriteAllowed("POST", ["v1", "ops", "tasks"], env), false);
  // and the generic write gate stays off even with coord write enabled
  assert.equal(isWriteAllowed("POST", env), false);
  assert.equal(isWriteAllowed("DELETE", env), false);
});

test("M27: DTO validation rejects malformed/unknown/nested-evil payloads", () => {
  let n = 0; const gen = () => `g${++n}`;
  const bad = [
    null, 42, "str", [],
    { kind: "ok", payload: "not-an-object" },          // payload must be object -> coerced, but check unknown field
    { kind: "ok", unknown_field: 1 },
    { kind: "ok", priority: 5.5 },
    { kind: "ok", priority: "5" },
    { kind: "ok", depends_on: "notalist" },
    { kind: "ok", depends_on: Array(51).fill("a") },
    { kind: "ok", timeout_s: 0 },
    { kind: "ok", timeout_s: 86400 * 31 },
    { kind: "ok", requires_approval: "yes" },
    { kind: "x".repeat(65) },
    { kind: "ok", task_id: "bad id with spaces" },
  ];
  for (const b of bad) assert.equal(validateCoordTaskBody(b, gen).ok, false, JSON.stringify(b)?.slice(0, 60));
  const good = validateCoordTaskBody({ kind: "frontend_e2e", priority: 3, title: "t", payload: { a: [1, 2] }, depends_on: ["x-1"], timeout_s: 60, requires_approval: false }, gen);
  assert.equal(good.ok, true);
  assert.equal(good.value.kind, "frontend_e2e");
  assert.ok(good.value.idempotency_key.startsWith("g"));
});

test("M27: read token is injected for GETs; write token is separate and never mixed", () => {
  const h = new Headers();
  const out = buildUpstreamHeaders(h, { WEB_BFF_API_TOKEN: "read-tok", WEB_BFF_WRITE_TOKEN: "write-tok" });
  assert.equal(out.get("Authorization"), "Bearer read-tok"); // GET path uses read token
  assert.equal(coordWriteToken({ WEB_BFF_API_TOKEN: "read-tok", WEB_BFF_WRITE_TOKEN: "write-tok" }), "write-tok");
  assert.equal(coordWriteToken({ WEB_BFF_API_TOKEN: "read-tok" }), ""); // no write token configured -> write path disabled
});

// ---- M30: BFF boundary regressions ----

test("M30: x-cicc-* client headers are stripped; client auth never reaches upstream", () => {
  const h = new Headers({
    "x-cicc-token": "leaked-client-token",
    "x-cicc-idempotency-key": "client-forged",
    "authorization": "Bearer client-token",
    "content-type": "application/json",
  });
  const out = buildUpstreamHeaders(h, { WEB_BFF_API_TOKEN: "server-read" });
  assert.equal(out.get("x-cicc-token"), null);
  assert.equal(out.get("x-cicc-idempotency-key"), null);
  assert.equal(out.get("Authorization"), "Bearer server-read"); // client auth replaced, never forwarded
});

test("M30: same-origin enforcement (Sec-Fetch-Site) rejects cross-site when enabled", () => {
  const env = { WEB_BFF_ENFORCE_SAME_ORIGIN: "1" };
  assert.equal(sameOriginOk(new Headers(), env), true); // non-browser: no header -> allow
  assert.equal(sameOriginOk(new Headers({ "sec-fetch-site": "same-origin" }), env), true);
  assert.equal(sameOriginOk(new Headers({ "sec-fetch-site": "same-site" }), env), true);
  assert.equal(sameOriginOk(new Headers({ "sec-fetch-site": "none" }), env), true);
  assert.equal(sameOriginOk(new Headers({ "sec-fetch-site": "cross-site" }), env), false);
  assert.equal(sameOriginOk(new Headers({ "sec-fetch-site": "cross-site" }), {}), true); // disabled -> allow
});

test("M30: concurrent duplicate submissions get distinct server keys (no cross-request dedup at BFF)", async () => {
  // BFF generates a fresh bff-<uuid> per request; API-level dedup applies only
  // when the same idempotency_key is presented — client keys are rejected (422)
  // so two identical POSTs create two distinct tasks with distinct keys.
  const env = { WEB_BFF_ALLOW_COORD_WRITE: "1", WEB_BFF_WRITE_TOKEN: "w" };
  let n = 0; const gen = () => `bff-test-${++n}`;
  const a = validateCoordTaskBody({ kind: "k", payload: {} }, gen);
  const b = validateCoordTaskBody({ kind: "k", payload: {} }, gen);
  assert.equal(a.ok && b.ok, true);
  assert.notEqual(a.value.idempotency_key, b.value.idempotency_key);
  assert.equal(isCoordWriteAllowed("POST", ["v1", "coordination", "tasks"], env), true);
});

test("M33: write path exposes server idempotency key contract (bff-<uuid> per request)", () => {
  let n = 0;
  const a = validateCoordTaskBody({ kind: "k", payload: {} }, () => `bff-${++n}`);
  const b = validateCoordTaskBody({ kind: "k", payload: {} }, () => `bff-${++n}`);
  assert.ok(a.value.idempotency_key.startsWith("bff-"));
  assert.notEqual(a.value.idempotency_key, b.value.idempotency_key);
});
