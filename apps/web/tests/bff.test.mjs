import test from "node:test";
import assert from "node:assert/strict";
import {
  buildUpstreamHeaders,
  buildUpstreamUrl,
  isWriteAllowed,
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
