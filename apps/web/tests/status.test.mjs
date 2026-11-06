import test from "node:test";
import assert from "node:assert/strict";

import { overallStatus, severityOf, STATUS_SEVERITY } from "../lib/status.mjs";

test("all ok -> ok", () => {
  assert.equal(overallStatus(["ok", "ok"]), "ok");
});

test("empty input -> unknown", () => {
  assert.equal(overallStatus([]), "unknown");
  assert.equal(overallStatus(undefined), "unknown");
});

test("not_configured / not_implemented degrade the overall status", () => {
  assert.equal(overallStatus(["ok", "not_configured"]), "degraded");
  assert.equal(overallStatus(["ok", "not_implemented"]), "degraded");
  assert.equal(overallStatus(["degraded", "not_implemented"]), "degraded");
});

test("any down -> down", () => {
  assert.equal(overallStatus(["ok", "down"]), "down");
  assert.equal(overallStatus(["down", "not_configured"]), "down");
});

test("invalid status -> unknown", () => {
  assert.equal(overallStatus(["bogus"]), "unknown");
  assert.equal(severityOf("bogus"), STATUS_SEVERITY.unknown);
  assert.equal(severityOf("ok"), 0);
});
