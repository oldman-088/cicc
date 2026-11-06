import test from "node:test";
import assert from "node:assert/strict";

import { deriveAlerts } from "../lib/alerts.mjs";

test("down and degraded raise alerts, others do not", () => {
  const components = [
    { key: "api", status: "ok", name: "API", detail: "" },
    { key: "db", status: "down", name: "DB", detail: "conn failed" },
    { key: "mq", status: "not_configured", name: "MQ", detail: "" },
    { key: "mod", status: "not_implemented", name: "Mod", detail: "" },
    { key: "ext", status: "degraded", name: "Ext", detail: "slow" },
  ];
  const alerts = deriveAlerts(components);
  assert.deepEqual(
    alerts.map((a) => a.key),
    ["db", "ext"]
  );
  assert.equal(alerts[0].detail, "conn failed");
});

test("down sorts before degraded", () => {
  const alerts = deriveAlerts([
    { key: "a", status: "degraded" },
    { key: "b", status: "down" },
  ]);
  assert.deepEqual(alerts.map((a) => a.key), ["b", "a"]);
});

test("tolerates bad input", () => {
  assert.deepEqual(deriveAlerts(null), []);
  assert.deepEqual(deriveAlerts([{ key: "x" }]), []);
});
