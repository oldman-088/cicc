import test from "node:test";
import assert from "node:assert/strict";

import { toSeries, maxValue } from "../lib/trends.mjs";

test("toSeries maps snapshots to ts/value points", () => {
  const snaps = [
    { ts: "2026-11-04T00:00:00Z", entities: 1, vulnerabilities: 0, campaigns: 2 },
    { ts: "2026-11-04T01:00:00Z", entities: 5, vulnerabilities: 3, campaigns: 2 },
  ];
  const s = toSeries(snaps, "entities");
  assert.deepEqual(s, [
    { ts: "2026-11-04T00:00:00Z", value: 1 },
    { ts: "2026-11-04T01:00:00Z", value: 5 },
  ]);
});

test("toSeries tolerates bad input", () => {
  assert.deepEqual(toSeries(null, "entities"), []);
  assert.deepEqual(toSeries([{ entities: 3 }], "entities"), []); // missing ts
  assert.deepEqual(toSeries([{ ts: "x", entities: "7" }], "entities"), [
    { ts: "x", value: 7 },
  ]);
});

test("maxValue", () => {
  assert.equal(maxValue([]), 0);
  assert.equal(maxValue([{ value: 2 }, { value: 9 }, { value: 4 }]), 9);
});
