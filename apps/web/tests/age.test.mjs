import test from "node:test";
import assert from "node:assert/strict";

import { formatAge } from "../lib/age.mjs";

test("formatAge buckets", () => {
  assert.equal(formatAge(0), "0s");
  assert.equal(formatAge(42), "42s");
  assert.equal(formatAge(59.9), "59s");
  assert.equal(formatAge(60), "1m");
  assert.equal(formatAge(3599), "59m");
  assert.equal(formatAge(3600), "1h");
  assert.equal(formatAge(90000), "1d");
});

test("formatAge tolerates bad input", () => {
  assert.equal(formatAge(null), "—");
  assert.equal(formatAge(undefined), "—");
  assert.equal(formatAge(NaN), "—");
  assert.equal(formatAge(-5), "0s");
});
