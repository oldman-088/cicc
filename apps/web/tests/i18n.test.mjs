import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { LOCALES, DEFAULT_LOCALE, RTL_MAP, isRTL } from "../lib/locales.mjs";

const load = (p) =>
  JSON.parse(readFileSync(new URL(p, import.meta.url), "utf8"));
const en = load("../messages/en.json");
const ar = load("../messages/ar.json");

test("en and ar dictionaries expose identical keys", () => {
  assert.deepEqual(Object.keys(en).sort(), Object.keys(ar).sort());
});

test("all dictionary values are non-empty strings", () => {
  for (const dict of [en, ar]) {
    for (const [k, v] of Object.entries(dict)) {
      assert.equal(typeof v, "string", k);
      assert.ok(v.trim().length > 0, `empty value for key ${k}`);
    }
  }
});

test("arabic dictionary actually contains arabic text", () => {
  assert.match(ar.appTitle, /[؀-ۿ]/);
});

test("RTL mapping: ar -> rtl, en -> ltr", () => {
  assert.equal(RTL_MAP.ar, "rtl");
  assert.equal(RTL_MAP.en, "ltr");
  assert.ok(isRTL("ar"));
  assert.ok(!isRTL("en"));
  assert.ok(LOCALES.includes(DEFAULT_LOCALE));
});
