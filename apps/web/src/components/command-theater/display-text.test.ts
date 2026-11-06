import { describe, expect, it } from "vitest";
import { safeDisplayText } from "./display-text";

describe("safeDisplayText", () => {
  it("removes directional override and isolate controls while preserving visible text", () => {
    expect(safeDisplayText("IP \u202E192.0.2.1\u202C · جهة تهديد\u2069"))
      .toBe("IP 192.0.2.1 · جهة تهديد");
  });

  it("leaves ordinary RTL text and punctuation intact", () => {
    expect(safeDisplayText("مثال.شبكة — Threat actor"))
      .toBe("مثال.شبكة — Threat actor");
  });
});
