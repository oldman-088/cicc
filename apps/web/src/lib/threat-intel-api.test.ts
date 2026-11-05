import { describe, expect, it } from "vitest";
import { parseThreatError, parseThreatList, threatDataPresentation } from "./threat-intel-api";

// Synthetic contract fixtures only — no provider exists and none is implied.
const fixture = {
  data: [{ id: "ind-1", type: "indicator", name: "fixture.example", confidence: { score: 0.4, verification_mode: "fixture_tested", corroborating_source_count: 1, conflict_open: false }, first_seen: null, last_seen: "2026-11-05T09:00:00Z", provenance: [{ source_id: "fixture", observation_count: 1, source_reference: null, retrieved_at: null }], attributes: {} }],
  page: { limit: 50, total_count: null, next_cursor: null },
  freshness: { origin: "EXPERIMENTAL_DEMO_DATA_ONLY", verification_mode: "fixture_tested", host_mount_status: "not_mounted_pending_owner_approval", collected_at: "2026-11-05T10:00:00Z", last_successful_sync: null, is_stale: false, age_seconds: 60, stale_after_seconds: 3600 },
};

describe("threat-intelligence adapter (prepared, not bound)", () => {
  it("decodes the amended envelope and derives has_more from the cursor", () => {
    const parsed = parseThreatList(fixture);
    expect(parsed.data[0]).toMatchObject({ id: "ind-1", confidence: { score: 0.4 } });
    expect(parsed.page).toMatchObject({ total_count: null, has_more: false });
    expect(threatDataPresentation(parsed.freshness)).toBe("unavailable");
  });
  it("rejects naive timestamps, out-of-range confidence, and untyped entities", () => {
    expect(() => parseThreatList({ ...fixture, freshness: { ...fixture.freshness, collected_at: "2026-11-05T10:00:00" } })).toThrow(/timezone-aware/);
    expect(() => parseThreatList({ ...fixture, data: [{ ...fixture.data[0], confidence: { ...fixture.data[0].confidence, score: 1.5 } }] })).toThrow(/confidence/);
    expect(() => parseThreatList({ ...fixture, data: [{ ...fixture.data[0], type: "not_a_type" }] })).toThrow(/entity type/);
    expect(() => parseThreatList({ ...fixture, freshness: { ...fixture.freshness, is_stale: true, stale_after_seconds: null } })).toThrow(/is_stale/);
    expect(() => parseThreatList({ ...fixture, data: [{ name: "missing id/type" }] })).toThrow();
  });
  it("decodes the aligned error envelope with correlation id", () => {
    expect(parseThreatError({ error: { code: "rate_limited", message: "slow down", correlation_id: "corr-1", retry_after_seconds: 5 } }))
      .toEqual({ code: "rate_limited", message: "slow down", correlation_id: "corr-1", retry_after_seconds: 5 });
  });
});
