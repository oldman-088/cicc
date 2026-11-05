import { describe, expect, it } from "vitest";
import { parseVulnList, vulnDataPresentation } from "./vuln-intel-api";

// Synthetic contract fixtures only.
const fixture = { data: [{ cve_id: "CVE-2026-0001", severity: "high", cvss_score: 8.1, epss_score: null, kev: null, kev_required_action: null, published_at: "2026-01-01T00:00:00Z", provenance: { sources: ["fixture"], observations_count: 1 } }], page: { limit: 25, total_count: null, next_cursor: null } };
describe("vulnerability adapter (prepared, not bound)", () => {
  it("decodes records preserving tri-state kev/epss nulls", () => {
    const parsed = parseVulnList(fixture);
    expect(parsed.data[0]).toMatchObject({ cve_id: "CVE-2026-0001", kev: null, epss_score: null });
    expect(vulnDataPresentation("not_mounted", "live")).toBe("unavailable");
  });
  it("rejects non-canonical CVE ids and malformed scores", () => {
    expect(() => parseVulnList({ ...fixture, data: [{ ...fixture.data[0], cve_id: "not-a-cve" }] })).toThrow(/CVE/);
    expect(() => parseVulnList({ ...fixture, data: [{ ...fixture.data[0], cvss_score: "8.1" }] })).toThrow(/cvss_score/);
  });
});
