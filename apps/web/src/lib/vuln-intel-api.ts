/**
 * Vulnerability Intelligence frontend adapter — PREPARED, NOT BOUND.
 * PR #1's contract is framework-neutral and NOT mounted on a host
 * (`integration/api.py` in that PR states this explicitly). These decoders
 * implement the frontend-side shape the host binding must produce; there is
 * no endpoint and no fetch here. Contract state: implemented (package) /
 * proposed (host binding) / NOT mounted / NOT executed / NOT verified.
 */
export type VulnRecord = {
  cve_id: string;
  severity: string | null;
  cvss_score: number | null;
  epss_score: number | null; // null = provider not consulted, never fabricated as 0
  kev: boolean | null;      // null = not consulted (tri-state, mirrors Agent 3 M1)
  kev_required_action: string | null;
  published_at: string | null;
  provenance: { sources: string[]; observations_count: number };
};
export type VulnList = { data: VulnRecord[]; page: { limit: number; total_count: number | null; next_cursor: string | null; has_more: boolean } };

function fail(m: string): never { throw new Error(`Invalid vulnerability-intelligence response: ${m}`); }
function obj(v: unknown, l: string): Record<string, unknown> { if (typeof v !== "object" || v === null || Array.isArray(v)) return fail(`${l} must be an object`); return v as Record<string, unknown>; }
function str(v: unknown, l: string): string { if (typeof v !== "string" || !v) return fail(`${l} must be a non-empty string`); return v; }
function nstr(v: unknown, l: string): string | null { return v == null ? null : str(v, l); }
function nnum(v: unknown, l: string): number | null { if (v == null) return null; if (typeof v !== "number" || !Number.isFinite(v)) return fail(`${l} must be a finite number or null`); return v; }

export function parseVulnRecord(value: unknown, index: number): VulnRecord {
  const item = obj(value, `data[${index}]`);
  const cve = str(item.cve_id, `data[${index}].cve_id`);
  if (!/^CVE-\d{4}-\d{4,}$/.test(cve)) return fail(`data[${index}].cve_id must be a canonical CVE id`);
  const prov = obj(item.provenance, `data[${index}].provenance`);
  if (!Array.isArray(prov.sources)) return fail(`data[${index}].provenance.sources must be an array`);
  const kev = item.kev;
  if (kev !== null && kev !== undefined && typeof kev !== "boolean") return fail(`data[${index}].kev must be boolean or null`);
  return {
    cve_id: cve,
    severity: nstr(item.severity, `data[${index}].severity`),
    cvss_score: nnum(item.cvss_score, `data[${index}].cvss_score`),
    epss_score: nnum(item.epss_score, `data[${index}].epss_score`),
    kev: kev ?? null,
    kev_required_action: nstr(item.kev_required_action, `data[${index}].kev_required_action`),
    published_at: nstr(item.published_at, `data[${index}].published_at`),
    provenance: { sources: prov.sources.map((s, i) => str(s, `sources[${i}]`)), observations_count: (typeof prov.observations_count === "number" ? prov.observations_count : fail("observations_count must be a number")) as number },
  };
}

export function parseVulnList(value: unknown): VulnList {
  const root = obj(value, "vuln list");
  if (!Array.isArray(root.data)) return fail("data must be an array");
  const page = obj(root.page, "page");
  const next = nstr(page.next_cursor, "page.next_cursor");
  return {
    data: root.data.map(parseVulnRecord),
    page: { limit: (typeof page.limit === "number" ? page.limit : fail("page.limit must be a number")) as number, total_count: nnum(page.total_count, "page.total_count"), next_cursor: next, has_more: next !== null },
  };
}

/** Same fail-closed presentation guard as Threat Intelligence. */
export function vulnDataPresentation(mountStatus: "not_mounted" | "mounted_unverified" | "mounted_verified", origin: "fixture" | "live"): "live" | "fixture" | "unavailable" {
  if (mountStatus !== "mounted_verified") return "unavailable";
  return origin === "live" ? "live" : "fixture";
}
