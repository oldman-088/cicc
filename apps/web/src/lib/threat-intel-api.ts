/**
 * Threat Intelligence frontend adapter — PREPARED, NOT BOUND.
 *
 * Boundary: Agent 6 proposed these envelopes on PR #6; the frontend owner
 * accepted-in-principle with amendments (PR #6 comment 6657783177). The
 * contract is NOT mutually accepted and NOTHING is mounted on a host, so
 * this module deliberately contains only runtime decoders — there is no
 * endpoint, no fetch, and no data source. UI code must not render Threat
 * Intelligence records until (a) amendments are resolved, (b) owners
 * explicitly accept, and (c) a mounted endpoint is verified with a real
 * request/response. Fixture use in tests must stay labeled as fixtures.
 */

export type ThreatVerificationMode = "fixture_tested" | "oracle_verified" | "live_verified";
export type ThreatHostMountStatus = "not_mounted_pending_owner_approval" | "mounted_unverified" | "mounted_verified";

export type ThreatEntity = {
  id: string;
  type: string;
  name: string;
  confidence: number; // 0..100, distinct from verification
  verification: string;
  first_seen: string | null;
  last_seen: string | null;
  provenance: { sources: string[]; observations_count: number };
};

export type ThreatFreshness = {
  origin: "EXPERIMENTAL_DEMO_DATA_ONLY" | "live_source";
  verification_mode: ThreatVerificationMode;
  host_mount_status: ThreatHostMountStatus;
  collected_at: string; // must be timezone-aware ISO-8601
  last_successful_sync: string | null;
  is_stale: boolean;
  stale_after_seconds: number | null;
};

export type ThreatList = {
  data: ThreatEntity[];
  page: { limit: number; total_count: number | null; next_cursor: string | null; has_more: boolean };
  freshness: ThreatFreshness;
};

export type ThreatError = { code: string; message: string; correlation_id: string | null; retry_after_seconds: number | null };

function fail(message: string): never { throw new Error(`Invalid threat-intelligence response: ${message}`); }
function obj(v: unknown, l: string): Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return fail(`${l} must be an object`);
  return v as Record<string, unknown>;
}
function str(v: unknown, l: string): string { if (typeof v !== "string" || v.length === 0) return fail(`${l} must be a non-empty string`); return v; }
function nullableStr(v: unknown, l: string): string | null { if (v === null || v === undefined) return null; return str(v, l); }
function num(v: unknown, l: string): number { if (typeof v !== "number" || !Number.isFinite(v)) return fail(`${l} must be a finite number`); return v; }
function bool(v: unknown, l: string): boolean { if (typeof v !== "boolean") return fail(`${l} must be a boolean`); return v; }
function tzAware(v: unknown, l: string): string {
  const s = str(v, l);
  if (!/(Z|[+-]\d{2}:?\d{2})$/.test(s) || Number.isNaN(Date.parse(s))) return fail(`${l} must be timezone-aware ISO-8601`);
  return s;
}
function oneOf<T extends string>(v: unknown, allowed: readonly T[], l: string): T {
  const s = str(v, l); if (!(allowed as readonly string[]).includes(s)) return fail(`${l} has unsupported value ${s}`); return s as T;
}

export function parseThreatEntity(value: unknown, index: number): ThreatEntity {
  const item = obj(value, `data[${index}]`);
  const prov = obj(item.provenance, `data[${index}].provenance`);
  if (!Array.isArray(prov.sources)) return fail(`data[${index}].provenance.sources must be an array`);
  const confidence = num(item.confidence, `data[${index}].confidence`);
  if (confidence < 0 || confidence > 100) return fail(`data[${index}].confidence must be within 0..100`);
  return {
    id: str(item.id, `data[${index}].id`),
    type: str(item.type, `data[${index}].type`),
    name: str(item.name, `data[${index}].name`),
    confidence,
    verification: str(item.verification, `data[${index}].verification`),
    first_seen: item.first_seen == null ? null : tzAware(item.first_seen, `data[${index}].first_seen`),
    last_seen: item.last_seen == null ? null : tzAware(item.last_seen, `data[${index}].last_seen`),
    provenance: { sources: prov.sources.map((s, i) => str(s, `data[${index}].provenance.sources[${i}]`)), observations_count: num(prov.observations_count, `data[${index}].provenance.observations_count`) },
  };
}

export function parseThreatList(value: unknown): ThreatList {
  const root = obj(value, "threat list");
  if (!Array.isArray(root.data)) return fail("data must be an array");
  const page = obj(root.page, "page");
  const fresh = obj(root.freshness, "freshness");
  const next_cursor = nullableStr(page.next_cursor, "page.next_cursor");
  return {
    data: root.data.map(parseThreatEntity),
    page: {
      limit: num(page.limit, "page.limit"),
      total_count: page.total_count == null ? null : num(page.total_count, "page.total_count"),
      next_cursor,
      has_more: next_cursor !== null,
    },
    freshness: {
      origin: oneOf(fresh.origin, ["EXPERIMENTAL_DEMO_DATA_ONLY", "live_source"] as const, "freshness.origin"),
      verification_mode: oneOf(fresh.verification_mode, ["fixture_tested", "oracle_verified", "live_verified"] as const, "freshness.verification_mode"),
      host_mount_status: oneOf(fresh.host_mount_status, ["not_mounted_pending_owner_approval", "mounted_unverified", "mounted_verified"] as const, "freshness.host_mount_status"),
      collected_at: tzAware(fresh.collected_at, "freshness.collected_at"),
      last_successful_sync: fresh.last_successful_sync == null ? null : tzAware(fresh.last_successful_sync, "freshness.last_successful_sync"),
      is_stale: bool(fresh.is_stale, "freshness.is_stale"),
      stale_after_seconds: fresh.stale_after_seconds == null ? null : num(fresh.stale_after_seconds, "freshness.stale_after_seconds"),
    },
  };
}

export function parseThreatError(value: unknown): ThreatError {
  const root = obj(value, "threat error");
  const error = obj(root.error, "error");
  return {
    code: str(error.code, "error.code"),
    message: str(error.message, "error.message"),
    correlation_id: nullableStr(error.correlation_id, "error.correlation_id"),
    retry_after_seconds: error.retry_after_seconds == null ? null : num(error.retry_after_seconds, "error.retry_after_seconds"),
  };
}

/** Guard used by any future UI binding: refuses to present unmounted/unverified data as live. */
export function threatDataPresentation(freshness: ThreatFreshness): "live" | "fixture" | "unavailable" {
  if (freshness.host_mount_status !== "mounted_verified") return "unavailable";
  return freshness.origin === "live_source" && freshness.verification_mode === "live_verified" ? "live" : "fixture";
}
