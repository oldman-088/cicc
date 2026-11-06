// M49: convert the Agent 1 read-only domain-gateway endpoints into a bounded,
// presentation-safe snapshot. This is observability only; it does not mount or
// invoke a TI/VI implementation and it never treats a missing response as healthy.

export const EXPECTED_DOMAIN_KINDS = Object.freeze(["threat_intel", "vuln_intel"]);
export const DOMAIN_GATEWAY_STATES = Object.freeze([
  "NOT_MOUNTED",
  "MOUNTED",
  "AVAILABLE",
  "EXECUTION_VERIFIED",
  "DEGRADED",
  "FAILED",
  "UNKNOWN",
]);

const VALID_STATES = new Set(DOMAIN_GATEWAY_STATES);
const MOUNTED_STATES = new Set([
  "MOUNTED",
  "AVAILABLE",
  "EXECUTION_VERIFIED",
  "DEGRADED",
  "FAILED",
]);
const KIND_PATTERN = /^[a-z0-9][a-z0-9_]{0,63}$/;
const MAX_DOMAIN_KINDS = 64;

function asRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value
    : null;
}

function ownRecord(source, key) {
  const record = asRecord(source);
  return record && Object.hasOwn(record, key) ? asRecord(record[key]) : null;
}

function nonNegativeCount(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function nonNegativeNumber(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? value
    : null;
}

function timestamp(value) {
  return typeof value === "string" && value.length <= 64 && Number.isFinite(Date.parse(value))
    ? value
    : null;
}

function kindId(value) {
  return typeof value === "string" && KIND_PATTERN.test(value) ? value : null;
}

/**
 * Normalize the two read-only API responses. Return null for an unavailable or
 * malformed response so callers cannot turn an auth/network/shape error into a
 * misleading NOT_MOUNTED result.
 */
export function normalizeDomainGateway(statusPayload, metricsPayload) {
  const statusBody = asRecord(statusPayload);
  const metricsBody = asRecord(metricsPayload);
  if (
    !statusBody ||
    !Array.isArray(statusBody.domains) ||
    !asRecord(statusBody.statuses) ||
    !metricsBody ||
    !asRecord(metricsBody.domains)
  ) {
    return null;
  }

  const mountedByKind = new Map();
  for (const entryValue of statusBody.domains) {
    const entry = asRecord(entryValue);
    const kind = kindId(entry?.kind);
    if (kind && !mountedByKind.has(kind)) mountedByKind.set(kind, entry);
  }

  const statusMap = statusBody.statuses;
  const metricsMap = metricsBody.domains;
  const candidateKinds = new Set(EXPECTED_DOMAIN_KINDS);
  for (const rawKind of Object.keys(statusMap)) {
    const kind = kindId(rawKind);
    if (kind) candidateKinds.add(kind);
  }
  for (const rawKind of Object.keys(metricsMap)) {
    const kind = kindId(rawKind);
    if (kind) candidateKinds.add(kind);
  }
  for (const kind of mountedByKind.keys()) candidateKinds.add(kind);

  const orderedKinds = [
    ...EXPECTED_DOMAIN_KINDS,
    ...[...candidateKinds]
      .filter((kind) => !EXPECTED_DOMAIN_KINDS.includes(kind))
      .sort(),
  ].slice(0, MAX_DOMAIN_KINDS);

  const rows = orderedKinds.map((kind) => {
    const mountedEntry = mountedByKind.get(kind) ?? null;
    const mounted = mountedEntry !== null;
    const statusEntry = ownRecord(statusMap, kind);
    const metricEntry = ownRecord(metricsMap, kind);
    const statusCircuit = ownRecord(statusEntry, "circuit");
    const metricCircuit = ownRecord(metricEntry, "circuit");

    const rawStatus =
      statusEntry && Object.hasOwn(statusEntry, "status")
        ? statusEntry.status
        : metricEntry && Object.hasOwn(metricEntry, "status")
          ? metricEntry.status
          : mountedEntry?.status;
    let status =
      typeof rawStatus === "string"
        ? VALID_STATES.has(rawStatus)
          ? rawStatus
          : "UNKNOWN"
        : mounted
          ? "UNKNOWN"
          : "NOT_MOUNTED";

    // Require the authoritative mounted-domain list to agree with lifecycle
    // labels. A contradictory response is unknown, never an implicit green.
    if ((!mounted && MOUNTED_STATES.has(status)) || (mounted && status === "NOT_MOUNTED")) {
      status = "UNKNOWN";
    }

    const invokes =
      statusEntry && Object.hasOwn(statusEntry, "invokes")
        ? statusEntry.invokes
        : metricEntry?.invokes;
    const successes =
      statusEntry && Object.hasOwn(statusEntry, "successes")
        ? statusEntry.successes
        : metricEntry?.successes;
    const probeInFlight =
      statusCircuit && Object.hasOwn(statusCircuit, "probe_inflight")
        ? statusCircuit.probe_inflight
        : metricCircuit?.probe_inflight;
    const leaseRemaining =
      statusCircuit && Object.hasOwn(statusCircuit, "probe_lease_expires_in_s")
        ? statusCircuit.probe_lease_expires_in_s
        : metricCircuit?.probe_lease_expires_in_s;

    return {
      kind,
      mounted,
      status,
      invokes: nonNegativeCount(invokes),
      successes: nonNegativeCount(successes),
      probeInFlight: typeof probeInFlight === "boolean" ? probeInFlight : null,
      probeLeaseExpiresInS: nonNegativeNumber(leaseRemaining),
      probeLeaseExpirations: nonNegativeCount(metricCircuit?.probe_lease_expirations),
      lastInvokeAt: timestamp(statusEntry?.last_invoke_at),
    };
  });

  return { rows };
}
