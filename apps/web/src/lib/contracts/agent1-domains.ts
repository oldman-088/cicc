import {
  contractArray,
  contractBoolean,
  contractEnum,
  contractJsonObject,
  contractNonEmptyString,
  contractNonNegativeInteger,
  contractNonNegativeNumber,
  contractNullableString,
  contractNullableTimestamp,
  contractObject,
  contractString,
  contractStringArray,
  type JsonObject,
} from "./decoder";

/** Candidate fields documented by Agent 1 PR #4 M45; not an approved host DTO. */
export const DOMAIN_LIFECYCLE_STATES = [
  "NOT_MOUNTED",
  "MOUNTED",
  "AVAILABLE",
  "EXECUTION_VERIFIED",
  "DEGRADED",
  "FAILED",
  "UNKNOWN",
] as const;

export type DomainLifecycleState = (typeof DOMAIN_LIFECYCLE_STATES)[number];

export type DomainCircuitCandidate = {
  open: boolean;
  opened_at: string | null;
  threshold: number;
  cooldown_s: number;
  opens?: number;
  closes?: number;
};

export type DomainLifecycleEvidenceCandidate = {
  status: DomainLifecycleState;
  version: string | null;
  source_ref: string | null;
  mounted_at: string | null;
  invokes: number;
  successes: number;
  consecutive_failures: number;
  last_stale: boolean | null;
  stale_after_s: number | null;
  last_invoke_at: string | null;
  last_error: string | null;
  /** M45 process-local last successful invoke; absent on older M44 responses. */
  last_success_at?: string | null;
  circuit?: DomainCircuitCandidate;
  /** Process-local counts only; `mounts_total` is a separate persisted metric. */
  mount_count?: number;
  previous_version?: string | null;
};

export type DomainDescriptorCandidate = {
  kind: string;
  version: string | null;
  source_ref: string | null;
  mounted_at: string | null;
  status: DomainLifecycleState;
};

export type DomainLifecycleListCandidate = {
  domains: DomainDescriptorCandidate[];
  statuses: Record<string, DomainLifecycleEvidenceCandidate>;
  states: DomainLifecycleState[];
  note: string;
};

export type DomainLifecycleStatusCandidate = {
  kind: string;
  status: DomainLifecycleState;
  evidence: DomainLifecycleEvidenceCandidate;
};

export type DomainLatencyCandidate = {
  count: number;
  /** Null until the first invoke has produced a latency sample. */
  avg_s: number | null;
  max_s: number;
  /** Null until the first invoke has produced a latency sample. */
  last_s: number | null;
};

export type DomainMetricsCandidate = {
  invokes: number;
  successes: number;
  failures: number;
  /** Null before any invokes; do not coerce missing measurements to 0%. */
  success_rate: number | null;
  timeouts: number;
  retries: number;
  stale_count: number;
  skew_count: number;
  latency: DomainLatencyCandidate;
  circuit: Required<Pick<DomainCircuitCandidate, "open" | "opened_at" | "threshold" | "cooldown_s" | "opens" | "closes">>;
  mount_count: number;
  /** Persisted mount-event count from the operations audit stream (M45). */
  mounts_total?: number;
  /** Process-local last-success timestamp (M45). */
  last_success_at?: string | null;
  status: DomainLifecycleState;
};

export type DomainMetricsResponseCandidate = {
  domains: Record<string, DomainMetricsCandidate>;
  labels: readonly ["kind"];
  note: string;
};

/** Documented M42 read shape; still only a PR #4 candidate, not host-verified. */
export type DomainDiagnosticsCandidate = {
  status: "ok" | "degraded";
  db_ok: boolean;
  version: string;
  uptime_s: number;
  mounted_domains: DomainDescriptorCandidate[];
  domain_statuses: Record<string, DomainLifecycleEvidenceCandidate>;
  stale_after_s: number;
  note: string;
};

export type DomainFreshnessCandidate = {
  stale: boolean;
  age_s: number;
  clock_skew_s: number;
  basis: "freshness_s" | "produced_at";
};

export type DomainProvenanceCandidate = {
  source: string;
  produced_at: string | null;
  confidence: number | null;
  freshness_s: number | null;
  stale?: boolean;
  freshness?: DomainFreshnessCandidate;
  domain_specific?: JsonObject;
};

export type DomainOperationalAlertCandidate = {
  rule: "domain_status";
  component_key: string | null;
  severity: string;
  status: string;
  message: string;
  first_seen: string | null;
  last_seen: string | null;
  resolved_at: string | null;
  acked_at: string | null;
  acked_by: string | null;
  occurrences: number;
};

export type DomainGatewayErrorCodeCandidate =
  | "domain_not_mounted"
  | "domain_invalid"
  | "domain_error"
  | "domain_circuit_open"
  | "payload_too_large";

/**
 * The route/error document lists candidate status codes and codes, but does not
 * publish one exact per-route JSON envelope. Keep the body unparsed until that
 * shared contract is approved.
 */
export type DomainGatewayErrorEnvelopeStatus = "unresolved";
export type DomainDiagnosticsContractStatus = "documented-candidate-not-approved";

export const DOMAIN_LIFECYCLE_FRONTEND_GATE = {
  approval: "pending",
  principalAndTenantScope: "pending",
  errorEnvelope: "unresolved",
  diagnosticsDto: "documented-candidate-not-approved",
  getSideEffectPolicy: "pending",
  mountHistoryPersistence: "mounts_total-persisted; mount_count-and-previous_version-process-local",
} as const;

function parseLifecycleState(value: unknown, path: string): DomainLifecycleState {
  return contractEnum(value, DOMAIN_LIFECYCLE_STATES, path);
}

function nullableNonNegativeNumber(value: unknown, path: string): number | null {
  if (value === null) return null;
  return contractNonNegativeNumber(value, path);
}

function nullableBoolean(value: unknown, path: string): boolean | null {
  if (value === null) return null;
  return contractBoolean(value, path);
}

function parseCircuit(value: unknown, path: string): DomainCircuitCandidate {
  const input = contractObject(value, path);
  const base: DomainCircuitCandidate = {
    open: contractBoolean(input.open, `${path}.open`),
    opened_at: contractNullableTimestamp(input.opened_at, `${path}.opened_at`),
    threshold: contractNonNegativeInteger(input.threshold, `${path}.threshold`),
    cooldown_s: contractNonNegativeNumber(input.cooldown_s, `${path}.cooldown_s`),
  };
  if (input.opens !== undefined) base.opens = contractNonNegativeInteger(input.opens, `${path}.opens`);
  if (input.closes !== undefined) base.closes = contractNonNegativeInteger(input.closes, `${path}.closes`);
  return base;
}

export function parseDomainLifecycleEvidenceCandidate(value: unknown, path = "evidence"): DomainLifecycleEvidenceCandidate {
  const input = contractObject(value, path);
  const result: DomainLifecycleEvidenceCandidate = {
    status: parseLifecycleState(input.status, `${path}.status`),
    version: contractNullableString(input.version, `${path}.version`),
    source_ref: contractNullableString(input.source_ref, `${path}.source_ref`),
    mounted_at: contractNullableTimestamp(input.mounted_at, `${path}.mounted_at`),
    invokes: contractNonNegativeInteger(input.invokes, `${path}.invokes`),
    successes: contractNonNegativeInteger(input.successes, `${path}.successes`),
    consecutive_failures: contractNonNegativeInteger(input.consecutive_failures, `${path}.consecutive_failures`),
    last_stale: nullableBoolean(input.last_stale, `${path}.last_stale`),
    stale_after_s: nullableNonNegativeNumber(input.stale_after_s, `${path}.stale_after_s`),
    last_invoke_at: contractNullableTimestamp(input.last_invoke_at, `${path}.last_invoke_at`),
    last_error: contractNullableString(input.last_error, `${path}.last_error`),
  };
  if (input.circuit !== undefined) result.circuit = parseCircuit(input.circuit, `${path}.circuit`);
  if (input.mount_count !== undefined) result.mount_count = contractNonNegativeInteger(input.mount_count, `${path}.mount_count`);
  if (input.previous_version !== undefined) result.previous_version = contractNullableString(input.previous_version, `${path}.previous_version`);
  if (input.last_success_at !== undefined) result.last_success_at = contractNullableTimestamp(input.last_success_at, `${path}.last_success_at`);
  return result;
}

function parseDomainDescriptor(value: unknown, path: string): DomainDescriptorCandidate {
  const input = contractObject(value, path);
  return {
    kind: contractNonEmptyString(input.kind, `${path}.kind`),
    version: contractNullableString(input.version, `${path}.version`),
    source_ref: contractNullableString(input.source_ref, `${path}.source_ref`),
    mounted_at: contractNullableTimestamp(input.mounted_at, `${path}.mounted_at`),
    status: parseLifecycleState(input.status, `${path}.status`),
  };
}

export function parseDomainLifecycleListCandidate(value: unknown): DomainLifecycleListCandidate {
  const input = contractObject(value, "domain-list");
  const statusesInput = contractObject(input.statuses, "domain-list.statuses");
  const statuses = Object.fromEntries(
    Object.entries(statusesInput).map(([kind, evidence]) => [
      kind,
      parseDomainLifecycleEvidenceCandidate(evidence, `domain-list.statuses.${kind}`),
    ]),
  );
  return {
    domains: contractArray(input.domains, "domain-list.domains", parseDomainDescriptor),
    statuses,
    states: contractArray(input.states, "domain-list.states", parseLifecycleState),
    note: contractString(input.note, "domain-list.note"),
  };
}

export function parseDomainLifecycleStatusCandidate(value: unknown): DomainLifecycleStatusCandidate {
  const input = contractObject(value, "domain-status");
  return {
    kind: contractNonEmptyString(input.kind, "domain-status.kind"),
    status: parseLifecycleState(input.status, "domain-status.status"),
    evidence: parseDomainLifecycleEvidenceCandidate(input.evidence, "domain-status.evidence"),
  };
}

function parseLatency(value: unknown, path: string): DomainLatencyCandidate {
  const input = contractObject(value, path);
  return {
    count: contractNonNegativeInteger(input.count, `${path}.count`),
    avg_s: input.avg_s === null ? null : contractNonNegativeNumber(input.avg_s, `${path}.avg_s`),
    max_s: contractNonNegativeNumber(input.max_s, `${path}.max_s`),
    last_s: input.last_s === null ? null : contractNonNegativeNumber(input.last_s, `${path}.last_s`),
  };
}

function parseMetricsDomain(value: unknown, path: string): DomainMetricsCandidate {
  const input = contractObject(value, path);
  const rate = input.success_rate === null ? null : contractNonNegativeNumber(input.success_rate, `${path}.success_rate`);
  if (rate !== null && rate > 1) throw new Error(`Contract payload at ${path}.success_rate must be between 0 and 1`);
  const circuit = parseCircuit(input.circuit, `${path}.circuit`);
  if (circuit.opens === undefined || circuit.closes === undefined) {
    throw new Error(`Contract payload at ${path}.circuit must include opens and closes`);
  }
  const result: DomainMetricsCandidate = {
    invokes: contractNonNegativeInteger(input.invokes, `${path}.invokes`),
    successes: contractNonNegativeInteger(input.successes, `${path}.successes`),
    failures: contractNonNegativeInteger(input.failures, `${path}.failures`),
    success_rate: rate,
    timeouts: contractNonNegativeInteger(input.timeouts, `${path}.timeouts`),
    retries: contractNonNegativeInteger(input.retries, `${path}.retries`),
    stale_count: contractNonNegativeInteger(input.stale_count, `${path}.stale_count`),
    skew_count: contractNonNegativeInteger(input.skew_count, `${path}.skew_count`),
    latency: parseLatency(input.latency, `${path}.latency`),
    circuit: circuit as Required<Pick<DomainCircuitCandidate, "open" | "opened_at" | "threshold" | "cooldown_s" | "opens" | "closes">>,
    mount_count: contractNonNegativeInteger(input.mount_count, `${path}.mount_count`),
    status: parseLifecycleState(input.status, `${path}.status`),
  };
  if (input.mounts_total !== undefined) result.mounts_total = contractNonNegativeInteger(input.mounts_total, `${path}.mounts_total`);
  if (input.last_success_at !== undefined) result.last_success_at = contractNullableTimestamp(input.last_success_at, `${path}.last_success_at`);
  return result;
}

export function parseDomainMetricsCandidate(value: unknown): DomainMetricsResponseCandidate {
  const input = contractObject(value, "domain-metrics");
  const domainsInput = contractObject(input.domains, "domain-metrics.domains");
  const domains = Object.fromEntries(
    Object.entries(domainsInput).map(([kind, metrics]) => [kind, parseMetricsDomain(metrics, `domain-metrics.domains.${kind}`)]),
  );
  const labels = contractStringArray(input.labels, "domain-metrics.labels");
  if (labels.length !== 1 || labels[0] !== "kind") {
    throw new Error("Contract payload at domain-metrics.labels must contain only the bounded 'kind' label");
  }
  return { domains, labels: ["kind"], note: contractString(input.note, "domain-metrics.note") };
}

/** Decode the documented diagnostics shape without implying an approved host mount. */
export function parseDomainDiagnosticsCandidate(value: unknown): DomainDiagnosticsCandidate {
  const input = contractObject(value, "domain-diagnostics");
  const statusesInput = contractObject(input.domain_statuses, "domain-diagnostics.domain_statuses");
  const domainStatuses = Object.fromEntries(
    Object.entries(statusesInput).map(([kind, evidence]) => [
      kind,
      parseDomainLifecycleEvidenceCandidate(evidence, `domain-diagnostics.domain_statuses.${kind}`),
    ]),
  );
  const uptime = contractNonNegativeNumber(input.uptime_s, "domain-diagnostics.uptime_s");
  return {
    status: contractEnum(input.status, ["ok", "degraded"] as const, "domain-diagnostics.status"),
    db_ok: contractBoolean(input.db_ok, "domain-diagnostics.db_ok"),
    version: contractNonEmptyString(input.version, "domain-diagnostics.version"),
    uptime_s: uptime,
    mounted_domains: contractArray(input.mounted_domains, "domain-diagnostics.mounted_domains", parseDomainDescriptor),
    domain_statuses: domainStatuses,
    stale_after_s: contractNonNegativeNumber(input.stale_after_s, "domain-diagnostics.stale_after_s"),
    note: contractString(input.note, "domain-diagnostics.note"),
  };
}

export function parseDomainFreshnessCandidate(value: unknown): DomainFreshnessCandidate {
  const input = contractObject(value, "domain-freshness");
  return {
    stale: contractBoolean(input.stale, "domain-freshness.stale"),
    age_s: contractNonNegativeNumber(input.age_s, "domain-freshness.age_s"),
    clock_skew_s: contractNonNegativeNumber(input.clock_skew_s, "domain-freshness.clock_skew_s"),
    basis: contractEnum(input.basis, ["freshness_s", "produced_at"] as const, "domain-freshness.basis"),
  };
}

export function parseDomainProvenanceCandidate(value: unknown): DomainProvenanceCandidate {
  const input = contractObject(value, "domain-provenance");
  const confidence = input.confidence === null ? null : contractNonNegativeNumber(input.confidence, "domain-provenance.confidence");
  if (confidence !== null && confidence > 1) throw new Error("Contract payload at domain-provenance.confidence must be between 0 and 1");
  const freshnessSeconds = input.freshness_s === null ? null : contractNonNegativeNumber(input.freshness_s, "domain-provenance.freshness_s");
  const result: DomainProvenanceCandidate = {
    source: contractNonEmptyString(input.source, "domain-provenance.source"),
    produced_at: contractNullableTimestamp(input.produced_at, "domain-provenance.produced_at"),
    confidence,
    freshness_s: freshnessSeconds,
  };
  if (input.stale !== undefined) result.stale = contractBoolean(input.stale, "domain-provenance.stale");
  if (input.freshness !== undefined) result.freshness = parseDomainFreshnessCandidate(input.freshness);
  if (input.domain_specific !== undefined) result.domain_specific = contractJsonObject(input.domain_specific, "domain-provenance.domain_specific");
  return result;
}

/** M45 documents diagnostics and last-success fields; ownership gates remain open. */
export const agent1DomainUnresolvedSurfaces = {
  diagnostics: "documented-candidate-not-approved-or-wired",
  perRouteErrorEnvelope: "unresolved",
  ownerApproval: "pending",
  principalTenantScope: "pending",
  getSideEffectPolicy: "pending",
  mountCountPersistence: "process-local",
  mountsTotalPersistence: "persisted-audit-event-count",
  lastSuccessPersistence: "process-local",
  previousVersionPersistence: "process-local",
} as const;
