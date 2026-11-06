export type IntegrationFailureKind =
  | "not_configured"
  | "unauthorized"
  | "forbidden"
  | "rate_limited"
  | "invalid_request"
  | "conflict"
  | "expired"
  | "payload_too_large"
  | "invalid_response"
  | "not_found"
  | "unavailable"
  | "other";

export class IntegrationApiError extends Error {
  readonly kind: IntegrationFailureKind;
  readonly status?: number;
  readonly retryAfterSeconds?: number;

  constructor(
    kind: IntegrationFailureKind,
    status?: number,
    retryAfterSeconds?: number,
  ) {
    super(kind);
    this.name = "IntegrationApiError";
    this.kind = kind;
    this.status = status;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export type OpsComponent = {
  key: string;
  kind: string;
  name: string;
  status: string;
  detail: string;
  last_check_at: string | null;
};

export type OpsActivityEvent = {
  id: number;
  ts: string | null;
  level: string;
  source: string;
  message: string;
};

export type OpsOverview = {
  generated_at: string;
  overall_status: string;
  services: OpsComponent[];
  modules: OpsComponent[];
  metrics: {
    entities: number;
    vulnerabilities: number;
    campaigns: number;
    recent_updates_24h: number;
    last_successful_sync: string | null;
  };
  activity: OpsActivityEvent[];
  data_source: string;
  cached: boolean | null;
  cache_age_s: number | null;
};

export type OpsAlert = {
  id: number;
  rule: string;
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
  escalated: boolean;
  flapping: boolean;
  owner: string | null;
};

export type OpsWorkers = {
  stall_threshold_s: number;
  workers: Array<{
    worker: string;
    last_seen: string | null;
    age_s: number | null;
    stalled: boolean;
    tasks_24h: number;
    failed_24h: number;
    details: string;
    registered: boolean;
    version: string | null;
    capabilities: string[];
    registered_at: string | null;
  }>;
};

export type CoordinationAgent = {
  agent: string;
  specialization: string | null;
  capabilities: string[];
  status: string;
  health: string | null;
  stale: boolean;
  last_seen: string | null;
  last_seen_field: "last_seen" | "last_heartbeat" | null;
  active_tasks: number;
  completed_tasks: number;
  failed_tasks: number;
};

export type CoordinationRoutingExplanation = {
  via: string;
  rule: string | null;
  score: number | null;
  candidates: number | null;
  reasons: string[];
};

export type CoordinationTask = {
  task_id: string;
  kind: string;
  state: string;
  priority: number;
  agent: string | null;
  title: string | null;
  repo: string | null;
  branch_ref: string | null;
  created_at: string | null;
  updated_at: string | null;
  idempotency_key: string | null;
  dead_letter: boolean;
  attempts: number | null;
  progress: number | null;
  result: string | null;
  routing_explanation: CoordinationRoutingExplanation | null;
};

export type CoordinationWriteCapabilities = {
  task_creation_enabled: boolean;
  task_routing_enabled: boolean;
};

export type CreateCoordinationTaskInput = {
  kind: string;
  title: string;
  priority: number;
  payload: Record<string, unknown>;
  requires_approval: boolean;
};

export type CreateCoordinationTaskResult = {
  task_id: string;
  kind: string;
  state: string;
  duplicate: boolean;
  idempotency_key: string | null;
};

export type RouteCoordinationTaskResult = {
  task_id: string;
  agent: string | null;
  state: string;
  explanation: CoordinationRoutingExplanation;
};

export type CoordinationMetrics = {
  tasks_total: number;
  by_state: Record<string, number>;
  by_kind: Record<string, number>;
  active_by_agent: Record<string, number>;
  avg_progress_active: number;
  dead_lettered: number;
  deliveries_total: number;
  deliveries_by_outcome: Record<string, number>;
  approvals_pending: number;
  agents_registered: number;
  agents_online: number;
};

export type CoordinationEvent = {
  delivery_id: string;
  event: string;
  received_at: string | null;
  action: string | null;
  repo: string | null;
  sender: string | null;
  task_id: string | null;
};

export type OpsAlerts = { alerts: OpsAlert[] };
export type CoordinationAgents = { agents: CoordinationAgent[] };
export type CoordinationTasks = { tasks: CoordinationTask[] };
export type CoordinationEvents = { events: CoordinationEvent[] };

export type CoordinationHealthStatus =
  | "healthy"
  | "degraded"
  | "stale"
  | "failed"
  | "unavailable"
  | "not_configured"
  | "unknown";

export type CoordinationHealth = {
  overall: CoordinationHealthStatus;
  components: Array<{
    key: string;
    status: CoordinationHealthStatus;
    detail: string;
    reasons: string[];
  }>;
  reasons: string[];
  last_operations: {
    last_webhook_received: string | null;
    last_github_sync_success: string | null;
    last_github_sync_attempt: string | null;
    last_task_event: string | null;
    checked_at: string | null;
    note: string;
  };
  at: string | null;
};

export type CoordinationTaskTrace = {
  task_id: string;
  correlation: { idempotency_key: string | null; event_id: string | null };
  state: string;
  agent: string | null;
  attempts: number;
  dead_letter: boolean;
  events: Array<{ id: number; at: string | null; kind: string; detail: string | null }>;
  deliveries: Array<{
    id: number;
    channel: string | null;
    queue: string | null;
    message_id: string | null;
    status: string | null;
    attempt: number;
    at: string | null;
  }>;
  approvals: Array<{
    id: number;
    status: string;
    requested_by: string | null;
    decided_by: string | null;
    at: string | null;
  }>;
};

export const integrationEndpoints = {
  opsOverview: "/api/integrations/ops/overview",
  opsAlerts: "/api/integrations/ops/alerts",
  opsWorkers: "/api/integrations/ops/workers",
  coordinationAgents: "/api/integrations/coordination/agents",
  coordinationHealth: "/api/integrations/coordination/health",
  coordinationTasks: "/api/integrations/coordination/tasks",
  coordinationWriteCapabilities: "/api/integrations/coordination/write-capabilities",
  coordinationTaskRoute: (taskId: string) =>
    `/api/integrations/coordination/tasks/${encodeURIComponent(taskId)}/route`,
  coordinationTaskTrace: (taskId: string) =>
    `/api/integrations/coordination/task-trace?task_id=${encodeURIComponent(taskId)}`,
  coordinationMetrics: "/api/integrations/coordination/metrics",
  coordinationEvents: "/api/integrations/coordination/events",
} as const;

function fail(message: string): never {
  throw new Error(`Invalid integration response: ${message}`);
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return fail(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function string(value: unknown, label: string): string {
  if (typeof value !== "string") return fail(`${label} must be a string`);
  return value;
}

function nonEmptyString(value: unknown, label: string): string {
  const result = string(value, label);
  if (result.trim().length === 0) return fail(`${label} must not be empty`);
  return result;
}

function nullableString(value: unknown, label: string): string | null {
  if (value === null || value === undefined) return null;
  return string(value, label);
}

function nonNegativeInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    return fail(`${label} must be a non-negative integer`);
  }
  return value;
}

function finiteNonNegative(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    return fail(`${label} must be a non-negative number`);
  }
  return value;
}

function boolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") return fail(`${label} must be a boolean`);
  return value;
}

function stringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value)) return fail(`${label} must be an array`);
  return value.map((item, index) => string(item, `${label}[${index}]`));
}

function array<T>(value: unknown, label: string, parse: (item: unknown, index: number) => T): T[] {
  if (!Array.isArray(value)) return fail(`${label} must be an array`);
  return value.map(parse);
}

function optionalBoolean(value: unknown, label: string, fallback: boolean): boolean {
  if (value === undefined || value === null) return fallback;
  return boolean(value, label);
}

function optionalNumber(value: unknown, label: string): number | null {
  if (value === undefined || value === null) return null;
  return finiteNonNegative(value, label);
}

function optionalInteger(value: unknown, label: string): number | null {
  if (value === undefined || value === null) return null;
  return nonNegativeInteger(value, label);
}

function optionalProgress(value: unknown, label: string): number | null {
  const progress = optionalInteger(value, label);
  if (progress !== null && progress > 100) return fail(`${label} must be between 0 and 100`);
  return progress;
}

function parseComponent(value: unknown, index: number): OpsComponent {
  const item = object(value, `component[${index}]`);
  return {
    key: string(item.key, `component[${index}].key`),
    kind: string(item.kind, `component[${index}].kind`),
    name: string(item.name, `component[${index}].name`),
    status: string(item.status, `component[${index}].status`),
    detail: string(item.detail, `component[${index}].detail`),
    last_check_at: nullableString(item.last_check_at, `component[${index}].last_check_at`),
  };
}

function parseOpsActivity(value: unknown, index: number): OpsActivityEvent {
  const item = object(value, `activity[${index}]`);
  return {
    id: nonNegativeInteger(item.id, `activity[${index}].id`),
    ts: nullableString(item.ts, `activity[${index}].ts`),
    level: string(item.level, `activity[${index}].level`),
    source: string(item.source, `activity[${index}].source`),
    message: string(item.message, `activity[${index}].message`),
  };
}

export function parseOpsOverview(value: unknown): OpsOverview {
  const root = object(value, "overview");
  const metrics = object(root.metrics, "overview.metrics");
  return {
    generated_at: string(root.generated_at, "overview.generated_at"),
    overall_status: string(root.overall_status, "overview.overall_status"),
    services: array(root.services, "overview.services", parseComponent),
    modules: array(root.modules, "overview.modules", parseComponent),
    metrics: {
      entities: nonNegativeInteger(metrics.entities, "metrics.entities"),
      vulnerabilities: nonNegativeInteger(metrics.vulnerabilities, "metrics.vulnerabilities"),
      campaigns: nonNegativeInteger(metrics.campaigns, "metrics.campaigns"),
      recent_updates_24h: nonNegativeInteger(metrics.recent_updates_24h, "metrics.recent_updates_24h"),
      last_successful_sync: nullableString(metrics.last_successful_sync, "metrics.last_successful_sync"),
    },
    activity: array(root.activity, "overview.activity", parseOpsActivity),
    data_source: string(root.data_source, "overview.data_source"),
    cached: root.cached === undefined || root.cached === null ? null : boolean(root.cached, "overview.cached"),
    cache_age_s: optionalNumber(root.cache_age_s, "overview.cache_age_s"),
  };
}

function parseOpsAlert(value: unknown, index: number): OpsAlert {
  const item = object(value, `alerts[${index}]`);
  return {
    id: nonNegativeInteger(item.id, `alerts[${index}].id`),
    rule: string(item.rule, `alerts[${index}].rule`),
    component_key: nullableString(item.component_key, `alerts[${index}].component_key`),
    severity: string(item.severity, `alerts[${index}].severity`),
    status: string(item.status, `alerts[${index}].status`),
    message: string(item.message, `alerts[${index}].message`),
    first_seen: nullableString(item.first_seen, `alerts[${index}].first_seen`),
    last_seen: nullableString(item.last_seen, `alerts[${index}].last_seen`),
    resolved_at: nullableString(item.resolved_at, `alerts[${index}].resolved_at`),
    acked_at: nullableString(item.acked_at, `alerts[${index}].acked_at`),
    acked_by: nullableString(item.acked_by, `alerts[${index}].acked_by`),
    occurrences: nonNegativeInteger(item.occurrences, `alerts[${index}].occurrences`),
    escalated: optionalBoolean(item.escalated, `alerts[${index}].escalated`, false),
    flapping: optionalBoolean(item.flapping, `alerts[${index}].flapping`, false),
    owner: nullableString(item.owner, `alerts[${index}].owner`),
  };
}

export function parseOpsAlerts(value: unknown): OpsAlerts {
  const root = object(value, "alerts response");
  return { alerts: array(root.alerts, "alerts", parseOpsAlert) };
}

function parseWorker(value: unknown, index: number): OpsWorkers["workers"][number] {
  const item = object(value, `workers[${index}]`);
  return {
    worker: string(item.worker, `workers[${index}].worker`),
    last_seen: nullableString(item.last_seen, `workers[${index}].last_seen`),
    age_s: optionalNumber(item.age_s, `workers[${index}].age_s`),
    stalled: boolean(item.stalled, `workers[${index}].stalled`),
    tasks_24h: nonNegativeInteger(item.tasks_24h, `workers[${index}].tasks_24h`),
    failed_24h: nonNegativeInteger(item.failed_24h, `workers[${index}].failed_24h`),
    details: string(item.details, `workers[${index}].details`),
    registered: optionalBoolean(item.registered, `workers[${index}].registered`, false),
    version: nullableString(item.version, `workers[${index}].version`),
    capabilities: item.capabilities === undefined ? [] : stringArray(item.capabilities, `workers[${index}].capabilities`),
    registered_at: nullableString(item.registered_at, `workers[${index}].registered_at`),
  };
}

export function parseOpsWorkers(value: unknown): OpsWorkers {
  const root = object(value, "workers response");
  return {
    stall_threshold_s: finiteNonNegative(root.stall_threshold_s, "workers.stall_threshold_s"),
    workers: array(root.workers, "workers", parseWorker),
  };
}

function integerAlias(
  item: Record<string, unknown>,
  documentedKey: string,
  implementationKey: string,
  label: string,
): number {
  const candidates = [documentedKey, implementationKey]
    .filter((key) => item[key] !== undefined)
    .map((key) => nonNegativeInteger(item[key], `${label}.${key}`));
  if (candidates.length === 0) return fail(`${label}.${documentedKey} or ${implementationKey} is required`);
  if (candidates.some((candidate) => candidate !== candidates[0])) {
    return fail(`${label}.${documentedKey} and ${implementationKey} conflict`);
  }
  return candidates[0];
}

function timestampAlias(
  item: Record<string, unknown>,
  label: string,
): { value: string | null; field: "last_seen" | "last_heartbeat" | null } {
  const keys = (["last_seen", "last_heartbeat"] as const).filter((key) => item[key] !== undefined);
  const candidates = keys.map((key) => ({ key, value: nullableString(item[key], `${label}.${key}`) }));
  if (candidates.length > 1 && candidates.some((candidate) => candidate.value !== candidates[0].value)) {
    return fail(`${label}.last_seen and last_heartbeat conflict`);
  }
  const selected = candidates[0];
  return selected ? { value: selected.value, field: selected.key } : { value: null, field: null };
}

function parseCoordinationAgent(value: unknown, index: number): CoordinationAgent {
  const item = object(value, `agents[${index}]`);
  const reportedTimestamp = timestampAlias(item, `agents[${index}]`);
  return {
    agent: nonEmptyString(item.agent, `agents[${index}].agent`),
    specialization: nullableString(item.specialization, `agents[${index}].specialization`),
    capabilities: stringArray(item.capabilities, `agents[${index}].capabilities`),
    status: string(item.status, `agents[${index}].status`),
    health: nullableString(item.health, `agents[${index}].health`),
    stale: boolean(item.stale, `agents[${index}].stale`),
    last_seen: reportedTimestamp.value,
    last_seen_field: reportedTimestamp.field,
    active_tasks: nonNegativeInteger(item.active_tasks, `agents[${index}].active_tasks`),
    completed_tasks: integerAlias(item, "completed_tasks", "completed", `agents[${index}]`),
    failed_tasks: integerAlias(item, "failed_tasks", "failed", `agents[${index}]`),
  };
}

export function parseCoordinationAgents(value: unknown): CoordinationAgents {
  const root = object(value, "agents response");
  return { agents: array(root.agents, "agents", parseCoordinationAgent) };
}

function parseCoordinationRoutingExplanation(value: unknown, label: string): CoordinationRoutingExplanation {
  const item = object(value, label);
  return {
    via: nonEmptyString(item.via, `${label}.via`),
    rule: nullableString(item.rule, `${label}.rule`),
    score: optionalNumber(item.score, `${label}.score`),
    candidates: optionalInteger(item.candidates, `${label}.candidates`),
    reasons: item.reasons === undefined || item.reasons === null
      ? []
      : stringArray(item.reasons, `${label}.reasons`),
  };
}

function parseCoordinationTask(value: unknown, index: number): CoordinationTask {
  const item = object(value, `tasks[${index}]`);
  return {
    task_id: nonEmptyString(item.task_id, `tasks[${index}].task_id`),
    kind: string(item.kind, `tasks[${index}].kind`),
    state: string(item.state, `tasks[${index}].state`),
    priority: nonNegativeInteger(item.priority, `tasks[${index}].priority`),
    agent: nullableString(item.agent, `tasks[${index}].agent`),
    title: nullableString(item.title, `tasks[${index}].title`),
    repo: nullableString(item.repo, `tasks[${index}].repo`),
    branch_ref: nullableString(item.branch_ref, `tasks[${index}].branch_ref`),
    created_at: nullableString(item.created_at, `tasks[${index}].created_at`),
    updated_at: nullableString(item.updated_at, `tasks[${index}].updated_at`),
    idempotency_key: nullableString(item.idempotency_key, `tasks[${index}].idempotency_key`),
    dead_letter: optionalBoolean(item.dead_letter, `tasks[${index}].dead_letter`, false),
    attempts: optionalInteger(item.attempts, `tasks[${index}].attempts`),
    progress: optionalProgress(item.progress, `tasks[${index}].progress`),
    result: nullableString(item.result, `tasks[${index}].result`),
    routing_explanation: item.routing_explanation === undefined || item.routing_explanation === null
      ? null
      : parseCoordinationRoutingExplanation(item.routing_explanation, `tasks[${index}].routing_explanation`),
  };
}

export function parseCoordinationTasks(value: unknown): CoordinationTasks {
  const root = object(value, "tasks response");
  return { tasks: array(root.tasks, "tasks", parseCoordinationTask) };
}

export function parseCoordinationWriteCapabilities(value: unknown): CoordinationWriteCapabilities {
  const root = object(value, "coordination write capabilities");
  return {
    task_creation_enabled: boolean(root.task_creation_enabled, "capabilities.task_creation_enabled"),
    task_routing_enabled: boolean(root.task_routing_enabled, "capabilities.task_routing_enabled"),
  };
}

export function parseCreateCoordinationTaskResult(value: unknown): Omit<CreateCoordinationTaskResult, "idempotency_key"> {
  const root = object(value, "create task response");
  return {
    task_id: nonEmptyString(root.task_id, "create.task_id"),
    kind: nonEmptyString(root.kind, "create.kind"),
    state: nonEmptyString(root.state, "create.state"),
    duplicate: boolean(root.duplicate, "create.duplicate"),
  };
}

export function parseRouteCoordinationTaskResult(value: unknown): RouteCoordinationTaskResult {
  const root = object(value, "route task response");
  return {
    task_id: nonEmptyString(root.task_id, "route.task_id"),
    agent: nullableString(root.agent, "route.agent"),
    state: nonEmptyString(root.state, "route.state"),
    explanation: parseCoordinationRoutingExplanation(root.explanation, "route.explanation"),
  };
}

function numberMap(value: unknown, label: string): Record<string, number> {
  const entries = object(value, label);
  return Object.fromEntries(
    Object.entries(entries).map(([key, count]) => [key, nonNegativeInteger(count, `${label}.${key}`)]),
  );
}

export function parseCoordinationMetrics(value: unknown): CoordinationMetrics {
  const root = object(value, "coordination metrics");
  return {
    tasks_total: nonNegativeInteger(root.tasks_total, "metrics.tasks_total"),
    by_state: numberMap(root.by_state, "metrics.by_state"),
    by_kind: numberMap(root.by_kind, "metrics.by_kind"),
    active_by_agent: numberMap(root.active_by_agent, "metrics.active_by_agent"),
    avg_progress_active: finiteNonNegative(root.avg_progress_active, "metrics.avg_progress_active"),
    dead_lettered: nonNegativeInteger(root.dead_lettered, "metrics.dead_lettered"),
    deliveries_total: nonNegativeInteger(root.deliveries_total, "metrics.deliveries_total"),
    deliveries_by_outcome: numberMap(root.deliveries_by_outcome, "metrics.deliveries_by_outcome"),
    approvals_pending: nonNegativeInteger(root.approvals_pending, "metrics.approvals_pending"),
    agents_registered: nonNegativeInteger(root.agents_registered, "metrics.agents_registered"),
    agents_online: nonNegativeInteger(root.agents_online, "metrics.agents_online"),
  };
}

function parseCoordinationEvent(value: unknown, index: number): CoordinationEvent {
  const item = object(value, `events[${index}]`);
  return {
    delivery_id: nonEmptyString(item.delivery_id, `events[${index}].delivery_id`),
    event: nonEmptyString(item.event, `events[${index}].event`),
    received_at: nullableString(item.received_at, `events[${index}].received_at`),
    action: nullableString(item.action, `events[${index}].action`),
    repo: nullableString(item.repo, `events[${index}].repo`),
    sender: nullableString(item.sender, `events[${index}].sender`),
    task_id: nullableString(item.task_id, `events[${index}].task_id`),
  };
}

export function parseCoordinationEvents(value: unknown): CoordinationEvents {
  const root = object(value, "events response");
  return { events: array(root.events, "events", parseCoordinationEvent) };
}

const coordinationHealthStatuses = new Set<CoordinationHealthStatus>([
  "healthy", "degraded", "stale", "failed", "unavailable", "not_configured", "unknown",
]);

function coordinationHealthStatus(value: unknown, label: string): CoordinationHealthStatus {
  const parsed = string(value, label);
  if (!coordinationHealthStatuses.has(parsed as CoordinationHealthStatus)) {
    return fail(`${label} is not a documented coordination health status`);
  }
  return parsed as CoordinationHealthStatus;
}

function parseCoordinationHealthComponent(value: unknown, index: number): CoordinationHealth["components"][number] {
  const item = object(value, `health.components[${index}]`);
  return {
    key: nonEmptyString(item.key, `health.components[${index}].key`),
    status: coordinationHealthStatus(item.status, `health.components[${index}].status`),
    detail: string(item.detail, `health.components[${index}].detail`),
    reasons: stringArray(item.reasons, `health.components[${index}].reasons`),
  };
}

export function parseCoordinationHealth(value: unknown): CoordinationHealth {
  const root = object(value, "coordination health");
  const operations = object(root.last_operations, "health.last_operations");
  return {
    overall: coordinationHealthStatus(root.overall, "health.overall"),
    components: array(root.components, "health.components", parseCoordinationHealthComponent),
    reasons: stringArray(root.reasons, "health.reasons"),
    last_operations: {
      last_webhook_received: nullableString(operations.last_webhook_received, "health.last_operations.last_webhook_received"),
      last_github_sync_success: nullableString(operations.last_github_sync_success, "health.last_operations.last_github_sync_success"),
      last_github_sync_attempt: nullableString(operations.last_github_sync_attempt, "health.last_operations.last_github_sync_attempt"),
      last_task_event: nullableString(operations.last_task_event, "health.last_operations.last_task_event"),
      checked_at: nullableString(operations.checked_at, "health.last_operations.checked_at"),
      note: string(operations.note, "health.last_operations.note"),
    },
    at: nullableString(root.at, "health.at"),
  };
}

function parseTraceEvent(value: unknown, index: number): CoordinationTaskTrace["events"][number] {
  const item = object(value, `trace.events[${index}]`);
  return {
    id: nonNegativeInteger(item.id, `trace.events[${index}].id`),
    at: nullableString(item.at, `trace.events[${index}].at`),
    kind: nonEmptyString(item.kind, `trace.events[${index}].kind`),
    detail: nullableString(item.detail, `trace.events[${index}].detail`),
  };
}

function parseTraceDelivery(value: unknown, index: number): CoordinationTaskTrace["deliveries"][number] {
  const item = object(value, `trace.deliveries[${index}]`);
  return {
    id: nonNegativeInteger(item.id, `trace.deliveries[${index}].id`),
    channel: nullableString(item.channel, `trace.deliveries[${index}].channel`),
    queue: nullableString(item.queue, `trace.deliveries[${index}].queue`),
    message_id: nullableString(item.message_id, `trace.deliveries[${index}].message_id`),
    status: nullableString(item.status, `trace.deliveries[${index}].status`),
    attempt: nonNegativeInteger(item.attempt, `trace.deliveries[${index}].attempt`),
    at: nullableString(item.at, `trace.deliveries[${index}].at`),
  };
}

function parseTraceApproval(value: unknown, index: number): CoordinationTaskTrace["approvals"][number] {
  const item = object(value, `trace.approvals[${index}]`);
  return {
    id: nonNegativeInteger(item.id, `trace.approvals[${index}].id`),
    status: nonEmptyString(item.status, `trace.approvals[${index}].status`),
    requested_by: nullableString(item.requested_by, `trace.approvals[${index}].requested_by`),
    decided_by: nullableString(item.decided_by, `trace.approvals[${index}].decided_by`),
    at: nullableString(item.at, `trace.approvals[${index}].at`),
  };
}

export function parseCoordinationTaskTrace(value: unknown): CoordinationTaskTrace {
  const root = object(value, "coordination task trace");
  const correlation = object(root.correlation, "trace.correlation");
  return {
    task_id: nonEmptyString(root.task_id, "trace.task_id"),
    correlation: {
      idempotency_key: nullableString(correlation.idempotency_key, "trace.correlation.idempotency_key"),
      event_id: nullableString(correlation.event_id, "trace.correlation.event_id"),
    },
    state: nonEmptyString(root.state, "trace.state"),
    agent: nullableString(root.agent, "trace.agent"),
    attempts: nonNegativeInteger(root.attempts, "trace.attempts"),
    dead_letter: boolean(root.dead_letter, "trace.dead_letter"),
    events: array(root.events, "trace.events", parseTraceEvent),
    deliveries: array(root.deliveries, "trace.deliveries", parseTraceDelivery),
    approvals: array(root.approvals, "trace.approvals", parseTraceApproval),
  };
}

function errorKind(code: unknown, status: number): IntegrationFailureKind {
  if (code === "provider_not_configured") return "not_configured";
  if (code === "unauthorized") return "unauthorized";
  if (code === "forbidden") return "forbidden";
  if (code === "rate_limited") return "rate_limited";
  if (code === "invalid_request") return "invalid_request";
  if (code === "conflict") return "conflict";
  if (code === "expired") return "expired";
  if (code === "payload_too_large") return "payload_too_large";
  if (code === "invalid_upstream_response") return "invalid_response";
  if (code === "not_found") return "not_found";
  if (code === "upstream_unavailable") return "unavailable";
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  if (status === 404) return "not_found";
  if (status === 409) return "conflict";
  if (status === 410) return "expired";
  if (status === 413) return "payload_too_large";
  if (status === 422) return "invalid_request";
  if (status === 429) return "rate_limited";
  if (status >= 500) return "unavailable";
  return "other";
}

export async function readIntegrationResource<T>(
  endpoint: string,
  decode: (value: unknown) => T,
  signal: AbortSignal,
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(endpoint, {
      method: "GET",
      headers: { Accept: "application/json" },
      cache: "no-store",
      credentials: "same-origin",
      signal,
    });
  } catch (error) {
    if (signal.aborted) throw error;
    throw new IntegrationApiError("unavailable");
  }

  if (!response.ok) {
    let code: unknown;
    try {
      const body: unknown = await response.json();
      const root = object(body, "error response");
      const details = object(root.error, "error response.error");
      code = details.code;
    } catch {
      code = undefined;
    }
    const retryAfter = response.headers.get("retry-after");
    const retryAfterSeconds = retryAfter && /^\d{1,5}$/.test(retryAfter) ? Number(retryAfter) : undefined;
    throw new IntegrationApiError(errorKind(code, response.status), response.status, retryAfterSeconds);
  }

  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) {
    throw new IntegrationApiError("invalid_response", response.status);
  }

  let value: unknown;
  try {
    value = await response.json();
  } catch {
    throw new IntegrationApiError("invalid_response", response.status);
  }
  try {
    return decode(value);
  } catch {
    throw new IntegrationApiError("invalid_response", response.status);
  }
}

async function integrationErrorFromResponse(response: Response): Promise<IntegrationApiError> {
  let code: unknown;
  try {
    const body: unknown = await response.json();
    const root = object(body, "error response");
    const details = object(root.error, "error response.error");
    code = details.code;
  } catch {
    code = undefined;
  }
  const retryAfter = response.headers.get("retry-after");
  const retryAfterSeconds = retryAfter && /^\d{1,5}$/.test(retryAfter) ? Number(retryAfter) : undefined;
  return new IntegrationApiError(errorKind(code, response.status), response.status, retryAfterSeconds);
}

async function postIntegrationJson<T>(
  endpoint: string,
  body: Record<string, unknown> | undefined,
  decode: (value: unknown) => T,
  signal?: AbortSignal,
): Promise<{ value: T; response: Response }> {
  let response: Response;
  try {
    response = await fetch(endpoint, {
      method: "POST",
      headers: {
        Accept: "application/json",
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      cache: "no-store",
      credentials: "same-origin",
      signal,
    });
  } catch (error) {
    if (signal?.aborted) throw error;
    throw new IntegrationApiError("unavailable");
  }

  if (!response.ok) throw await integrationErrorFromResponse(response);
  const contentType = response.headers.get("content-type") ?? "";
  if (!/^application\/json\b/i.test(contentType)) {
    throw new IntegrationApiError("invalid_response", response.status);
  }
  let raw: unknown;
  try {
    raw = await response.json();
  } catch {
    throw new IntegrationApiError("invalid_response", response.status);
  }
  try {
    return { value: decode(raw), response };
  } catch {
    throw new IntegrationApiError("invalid_response", response.status);
  }
}

export async function createCoordinationTask(
  input: CreateCoordinationTaskInput,
  signal?: AbortSignal,
): Promise<CreateCoordinationTaskResult> {
  const { value, response } = await postIntegrationJson(
    integrationEndpoints.coordinationTasks,
    input,
    parseCreateCoordinationTaskResult,
    signal,
  );
  const idempotencyKey = response.headers.get("x-cicc-idempotency-key");
  if (idempotencyKey !== null && !/^[A-Za-z0-9_.:-]{1,300}$/.test(idempotencyKey)) {
    throw new IntegrationApiError("invalid_response", response.status);
  }
  return { ...value, idempotency_key: idempotencyKey };
}

export async function routeCoordinationTask(
  taskId: string,
  signal?: AbortSignal,
): Promise<RouteCoordinationTaskResult> {
  const { value } = await postIntegrationJson(
    integrationEndpoints.coordinationTaskRoute(taskId),
    undefined,
    parseRouteCoordinationTaskResult,
    signal,
  );
  if (value.task_id !== taskId) throw new IntegrationApiError("invalid_response", 200);
  return value;
}
