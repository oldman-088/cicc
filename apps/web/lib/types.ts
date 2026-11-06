export type ComponentKind = "service" | "module";

export interface ComponentInfo {
  key: string;
  kind: ComponentKind | string;
  name: string;
  status: string;
  detail: string;
  last_check_at: string | null;
  check?: Record<string, unknown> | null;
}

export interface Metrics {
  entities: number;
  vulnerabilities: number;
  campaigns: number;
  recent_updates_24h: number;
  last_successful_sync: string | null;
}

export interface ActivityEvent {
  id: number;
  ts: string | null;
  level: string;
  source: string;
  message: string;
}

export interface Overview {
  generated_at: string;
  overall_status: string;
  services: ComponentInfo[];
  modules: ComponentInfo[];
  metrics: Metrics;
  activity: ActivityEvent[];
  data_source: string;
}

export interface HealthResponse {
  web: { status: string; response_ms: number };
  backend: { status: string; detail: unknown };
}

export interface Snapshot {
  ts: string | null;
  entities: number;
  vulnerabilities: number;
  campaigns: number;
  recent_updates_24h: number;
}

export interface HistoryResponse {
  window_hours: number;
  snapshots: Snapshot[];
}

export interface DependencyEdge {
  from: string;
  to: string;
  label: string;
}

export interface DependencyGraph {
  nodes: ComponentInfo[];
  edges: DependencyEdge[];
}

export interface TaskStats {
  window_hours: number;
  completed: number;
  failed: number;
  pending: number;
  avg_duration_ms: number | null;
  oldest_pending_started: string | null;
}

export interface Alert {
  key: string;
  status: string;
  name: string;
  detail: string;
}

export interface Alert {
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
}

export interface WorkerInfo {
  worker: string;
  last_seen: string | null;
  age_s: number | null;
  stalled: boolean;
  tasks_24h: number;
  failed_24h: number;
  details: string;
}

export interface TaskRunItem {
  id: number;
  worker: string;
  queue: string;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  error: string | null;
  created_at: string | null;
}

export interface TaskListResponse {
  tasks: TaskRunItem[];
}

export interface TaskFailureGroup {
  worker: string;
  error: string;
  count: number;
  last_seen: string | null;
}

export interface TaskFailuresResponse {
  window_hours: number;
  groups: TaskFailureGroup[];
}

export interface WorkersResponse {
  stall_threshold_s: number;
  workers: WorkerInfo[];
}

export interface SystemMetrics {
  process: {
    pid: number;
    rss_mb: number;
    cpu_user_s: number;
    cpu_system_s: number;
    threads: number | null;
    uptime_s: number | null;
  };
  python: string;
  database: string;
}

export interface BannerAlert {
  key: string;
  status: string;
  name: string;
  detail: string;
}

export interface CoordinationTask {
  id: number;
  task_id: string;
  event_id: string | null;
  source: string;
  kind: string;
  agent: string | null;
  state: string;
  priority: number;
  repo: string | null;
  pr_ref: string | null;
  branch_ref: string | null;
  title: string | null;
  attempts: number;
  progress?: number;
  next_retry_at?: string | null;
  result: string | null;
  routing_explanation?: unknown;
  created_at: string | null;
  updated_at: string | null;
}

export interface CoordinationTasksResponse {
  tasks: CoordinationTask[];
}

export interface GitHubEventItem {
  delivery_id: string;
  event: string;
  action: string | null;
  repo: string | null;
  sender: string | null;
  task_id: string | null; // M13: link to the registry task created from this event
  received_at: string | null;
}

export interface CoordinationEventsResponse {
  events: GitHubEventItem[];
}

export interface CoordinationAgent {
  agent: string;
  specialization: string | null;
  capabilities: string[];
  status: string;
  stale: boolean;
  health?: "ACTIVE" | "STALE" | "UNAVAILABLE" | "UNKNOWN"; // M24 health classification (docs/AGENT_HEALTH_MODEL.md)
  version: string | null;
  last_heartbeat: string | null;
  active_tasks: number;
  completed: number;
  failed: number;
  retries: number;
}

export interface CoordinationAgentsResponse {
  agents: CoordinationAgent[];
}

export interface GitHubRepoStatus {
  status: string;
  detail?: string;
  repo?: string;
  open_prs?: { number: number; title: string; head: string; user: string; url: string }[];
  open_issues?: { number: number; title: string; user: string; labels: string[] }[];
  check_runs?: { name: string; status: string; conclusion: string | null; head_branch: string; html_url: string }[];
}

export interface CoordinationHealthComponent {
  key: string;
  status: string;
  detail: string;
  reasons: string[];
}
export interface CoordinationHealth {
  overall: string;
  components: CoordinationHealthComponent[];
  reasons: string[];
  last_operations?: Record<string, string | null>;
  at: string;
}
export interface CoordinationMetrics {
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
}

export type DomainGatewayStatus =
  | "NOT_MOUNTED"
  | "MOUNTED"
  | "AVAILABLE"
  | "EXECUTION_VERIFIED"
  | "DEGRADED"
  | "FAILED"
  | "UNKNOWN";

export interface DomainGatewayRow {
  kind: string;
  mounted: boolean;
  status: DomainGatewayStatus;
  invokes: number | null;
  successes: number | null;
  probeInFlight: boolean | null;
  probeLeaseExpiresInS: number | null;
  probeLeaseExpirations: number | null;
  lastInvokeAt: string | null;
}

export interface DomainGatewaySnapshot {
  rows: DomainGatewayRow[];
}
