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
