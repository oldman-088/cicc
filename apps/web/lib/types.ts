export type ComponentKind = "service" | "module";

export interface ComponentInfo {
  key: string;
  kind: ComponentKind | string;
  name: string;
  status: string;
  detail: string;
  last_check_at: string | null;
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
