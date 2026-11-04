"use client";

import { useCallback, useEffect, useState } from "react";

import ActivityTimeline from "../components/ActivityTimeline";
import ActivityView from "../components/ActivityView";
import AlertsBanner from "../components/AlertsBanner";
import AlertsView from "../components/AlertsView";
import ComponentsTable from "../components/ComponentsTable";
import DependencyGraph from "../components/DependencyGraph";
import LanguageSwitcher from "../components/LanguageSwitcher";
import MetricsGrid from "../components/MetricsGrid";
import NavTabs, { type Tab } from "../components/NavTabs";
import OverviewCards from "../components/OverviewCards";
import Section from "../components/Section";
import TrendChart from "../components/TrendChart";
import WorkersView from "../components/WorkersView";
import { deriveAlerts } from "../lib/alerts.mjs";
import { formatTime } from "../lib/format";
import { useLocale } from "../lib/i18n";
import { overallStatus } from "../lib/status.mjs";
import type {
  ActivityEvent,
  Alert,
  ComponentInfo,
  DependencyGraph as Deps,
  HealthResponse,
  Overview,
  Snapshot,
  SystemMetrics,
  TaskStats,
  WorkersResponse,
} from "../lib/types";

const REFRESH_MS = 15000;

type View =
  | "overview"
  | "components"
  | "metrics"
  | "activity"
  | "dependencies"
  | "alerts"
  | "workers";

export default function DashboardPage() {
  const { t, locale } = useLocale();
  const [view, setView] = useState<View>("overview");
  const [overview, setOverview] = useState<Overview | null>(null);
  const [deps, setDeps] = useState<Deps | null>(null);
  const [history, setHistory] = useState<Snapshot[]>([]);
  const [activity, setActivity] = useState<ActivityEvent[]>([]);
  const [taskStats, setTaskStats] = useState<TaskStats | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [workers, setWorkers] = useState<WorkersResponse | null>(null);
  const [system, setSystem] = useState<SystemMetrics | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const [h, o, d, hi, a, ts, al, w, sy] = await Promise.all([
        fetch("/api/health", { cache: "no-store" }),
        fetch("/api/v1/ops/overview", { cache: "no-store" }),
        fetch("/api/v1/ops/dependencies", { cache: "no-store" }),
        fetch("/api/v1/ops/metrics/history?hours=24", { cache: "no-store" }),
        fetch("/api/v1/ops/activity?limit=100", { cache: "no-store" }),
        fetch("/api/v1/ops/tasks/stats?hours=24", { cache: "no-store" }),
        fetch("/api/v1/ops/alerts?state=all&limit=100", { cache: "no-store" }),
        fetch("/api/v1/ops/workers", { cache: "no-store" }),
        fetch("/api/v1/ops/system", { cache: "no-store" }),
      ]);
      setHealth(h.ok ? await h.json() : null);
      if (!o.ok) throw new Error(`overview_http_${o.status}`);
      setOverview(await o.json());
      setDeps(d.ok ? await d.json() : null);
      setHistory(hi.ok ? (await hi.json()).snapshots : []);
      setActivity(a.ok ? (await a.json()).events : []);
      setTaskStats(ts.ok ? await ts.json() : null);
      setAlerts(al.ok ? (await al.json()).alerts : []);
      setWorkers(w.ok ? await w.json() : null);
      setSystem(sy.ok ? await sy.json() : null);
      setLastRefresh(new Date().toISOString());
    } catch {
      setHealth(null);
      setOverview(null);
      setError("network");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const id = window.setInterval(load, REFRESH_MS);
    return () => window.clearInterval(id);
  }, [load]);

  const nameOf = useCallback(
    (key: string) => {
      const k = `name_${key}`;
      const tr = t(k);
      return tr === k ? key : tr;
    },
    [t]
  );

  // Web UI is "ok" whenever this page can reach its own health route.
  const webComponent: ComponentInfo = {
    key: "web",
    kind: "service",
    name: t("webService"),
    status: health?.web.status ?? "unknown",
    detail: health ? `HTTP 200 · ${health.web.response_ms} ms` : "—",
    last_check_at: lastRefresh,
  };
  const services: ComponentInfo[] = [webComponent, ...(overview?.services ?? [])];
  const modules = overview?.modules ?? [];
  const components = [...services, ...modules];
  // Prefer server-evaluated alerts; fall back to client-side derivation.
  const bannerAlerts =
    alerts.length > 0
      ? alerts
          .filter((a) => a.status !== "resolved")
          .map((a) => ({ key: a.component_key ?? a.rule, status: a.severity === "critical" ? "down" : "degraded", name: a.component_key ?? a.rule, detail: a.message }))
      : deriveAlerts(components);
  const overall = overview
    ? overview.overall_status
    : overallStatus(services.map((s) => s.status));
  const activeModules = modules.filter(
    (m) => m.status === "ok" || m.status === "degraded"
  ).length;
  const servicesUp = services.filter((s) => s.status === "ok").length;
  const broker = services.find((s) => s.key === "rabbitmq") ?? null;

  const tabs: Tab[] = [
    { id: "overview", label: t("navOverview") },
    { id: "components", label: t("navComponents") },
    { id: "metrics", label: t("navMetrics") },
    { id: "activity", label: t("navActivity") },
    { id: "dependencies", label: t("navDependencies") },
    { id: "alerts", label: `${t("navAlerts")}${alerts.filter((a) => a.status === "active").length ? ` (${alerts.filter((a) => a.status === "active").length})` : ""}` },
    { id: "workers", label: t("navWorkers") },
  ];

  return (
    <main className="mx-auto max-w-6xl px-4 py-8">
      <header className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-cyan-300">{t("appTitle")}</h1>
          <p className="mt-1 text-sm text-slate-400">{t("appSubtitle")}</p>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-xs text-slate-500">
            {t("autoRefreshNote")}
            {lastRefresh
              ? ` · ${t("lastRefresh")}: ${formatTime(lastRefresh, locale)}`
              : ""}
          </span>
          <LanguageSwitcher />
        </div>
      </header>

      <NavTabs tabs={tabs} active={view} onChange={(id) => setView(id as View)} />

      {loading && !overview ? (
        <div className="card p-8 text-center text-slate-400" aria-live="polite">
          {t("loading")}
        </div>
      ) : error && !overview ? (
        <div className="card border-red-900/60 p-8 text-center">
          <p className="mb-2 font-medium text-red-300">{t("loadError")}</p>
          <p className="mb-4 text-sm text-slate-400">{t("backendUnavailable")}</p>
          <button type="button" className="btn" onClick={load}>
            {t("retry")}
          </button>
        </div>
      ) : (
        <div className="space-y-6" aria-live="polite">
          <AlertsBanner alerts={bannerAlerts} nameOf={nameOf} />

          {view === "overview" && overview && (
            <>
              <Section title={t("systemOverview")}>
                <OverviewCards
                  overall={overall}
                  activeModules={activeModules}
                  totalModules={modules.length}
                  servicesUp={servicesUp}
                  servicesTotal={services.length}
                  activityCount={overview.activity.length}
                />
              </Section>
              {system && (
                <Section title={t("capacityTitle")}>
                  <div className="grid grid-cols-2 gap-4 md:grid-cols-4 lg:grid-cols-7">
                    {[
                      { label: t("rssMb"), value: system.process.rss_mb },
                      { label: t("cpuUser"), value: system.process.cpu_user_s },
                      { label: t("cpuSys"), value: system.process.cpu_system_s },
                      { label: t("threads"), value: system.process.threads ?? "—" },
                      { label: t("pid"), value: system.process.pid },
                      { label: t("uptime"), value: system.process.uptime_s ?? "—" },
                      { label: t("pythonVer"), value: system.python },
                    ].map((it) => (
                      <div key={it.label} className="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
                        <div className="text-xs uppercase tracking-wider text-slate-400">{it.label}</div>
                        <div className="mt-1 truncate text-base font-semibold text-slate-100">
                          {String(it.value)}
                        </div>
                      </div>
                    ))}
                  </div>
                </Section>
              )}
              <ActivityTimeline events={overview.activity.slice(0, 8)} />
            </>
          )}

          {view === "components" && (
            <ComponentsTable title={t("moduleHealth")} rows={components} nameOf={nameOf} />
          )}

          {view === "metrics" && overview && (
            <>
              <Section title={t("operationalMetrics")}>
                <MetricsGrid metrics={overview.metrics} />
              </Section>
              <Section title={t("trendsTitle")}>
                {history.length === 0 ? (
                  <p className="text-sm text-slate-400">{t("noHistory")}</p>
                ) : (
                  <div className="grid gap-4 md:grid-cols-3">
                    <TrendChart snapshots={history} metricKey="entities" label={t("trendEntities")} color="#22d3ee" />
                    <TrendChart snapshots={history} metricKey="vulnerabilities" label={t("trendVulnerabilities")} color="#f59e0b" />
                    <TrendChart snapshots={history} metricKey="campaigns" label={t("trendCampaigns")} color="#a78bfa" />
                  </div>
                )}
              </Section>
            </>
          )}

          {view === "activity" && <ActivityView events={activity} />}

          {view === "dependencies" && <DependencyGraph deps={deps} nameOf={nameOf} />}

          {view === "alerts" && <AlertsView alerts={alerts} onAction={load} />}

          {view === "workers" && (
            <WorkersView workers={workers} broker={broker} taskStats={taskStats} />
          )}

          <p className="text-center text-xs text-slate-500">{t("dataSourceNote")}</p>
        </div>
      )}
    </main>
  );
}
