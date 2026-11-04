"use client";

import { useCallback, useEffect, useState } from "react";

import ActivityTimeline from "../components/ActivityTimeline";
import ComponentsTable from "../components/ComponentsTable";
import LanguageSwitcher from "../components/LanguageSwitcher";
import MetricsGrid from "../components/MetricsGrid";
import OverviewCards from "../components/OverviewCards";
import Section from "../components/Section";
import { useLocale } from "../lib/i18n";
import { overallStatus } from "../lib/status.mjs";
import { formatTime } from "../lib/format";
import type { ComponentInfo, HealthResponse, Overview } from "../lib/types";

const REFRESH_MS = 15000;

export default function DashboardPage() {
  const { t, locale } = useLocale();
  const [overview, setOverview] = useState<Overview | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const [hRes, oRes] = await Promise.all([
        fetch("/api/health", { cache: "no-store" }),
        fetch("/api/v1/ops/overview", { cache: "no-store" }),
      ]);
      setHealth(hRes.ok ? await hRes.json() : null);
      if (oRes.ok) {
        setOverview(await oRes.json());
        setLastRefresh(new Date().toISOString());
      } else {
        setOverview(null);
        setError(`overview_http_${oRes.status}`);
      }
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

  // Web UI is "ok" whenever this page can reach its own health route.
  const webComponent: ComponentInfo = {
    key: "web",
    kind: "service",
    name: t("webService"),
    status: health?.web.status ?? "unknown",
    detail: health ? `HTTP 200 · ${health.web.response_ms} ms` : "—",
    last_check_at: lastRefresh,
  };
  const services: ComponentInfo[] = [
    webComponent,
    ...(overview?.services ?? []),
  ];
  const modules = overview?.modules ?? [];
  const overall = overview
    ? overview.overall_status
    : overallStatus(services.map((s) => s.status));
  const activeModules = modules.filter(
    (m) => m.status === "ok" || m.status === "degraded"
  ).length;
  const servicesUp = services.filter((s) => s.status === "ok").length;

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

      {loading && !overview ? (
        <div className="card p-8 text-center text-slate-400">
          {t("loading")}
        </div>
      ) : error && !overview ? (
        <div className="card border-red-900/60 p-8 text-center">
          <p className="mb-2 font-medium text-red-300">{t("loadError")}</p>
          <p className="mb-4 text-sm text-slate-400">
            {t("backendUnavailable")}
          </p>
          <button type="button" className="btn" onClick={load}>
            {t("retry")}
          </button>
        </div>
      ) : (
        overview && (
          <div className="space-y-6">
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

            <ComponentsTable
              title={t("moduleHealth")}
              rows={[...services, ...modules]}
            />

            <Section title={t("operationalMetrics")}>
              <MetricsGrid metrics={overview.metrics} />
            </Section>

            <ActivityTimeline events={overview.activity} />

            <p className="text-center text-xs text-slate-500">
              {t("dataSourceNote")}
            </p>
          </div>
        )
      )}
    </main>
  );
}
