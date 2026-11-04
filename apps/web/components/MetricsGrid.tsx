"use client";

import { useLocale } from "../lib/i18n";
import { formatTime } from "../lib/format";
import type { Metrics } from "../lib/types";

export default function MetricsGrid({ metrics }: { metrics: Metrics }) {
  const { t, locale } = useLocale();
  const items: { label: string; value: string }[] = [
    { label: t("entities"), value: String(metrics.entities) },
    { label: t("vulnerabilities"), value: String(metrics.vulnerabilities) },
    { label: t("campaigns"), value: String(metrics.campaigns) },
    { label: t("recentUpdates24h"), value: String(metrics.recent_updates_24h) },
    {
      label: t("lastSuccessfulSync"),
      value: metrics.last_successful_sync
        ? formatTime(metrics.last_successful_sync, locale)
        : t("never"),
    },
  ];
  return (
    <div className="grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-5">
      {items.map((it) => (
        <div
          key={it.label}
          className="rounded-lg border border-slate-800 bg-slate-900/70 p-4"
        >
          <div className="text-xs uppercase tracking-wider text-slate-400">
            {it.label}
          </div>
          <div className="mt-2 truncate text-lg font-semibold text-slate-100">
            {it.value}
          </div>
        </div>
      ))}
    </div>
  );
}
