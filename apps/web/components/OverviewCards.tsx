"use client";

import StatusBadge from "./StatusBadge";
import { useLocale } from "../lib/i18n";

interface Props {
  overall: string;
  activeModules: number;
  totalModules: number;
  servicesUp: number;
  servicesTotal: number;
  activityCount: number;
}

export default function OverviewCards({
  overall,
  activeModules,
  totalModules,
  servicesUp,
  servicesTotal,
  activityCount,
}: Props) {
  const { t } = useLocale();
  const cards = [
    { label: t("overallStatus"), value: <StatusBadge status={overall} /> },
    {
      label: t("activeModules"),
      value: (
        <span className="text-xl font-semibold text-slate-100">
          {activeModules}
          <span className="text-sm text-slate-400"> / {totalModules}</span>
        </span>
      ),
    },
    {
      label: t("serviceAvailability"),
      value: (
        <span className="text-xl font-semibold text-slate-100">
          {servicesUp}
          <span className="text-sm text-slate-400"> / {servicesTotal}</span>
        </span>
      ),
    },
    {
      label: t("recentActivity"),
      value: (
        <span className="text-xl font-semibold text-slate-100">
          {activityCount}
        </span>
      ),
    },
  ];
  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      {cards.map((c) => (
        <div key={c.label} className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
          <div className="text-xs uppercase tracking-wider text-slate-400">
            {c.label}
          </div>
          <div className="mt-2">{c.value}</div>
        </div>
      ))}
    </div>
  );
}
