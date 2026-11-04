"use client";

import StatusBadge from "./StatusBadge";
import { useLocale } from "../lib/i18n";
import type { BannerAlert } from "../lib/types";

export default function AlertsBanner({
  alerts,
  nameOf,
}: {
  alerts: BannerAlert[];
  nameOf: (key: string) => string;
}) {
  const { t } = useLocale();
  if (alerts.length === 0) {
    return (
      <div
        className="card border-emerald-900/50 p-4 text-sm text-emerald-300"
        role="status"
      >
        {t("noAlerts")}
      </div>
    );
  }
  return (
    <div className="card border-amber-900/60 p-4" role="alert">
      <h2 className="mb-2 text-sm font-semibold uppercase tracking-wider text-amber-300">
        {t("alertsTitle")} ({alerts.length})
      </h2>
      <ul className="space-y-1.5">
        {alerts.map((a) => (
          <li key={a.key} className="flex flex-wrap items-center gap-2 text-sm">
            <StatusBadge status={a.status} />
            <span className="font-medium text-slate-100">{nameOf(a.key)}</span>
            {a.detail ? (
              <span className="text-slate-400">{a.detail}</span>
            ) : null}
          </li>
        ))}
      </ul>
    </div>
  );
}
