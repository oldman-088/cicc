"use client";

import Section from "./Section";
import StatusBadge from "./StatusBadge";
import { useLocale } from "../lib/i18n";
import { formatTime } from "../lib/format";
import { formatAge } from "../lib/age.mjs";
import type { ComponentInfo, TaskStats, WorkersResponse } from "../lib/types";

export default function WorkersView({
  workers,
  broker,
  taskStats,
}: {
  workers: WorkersResponse | null;
  broker: ComponentInfo | null;
  taskStats: TaskStats | null;
}) {
  const { t, locale } = useLocale();
  const bc = (broker?.check ?? {}) as Record<string, unknown>;
  const brokerConfigured = broker && broker.status !== "not_configured";

  return (
    <>
      <Section title={t("workersTitle")}>
        {!workers || workers.workers.length === 0 ? (
          <p className="text-sm text-slate-400">
            {t("noEvents")} — POST /api/v1/ops/workers/heartbeat
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="th">{t("workerCol")}</th>
                  <th className="th">{t("lastSeen")}</th>
                  <th className="th">{t("ageCol")}</th>
                  <th className="th">{t("stalledCol")}</th>
                  <th className="th">{t("tasks24h")}</th>
                  <th className="th">{t("failed24h")}</th>
                </tr>
              </thead>
              <tbody>
                {workers.workers.map((w) => (
                  <tr key={w.worker} className="border-b border-slate-800/60">
                    <td className="td font-medium text-slate-100">{w.worker}</td>
                    <td className="td whitespace-nowrap text-slate-400">
                      {formatTime(w.last_seen, locale)}
                    </td>
                    <td className="td text-slate-400">
                      {w.age_s !== null ? formatAge(w.age_s) : "—"}
                    </td>
                    <td className="td">
                      <StatusBadge status={w.stalled ? "down" : "ok"} />
                      <span className="ms-2 text-xs text-slate-400">
                        {w.stalled ? t("yes") : t("no")}
                      </span>
                    </td>
                    <td className="td text-slate-300">{w.tasks_24h}</td>
                    <td className="td text-slate-300">{w.failed_24h}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {workers && (
          <p className="mt-2 text-xs text-slate-500">
            stall threshold: {workers.stall_threshold_s}s
          </p>
        )}
      </Section>

      <Section title={t("brokerTitle")}>
        {!brokerConfigured ? (
          <p className="text-sm text-slate-400">{t("noBroker")}</p>
        ) : (
          <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
            {[
              { label: t("messagesReady"), value: bc.messages_ready },
              { label: t("messagesUnack"), value: bc.messages_unacknowledged },
              { label: t("queuesCount"), value: bc.queues },
              { label: t("consumersCount"), value: bc.consumers },
              { label: t("dlqCount"), value: bc.dead_letter_queues },
            ].map((it) => (
              <div key={it.label} className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
                <div className="text-xs uppercase tracking-wider text-slate-400">{it.label}</div>
                <div className="mt-2 text-lg font-semibold text-slate-100">
                  {it.value === null || it.value === undefined ? "—" : String(it.value)}
                </div>
              </div>
            ))}
          </div>
        )}
      </Section>

      <Section title={t("tasksTitle")}>
        {taskStats ? (
          <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
            {[
              { label: t("completed"), value: taskStats.completed },
              { label: t("failed"), value: taskStats.failed },
              { label: t("pending"), value: taskStats.pending },
              { label: t("avgDuration"), value: taskStats.avg_duration_ms ?? "—" },
              {
                label: t("oldestPending"),
                value: taskStats.oldest_pending_started
                  ? formatTime(taskStats.oldest_pending_started, locale)
                  : t("never"),
              },
            ].map((it) => (
              <div key={it.label} className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
                <div className="text-xs uppercase tracking-wider text-slate-400">{it.label}</div>
                <div className="mt-2 truncate text-lg font-semibold text-slate-100">
                  {String(it.value)}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-slate-400">—</p>
        )}
      </Section>
    </>
  );
}
