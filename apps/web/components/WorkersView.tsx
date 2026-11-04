"use client";

import Section from "./Section";
import StatusBadge from "./StatusBadge";
import { useLocale } from "../lib/i18n";
import { formatTime } from "../lib/format";
import { formatAge } from "../lib/age.mjs";
import type {
  ComponentInfo,
  TaskFailuresResponse,
  TaskRunItem,
  TaskStats,
  WorkersResponse,
} from "../lib/types";

export default function WorkersView({
  workers,
  broker,
  taskStats,
  tasks,
  taskFailures,
}: {
  workers: WorkersResponse | null;
  broker: ComponentInfo | null;
  taskStats: TaskStats | null;
  tasks: TaskRunItem[];
  taskFailures: TaskFailuresResponse | null;
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

      <Section title={t("failuresTitle")}>
        {!taskFailures || taskFailures.groups.length === 0 ? (
          <p className="text-sm text-slate-400">{t("noFailures")}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="th">{t("workerCol")}</th>
                  <th className="th">{t("colError")}</th>
                  <th className="th">{t("colCount")}</th>
                  <th className="th">{t("colLastSeen")}</th>
                </tr>
              </thead>
              <tbody>
                {taskFailures.groups.map((g, i) => (
                  <tr key={i} className="border-b border-slate-800/60">
                    <td className="td font-medium text-slate-100">{g.worker}</td>
                    <td className="td max-w-md truncate text-red-300" title={g.error}>
                      {g.error}
                    </td>
                    <td className="td text-slate-300">{g.count}</td>
                    <td className="td whitespace-nowrap text-slate-400">
                      {g.last_seen ? formatTime(g.last_seen, locale) : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section title={t("recentTasks")}>
        {tasks.length === 0 ? (
          <p className="text-sm text-slate-400">{t("noTasks")}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="th">{t("colId")}</th>
                  <th className="th">{t("workerCol")}</th>
                  <th className="th">{t("colQueue")}</th>
                  <th className="th">{t("colStatus")}</th>
                  <th className="th">{t("colDuration")}</th>
                  <th className="th">{t("colError")}</th>
                  <th className="th">{t("colCreated")}</th>
                </tr>
              </thead>
              <tbody>
                {tasks.map((task) => (
                  <tr key={task.id} className="border-b border-slate-800/60">
                    <td className="td text-slate-400">{task.id}</td>
                    <td className="td font-medium text-slate-100">{task.worker}</td>
                    <td className="td text-slate-300">{task.queue}</td>
                    <td className="td">
                      <StatusBadge
                        status={
                          task.status === "success"
                            ? "ok"
                            : task.status === "failed"
                              ? "down"
                              : "degraded"
                        }
                      />
                      <span className="ms-2 text-xs text-slate-400">{task.status}</span>
                    </td>
                    <td className="td text-slate-300">
                      {task.duration_ms !== null ? task.duration_ms : "—"}
                    </td>
                    <td className="td max-w-xs truncate text-red-300" title={task.error ?? ""}>
                      {task.error ?? "—"}
                    </td>
                    <td className="td whitespace-nowrap text-slate-400">
                      {task.created_at ? formatTime(task.created_at, locale) : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </>
  );
}
