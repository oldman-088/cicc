"use client";

import { useState } from "react";
import Section from "./Section";
import { useLocale } from "../lib/i18n";
import { formatTime } from "../lib/format";
import type { ComponentInfo, CoordinationAgent, CoordinationMetrics, CoordinationTask, GitHubEventItem, GitHubRepoStatus } from "../lib/types";

const STATE_COLORS: Record<string, string> = {
  NEW: "border-slate-500/50 text-slate-300",
  QUEUED: "border-cyan-500/50 text-cyan-300",
  DELIVERED: "border-blue-500/50 text-blue-300",
  IN_PROGRESS: "border-amber-500/50 text-amber-300",
  WAITING_FOR_APPROVAL: "border-purple-500/50 text-purple-300",
  COMPLETED: "border-emerald-500/50 text-emerald-300",
  FAILED: "border-red-500/60 text-red-300",
  RETRYING: "border-orange-500/50 text-orange-300",
  BLOCKED: "border-red-500/60 text-red-300",
};

export default function CoordinationView({
  tasks,
  events,
  agents,
  gh,
  metrics,
  broker,
}: {
  tasks: CoordinationTask[];
  events: GitHubEventItem[];
  agents: CoordinationAgent[];
  gh: GitHubRepoStatus | null;
  metrics: CoordinationMetrics | null;
  broker: ComponentInfo | null;
}) {
  const { t, locale } = useLocale();
  const [newTask, setNewTask] = useState({ title: "", kind: "ops_review", priority: 5 });
  const [newTaskResult, setNewTaskResult] = useState<string | null>(null);
  const [newTaskErr, setNewTaskErr] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  // M26: real frontend-originated write through the BFF's single approved
  // route POST /api/v1/coordination/tasks (relative URL, no browser token —
  // the server-side BFF injects the write token and idempotency key).
  async function createTask() {
    setCreating(true); setNewTaskErr(null); setNewTaskResult(null);
    try {
      const r = await fetch("/api/v1/coordination/tasks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kind: newTask.kind || "ops_review", priority: Number(newTask.priority) || 5, title: newTask.title || undefined, payload: { source: "reference-dashboard", at: new Date().toISOString() } }),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) setNewTaskErr(`${r.status}: ${j.detail || r.statusText}`);
      else setNewTaskResult(`created ${j.task_id ?? "?"}`);
    } catch (e) {
      setNewTaskErr(String(e));
    } finally { setCreating(false); }
  }
  return (
    <>
      <Section title={t("coordTitle")}>
        {tasks.length === 0 ? (
          <p className="text-sm text-slate-400">{t("noCoordTasks")}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="th">{t("colTaskId")}</th>
                  <th className="th">{t("colKind")}</th>
                  <th className="th">{t("colAgent")}</th>
                  <th className="th">{t("colState")}</th>
                  <th className="th">{t("colRepo")}</th>
                  <th className="th">{t("colPR")}</th>
                  <th className="th">{t("colAttempts")}</th>
                  <th className="th">{t("colProgress")}</th>
                  <th className="th">{t("colUpdated")}</th>
                </tr>
              </thead>
              <tbody>
                {tasks.map((task) => (
                  <tr key={task.task_id} className="border-b border-slate-800/60">
                    <td className="td font-mono text-xs text-slate-300" title={task.routing_explanation ? JSON.stringify(task.routing_explanation) : ""}>{task.task_id}</td>
                    <td className="td text-slate-300">{task.kind}</td>
                    <td className="td text-slate-200">{task.agent ?? "—"}</td>
                    <td className="td">
                      <span className={`rounded-full border px-2 py-0.5 text-xs ${STATE_COLORS[task.state] ?? STATE_COLORS.NEW}`}>
                        {task.state}
                      </span>
                    </td>
                    <td className="td text-slate-400">{task.repo ?? "—"}</td>
                    <td className="td text-slate-300">{task.pr_ref ?? "—"}</td>
                    <td className="td text-slate-300">{task.attempts}</td>
                    <td className="td w-32">
                      <div className="h-2 w-full rounded bg-slate-800" title={`${task.progress ?? 0}%`}>
                        <div
                          className={`h-2 rounded ${task.state === "COMPLETED" ? "bg-emerald-500" : task.state === "FAILED" || task.state === "BLOCKED" ? "bg-red-500" : "bg-sky-500"}`}
                          style={{ width: `${Math.min(100, task.progress ?? 0)}%` }}
                        />
                      </div>
                    </td>
                    <td className="td whitespace-nowrap text-xs text-slate-400">
                      {task.updated_at ? formatTime(task.updated_at, locale) : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="mt-2 text-xs text-slate-500">{t("coordBoundary")}</p>
      </Section>

      <Section title={t("agentsTitle")}>
        <div className="mb-3 flex flex-wrap items-center gap-2 rounded border border-slate-800 bg-slate-900/60 p-2">
          <input className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-sm" placeholder="task title" value={newTask.title} onChange={(e) => setNewTask({ ...newTask, title: e.target.value })} />
          <input className="w-40 rounded border border-slate-700 bg-slate-950 px-2 py-1 text-sm" placeholder="kind (a-z0-9_)" value={newTask.kind} onChange={(e) => setNewTask({ ...newTask, kind: e.target.value })} />
          <input className="w-16 rounded border border-slate-700 bg-slate-950 px-2 py-1 text-sm" type="number" min={1} max={10} value={newTask.priority} onChange={(e) => setNewTask({ ...newTask, priority: Number(e.target.value) })} />
          <button disabled={creating} onClick={createTask} className="rounded border border-emerald-600 px-3 py-1 text-sm text-emerald-300 disabled:opacity-50">
            {creating ? "…" : "Create task via BFF"}
          </button>
          {newTaskResult && <span className="text-xs text-emerald-300">{newTaskResult}</span>}
          {newTaskErr && <span className="text-xs text-red-300">{newTaskErr}</span>}
        </div>
        {agents.length === 0 ? (
          <p className="text-sm text-slate-400">{t("noAgents")}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="th">{t("colAgent")}</th>
                  <th className="th">{t("colState")}</th>
                  <th className="th">{t("specialization")}</th>
                  <th className="th">{t("capabilities")}</th>
                  <th className="th">{t("activeTasks")}</th>
                  <th className="th">{t("done")}</th>
                  <th className="th">{t("failedCol")}</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((a) => (
                  <tr key={a.agent} className="border-b border-slate-800/60">
                    <td className="td font-medium text-slate-100">{a.agent}</td>
                    <td className="td">
                      <span className={`rounded-full border px-2 py-0.5 text-xs ${a.stale ? "border-red-500/60 text-red-300" : a.status === "available" ? "border-emerald-500/50 text-emerald-300" : "border-amber-500/50 text-amber-300"}`}>
                        {a.stale ? "offline(stale)" : a.status}
                      </span>
                      {a.health && (
                        <span className={`ml-1 rounded-full border px-2 py-0.5 text-xs ${a.health === "ACTIVE" ? "border-emerald-500/50 text-emerald-300" : a.health === "STALE" || a.health === "UNAVAILABLE" ? "border-red-500/60 text-red-300" : "border-slate-500/60 text-slate-300"}`} title="heartbeat health (not Arena session availability)">
                          {a.health}
                        </span>
                      )}
                    </td>
                    <td className="td text-slate-300">{a.specialization ?? "—"}</td>
                    <td className="td text-xs text-slate-400">{a.capabilities.join(", ") || "—"}</td>
                    <td className="td text-slate-300">{a.active_tasks}</td>
                    <td className="td text-emerald-300">{a.completed}</td>
                    <td className="td text-red-300">{a.failed}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section title={t("ghLiveTitle")}>
        {!gh ? (
          <p className="text-sm text-slate-400">—</p>
        ) : gh.status !== "ok" ? (
          <p className="text-sm text-slate-400">{t("ghUnavailable")}: {gh.detail ?? gh.status}</p>
        ) : (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            <div>
              <h4 className="mb-1 text-xs uppercase tracking-wider text-slate-400">{t("ghOpenPRs")}</h4>
              <ul className="text-sm text-slate-200">
                {(gh.open_prs ?? []).map((p) => (
                  <li key={p.number}>#{p.number} {p.title} <span className="text-slate-500">({p.head})</span></li>
                ))}
              </ul>
            </div>
            <div>
              <h4 className="mb-1 text-xs uppercase tracking-wider text-slate-400">{t("ghOpenIssues")}</h4>
              <ul className="text-sm text-slate-200">
                {(gh.open_issues ?? []).map((i) => (
                  <li key={i.number}>#{i.number} {i.title}</li>
                ))}
              </ul>
            </div>
            <div>
              <h4 className="mb-1 text-xs uppercase tracking-wider text-slate-400">{t("ghCheckRuns")}</h4>
              <ul className="text-sm text-slate-200">
                {(gh.check_runs ?? []).slice(0, 8).map((c, i) => (
                  <li key={i}>
                    <span className={c.conclusion === "failure" ? "text-red-300" : c.conclusion === "success" ? "text-emerald-300" : "text-slate-300"}>
                      {c.conclusion ?? c.status}
                    </span>{" "}
                    {c.name} <span className="text-slate-500">({c.head_branch})</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
        <p className="mt-2 text-xs text-slate-500">{t("ghLiveNote")}</p>
      </Section>

      {broker && (
        <div className="mb-4">
          <span className={`rounded border px-2 py-1 text-xs ${broker.status === "ok" || broker.status === "up" ? "border-emerald-800 text-emerald-300" : "border-red-800 text-red-300"}`}>
            {t("brokerLabel")}: {broker.status === "ok" || broker.status === "up" ? t("brokerConnected") : t("brokerUnavailable")}
          </span>
        </div>
      )}
      {metrics && (
        <div className="mb-4 flex flex-wrap gap-2 text-xs">
          <span className="rounded border border-slate-700 px-2 py-1 text-slate-300">{t("mTasks")}: {metrics.tasks_total}</span>
          <span className="rounded border border-emerald-800 px-2 py-1 text-emerald-300">{t("mCompleted")}: {metrics.by_state.COMPLETED ?? 0}</span>
          <span className="rounded border border-amber-800 px-2 py-1 text-amber-300">{t("mActive")}: {(metrics.by_state.QUEUED ?? 0) + (metrics.by_state.ASSIGNED ?? 0) + (metrics.by_state.RUNNING ?? 0) + (metrics.by_state.ACKNOWLEDGED ?? 0) + (metrics.by_state.DELIVERING ?? 0) + (metrics.by_state.WAITING_FOR_APPROVAL ?? 0)}</span>
          <span className="rounded border border-red-800 px-2 py-1 text-red-300">{t("mDeadLetter")}: {metrics.dead_lettered}</span>
          <span className="rounded border border-slate-700 px-2 py-1 text-slate-300">{t("mDeliveries")}: {metrics.deliveries_total}</span>
          <span className="rounded border border-slate-700 px-2 py-1 text-slate-300">{t("mApprovalsPending")}: {metrics.approvals_pending}</span>
          <span className="rounded border border-slate-700 px-2 py-1 text-slate-300">{t("mAgentsOnline")}: {metrics.agents_online}/{metrics.agents_registered}</span>
          <span className="rounded border border-slate-700 px-2 py-1 text-slate-300">
            {t("mDelivHuman")}: {metrics.deliveries_by_outcome?.human_assisted ?? metrics.deliveries_by_outcome?.published ?? 0}
            {" · "}{t("mDelivBroker")}: {metrics.deliveries_by_outcome?.confirmed ?? 0}
          </span>
        </div>
      )}

      <Section title={t("coordEventsTitle")}>
        {events.length === 0 ? (
          <p className="text-sm text-slate-400">{t("noCoordEvents")}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="th">{t("colDelivery")}</th>
                  <th className="th">{t("colEvent")}</th>
                  <th className="th">{t("colAction")}</th>
                  <th className="th">{t("colRepo")}</th>
                  <th className="th">{t("colSender")}</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.delivery_id} className="border-b border-slate-800/60">
                    <td className="td font-mono text-xs text-slate-400">{e.delivery_id}</td>
                    <td className="td text-slate-300">{e.event}</td>
                    <td className="td text-slate-400">{e.action ?? "—"}</td>
                    <td className="td text-slate-400">{e.repo ?? "—"}</td>
                    <td className="td text-slate-300">{e.sender ?? "—"}</td>
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
