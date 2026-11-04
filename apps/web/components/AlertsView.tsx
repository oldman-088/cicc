"use client";

import { useState } from "react";

import Section from "./Section";
import { useLocale } from "../lib/i18n";
import { formatTime } from "../lib/format";
import type { Alert } from "../lib/types";

const SEV_COLORS: Record<string, string> = {
  critical: "border-red-500/40 bg-red-500/15 text-red-300",
  warning: "border-amber-500/40 bg-amber-500/15 text-amber-300",
  info: "border-cyan-500/40 bg-cyan-500/10 text-cyan-300",
};

const STATE_COLORS: Record<string, string> = {
  active: "border-red-500/40 bg-red-500/15 text-red-300",
  acknowledged: "border-amber-500/40 bg-amber-500/15 text-amber-300",
  resolved: "border-emerald-500/40 bg-emerald-500/15 text-emerald-300",
};

const STATES = ["all", "active", "acknowledged", "resolved"];

export default function AlertsView({
  alerts,
  onAction,
}: {
  alerts: Alert[];
  onAction: () => void;
}) {
  const { t, locale } = useLocale();
  const [state, setState] = useState("all");
  const [busy, setBusy] = useState<number | null>(null);

  const shown = state === "all" ? alerts : alerts.filter((a) => a.status === state);

  const act = async (id: number, action: "ack" | "resolve") => {
    setBusy(id);
    try {
      await fetch(`/api/v1/ops/alerts/${id}/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: action === "ack" ? JSON.stringify({ acked_by: "dashboard" }) : "{}",
      });
      onAction();
    } finally {
      setBusy(null);
    }
  };

  return (
    <Section title={t("alertsViewTitle")}>
      <div className="mb-3 flex flex-wrap gap-1" role="group" aria-label={t("status")}>
        {STATES.map((s) => (
          <button
            key={s}
            type="button"
            aria-pressed={state === s}
            onClick={() => setState(s)}
            className={`rounded-md border px-2.5 py-1 text-xs font-medium transition focus:outline-none focus:ring-2 focus:ring-cyan-400 ${
              state === s
                ? "border-cyan-500/60 bg-cyan-500/15 text-cyan-200"
                : "border-slate-700 bg-slate-900/60 text-slate-300 hover:border-slate-500"
            }`}
          >
            {t(`state_${s}`)}
          </button>
        ))}
      </div>
      {shown.length === 0 ? (
        <p className="text-sm text-slate-400">{t("noAlertsList")}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-slate-800">
                <th className="th">{t("status")}</th>
                <th className="th">{t("severity")}</th>
                <th className="th">{t("rule")}</th>
                <th className="th">{t("componentCol")}</th>
                <th className="th">{t("messageCol")}</th>
                <th className="th">{t("occurrences")}</th>
                <th className="th">{t("lastSeen")}</th>
                <th className="th">{t("ackedBy")}</th>
                <th className="th"> </th>
              </tr>
            </thead>
            <tbody>
              {shown.map((a) => (
                <tr key={a.id} className="border-b border-slate-800/60">
                  <td className="td">
                    <span className={`rounded-full border px-2 py-0.5 text-xs ${STATE_COLORS[a.status] ?? STATE_COLORS.active}`}>
                      {t(`state_${a.status}`)}
                    </span>
                  </td>
                  <td className="td">
                    <span className={`rounded-full border px-2 py-0.5 text-xs ${SEV_COLORS[a.severity] ?? SEV_COLORS.info}`}>
                      {t(`severity_${a.severity}`)}
                    </span>
                    {a.escalated && (
                      <span className="ms-1 rounded-full border border-red-500/60 px-2 py-0.5 text-xs text-red-300">
                        {t("escalated")}
                      </span>
                    )}
                    {a.flapping && (
                      <span className="ms-1 rounded-full border border-orange-500/60 px-2 py-0.5 text-xs text-orange-300">
                        {t("flapping")}
                      </span>
                    )}
                  </td>
                  <td className="td font-mono text-xs text-slate-300">{a.rule}</td>
                  <td className="td text-slate-300">{a.component_key ?? "—"}</td>
                  <td className="td max-w-md text-slate-200">{a.message}</td>
                  <td className="td text-slate-400">×{a.occurrences}</td>
                  <td className="td whitespace-nowrap text-xs text-slate-400">
                    {formatTime(a.last_seen, locale)}
                  </td>
                  <td className="td text-xs text-slate-400">{a.acked_by ?? "—"}</td>
                  <td className="td">
                    {a.status !== "resolved" && (
                      <div className="flex gap-1">
                        {a.status === "active" && (
                          <button
                            type="button"
                            className="rounded border border-amber-500/50 px-2 py-0.5 text-xs text-amber-300 hover:bg-amber-500/10 disabled:opacity-50"
                            disabled={busy === a.id}
                            onClick={() => act(a.id, "ack")}
                          >
                            {t("ack")}
                          </button>
                        )}
                        <button
                          type="button"
                          className="rounded border border-emerald-500/50 px-2 py-0.5 text-xs text-emerald-300 hover:bg-emerald-500/10 disabled:opacity-50"
                          disabled={busy === a.id}
                          onClick={() => act(a.id, "resolve")}
                        >
                          {t("resolve")}
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Section>
  );
}
