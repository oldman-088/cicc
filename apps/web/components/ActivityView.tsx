"use client";

import { useMemo, useState } from "react";

import Section from "./Section";
import { useLocale } from "../lib/i18n";
import { formatTime } from "../lib/format";
import type { ActivityEvent } from "../lib/types";

const LEVELS = ["all", "info", "warning", "error"];

const LEVEL_COLORS: Record<string, string> = {
  info: "border-cyan-500/40 bg-cyan-500/10 text-cyan-300",
  warning: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  error: "border-red-500/40 bg-red-500/10 text-red-300",
};

export default function ActivityView({ events }: { events: ActivityEvent[] }) {
  const { t, locale } = useLocale();
  const [level, setLevel] = useState("all");
  const [q, setQ] = useState("");

  const filtered = useMemo(
    () =>
      events.filter(
        (e) =>
          (level === "all" || e.level === level) &&
          (!q ||
            `${e.message} ${e.source}`.toLowerCase().includes(q.toLowerCase()))
      ),
    [events, level, q]
  );

  return (
    <Section title={t("activityTimeline")}>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="flex gap-1" role="group" aria-label={t("level")}>
          {LEVELS.map((l) => (
            <button
              key={l}
              type="button"
              aria-pressed={level === l}
              onClick={() => setLevel(l)}
              className={`rounded-md border px-2.5 py-1 text-xs font-medium transition focus:outline-none focus:ring-2 focus:ring-cyan-400 ${
                level === l
                  ? "border-cyan-500/60 bg-cyan-500/15 text-cyan-200"
                  : "border-slate-700 bg-slate-900/60 text-slate-300 hover:border-slate-500"
              }`}
            >
              {l === "all" ? t("filterAll") : t(`level_${l}`)}
            </button>
          ))}
        </div>
        <input
          type="search"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder={t("searchActivity")}
          aria-label={t("searchActivity")}
          className="rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-400"
        />
        <span className="text-xs text-slate-500">
          {t("resultsShown")
            .replace("{n}", String(filtered.length))
            .replace("{total}", String(events.length))}
        </span>
      </div>
      {filtered.length === 0 ? (
        <p className="text-sm text-slate-400">{t("noEvents")}</p>
      ) : (
        <ul className="space-y-2">
          {filtered.map((e) => (
            <li
              key={e.id}
              className="flex flex-wrap items-center gap-3 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2"
            >
              <span
                className={`rounded-full border px-2 py-0.5 text-xs font-medium ${
                  LEVEL_COLORS[e.level] ?? LEVEL_COLORS.info
                }`}
              >
                {t(`level_${e.level}`)}
              </span>
              <span className="whitespace-nowrap text-xs text-slate-400">
                {formatTime(e.ts, locale)}
              </span>
              <span className="text-xs font-medium text-slate-300">
                {e.source}
              </span>
              <span className="text-sm text-slate-200">{e.message}</span>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}
