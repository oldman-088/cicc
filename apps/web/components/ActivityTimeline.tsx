"use client";

import Section from "./Section";
import { useLocale } from "../lib/i18n";
import { formatTime } from "../lib/format";
import type { ActivityEvent } from "../lib/types";

const LEVEL_COLORS: Record<string, string> = {
  info: "border-cyan-500/40 bg-cyan-500/10 text-cyan-300",
  warning: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  error: "border-red-500/40 bg-red-500/10 text-red-300",
};

export default function ActivityTimeline({
  events,
}: {
  events: ActivityEvent[];
}) {
  const { t, locale } = useLocale();
  return (
    <Section title={t("activityTimeline")}>
      {events.length === 0 ? (
        <p className="text-sm text-slate-400">{t("noEvents")}</p>
      ) : (
        <ul className="space-y-2">
          {events.map((e) => (
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
