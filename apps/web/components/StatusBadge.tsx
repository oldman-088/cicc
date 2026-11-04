"use client";

import { useLocale } from "../lib/i18n";

const COLORS: Record<string, string> = {
  ok: "border-emerald-500/40 bg-emerald-500/15 text-emerald-300",
  degraded: "border-amber-500/40 bg-amber-500/15 text-amber-300",
  down: "border-red-500/40 bg-red-500/15 text-red-300",
  not_implemented: "border-slate-500/40 bg-slate-500/15 text-slate-300",
  not_configured: "border-slate-500/40 bg-slate-500/15 text-slate-300",
  unknown: "border-slate-500/40 bg-slate-500/15 text-slate-300",
};

export default function StatusBadge({ status }: { status: string }) {
  const { t } = useLocale();
  const cls = COLORS[status] ?? COLORS.unknown;
  return (
    <span
      className={`inline-block whitespace-nowrap rounded-full border px-2.5 py-0.5 text-xs font-medium ${cls}`}
    >
      {t(`status_${status}`)}
    </span>
  );
}
