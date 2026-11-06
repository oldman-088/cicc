"use client";

import { toSeries, maxValue } from "../lib/trends.mjs";
import type { Snapshot } from "../lib/types";

export default function TrendChart({
  snapshots,
  metricKey,
  label,
  color = "#22d3ee",
}: {
  snapshots: Snapshot[];
  metricKey: "entities" | "vulnerabilities" | "campaigns";
  label: string;
  color?: string;
}) {
  const series = toSeries(snapshots, metricKey);
  const max = Math.max(1, maxValue(series));
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
      <div className="mb-2 text-xs uppercase tracking-wider text-slate-400">
        {label}
      </div>
      {series.length === 0 ? (
        <p className="text-sm text-slate-500">—</p>
      ) : (
        <svg
          viewBox="0 0 300 60"
          className="h-16 w-full"
          role="img"
          aria-label={`${label}: ${series.length} points, max ${max}`}
        >
          {series.map((p, i) => {
            const x =
              series.length === 1 ? 5 : 5 + (i / (series.length - 1)) * 290;
            const h = (p.value / max) * 50;
            const w = Math.max(2, 290 / series.length - 2);
            return (
              <rect
                key={`${p.ts}-${i}`}
                x={x}
                y={55 - Math.max(h, 1)}
                width={w}
                height={Math.max(h, 1)}
                fill={color}
              />
            );
          })}
        </svg>
      )}
      <div className="mt-1 text-xs text-slate-500">
        {series.length} pts · max {max}
      </div>
    </div>
  );
}
