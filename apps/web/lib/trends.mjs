// Pure helpers for trend series built from real metric snapshots.
export function toSeries(snapshots, key) {
  if (!Array.isArray(snapshots)) return [];
  return snapshots
    .filter((s) => s && s.ts)
    .map((s) => ({ ts: s.ts, value: Number(s[key] ?? 0) }));
}

export function maxValue(series) {
  if (!Array.isArray(series) || series.length === 0) return 0;
  return series.reduce((m, p) => Math.max(m, Number(p.value) || 0), 0);
}
