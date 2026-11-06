// Format an age in seconds as a short human string (locale-independent).
export function formatAge(ageSeconds) {
  if (ageSeconds === null || ageSeconds === undefined || Number.isNaN(ageSeconds)) return "—";
  const s = Math.max(0, Math.floor(ageSeconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h`;
  return `${Math.floor(h / 24)}d`;
}
