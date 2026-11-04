// Derive operational alerts from component statuses.
// Only "down" and "degraded" raise alerts; "not_implemented"/"not_configured"
// are informational and shown in the component table instead.
const ORDER = { down: 0, degraded: 1 };

export function deriveAlerts(components) {
  if (!Array.isArray(components)) return [];
  return components
    .filter((c) => c && (c.status === "down" || c.status === "degraded"))
    .map((c) => ({
      key: c.key,
      status: c.status,
      name: c.name,
      detail: c.detail ?? "",
    }))
    .sort((a, b) => (ORDER[a.status] ?? 9) - (ORDER[b.status] ?? 9));
}
