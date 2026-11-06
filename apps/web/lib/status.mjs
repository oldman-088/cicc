// Overall-status aggregation shared by the dashboard UI and the node tests.
// Severity order mirrors apps/api/app/ops.py::compute_overall.
export const STATUS_SEVERITY = Object.freeze({
  ok: 0,
  not_configured: 1,
  not_implemented: 1,
  degraded: 2,
  down: 3,
  unknown: 4,
});

export function severityOf(status) {
  return Object.prototype.hasOwnProperty.call(STATUS_SEVERITY, status)
    ? STATUS_SEVERITY[status]
    : STATUS_SEVERITY.unknown;
}

// Returns one of: "ok" | "degraded" | "down" | "unknown"
export function overallStatus(statuses) {
  if (!Array.isArray(statuses) || statuses.length === 0) return "unknown";
  let max = 0;
  for (const s of statuses) max = Math.max(max, severityOf(s));
  if (max === 0) return "ok";
  if (max === STATUS_SEVERITY.down) return "down";
  if (max >= STATUS_SEVERITY.unknown) return "unknown";
  return "degraded";
}
