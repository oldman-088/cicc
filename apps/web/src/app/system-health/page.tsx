import type { Metadata } from "next";
import { SystemHealthWorkspace } from "../../components/system-health/SystemHealthWorkspace";

export const metadata: Metadata = {
  title: "System Health | CICC",
  description: "Read-only system health and operational telemetry from the configured provider.",
};

export default function SystemHealthPage() {
  return <SystemHealthWorkspace />;
}
