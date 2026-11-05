import type { Metadata } from "next";
import { UnconfiguredModulePage } from "../../components/application/UnconfiguredModulePage";

export const metadata: Metadata = {
  title: "System Health | CICC",
  description: "Operations workspace. No verified health or telemetry source is connected.",
};

export default function SystemHealthPage() {
  return <UnconfiguredModulePage moduleId="system-health" />;
}
