import type { Metadata } from "next";
import { UnconfiguredModulePage } from "../../components/application/UnconfiguredModulePage";

export const metadata: Metadata = {
  title: "Threat Intelligence | CICC",
  description: "Threat intelligence workspace. Data integration is not configured in this frontend.",
};

export default function ThreatIntelligencePage() {
  return <UnconfiguredModulePage moduleId="threat-intelligence" />;
}
