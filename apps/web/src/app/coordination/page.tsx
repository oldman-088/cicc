import type { Metadata } from "next";
import { UnconfiguredModulePage } from "../../components/application/UnconfiguredModulePage";

export const metadata: Metadata = {
  title: "Agent Coordination | CICC",
  description: "Agent coordination workspace. No verified agent or task provider is connected.",
};

export default function CoordinationPage() {
  return <UnconfiguredModulePage moduleId="coordination" />;
}
