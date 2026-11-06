import type { Metadata } from "next";
import { CoordinationWorkspace } from "../../components/coordination/CoordinationWorkspace";

export const metadata: Metadata = {
  title: "Agent Coordination | CICC",
  description: "Read-only agent, task, metric, and event views from the configured coordination provider.",
};

export default function CoordinationPage() {
  return <CoordinationWorkspace />;
}
