import { WorkspaceOverview } from "../components/overview/WorkspaceOverview";

export default function HomePage() {
  return <WorkspaceOverview demoMode={process.env.NODE_ENV === "development"} />;
}
