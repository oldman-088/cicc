import { WorkspaceOverview } from "../components/overview/WorkspaceOverview";
import { LocalDataSearch } from "../components/search/LocalDataSearch";

export default function HomePage() {
  return (
    <>
      <WorkspaceOverview demoMode={process.env.NODE_ENV === "development"} />
      <LocalDataSearch />
    </>
  );
}
