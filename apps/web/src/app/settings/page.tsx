import type { Metadata } from "next";
import { SettingsPage } from "../../components/application/SettingsPage";

export const metadata: Metadata = {
  title: "Settings | CICC",
  description: "Manage CICC interface language and reduced-motion preferences.",
};

export default function WorkspaceSettingsPage() {
  return <SettingsPage />;
}
