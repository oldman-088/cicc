import type { Metadata } from "next";
import { CommandTheater } from "../../components/command-theater/CommandTheater";

export const metadata: Metadata = {
  title: "Command Theater | CICC",
  description: "Explore intelligence relationships with an accessible 2D graph and optional 3D view.",
};

export default function CommandTheaterPage() {
  return <CommandTheater demoMode={process.env.NODE_ENV === "development"} />;
}
