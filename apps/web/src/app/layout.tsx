import type { Metadata } from "next";
import type { ReactNode } from "react";
import { CiccApplication } from "../components/application/CiccApplication";
import "./globals.css";

export const metadata: Metadata = {
  title: "CICC | Cyber Intelligence Command Center",
  description:
    "An accessible, multilingual cyber intelligence workspace with transparent integration and data availability states.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" dir="ltr">
      <body>
        <CiccApplication>{children}</CiccApplication>
      </body>
    </html>
  );
}
