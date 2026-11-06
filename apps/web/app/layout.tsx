import type { Metadata } from "next";
import "./globals.css";
import { LocaleProvider } from "../lib/i18n";

export const metadata: Metadata = {
  title: "CICC — System Health & Operations",
  description:
    "Operational health dashboard for the Cyber Intelligence Command Center (CICC).",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" dir="ltr" suppressHydrationWarning>
      <body>
        <LocaleProvider>{children}</LocaleProvider>
      </body>
    </html>
  );
}
