import type { AnchorHTMLAttributes } from "react";
import { render, screen } from "@testing-library/react";
import axe from "axe-core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { WorkspaceOverview } from "./WorkspaceOverview";

const overviewLocale = vi.hoisted(() => ({ value: "en" as "en" | "ar" | "fa" }));

vi.mock("next/link", () => ({
  default: ({ href, children, ...props }: AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }) =>
    <a href={href} {...props}>{children}</a>,
}));

vi.mock("../application/CiccApplication", () => ({
  useCiccLocale: () => ({ locale: overviewLocale.value, setLocale: () => {} }),
}));

describe("workspace overview", () => {
  beforeEach(() => {
    overviewLocale.value = "en";
  });
  it("shows only real frontend scope and makes missing live data explicit", () => {
    render(<WorkspaceOverview demoMode={false} />);

    expect(screen.getByRole("heading", { name: "Workspace overview", level: 1 })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "No live data provider is configured" })).toBeInTheDocument();
    expect(screen.getByText(/has no verified backend\/API integration.*do not display production intelligence or operational metrics/i))
      .toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Command Theater" }))
      .toHaveAttribute("href", "/command-theater");
    expect(screen.getByRole("link", { name: "Threat Intelligence" }))
      .toHaveAttribute("href", "/threat-intelligence");
    expect(screen.getByRole("link", { name: "Vulnerability Intelligence" }))
      .toHaveAttribute("href", "/vulnerability-intelligence");
    expect(screen.getByRole("link", { name: "System Health" }))
      .toHaveAttribute("href", "/system-health");
    expect(screen.getByRole("link", { name: "Agent Coordination" }))
      .toHaveAttribute("href", "/coordination");
    expect(screen.getByText(/No CVE records, scores, or status are displayed without a verified source/i))
      .toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Data sources and freshness" })).toBeInTheDocument();
    expect(screen.getByText(/no source update time or freshness claim is available/i)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Recent events" })).toBeInTheDocument();
    expect(screen.getByText("No event provider is configured, so no recent activity is shown."))
      .toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "Related activity workspaces" })).toBeInTheDocument();
    expect(screen.queryByText(/live threat count|active incidents/i)).not.toBeInTheDocument();
  });

  it("labels the development sample as synthetic rather than live", () => {
    render(<WorkspaceOverview demoMode />);

    expect(screen.getByRole("heading", { name: "Synthetic development sample only" }))
      .toBeInTheDocument();
    expect(screen.getByText(/never presented as live intelligence/i)).toBeInTheDocument();
    expect(screen.getByText(/synthetic, not live intelligence, and has no production source timestamp/i))
      .toBeInTheDocument();
    expect(screen.getByText(/synthetic graph fixtures are not presented as recent events/i))
      .toBeInTheDocument();
  });

  it("renders translated overview headings in both RTL locales", () => {
    const localizedHeadings = [
      { locale: "ar" as const, heading: "نظرة عامة على مساحة العمل" },
      { locale: "fa" as const, heading: "نمای کلی فضای کاری" },
    ];

    for (const { locale, heading } of localizedHeadings) {
      overviewLocale.value = locale;
      const { container, unmount } = render(<WorkspaceOverview demoMode={false} />);
      expect(screen.getByRole("heading", { name: heading, level: 1 })).toBeInTheDocument();
      expect(container.firstElementChild).toHaveAttribute("dir", "rtl");
      unmount();
    }
  });

  it("passes automated axe structure checks for the no-provider state", async () => {
    const { container } = render(<WorkspaceOverview demoMode={false} />);
    const canvasContext = vi.spyOn(HTMLCanvasElement.prototype, "getContext")
      .mockImplementation(() => null as never);
    const results = await axe.run(container, {
      rules: { "color-contrast": { enabled: false } },
    }).finally(() => canvasContext.mockRestore());

    expect(results.violations.map((violation) => violation.id)).toEqual([]);
  });
});
