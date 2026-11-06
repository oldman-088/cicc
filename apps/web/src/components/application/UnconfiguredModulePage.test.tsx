import type { AnchorHTMLAttributes } from "react";
import { render, screen } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { UnconfiguredModulePage } from "./UnconfiguredModulePage";

type ModuleId = "threat-intelligence" | "vulnerability-intelligence" | "system-health" | "coordination";
const moduleLocale = vi.hoisted(() => ({ value: "en" as "en" | "ar" | "fa" }));

vi.mock("next/link", () => ({
  default: ({ href, children, ...props }: AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }) =>
    <a href={href} {...props}>{children}</a>,
}));

vi.mock("./CiccApplication", () => ({
  useCiccLocale: () => ({ locale: moduleLocale.value, setLocale: () => {} }),
}));

const englishModules: { id: ModuleId; title: string; status: string; scope: string }[] = [
  { id: "threat-intelligence", title: "Threat Intelligence", status: "Threat data is not connected", scope: "Planned scope — not yet available" },
  { id: "vulnerability-intelligence", title: "Vulnerability Intelligence", status: "Vulnerability API proposal is not mounted", scope: "Planned scope — not yet available" },
  { id: "system-health", title: "System Health", status: "Operations provider is not available", scope: "Available read-only views" },
  { id: "coordination", title: "Agent Coordination", status: "Coordination provider is not available", scope: "Available read-only views" },
];

afterEach(() => {
  moduleLocale.value = "en";
});

describe("unconfigured workspace modules", () => {
  it.each(englishModules)("explains the unavailable integration for $title", ({ id, title, status, scope }) => {
    const { container } = render(<UnconfiguredModulePage moduleId={id} />);

    expect(screen.getByRole("heading", { name: title, level: 1 })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: status })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: scope })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back to workspace overview" })).toHaveAttribute("href", "/");
    expect(container).not.toHaveTextContent(/live count|service is healthy/i);
  });

  it("describes vulnerability exports as package-level and still unmounted", () => {
    render(<UnconfiguredModulePage moduleId="vulnerability-intelligence" />);

    expect(screen.getByText(/supports vulnerability list\/detail and CycloneDX VEX, OpenVEX, and SARIF exports/)).toBeInTheDocument();
    expect(screen.getByText(/OpenAPI contract is still proposed/)).toBeInTheDocument();
    expect(screen.getByText(/No provider is connected/)).toBeInTheDocument();
  });

  it("sets RTL on the Farsi module shell and keeps module labels localized", () => {
    moduleLocale.value = "fa";
    const { container } = render(<UnconfiguredModulePage moduleId="system-health" />);

    expect(screen.getByRole("heading", { name: "سلامت سامانه", level: 1 })).toBeInTheDocument();
    expect(container.firstElementChild).toHaveAttribute("dir", "rtl");
    expect(screen.getByRole("link", { name: "بازگشت به نمای کلی فضای کاری" })).toHaveAttribute("href", "/");
  });

  it("passes axe structural checks in jsdom; browser E2E covers color contrast", async () => {
    const { container } = render(<UnconfiguredModulePage moduleId="threat-intelligence" />);
    const canvasContext = vi.spyOn(HTMLCanvasElement.prototype, "getContext")
      .mockImplementation(() => null as never);
    const results = await axe.run(container, {
      rules: { "color-contrast": { enabled: false } },
    }).finally(() => canvasContext.mockRestore());

    expect(results.violations.map((violation) => violation.id)).toEqual([]);
  });
});
