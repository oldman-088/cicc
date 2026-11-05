import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CiccApplication } from "./CiccApplication";
import { SettingsPage } from "./SettingsPage";

afterEach(() => {
  window.localStorage.removeItem("cicc:locale");
  window.localStorage.removeItem("cicc:reduce-motion");
  document.documentElement.removeAttribute("data-cicc-reduce-motion");
});

describe("workspace settings", () => {
  it("updates the shared locale and persists the app-level reduced-motion preference", async () => {
    render(
      <CiccApplication>
        <SettingsPage />
      </CiccApplication>,
    );

    expect(screen.getByRole("heading", { name: "Settings", level: 1 })).toBeInTheDocument();
    const language = screen.getByRole("combobox", { name: "Choose interface language" });
    fireEvent.change(language, { target: { value: "fa" } });
    await waitFor(() => {
      expect(document.documentElement.lang).toBe("fa");
      expect(document.documentElement.dir).toBe("rtl");
      expect(screen.getByRole("heading", { name: "تنظیمات", level: 1 })).toBeInTheDocument();
      expect(window.localStorage.getItem("cicc:locale")).toBe("fa");
    });

    const motionControl = screen.getByRole("checkbox", { name: "کاهش حرکت در CICC" });
    fireEvent.click(motionControl);
    await waitFor(() => {
      expect(document.documentElement).toHaveAttribute("data-cicc-reduce-motion", "true");
      expect(window.localStorage.getItem("cicc:reduce-motion")).toBe("true");
    });
  });

  it("restores browser-only locale and reduced-motion preferences on startup", async () => {
    window.localStorage.setItem("cicc:locale", "ar");
    window.localStorage.setItem("cicc:reduce-motion", "true");
    render(
      <CiccApplication>
        <SettingsPage />
      </CiccApplication>,
    );

    await waitFor(() => {
      expect(document.documentElement.lang).toBe("ar");
      expect(document.documentElement.dir).toBe("rtl");
      expect(screen.getByRole("combobox", { name: "اختيار لغة الواجهة" })).toHaveValue("ar");
      expect(screen.getByRole("checkbox", { name: "تقليل الحركة في CICC" })).toBeChecked();
      expect(document.documentElement).toHaveAttribute("data-cicc-reduce-motion", "true");
    });
  });

  it("applies the optional light theme and persists it browser-only", async () => {
    window.localStorage.clear();
    render(<CiccApplication><SettingsPage /></CiccApplication>);
    const themeSelect = await screen.findByRole("combobox", { name: "Choose interface theme" });
    fireEvent.change(themeSelect, { target: { value: "light" } });
    expect(document.documentElement.getAttribute("data-cicc-theme")).toBe("light");
    expect(window.localStorage.getItem("cicc:theme")).toBe("light");
    fireEvent.change(themeSelect, { target: { value: "dark" } });
    expect(document.documentElement.getAttribute("data-cicc-theme")).toBeNull();
  });

  it("states that account and tenant preferences are unavailable without an integration", () => {
    render(
      <CiccApplication>
        <SettingsPage />
      </CiccApplication>,
    );

    expect(screen.getByRole("heading", { name: "Account and tenant settings" })).toBeInTheDocument();
    expect(screen.getByText(/no verified identity, tenant, or preference-service contract/i))
      .toBeInTheDocument();
  });

  it("passes automated axe structural checks without making a manual contrast claim", async () => {
    const { container } = render(
      <CiccApplication>
        <SettingsPage />
      </CiccApplication>,
    );
    const canvasContext = vi.spyOn(HTMLCanvasElement.prototype, "getContext")
      .mockImplementation(() => null as never);
    const results = await axe.run(container, {
      rules: { "color-contrast": { enabled: false } },
    }).finally(() => canvasContext.mockRestore());

    expect(results.violations.map((violation) => violation.id)).toEqual([]);
  });
});
