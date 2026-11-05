import type { AnchorHTMLAttributes } from "react";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import axe from "axe-core";
import { describe, expect, it, vi } from "vitest";
import { ApplicationShell } from "./ApplicationShell";

const routeState = vi.hoisted(() => ({ pathname: "/command-theater" }));

vi.mock("next/link", () => ({
  default: ({
    href,
    children,
    ...props
  }: AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }) => {
    const { onClick, ...anchorProps } = props;
    return (
      <a
        href={href}
        {...anchorProps}
        onClick={(event) => {
          onClick?.(event);
          event.preventDefault();
        }}
      >
        {children}
      </a>
    );
  },
}));

vi.mock("next/navigation", () => ({ usePathname: () => routeState.pathname }));

describe("CICC application shell", () => {
  it("exposes module routes, preferences, and usable skip/navigation controls", () => {
    const onLocaleChange = vi.fn();
    render(
      <ApplicationShell locale="fa" onLocaleChange={onLocaleChange}>
        <h1>Investigation workspace</h1>
      </ApplicationShell>,
    );

    expect(screen.getByRole("link", { name: "رفتن به محتوای اصلی" }))
      .toHaveAttribute("href", "#cicc-main-content");
    expect(screen.getByRole("main")).toHaveAttribute("id", "cicc-main-content");

    const navigation = screen.getByRole("navigation", { name: "پیمایش اصلی" });
    const moduleLink = within(navigation).getByRole("link", { name: "تالار فرماندهی" });
    expect(moduleLink).toHaveAttribute("aria-current", "page");
    expect(within(navigation).getAllByRole("link")).toHaveLength(7);
    expect(within(navigation).getByRole("link", { name: "اطلاعات تهدید" }))
      .toHaveAttribute("href", "/threat-intelligence");
    expect(within(navigation).getByRole("link", { name: "تنظیمات" }))
      .toHaveAttribute("href", "/settings");
    expect(screen.getByRole("navigation", { name: "مسیر راهنما" }))
      .toHaveTextContent("فضای کاری");

    fireEvent.change(screen.getByRole("combobox", { name: "زبان رابط کاربری" }), {
      target: { value: "ar" },
    });
    expect(onLocaleChange).toHaveBeenCalledWith("ar");

    const toggle = screen.getByRole("button", { name: "بازکردن پیمایش فضای کاری" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(toggle);
    expect(screen.getByRole("button", { name: "بستن پیمایش فضای کاری" }))
      .toHaveAttribute("aria-expanded", "true");

    fireEvent.click(moduleLink);
    expect(screen.getByRole("button", { name: "بازکردن پیمایش فضای کاری" }))
      .toHaveAttribute("aria-expanded", "false");
  });

  it("searches workspace routes only and explains that entity search is not connected", () => {
    render(
      <ApplicationShell locale="fa" onLocaleChange={vi.fn()}>
        <h1>Investigation workspace</h1>
      </ApplicationShell>,
    );

    const search = screen.getByRole("searchbox", { name: "یافتن صفحهٔ فضای کاری" });
    expect(search).toHaveAttribute("aria-describedby");
    expect(screen.getByText(/فقط صفحه‌ها جست‌وجو می‌شوند/)).toBeInTheDocument();
    expect(screen.getByText("Ctrl/⌘+K")).toHaveAttribute("dir", "ltr");
    fireEvent.change(search, { target: { value: "آسیب‌پذیری" } });

    const navigation = screen.getByRole("navigation", { name: "پیمایش اصلی" });
    expect(within(navigation).getAllByRole("link")).toHaveLength(1);
    expect(within(navigation).getByRole("link", { name: "اطلاعات آسیب‌پذیری" }))
      .toHaveAttribute("href", "/vulnerability-intelligence");

    fireEvent.change(search, { target: { value: "not-a-module" } });
    expect(screen.getByRole("status")).toHaveTextContent("صفحه‌ای در فضای کاری با این جست‌وجو پیدا نشد.");
  });

  it("opens navigation search with Ctrl/Meta+K without hijacking form-field shortcuts", async () => {
    for (const modifiers of [{ ctrlKey: true }, { metaKey: true }]) {
      const { unmount } = render(
        <ApplicationShell locale="en" onLocaleChange={vi.fn()}>
          <h1>Workspace overview</h1>
        </ApplicationShell>,
      );
      const search = screen.getByRole("searchbox", { name: "Find a workspace page" });
      const toggle = screen.getByRole("button", { name: "Open workspace navigation" });
      expect(search).toHaveAttribute("aria-keyshortcuts", "Control+K Meta+K");
      expect(screen.getByText("Ctrl/⌘+K")).toBeInTheDocument();

      const fieldShortcut = new KeyboardEvent("keydown", {
        key: "k", bubbles: true, cancelable: true, ctrlKey: true,
      });
      search.dispatchEvent(fieldShortcut);
      expect(fieldShortcut.defaultPrevented).toBe(false);
      expect(toggle).toHaveAttribute("aria-expanded", "false");

      const globalShortcut = new KeyboardEvent("keydown", {
        key: "k", bubbles: true, cancelable: true, ...modifiers,
      });
      window.dispatchEvent(globalShortcut);
      await waitFor(() => expect(search).toHaveFocus());
      expect(globalShortcut.defaultPrevented).toBe(true);
      expect(screen.getByRole("button", { name: "Close workspace navigation" }))
        .toHaveAttribute("aria-expanded", "true");
      unmount();
    }
  });

  it("marks the overview destination as current on the home route", () => {
    routeState.pathname = "/";
    render(
      <ApplicationShell locale="en" onLocaleChange={vi.fn()}>
        <h1>Workspace overview</h1>
      </ApplicationShell>,
    );

    const navigation = screen.getByRole("navigation", { name: "Primary navigation" });
    expect(within(navigation).getByRole("link", { name: "Overview" }))
      .toHaveAttribute("aria-current", "page");
    expect(within(navigation).getByRole("link", { name: "Command Theater" }))
      .not.toHaveAttribute("aria-current");
    expect(screen.getByRole("navigation", { name: "Breadcrumb" }))
      .toHaveTextContent("Overview");
  });

  it("marks settings as current on the settings route", () => {
    routeState.pathname = "/settings";
    render(
      <ApplicationShell locale="en" onLocaleChange={vi.fn()}>
        <h1>Settings</h1>
      </ApplicationShell>,
    );

    const navigation = screen.getByRole("navigation", { name: "Primary navigation" });
    expect(within(navigation).getByRole("link", { name: "Settings" }))
      .toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("navigation", { name: "Breadcrumb" }))
      .toHaveTextContent("Settings");
  });

  it("passes axe structural checks in Arabic without claiming color-contrast verification", async () => {
    const { container } = render(
      <ApplicationShell locale="ar" onLocaleChange={vi.fn()}>
        <h1>مسرح القيادة</h1>
      </ApplicationShell>,
    );

    const canvasContext = vi.spyOn(HTMLCanvasElement.prototype, "getContext")
      .mockImplementation(() => null as never);
    const results = await axe.run(container, {
      rules: { "color-contrast": { enabled: false } },
    }).finally(() => canvasContext.mockRestore());
    expect(results.violations.map((violation) => violation.id)).toEqual([]);
  });
});
