import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { AnchorHTMLAttributes } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CiccApplication } from "./CiccApplication";
import { CommandTheater } from "../command-theater/CommandTheater";

vi.mock("next/link", () => ({
  default: ({ href, children, ...props }: AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }) =>
    <a href={href} {...props}>{children}</a>,
}));

vi.mock("next/navigation", () => ({ usePathname: () => "/command-theater" }));

vi.mock("next/dynamic", () => ({
  default: () => function MockTheater3D() { return <div />; },
}));

vi.mock("../command-theater/webgl-support", () => ({
  detectWebGLAvailability: () => false,
}));

afterEach(() => {
  document.documentElement.lang = "en";
  document.documentElement.dir = "ltr";
});

describe("CICC application locale coordination", () => {
  it("keeps global navigation, document language, and Command Theater in sync", async () => {
    render(
      <CiccApplication>
        <CommandTheater />
      </CiccApplication>,
    );

    const languageControl = screen.getByRole("combobox", { name: "Interface language" });
    expect(screen.getAllByRole("combobox", { name: "Interface language" })).toHaveLength(1);
    fireEvent.change(languageControl, { target: { value: "fa" } });

    await waitFor(() => {
      expect(document.documentElement.lang).toBe("fa");
      expect(document.documentElement.dir).toBe("rtl");
      expect(screen.getByRole("navigation", { name: "پیمایش اصلی" })).toBeInTheDocument();
    });
    expect(screen.getByRole("region", { name: "تالار فرماندهی اطلاعات" }))
      .toHaveAttribute("dir", "rtl");
    expect(screen.getByRole("link", { name: "تالار فرماندهی" }))
      .toHaveAttribute("aria-current", "page");
  });
});
