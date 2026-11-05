import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { NotificationCenter } from "./NotificationCenter";

afterEach(() => { window.localStorage.clear(); });

describe("NotificationCenter local reminders", () => {
  it("tracks unread count, filters by category, and marks all read — locally only", () => {
    window.localStorage.setItem("cicc.local-reminders.v1", JSON.stringify([
      { id: "r1", text: "Ops reminder", category: "operations", read: false, at: "t" },
      { id: "r2", text: "Case reminder", category: "investigation", read: false, at: "t" },
    ]));
    render(<NotificationCenter />);
    expect(screen.getByText(/No notification service is connected/)).toBeInTheDocument();
    expect(screen.getByText(/Unread: 2/)).toBeInTheDocument();
    fireEvent.change(screen.getByRole("combobox", { name: "Filter by category" }), { target: { value: "operations" } });
    expect(screen.getByText("Ops reminder")).toBeInTheDocument();
    expect(screen.queryByText("Case reminder")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Mark all read" }));
    expect(screen.getByText(/Unread: 0/)).toBeInTheDocument();
    const stored = JSON.parse(window.localStorage.getItem("cicc.local-reminders.v1") ?? "[]") as Array<{ read: boolean }>;
    expect(stored.every((r) => r.read)).toBe(true);
  });
});
