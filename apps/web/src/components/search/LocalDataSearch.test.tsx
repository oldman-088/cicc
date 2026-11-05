import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { LocalDataSearch } from "./LocalDataSearch";

afterEach(() => { window.localStorage.clear(); });

describe("LocalDataSearch (browser-local only)", () => {
  it("finds local investigations and reminders, states the local boundary, and never fabricates", () => {
    window.localStorage.setItem("cicc.investigations.v1", JSON.stringify([{ id: "i1", title: "Beacon case", summary: "s", status: "open", notes: [{ text: "x", at: "t" }], entities: ["host-1"], linkedTaskId: null, createdAt: "t" }]));
    window.localStorage.setItem("cicc.local-reminders.v1", JSON.stringify([{ id: "r1", text: "Rotate beacon keys", category: "operations", read: false, at: "t" }]));
    render(<LocalDataSearch />);
    expect(screen.getByText(/Server-side global search across providers is not available yet/)).toBeInTheDocument();
    fireEvent.change(screen.getByRole("searchbox", { name: /Search investigations and reminders/ }), { target: { value: "beacon" } });
    expect(screen.getByRole("link", { name: /Beacon case/ })).toHaveAttribute("href", "/investigations");
    expect(screen.getByRole("link", { name: /Rotate beacon keys/ })).toHaveAttribute("href", "/settings");
    fireEvent.change(screen.getByRole("searchbox", { name: /Search investigations and reminders/ }), { target: { value: "zzz" } });
    expect(screen.getByText("No local records match this search.")).toBeInTheDocument();
  });

  it("ignores malformed local data instead of throwing or inventing results", () => {
    window.localStorage.setItem("cicc.investigations.v1", "{broken");
    render(<LocalDataSearch />);
    fireEvent.change(screen.getByRole("searchbox", { name: /Search investigations and reminders/ }), { target: { value: "x" } });
    expect(screen.getByText("No local records match this search.")).toBeInTheDocument();
  });
});
