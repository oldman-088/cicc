import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { CiccApplication } from "../application/CiccApplication";
import { InvestigationsWorkspace } from "./InvestigationsWorkspace";

afterEach(() => window.localStorage.clear());

function renderWorkspace() {
  return render(<CiccApplication><InvestigationsWorkspace /></CiccApplication>);
}

describe("Investigations workspace (browser-local)", () => {
  it("creates, searches, and annotates a local investigation without claiming server sync", async () => {
    renderWorkspace();
    expect(await screen.findByText(/stored only in this browser/)).toBeInTheDocument();
    expect(screen.getByText(/No investigations yet/)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Title"), { target: { value: "Suspicious beaconing" } });
    fireEvent.change(screen.getByLabelText("Summary"), { target: { value: "Local analyst case" } });
    fireEvent.click(screen.getByRole("button", { name: "Create investigation" }));

    expect(await screen.findByRole("heading", { name: "Suspicious beaconing", level: 3 })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Add a note"), { target: { value: "Checked local notes" } });
    fireEvent.click(screen.getByRole("button", { name: "Add note" }));
    expect(await screen.findByText("Checked local notes")).toBeInTheDocument();

    fireEvent.change(screen.getByRole("searchbox", { name: /Search local investigations/ }), { target: { value: "nomatch" } });
    expect(await screen.findByText(/No local investigations match/)).toBeInTheDocument();
    expect(window.localStorage.getItem("cicc.investigations.v1")).toContain("Suspicious beaconing");
  });
});
