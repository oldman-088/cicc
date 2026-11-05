import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { CiccApplication } from "../application/CiccApplication";
import { IntelligenceWorkspace } from "./IntelligenceWorkspace";

describe("Intelligence workspaces (no provider bound)", () => {
  it("threat workspace shows structure and honest unavailable state with no records", async () => {
    render(<CiccApplication><IntelligenceWorkspace kind="threat" /></CiccApplication>);
    expect(await screen.findByRole("heading", { name: "Threat Intelligence", level: 1 })).toBeInTheDocument();
    expect(screen.getAllByText(/not connected/).length).toBeGreaterThan(0);
    expect(screen.getByLabelText(/Search indicators/)).toBeDisabled();
    expect(document.body.textContent).not.toMatch(/CVE-\d{4}/);
  });
  it("vulnerability workspace mirrors the boundary for its own domain", async () => {
    render(<CiccApplication><IntelligenceWorkspace kind="vulnerability" /></CiccApplication>);
    expect(await screen.findByRole("heading", { name: "Vulnerability Intelligence", level: 1 })).toBeInTheDocument();
    expect(screen.getByLabelText(/Severity \(disabled\)/)).toBeDisabled();
  });
});
