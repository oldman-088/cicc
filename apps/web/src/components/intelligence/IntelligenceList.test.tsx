import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { IntelligenceList, filterIntelligenceRecords } from "./IntelligenceList";

// Labeled synthetic fixture records for component testing only.
const fixtures = [
  { id: "ind-1", name: "fixture-indicator", kind: "indicator", confidence: 40, verification: "unverified", provenanceSources: ["fixture"] },
  { id: "actor-1", name: "fixture-actor", kind: "actor", confidence: 70, verification: "corroborated", provenanceSources: ["fixture", "fixture-2"] },
];
describe("IntelligenceList", () => {
  it("filters by query/kind and shows provenance + confidence in detail", () => {
    expect(filterIntelligenceRecords(fixtures, "actor", "all")).toHaveLength(1);
    expect(filterIntelligenceRecords(fixtures, "", "indicator")).toHaveLength(1);
    render(<IntelligenceList records={fixtures} emptyMessage="No records" />);
    fireEvent.click(screen.getByRole("button", { name: /fixture-actor/ }));
    expect(screen.getByText(/Provenance sources: fixture, fixture-2/)).toBeInTheDocument();
    fireEvent.change(screen.getByRole("searchbox", { name: "Search records" }), { target: { value: "zzz" } });
    expect(screen.getByText("No records")).toBeInTheDocument();
  });
});
