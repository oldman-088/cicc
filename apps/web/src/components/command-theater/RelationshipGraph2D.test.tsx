import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { DEMO_NODES, DEMO_RELATIONSHIPS } from "./demo-graph";
import { RelationshipExplorer } from "./RelationshipExplorer";
import { RelationshipGraph2D } from "./RelationshipGraph2D";

describe("RelationshipGraph2D", () => {
  it("draws a labelled 2D map for each sample relationship", () => {
    render(
      <RelationshipGraph2D
        nodes={DEMO_NODES}
        relationships={DEMO_RELATIONSHIPS}
        selectedNodeId="actor-demo"
        locale="en"
      />,
    );

    const map = screen.getByRole("img", { name: /2D intelligence relationship map/ });
    expect(map).toHaveAttribute("viewBox", "0 0 1000 520");
    expect(map.querySelectorAll("line")).toHaveLength(DEMO_RELATIONSHIPS.length);
    expect(map.querySelectorAll("circle").length).toBeGreaterThan(DEMO_NODES.length);
  });
});

describe("RelationshipExplorer", () => {
  it("exposes relationship direction, confidence, evidence state, and provenance", () => {
    render(
      <RelationshipExplorer
        nodes={DEMO_NODES}
        relationships={DEMO_RELATIONSHIPS}
        selectedNodeId="actor-demo"
        locale="en"
        onSelectNode={vi.fn()}
      />,
    );

    const relationshipList = screen.getByRole("list", { name: /Relationships/ });
    expect(within(relationshipList).getAllByText("Demo threat actor").length).toBeGreaterThan(0);
    expect(within(relationshipList).getByText("associated with")).toBeInTheDocument();
    expect(within(relationshipList).getByText(/55%/)).toBeInTheDocument();
    expect(screen.getAllByText(/No verified evidence attached/).length).toBeGreaterThan(0);
    expect(screen.getByText(/Synthetic UI fixture; not an intelligence record/)).toBeInTheDocument();
  });

  it("moves keyboard focus along a relationship in the LTR direction", () => {
    const onSelectNode = vi.fn();
    render(
      <RelationshipExplorer
        nodes={DEMO_NODES}
        relationships={DEMO_RELATIONSHIPS}
        selectedNodeId="actor-demo"
        locale="en"
        onSelectNode={onSelectNode}
      />,
    );

    const actor = screen.getByRole("button", { name: /Demo threat actor/ });
    const campaign = screen.getByRole("button", { name: /Demo campaign/ });
    actor.focus();
    fireEvent.keyDown(actor, { key: "ArrowRight" });

    expect(onSelectNode).toHaveBeenCalledWith("campaign-demo");
    expect(campaign).toHaveFocus();
  });

  it("uses the left arrow as forward navigation in an RTL locale", () => {
    const onSelectNode = vi.fn();
    render(
      <RelationshipExplorer
        nodes={DEMO_NODES}
        relationships={DEMO_RELATIONSHIPS}
        selectedNodeId="actor-demo"
        locale="fa"
        onSelectNode={onSelectNode}
      />,
    );

    const actor = screen.getByRole("button", { name: /Demo threat actor/ });
    const campaign = screen.getByRole("button", { name: /Demo campaign/ });
    actor.focus();
    fireEvent.keyDown(actor, { key: "ArrowLeft" });

    expect(onSelectNode).toHaveBeenCalledWith("campaign-demo");
    expect(campaign).toHaveFocus();
  });

  it("supports Home and End for predictable keyboard navigation", () => {
    const onSelectNode = vi.fn();
    render(
      <RelationshipExplorer
        nodes={DEMO_NODES}
        relationships={DEMO_RELATIONSHIPS}
        selectedNodeId="campaign-demo"
        locale="en"
        onSelectNode={onSelectNode}
      />,
    );

    const campaign = screen.getByRole("button", { name: /Demo campaign/ });
    campaign.focus();
    fireEvent.keyDown(campaign, { key: "End" });
    expect(onSelectNode).toHaveBeenCalledWith("asset-demo");
    expect(screen.getByRole("button", { name: /Demo research workstation/ })).toHaveFocus();
  });
});
