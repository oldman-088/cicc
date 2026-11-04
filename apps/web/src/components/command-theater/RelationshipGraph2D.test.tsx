import { fireEvent, render, screen, within } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { DEMO_NODES, DEMO_RELATIONSHIPS } from "./demo-graph";
import type { IntelligenceRelationship } from "./types";
import { RelationshipExplorer } from "./RelationshipExplorer";
import { RelationshipGraph2D } from "./RelationshipGraph2D";

function buildRelationships(count: number): IntelligenceRelationship[] {
  const template = DEMO_RELATIONSHIPS[0]!;
  return Array.from({ length: count }, (_, index) => ({
    ...template,
    id: `stress-edge-${index}`,
  }));
}

function buildNodes(count: number) {
  const template = DEMO_NODES[0]!;
  return Array.from({ length: count }, (_, index) => ({
    ...template,
    id: `stress-node-${index}`,
    label: `Entity ${index}`,
  }));
}

const explorerDefaults = {
  sourceKind: "demo" as const,
  totalNodes: DEMO_NODES.length,
  totalRelationships: DEMO_RELATIONSHIPS.length,
  hasMoreData: false,
  loadingMore: false,
  pageError: null,
  historyPosition: "Step 1 of 1.",
  canNavigateBack: false,
  canNavigateForward: false,
  onNavigateBack: vi.fn(),
  onNavigateForward: vi.fn(),
  onLoadMore: vi.fn(),
  onRetryMore: vi.fn(),
};

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

  it("supports pointer and LTR keyboard selection from the accessible 2D map", () => {
    const onSelectNode = vi.fn();
    render(
      <RelationshipGraph2D
        nodes={DEMO_NODES}
        relationships={DEMO_RELATIONSHIPS}
        selectedNodeId="actor-demo"
        locale="en"
        onSelectNode={onSelectNode}
      />,
    );

    const map = screen.getByRole("group", { name: /2D intelligence relationship map/ });
    const actor = within(map).getByRole("button", { name: /Demo threat actor/ });
    const campaign = within(map).getByRole("button", { name: /Demo campaign/ });
    expect(actor).toHaveAttribute("aria-pressed", "true");
    expect(actor).toHaveAttribute("tabindex", "0");
    expect(campaign).toHaveAttribute("tabindex", "-1");

    actor.focus();
    fireEvent.keyDown(actor, { key: "ArrowRight" });
    expect(onSelectNode).toHaveBeenCalledWith("campaign-demo");
    expect(campaign).toHaveFocus();

    fireEvent.click(campaign);
    expect(onSelectNode).toHaveBeenLastCalledWith("campaign-demo");
  });

  it("uses the left arrow for forward selection in an RTL 2D map", () => {
    const onSelectNode = vi.fn();
    render(
      <RelationshipGraph2D
        nodes={DEMO_NODES}
        relationships={DEMO_RELATIONSHIPS}
        selectedNodeId="actor-demo"
        locale="fa"
        onSelectNode={onSelectNode}
      />,
    );

    const map = screen.getByRole("group", { name: /نقشهٔ دوبعدی/ });
    const actor = within(map).getByRole("button", { name: /Demo threat actor/ });
    const campaign = within(map).getByRole("button", { name: /Demo campaign/ });
    actor.focus();
    fireEvent.keyDown(actor, { key: "ArrowLeft" });

    expect(onSelectNode).toHaveBeenCalledWith("campaign-demo");
    expect(campaign).toHaveFocus();
  });

  it("bounds SVG rendering to 250 edges for a 5,000-relationship graph", () => {
    render(
      <RelationshipGraph2D
        nodes={DEMO_NODES}
        relationships={buildRelationships(5_000)}
        selectedNodeId="actor-demo"
        locale="en"
      />,
    );

    const map = screen.getByRole("img", { name: /2D intelligence relationship map/ });
    expect(map.querySelectorAll("line")).toHaveLength(250);
    expect(map).toHaveAccessibleDescription(/Map shows 250 of 5,000 relationships/);
    expect(screen.getByRole("note")).toHaveTextContent(/Map shows 250 of 5,000 relationships/);
  });
});

describe("RelationshipExplorer", () => {
  it("exposes relationship direction, confidence, evidence state, and provenance", () => {
    render(
      <RelationshipExplorer
        {...explorerDefaults}
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
    expect(screen.getAllByText(/No evidence attached to this synthetic sample/).length).toBeGreaterThan(0);
    expect(screen.getByText("Synthetic UI fixture")).toBeInTheDocument();
  });

  it("moves keyboard focus along a relationship in the LTR direction", () => {
    const onSelectNode = vi.fn();
    render(
      <RelationshipExplorer
        {...explorerDefaults}
        nodes={DEMO_NODES}
        relationships={DEMO_RELATIONSHIPS}
        selectedNodeId="actor-demo"
        locale="en"
        onSelectNode={onSelectNode}
      />,
    );

    const actor = screen.getByRole("button", { name: /Demo threat actor/ });
    const campaign = screen.getByRole("button", { name: /Demo campaign/ });
    expect(actor).toHaveAttribute("tabindex", "0");
    expect(campaign).toHaveAttribute("tabindex", "-1");
    actor.focus();
    fireEvent.keyDown(actor, { key: "ArrowRight" });

    expect(onSelectNode).toHaveBeenCalledWith("campaign-demo");
    expect(campaign).toHaveFocus();
  });

  it("uses the left arrow as forward navigation in an RTL locale", () => {
    const onSelectNode = vi.fn();
    render(
      <RelationshipExplorer
        {...explorerDefaults}
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
        {...explorerDefaults}
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

  it("paginates the entity list while keeping an off-page selection visible", () => {
    const nodes = buildNodes(80);
    render(
      <RelationshipExplorer
        {...explorerDefaults}
        totalNodes={nodes.length}
        totalRelationships={0}
        nodes={nodes}
        relationships={[]}
        selectedNodeId="stress-node-70"
        locale="en"
        onSelectNode={vi.fn()}
      />,
    );

    const entityList = screen.getByRole("list", { name: /Entities/ });
    expect(within(entityList).getAllByRole("button")).toHaveLength(50);
    expect(within(entityList).getByRole("button", { name: /Entity 70/ })).toHaveAttribute("tabindex", "0");
    expect(screen.getByText("Showing 50 of 80 entities.")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Show more entities" }));
    expect(within(entityList).getAllByRole("button")).toHaveLength(80);
    expect(screen.getByText("Showing 80 of 80 entities.")).toBeInTheDocument();
  });

  it("moves focus to an off-page linked entity without rendering every entity", () => {
    const nodes = buildNodes(60);
    const relationship = {
      ...DEMO_RELATIONSHIPS[0]!,
      id: "off-page-link",
      sourceId: nodes[0]!.id,
      targetId: nodes[55]!.id,
    };

    function InteractiveExplorer() {
      const [selectedNodeId, setSelectedNodeId] = useState(nodes[0]!.id);
      return (
        <RelationshipExplorer
          {...explorerDefaults}
          totalNodes={nodes.length}
          totalRelationships={1}
          nodes={nodes}
          relationships={[relationship]}
          selectedNodeId={selectedNodeId}
          locale="en"
          onSelectNode={setSelectedNodeId}
        />
      );
    }

    render(<InteractiveExplorer />);
    const firstEntity = screen.getByRole("button", { name: /Entity 0/ });
    expect(screen.queryByRole("button", { name: /Entity 55/ })).not.toBeInTheDocument();
    firstEntity.focus();
    fireEvent.keyDown(firstEntity, { key: "ArrowRight" });

    const linkedEntity = screen.getByRole("button", { name: /Entity 55/ });
    expect(linkedEntity).toHaveFocus();
    expect(screen.getAllByRole("list", { name: /Entities/ })[0]?.querySelectorAll("button")).toHaveLength(50);
  });

  it("paginates the accessible relationship list for large graphs", () => {
    render(
      <RelationshipExplorer
        {...explorerDefaults}
        totalRelationships={5_000}
        nodes={DEMO_NODES}
        relationships={buildRelationships(5_000)}
        selectedNodeId="actor-demo"
        locale="en"
        onSelectNode={vi.fn()}
      />,
    );

    const relationshipList = screen.getByRole("list", { name: /Relationships/ });
    expect(within(relationshipList).getAllByRole("listitem")).toHaveLength(50);
    expect(screen.getByText("Showing 50 of 5,000 relationships.")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Show more relationships" }));
    expect(within(relationshipList).getAllByRole("listitem")).toHaveLength(100);
    expect(screen.getByText("Showing 100 of 5,000 relationships.")).toBeInTheDocument();
  });
});
