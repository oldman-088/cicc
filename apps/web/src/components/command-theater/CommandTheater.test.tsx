import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import axe from "axe-core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CommandTheater } from "./CommandTheater";
import { detectWebGLAvailability } from "./webgl-support";
import type {
  CommandTheaterDataSource,
  GraphPage,
  GraphPageRequest,
  IntelligenceNode,
  IntelligenceRelationship,
} from "./types";

const theaterMock = vi.hoisted(() => ({ throwsOnRender: false }));

vi.mock("next/dynamic", () => ({
  default: () =>
    function MockTheater3D({ onFallback }: { onFallback: (reason?: "context-lost") => void }) {
      if (theaterMock.throwsOnRender) throw new Error("3D chunk initialization failed");
      return (
        <div data-testid="mock-3d-theater">
          <button type="button" onClick={() => onFallback()}>simulate WebGL failure</button>
          <button type="button" onClick={() => onFallback("context-lost")}>simulate WebGL context loss</button>
          3D scene mounted
        </div>
      );
    },
}));

vi.mock("./webgl-support", () => ({
  detectWebGLAvailability: vi.fn(),
}));

function backendNode(id: string, label: string, type: IntelligenceNode["type"] = "domain"): IntelligenceNode {
  return {
    id,
    label,
    type,
    confidence: { value: 0.82, basis: "analyst-assessed", method: "controlled-test" },
    verificationStatus: "verified",
    provenance: {
      sourceName: "Controlled integration fixture",
      sourceRecordId: `record-${id}`,
      collectedAt: "2026-10-01T12:00:00Z",
      publishedAt: "2026-10-01T11:00:00Z",
    },
    evidence: [
      {
        id: `evidence-${id}`,
        label: "Analyst-reviewed source note",
        sourceName: "Controlled source",
        status: "verified",
        observedAt: "2026-10-01T10:00:00Z",
      },
    ],
  };
}

function backendRelationship(
  id: string,
  sourceId: string,
  targetId: string,
): IntelligenceRelationship {
  return {
    id,
    sourceId,
    targetId,
    type: "associated-with",
    confidence: { value: 0.74, basis: "model-assessed", method: "controlled-test" },
    verificationStatus: "inferred",
    provenance: { sourceName: "Controlled correlation service", sourceRecordId: `edge-${id}` },
    evidence: [],
  };
}

function backendPage(
  nodes: IntelligenceNode[],
  relationships: IntelligenceRelationship[] = [],
  extras: Partial<GraphPage> = {},
): GraphPage {
  return {
    nodes,
    relationships,
    nextCursor: null,
    totalNodes: nodes.length,
    totalRelationships: relationships.length,
    ...extras,
  };
}

function backendSource(loadPage: CommandTheaterDataSource["loadPage"]): CommandTheaterDataSource {
  return { kind: "backend", loadPage };
}

describe("CommandTheater", () => {
  beforeEach(() => {
    theaterMock.throwsOnRender = false;
    vi.mocked(detectWebGLAvailability).mockReturnValue(false);
  });

  it("does not substitute synthetic records when no provider is configured", async () => {
    render(<CommandTheater />);

    expect(await screen.findByText(/No graph data source is configured/i)).toBeInTheDocument();
    expect(screen.queryByText("Demo threat actor")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "3D theater" })).toBeDisabled();
  });

  it("loads synthetic fixtures only when demo mode is explicitly enabled", async () => {
    render(<CommandTheater demoMode />);

    expect(await screen.findByRole("group", { name: /2D intelligence relationship map/i })).toBeInTheDocument();
    expect(screen.getByText(/Synthetic sample only · no live feeds/i)).toBeInTheDocument();
    expect(screen.getAllByText("Demo threat actor").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/illustrative only/i).length).toBeGreaterThan(0);
  });

  it("passes automated axe checks in the accessible 2D demo state", async () => {
    const { container } = render(
      <main><CommandTheater demoMode /></main>,
    );
    await screen.findByRole("group", { name: /2D intelligence relationship map/i });

    // jsdom has no canvas implementation; color contrast is intentionally left for browser QA.
    const canvasContext = vi.spyOn(HTMLCanvasElement.prototype, "getContext")
      .mockImplementation(() => null as never);
    const results = await axe.run(container, {
      rules: { "color-contrast": { enabled: false } },
    }).finally(() => canvasContext.mockRestore());
    expect(results.violations.map((violation) => violation.id)).toEqual([]);
  });

  it("starts with the 2D map and keeps it available when WebGL is unavailable", async () => {
    render(<CommandTheater demoMode />);

    expect(await screen.findByRole("group", { name: /2D intelligence relationship map/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "2D map" })).toHaveAttribute("aria-pressed", "true");

    const threeDButton = screen.getByRole("button", { name: "3D theater" });
    await waitFor(() => expect(threeDButton).toBeDisabled());
    expect(screen.getByText(/3D is unavailable/i)).toBeInTheDocument();
    expect(screen.queryByTestId("mock-3d-theater")).not.toBeInTheDocument();
  });

  it("loads the 3D module only after the user opts into the 3D view", async () => {
    vi.mocked(detectWebGLAvailability).mockReturnValue(true);
    render(<CommandTheater demoMode />);

    expect(await screen.findByRole("group", { name: /2D intelligence relationship map/i })).toBeInTheDocument();
    const threeDButton = screen.getByRole("button", { name: "3D theater" });
    await waitFor(() => expect(threeDButton).toBeEnabled());
    expect(screen.queryByTestId("mock-3d-theater")).not.toBeInTheDocument();

    fireEvent.click(threeDButton);
    expect(await screen.findByTestId("mock-3d-theater")).toBeInTheDocument();
  });

  it("returns to 2D after a runtime WebGL failure", async () => {
    vi.mocked(detectWebGLAvailability).mockReturnValue(true);
    render(<CommandTheater demoMode />);

    const threeDButton = screen.getByRole("button", { name: "3D theater" });
    await waitFor(() => expect(threeDButton).toBeEnabled());
    fireEvent.click(threeDButton);
    fireEvent.click(await screen.findByRole("button", { name: "simulate WebGL failure" }));

    expect(screen.getByRole("group", { name: /2D intelligence relationship map/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "2D map" })).toHaveFocus();
    expect(screen.getByText(/3D is unavailable/i)).toBeInTheDocument();
  });

  it("announces WebGL context loss and restores focus to the 2D view", async () => {
    vi.mocked(detectWebGLAvailability).mockReturnValue(true);
    render(<CommandTheater demoMode />);

    const threeDButton = screen.getByRole("button", { name: "3D theater" });
    await waitFor(() => expect(threeDButton).toBeEnabled());
    fireEvent.click(threeDButton);
    fireEvent.click(await screen.findByRole("button", { name: "simulate WebGL context loss" }));

    expect(screen.getByRole("group", { name: /2D intelligence relationship map/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "2D map" })).toHaveFocus();
    expect(screen.getByText(/The WebGL context was lost/i)).toBeInTheDocument();
  });

  it("falls back to 2D if the lazy 3D scene throws during initialization", async () => {
    vi.mocked(detectWebGLAvailability).mockReturnValue(true);
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    render(<CommandTheater demoMode />);

    const threeDButton = await screen.findByRole("button", { name: "3D theater" });
    await waitFor(() => expect(threeDButton).toBeEnabled());
    theaterMock.throwsOnRender = true;
    fireEvent.click(threeDButton);

    expect(await screen.findByRole("group", { name: /2D intelligence relationship map/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "2D map" })).toHaveFocus();
    expect(screen.getByText(/3D is unavailable/i)).toBeInTheDocument();
    consoleError.mockRestore();
  });

  it("preserves per-record verification, evidence, provenance, and assessment basis", async () => {
    const node = backendNode("node-1", "Threat indicator", "domain");
    const source = backendSource(vi.fn(async () => backendPage(
      [node],
      [],
      { totalNodes: 1, totalRelationships: 0 },
    )));
    render(<CommandTheater dataSource={source} />);

    expect((await screen.findAllByText("CONFIGURED DATA SOURCE")).length).toBeGreaterThan(0);
    expect(screen.getAllByText("Verified").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/analyst assessment; not factual certainty/i).length).toBeGreaterThan(0);
    expect(screen.getByText("Controlled integration fixture")).toBeInTheDocument();
    expect(screen.getByText("record-node-1")).toBeInTheDocument();
    expect(screen.getByText("Analyst-reviewed source note")).toBeInTheDocument();
    expect(screen.queryByText(/Synthetic sample only/)).not.toBeInTheDocument();
  });

  it("passes server-side filters to the provider", async () => {
    const node = backendNode("node-1", "example.net", "domain");
    const loadPage = vi.fn(async (_request: GraphPageRequest, _signal: AbortSignal) =>
      backendPage([node], [], { totalNodes: 1, totalRelationships: 0 }),
    );
    render(<CommandTheater dataSource={backendSource(loadPage)} />);

    await screen.findAllByText("CONFIGURED DATA SOURCE");
    fireEvent.change(screen.getByRole("searchbox", { name: "Search entities and relationships" }), {
      target: { value: "example.net" },
    });
    fireEvent.change(screen.getByRole("combobox", { name: "Entity type filter" }), {
      target: { value: "domain" },
    });
    fireEvent.change(screen.getByRole("combobox", { name: "Relationship type filter" }), {
      target: { value: "uses" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));

    await waitFor(() => expect(loadPage).toHaveBeenCalledTimes(2));
    expect(loadPage.mock.calls[1]?.[0]).toEqual({
      cursor: null,
      limit: 250,
      filters: { search: "example.net", entityType: "domain", relationshipType: "uses" },
    });
  });

  it("continues from an empty cursor page instead of leaving the theater blank", async () => {
    const entity = backendNode("entity-after-empty-page", "Entity after empty page");
    const loadPage = vi.fn(async (request: GraphPageRequest) =>
      request.cursor === null
        ? backendPage([], [], { nextCursor: "opaque-page-2", totalNodes: 1, totalRelationships: 0 })
        : backendPage([entity], [], { totalNodes: 1, totalRelationships: 0 }),
    );
    render(<CommandTheater dataSource={backendSource(loadPage)} />);

    expect(await screen.findByText("This page contains no graph records; load the next page to continue.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Load more graph records" }));

    const entityList = await screen.findByRole("list", { name: /Entities/ });
    expect(within(entityList).getByRole("button", { name: /Entity after empty page/ })).toBeInTheDocument();
    expect(loadPage).toHaveBeenCalledTimes(2);
  });

  it("rejects a non-advancing cursor instead of allowing an endless page loop", async () => {
    const entity = backendNode("entity-1", "Entity one");
    const loadPage = vi.fn(async (request: GraphPageRequest) =>
      backendPage(
        [entity],
        [],
        {
          nextCursor: request.cursor === null ? "same-cursor" : "same-cursor",
          totalNodes: 1,
          totalRelationships: 0,
        },
      ),
    );
    render(<CommandTheater dataSource={backendSource(loadPage)} />);

    const entityList = await screen.findByRole("list", { name: /Entities/ });
    fireEvent.click(screen.getByRole("button", { name: "Load more graph records" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/invalid graph response/i);
    expect(within(entityList).getByRole("button", { name: /Entity one/ })).toBeInTheDocument();
    expect(loadPage).toHaveBeenCalledTimes(2);
  });

  it("preserves an in-session investigation trail with back, forward, and branch navigation", async () => {
    render(<CommandTheater demoMode />);

    const entityList = await screen.findByRole("list", { name: /Entities/ });
    const actor = within(entityList).getByRole("button", { name: /Demo threat actor/ });
    const campaign = within(entityList).getByRole("button", { name: /Demo campaign/ });
    const domain = within(entityList).getByRole("button", { name: /example.net/ });
    const asset = within(entityList).getByRole("button", { name: /Demo research workstation/ });
    const previous = screen.getByRole("button", { name: "Previous entity in investigation" });
    const next = screen.getByRole("button", { name: "Next entity in investigation" });

    await waitFor(() => expect(screen.getByText("Step 1 of 1.")).toBeInTheDocument());
    fireEvent.click(campaign);
    fireEvent.click(domain);
    expect(domain).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("Step 3 of 3.")).toBeInTheDocument();

    fireEvent.click(previous);
    expect(campaign).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("Step 2 of 3.")).toBeInTheDocument();
    fireEvent.click(next);
    expect(domain).toHaveAttribute("aria-pressed", "true");

    fireEvent.click(previous);
    fireEvent.click(asset);
    expect(asset).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("Step 3 of 3.")).toBeInTheDocument();
    expect(next).toBeDisabled();
    expect(actor).toHaveAttribute("aria-pressed", "false");
  });

  it("caps the in-session investigation trail at 50 selected entities", async () => {
    const nodes = Array.from({ length: 55 }, (_, index) =>
      backendNode(`entity-${index}`, `Entity ${index}`),
    );
    const source = backendSource(vi.fn(async () => backendPage(nodes)));
    render(<CommandTheater dataSource={source} />);

    const entityList = await screen.findByRole("list", { name: /Entities/ });
    fireEvent.click(await screen.findByRole("button", { name: /Show more entities/ }));
    await waitFor(() => expect(screen.getByText("Step 1 of 1.")).toBeInTheDocument());

    for (let index = 1; index <= 50; index += 1) {
      fireEvent.click(within(entityList).getByRole("button", { name: new RegExp(`^Entity ${index},`) }));
    }

    expect(screen.getByText("Step 50 of 50.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Previous entity in investigation" }));
    expect(screen.getByText("Step 49 of 50.")).toBeInTheDocument();
  });

  it("loads cursor pages without losing nodes and never falls back to demo data on failure", async () => {
    const actor = backendNode("actor-1", "Threat actor", "threat-actor");
    const domain = backendNode("domain-1", "example.org", "domain");
    const incident = backendNode("incident-1", "Incident 1", "incident");
    const first = backendPage(
      [actor, domain],
      [backendRelationship("edge-1", actor.id, domain.id)],
      { nextCursor: "opaque-page-2", totalNodes: 3, totalRelationships: 2 },
    );
    const second = backendPage(
      [incident],
      [backendRelationship("edge-2", domain.id, incident.id)],
      { totalNodes: 3, totalRelationships: 2 },
    );
    const loadPage = vi.fn(async (request: GraphPageRequest) =>
      request.cursor === null ? first : second,
    );
    render(<CommandTheater dataSource={backendSource(loadPage)} />);

    const relationshipList = await screen.findByRole("list", { name: /Relationships/ });
    expect(within(relationshipList).getAllByRole("listitem")).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Load more graph records" }));

    await waitFor(() => expect(within(relationshipList).getAllByRole("listitem")).toHaveLength(2));
    expect(loadPage.mock.calls[1]?.[0].cursor).toBe("opaque-page-2");
    expect(screen.getAllByText("Incident 1").length).toBeGreaterThan(0);
  });

  it("shows provider errors instead of using synthetic samples", async () => {
    const source = backendSource(vi.fn(async () => {
      throw new Error("sensitive implementation details must not reach the UI");
    }));
    render(<CommandTheater dataSource={source} />);

    expect(await screen.findByRole("alert")).toHaveTextContent(/No synthetic data was substituted/i);
    expect(screen.queryByText("Demo threat actor")).not.toBeInTheDocument();
    expect(screen.queryByText(/sensitive implementation details/)).not.toBeInTheDocument();
  });

  it("applies Arabic and Persian direction and translated verification labels", async () => {
    render(<CommandTheater locale="ar" demoMode />);

    const theater = screen.getByRole("region", { name: "مسرح قيادة الاستخبارات" });
    expect(theater).toHaveAttribute("dir", "rtl");
    expect((await screen.findAllByText(/توضيحية فقط/)).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "الكيان السابق في التحقيق" })).toBeDisabled();

    fireEvent.change(screen.getByRole("combobox", { name: "لغة الواجهة" }), {
      target: { value: "fa" },
    });

    expect(theater).toHaveAttribute("lang", "fa");
    expect(theater).toHaveAttribute("dir", "rtl");
    expect(screen.getByRole("heading", { name: "تالار فرماندهی اطلاعات" })).toBeInTheDocument();
    expect((await screen.findAllByText(/صرفاً نمایشی/)).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "موجودیت پیشین در بررسی" })).toBeDisabled();
  });

  it("creates unique accessible ids for multiple embedded theaters", async () => {
    render(
      <>
        <CommandTheater demoMode />
        <CommandTheater demoMode />
      </>,
    );

    const regions = await screen.findAllByRole("region", { name: "Intelligence Command Theater" });
    expect(regions).toHaveLength(2);
    const ids = regions.map((region) => region.getAttribute("aria-labelledby"));
    expect(new Set(ids).size).toBe(2);
  });
});
