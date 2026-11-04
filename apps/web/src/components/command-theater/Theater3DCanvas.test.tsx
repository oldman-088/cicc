import type { ReactNode } from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { DEMO_NODES, DEMO_RELATIONSHIPS } from "./demo-graph";
import { Theater3DCanvas } from "./Theater3DCanvas";

vi.mock("@react-three/fiber", () => ({
  Canvas: ({ fallback }: { fallback: ReactNode }) => <>{fallback}</>,
}));

vi.mock("@react-three/drei", () => ({
  Html: "div",
  Line: "line",
  OrbitControls: "div",
}));

describe("Theater3DCanvas", () => {
  it("surfaces a localized, screen-reader-visible 2D fallback when WebGL cannot start", async () => {
    const onFallback = vi.fn();
    render(
      <Theater3DCanvas
        nodes={DEMO_NODES}
        relationships={DEMO_RELATIONSHIPS}
        selectedNodeId="actor-demo"
        locale="ar"
        onSelectNode={vi.fn()}
        onFallback={onFallback}
      />,
    );

    expect(await screen.findByRole("alert")).toHaveTextContent("تعذّر إنشاء سياق WebGL");
    fireEvent.click(screen.getByRole("button", { name: "الانتقال إلى الخريطة ثنائية الأبعاد" }));
    expect(onFallback).toHaveBeenCalledOnce();
  });
});
