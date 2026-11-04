import type { ReactNode } from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { DEMO_NODES, DEMO_RELATIONSHIPS } from "./demo-graph";
import { Theater3DCanvas } from "./Theater3DCanvas";

const canvasState = vi.hoisted(() => ({ throwsOnMount: false }));

vi.mock("@react-three/fiber", () => ({
  Canvas: ({ fallback }: { fallback: ReactNode }) => {
    if (canvasState.throwsOnMount) throw new Error("WebGL initialization failed");
    return <>{fallback}</>;
  },
}));

vi.mock("@react-three/drei", () => ({
  Html: "div",
  OrbitControls: "div",
}));

describe("Theater3DCanvas", () => {
  beforeEach(() => {
    canvasState.throwsOnMount = false;
  });

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
    expect(onFallback).toHaveBeenCalledOnce();
    fireEvent.click(screen.getByRole("button", { name: "الانتقال إلى الخريطة ثنائية الأبعاد" }));
    expect(onFallback).toHaveBeenCalledTimes(2);
  });

  it("catches a scene initialization exception and requests the 2D fallback", async () => {
    canvasState.throwsOnMount = true;
    const onFallback = vi.fn();
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});

    render(
      <Theater3DCanvas
        nodes={DEMO_NODES}
        relationships={DEMO_RELATIONSHIPS}
        selectedNodeId="actor-demo"
        locale="en"
        onSelectNode={vi.fn()}
        onFallback={onFallback}
      />,
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(/WebGL context could not be created/i);
    expect(onFallback).toHaveBeenCalledOnce();
    consoleError.mockRestore();
  });
});
