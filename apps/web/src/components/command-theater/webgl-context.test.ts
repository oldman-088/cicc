import { describe, expect, it, vi } from "vitest";
import { subscribeToWebGLContextLoss } from "./webgl-context";

describe("WebGL context lifecycle", () => {
  it("prevents default context loss and removes its listener during cleanup", () => {
    const canvas = document.createElement("canvas");
    const onContextLost = vi.fn();
    const unsubscribe = subscribeToWebGLContextLoss(canvas, onContextLost);
    const firstEvent = new Event("webglcontextlost", { cancelable: true });

    canvas.dispatchEvent(firstEvent);
    expect(firstEvent.defaultPrevented).toBe(true);
    expect(onContextLost).toHaveBeenCalledOnce();

    unsubscribe();
    canvas.dispatchEvent(new Event("webglcontextlost", { cancelable: true }));
    expect(onContextLost).toHaveBeenCalledOnce();
  });
});
