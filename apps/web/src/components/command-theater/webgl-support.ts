export function detectWebGLAvailability(): boolean {
  if (typeof document === "undefined") return false;

  try {
    const canvas = document.createElement("canvas");
    const context = (
      canvas.getContext("webgl2") ??
      canvas.getContext("webgl") ??
      canvas.getContext("experimental-webgl")
    ) as WebGLRenderingContext | null;

    if (!context) return false;

    // Release the probe context so the detector does not consume a browser's
    // limited WebGL context budget before the selected scene is mounted.
    const loseContext = context.getExtension("WEBGL_lose_context");
    loseContext?.loseContext();
    return true;
  } catch {
    return false;
  }
}
