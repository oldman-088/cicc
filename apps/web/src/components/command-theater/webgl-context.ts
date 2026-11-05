export function subscribeToWebGLContextLoss(
  canvas: HTMLCanvasElement,
  onContextLost: () => void,
): () => void {
  const handleContextLost = (event: Event) => {
    event.preventDefault();
    onContextLost();
  };

  canvas.addEventListener("webglcontextlost", handleContextLost);
  return () => canvas.removeEventListener("webglcontextlost", handleContextLost);
}
