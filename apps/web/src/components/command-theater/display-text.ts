// Directional formatting controls supplied inside external labels can visually
// reorder or spoof adjacent identifiers. Keep record values intact in the model,
// but strip invisible overrides/embeddings at the presentation boundary.
const UNSAFE_BIDI_CONTROLS = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u206f]/gi;

export function safeDisplayText(value: string): string {
  return value.replace(UNSAFE_BIDI_CONTROLS, "");
}
