# CICC design system

**Status:** initial shared system · **Updated:** 2026-11-05

## Design intent

CICC uses an original, dark, high-density analyst workspace. The visual language uses restrained blue-teal accents, layered navy surfaces, amber for attention/unconfigured conditions, and clear text hierarchy. It is not a copy of OpenCTI, MISP, OpenCTEM, Wazuh, or another product's brand/assets. External products were studied only for general information architecture and interaction patterns; license notes are in `DEVELOPMENT_LOG.md`.

The product may show an empty, unavailable, cached, demo, live, or unverified data state only when the interface can substantiate that state. A status is not represented by color alone, and unconnected modules do not display sample cards that look like operational records.

## Global tokens

Defined in `src/app/globals.css`. CSS Modules should prefer these values; a number of component-level color values remain intentionally explicit and are candidates for consolidation.

| Token | Current value | Purpose |
| --- | --- | --- |
| `--cicc-canvas` | `#07101b` | App page background |
| `--cicc-surface` | `#0c1927` | Main panels and controls |
| `--cicc-surface-raised` | `#0f2030` | Hover/raised panel surface |
| `--cicc-surface-inset` | `#091724` | Inset area |
| `--cicc-border` | `#20364b` | Primary component border |
| `--cicc-border-subtle` | `#1c3044` | Structural separators |
| `--cicc-text` | `#e7f0ff` | Primary text |
| `--cicc-text-strong` | `#f4f8ff` | High-emphasis text |
| `--cicc-text-muted` | `#9aacc2` | Secondary text |
| `--cicc-accent` | `#70d7dd` | Primary teal accent |
| `--cicc-info` | `#8fc6ff` | Informational semantic token |
| `--cicc-success` | `#7eddd4` | Success semantic token; use only for source-backed success |
| `--cicc-warning` | `#ffd28b` | Attention / not-configured emphasis |
| `--cicc-danger` | `#f2c4ba` | Error semantic token |
| `--cicc-focus` | `#f3bf68` | Keyboard focus outline |
| `--cicc-font-sans` | system sans stack (Inter fallback first) | Interface text |
| `--cicc-font-mono` | system monospace stack | IDs/technical values where appropriate |
| `--cicc-content-regular` | `1320px` | Overview and standard page maximum width |
| `--cicc-content-wide` | `1560px` | Wide investigation surfaces |
| `--cicc-sidebar-width` | `16rem` | Desktop shell navigation |
| `--cicc-topbar-height` | `4.25rem` | Desktop top bar |

Spacing tokens: `--cicc-space-1/2/3/4/6/8` = `0.25/0.5/0.75/1/1.5/2rem`. Radius tokens: `--cicc-radius-sm/md/lg` = `0.55/0.85/1rem`. `--cicc-shadow-panel` is reserved for restrained panel elevation. Responsive component rules may use fluid `clamp()` values.

## Typography and layout

- Base body text is 14px with a 1.5 line-height. Page titles scale with `clamp()`; headings emphasize hierarchy instead of oversized dashboards.
- Prefer system font fallbacks; no remote font request or proprietary font asset is required. Numeric/technical identifiers may use the monospace token, but mixed-direction IDs should be isolated with `<bdi>`/explicit direction.
- Layout uses CSS Grid/Flexbox and logical properties (`margin-inline`, `padding-block`, `inset-inline`) so AR/FA direction changes flow without duplicating entire layouts.
- Shell breakpoints are 960px (desktop sidebar becomes a collapsible navigation region) and 640px (compact top bar and content padding). The document supports a minimum 320px layout width; browser zoom and reflow still require manual review.
- Content widths are capped, long text wraps, and cards use a responsive auto-fit grid rather than fixed desktop columns.

## Components and states

- **Application shell:** sticky top bar, brand mark, breadcrumb, global language control, responsive navigation, page-only route filter, skip link, and a single main landmark. The current route receives `aria-current="page"`.
- **Overview card:** whole-card navigation, title + described-by text, and a visible state badge; CT demo is explicitly labeled synthetic in development. The remaining domain cards state that their provider is not connected.
- **Unavailable module panel:** warning-toned integration message, plain-language explanation, explicit “planned/not yet available” scope, and a route back to the overview. It shows no record-shaped fixtures.
- **Settings:** labeled locale selector, keyboard-accessible motion checkbox, explanation of local/session persistence, and a separate notice for unsupported account/tenant controls.
- **Command Theater:** shared 2D/3D relationship view, filter and metadata panels, bounded graph rendering, accessible explorer, provider/error/empty states. Detail is maintained in the Command Theater component and integration docs.
- **Focus:** global `:focus-visible` outline is 3px with offset; forced-colors mode uses a system-color outline. Do not remove focus indicators to make hover states look cleaner.
- **Motion:** default interactions are restrained. `prefers-reduced-motion` is respected; the app-level option can further reduce animation and is never an override that forces motion.

## Localization and direction

Supported locale identifiers are `en`, `ar`, and `fa`. English is LTR; Arabic and Persian are RTL. Keep translated strings in typed per-locale maps, use logical CSS, preserve browser-native select behavior, isolate Latin identifiers, and test long labels and punctuation. Language switching is session-only today; it does not imply account preference persistence or a translated backend.

## Status color use

Color is supplemental, not the only status cue. Pair semantic color with a textual badge/message and appropriate icon/landmark where useful. Do not use the “success” token to imply system health in the absence of a verified source. A warm warning panel currently denotes missing integration, not a degraded production service.

## Accessibility and visual verification limits

Automated axe-core structure checks run in jsdom with the color-contrast rule disabled. The token set and CSS do not by themselves establish WCAG contrast. Actual color contrast, focus geometry, zoom/reflow, RTL browser behavior, motion, forced colors, and screen-reader output must be validated in browsers and assistive technologies; this checkout has not completed that manual review. See `ACCESSIBILITY_REVIEW.md`.
