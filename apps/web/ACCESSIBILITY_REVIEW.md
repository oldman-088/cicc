# CICC frontend accessibility review

**Review type:** automated component-level checks plus outstanding manual checklist · **Updated:** 2026-11-05

## Scope and claim boundary

This is a working review, not a conformance statement. JSDOM and axe-core cannot establish real color contrast, browser layout, screen-reader quality, GPU behavior, zoom/reflow, or assistive-technology support. No WCAG conformance claim is made. Manual browser/device and screen-reader testing has **not** been completed in this task.

## Implemented foundations

- One shared shell with a skip-to-main link, a single main landmark, labeled breadcrumb/primary navigation, `aria-current` route state, a responsive button with `aria-expanded`/`aria-controls`, and a page-only search field with a clear scope description.
- EN/AR/FA UI labels, runtime document `lang`/`dir` updates, and page-level direction. English is LTR; Arabic/Persian are RTL. CSS generally uses logical properties; selected arrows are direction-aware.
- Native links, selects, checkbox, input, heading levels, fieldset/legend, and semantic `status`/`alert` behavior where applicable.
- Global `:focus-visible` outline; forced-colors focus outline; system `prefers-reduced-motion` handling; an additional app-level reduced-motion option that can only reduce movement.
- Command Theater has an accessible entity explorer alongside the graph, keyboard map selection/roving focus, RTL-aware horizontal navigation, bounded selection history, labeled filters, and a 2D fallback if graphics initialization/context fails.
- Domain shells explicitly describe absent integrations rather than rendering fake data. Settings explicitly states unsupported account/tenant controls.

## Automated checks (not manual validation)

The current suite uses Vitest, React Testing Library, JSDOM, and axe-core. Most recent pass: **60 tests across 13 test files**; the typecheck passed. Axe structural checks cover the shell, overview, settings, unconfigured module state, and selected Command Theater states. In those tests the `color-contrast` rule is explicitly disabled because JSDOM does not provide the needed rendered color/canvas environment. Tests of simulated WebGL/context loss use mocks and do not prove real GPU behavior.

Automated coverage includes:

- Route links, current-page state, page-only filtering/search scope, skip link, mobile navigation semantics, and EN/AR/FA labels.
- Document direction and locale coordination between the shell and Command Theater.
- Settings changes for locale and the local reduced-motion preference.
- Clear no-provider language on overview and module shells.
- Command Theater 2D keyboard navigation, selection, pagination/request failures, and mocked graphics fallback paths.

Axe results are automated structural findings only; they do not establish WCAG conformance or substitute for expert review.

## Manual verification status

| Check | Status | Notes |
| --- | --- | --- |
| Keyboard-only navigation across every route | Not performed in a real browser | Component tests cover selected controls only |
| Visible focus over actual surfaces and all UI states | Not performed | CSS focus tokens exist; rendered contrast unknown |
| Text, non-text, focus, and status color contrast | Not performed | Axe contrast rule disabled in JSDOM |
| Browser zoom, text resize, and 320px reflow | Not performed | CSS has responsive breakpoints; no device/browser evidence |
| AR/FA RTL layout, bidi identifiers, punctuation and numbers | Not performed | Unit checks verify selected direction attributes only |
| NVDA/JAWS/VoiceOver/TalkBack output | Not performed | No screen-reader session recorded |
| Forced-colors/high-contrast mode | Not performed | Focus rule exists; no browser validation |
| OS/app reduced motion and actual animation behavior | Not performed | CSS and preference signal are tested only structurally |
| Real WebGL unavailable/loss/recovery and focus restoration | Not performed on GPU/browser | JSDOM event simulation only |
| Fluent-speaker review of translations | Not performed | EN/AR/FA copy is present in code |

## Outstanding risks and follow-up

1. Measure actual text, badge, focus-ring, and control contrast against every dark surface; adjust tokens/semantic colors and retest in browsers.
2. Manually traverse the routes with keyboard only, checking skip target, search filtering, focus retention, RTL sequence, 2D graph roving focus, history, error/retry, and 3D fallback.
3. Test at 320px, 200% zoom, large text, and narrow/tablet widths with long Arabic/Persian strings and mixed-script IDs; ensure no clipped controls or horizontal page scrolling.
4. Have fluent speakers review localized terminology. Test actual screen-reader output for route changes, translated controls, data status, graph relationships, and errors.
5. Verify forced colors and both OS-level and app-level reduced motion on real browsers. Confirm no animation is needed to understand status.
6. Use a browser/GPU-enabled environment to verify real WebGL context loss, recovery/fallback, focus restoration, and 2D/3D parity.
7. Keep future live status accessible as text plus icon/shape, never color only, and expose freshness/provenance when a verified API supplies it.

Record browser/device/AT, version, viewport, locale, steps, result, and artifacts in follow-up work. Do not replace “Not performed” with “pass” based on a unit test or HTTP response.
