# CICC frontend performance report

**Status:** limited frontend/Node evidence; no browser profile · **Updated:** 2026-11-05

## Evidence boundary

This report contains isolated CPU microbenchmarks from Command Theater and implementation-level bounds. It does **not** contain Lighthouse/Core Web Vitals, browser route/hydration timings, bundle sizes, memory profiles, network/API latency, browser long-task measurements, WebGL frame rate, GPU cost, or device testing. No production performance target has been invented, and the historical microbenchmarks are not a browser UX guarantee.

## Recorded Node CPU microbenchmarks

Environment: Node.js `v22.22.3`. Each value is the median of 7 measured runs after 2 warm-up runs.

| Operation | Input | Result | What it does not measure |
| --- | --- | --- | --- |
| `layoutGraphNodes` (`graph-layout.ts`) | 10,000 nodes | **3.10 ms median** (0.73 ms min, 4.00 ms max) | Layout paint, browser main-thread contention, DOM/SVG cost, memory, or GPU |
| `selectGraphView` (`graph-view.ts`) | 10,000 nodes and 50,001 relationships; returns at most 250 nodes and 250 relationships | **6.37 ms median** (5.42 ms min, 7.65 ms max) | Query/network time, React commit, frame time, 3D/GPU cost, or user-perceived interaction latency |

The timing inputs are synthetic stress fixtures, not a measured production corpus. They should be rerun when the implementation, Node version, or graph policy changes.

## Current implementation controls

- Both 2D and 3D visualizations are bounded to at most 250 entities and 250 relationships. The 3D view slice is computed by the parent only while 3D is active and supplied to the canvas; the canvas does not repeat the full selection pass.
- The accessible explorer paginates records already loaded by the provider and reveals 50 items at a time.
- The golden-angle fallback layout is deterministic and display-only; supplied presentation positions remain authoritative. Coordinates do not encode significance.
- The 3D canvas is loaded dynamically without SSR and is optional; the 2D graph and entity explorer remain usable when WebGL is unavailable.
- Provider page requests are limited to 250 records and support abort/cancellation; runtime validation rejects invalid graph data. A failed provider request never activates the demo source.
- The app shell and overview use CSS Grid/Flexbox, capped content widths, responsive breakpoints at 960px and 640px, and reduced-motion styles. These are code characteristics, not measured frame/latency results.

## Known trade-offs / unmeasured areas

- Loaded graph pages accumulate in app memory while each visualization slice is bounded. Retention/windowing cannot be chosen safely without a verified backend query/window contract, so memory behavior beyond current synthetic tests remains unknown.
- Next.js route splitting is present, and the 3D scene is dynamically imported, but emitted chunk sizes have not been measured. No claim is made about the total JS transfer or route hydration cost.
- The development server can return HTML for routes, but an HTTP 200 is not a performance or visual-quality measurement.
- No browser or GPU profile has verified dense SVG behavior, 3D context loss, low-end devices, long tasks, or responsive reflow.

## Measurement plan

When a reproducible browser environment and approved provider are available, capture separately:

1. Build output and route-level JS/CSS transfer sizes (production build, cold/warm cache, compression).
2. Browser navigation, hydration, and interaction timings for overview, settings, all shells, and Command Theater.
3. Main-thread long tasks, memory growth across pages, graph commit/paint time, and 2D/3D frame pacing on named reference devices.
4. Network request/response times only against an approved environment and real contract; distinguish server latency, client processing, and rendering.
5. Responsive viewport and locale profiles (EN/AR/FA), including 320px and large-screen cases.

Record browser/version, device/CPU/GPU, viewport, fixture/live status, sample count, and warm/cold conditions. Until those observations exist, keep the above “unmeasured” statements intact and do not turn Node timings into user-facing SLA claims.
