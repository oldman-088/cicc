# Command Theater data integration contract

## Current repository findings

The checked-out repository contains a Next.js/React frontend only. There are no backend applications, API routes, OpenAPI documents, generated clients, or configured data-source services in this checkout. No endpoint or server payload is assumed by Command Theater. A host CICC team must provide and own the adapter described below after its real contract is confirmed.

## Frontend adapter boundary

`CommandTheaterDataSource` in `types.ts` is a **frontend presentation contract**, not a claim about a backend schema. A host should pass a stable, memoized adapter to `<CommandTheater dataSource={source} />`. The adapter owns authentication-aware transport and maps verified backend contracts to `GraphPage`.

`loadPage(request, signal)` receives:

- An opaque cursor (`null` for the first page), a bounded page limit, and normalized search/entity-type/relationship-type filters.
- An `AbortSignal`; adapters must pass it to their transport and treat aborts as cancellation, not user-visible errors.
- A `GraphPage` containing presentation-layer nodes and relationships, an opaque next cursor, and optional authoritative totals.

Filtering is expected to happen in the adapter/backend **before pagination**. Each relationship returned must reference nodes present in the current page or an earlier page; return endpoint node summaries when necessary. The UI merges pages by record ID, validates them at runtime, preserves previous layout coordinates for repeated node IDs, and reports invalid/dangling data rather than silently dropping it.

## Record semantics

- `verificationStatus` is separate from `confidence.basis`. A backend record can be verified while a confidence estimate is still an assessment, not objective truth.
- `provenance` preserves source name, source record ID, collection time, and publication time when available. Missing provenance is represented as `null`, never filled with a fabricated source.
- `evidence` contains only references returned by the adapter, each with its own source, verification state, and observation timestamp. The UI does not create evidence or infer verification.
- Confidence values are normalized to `[0, 1]`; the runtime boundary rejects invalid values. Use `basis: "unavailable"` with a `null` value if the source supplies no score.
- Optional positions are view-layout hints, not intelligence facts. If absent, a deterministic golden-angle spiral placement is assigned for display only; it conveys no analytic significance.
- IDs and labels render as text (React escaping); the contract intentionally does not accept arbitrary HTML or evidence URLs. A future link field needs a separate URL allowlist/security review.

## Demo isolation and failure behavior

The app route explicitly enables `demoMode` only when `NODE_ENV` is `development`. The demo provider and fixture graph are dynamically imported only for that explicit mode. Production defaults to an accessible “no provider configured” state. When an injected backend provider fails or returns invalid data, Command Theater shows an error and retry action; it never substitutes demo records. Demo records are also visibly marked synthetic, and their confidence basis remains `illustrative`.

## Visualization limits and interaction

Both renderers use the same selected-entity-prioritized slice policy: at most 250 entities and 250 relationships per view. The 3D slice is computed by `CommandTheater` only when 3D mode is active and passed into the canvas; the canvas does not repeat the full-graph selection pass. The 2D renderer computes its own slice once and reports omitted records, while the accessible explorer retains paginated access to all records loaded so far. A lifecycle-managed `webglcontextlost` listener switches the parent back to 2D, announces the specific failure in the selected locale, and cleans up on unmount. Automated tests simulate the event and cleanup; actual GPU/context-loss behavior still requires browser verification.

When an `onSelectNode` handler is supplied, 2D map entities are actionable buttons with a single roving tab stop, related-entity arrow navigation, Home/End navigation, Enter/Space activation, and RTL-aware horizontal arrows. Without a selection handler, the SVG remains a descriptive static image. The entity list remains the primary accessible route to metadata and works independently of WebGL.

The explorer keeps a bounded, in-memory 50-step selection trail with back/forward and branch truncation. It seeds context from the initial selected entity and resets when filters or the provider change. This is local UI navigation state only; it is not persisted, synchronized, or represented as a backend investigation record.

## Not implemented / requires coordination

- There is no real CICC backend contract or adapter in this repository; production data is therefore **not connected**.
- Authentication, tenant scoping, authorization, API caching, and transport policy belong to the host application/BFF and must be verified before connecting operational data. Do not expose service credentials in browser code.
- The contract currently supports cursor pagination and server-side filters. A push/WebSocket subscription is intentionally not invented; add it only after the owning backend team confirms an incremental-update contract and lifecycle/auth requirements.
- Automated tests use controlled fixtures. They do not verify a live endpoint or production authorization behavior.
