# Command Theater engineering log and backlog

Updated: 2026-11-04

## Current implementation status

The active feature branch is `arena/09952395-cicc`. Command Theater has a typed, injected frontend data-source boundary with runtime validation, cursor pagination, retry/cancellation handling, metadata presentation, and explicit synthetic-demo isolation. This is an integration boundary, not a live CICC backend connection.

The 2D map supports selection by pointer and keyboard, roving focus, linked-entity arrow navigation, Home/End, Enter/Space, localized labels, and RTL-aware horizontal navigation. Selection is shared with the accessible entity explorer and 3D scene. WebGL initialization failure and simulated context loss return focus to the 2D control; the context-loss listener is cleaned up when the canvas unmounts and the failure is announced in the active locale. A bounded, in-memory 50-step selection history supports back/forward and truncates forward history after a new branch; it resets when the provider or filters change and is not a persisted investigation record.

The fallback layout uses a deterministic golden-angle spiral with a low-amplitude display-only depth variation; adapter-supplied positions remain authoritative. Coordinates do not encode intelligence significance.

For performance, the 2D renderer computes its bounded view once. The parent computes the selected-entity-prioritized slice only while 3D is active and passes it to the canvas, avoiding a second full-graph selection pass there. Both renderers are capped at 250 entities and 250 relationships; accessible entity and relationship lists reveal 50 items at a time.

## Measurements and automated verification

Synthetic Node v22.22.3 CPU measurements in this workspace:

- Golden-angle `layoutGraphNodes` with 10,000 nodes: 7 measured runs after 2 warm-ups; 3.10 ms median (0.73 ms min, 4.00 ms max). Positions spanned x=8.01–91.92 and y=12.08–87.92 with 10,000 distinct 0.1-unit XY buckets.
- `selectGraphView` with 10,000 nodes and 50,001 relationships, returning 250 nodes and 250 relationships: 7 measured runs after 2 warm-ups; 6.37 ms median (5.42 ms min, 7.65 ms max).

These are isolated CPU microbenchmarks, not browser interaction latency, memory profiling, WebGL frame-time, or GPU measurements.

Current automated results: TypeScript typecheck passes; 41 tests across 8 files pass; production build passes; `npm audit --omit=dev --audit-level=high` reports 0 vulnerabilities. Tests cover axe-core structural/accessibility rules (color contrast excluded because jsdom lacks a canvas implementation), RTL/LTR keyboard selection, bounded 50-step selection history, simulated context-loss listener cleanup, focus after 3D fallback, cursor failure paths, and 10,000-node/50,000-edge stress fixtures. Real-browser, GPU/context-loss, contrast, and manual screen-reader verification remain outstanding.

## Prioritized backlog

### 1. Real-browser and assistive-technology verification — environment-dependent

Use a browser/GPU-enabled environment to verify responsive layouts, actual SVG focus outlines and screen-reader output, 3D interaction parity, context-loss degradation, recovery behavior, and color contrast. Keep these results separate from jsdom/fixture-based tests.

### 2. Real backend adapters — blocked on verified contracts

The checkout contains only `apps/web`; no backend/API routes, OpenAPI documents, generated clients, or service contracts are present. Integrations for Threat Intelligence, Vulnerability Intelligence, Investigations, and System Health remain unconnected. Implement mappings only after owners provide verified contracts for IDs, entity/relationship semantics, pagination/filter behavior, provenance/evidence, authentication, and tenant scoping. Do not invent endpoints or payloads.

### 3. Incremental updates — contract-dependent

The current provider contract is request/page based. Add subscriptions or refresh/update handling only when the backend confirms ordering/version semantics, deletes, reconnect behavior, authorization, and lifecycle guarantees. Do not simulate live data as operational status.

### 4. Scale and memory policy

Graph records accumulate as pages are loaded while rendering is bounded. Before introducing client-side retention or truncation, agree on a query/window or neighborhood contract with the data-source owner so the UI does not silently discard investigation context. Add explicit limits and user-visible continuation behavior when that contract exists.

### 5. Operational integration prerequisites

RabbitMQ monitoring/worker heartbeats, PostgreSQL verification, authentication/tenant isolation, system-health alerting, and Docker/Compose validation belong to backend/operations ownership and have no implementation in this checkout. Coordinate through their confirmed interfaces; do not create duplicate services or shared migrations from this feature branch.
