# CICC frontend UX guidelines

**Status:** active guidance for the current alpha · **Updated:** 2026-11-05

## 1. Tell the truth about data

Treat integration state as part of the product experience, not a footnote.

| State | Meaning | Required UI behavior |
| --- | --- | --- |
| **Not integrated** | No reviewed provider/adapter is wired into this frontend | Say so directly; explain the missing contract; show no record-shaped placeholders or retry action that cannot work |
| **Provider not configured** | A reviewed adapter exists, but this deployment lacks the server-side URL and credential/trusted-mode acknowledgement | Say the deployment is unconfigured; do not call it an outage or empty result; offer retry only if configuration can change without a redeploy |
| **Unavailable / error** | A configured provider made a request but failed, timed out, was cancelled, or returned invalid data | Preserve the distinction from an empty successful result; explain what failed; offer retry only when a real retry path exists; never replace the result with fixtures |
| **Empty** | A source returned a valid successful result containing no matching data | Say that the query/result is empty; do not label it “not configured” or “offline” |
| **Cached** | A provider explicitly identifies the result as cached/stale and supplies usable freshness context | Mark cached state and show the source timestamp/age when supplied; do not call it live |
| **Demo / synthetic** | A deliberately selected UI-only fixture provider is active | Display a persistent, high-visibility synthetic/demo label; never enable in production or on request failure |
| **Live** | A verified live provider returned the result and the contract supports that assertion | Show source and freshness as provided by the provider; do not infer health or recency |
| **Unverified / illustrative** | Verification/confidence is unknown, assessed, inferred, or intentionally illustrative | Preserve those semantics; do not visually convert them to “verified” or objective truth |

No aggregate provider is connected to the overview. Threat Intelligence and Vulnerability Intelligence remain unintegrated shells. System Health and Coordination now have read-only server-side adapters to Agent 1's documented PR #4 read contract, but no API deployment is configured or verified in this checkout; both pages fail closed and visibly disclose the trusted single-tenant/no-user-auth boundary. Command Theater is adapter-ready but has no production provider; its synthetic development fixtures are isolated and labeled. Do not invent incidents, IOC/CVE counts, agent statuses, feed health, worker/queue state, or SLAs.

## 2. Navigation and search

- Use the shared shell for every route: consistent brand, breadcrumb, locale selector, skip link, one main landmark, and primary navigation.
- The sidebar search is explicitly **page-only**. It filters translated route labels and never claims to search threat entities, IOCs, vulnerabilities, alerts, or agents. State that entity search requires a verified data provider; expose the `Ctrl/⌘+K` shortcut to focus the search.
- Keep links and actions separate from status labels. A page that is not configured remains navigable so users can inspect the reason and planned scope.
- On mobile/tablet widths, the navigation toggle exposes the same destinations; activate it with a button and keep `aria-expanded`/`aria-controls` synchronized.
- Do not render a bell, avatar, tenant selector, live badge, or disabled-looking CTA unless the feature has a real behavior and a truthful availability message.

## 3. Overview and module landing pages

The overview is a launchpad and data-integrity disclosure, not an operational dashboard. Cards should communicate (a) what the module is for, (b) whether data is connected, and (c) what the link will open. Never add summary numbers/charts until they have a source, time window, authorization, freshness, and explicit empty/error handling.

For unconfigured modules:

- Put the integration state near the page heading, not only in documentation.
- Explain that no data is displayed and that the page is a frontend shell.
- Label any future scope as planned/not available; do not imitate a populated table or alert list.
- Provide only real navigation (for example, return to Overview); do not add inert filters, buttons, or fake refresh controls.

## 4. Command Theater investigation flow

- The accessible entity explorer is the stable path to records. The graph is an additional visualization, not the only way to select or inspect entities.
- Keep evidence, provenance, verification, and confidence separate. A view-layout coordinate has no analytic meaning.
- Map selection should remain synchronized with the explorer and optional 3D view. Keep keyboard focus predictable and restore it to 2D if graphics support fails.
- Respect graph limits and state when the visual slice omits records. Do not imply that a bounded graph is the complete dataset.
- If a host adapter fails or returns invalid data, show an error and a genuine retry path; never silently switch to synthetic data.
- Keep selection history as local navigation unless a real investigation persistence contract is added. Do not describe it as a saved investigation.

## 5. Locale and direction

- Keep the locale selector available in the top-level shell and Settings. Both controls update the same app state.
- English is LTR; Arabic and Persian are RTL. Set document/component language and direction. Use logical CSS properties and mirror directional arrows when their meaning is “back/forward”.
- Wrap technical IDs, URLs, CVE/IOC values, and mixed-script tokens in `<bdi>` or an explicit direction where needed. Do not translate source identifiers.
- Locale and reduced-motion choices are stored only in this browser. Explain scope and persistence; do not imply account-wide or cross-device sync.
- Translation coverage is code-backed but has not been reviewed by fluent speakers. Leave space for text expansion and verify mixed-direction punctuation in a browser.

## 6. Settings and accessibility preferences

The settings page provides only behaviors that exist: EN/AR/FA locale and an additional reduce-motion option, both saved in this browser only. The OS reduced-motion preference always remains respected. These preferences do not alter any server service. Account/tenant settings are explicitly unavailable because no verified identity/preferences contract is present.

Use native controls with explicit labels, keyboard focus, semantic headings, and useful descriptions. Do not add a custom switch or select without a demonstrated need. Forced-colors focus styling and reduced-motion CSS exist, but require browser verification.

## 7. Loading, empty, error, and feedback

- Keep loading states distinct from empty, unconfigured, error, and stale/cached states.
- Announce asynchronous failures/status changes only when needed; use `role="status"` for non-urgent outcomes and `role="alert"` for actionable critical errors.
- Preserve useful context when a request fails. Avoid destructive clearing of an existing graph unless the source contract requires it and the UI explains why.
- Do not show success toasts for actions that were not actually persisted.
- Avoid infinite spinners: where a provider exists, provide a clear cancellation or recoverable failure path according to its contract.

## 8. Interaction acceptance checklist

Before shipping a control, verify:

- It has an explicit name/label and a correct native role.
- Keyboard users can reach and activate it; focus is visible and does not disappear after route or graph changes.
- Disabled or unavailable behavior is explained; no visible control is inert.
- EN/AR/FA labels, direction, ordering, and focus behavior make sense at desktop and mobile widths.
- Loading, no-provider, empty-success, provider-error, stale/cached, and demo states are not conflated.
- Tests cover behavior, but browser/device/assistive-technology evidence is reported separately.
