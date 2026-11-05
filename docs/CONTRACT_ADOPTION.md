# Contract Adoption Record — M12-01 (2026-11-05)

Contract under adoption: **coordination contract v1.0** (`docs/INTEGRATION_CONTRACTS.md`),
base `/api/v1/coordination`, reviewed by other agents at commit `c610917`.

## Status per agent (evidence: PR branches, read-only)

| Agent | PR / branch | Adoption status (verified 2026-11-05) | Evidence |
|---|---|---|---|
| Agent 2 (Threat Intel) | #3 `arena/93315d2c-cicc` | **Doc-level only.** `INTEGRATION_PREPARATION_REPORT.md` lists "Coordination Interfaces (Defined) — clean interface contract with Agent 1", but no code calls `/api/v1/coordination/*` yet. | PR #3 files list; report content |
| Agent 3 (Vuln Intel) | #1 `arena/fa0df787-cicc` | **Proposed, not wired.** Own `INTEGRATION_CONTRACTS.md` says "proposed, not agreed; nothing wired into the platform"; storage/tenant adoption explicitly an owner decision. No coordination API calls. | PR #1 docs/vulnerability-intelligence/INTEGRATION_CONTRACTS.md |
| Agent 4 (Frontend/UX) | #2 `arena/09952395-cicc` | **Awaiting alignment.** `apps/web/API_INTEGRATION_CONTRACTS.md`: "Agent coordination/tasks — explicit unconfigured route; PR #4 reviewed at c610917; endpoint ownership/path alignment and heartbeat/task identity contract remain unconfirmed". | PR #2 file content (quoted) |

## Discrepancies / open items
1. Agent 4 needs the **final path + DTO list** — provided as contract v1.0 (25 endpoints) in INTEGRATION_CONTRACTS.md; PR #4 comment posted with the dashboard-relevant subset. Awaiting their wiring + visual verification (M12-05).
2. Agents 2/3 have not yet submitted a task through `POST /api/v1/coordination/tasks`. M12-02 proves the flow works from their side using labeled simulated agents (test fixtures, NOT Arena sessions).
3. No shared contract was silently changed; v1.0 is additive over M6–M11 behavior.

## Confirmations requested
- PR #4 comments (2026-11-04/05) ask Agents 2/3/4 to confirm v1.0 or propose changes; issue #5 tracks the worker heartbeat/task identity contract.
- If no response: proceed with v1.0 as proposed (per M11-02/M12-01 mandate).
