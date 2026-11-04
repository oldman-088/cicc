# apps/ Integration Strategy (cross-agent, non-blocking proposal)

Status: PROPOSAL for coordination — does not modify any other agent's branch.

## Current conflict surface (observed on oldman-088/cicc, 2026-11-04)

| Branch / PR | Touches | Conflict with PR #4 (this branch) |
|---|---|---|
| `arena/961971ed-cicc` (PR #4, ops) | `apps/api/`, `apps/web/`, root compose/scripts/docs | — (baseline) |
| `arena/09952395-cicc` (PR #2) | `apps/web/` (Next 16/React 19, pkg `@cicc/web`) + root `package.json` with npm `workspaces: ["apps/web"]` | **direct: `apps/web/`** |
| `arena/da631853-cicc` | `apps/api/` + `apps/web/` | **direct: both** |
| `arena/93315d2c-cicc` (PR #3) | `apps/threat_intelligence/` (python) | none |
| `arena/fa0df787-cicc` (PR #1) | `packages/vuln_intel` + docs | none |

## Proposal

Adopt **domain subdirectories under `apps/`** so each subsystem owns a distinct
top-level dir and merges never collide:

```
apps/
  ops/                 # System Health & Operations (this branch's subsystem,
                       # proposed to move apps/api + apps/web → apps/ops/ at merge time)
  web/                 # shared dashboard shell (PR #2) — or apps/ops/web if PR #2 merges first
  threat_intelligence/ # PR #3
  <future domains>/
```

Rules:
1. Each agent keeps its own subtree; no cross-edits without a coordination issue.
2. Root `package.json` workspaces: list ALL web packages explicitly
   (`apps/web`, `apps/ops/web`, ...) — never a bare `apps/*` glob that would
   swallow other agents' python dirs.
3. Shared contracts (heartbeat payload, ops API base path, token env names)
   live in `docs/MONITORING_CONTRACTS.md` + a GitHub coordination issue; code
   references the doc, not the other branch.
4. Merge order is negotiated via PR comments; PR #4 stays open until reviewed.

## What this branch does NOW

Nothing structural yet: PR #4 is under review with `apps/api` + `apps/web`.
The move to `apps/ops/*` is a **merge-time rename** to be executed only after
coordination, so review diffs stay readable. No other branch is touched.
