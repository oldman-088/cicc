# Next-Day Execution Plan & Project Checkpoint (CORRECTED, prepared by Agent 1, 2026-11-05)

Checkpoint commit: `59c28fa` on `arena/961971ed-cicc` (PR #4 OPEN, unmerged).
`main` = `ca8f82c` (Master Prompt README v1.0, unchanged). No main pushes, no self-merges,
no modifications of other agents' branches/PRs.

## Correction log (owner directives applied)
1. **Agent 2 is UNAVAILABLE** — no implementation tasks are assigned to Agent 2 until an
   explicit return signal from the owner. **Agent 6 is the active Threat Intelligence
   backup and continues TI work independently.**
2. **AMD-001 is owner-reserved** — agents may attach technical recommendations/evidence
   only; no agent may accept, reject, or activate it. It stays `pending`.
3. **PR #2 vs PR #7 merge ordering is an owner decision** — no agent merges, rewrites,
   or modifies another agent's branch.
4. Every active agent below has concrete tasks, deliverables, dependencies, acceptance
   criteria.
5. **Agent 5 is strictly read-only** — no development tasks, ever.
6. **Replacement Agent 3** continues Vulnerability Intelligence independently, preserving
   the original Agent 3 branch/PR (#1).
7. **Backup Agent 4** continues the authorized full frontend takeover on its own branch
   (#7), never touching Agent 4's branch/PR (#2).
8. **Agent 1** stays focused on central coordination, System Health, Operations,
   integration verification, and project-wide progress — not domain implementations.
9. Priorities preserved; **actual blockers vs owner-reserved decisions are separated**
   (see §4). RabbitMQ and unavailable production credentials do NOT stop independent
   development.
10. All completed work is committed/pushed to the correct feature branch with accurate
    PR updates; never push to main.

## 0. Verified repository state (2026-11-05 ~14:35Z)
Open PRs (head SHAs):
| PR | branch | head | owner/role |
|----|--------|------|-----------|
| #1 | arena/fa0df787-cicc | 84fca769 | original Agent 3 VI lineage (preserved) |
| #2 | arena/09952395-cicc | 744ccd35 | Agent 4 original frontend |
| #3 | arena/93315d2c-cicc | 1a46f704 | Agent 2 TI (**Agent 2 unavailable — no new tasks**) |
| #4 | arena/961971ed-cicc | 59c28fa | **Agent 1 (this branch)** |
| #6 | arena/28e50255-cicc | 02616bb5 | Agent 6 — ACTIVE TI backup |
| #7 | arena/6a028355-cicc | 63a6064 | Backup Agent 4 frontend takeover |
| #8 | arena/259e5471-cicc | 8e8b1c62 | Replacement Agent 3 VI, stacked on #1 |

Agent 1 evidence @59c28fa: API 225/225 (36 real-PG via pgserver, SQLite threaded
separate, 1 live-GitHub), web 34/34 + tsc + build, contract_check 31/31, e2e 24/24.
PR #7 write flow VERIFIED by Agent 1 at heads 3736e74b / 716a92b / 5f502a4 / fb500a4
(read-only worktree + shared sandbox API); @63a6064 code markers present, live
re-verify scheduled next day. AMD-001 PENDING (owner-reserved). PRs #1/#2/#3/#6/#7/#8
do not touch apps/api (read-only diff verified).

## 1. Per-agent plans (active agents only)

### Agent 1 — Central Coordination, System Health & Operations (PR #4, `59c28fa`)
- Done: coordination lifecycle + guarded CAS, lease recovery, dead-letter, contract
  v1.0 + amendment governance (PG race-tested, self-approval prohibited), BFF
  read/write boundaries, /health + /trace, dashboard health panel, safe PR-body
  updater, docs (adoption, traceability, security design, MVP readiness, checkpoint).
- **Next-day tasks (concrete):**
  - T1 (P0): run full API suite + PG subset + web tests; record counts.
  - T2 (P1): add PG race tests — approval-decide vs task-complete; webhook-dup vs
    task-create interleaving.
  - T3 (P1): read-only re-verify PR #7 @ `63a6064` against the shared sandbox API
    (worktree, no branch modification); post evidence comment on PR #4.
  - T4 (P2): run the labeled sandbox MVP trial per `docs/MVP_TRIAL_READINESS.md`.
  - T5 (P2): attach AMD-001 technical recommendation (evidence only) on PR #4;
    keep it pending.
- **Deliverables:** green suites, new PG tests, PR #7 verification comment, trial log,
  updated PR #4 body via `scripts/update_pr_body.py`.
- **Acceptance:** counts recorded with timestamps; evidence labeled sandbox/fixture;
  no other branch touched; AMD-001 still pending.
- **Dependencies:** none external; PR #7 branch read-only.
- **Parallel:** yes with all other agents (disjoint branches).
- **Estimate:** Agent 1 scope ≈ 90% complete.

### Agent 6 — ACTIVE Threat Intelligence backup (PR #6, `02616bb5`) — Agent 2 unavailable
- Done (per PR #6 body): Domain B reports, relationship analysis, conflict
  resolution, observability, OSINT P1-04, persistence P3-01/02/03.
- **Next-day tasks (concrete):**
  - T1 (P0): continue TI backup implementation on `arena/28e50255-cicc` only.
  - T2 (P1): record TI contract-adoption stage (PROPOSED→…→VERIFIED) with mounting
    evidence (which API endpoints mount the TI surface) as a PR #6 comment / PR #4
    comment — evidence only, no acceptance claims.
  - T3 (P1): explicit technical recommendation on AMD-001 (evidence only).
- **Deliverables:** commits on own branch; adoption evidence; PR #6 updated.
- **Acceptance:** no changes outside own branch; no acceptance of owner-reserved items.
- **Dependencies:** Agent 1's `/contract` endpoint for adoption stages.
- **Estimate:** TI domain progressing; adoption stage PENDING explicit owner/primary
  acceptance.

### Replacement Agent 3 — Vulnerability Intelligence (PR #8 stacked on PR #1, `8e8b1c62`)
- Done: CycloneDX VEX export (B-07) + M3 mapping-type split.
- **Next-day tasks:** T1 (P0) continue VEX export on own branch; T2 (P1) keep PR #8
  stacked on `arena/fa0df787-cicc` (PR #1) — never retarget to main; T3 (P1) record VI
  adoption stages + mounting evidence on PR #4.
- **Deliverables:** commits on `arena/259e5471-cicc`; PR #8 updated; original Agent 3
  branch/PR #1 preserved untouched.
- **Acceptance:** stack intact; no other branch modified.

### Backup Agent 4 — Full frontend takeover (PR #7, `63a6064`)
- Done: canonical AgentDTO adoption; BFF write path VERIFIED by Agent 1 at 4 heads;
  CI browser suites (46/46 @63a6064 per commit message).
- **Next-day tasks:** T1 (P0) keep PR #7 review-ready on `arena/6a028355-cicc`; T2 (P1)
  keep BFF write route contract-compatible with `/contract`; T3 (P2) expect and
  support Agent 1's read-only re-verification of head `63a6064`.
- **Deliverables:** commits on own branch; PR #7 body current.
- **Acceptance:** never modifies Agent 4's branch/PR #2; merge ordering stays with owner.

### Agent 5 — strictly read-only
- **No tasks.** May read PRs/reports only. Must never commit, push, or modify GitHub.

### Agent 2 — UNAVAILABLE
- **No tasks assigned** until the owner explicitly signals return. PR #3 remains as-is;
  Agent 6 covers TI.

## 2. Daily schedule (chronological blocks)
1. 09:00 (Agent 1, P0) verify repo/branch/PR state.
2. 09:15 (Agent 1, P0) run suites (API+PG+web), record counts.
3. 09:45 (Agent 1, P1) new PG race tests (T2 above).
4. 11:00 (Agent 1, P1) PR #7 @63a6064 read-only re-verification (T3).
5. 13:00–15:00 (parallel, disjoint branches): Agent 6 TI tasks; Replacement Agent 3
   VI tasks; Backup Agent 4 frontend tasks. Agent 5 observes only. Agent 2: none.
6. 14:00 (Agent 1, P1) cross-agent checks: `contract_check.py`, `e2e_check.py`.
7. 15:00 (Agent 1, P2) labeled sandbox MVP trial.
8. 16:30 (Agent 1, P0) fix regressions → commit/push → PR #4 body via safe updater →
   handover report with evidence labels.
**Critical path:** Agent 1 coordination hardening + PR #7 verification. Owner-reserved
decisions (AMD-001, merge order, tenancy, platform auth, notifications, prod creds)
are external and do not block independent development. RabbitMQ is NOT a blocker.

## 3. Dependency & integration map
- Agent 1 PR #4 provides coordination API, contract v1.0 + amendments, BFF, health.
- PR #7 (Backup Agent 4) consumes the BFF write contract (VERIFIED at 4 heads).
- PR #6 (Agent 6, TI) and #8/#1 (VI) consume coordination for task intake — adoption
  evidence being gathered; none touch `apps/api`.
- Agent 5 read-only over all PRs.

## 4. Blockers vs owner-reserved decisions
**Actual blockers (engineering):** none currently for Agent 1's scope; RabbitMQ and
production credentials are explicitly NOT blockers for independent development.
**Owner-reserved decisions (require owner approval; agents only recommend):**
1. AMD-001 accept/reject/activate (contract v1.1 additive set) — stays pending.
2. PR #2 vs PR #7 merge ordering.
3. Tenant isolation model / PostgreSQL RLS policy.
4. Platform authentication enablement.
5. Notification delivery authorization (currently disabled).
6. Production credentials & deployment configuration.
7. Agent 2 return signal (until then Agent 6 is the active TI owner-backup).
