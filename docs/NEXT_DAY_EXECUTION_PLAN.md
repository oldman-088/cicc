# Next-Day Execution Plan & Project Checkpoint (prepared by Agent 1, 2026-11-05)

Checkpoint commit: `469935e` on `arena/961971ed-cicc` (PR #4 OPEN, unmerged).
`main` = `ca8f82c` (Master Prompt README v1.0, unchanged). No main pushes, no self-merges.

## 0. Verified repository state (2026-11-05 ~14:20Z)
Open PRs (head SHAs):
| PR | branch | head | owner/role |
|----|--------|------|-----------|
| #1 | arena/fa0df787-cicc | 84fca769 | Vuln Intel (original Agent 3 lineage) |
| #2 | arena/09952395-cicc | 744ccd35 | Agent 4 original frontend |
| #3 | arena/93315d2c-cicc | 1a46f704 | Agent 2 Threat Intelligence |
| #4 | arena/961971ed-cicc | 469935ef | **Agent 1 (this branch)** |
| #6 | arena/28e50255-cicc | 02616bb5 | Agent 6 TI backup |
| #7 | arena/6a028355-cicc | 63a6064 | Backup Agent 4 frontend takeover |
| #8 | arena/259e5471-cicc | 8e8b1c62 | Replacement Agent 3 (Vuln Intel), stacked on #1 |

Agent 1 evidence @469935e: API 225/225 (36 real-PG via pgserver, SQLite threaded
separate, 1 live-GitHub), web 34/34 + tsc + build, contract_check 31/31, e2e 24/24.
PR #7 write flow VERIFIED by Agent 1 at heads 3736e74b / 716a92b / 5f502a4 /
fb500a4 (read-only worktree + shared sandbox API); @63a6064 code markers present
(9 matches), no apps/api changes in #6/#7/#8. AMD-001 PENDING (owner decision).

## 1. Per-agent plans

### Agent 1 — Central Coordination, System Health & Operations (PR #4, `469935e`)
- Done: coordination lifecycle + guarded CAS, lease recovery, dead-letter,
  contract v1.0 + amendment governance (PG race-tested, self-approval prohibited),
  BFF read/write boundaries, /health + /trace, dashboard health panel, safe PR-body
  updater, docs (adoption, traceability, security design, MVP readiness).
- Next-day P0: more PG race windows (task sweep vs amendment sweep variants done;
  try approval decide vs task complete, webhook dup vs task create).
- P1: re-verify PR #7 head 63a6064 live (read-only worktree) — last verified fb500a4.
- P1: MVP trial dry-run script (sandbox, labeled) per docs/MVP_TRIAL_READINESS.md.
- P2: keep AMD-001 pending; escalate owner decisions (AMD-001, tenancy, platform
  auth, notifications, prod creds, Agents 2/6 ACCEPTs).
- Acceptance: suites green, evidence labeled, PR #4 body updated via safe updater.
- Continuation prompt: "Continue on arena/961971ed-cicc from 469935e: run full API+PG
  suites, add the next PG race tests, re-verify PR #7 @63a6064 read-only against the
  shared sandbox API, run the MVP sandbox trial script, commit/push, update PR #4
  body with scripts/update_pr_body.py, report with evidence labels. Keep AMD-001
  pending; never touch other branches."

### Agent 2 — Threat Intelligence primary (PR #3, `1a46f704`)
- Done (per PR #3 body): TI modules implementation on own branch.
- Next-day P0: state availability explicitly (owner said Agent 2 unavailable until
  explicit return — Agent 6 covers); if active: publish TI contract adoption status
  against /api/v1/coordination/contract (PROPOSED→ACCEPTED…) and provide mounting
  evidence (which endpoints mount the TI surface).
- P1: explicit ACCEPT/REJECT of coordination contract v1.0 + AMD-001 as domain owner.
- Dependencies: Agent 1 contract endpoint; no branch conflicts (separate PR).
- Prompt: "On arena/93315d2c-cicc @1a46f704: state your availability; record explicit
  adoption decision for coordination contract v1.0/AMD-001 on PR #4; provide mounted
  API evidence for the TI surface; do not modify other branches."

### Replacement Agent 3 — Vulnerability Intelligence (PR #8 stacked on PR #1, `8e8b1c62`)
- Done: CycloneDX VEX export (B-07) + M3 mapping-type split (per PR #8 body).
- Next-day P0: keep PR #8 stacked on PR #1's branch; do not retarget to main.
- P1: publish VI contract-adoption stage + mounting evidence; explicit owner ACCEPT
  of coordination contract where VI consumes it.
- Dependencies: PR #1 base; Agent 1 contract endpoint. Agent 5 read-only reviews.
- Prompt: "On arena/259e5471-cicc @8e8b1c62 (PR #8 targeting PR #1's branch): continue
  VEX export work, record VI adoption stages vs /contract on PR #4, keep stacking on
  arena/fa0df787-cicc, never modify other branches."

### Backup Agent 4 — Full Frontend takeover (PR #7, `63a6064`)
- Done: canonical AgentDTO adoption, BFF write path (VERIFIED by Agent 1 at 4 heads),
  CI browser suites (46/46 @63a6064 per commit message).
- Next-day P0: keep PR #7 review-ready; note PR #2 merge-sequence is an owner decision.
- P1: when Agent 1 re-verifies head 63a6064, align on any new contract amendments.
- Dependencies: Agent 1 verification runs (read-only); owner merge decision.
- Prompt: "On arena/6a028355-cicc @63a6064: continue frontend takeover; keep the BFF
  write route contract-compatible; expect Agent 1 read-only re-verification; do not
  modify Agent 4's branch or PR #2."

### Agent 5 — Read-only observer
- No development tasks. May read PRs and reports; must never commit/push/modify.
- Prompt: "Read-only review of PRs #1-#8 and Agent 1's PR #4 body; report observations
  as PR comments only if authorized; make no changes."

### Agent 6 — TI backup (PR #6, `02616bb5`)
- Done: Domain B reports, relationship analysis, conflict resolution, observability,
  OSINT P1-04, persistence P3-01/02/03 (per PR #6 body).
- Next-day P0: remain active backup until Agent 2 explicitly returns; keep PR #6 on
  own branch; provide TI mounting evidence for coordination adoption.
- Prompt: "On arena/28e50255-cicc @02616bb5: continue TI backup work; record explicit
  adoption evidence vs Agent 1's /contract; do not modify other branches."

## 2. Daily schedule (Agent 1-executable blocks; other agents parallel on own branches)
1. 09:00 Verify repo/branch/PR state (git status, gh api pulls) — Agent 1.
2. 09:15 Run full API suite + PG subset + web tests; record counts — Agent 1.
3. 09:45 P0: new PG race tests (approval-vs-complete; webhook-vs-create) — Agent 1.
4. 11:00 P1: read-only re-verify PR #7 @63a6064 against shared sandbox API — Agent 1.
5. 13:00 Parallel: Agents 2/6/3/Backup-4 continue own branches (owner-authorized).
6. 14:00 Cross-agent contract check: scripts/contract_check.py + e2e_check.py — Agent 1.
7. 15:00 MVP sandbox trial script run, labeled sandbox — Agent 1.
8. 16:30 Fix regressions; commit/push Agent 1 branch; update PR #4 via safe updater;
   post PR comments; handover report — Agent 1.
Critical path: Agent 1 coordination hardening + PR #7 verification; owner decisions
(AMD-001, tenancy, platform auth, merge sequence #2/#7) are external blockers, not
on the critical path of Agent 1's own work.

## 3. Dependency & integration map
- Agent 1 PR #4 provides: coordination API, contract v1.0 + amendments, BFF, health.
- PR #7 (Backup Agent 4) consumes the BFF write contract (VERIFIED at 4 heads).
- PR #3/#6 (TI) and #1/#8 (VI) consume coordination for task intake — adoption
  PENDING explicit ACCEPTs; none touch apps/api (verified).
- Owner decisions needed: AMD-001 accept/reject; merge sequence PR #2 vs #7; tenant
  model; platform auth enablement; notifications; prod credentials; RabbitMQ (non-blocking).

## 4. Owner decisions genuinely requiring approval
1. AMD-001 (contract v1.1 additive changes) — accept/reject.
2. PR #2 vs PR #7 merge sequence.
3. Tenant isolation model (RLS) — policy decision before any activation.
4. Platform authentication enablement.
5. Notification delivery authorization (currently disabled).
6. Production credentials/deployment config.
7. Agent 2 return timing (Agent 6 remains backup until then).
