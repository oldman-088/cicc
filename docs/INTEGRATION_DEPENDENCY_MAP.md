# Unified Dependency & Integration Map (updated M33, 2026-11-05)

Agent 1 checkpoint: branch `arena/961971ed-cicc` @ M33, PR #4 OPEN, main `ca8f82c`.

## Provided by Agent 1 (PR #4) — consumed by other roles
| Surface | Contract | Adoption stage | Evidence |
|---|---|---|---|
| Coordination API (tasks/agents/approvals/sweep/webhook) | `GET /api/v1/coordination/contract` v1.0 | IMPLEMENTED+MOUNTED+EXECUTED+VERIFIED (own live env) | 227 API tests, 38 PG, e2e 24/24 |
| Amendment governance | `/contract/amendments` | IMPLEMENTED+MOUNTED, AMD-001 **PENDING (owner-reserved)** | PG race suite 12 |
| BFF read proxy + single approved write route | `POST /api/v1/coordination/tasks` | VERIFIED for PR #4 reference BFF (live) and PR #7 component (Agent 1 re-verified @ 3736e74b/716a92b/5f502a4/fb500a4) | live runs, PR #4 comments |
| Health + trace | `/coordination/health`, `/tasks/{id}/trace` | VERIFIED live via BFF | MVP trial 23/23 |

## Consumers
| PR | role | head | touches apps/api? | stage vs coordination contract |
|----|------|------|-------------------|-------------------------------|
| #3 `1a46f704` | Agent 2 TI — **UNAVAILABLE**, availability confirmation requested from owner | — | no | PENDING explicit ACCEPT |
| #6 `02616bb5` | Agent 6 active TI backup | 02616bb5 | no | evidence gathering |
| #1 `84fca769` / #8 `8e8b1c62` | VI (orig Agent 3 / replacement) | 8e8b1c62 | no | evidence gathering; #8 stacked on #1 |
| #2 `744ccd35` / #7 `63a6064` | Frontend (Agent 4 / Backup Agent 4) | 63a6064 | no | PR #7 write flow VERIFIED; #2 read-only surface compatible |

## Sandbox MVP trial (M33)
`scripts/mvp_sandbox_trial.py` — 23/23 PASS @14:52:27Z (sandbox/fixture only):
contract+health via BFF, BFF write 201 + `x-cicc-idempotency-key` header == read key,
negatives 422/403, full lifecycle, honest human-assisted delivery (no broker claim),
fail/retry, approval, trace correlation, amendment pending, sweep.

## Blockers vs owner-reserved
- Not blockers: RabbitMQ (human-coordinated), missing prod credentials.
- Owner-reserved: AMD-001, PR #2/#7 merge order, tenant/RLS, platform auth,
  notifications, prod creds, Agent 2 return signal.
# Unified Dependency & Integration Map (updated M33, 2026-11-05)

Agent 1 checkpoint: branch `arena/961971ed-cicc` @ M33, PR #4 OPEN, main `ca8f82c`.

## Provided by Agent 1 (PR #4) — consumed by other roles
| Surface | Contract | Adoption stage | Evidence |
|---|---|---|---|
| Coordination API (tasks/agents/approvals/sweep/webhook) | `GET /api/v1/coordination/contract` v1.0 | IMPLEMENTED+MOUNTED+EXECUTED+VERIFIED (own live env) | 227 API tests, 38 PG, e2e 24/24 |
| Amendment governance | `/contract/amendments` | IMPLEMENTED+MOUNTED, AMD-001 **PENDING (owner-reserved)** | PG race suite 12 |
| BFF read proxy + single approved write route | `POST /api/v1/coordination/tasks` | VERIFIED for PR #4 reference BFF (live) and PR #7 component (Agent 1 re-verified @ 3736e74b/716a92b/5f502a4/fb500a4) | live runs, PR #4 comments |
| Health + trace | `/coordination/health`, `/tasks/{id}/trace` | VERIFIED live via BFF | MVP trial 23/23 |

## Consumers
| PR | role | head | touches apps/api? | stage vs coordination contract |
|----|------|------|-------------------|-------------------------------|
| #3 `1a46f704` | Agent 2 TI — **UNAVAILABLE**, availability confirmation requested from owner | — | no | PENDING explicit ACCEPT |
| #6 `02616bb5` | Agent 6 active TI backup | 02616bb5 | no | evidence gathering |
| #1 `84fca769` / #8 `8e8b1c62` | VI (orig Agent 3 / replacement) | 8e8b1c62 | no | evidence gathering; #8 stacked on #1 |
| #2 `744ccd35` / #7 `63a6064` | Frontend (Agent 4 / Backup Agent 4) | 63a6064 | no | PR #7 write flow VERIFIED; #2 read-only surface compatible |

## Sandbox MVP trial (M33)
`scripts/mvp_sandbox_trial.py` — 23/23 PASS @14:52:27Z (sandbox/fixture only):
contract+health via BFF, BFF write 201 + `x-cicc-idempotency-key` header == read key,
negatives 422/403, full lifecycle, honest human-assisted delivery (no broker claim),
fail/retry, approval, trace correlation, amendment pending, sweep.

## Blockers vs owner-reserved
- Not blockers: RabbitMQ (human-coordinated), missing prod credentials.
- Owner-reserved: AMD-001, PR #2/#7 merge order, tenant/RLS, platform auth,
  notifications, prod creds, Agent 2 return signal.

## M34 addendum (2026-11-06)
- Cross-domain workflow executed at coordination layer: `scripts/cross_domain_trial.py` 32/32 PASS (threat_intel, vuln_intel, frontend_e2e through BFF; lifecycle, visibility, trace, health).
- Domain endpoints themselves (TI/VI/frontend surfaces) remain owned by their agents; coordination contract stage for them: IMPLEMENTED (their branches) / CONSUMED-pending until their agents mount and accept.
