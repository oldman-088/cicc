# M49 cross-agent ownership and integration review

**Reviewed:** 2026-11-06 · **Lead branch:** `arena/961971ed-cicc`
**Evidence method:** fetched PR descriptions, changed-file lists, handovers, and source files from the exact GitHub-reported head SHAs with GitHub's API; used GitHub compare results for ancestry. Local remote-tracking refs for PR #1/#3 were stale at the time of the earlier M48 review and are not used here.

## 1. Ownership and history — corrected finding

The current preservation map is **PR #1 = original Agent 3 VI; PR #3 = replacement Agent 3 VI with earlier Agent 2 TI history**. Exact-head evidence:

| PR | GitHub head | Current source evidence | State |
|---|---|---|---|
| [#1](https://github.com/oldman-088/cicc/pull/1) | `a942baabc3260683ec1a2b8c9d953c04dceaae9a` (`arena/fa0df787-cicc`) | Its current `docs/handover/AGENT3_VULNERABILITY_INTELLIGENCE_HANDOVER.md` says PR #1 is the original Agent 3 author's own branch and PR #3 is a separate role. It says the *earlier handover task brief* that assigned that author to PR #3 was inverted. | OPEN, non-draft; no review decision. |
| [#3](https://github.com/oldman-088/cicc/pull/3) | `7136538f74ab08b33607774c507785fc0c59cd03` (`arena/93315d2c-cicc`) | Its current body labels the work Replacement Agent 3 and says the branch/PR historically carried TI; its current tree contains `docs/handover/AGENT2_THREAT_INTELLIGENCE_HANDOVER.md` and M54 replacement-VI work. | OPEN, Draft; no review decision; actual-host suite reported 0/8. |

The current PR #1 handover and PR #3 description therefore **support**, rather than contradict, the working preservation map. The apparent conflict was between the PR #1 author's earlier commissioning brief and the current task assignment. The M48 report and my M55 PR #1 comment incorrectly said the current handover assigned PR #1/#3 in reverse. I corrected both statements publicly and in this report; the original comments remain visible as history. Correction: [PR #1 comment 6689778670](https://github.com/oldman-088/cicc/pull/1#issuecomment-6689778670).

This is role-level, self-reported evidence, not proof of individual human identity: both public PR records and comments use the same GitHub account, and there is no separate author or reviewer confirmation. Do not infer contributor roles from Git commit metadata alone. The current PR #1 handover also contains stale head/count details (for example, it describes PR #3 at `5fec62e`/31 commits while the current head is `7136538`/32 commits); its role statement is useful, but its old revision measurements are not current.

GitHub's exact-SHA compare API reports:

- `main` `ca8f82c0500637e22851d7128cddf99081ef3c08` → PR #1 head: **154 ahead**, 0 behind, merge base `main`.
- The same `main` → PR #3 head: **32 ahead**, 0 behind, merge base `main`.
- PR #1 ↔ PR #3: **diverged**, with `main` as their merge base. The feature histories are independent; this does not settle authorship or merge order.

No PR #1/#3 head, branch, review state, or merge state has been changed by Agent 1.

## 2. PR #1 VI review — route, persistence, identity, tenancy, migration

Reviewed at `a942baabc3260683ec1a2b8c9d953c04dceaae9a`:

- `packages/vuln_intel/vuln_intel/integration/api.py` is a framework-neutral read API contract; `asgi.py` builds a candidate ASGI surface. `host_adapter.py` expects authentication, principal resolution, and authorization to be supplied by the host. The package itself does not establish production identity.
- `integration/sbom_handler.py` explicitly performs bounded parsing/validation and receives a host-resolved tenant argument. It documents authentication, authorization, tenant resolution, audit, raw-byte storage, and persistence as host concerns. It is not a mounted or persisted SBOM import route.
- `integration/dbapi_store.py` has tenant-qualified reads/writes and injected DB-API connections. Its default does not create schema; it publishes DDL for deliberate adoption. This is candidate persistence, not proof that the Agent 1 database has the tables or approved runtime roles.
- `test_actual_host_sbom_acceptance.py` names the moving ref `origin/arena/da631853-cicc`, not a host SHA. Its six tests cover host session/principal resolution, a direct authorizer tenant-denial check, direct `handle_sbom_import` tenant binding, a no-persistence assertion, a representative SBOM/body-size comparison, and a direct body-limit middleware check. It creates a disposable PostgreSQL schema from the host's SQLAlchemy metadata. It does **not** mount the candidate API, exercise a persisted import, or run the current Agent 1 merged application. The current moving ref resolves to `2dc1a7b2…`, but the source does not prove that was the commit fetched by CI run `42224686079`.
- The PR #1 handover claims **6/6** candidate actual-host tests. The six CI jobs succeeded, but the raw hosted log was unavailable to this review; the host test's own dynamic branch reference does not pin the CI host SHA. Treat the claim as useful candidate boundary evidence, not merged-app, current-head, or production acceptance.

**Migration discrepancy:** the PR #1 body says “No migration authored” / “no migration exists,” while its same current head contains `packages/vuln_intel/migrations/versions/0043_vuln_intel_records.py` (`revision=0043_vuln_intel_records`, `down_revision=0042_note_corrections`). The file creates `vulnerability_record` and `vulnerability_provenance_event` plus indexes and foreign keys. The handover says it is **unapplied**. Older integration docs still describe no migration and a different `vuln_observations` shape. Agent 1's current checkout has no matching Alembic chain and uses `Base.metadata.create_all`; the migration is not approved for this host. It must not be applied or adapted without the schema owner, AMD-003, and migration approval. Clarification request: [PR #1 comment 6689778670](https://github.com/oldman-088/cicc/pull/1#issuecomment-6689778670).

## 3. PR #3 TI/VI review — host, database, and actual-host evidence

Reviewed at `7136538f74ab08b33607774c507785fc0c59cd03`:

- `apps/threat_intelligence/relationship_api.py` uses an in-memory relationship store by default. Its standalone FastAPI routes are not registered in the Agent 1 application.
- `apps/threat_intelligence/host_adapter.py::create_host_application` is an integration proposal requiring host callbacks for verified principal resolution, a principal/tenant-bound PostgreSQL engine, durable security audit, and trace linkage. It builds the candidate subapplication; it is not itself an installed host contract or owner approval.
- `test_agent1_gateway_contract.py` requires an owner-supplied, isolated actual-host harness. The handover reports **0 executed / 8 skipped**. Its proposed schema/RLS/role SQL is explicitly proposal material, not an applied migration. A disposable PostgreSQL SELECT-only test role is not proof of the production runtime role.
- `vi_read_only_adapter.py` is an isolated adapter for a quality snapshot; it is not a connected VI endpoint or Agent 4 UI.
- The branch's current ownership proposal explicitly says no owner acceptance has been received. No schema, host, route, permission, tenant, source-of-record, or UI contract is approved by silence or CI.

M49 follow-up requests are on [PR #3 comment 6689783355](https://github.com/oldman-088/cicc/pull/3#issuecomment-6689783355). They ask Agent 2 and Replacement Agent 3 to deliver scoped evidence on their **own branches/PRs**, with exact source SHAs, contracts, non-skipped actual-host tests after approval, and commit/CI links. No acknowledgement has been observed; a posted request is not acceptance.

## 4. Frontend and API contract boundary

PR #2 (`e745cc2b8ff995b040896212eab2995607c48963`) remains separate. Its Web check is branch evidence; its candidate UI does not establish a live TI/VI data path through the current Agent 1 BFF. The M49 panel is an Agent 1-owned status view using only the already-existing, authenticated read endpoints:

- `GET /api/v1/coordination/domains`
- `GET /api/v1/coordination/domains/metrics`

The browser uses relative `/api/...` URLs; the Next.js BFF adds the server-only API token. The panel is read-only and displays bounded lifecycle/probe facts. It deliberately omits candidate `source_ref`, version, raw errors, tenant IDs, payloads, and provider data. It treats malformed/unavailable responses as unavailable and inconsistent/unknown lifecycle states as `UNKNOWN`, never healthy. This is **gateway observability**, not a TI/VI route, product workflow, or tenant-acceptance test.

Agent 4 received a scoped own-branch decoder/UI request at [PR #2 comment 6689786705](https://github.com/oldman-088/cicc/pull/2#issuecomment-6689786705). It requests tolerant handling of optional M47 build/probe fields, accessible unavailable/unknown states, passing own-branch Web CI, and no TI/VI data routes before approval. No acknowledgement has been observed.

## 5. M49 smallest safe integration milestone delivered

**M49 completes a read-only in-product status slice, not TI or VI feature integration.** Agent 1's Coordination view now fetches the gateway lifecycle and bounded probe counters on the regular dashboard refresh, renders `NOT_MOUNTED` for the known TI/VI kinds when no handler exists, and keeps unknown/error states explicit. The helper and unit tests reject unbounded kind IDs, unknown/contradictory status values, malformed API payloads, invalid counters and metadata leakage. The browser remains tokenless and the BFF write path remains closed.

Local evidence on Agent 1 branch commit `e1122bd3aed644af8607bd0873f1863a2a2edf94`:

- Web unit tests: **40 passed** (five M49 domain-gateway normalization tests included).
- Web typecheck and production build: passed.
- API suite: **309 passed**, two pre-existing warnings.
- PostgreSQL-selected suite: **42 passed**, 267 deselected.
- `scripts/m49_domain_gateway_smoke.py`: passed with a temporary SQLite database, random ephemeral tokens, a production Next.js server and the actual FastAPI API. Direct unauthenticated API read returned 401; BFF GETs for domain status/metrics returned 200 without client credentials; cross-site GET and POST were denied with 403; the clean app reported no mounted domain; no server token appeared in responses. The test starts no TI/VI module, makes no external-source call, and cleans up its processes/database.
- `.github/workflows/agent1-ci.yml` now runs this isolated API→production-BFF smoke after the Web build. Hosted PR run [42252536511](https://github.com/oldman-088/cicc/actions/runs/42252536511) and push run [42252527313](https://github.com/oldman-088/cicc/actions/runs/42252527313) each passed all three jobs; the Web job includes `Verify domain gateway through the production BFF`. This is Agent 1 branch CI, not deployment or whole-product acceptance.

### Smallest safe TI/VI data milestones still gated

1. **VI read-only slice (proposal, not authorized):** after the owner pins PR #1 or PR #3 as the chosen VI source and approves the host contract, expose only bounded CVE list/detail reads through a host-resolved tenant and an approved read-only store. Keep SBOM import, writes, cross-tenant lookup, and migration 0043 out of the first slice. Prove authentication/permission/tenant-negative cases and exact host revision. A real populated store still requires an approved schema/source decision; an empty or fixture store is not a live Beta feed.
2. **TI read-only slice (proposal, not authorized):** Agent 2/Replacement Agent 3 must provide an isolated read-only relationship route/adapter contract and a real host harness. Start with GET/list/detail/traverse only behind verified host identity and an approved tenant-bound read-only pool; keep POST/create and all candidate SQL/RLS proposals out until audit/trace/write transaction and migration owners approve them.
3. **Frontend data slice (proposal, not authorized):** Agent 4 consumes only the approved versioned API contract through the BFF, with strict unknown/error/loading/stale behavior and real request/response tests. The M49 status panel does not satisfy this data/UI acceptance.
4. **Exact app acceptance:** after the owner supplies the pinned revision/module/host/tenant manifest and production identity decision, run the existing fail-closed M47 gate against the exact checkout. Candidate adapter tests, branch CI, or the M49 gateway smoke cannot substitute.

## 6. Owner approvals and continuing blockers

No decision is recorded for the following; do not infer approval from these notes:

- Revision/module/host/tenant manifest: exact application SHA, chosen TI and VI PR/source SHAs, entrypoints/module trees, route prefixes, API/error/provenance contract, auth/permission model, trusted tenant resolver, database role/pool, audit/trace callbacks, body/time limits, and executable isolated host harness.
- AMD-003: shared data model, RLS/tenant mapping and migration ownership/approval.
- PR #1 migration 0043: authorship/lifecycle clarification, base-revision compatibility, schema/security review, rollback and deployment approval.
- Production identity, least-privilege authorization, actor attribution and tenant-isolation acceptance on the intended integrated app.

All four PRs and specialist requests remain unchanged except for Agent 1-authored discussion comments. Requests: PR #1 correction/evidence `6689778670`, PR #3 owner-specific TI/VI plan `6689783355`, PR #2 decoder/UI task `6689786705`. No separate specialist acknowledgement or owner approval was observed at this review.
