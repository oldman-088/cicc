# M47 — exact-revision application acceptance runbook

**Owner:** Agent 1 (host / coordination acceptance). **Status:** prepared, not yet run.
**Scope:** application/code acceptance only; never production acceptance. This does not approve an Agent 2/3/4 contract, shared schema, tenant boundary, or AMD-003.

## Evidence classes

- `SANDBOX/FIXTURE`: local tests with synthetic handlers/data.
- `SANDBOX/UNMERGED-BRANCH`: read-only source exports from open PR heads run through an Agent 1 sandbox gateway. These are not merged-application tests.
- `MERGED-APPLICATION`: only the exact clean CICC application checkout is started by `scripts/m47_merged_app_acceptance.py`, with the exact required PR merge-result commits and exact included module trees verified first.
- `APPROVED-INTEGRATION-CHECKOUT`: the same exact local application run after explicit owner approval is recorded in the manifest and `--allow-approved-checkout` is supplied. It is not described as merged.
- **Production:** not claimed by this runbook or by any sandbox run.

The older `scripts/m46_merged_app_acceptance.py` is retained as a legacy source-snapshot probe plus checks against an externally supplied API URL. It does not start or pin the runtime build SHA; its results are `SANDBOX/EXTERNAL-API`, never `MERGED-APPLICATION`. M40/M45 codeload tests likewise remain sandbox/unmerged-branch evidence.

## Mandatory inputs

1. A clean local checkout at a full 40-character `application_commit`.
2. In `merged_main` mode, GitHub must report PR #1 and PR #3 merged to `main`; each exact `merge_commit_sha` must be reachable from both queried `main` and the exact application commit. The script does not accept open-PR head SHAs, GitHub test-merge candidates, or package presence as evidence of merge.
3. For each domain, an owner-reviewed manifest entry binds:
   - owner and source PR number;
   - exact `module_revision` source commit;
   - source subtree path and included application subtree path (their Git tree objects must match exactly);
   - Agent 1 adapter name, source ref, and owner-approved probe payload.
4. Required Git objects for module revisions must be present in the checkout. If needed, fetch the exact commit objects without switching branches.
5. For `approved_checkout`, a non-empty owner approval reference and the explicit CLI switch are required. This is an operator-attested exception to the PR merge gate and is reported separately.

The accepted manifest has schema `cicc-m47-acceptance-manifest/1` and two module entries. Each entry must include `kind` (`threat_intel` or `vuln_intel`), assigned `owner` (Agent 2 or Replacement Agent 3), `source_pr` (#1 or #3), full exact `module_revision`, safe repository-relative `source_path` and `app_path`, the allowlisted Agent 1 adapter name, a <=256-character `source_ref`, `version` equal to the full module SHA, and an owner-approved JSON `probe_payload`. The top-level object includes `integration_mode`, full `application_commit`, `required_prs: [1, 3]`, and (for the tenant gate) `tenant_isolation.driver` plus `approval_ref`.

**No manifest is approved yet.** Current PR ownership/path mapping is ambiguous: PR #3's current description assigns its VI work to Replacement Agent 3 and says it historically contained TI, while the Agent 1 TI adapter targets `apps/threat_intelligence/api.py`. Do not assume a PR-to-domain mapping or copy demo payloads. Each owner must confirm their exact source, adapter entrypoint, module path, and probe before an operator creates the manifest. Never put credentials, tenant IDs, `.env` contents, or tokens in it.

## Run

Use the API virtual environment from the exact checkout; the runner starts the actual supported FastAPI entrypoint (`python -m uvicorn app.main:app`) from `apps/api`, sets the documented `DATABASE_URL` and `CICC_BUILD_SHA`, generates disposable read/write Ops tokens, and starts a second actual process on the same database for restart verification.

```bash
cd apps/api
.venv/bin/python ../../scripts/m47_merged_app_acceptance.py \
  --checkout ../.. \
  --manifest /secure/m47-acceptance-manifest.json \
  --report /tmp/m47-acceptance-report.json
```

For an approved pre-merge checkout only:

```bash
.venv/bin/python ../../scripts/m47_merged_app_acceptance.py \
  --checkout /path/to/approved/cicc \
  --manifest /secure/m47-approved-manifest.json \
  --allow-approved-checkout \
  --report /tmp/m47-approved-report.json
```

The app uses a disposable SQLite DB by default. Set `CICC_M47_DATABASE_URL` to an **isolated disposable PostgreSQL** URL when verifying PG/RLS behavior; this value is passed to the app but never printed or written to the report. The runner does not drop tables or reset a supplied database.

## Checks the runner performs

- Exact clean checkout `HEAD`; exact app SHA in `GET /api/v1/coordination/diagnostics.build_commit` via `CICC_BUILD_SHA`.
- Required PR merge-result reachability; current module PR head equals the manifest module revision in merged mode; exact source/application subtree tree-object equality; Agent 1 adapter presence.
- Actual application startup and readiness; unauthenticated diagnostics/invocation rejected; valid Ops read/write tokens accepted.
- Mount the allowlisted real TI/VI Agent 1 adapters using only the manifest's exact application checkout modules; verify the mounted version/source refs.
- Authenticated invocations; `GET /diagnostics`, `/domains/metrics`, bounded kind-only labels; task/trace correlation and persisted operational audit event.
- Stop and restart the app process against the same DB; require handlers to be honestly `NOT_MOUNTED`, persisted invoke counters to survive, then remount and verify counts continue.
- Data evidence is reported separately: `EXPERIMENTAL_DEMO_DATA_ONLY` / `non-live:*` stays explicitly fixture/demo; a module-reported `live` value is still not independently source-verified.

## Tenant-isolation gate — currently unavailable

The runner reports tenant isolation `BLOCKED` unless an owner-approved driver and approval reference are supplied in the manifest, and the operator supplies both `CICC_M47_TENANT_A_TOKEN` and `CICC_M47_TENANT_B_TOKEN` through the environment. The driver receives these and the disposable API tokens only in its process environment; output is captured and never echoed. It must emit JSON with `status: PASS`, `evidence_class: ACTUAL_APPLICATION`, and a positive integer `cases` count. A missing/failed driver makes overall status `INCOMPLETE`/`FAIL`, never PASS.

The current Agent 1 API uses Ops bearer tokens, has no verified-principal-to-tenant mapping or actor-specific pools, and treats request `tenant_id` as an unverified claim. Therefore synthetic tenant fields, fixture tests, or an independent Agent 3 test host cannot satisfy this gate. Do not call the system tenant-isolated or production-authenticated until the approved host identity and real cross-tenant denial tests exist.

## Current state (M47)

At the GitHub review on 2026-11-06 13:22 UTC, PR #1 was OPEN at `a942baabc3260683ec1a2b8c9d953c04dceaae9a` and PR #3 was OPEN/Draft at `7136538f74ab08b33607774c507785fc0c59cd03`; neither was in `main` (`ca8f82c0500637e22851d7128cddf99081ef3c08`). The no-manifest preflight returned `BLOCKED` before starting any API. PR #3 currently contains both an Agent 2 TI handover and Replacement Agent 3 VI work; Agent 1's legacy TI adapter does not match the new standalone relationship API. No manifest/source-to-domain mapping is owner-approved. Continue independent Agent 1 reliability work; rerun this path only when exact merged commits or an explicitly approved integration checkout and owner-approved module mapping exist. AMD-003 remains pending and no shared schema change is required by this runbook.
