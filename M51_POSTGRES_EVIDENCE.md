# M51 PostgreSQL coverage and skip classification

The original Agent 3 PR #1 contains `.github/workflows/vuln-intel.yml` with a PostgreSQL job and its skip guard; that branch/file was not modified, and that separate job has not been run here. PR #3 previously had no `.github/workflows` directory. This branch adds a distinct `.github/workflows/vi-candidate-postgres.yml` and `scripts/verify_vi_pg_junit.py`, never replacing the original. The dedicated isolated engine suite locally executed **98 passed, 0 skipped, 1 live case deselected**; the guard verifies at least 98 cases and fails for any skipped/failing case or missing/invalid XML. This verifies the same command locally, not a hosted GitHub Actions run. The guard itself has unit tests.

The full isolated PostgreSQL-enabled suite reported **268 passed, 10 skipped**. Each skip:

1. `test_actual_gateway_create_postgres_and_audit`: **coverage gap** — approved actual gateway mount, verified principal, actor-scoped PostgreSQL, trusted audit and trace unavailable.
2. `test_actual_gateway_denies_unauthenticated_and_cross_tenant`: **coverage gap** — actual gateway authentication and two verified tenant identities unavailable.
3. `test_actual_gateway_rejects_invalid_and_forged_tenant`: **coverage gap** — actual principal binding and mounted validation unavailable.
4. `test_actual_gateway_duplicate_and_conflict`: **coverage gap** — actual gateway mount and isolated PostgreSQL idempotency environment unavailable.
5. `test_actual_gateway_audit_failure_rolls_back`: **coverage gap** — actual host audit-failure injection and transactional PostgreSQL unavailable.
6. `test_actual_host_pool_reuse_keeps_tenant_isolation`: **coverage gap** — actual actor-scoped pool reuse and rollback observation unavailable.
7. `test_actual_gateway_list_is_tenant_scoped_and_audited`: **coverage gap** — actual mounted list, two verified tenants and trusted audit unavailable.
8. `test_actual_host_rejects_unauthorized_direct_sql`: **coverage gap** — actual runtime DB role, direct SQL probe and trusted audit unavailable.
9. `test_live_official_cisa_github_mirror`: **intentional opt-in** in full offline run; separately executed and passed against real GitHub mirror.
10. `test_live_collection_persistence`: **intentional opt-in** in full offline run; separately executed and passed against real GitHub mirror and disposable PG.

Actual-host integration: 0 executed / 8 skipped; engine guard excludes all actual-host tests and one opt-in live test, not evidence for either. Full default offline suite: **170 passed, 108 skipped**. Live tests separately: **2 passed**. Categories overlap; no claim of fully covered database layer or deployed scheduler.
