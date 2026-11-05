# PR #3 ↔ PR #6 Reconciliation — Threat Intelligence

- **Repository:** `oldman-088/cicc`
- **`main`:** `ca8f82c0500637e22851d7128cddf99081ef3c08` (unchanged by either PR)
- **PR #3 (Agent 2, primary owner):** branch `arena/93315d2c-cicc`, head `1a46f704bc09207d2755fbfd5a7e8ae48b646e1b`, OPEN (draft), last updated `2026-11-05T09:59:39Z`
- **PR #6 (Agent 6, backup):** branch `arena/28e50255-cicc`, head `a221003601a09aa0130ac0b900e9d6273773876e`, OPEN
- **Neither PR has been merged, closed, rebased or force-pushed by Agent 6.**

All findings below were produced with `git ls-tree`, `git show`, `git diff` and
`comm` against the two head commits. Nothing is inferred.

---

## 1. How the two branches came to overlap

`arena/93315d2c-cicc` was force-pushed back to `ca8f82c` **twice**. Each reset
dropped commits from every branch ref while leaving the objects reachable on
`origin`. The consequence is that PR #3's tree is **not** the full Threat
Intelligence domain — it is only the tail of the lineage.

| Commit | What it contained | Reachable from a branch ref? |
|---|---|---|
| `f8f2868` | Phase 0 core | no (ancestor chain reset) |
| `d639eee` | Extended layers | no |
| `933b29f` | Completion & handoff + 10 core/extended modules & tests | **no — orphaned** |
| `805cd2b` | P1-01 MITRE ATT&CK ingestion + tests | **no — orphaned** |
| `f7d3939` | P1-02 CISA KEV | no |
| `480fa3d` | doc update | no |
| `1a46f70` | P1-03 vendor advisories + docs — **PR #3 head** | yes (`arena/93315d2c-cicc`) |

`git ls-tree -r --name-only 1a46f70 -- apps/` returns exactly four files:

```
apps/threat_intelligence/cisa_kev.py
apps/threat_intelligence/tests/test_cisa_kev.py
apps/threat_intelligence/tests/test_vendor_advisories.py
apps/threat_intelligence/vendor_advisories.py
```

**This is the central reconciliation finding.** PR #3 does not contain the
threat-actor, malware, campaign, TTP, MITRE-mapping, relationship, enrichment,
collection or MITRE-ingestion modules at all. Merging PR #3 alone would land a
P1-02/P1-03 pair with none of the domain they depend on.

Agent 6 recovered `933b29f` and `805cd2b` by SHA:

```
git fetch origin 933b29f956ea0092aed56745020a4919fe1ffcd6 \
                 805cd2b17eda826de8ec7b982dc9377315352327
```

Both objects are still present and unmodified (`git cat-file -t` → `commit`).

---

## 2. File-level comparison

### 2.1 Files in PR #3 only
**None.** Every file PR #3 adds, PR #6 also adds.

### 2.2 Files in both PRs (12)

`README.md` is shared but byte-identical on both branches (verified:
`git diff --exit-code ca8f82c a221003 -- README.md` → no diff), so it is not a
conflict source. That leaves 11 genuinely shared files.

| File | Relationship |
|---|---|
| `apps/threat_intelligence/cisa_kev.py` | PR #6 is a functional superset (§3.1) |
| `apps/threat_intelligence/vendor_advisories.py` | PR #6 is a functional superset (§3.2) |
| `apps/threat_intelligence/tests/test_cisa_kev.py` | PR #6 = PR #3 + 1 test |
| `apps/threat_intelligence/tests/test_vendor_advisories.py` | PR #6 = PR #3 + 1 test |
| 7 root docs (`PROJECT_STATE.json`, `BACKLOG.md`, `MASTER_TASK_QUEUE.md`, `DEVELOPMENT_LOG.md`, `PROJECT_ARCHITECTURE.md`, `INTEGRATION_PREPARATION_REPORT.md`, `SECURITY_REVIEW.md`) | Content conflict expected — both branches rewrote the same headers (§5) |

### 2.3 Files exclusive to PR #6 (37)

Verified with `comm -13 <(git ls-tree -r --name-only 1a46f70 | sort) <(git ls-files | sort)`
→ **37 files**, and `comm -23` in the other direction → **0 files**.

Recovered from orphaned commits (would otherwise be lost):
`threat_actors.py`, `malware.py`, `campaigns.py`, `ttps.py`, `mitre_mapping.py`,
`relationships.py`, `enrichment.py`, `collection.py`, `mitre_ingestion.py` and
their 9 test files.

New in PR #6:
`.gitignore`, `apps/threat_intelligence/__init__.py`, `osint_sources.py`,
`integration_contracts.py`, `persistence.py`, `api_surface.py`,
`collection_workers.py`, `source_reliability.py`, `contract_registry.py`,
`docs/THREAT_INTELLIGENCE_INTEGRATION_CONTRACTS.md`,
`docs/PR3_PR6_RECONCILIATION.md`, and 7 new test files.

---

## 3. Change-level comparison of the shared modules

Method sets were diffed with `grep -oE "^(class |    def |def )"` plus `comm`,
and line sets with `comm -23` over sorted unique lines.

### 3.1 `cisa_kev.py`

- **No method present in PR #3 is absent from PR #6.** All 19 PR #3 methods
  survive with the same names.
- **No test present in PR #3 is absent from PR #6** (`comm -23` → 0 lines).
- **Added in PR #6:** `ingest_kev_catalog_feed` (official CISA JSON schema),
  `get_by_cve` (CVE index), `_parse_timestamp`.
- **43 unique lines exist only in PR #3.** They are all stub bodies or comments
  replaced by real logic, not deleted capability. Verified examples:
  - PR #3 `implement_timeouts_retries(self) -> None` body was
    `# Simulated implementation for offline fixtures` / `pass`.
    PR #6 returns a `Dict[str, Any]` of the actual resilience configuration.
    **This is a signature change (`None` → `Dict`)** — see §6.
  - PR #3 `avoid_silent_discard` body was `# Audit logging of failure` /
    `# Alert mechanism design` / `pass`. PR #6 records the failure in
    `_failed_collections` and appends an audit entry.
  - PR #3 `detect_duplicates` / `detect_updates` were unconditional `return False`.
    PR #6 performs real comparison.

### 3.2 `vendor_advisories.py`

- **No method present in PR #3 is absent from PR #6.**
- **No test present in PR #3 is absent from PR #6** (0 lost lines).
- **Added in PR #6:** `_normalize_cves`, `_parse_debian` (`DSA-*`),
  `_parse_github_ghsa` (`GHSA-*`), `get_advisories_for_cve`.
- **68 unique lines exist only in PR #3**, all narrow-field reads widened in
  PR #6. Every case was verified side by side:

  | PR #3 | PR #6 |
  |---|---|
  | `raw_data.get("msrc_id", "MSRC-UNKNOWN")` | `raw_data.get("msrc_id") or raw_data.get("advisory_id") or "MSRC-UNKNOWN"` |
  | `raw_data.get("cisco_id", "CISCO-UNKNOWN")` | `raw_data.get("cisco_id") or raw_data.get("advisory_id") or "CISCO-UNKNOWN"` |
  | `raw_data.get("rhsa_id", "RHSA-UNKNOWN")` | `raw_data.get("rhsa_id") or raw_data.get("advisory_id") or "RHSA-UNKNOWN"` |
  | `raw_data.get("usn_id", "USN-UNKNOWN")` | `raw_data.get("usn_id") or raw_data.get("advisory_id") or "USN-UNKNOWN"` |
  | `raw_data.get("cve_ids", [])` | `self._normalize_cves(raw_data.get("cves", raw_data.get("cve_ids", [])))` |

  PR #6 accepts a strict superset of inputs and normalizes CVE case.

### 3.3 Both confidence-defect fixes are preserved

1. `osint_sources.py` — corroborated confidence was computed from
   `existing.confidence`, so a same-source re-fetch raised confidence on every
   poll. Now `_compute_entity_confidence` recomputes from raw observations plus
   `0.05 * (distinct_source_count - 1)`.
   Regression tests: `test_indicator_deduplication_and_provenance_granularity`,
   `test_conflict_detection_and_resolution`.
2. `ingest_threat_actor` held a stale `_corroborated_confidence` reference and
   raised `AttributeError`. Fixed; covered by the same tests.

Both fixes live only in PR #6 files and are unaffected by any merge strategy.

---

## 4. What a merge would actually conflict on

Only the **7 root documentation files**. Both branches rewrote the same
`## Project Overview` / `# Last Updated` headers with different branch names,
commit lists and test counts. Every code file either does not overlap or is a
clean superset.

---

## 5. Recommended reconciliation sequence

Safe, reproducible, and reversible at every step. **To be executed by the owner
or Agent 2 — Agent 6 will not merge PR #3, close it, or rewrite its history.**

```bash
# 0. Confirm starting state.
git fetch origin --prune
git ls-remote origin refs/heads/main                 # expect ca8f82c...
gh pr view 3 --json state,headRefOid                 # expect OPEN, 1a46f70...
gh pr view 6 --json state,headRefOid                 # expect OPEN, a221003...

# 1. Land PR #3 first. It is the primary owner's work.
gh pr merge 3 --merge                                # owner/Agent 2 only

# 2. Rebase PR #6 onto the new main.
git checkout arena/28e50255-cicc
git fetch origin main
git rebase origin/main

# 3. Conflicts will be limited to the 7 root docs. For each, keep PR #6's
#    body but restore any Agent 2 content that PR #3 added after 1a46f70.
#    Code files should not conflict; if one does, STOP and re-run §3.

# 4. Re-verify before pushing.
PYTHONPATH=. pytest apps/threat_intelligence/tests -q     # expect all green
python -c "import apps.threat_intelligence as t; \
assert not [n for n in t.__all__ if not hasattr(t, n)]"

# 5. Push and let PR #6 update.
git push --force-with-lease origin arena/28e50255-cicc
```

### Alternative, if PR #3 must not be merged first

Land PR #6 and then re-point `arena/93315d2c-cicc` at the merged result. This
un-orphans `933b29f` and `805cd2b` as a side effect because their content is
already in `main`. **Agent 6 has not done this and will not.**

### What must not be done

- Do not `git rebase --onto ca8f82c` PR #3 — that is how the commits were
  orphaned in the first place.
- Do not cherry-pick `933b29f` / `805cd2b` onto PR #3's branch. Their file sets
  are already complete in PR #6 and a partial pick would produce a tree that
  passes fewer tests than either branch alone.
- Do not resolve the doc conflicts by taking one side wholesale without
  checking whether PR #3 gained doc content after `1a46f70`.

---

## 6. Open items the owner must decide

1. **`implement_timeouts_retries` signature.** PR #3 returns `None`; PR #6
   returns `Dict[str, Any]`. No caller exists in either branch, so nothing
   breaks today, but the return type is a public surface. Recommend adopting
   the PR #6 signature and recording it as a deliberate widening.
2. **`debian` (`DSA-*`) and `ghsa` (`GHSA-*`) parsers.** Agent 6 additions
   beyond the MSRC/Cisco/Red Hat/Ubuntu scope. Justification and evidence in
   §7. Recommend keeping; they are the only parsers that satisfy Agent 3's M2
   requirement for a *fixed version* per advisory.
3. **`__init__.py` eager imports.** The package was previously importable only
   as a namespace package. Verified acyclic, 128 exports, all resolving, import
   cost measured (§8). Recommend keeping.
4. **Whether `integration_contracts.py` and `contract_registry.py` land
   independently or fold into PR #3.** Both are proposal-tracking code;
   `contract_registry.py` marks every dependency `proposed`.

---

## 7. Debian DSA / GitHub GHSA parser justification

| Criterion | Debian `DSA-*` | GitHub `GHSA-*` |
|---|---|---|
| Source-format justification | DSA is the authoritative statement of the **fixed package version** for Debian. Agent 3 M2 explicitly names `DSA-*` as a family it recognises but has no connector for. | GHSA is the authoritative fixed-version source for the GitHub/npm/PyPI dependency ecosystem, which no other parser in the set covers. |
| Contract justification | Satisfies Agent 3 M2: advisories as a **separate** structured record, not a CVE alias. | Same. |
| Test coverage | `test_debian_and_ghsa_parsers_and_cve_lookup` plus the 26-test `test_vendor_advisories.py` suite. | Same test. |
| Live-source verification | **None.** Fixture-tested only. No Debian feed was contacted. | **None.** Fixture-tested only. No GitHub API call was made. |
| Licensing | Debian advisory data is published for redistribution; no licence file is vendored here because no upstream data is committed. | GHSA data is published under CC-BY-4.0; no upstream data is committed here, so no attribution file is required at this stage. |
| Maintenance risk | Low — the DSA field set (`dsa_id`, `cves`, `packages`, `fixed_versions`) is stable. | Medium — GHSA's GraphQL/REST shape changes more often; the parser accepts both `summary`/`description` and `updated`/`modified` spellings to absorb that. |
| Recommendation | **Keep.** | **Keep**, with the field-alias tolerance documented as intentional. |

Both parsers were retained because removing them to shrink the diff would drop
the only implementation of a contract requirement Agent 3 has explicitly
requested.

---

## 8. `__init__.py` eager-import verification

- Intra-package import graph built by AST (no execution): **acyclic, a DAG**.
  `api_surface` → {`integration_contracts`, `persistence`};
  `integration_contracts` → {`cisa_kev`, `vendor_advisories`}; every other
  module is a leaf.
- All 18 submodules import standalone in a clean interpreter.
- 128 exports, zero missing, zero duplicates.
- Cold import measured in a subprocess: **~135 ms**, asserted `< 2000 ms` by
  `test_package_integrity.py`.
- Importing the package opens no socket and starts no thread (asserted in a
  subprocess with `socket.socket` replaced by a guard).

---

## 9. Evidence commands

```bash
git ls-tree -r --name-only 1a46f70 -- apps/
git diff --name-status 1a46f70 a221003
git diff --numstat 1a46f70 a221003
git cat-file -t 933b29f956ea0092aed56745020a4919fe1ffcd6
git cat-file -t 805cd2b17eda826de8ec7b982dc9377315352327
comm -23 <(git show 1a46f70:<file> | sort -u) <(git show a221003:<file> | sort -u)
```
