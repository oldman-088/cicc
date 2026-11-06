"""M47 fail-closed integration manifest and exact-merge gate tests."""
import importlib.util
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "m47_merged_app_acceptance.py"
SPEC = importlib.util.spec_from_file_location("m47_merged_app_acceptance", SCRIPT)
M47 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M47)

APP = "a" * 40
TI = "b" * 40
VI = "c" * 40


def manifest(mode="merged_main"):
    return {
        "schema": M47.SCHEMA,
        "integration_mode": mode,
        "application_commit": APP,
        "approval_ref": "owner-approved integration checkout #M47" if mode == "approved_checkout" else None,
        "required_prs": [1, 3],
        "modules": [
            {"kind": "threat_intel", "owner": "Agent 2", "adapter": "threat_intel_adapter",
             "source_pr": 3, "module_revision": TI, "source_path": "apps/threat_intelligence",
             "app_path": "apps/threat_intelligence", "source_ref": f"Agent 2 @ {TI}",
             "version": TI, "probe_payload": {"query": "approval-supplied probe"}},
            {"kind": "vuln_intel", "owner": "Replacement Agent 3", "adapter": "vuln_intel_adapter",
             "source_pr": 1, "module_revision": VI, "source_path": "packages/vuln_intel",
             "app_path": "packages/vuln_intel", "source_ref": f"Replacement Agent 3 @ {VI}",
             "version": VI, "probe_payload": {"op": "health", "states": []}},
        ],
    }


def test_open_pr_merge_candidate_never_satisfies_exact_merge_gate(monkeypatch):
    def fail_if_compared(*_):
        raise AssertionError("open PR merge candidate must not be compared as a merge result")

    monkeypatch.setattr(M47, "reachable", fail_if_compared)
    pr = {"merged": False, "state": "open", "base_ref": "main", "merged_at": None,
          "merge_commit_sha": "d" * 40}
    assert M47.verify_pr_merge(pr, "e" * 40, "f" * 40) is False


def test_exact_squash_merge_result_must_be_reachable_from_main_and_app(monkeypatch):
    calls = []

    def reachable(ancestor, descendant):
        calls.append((ancestor, descendant))
        return True

    monkeypatch.setattr(M47, "reachable", reachable)
    merge_sha = "d" * 40
    pr = {"merged": True, "state": "closed", "base_ref": "main",
          "merged_at": "2026-11-06T12:00:00Z", "merge_commit_sha": merge_sha}
    assert M47.verify_pr_merge(pr, "e" * 40, APP) is True
    assert calls == [(merge_sha, "e" * 40), (merge_sha, APP)]


def test_merge_gate_rejects_wrong_base_or_missing_merge_sha(monkeypatch):
    monkeypatch.setattr(M47, "reachable", lambda *_: True)
    base = {"merged": True, "state": "closed", "base_ref": "release",
            "merged_at": "2026-11-06T12:00:00Z", "merge_commit_sha": "d" * 40}
    assert M47.verify_pr_merge(base, "e" * 40, APP) is False
    base["base_ref"] = "main"
    base["merge_commit_sha"] = None
    assert M47.verify_pr_merge(base, "e" * 40, APP) is False


def test_approved_checkout_requires_explicit_opt_in_and_reference():
    doc = manifest(mode="approved_checkout")
    assert M47.validate_manifest(doc, allow_approved_checkout=False) == [
        "approved checkout requires --allow-approved-checkout"]
    doc["approval_ref"] = ""
    errors = M47.validate_manifest(doc, allow_approved_checkout=True)
    assert "approved checkout requires a non-empty approval_ref" in errors


def test_manifest_requires_two_exact_owner_module_revisions():
    doc = manifest()
    doc["modules"] = doc["modules"][:1]
    errors = M47.validate_manifest(doc, allow_approved_checkout=False)
    assert "modules must contain exactly threat_intel and vuln_intel entries" in errors

    doc = manifest()
    doc["modules"][1]["module_revision"] = "short"
    assert "vuln_intel.module_revision must be a full 40-character SHA" in \
        M47.validate_manifest(doc, allow_approved_checkout=False)


def test_manifest_rejects_path_escape_and_wrong_module_owner():
    doc = manifest()
    doc["modules"][0]["source_path"] = "../../outside"
    doc["modules"][1]["owner"] = "Agent 2"
    doc["tenant_isolation"] = {"driver": "../tenant.py", "approval_ref": "approved"}
    errors = M47.validate_manifest(doc, allow_approved_checkout=False)
    assert "threat_intel.source_path must be a safe repository-relative path" in errors
    assert "vuln_intel.owner must be the assigned Replacement Agent 3" in errors
    assert "tenant_isolation.driver must be a safe repository-relative path" in errors


def test_tenant_driver_requires_actual_application_evidence_and_nonzero_cases(tmp_path, monkeypatch):
    checkout = tmp_path
    driver = checkout / "tenant_check.py"
    driver.write_text("# owner-approved test entrypoint\n")
    tenant = {"driver": "tenant_check.py", "approval_ref": "SEC-123"}
    monkeypatch.setenv("CICC_M47_TENANT_A_TOKEN", "tenant-a-secret")
    monkeypatch.setenv("CICC_M47_TENANT_B_TOKEN", "tenant-b-secret")
    monkeypatch.setattr(M47.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=0, stdout=json.dumps({"status": "PASS", "evidence_class": "ACTUAL_APPLICATION", "cases": 0}),
        stderr=""))
    zero = M47._run_tenant_driver(checkout, "http://127.0.0.1:8000", tenant,
                                  "read-token", "write-token", tmp_path)
    assert zero["status"] == "FAIL"
    assert zero["cases"] == 0

    monkeypatch.setattr(M47.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=0, stdout=json.dumps({"status": "PASS", "evidence_class": "ACTUAL_APPLICATION", "cases": 2}),
        stderr=""))
    passed = M47._run_tenant_driver(checkout, "http://127.0.0.1:8000", tenant,
                                    "read-token", "write-token", tmp_path)
    assert passed["status"] == "PASS"
    assert passed["cases"] == 2


def _commit(checkout):
    subprocess.run(["git", "-C", str(checkout), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(checkout), "commit", "-m", "fixture"], check=True,
                   stdout=subprocess.DEVNULL)
    return subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()


def _fake_checkout(path, tamper=False):
    subprocess.run(["git", "init", str(path)], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "M47 test"], check=True)
    (path / "apps/threat_intelligence").mkdir(parents=True)
    (path / "apps/threat_intelligence/api.py").write_text("TI=v1\n")
    (path / "packages/vuln_intel").mkdir(parents=True)
    (path / "packages/vuln_intel/__init__.py").write_text("VI=1\n")
    module_sha = _commit(path)
    (path / "apps/api/app/coordination/domain_adapters").mkdir(parents=True)
    (path / "apps/api/app/coordination/domain_adapters/threat_intel_adapter.py").write_text("# adapter\n")
    (path / "apps/api/app/coordination/domain_adapters/vuln_intel_adapter.py").write_text("# adapter\n")
    if tamper:
        (path / "apps/threat_intelligence/api.py").write_text("TI=changed-after-approved-source\n")
    app_sha = _commit(path)
    return module_sha, app_sha


def test_preflight_checks_exact_module_subtree_and_application_commit(tmp_path, monkeypatch):
    module_sha, app_sha = _fake_checkout(tmp_path / "clean")
    doc = manifest()
    doc["application_commit"] = app_sha
    for item in doc["modules"]:
        item["module_revision"] = module_sha
        item["version"] = module_sha
        item["source_ref"] = f"approved source @ {module_sha}"
    monkeypatch.setattr(M47, "_pr_status", lambda number: {
        "number": number, "state": "closed", "merged": True, "base_ref": "main",
        "head_sha": module_sha, "merge_commit_sha": app_sha,
        "merged_at": "2026-11-06T12:00:00Z"})
    monkeypatch.setattr(M47, "gh_api", lambda endpoint: {"sha": app_sha} if endpoint.endswith("commits/main") else {})
    monkeypatch.setattr(M47, "reachable", lambda ancestor, descendant: ancestor == app_sha or descendant == app_sha)

    result = M47.preflight(tmp_path / "clean", doc, allow_approved_checkout=False)
    assert result["status"] == "READY"
    assert all(m["tree_matches"] and m["adapter_present"] for m in result["module_revisions"])


def test_preflight_rejects_module_subtree_drift_even_when_app_sha_is_pinned(tmp_path, monkeypatch):
    module_sha, app_sha = _fake_checkout(tmp_path / "drifted", tamper=True)
    doc = manifest()
    doc["application_commit"] = app_sha
    for item in doc["modules"]:
        item["module_revision"] = module_sha
        item["version"] = module_sha
        item["source_ref"] = f"approved source @ {module_sha}"
    monkeypatch.setattr(M47, "_pr_status", lambda number: {
        "number": number, "state": "closed", "merged": True, "base_ref": "main",
        "head_sha": module_sha, "merge_commit_sha": app_sha,
        "merged_at": "2026-11-06T12:00:00Z"})
    monkeypatch.setattr(M47, "gh_api", lambda endpoint: {"sha": app_sha} if endpoint.endswith("commits/main") else {})
    monkeypatch.setattr(M47, "reachable", lambda ancestor, descendant: ancestor == app_sha or descendant == app_sha)

    result = M47.preflight(tmp_path / "drifted", doc, allow_approved_checkout=False)
    assert result["status"] == "BLOCKED"
    assert any("threat_intel source subtree differs" in error for error in result["errors"])
