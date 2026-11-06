#!/usr/bin/env python3
"""M47 exact-revision application acceptance runner.

This runner is deliberately fail-closed. It will not call a codeload export,
PR head, fixture, or merge-candidate "merged application" evidence. Before it
starts the local FastAPI app it verifies the exact checkout commit, required
PR merge-result commits (or an explicitly approved integration-checkout attestation),
and exact module subtrees for TI and VI. It then runs the actual app with its
supported DATABASE_URL configuration, mounts the allowlisted Agent 1 adapters,
checks authenticated API/diagnostics/metrics/trace/audit behavior, and performs
a two-process restart drill against the same isolated DB.

Tenant isolation is reported PASS only when an owner-approved tenant test
driver and its approval reference are present and both tenant test credentials
are supplied through the process environment. Without those, the rest of the
application checks still run, but overall acceptance is INCOMPLETE, never PASS.

Usage (after approvals):
  cd apps/api && .venv/bin/python ../../scripts/m47_merged_app_acceptance.py \\
    --checkout ../.. --manifest /secure/m47-acceptance-manifest.json

For an approved pre-merge integration checkout, also pass
  --allow-approved-checkout

No token, DATABASE_URL, tenant identifier, or request payload is printed.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

REPOSITORY = "oldman-088/cicc"
REQUIRED_PRS = (1, 3)
EXPECTED_KINDS = ("threat_intel", "vuln_intel")
ADAPTERS = {
    "threat_intel": {
        "adapter": "threat_intel_adapter",
        "source_filename": "api.py",
        "factory_arg": "module_path",
    },
    "vuln_intel": {
        "adapter": "vuln_intel_adapter",
        "source_filename": None,
        "factory_arg": "package_path",
    },
}
SCHEMA = "cicc-m47-acceptance-manifest/1"


class AcceptanceError(RuntimeError):
    pass


def _run(args: list[str], cwd: Path | None = None, *, check: bool = True) -> str:
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False)
    if check and result.returncode != 0:
        raise AcceptanceError(f"command failed: {args[0]} (exit {result.returncode})")
    return result.stdout.strip()


def git(checkout: Path, *args: str, check: bool = True) -> str:
    return _run(["git", "-C", str(checkout), *args], check=check)


def gh_api(endpoint: str) -> dict:
    result = subprocess.run(["gh", "api", endpoint], text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise AcceptanceError("GitHub API query failed; verify gh authentication and connectivity")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AcceptanceError("GitHub API returned invalid JSON") from exc


def compare_reachability(ancestor: str, descendant: str) -> dict:
    """Return a GitHub compare result; `ahead`/`identical` means reachable."""
    return gh_api(f"repos/{REPOSITORY}/compare/{ancestor}...{descendant}")


def reachable(ancestor: str, descendant: str) -> bool:
    comparison = compare_reachability(ancestor, descendant)
    return comparison.get("status") in ("ahead", "identical") and comparison.get("behind_by", 0) == 0


def _valid_sha(value) -> bool:
    return (isinstance(value, str) and value == value.lower() and len(value) == 40
            and all(c in "0123456789abcdef" for c in value))


def _safe_rel(root: Path, raw: str) -> Path:
    rel = PurePosixPath(raw)
    if rel.is_absolute() or not raw or ".." in rel.parts or "\\" in raw:
        raise AcceptanceError(f"unsafe manifest path: {raw!r}")
    result = (root / Path(*rel.parts)).resolve()
    try:
        result.relative_to(root.resolve())
    except ValueError as exc:
        raise AcceptanceError(f"manifest path escapes checkout: {raw!r}") from exc
    return result


def _git_object_exists(checkout: Path, revision: str) -> bool:
    return subprocess.run(["git", "-C", str(checkout), "cat-file", "-e", f"{revision}^{{commit}}"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def _tree_oid(checkout: Path, revision: str, path: str) -> str:
    return git(checkout, "rev-parse", f"{revision}:{path}")


def validate_manifest(manifest: dict, allow_approved_checkout: bool) -> list[str]:
    errors = []
    if manifest.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA}")
    mode = manifest.get("integration_mode")
    if mode not in ("merged_main", "approved_checkout"):
        errors.append("integration_mode must be merged_main or approved_checkout")
    if mode == "approved_checkout":
        if not allow_approved_checkout:
            errors.append("approved checkout requires --allow-approved-checkout")
        if not isinstance(manifest.get("approval_ref"), str) or not manifest["approval_ref"].strip():
            errors.append("approved checkout requires a non-empty approval_ref")
    if not _valid_sha(manifest.get("application_commit")):
        errors.append("application_commit must be a full 40-character Git SHA")
    required_prs = manifest.get("required_prs", list(REQUIRED_PRS))
    if (not isinstance(required_prs, list)
            or not all(isinstance(n, int) and not isinstance(n, bool) for n in required_prs)
            or not set(REQUIRED_PRS).issubset(set(required_prs))):
        errors.append("required_prs must include integer PR numbers #1 and #3")
    modules = manifest.get("modules")
    if not isinstance(modules, list):
        errors.append("modules must be a list")
        modules = []
    by_kind = {}
    for entry in modules:
        if not isinstance(entry, dict):
            errors.append("each module entry must be an object")
            continue
        kind = entry.get("kind")
        if not isinstance(kind, str) or kind not in EXPECTED_KINDS:
            errors.append("module kind must be threat_intel or vuln_intel")
            continue
        if kind in by_kind:
            errors.append(f"duplicate module entry for {kind}")
        by_kind[kind] = entry
    if set(by_kind) != set(EXPECTED_KINDS):
        errors.append("modules must contain exactly threat_intel and vuln_intel entries")
    for kind in EXPECTED_KINDS:
        item = by_kind.get(kind, {})
        adapter = ADAPTERS[kind]
        if item.get("adapter") != adapter["adapter"]:
            errors.append(f"{kind}.adapter must be Agent 1's allowlisted {adapter['adapter']}")
        if not _valid_sha(item.get("module_revision")):
            errors.append(f"{kind}.module_revision must be a full 40-character SHA")
        for field in ("source_path", "app_path", "source_ref", "owner", "version"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                errors.append(f"{kind}.{field} is required")
        if (not isinstance(item.get("source_pr"), int) or isinstance(item.get("source_pr"), bool)
                or item.get("source_pr") not in REQUIRED_PRS):
            errors.append(f"{kind}.source_pr must identify required PR #1 or PR #3")
        if _valid_sha(item.get("module_revision")) and item.get("version") != item["module_revision"]:
            errors.append(f"{kind}.version must equal its exact module_revision")
        if isinstance(item.get("source_ref"), str) and len(item["source_ref"]) > 256:
            errors.append(f"{kind}.source_ref exceeds the host API limit of 256 characters")
        for field in ("source_path", "app_path"):
            value = item.get(field)
            if isinstance(value, str):
                path = PurePosixPath(value)
                if path.is_absolute() or ".." in path.parts or "\\" in value:
                    errors.append(f"{kind}.{field} must be a safe repository-relative path")
        expected_owner = "Agent 2" if kind == "threat_intel" else "Replacement Agent 3"
        if item.get("owner") and item["owner"] != expected_owner:
            errors.append(f"{kind}.owner must be the assigned {expected_owner}")
        if not isinstance(item.get("probe_payload"), dict):
            errors.append(f"{kind}.probe_payload must be an owner-approved JSON object")
    tenant = manifest.get("tenant_isolation") or {}
    if tenant:
        if not isinstance(tenant, dict):
            errors.append("tenant_isolation must be an object")
        elif (not isinstance(tenant.get("driver"), str) or not tenant["driver"].strip()
              or not isinstance(tenant.get("approval_ref"), str) or not tenant["approval_ref"].strip()):
            errors.append("tenant_isolation driver requires an approval_ref")
        elif (PurePosixPath(tenant["driver"]).is_absolute()
              or ".." in PurePosixPath(tenant["driver"]).parts or "\\" in tenant["driver"]):
            errors.append("tenant_isolation.driver must be a safe repository-relative path")
    return errors


def _pr_status(number: int) -> dict:
    p = gh_api(f"repos/{REPOSITORY}/pulls/{number}")
    return {
        "number": number,
        "state": p.get("state"),
        "merged": bool(p.get("merged")),
        "base_ref": (p.get("base") or {}).get("ref"),
        "head_sha": (p.get("head") or {}).get("sha"),
        "merge_commit_sha": p.get("merge_commit_sha"),
        "merged_at": p.get("merged_at"),
    }


def verify_pr_merge(pr: dict, main_sha: str, application_sha: str) -> bool:
    """Require the exact recorded merge result to be reachable from both refs."""
    if (not pr.get("merged") or pr.get("state") != "closed" or pr.get("base_ref") != "main"
            or not pr.get("merged_at") or not _valid_sha(pr.get("merge_commit_sha"))):
        return False
    return reachable(pr["merge_commit_sha"], main_sha) and reachable(
        pr["merge_commit_sha"], application_sha)


def preflight(checkout: Path, manifest: dict, allow_approved_checkout: bool) -> dict:
    """Verify commit, PR evidence, approvals, adapters, and exact module subtrees."""
    errors = validate_manifest(manifest, allow_approved_checkout)
    result = {"status": "BLOCKED", "application_commit": manifest.get("application_commit"),
              "integration_mode": manifest.get("integration_mode"), "checks": [], "errors": errors,
              "pr_status": [], "module_revisions": []}
    if errors:
        return result

    checkout = checkout.resolve()
    app_sha = manifest["application_commit"]
    try:
        head = git(checkout, "rev-parse", "HEAD")
        dirty = git(checkout, "status", "--porcelain", "--untracked-files=all")
    except AcceptanceError as exc:
        result["errors"].append(str(exc))
        return result
    if head != app_sha:
        result["errors"].append("checkout HEAD does not equal manifest application_commit")
    if dirty:
        result["errors"].append("application checkout is not clean")
    result["checks"].append({"name": "exact_clean_application_checkout", "passed": head == app_sha and not dirty,
                             "head": head, "dirty": bool(dirty)})

    mode = manifest["integration_mode"]
    main_sha = None
    if mode == "merged_main":
        try:
            main_sha = gh_api(f"repos/{REPOSITORY}/commits/main").get("sha")
        except AcceptanceError as exc:
            result["errors"].append(str(exc))
        result["main_sha"] = main_sha
        for number in sorted(set(manifest.get("required_prs", REQUIRED_PRS))):
            try:
                pr = _pr_status(int(number))
                verified = bool(main_sha and verify_pr_merge(pr, main_sha, app_sha))
                pr["merge_result_reachable_from_main_and_application"] = verified
                result["pr_status"].append(pr)
                if not verified:
                    result["errors"].append(f"PR #{number} exact merge-result SHA is not verified in app/main")
            except (AcceptanceError, ValueError) as exc:
                result["errors"].append(f"PR #{number} verification failed: {exc}")
        try:
            app_on_main = bool(main_sha and reachable(app_sha, main_sha))
            result["checks"].append({"name": "application_commit_reachable_from_main", "passed": app_on_main})
            if not app_on_main:
                result["errors"].append("application_commit is not reachable from queried main")
        except AcceptanceError as exc:
            result["errors"].append(str(exc))
    else:
        # This branch is an explicit human attestation, not an automated merge claim.
        result["approval_ref"] = manifest["approval_ref"]
        result["checks"].append({"name": "approved_integration_checkout_attestation", "passed": True,
                                 "approval_ref": manifest["approval_ref"]})
        for number in sorted(set(manifest.get("required_prs", REQUIRED_PRS))):
            try:
                result["pr_status"].append(_pr_status(int(number)))
            except AcceptanceError as exc:
                result["errors"].append(f"PR #{number} status unavailable: {exc}")

    pr_by_number = {p["number"]: p for p in result["pr_status"]}
    for item in manifest["modules"]:
        kind = item["kind"]
        module_path = item["source_path"]
        app_path = item["app_path"]
        try:
            source_pr = pr_by_number.get(item["source_pr"])
            if mode == "merged_main" and (
                    source_pr is None or source_pr.get("head_sha") != item["module_revision"]):
                raise AcceptanceError(f"{kind} module_revision is not the exact source PR head")
            if not _git_object_exists(checkout, item["module_revision"]):
                raise AcceptanceError(f"{kind} source commit object is absent; fetch it without switching branches")
            source_oid = _tree_oid(checkout, item["module_revision"], module_path)
            app_oid = _tree_oid(checkout, app_sha, app_path)
            included = source_oid == app_oid
            adapter_rel = f"apps/api/app/coordination/domain_adapters/{item['adapter']}.py"
            adapter_exists = _safe_rel(checkout, adapter_rel).is_file()
            detail = {"kind": kind, "owner": item["owner"], "source_commit": item["module_revision"],
                      "source_path": module_path, "app_path": app_path, "source_tree": source_oid,
                      "application_tree": app_oid, "tree_matches": included,
                      "adapter": adapter_rel, "adapter_present": adapter_exists}
            result["module_revisions"].append(detail)
            result["checks"].append({"name": f"{kind}_exact_included_revision", "passed": included and adapter_exists})
            if not included:
                result["errors"].append(f"{kind} source subtree differs from the exact application subtree")
            if not adapter_exists:
                result["errors"].append(f"{kind} Agent 1 adapter is not present in application checkout")
        except (AcceptanceError, subprocess.CalledProcessError) as exc:
            result["errors"].append(f"{kind} module revision verification failed: {exc}")

    if not result["errors"]:
        result["status"] = "READY"
    return result


def _api_request(base: str, method: str, path: str, token: str | None = None,
                 payload: dict | None = None, timeout: float = 3.0) -> tuple[int, dict]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
    try:
        body = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        body = {}
    return status, body if isinstance(body, dict) else {"_non_object_response": True}


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _child_environment(database_url: str, app_sha: str, read_token: str, write_token: str) -> dict:
    # Do not inherit ambient credentials, .env contents, or unrelated tokens.
    allow = ("PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "VIRTUAL_ENV",
             "SYSTEMROOT", "WINDIR", "LD_LIBRARY_PATH", "SSL_CERT_FILE", "SSL_CERT_DIR")
    env = {k: os.environ[k] for k in allow if k in os.environ}
    env.update({
        "DATABASE_URL": database_url,
        "CICC_BUILD_SHA": app_sha,
        "CICC_OPS_READ_TOKEN": read_token,
        "CICC_OPS_WRITE_TOKEN": write_token,
        "CICC_COORD_APPROVERS": "m47-acceptance",
        "CICC_DOMAIN_INVOKE_TIMEOUT_S": "10",
        "CICC_DOMAIN_INVOKE_RETRIES": "0",
        "LOG_LEVEL": "WARNING",
    })
    return env


def _start_api(api_dir: Path, base: str, app_sha: str, database_url: str,
               read_token: str, write_token: str, log_file: Path):
    port = int(base.rsplit(":", 1)[1])
    handle = log_file.open("ab")
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=api_dir, env=_child_environment(database_url, app_sha, read_token, write_token),
        stdout=handle, stderr=subprocess.STDOUT, close_fds=True)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            handle.close()
            raise AcceptanceError("actual API process exited during startup")
        try:
            status, _ = _api_request(base, "GET", "/live", timeout=1)
            if status == 200:
                return process, handle
        except (OSError, TimeoutError):
            pass
        time.sleep(0.2)
    process.terminate()
    process.wait(timeout=5)
    handle.close()
    raise AcceptanceError("actual API did not become live within 30 seconds")


def _stop_api(process, handle) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    handle.close()


def _mount_module(base: str, checkout: Path, item: dict, api_dir: Path,
                  run_dir: Path, write_token: str) -> dict:
    kind = item["kind"]
    source_root = _safe_rel(checkout, item["source_path"])
    if kind == "threat_intel":
        module_file = source_root if source_root.is_file() else source_root / ADAPTERS[kind]["source_filename"]
        factory_arg = "module_path"
        arg_value = str(module_file)
    else:
        # The VI adapter expects the directory containing `vuln_intel/`.
        package_dir = source_root
        if package_dir.name != "vuln_intel":
            package_dir = package_dir / "vuln_intel"
        factory_arg = "package_path"
        arg_value = str(package_dir.parent)
    if kind == "threat_intel":
        if not module_file.is_file():
            raise AcceptanceError("threat_intel source module is missing from the exact application checkout")
    elif not (package_dir / "__init__.py").is_file():
        raise AcceptanceError("vuln_intel package is missing from the exact application checkout")

    adapter = ADAPTERS[kind]["adapter"]
    wrapper = run_dir / f"m47_mount_{kind}_{uuid.uuid4().hex}.py"
    wrapper_lines = [
        "import sys",
        f"sys.path.insert(0, {str(api_dir)!r})",
        f"from app.coordination.domain_adapters.{adapter} import make_handler",
        f"handle = make_handler({factory_arg}={arg_value!r}"
        + (f", version_ref={item['module_revision']!r}" if kind == "vuln_intel" else "")
        + ")",
    ]
    wrapper.write_text("\n".join(wrapper_lines) + "\n", encoding="utf-8")
    path = f"/api/v1/coordination/domains/{kind}/mount"
    status, body = _api_request(base, "POST", path, token=write_token,
                                payload={"module_path": str(wrapper), "attr": "handle",
                                         "version": item["module_revision"],
                                         "source_ref": item["source_ref"]})
    wrapper.unlink(missing_ok=True)
    if status != 201 or body.get("version") != item["module_revision"]:
        raise AcceptanceError(f"{kind} actual API mount failed (HTTP {status})")
    return body


def _invoke_and_verify(base: str, item: dict, read_token: str, write_token: str,
                       run_id: str) -> dict:
    kind = item["kind"]
    task_id = f"m47-{kind}-{run_id}"
    status, body = _api_request(
        base, "POST", f"/api/v1/coordination/domains/{kind}/invoke", token=write_token,
        payload={"task_id": task_id, "idempotency_key": task_id,
                 "payload": item["probe_payload"]})
    if status != 201 or body.get("state") != "COMPLETED":
        raise AcceptanceError(f"{kind} authenticated invocation failed (HTTP {status})")
    trace_status, trace = _api_request(base, "GET", f"/api/v1/coordination/tasks/{task_id}/trace",
                                       token=read_token)
    event_kinds = [e.get("kind") for e in trace.get("events", []) if isinstance(e, dict)]
    if (trace_status != 200 or trace.get("task_id") != task_id or "domain_result" not in event_kinds
            or trace.get("state") != "COMPLETED"):
        raise AcceptanceError(f"{kind} trace/correlation verification failed (HTTP {trace_status})")
    audit_status, audit = _api_request(base, "GET", "/api/v1/ops/activity?limit=200", token=read_token)
    events = audit.get("events", [])
    if (audit_status != 200 or not any(
            e.get("source") == "coordination.domains" and task_id in e.get("message", "")
            for e in events if isinstance(e, dict))):
        raise AcceptanceError(f"{kind} persisted audit event not found (HTTP {audit_status})")
    provenance = body.get("provenance") if isinstance(body.get("provenance"), dict) else {}
    result = body.get("result") if isinstance(body.get("result"), dict) else {}
    data_origin = (provenance.get("experimental_label") or provenance.get("data_origin")
                   or result.get("experimental_label") or "UNVERIFIED/NOT_DECLARED")
    if str(data_origin).startswith("non-live:") or data_origin == "EXPERIMENTAL_DEMO_DATA_ONLY":
        data_class = "FIXTURE_OR_DEMO_LABEL_PRESERVED"
    elif data_origin == "live":
        data_class = "MODULE_REPORTED_LIVE (source independently unverified)"
    else:
        data_class = "UNVERIFIED/NOT_DECLARED"
    return {"kind": kind, "task_id": task_id, "invoke_status": status,
            "trace_status": trace_status, "trace_events": event_kinds,
            "audit_event_verified": True, "provenance_source": provenance.get("source"),
            "data_origin": data_origin, "data_evidence": data_class}


def _run_tenant_driver(checkout: Path, base: str, tenant: dict, read_token: str,
                       write_token: str, run_dir: Path) -> dict:
    driver = _safe_rel(checkout, tenant["driver"])
    if not driver.is_file():
        return {"status": "BLOCKED", "reason": "approved tenant-isolation driver is missing"}
    token_a = os.getenv("CICC_M47_TENANT_A_TOKEN")
    token_b = os.getenv("CICC_M47_TENANT_B_TOKEN")
    if not token_a or not token_b:
        return {"status": "BLOCKED", "reason": "two approved tenant test credentials were not supplied"}
    allow = ("PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "VIRTUAL_ENV",
             "SYSTEMROOT", "WINDIR", "LD_LIBRARY_PATH", "SSL_CERT_FILE", "SSL_CERT_DIR")
    env = {k: os.environ[k] for k in allow if k in os.environ}
    env.update({"CICC_M47_API_URL": base, "CICC_M47_READ_TOKEN": read_token,
                "CICC_M47_WRITE_TOKEN": write_token, "CICC_M47_TENANT_A_TOKEN": token_a,
                "CICC_M47_TENANT_B_TOKEN": token_b})
    result = subprocess.run([sys.executable, str(driver)], cwd=checkout, env=env,
                            capture_output=True, text=True, timeout=120, check=False)
    # Never echo child output: it may contain sensitive identity data.
    if result.returncode != 0:
        return {"status": "FAIL", "reason": f"approved tenant driver exited {result.returncode}"}
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"status": "FAIL", "reason": "tenant driver did not emit a JSON result"}
    case_count = payload.get("cases")
    passed = (payload.get("status") == "PASS"
              and payload.get("evidence_class") == "ACTUAL_APPLICATION"
              and isinstance(case_count, int) and not isinstance(case_count, bool) and case_count > 0)
    return {"status": "PASS" if passed else "FAIL", "cases": case_count,
            "evidence_class": payload.get("evidence_class"),
            "approval_ref": tenant.get("approval_ref")}


def _check_auth(base: str, read_token: str, write_token: str) -> None:
    status, _ = _api_request(base, "GET", "/api/v1/coordination/diagnostics")
    if status not in (401, 403):
        raise AcceptanceError(f"unauthenticated diagnostics unexpectedly returned HTTP {status}")
    status, _ = _api_request(base, "POST", "/api/v1/coordination/domains/unknown/invoke",
                             payload={"payload": {}})
    if status not in (401, 403):
        raise AcceptanceError(f"unauthenticated invocation unexpectedly returned HTTP {status}")
    status, diag = _api_request(base, "GET", "/api/v1/coordination/diagnostics", token=read_token)
    if status != 200 or diag.get("build_commit") is None:
        raise AcceptanceError(f"authenticated diagnostics/build commit check failed (HTTP {status})")
    status, _ = _api_request(base, "GET", "/api/v1/coordination/domains/metrics", token=read_token)
    if status != 200:
        raise AcceptanceError(f"authenticated metrics check failed (HTTP {status})")


def run_live_acceptance(checkout: Path, manifest: dict, preflight_result: dict,
                        report_path: Path | None = None) -> dict:
    app_sha = manifest["application_commit"]
    checkout = checkout.resolve()
    api_dir = checkout / "apps" / "api"
    run_report = {"application_evidence": "MERGED-APPLICATION" if manifest["integration_mode"] == "merged_main"
                  else "APPROVED-INTEGRATION-CHECKOUT",
                  "application_commit": app_sha, "preflight": preflight_result,
                  "environment": "DISPOSABLE-LOCAL-APPLICATION", "data_results": [],
                  "tenant_isolation": {"status": "NOT_RUN"}, "restart_recovery": "NOT_RUN"}
    if not api_dir.is_dir() or not (api_dir / "app" / "main.py").is_file():
        raise AcceptanceError("the exact application checkout has no supported apps/api FastAPI entrypoint")

    with tempfile.TemporaryDirectory(prefix="cicc-m47-acceptance-") as tmp:
        run_dir = Path(tmp)
        database_url = os.getenv("CICC_M47_DATABASE_URL")
        if not database_url:
            database_url = "sqlite:///" + str(run_dir / "m47-ops.db")
        read_token = secrets.token_urlsafe(32)
        write_token = secrets.token_urlsafe(32)
        port = _free_port()
        base = f"http://127.0.0.1:{port}"
        log_file = run_dir / "api.log"
        process = handle = None
        try:
            process, handle = _start_api(api_dir, base, app_sha, database_url,
                                         read_token, write_token, log_file)
            _check_auth(base, read_token, write_token)
            mounted = {}
            for item in manifest["modules"]:
                mounted[item["kind"]] = _mount_module(base, checkout, item, api_dir, run_dir, write_token)
            diag_status, diag = _api_request(base, "GET", "/api/v1/coordination/diagnostics", token=read_token)
            if diag_status != 200 or diag.get("build_commit") != app_sha:
                raise AcceptanceError("running API diagnostics do not match the exact application commit")
            live_mounts = {d.get("kind"): d for d in diag.get("mounted_domains", [])}
            for item in manifest["modules"]:
                actual = live_mounts.get(item["kind"], {})
                if actual.get("version") != item["module_revision"]:
                    raise AcceptanceError(f"diagnostics report the wrong {item['kind']} module revision")

            first_results = []
            for item in manifest["modules"]:
                first_results.append(_invoke_and_verify(base, item, read_token, write_token, uuid.uuid4().hex[:12]))
            metrics_status, metrics = _api_request(base, "GET", "/api/v1/coordination/domains/metrics", token=read_token)
            if metrics_status != 200:
                raise AcceptanceError("actual API metrics endpoint failed")
            for item in manifest["modules"]:
                m = metrics.get("domains", {}).get(item["kind"], {})
                if m.get("invokes") != 1 or m.get("successes") != 1:
                    raise AcceptanceError(f"actual API metrics do not match {item['kind']} invocations")
            run_report["data_results"].extend(first_results)
            run_report["diagnostics"] = {"status": diag_status, "build_commit": diag.get("build_commit"),
                                         "version": diag.get("version"), "db_ok": diag.get("db_ok"),
                                         "mounted_revisions": {k: v.get("version") for k, v in live_mounts.items()}}
            run_report["metrics"] = {"status": metrics_status,
                                      "invokes": {k: v.get("invokes") for k, v in metrics.get("domains", {}).items()}}
            _stop_api(process, handle)
            process = handle = None

            # Real second process, same DB and build; handlers must be unmounted,
            # counters must be restored, and a remount+invoke must continue.
            process, handle = _start_api(api_dir, base, app_sha, database_url,
                                         read_token, write_token, log_file)
            restart_diag_status, restart_diag = _api_request(
                base, "GET", "/api/v1/coordination/diagnostics", token=read_token)
            restart_metrics_status, restart_metrics = _api_request(
                base, "GET", "/api/v1/coordination/domains/metrics", token=read_token)
            if (restart_diag_status != 200 or restart_diag.get("build_commit") != app_sha
                    or restart_metrics_status != 200):
                raise AcceptanceError("second process diagnostics/metrics check failed")
            for item in manifest["modules"]:
                kind = item["kind"]
                before_mount = restart_metrics.get("domains", {}).get(kind, {})
                status = before_mount.get("status")
                if before_mount.get("invokes") != 1 or status != "NOT_MOUNTED":
                    raise AcceptanceError(f"{kind} persisted counters or fail-safe unmounted status incorrect after restart")
            second_results = []
            for item in manifest["modules"]:
                _mount_module(base, checkout, item, api_dir, run_dir, write_token)
                second_results.append(_invoke_and_verify(base, item, read_token, write_token, uuid.uuid4().hex[:12]))
            after_status, after_metrics = _api_request(
                base, "GET", "/api/v1/coordination/domains/metrics", token=read_token)
            if after_status != 200 or any(
                    after_metrics.get("domains", {}).get(item["kind"], {}).get("invokes") != 2
                    for item in manifest["modules"]):
                raise AcceptanceError("post-restart remount metrics did not continue from persisted counts")
            run_report["data_results"].extend(second_results)
            run_report["restart_recovery"] = "PASS: same DB/build, handlers NOT_MOUNTED after restart, counters restored, remount/invoke continued"

            tenant = manifest.get("tenant_isolation") or {}
            if tenant:
                tenant_result = _run_tenant_driver(checkout, base, tenant, read_token, write_token, run_dir)
            else:
                tenant_result = {"status": "BLOCKED", "reason": "no owner-approved tenant-isolation driver in manifest"}
            run_report["tenant_isolation"] = tenant_result
            run_report["status"] = "PASS" if tenant_result.get("status") == "PASS" else "INCOMPLETE"
            if run_report["status"] != "PASS":
                run_report["limitation"] = "tenant isolation is not accepted; no production-readiness inference"
        finally:
            if process is not None and handle is not None:
                _stop_api(process, handle)

    if report_path:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(run_report, indent=2) + "\n", encoding="utf-8")
    return run_report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, default=Path(__file__).resolve().parents[1],
                        help="clean local application checkout at the exact accepted commit")
    parser.add_argument("--manifest", type=Path, help="owner-approved integration manifest (no secrets)")
    parser.add_argument("--allow-approved-checkout", action="store_true",
                        help="explicitly permit a pre-merge integration checkout with manifest approval_ref")
    parser.add_argument("--report", type=Path, help="optional sanitized JSON report path")
    parser.add_argument("--preflight-only", action="store_true", help="do not start the application")
    args = parser.parse_args(argv)

    if args.manifest is None:
        prs = []
        try:
            main_sha = gh_api(f"repos/{REPOSITORY}/commits/main").get("sha")
            for number in REQUIRED_PRS:
                prs.append(_pr_status(number))
            result = {"status": "BLOCKED" if any(not p["merged"] for p in prs) else "MANIFEST_REQUIRED",
                      "main_sha": main_sha, "required_prs": prs,
                      "reason": "No owner-approved revision manifest supplied; no application was started."}
        except AcceptanceError as exc:
            result = {"status": "BLOCKED", "reason": str(exc)}
        print(json.dumps(result, indent=2))
        return 2

    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print(json.dumps({"status": "BLOCKED", "reason": "manifest unreadable or invalid JSON"}, indent=2))
        return 2
    if not isinstance(manifest, dict):
        print(json.dumps({"status": "BLOCKED", "reason": "manifest root must be an object"}, indent=2))
        return 2

    gate = preflight(args.checkout, manifest, args.allow_approved_checkout)
    if gate["status"] != "READY":
        result = {"status": "BLOCKED", "application_evidence": "NOT_RUN", "preflight": gate}
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 2
    if args.preflight_only:
        print(json.dumps(gate, indent=2))
        return 0

    try:
        result = run_live_acceptance(args.checkout, manifest, gate, args.report)
    except (AcceptanceError, OSError, subprocess.TimeoutExpired) as exc:
        result = {"status": "FAIL", "application_evidence": "RUN_FAILED",
                  "application_commit": manifest.get("application_commit"),
                  "reason": str(exc)}
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
