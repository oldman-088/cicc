#!/usr/bin/env python3
"""M46 — repeatable MERGED-APPLICATION acceptance test + live ops spot checks.

Merged-app phase runs only after the GitHub API reports PR #1 and PR #3
merged into main AND each PR's exact merge-result commit is reachable from the
exact main SHA queried for this run. PR head SHAs are also checked and recorded
(they need not be ancestors after squash/rebase merges). The script then exports
that exact main tree, mounts TI and VI from it, invokes both through the host
gateway, and records route statuses, response provenance, task/trace correlation,
and the evidence class.

If the PRs are not merged or their merge-result SHAs cannot be verified on main,
the merged-app phase reports NOT RUN. It never infers integration from an open
PR head, a preview merge SHA, package presence, or a sandbox execution.

Ops phase (always, against the running API — SANDBOX evidence): health,
metrics bounded labels, alert history, circuit metrics, and BFF read-only access.

Usage: API=http://127.0.0.1:8000 WEB=http://127.0.0.1:3000 \
       WRITE_TOKEN=smoke-write READ_TOKEN=smoke-read \
       python3 scripts/m46_merged_app_acceptance.py [--export-dir /tmp/cicc-main]
"""
import argparse
import json
import os
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

API = os.environ.get("API", "http://127.0.0.1:8000")
WEB = os.environ.get("WEB", "http://127.0.0.1:3000")
W = os.environ.get("WRITE_TOKEN", "smoke-write")
R = os.environ.get("READ_TOKEN", "smoke-read")
REPO = "oldman-088/cicc"
results = []


def as_dict(value):
    return value if isinstance(value, dict) else {}


def call(base, method, path, body=None, token=None, timeout=60):
    req = urllib.request.Request(base + path,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            p = resp.read().decode()
            return resp.status, (json.loads(p) if p else {}), dict(resp.headers)
    except urllib.error.HTTPError as e:
        p = e.read().decode()
        try:
            p = json.loads(p)
        except Exception:
            pass
        return e.code, p, dict(e.headers)


def check(name, cond, detail="", label="SANDBOX/FIXTURE"):
    results.append((name, bool(cond), label))
    print(f"[{'PASS' if cond else 'FAIL'}] [{label}] {name} {detail}")


def gh(*args):
    r = subprocess.run(["gh", "api", *args], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout)
    except (TypeError, json.JSONDecodeError):
        return None


def pr_state(num):
    d = gh(f"repos/{REPO}/pulls/{num}")
    if not d:
        return {"merged": False, "head_sha": None, "merge_commit_sha": None,
                "base_ref": None, "state": "unknown", "merged_at": None}
    return {
        "merged": bool(d.get("merged")),
        "head_sha": d.get("head", {}).get("sha"),
        # For an OPEN PR GitHub may expose a test-merge candidate here. It is
        # not treated as an integration commit unless merged == true.
        "merge_commit_sha": d.get("merge_commit_sha"),
        "base_ref": d.get("base", {}).get("ref"),
        "state": d.get("state"),
        "merged_at": d.get("merged_at"),
    }


def main_sha():
    d = gh(f"repos/{REPO}/commits/main")
    return d.get("sha") if d else None


def commit_on_main(sha, main):
    """Verify reachability by comparing candidate commit (base) to main (head)."""
    if not sha or not main:
        return {"on_main": False, "status": "missing_sha", "ahead_by": None, "behind_by": None}
    d = gh(f"repos/{REPO}/compare/{sha}...{main}")
    if not d:
        return {"on_main": False, "status": "unavailable", "ahead_by": None, "behind_by": None}
    status = d.get("status")
    ahead_by = d.get("ahead_by")
    behind_by = d.get("behind_by")
    # With candidate as base and main as head, main equal to or descended from
    # candidate is status=identical|ahead with no commits behind main.
    reachable = status in ("identical", "ahead") and behind_by == 0
    return {"on_main": reachable, "status": status,
            "ahead_by": ahead_by, "behind_by": behind_by}


def verify_pr_on_main(pr, main):
    """Return explicit head/merge reachability; require merged result on main."""
    head_check = commit_on_main(pr.get("head_sha"), main)
    merged = bool(pr.get("merged"))
    merge_check = (commit_on_main(pr.get("merge_commit_sha"), main) if merged else
                   {"on_main": False, "status": "pr_not_merged", "ahead_by": None, "behind_by": None})
    verified = bool(
        merged and pr.get("base_ref") == "main" and pr.get("merged_at")
        and pr.get("merge_commit_sha") and merge_check["on_main"]
    )
    return {"verified": verified, "head_on_main": head_check["on_main"],
            "head_check": head_check, "merge_check": merge_check}


def export_main(sha, dest):
    """Export one immutable main SHA into a commit-specific subdirectory."""
    export_dest = os.path.join(dest, f"main-{sha}")
    os.makedirs(export_dest, exist_ok=True)
    url = f"https://codeload.github.com/{REPO}/tar.gz/{sha}"
    with urllib.request.urlopen(url, timeout=120) as resp:
        data = resp.read()
    with tarfile.open(fileobj=__import__("io").BytesIO(data), mode="r:gz") as tf:
        members = tf.getmembers()
        if not members:
            raise RuntimeError("empty codeload archive")
        # Python 3.11 lacks extractall(filter=...). Validate every archive path
        # and reject links/devices before using the compatible extractor.
        for member in members:
            parts = member.name.replace("\\", "/").split("/")
            if (member.name.startswith("/") or ".." in parts
                    or member.issym() or member.islnk() or member.isdev()):
                raise RuntimeError(f"unsafe codeload archive member: {member.name}")
        prefix = members[0].name.split("/", 1)[0]
        tf.extractall(export_dest)
    root = os.path.join(export_dest, prefix)
    if not os.path.isdir(root):
        raise RuntimeError("codeload archive root not found")
    return root


def mount_real(kind, wrapper_body, version, source_ref):
    wr = tempfile.NamedTemporaryFile("w", suffix=f"_m46_{kind}.py", delete=False)
    wr.write(wrapper_body)
    wr.close()
    call(API, "POST", f"/api/v1/coordination/domains/{kind}/deregister", None, W)
    st, m, _ = call(API, "POST", f"/api/v1/coordination/domains/{kind}/mount",
                    {"module_path": wr.name, "attr": "handle", "version": version,
                     "source_ref": source_ref}, W)
    os.unlink(wr.name)
    return st, as_dict(m)


def trace_for(inv):
    task_id = as_dict(inv).get("task_id")
    if not task_id:
        return 0, {}
    st, trace, _ = call(API, "GET", f"/api/v1/coordination/tasks/{task_id}/trace", token=R)
    return st, as_dict(trace)


def print_domain_evidence(kind, module_sha, mount_status, invoke_status, inv, trace_status, trace):
    inv = as_dict(inv)
    trace = as_dict(trace)
    provenance = as_dict(inv.get("provenance"))
    correlation = as_dict(trace.get("correlation"))
    event_kinds = [e.get("kind") for e in trace.get("events", []) if isinstance(e, dict)]
    print(f"  exact_module_ref=main@{module_sha} route_mount=POST /api/v1/coordination/domains/{kind}/mount "
          f"status={mount_status}; route_invoke=POST /api/v1/coordination/domains/{kind}/invoke "
          f"status={invoke_status}")
    print(f"  response.task_id={inv.get('task_id')} state={inv.get('state')} "
          f"result={json.dumps(inv.get('result'), sort_keys=True, default=str)}")
    print(f"  provenance={json.dumps(provenance, sort_keys=True, default=str)}")
    print(f"  route_trace=GET /api/v1/coordination/tasks/{inv.get('task_id')}/trace status={trace_status}; "
          f"trace_task_id={trace.get('task_id')} correlation.idempotency_key="
          f"{correlation.get('idempotency_key')} correlation.event_id={correlation.get('event_id')} "
          f"event_kinds={event_kinds}; standalone_trace_id_field="
          f"{'present' if trace.get('trace_id') else 'not-exposed (task_id is trace handle)'}")


def trace_matches(inv, trace_status, trace):
    inv = as_dict(inv)
    trace = as_dict(trace)
    tid = inv.get("task_id")
    kinds = [e.get("kind") for e in trace.get("events", []) if isinstance(e, dict)]
    trace_result = as_dict(trace.get("result"))
    return bool(
        tid and trace_status == 200 and trace.get("task_id") == tid
        and trace.get("state") == "COMPLETED" and "domain_result" in kinds
        and trace_result.get("provenance") == inv.get("provenance")
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--export-dir", default="/tmp/cicc-main-m46")
    args = ap.parse_args()
    run = str(int(time.time()))
    print(f"== M46 MERGED-APP ACCEPTANCE @ {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} run={run} ==")

    # ---------- exact merged-application gate (verified, not assumed) ----------
    p1, p3 = pr_state(1), pr_state(3)
    msha = main_sha()
    v1, v3 = verify_pr_on_main(p1, msha), verify_pr_on_main(p3, msha)
    print(f"main_sha={msha}")
    for number, pr, verification in ((1, p1, v1), (3, p3, v3)):
        print(f"PR#{number}: state={pr['state']} merged={pr['merged']} base={pr['base_ref']} "
              f"head_sha={pr['head_sha']} head_on_main={verification['head_on_main']} "
              f"head_compare={verification['head_check']['status']} "
              f"merge_commit_sha={pr['merge_commit_sha']} "
              f"merge_commit_on_main={verification['merge_check']['on_main']} "
              f"merge_compare={verification['merge_check']['status']} merged_at={pr['merged_at']}")
    merged_app_verified = bool(msha and v1["verified"] and v3["verified"])
    if merged_app_verified:
        root = export_main(msha, args.export_dir)
        ti_mod = os.path.join(root, "apps", "threat_intelligence", "api.py")
        vi_pkg = os.path.join(root, "packages", "vuln_intel")
        api_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

        if os.path.exists(ti_mod):
            ti_src = f"main {msha} (PR #3 merge-result SHA {p3['merge_commit_sha']})"
            st, mounted = mount_real(
                "threat_intel",
                f"import sys\nsys.path.insert(0, {api_root!r})\n"
                "from app.coordination.domain_adapters.threat_intel_adapter import make_handler\n"
                f"handle = make_handler({ti_mod!r})\n",
                f"main@{msha}", ti_src)
            invoke_status, inv, _ = call(
                API, "POST", "/api/v1/coordination/domains/threat_intel/invoke",
                {"payload": {"query": "apt29"}, "idempotency_key": f"{run}-mti"}, W)
            trace_status, trace = trace_for(inv)
            provenance = as_dict(inv).get("provenance", {})
            print_domain_evidence("threat_intel", msha, st, invoke_status, inv, trace_status, trace)
            check("MERGED-APP: TI exact-main module mounted, invoked, provenance + trace verified",
                  st == 201 and invoke_status == 201
                  and as_dict(inv).get("state") == "COMPLETED"
                  and as_dict(provenance).get("experimental_label") == "EXPERIMENTAL_DEMO_DATA_ONLY"
                  and trace_matches(inv, trace_status, trace),
                  f"main_sha={msha} PR#3_head_sha={p3['head_sha']} "
                  f"PR#3_merge_commit_sha={p3['merge_commit_sha']} mount={st} invoke={invoke_status} "
                  f"task_id={as_dict(inv).get('task_id')} trace_status={trace_status}",
                  label="MERGED-APPLICATION")
        else:
            check("MERGED-APP: TI module present in verified main tree", False, ti_mod,
                  label="MERGED-APPLICATION")

        if os.path.isdir(os.path.join(vi_pkg, "vuln_intel")):
            vi_src = f"main {msha} (PR #1 merge-result SHA {p1['merge_commit_sha']})"
            st, mounted = mount_real(
                "vuln_intel",
                f"import sys\nsys.path.insert(0, {api_root!r})\n"
                "from app.coordination.domain_adapters.vuln_intel_adapter import make_handler\n"
                f"handle = make_handler({vi_pkg!r})\n",
                f"main@{msha}", vi_src)
            invoke_status, inv, _ = call(
                API, "POST", "/api/v1/coordination/domains/vuln_intel/invoke",
                {"payload": {"op": "search", "query": "log4shell", "records": [
                    {"cve": "CVE-2021-44228", "origin": "demo", "summary": "log4shell",
                     "severity": "critical", "kev": True}]},
                 "idempotency_key": f"{run}-mvi"}, W)
            trace_status, trace = trace_for(inv)
            provenance = as_dict(inv).get("provenance", {})
            print_domain_evidence("vuln_intel", msha, st, invoke_status, inv, trace_status, trace)
            check("MERGED-APP: VI exact-main module mounted, invoked, provenance + trace verified",
                  st == 201 and invoke_status == 201
                  and as_dict(inv).get("state") == "COMPLETED"
                  and as_dict(inv).get("result", {}).get("count") == 1
                  and str(as_dict(provenance).get("data_origin", "")).startswith("non-live")
                  and trace_matches(inv, trace_status, trace),
                  f"main_sha={msha} PR#1_head_sha={p1['head_sha']} "
                  f"PR#1_merge_commit_sha={p1['merge_commit_sha']} mount={st} invoke={invoke_status} "
                  f"task_id={as_dict(inv).get('task_id')} trace_status={trace_status}",
                  label="MERGED-APPLICATION")
        else:
            check("MERGED-APP: VI package present in verified main tree", False, vi_pkg,
                  label="MERGED-APPLICATION")
    else:
        print("[SKIP] MERGED-APPLICATION phase NOT RUN: requires PR #1 and PR #3 merged to main "
              "AND each exact PR merge-result SHA verified reachable from the queried main SHA. "
              f"main={msha}; PR#1 merged={p1['merged']} head={p1['head_sha']} "
              f"merge_sha={p1['merge_commit_sha']} merge_on_main={v1['merge_check']['on_main']}; "
              f"PR#3 merged={p3['merged']} head={p3['head_sha']} "
              f"merge_sha={p3['merge_commit_sha']} merge_on_main={v3['merge_check']['on_main']}. "
              "No merged-integration claim is made.")

    # ---------- live ops reliability spot checks (SANDBOX) ----------
    st, live, _ = call(API, "GET", "/live")
    check("ops: API liveness", st == 200, f"st={st}")
    st, comp, _ = call(API, "GET", "/api/v1/ops/components", token=R)
    svcs = as_dict(comp).get("services", [])
    db = [c for c in svcs if c.get("key") == "database"]
    check("ops: health components incl. database ok",
          st == 200 and bool(db) and db[0].get("status") == "ok",
          f"st={st} database={db[:1]}")
    st, m, _ = call(API, "GET", "/api/v1/coordination/domains/metrics", token=R)
    check("ops: metrics readable with read token, labels bounded to kind",
          st == 200 and as_dict(m).get("labels") == ["kind"],
          f"st={st} labels={as_dict(m).get('labels')}")
    st, ah, _ = call(API, "GET", "/api/v1/ops/alerts/history?rule=domain_status", token=R)
    check("ops: domain alert history endpoint live", st == 200 and "alerts" in as_dict(ah),
          f"st={st} n={len(as_dict(ah).get('alerts', []))}")
    st, d, _ = call(API, "GET", "/api/v1/coordination/domains", token=R)
    kinds = sorted(as_dict(d).get("statuses", {}).keys())
    check("ops: domain statuses visible (evidence-based)", st == 200, f"kinds={kinds}")
    st, _, _ = call(API, "GET", "/api/v1/coordination/domains/metrics")
    check("ops: metrics 401 without token", st == 401, f"st={st}")
    st, _, _ = call(WEB, "GET", "/api/v1/coordination/domains")
    check("ops: BFF read-only domain visibility for frontend", st == 200, f"st={st}")

    passed = sum(1 for _, ok, _ in results if ok)
    labels = sorted({label for _, _, label in results})
    print(f"\n== M46 RESULT: {passed}/{len(results)} PASS @ "
          f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} ==")
    print(f"   Evidence classes: {', '.join(labels)}. MERGED-APPLICATION: "
          f"{'VERIFIED GATE + TESTS RUN' if merged_app_verified else 'NOT RUN (PR #1/#3 merge SHAs not verified on main)'}; "
          "PRODUCTION-VERIFIED: never claimed.")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
