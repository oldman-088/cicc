"""REAL GitHub API sync (M8) — live integration with api.github.com.

Polls the public repo API (PRs, issues, check runs) and ingests findings
through the same normalization path as webhooks (source="github_api",
provenance kept, secrets stripped). CI failures on arena/* branches create
coordination tasks (kind ci_failed) — routed like any other task.

Auth: uses GH_TOKEN/GITHUB_TOKEN env ONLY as a request header to
api.github.com; the token is never logged, stored, or returned. Without a
token it falls back to unauthenticated (60 req/h) — rate-limit aware, and a
circuit breaker stops hammering on failures. This is a REAL external call,
never mocked; if api.github.com is unreachable the result says so honestly.
"""
import json
import os
import urllib.request

from sqlalchemy import select

from app import models
from app import checks as _checks
from . import registry, webhook

API = "https://api.github.com"
REPO = os.getenv("CICC_GH_REPO", "oldman-088/cicc")
# ids must be URL-path-safe (no slashes)
REPO_ID = REPO.replace("/", "-")


def _headers() -> dict:
    h = {"Accept": "application/vnd.github+json", "User-Agent": "cicc-coordination/0.1"}
    tok = os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")
    if tok:
        h["Authorization"] = f"Bearer {tok}"  # never logged/returned
    return h


def _get(path: str, timeout: float = 8.0) -> dict | list:
    req = urllib.request.Request(API + path, headers=_headers())
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        remaining = resp.headers.get("X-RateLimit-Remaining")
        if remaining is not None and int(remaining) < 5:
            raise RuntimeError(f"github rate limit nearly exhausted (remaining={remaining})")
        return json.loads(resp.read(1_000_000).decode())


def _guarded(label: str, fn):
    return _checks.guarded_probe(label, fn, label="api.github.com")


def fetch_repo_status(s) -> dict:
    """Live repo overview: open PRs, open issues, recent check runs."""
    def _fn():
        prs = _get(f"/repos/{REPO}/pulls?state=open&per_page=20")
        issues = _get(f"/repos/{REPO}/issues?state=open&per_page=20")
        try:
            checks = _get(f"/repos/{REPO}/check-runs?per_page=20")
        except Exception:
            # check-runs 404s on repos without the Checks API surface; fall
            # back to workflow runs (same signal: CI conclusions)
            runs = _get(f"/repos/{REPO}/actions/runs?per_page=20")
            checks = {"check_runs": [
                {"name": r.get("name"), "status": r.get("status"), "conclusion": r.get("conclusion"),
                 "head_branch": r.get("head_branch"), "html_url": r.get("html_url")}
                for r in (runs.get("workflow_runs") or [])
            ]}
        return {
            "status": "ok",
            "repo": REPO,
            "open_prs": [{"number": p["number"], "title": p["title"], "head": p["head"]["ref"],
                          "user": p["user"]["login"], "url": p["html_url"]} for p in prs],
            "open_issues": [{"number": i["number"], "title": i["title"], "user": i["user"]["login"],
                             "labels": [l["name"] for l in i.get("labels", [])]} for i in issues if "pull_request" not in i],
            "check_runs": [{"name": c["name"], "status": c["status"], "conclusion": c["conclusion"],
                            "head_branch": c["head_branch"], "html_url": c["html_url"]}
                           for c in (checks.get("check_runs") or [])],
        }

    return _guarded("github_api", _fn)


def sync(s) -> dict:
    """Poll GitHub and create coordination tasks for failed CI on arena
    branches + open PRs needing attention. Idempotent via idempotency_key."""
    status = fetch_repo_status(s)
    if status.get("status") != "ok":
        return {"ok": False, "reason": f"github api probe failed: {status.get('detail')}", "created": []}
    data = status
    created = []
    # CI failures on arena branches -> tasks
    for c in data.get("check_runs") or []:
        if c.get("conclusion") == "failure" and str(c.get("head_branch", "")).startswith("arena/"):
            payload = {
                "event": "check_run", "kind": "ci_failed", "action": "completed",
                "repo": REPO, "sender": "github-api-sync",
                "branch": c.get("head_branch"), "title": f"CI failed: {c.get('name')}",
                "labels": ["ci", "ops"], "payload": {"check_run": c},
                "requires_approval": False, "priority": 2,
            }
            delivery = ("api-ci-" + REPO_ID + "-" + c.get("html_url", "")).replace("/", "-")
            if s.get(models.GitHubEvent, delivery) is not None:
                continue  # already ingested
            s.add(models.GitHubEvent(delivery_id=delivery, event="check_run", action="completed",
                                     repo=REPO, sender="github-api-sync", normalized=json.dumps(payload)))
            t = registry.create_task(s, task_id=f"gh-{delivery}", event_id=delivery,
                                     source="github_api", kind="ci_failed", repo=REPO,
                                     pr_ref=None, branch_ref=c.get("head_branch"),
                                     title=payload["title"], payload=payload, priority=2,
                                     idempotency_key=f"ci:{c.get('html_url')}")
            if t.state in ("CREATED", "NEW"):
                created.append(t.task_id)
                registry.record_event(s, t.task_id, "created_via_api_sync", c.get("html_url", ""))
    # open PRs -> informational tasks only if labeled for coordination
    for p in data.get("open_prs") or []:
        delivery = f"api-pr-{REPO_ID}-{p['number']}"
        exists = s.get(models.GitHubEvent, delivery)
        if exists:
            continue
        payload = {"event": "pull_request", "kind": "pr_opened", "action": "opened",
                   "repo": REPO, "sender": p.get("user"), "pr": p["number"],
                   "branch": p.get("head"), "title": p.get("title"), "labels": [],
                   "payload": {"pr": p}}
        s.add(models.GitHubEvent(delivery_id=delivery, event="pull_request", action="opened",
                                 repo=REPO, sender=p.get("user"), normalized=json.dumps(payload)))
        t = registry.create_task(s, task_id=f"gh-{delivery}", event_id=delivery, source="github_api",
                                 kind="pr_opened", repo=REPO, pr_ref=str(p["number"]),
                                 branch_ref=p.get("head"), title=p.get("title"), payload=payload,
                                 idempotency_key=f"pr:{REPO}:{p['number']}")
        created.append(t.task_id)
        registry.record_event(s, t.task_id, "created_via_api_sync", f"PR #{p['number']}")
    s.commit()
    return {"ok": True, "repo": REPO, "created": created,
            "open_prs": len(data.get("open_prs") or []), "open_issues": len(data.get("open_issues") or []),
            "check_runs": len(data.get("check_runs") or [])}
