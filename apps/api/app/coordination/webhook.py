"""GitHub webhook ingestion: HMAC signature validation, replay protection,
dedup by delivery id, normalization with provenance, secrets stripped.

Fail-closed: when CICC_GH_WEBHOOK_SECRET is unset the endpoint answers 401
(no unauthenticated ingestion). Signature: X-Hub-Signature-256 =
"sha256=" + HMAC_SHA256(secret, raw_body). Replay: X-GitHub-Delivery id is the
primary key of coord_github_events — duplicates are acknowledged but not
re-processed.
"""
import hashlib
import hmac
import json
import os

from sqlalchemy import select

from app import models
from . import registry

# Only allowlisted event types can create coordination tasks (privileged ops
# are never triggered by arbitrary payloads). Configurable via env.
DEFAULT_ALLOWLIST = ("pull_request", "issues", "issue_comment",
                     "pull_request_review", "pull_request_review_comment", "check_run")
MAX_BODY_BYTES = 256 * 1024

EVENT_KINDS = {
    "pull_request": lambda p: f"pr_{p.get('action')}",
    "issues": lambda p: f"issue_{p.get('action')}",
    "issue_comment": lambda p: "issue_comment",
    "pull_request_review": lambda p: f"review_{p.get('action')}",
    "pull_request_review_comment": lambda p: "review_comment",
    "check_run": lambda p: f"ci_{p.get('check_run', {}).get('conclusion') or p.get('action')}",
    "push": lambda p: "push",
}


def verify_signature(secret: str, body: bytes, signature_header: str | None) -> bool:
    if not secret or not signature_header:
        return False
    if not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def normalize(event: str, payload: dict) -> dict:
    """Canonical event shape; provenance kept; secrets stripped."""
    repo = (payload.get("repository") or {}).get("full_name")
    sender = (payload.get("sender") or {}).get("login")
    pr = payload.get("pull_request") or {}
    issue = payload.get("issue") or {}
    ref = pr.get("number") or issue.get("number")
    kind_fn = EVENT_KINDS.get(event)
    kind = kind_fn(payload) if kind_fn else event
    labels = [l.get("name") for l in (pr.get("labels") or issue.get("labels") or []) if isinstance(l, dict)]
    # strip anything that looks like a credential from the normalized copy
    safe = json.loads(json.dumps(payload, default=str))
    for k in ("token", "authorization", "secret", "password"):
        _strip_keys(safe, k)
    return {
        "event": event,
        "kind": kind,
        "action": payload.get("action"),
        "repo": repo,
        "sender": sender,
        "pr": ref,
        "branch": pr.get("head", {}).get("ref") if pr else payload.get("ref"),
        "labels": labels,
        "title": pr.get("title") or issue.get("title"),
        "payload": safe,
    }


def _strip_keys(obj, key: str) -> None:
    if isinstance(obj, dict):
        obj.pop(key, None)
        for v in obj.values():
            _strip_keys(v, key)
    elif isinstance(obj, list):
        for v in obj:
            _strip_keys(v, key)


def allowlist() -> set[str]:
    import os

    raw = os.getenv("CICC_GH_EVENT_ALLOWLIST", ",".join(DEFAULT_ALLOWLIST))
    return {e.strip() for e in raw.split(",") if e.strip()}


def ingest(s, delivery_id: str, event: str, body: bytes, signature: str | None,
           secret: str | None) -> dict:
    """Validate + dedup + normalize + create registry task. Returns a result
    dict; never raises on bad input (fail closed with 4xx semantics)."""
    if not secret:
        return {"ok": False, "code": 401, "reason": "webhook secret not configured (fail closed)"}
    if not verify_signature(secret, body, signature):
        return {"ok": False, "code": 401, "reason": "invalid signature"}
    if len(body) > MAX_BODY_BYTES:
        return {"ok": False, "code": 413, "reason": "payload too large"}
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        return {"ok": False, "code": 400, "reason": "invalid json"}
    if not isinstance(payload, dict):
        return {"ok": False, "code": 400, "reason": "payload must be a JSON object"}
    existing = s.get(models.GitHubEvent, delivery_id)
    if existing is not None:
        return {"ok": True, "duplicate": True, "delivery_id": delivery_id, "task_id": None}
    norm = normalize(event, payload)
    s.add(models.GitHubEvent(
        delivery_id=delivery_id, event=event, action=norm["action"], repo=norm["repo"],
        sender=norm["sender"], normalized=json.dumps(norm),
    ))
    task_id = f"gh-{delivery_id}"
    if event not in allowlist():
        # recorded for provenance, but never creates a task
        registry.record_event(s, task_id, "event_not_allowlisted", f"event={event}")
        s.commit()
        return {"ok": True, "duplicate": False, "delivery_id": delivery_id, "task_id": None,
                "kind": norm["kind"], "state": None, "note": f"event type '{event}' not in allowlist; recorded only"}
    requires_approval = bool(norm.get("payload", {}).get("requires_approval")) or event in ("pull_request_review",)
    t = registry.create_task(
        s, task_id=task_id, event_id=delivery_id, source="github", kind=norm["kind"],
        repo=norm["repo"], pr_ref=str(norm["pr"]) if norm["pr"] else None,
        branch_ref=norm["branch"], title=norm["title"], payload=norm,
        priority=int(norm.get("payload", {}).get("priority") or 5),
        idempotency_key=f"gh:{delivery_id}",
        requires_approval=requires_approval,
    )
    if requires_approval:
        from . import approvals

        approvals.request_approval(s, t, norm.get("sender"))
    s.commit()
    return {"ok": True, "duplicate": False, "delivery_id": delivery_id, "task_id": task_id,
            "kind": norm["kind"], "state": registry.normalize_state(t.state)}
