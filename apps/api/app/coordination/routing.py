"""Routing & assignment engine: configurable rules (DB table) + defaults.

A rule's `match` is JSON with optional keys: kind, event, labels (any-of),
path_prefix (repo path touched), priority (lower wins). Default routing maps
GitHub activity to the owning agent by specialization; unknown -> "unassigned"
(state BLOCKED until a human/owner assigns), never silently dropped.
"""
import json

from sqlalchemy import select

from app import models

DEFAULT_ROUTES = [
    {"name": "ops", "match": {"labels_any": ["ops", "monitoring", "alerting", "health"]}, "agent": "agent-1-ops"},
    {"name": "threat-intel", "match": {"labels_any": ["threat-intel", "ttps", "mitre"]}, "agent": "agent-2-threat-intel"},
    {"name": "vuln-intel", "match": {"labels_any": ["vuln", "cve", "osv", "nvd"]}, "agent": "agent-3-vuln-intel"},
    {"name": "integration", "match": {"labels_any": ["integration", "coordination", "apps"]}, "agent": "agent-4-integration"},
]


def _matches(rule_match: dict, task_payload: dict, kind: str) -> bool:
    if "kind" in rule_match and rule_match["kind"] != kind:
        return False
    if "event" in rule_match and rule_match["event"] != task_payload.get("event"):
        return False
    labels = set(task_payload.get("labels") or [])
    if "labels_any" in rule_match and not labels.intersection(rule_match["labels_any"]):
        return False
    if "labels_all" in rule_match and not set(rule_match["labels_all"]).issubset(labels):
        return False
    return True


def route(s, task: models.CoordinationTask) -> str | None:
    """Return the assigned agent id (or None -> BLOCKED/unassigned)."""
    payload = {}
    try:
        payload = json.loads(task.payload) if task.payload else {}
    except Exception:
        payload = {}
    rules = s.execute(
        select(models.RoutingRule).where(models.RoutingRule.enabled.is_(True))
        .order_by(models.RoutingRule.priority.asc(), models.RoutingRule.id.asc())
    ).scalars().all()
    for r in rules:
        try:
            m = json.loads(r.match)
        except Exception:
            continue
        if _matches(m, payload, task.kind or ""):
            return r.agent
    for d in DEFAULT_ROUTES:
        if _matches(d["match"], payload, task.kind or ""):
            return d["agent"]
    return None


def seed_default_rules(s) -> int:
    """Idempotently seed the DEFAULT_ROUTES into the rules table."""
    added = 0
    for i, d in enumerate(DEFAULT_ROUTES):
        exists = s.execute(
            select(models.RoutingRule).where(models.RoutingRule.name == d["name"])
        ).scalar_one_or_none()
        if exists is None:
            s.add(models.RoutingRule(priority=100 + i, name=d["name"], match=json.dumps(d["match"]), agent=d["agent"]))
            added += 1
    return added
