"""Workload-aware routing engine v2 (M7).

Scores every eligible agent deterministically and returns an EXPLANATION
(reasons list) for the decision:

  score = 100
        - 25 * active_tasks            (workload)
        - 40 if status == busy          (availability)
        + 15 if specialization matches task domain
        + 10 per required capability present (cap at +30)
        + 5  * completion rate bonus (completed / (completed+failed), capped)
        - 10 * retries                  (retry history)
        - 50 * priority penalty for low-priority tasks on loaded agents

Rules (DB) still take precedence: a matching enabled rule assigns directly but
the explanation records the rule. No eligible agent -> None (caller marks
BLOCKED). Never routes to stale/offline/draining agents.
"""
import json

from sqlalchemy import select

from app import models
from . import agents as agent_registry

DEFAULT_ROUTES = [
    {"name": "ops", "match": {"labels_any": ["ops", "monitoring", "alerting", "health", "coordination"]}, "agent": "agent-1-ops"},
    {"name": "threat-intel", "match": {"labels_any": ["threat-intel", "ttps", "mitre"]}, "agent": "agent-2-threat-intel"},
    {"name": "vuln-intel", "match": {"labels_any": ["vuln", "cve", "osv", "nvd"]}, "agent": "agent-3-vuln-intel"},
    {"name": "integration", "match": {"labels_any": ["integration", "apps", "ui", "frontend"]}, "agent": "agent-4-integration"},
]

DOMAIN_BY_AGENT = {
    "agent-1-ops": {"ops", "monitoring", "health", "coordination"},
    "agent-2-threat-intel": {"threat-intel", "ttps", "mitre"},
    "agent-3-vuln-intel": {"vuln-intel", "cve", "vuln"},
    "agent-4-integration": {"integration", "ui", "frontend", "apps"},
}


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
    if "repo" in rule_match and rule_match["repo"] != task_payload.get("repo"):
        return False
    return True


def _required_capabilities(task: models.CoordinationTask) -> list[str]:
    try:
        payload = json.loads(task.payload) if task.payload else {}
    except Exception:
        payload = {}
    caps = payload.get("required_capabilities")
    if not caps:
        inner = payload.get("payload")
        if isinstance(inner, dict):
            caps = inner.get("required_capabilities")
    return list(caps) if isinstance(caps, list) else []


def score_agent(agent: dict, task: models.CoordinationTask, required_caps: list[str]) -> tuple[float, list[str]]:
    reasons = []
    score = 100.0
    active = agent["active_tasks"]
    score -= min(25.0, 5.0 * active)
    if active:
        reasons.append(f"workload: {active} active task(s) (-{min(25, 5*active):.0f})")
    if agent["status"] == "busy":
        score -= 40
        reasons.append("status busy (-40)")
    caps = set(agent["capabilities"])
    missing = [c for c in required_caps if c not in caps]
    if missing:
        return -1.0, [f"missing capabilities: {missing}"]
    if required_caps:
        reasons.append(f"capabilities ok: {required_caps} (+{min(30, 10*len(required_caps))})")
        score += min(30.0, 10.0 * len(required_caps))
    domain = DOMAIN_BY_AGENT.get(agent["agent"], set())
    try:
        payload = json.loads(task.payload) if task.payload else {}
    except Exception:
        payload = {}
    labels = set(payload.get("labels") or [])
    if labels & domain:
        score += 15
        reasons.append(f"specialization match: {sorted(labels & domain)} (+15)")
    done, failed = agent["completed"], agent["failed"]
    if done + failed > 0:
        rate = done / (done + failed)
        bonus = round(5 * rate, 1)
        score += bonus
        reasons.append(f"completion rate {rate:.0%} (+{bonus})")
    if agent["retries"]:
        score -= 10 * min(agent["retries"], 3)
        reasons.append(f"retry history: {agent['retries']} (-{10*min(agent['retries'],3)})")
    if task.priority and task.priority <= 2 and active >= 3:
        score -= 50
        reasons.append("low-priority task on loaded agent (-50)")
    if not reasons:
        reasons.append("baseline (no penalties)")
    return score, reasons


def route(s, task: models.CoordinationTask) -> dict:
    """Deterministic workload-aware assignment. Returns
    {"agent": str|None, "explanation": {...}} — never raises."""
    payload = {}
    try:
        payload = json.loads(task.payload) if task.payload else {}
    except Exception:
        payload = {}
    # 1) explicit DB rules win (explainable by rule name)
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
            return {"agent": r.agent, "explanation": {"via": "rule", "rule": r.name,
                                                      "reasons": [f"rule '{r.name}' matched"]}}
    for d in DEFAULT_ROUTES:
        if _matches(d["match"], payload, task.kind or ""):
            return {"agent": d["agent"], "explanation": {"via": "default_rule", "rule": d["name"],
                                                          "reasons": [f"default rule '{d['name']}' matched"]}}
    # 2) workload-aware scoring over eligible agents
    required = _required_capabilities(task)
    candidates = agent_registry.available_agents(s, required)
    if not candidates:
        return {"agent": None, "explanation": {"via": "none", "reasons": ["no available agents (all stale/offline/draining or missing capabilities)"]}}
    best = None
    for a in candidates:
        score, reasons = score_agent(a, task, required)
        if best is None or score > best[0]:
            best = (score, a, reasons)
    if best is None or best[0] < 0:
        return {"agent": None, "explanation": {"via": "none", "reasons": ["no agent satisfied required capabilities"]}}
    score, agent, reasons = best
    return {"agent": agent["agent"], "explanation": {"via": "score", "score": round(score, 1),
                                                     "reasons": reasons, "candidates": len(candidates)}}


def seed_default_rules(s) -> int:
    added = 0
    for i, d in enumerate(DEFAULT_ROUTES):
        exists = s.execute(
            select(models.RoutingRule).where(models.RoutingRule.name == d["name"])
        ).scalar_one_or_none()
        if exists is None:
            s.add(models.RoutingRule(priority=100 + i, name=d["name"], match=json.dumps(d["match"]), agent=d["agent"]))
            added += 1
    return added
