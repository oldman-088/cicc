"""M38 — Threat Intelligence domain adapter (Agent 2, PR #3).

Wraps Agent 2's ``apps/threat_intelligence/api.py`` (class ThreatIntelligenceAPI,
``invoke_endpoint(path, ThreatIntelligenceRequest) -> dict``) READ-ONLY into the
coordination gateway handler contract:

    handle(payload, task) -> {"result": ..., "provenance": {...}}

Field mapping (Agent 2 response -> gateway schema):
  status, data, total_count, has_more, experimental_label -> result
  provenance (their string "threat_intelligence_api_v1::<path>") -> provenance.source
  timestamp (their utcnow)                                  -> provenance.produced_at (tz-aware)
  confidence                                                -> provenance.confidence
  experimental_label (EXPERIMENTAL_DEMO_DATA_ONLY)          -> preserved in result AND provenance
  freshness_s                                               -> computed age of produced_at
  task.idempotency_key / task_id                            -> provenance (trace correlation)

Error semantics: their response ``status == "error"`` raises DomainError
(sanitized) so the gateway records a real failure (DEGRADED/FAILED), never a
fake success. A missing module raises DomainNotMounted — the domain is honestly
NOT_MOUNTED until Agent 2's branch is merged and the file is present.

The default module path points at the in-repo location the file will occupy once
PR #3 merges; override with CICC_TI_MODULE_PATH (e.g. a read-only export of the
PR head for verification). This adapter does not modify Agent 2's code.
"""
from __future__ import annotations

import importlib.util
import os
from datetime import datetime, timezone

DEFAULT_TI_MODULE = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "..", "apps", "threat_intelligence", "api.py")
DEFAULT_ENDPOINT = "/api/v1/threat-intelligence/osint-sources"


class _NotMounted(Exception):
    pass


def _load_api_class(module_path: str):
    if not os.path.exists(module_path):
        raise _NotMounted(f"threat_intel module not present: {module_path}")
    import sys
    spec = importlib.util.spec_from_file_location("cicc_ti_agent2_api", module_path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except ModuleNotFoundError:
        # newer PR heads import sibling modules as `apps.threat_intelligence.*` —
        # resolve by adding the module's ancestor dirs + this repo's root to
        # sys.path (READ-ONLY path fix, no file modification) and retry once
        here = os.path.dirname(os.path.abspath(module_path))
        cands = [here]
        d = here
        for _ in range(6):
            d = os.path.dirname(d)
            cands.append(d)
        cands.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")))
        for c in cands:
            if c not in sys.path:
                sys.path.insert(0, c)
        spec = importlib.util.spec_from_file_location("cicc_ti_agent2_api", module_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod, mod.ThreatIntelligenceAPI, mod.ThreatIntelligenceRequest


def make_handler(module_path: str | None = None):
    """Build a gateway-contract handler bound to Agent 2's module (read-only)."""
    path = module_path or os.getenv("CICC_TI_MODULE_PATH") or os.path.abspath(DEFAULT_TI_MODULE)
    mod, API, Req = _load_api_class(path)  # raises _NotMounted if absent
    # Agent 2 labels all current data EXPERIMENTAL_DEMO_DATA_ONLY — preserve it
    EXPERIMENTAL = getattr(mod, "EXPERIMENTAL_DEMO_DATA_ONLY", "EXPERIMENTAL_DEMO_DATA_ONLY")

    def handle(payload: dict, task=None):
        from .. import domains  # local import to raise the gateway's own types
        endpoint = payload.get("endpoint", DEFAULT_ENDPOINT)
        req = Req(
            tenant_id=payload.get("tenant_id"),
            query=payload.get("query"),
            limit=int(payload.get("limit", 100)),
            offset=int(payload.get("offset", 0)),
            experimental_label=payload.get("experimental_label"),
        )
        api = API(tenant_id=req.tenant_id, experimental_label=req.experimental_label)
        try:
            resp = api.invoke_endpoint(endpoint, req)
        except Exception as e:
            raise domains.DomainError(f"threat_intel: handler failed ({type(e).__name__})")
        if not isinstance(resp, dict):
            raise domains.DomainInvalid("threat_intel: non-dict response")
        if resp.get("status") != "success":
            raise domains.DomainError(f"threat_intel: domain returned status={resp.get('status')!r}")
        if not resp.get("experimental_label"):
            resp["experimental_label"] = EXPERIMENTAL  # never let experimental data look verified
        ts = resp.get("timestamp")
        produced_at = ts.isoformat() if isinstance(ts, datetime) else str(ts)
        if isinstance(ts, datetime) and ts.tzinfo is None:
            produced_at = ts.replace(tzinfo=timezone.utc).isoformat()
        age = max(0.0, (datetime.now(timezone.utc) - (
            ts.replace(tzinfo=timezone.utc) if isinstance(ts, datetime) and ts.tzinfo is None
            else ts if isinstance(ts, datetime) and ts.tzinfo else datetime.now(timezone.utc))).total_seconds())
        prov = {
            "source": str(resp.get("provenance", "threat_intelligence_api")),
            "produced_at": produced_at,
            "confidence": resp.get("confidence"),
            "freshness_s": round(age, 3),
            "experimental_label": resp.get("experimental_label"),
            "module_path": os.path.abspath(path),
            "endpoint": endpoint,
            "task_id": getattr(task, "task_id", None),
            "idempotency_key": getattr(task, "idempotency_key", None),
        }
        return {
            "result": {
                "status": resp.get("status"),
                "data": resp.get("data"),
                "total_count": resp.get("total_count"),
                "has_more": resp.get("has_more"),
                "experimental_label": resp.get("experimental_label"),
            },
            "provenance": prov,
        }

    handle.__cicc_domain__ = {"kind": "threat_intel", "module_path": os.path.abspath(path)}
    return handle
