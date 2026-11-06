"""M39 — Vulnerability Intelligence domain adapter (Replacement Agent 3).

Wraps the standalone ``packages/vuln_intel`` package (PR #8 @ 5215e31 /
PR #1 @ 84fca76 — merge order OWNER-RESERVED) READ-ONLY into the coordination
gateway handler contract:

    handle(payload, task) -> {"result": ..., "provenance": {...}}

Package entry points used (verified against the PR #8 head file list):
  vuln_intel.search.search_records(records, query, kev_only=, limit=)
  vuln_intel.health.build_health_report(states, kev_age=, epss_available=, now=)
  vuln_intel.schema.NormalizedVulnerability / SourceState / utcnow

Ops:
  {"op": "search", "query": ..., "kev_only"?, "limit"?, "records": [dict, ...]}
      -> result = {"hits": [SearchHit.as_dict(), ...], "count": n}
  {"op": "health", "states": [dict, ...], "epss_available"?: bool}
      -> result = health report as dict (readiness, sources, warnings)

Provenance: source = f"vuln_intel::{op}", produced_at = package utcnow (tz-aware),
confidence = 1.0 for computed search (calculated relevance is disclosed in-band,
not as source fact), freshness_s computed from produced_at, package path +
version ref recorded. Missing package (branches unmerged) -> _NotMounted:
honest NOT_MOUNTED, never a fake mount.
"""
from __future__ import annotations

import importlib
import os
import sys
from datetime import datetime, timezone

DEFAULT_VI_PACKAGE_PARENT = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "..", "packages", "vuln_intel")


class _NotMounted(Exception):
    pass


def _load_package(package_path: str):
    """Import the vuln_intel package from a directory READ-ONLY (sys.path append
    of the package parent). Returns the loaded modules."""
    if not os.path.isdir(os.path.join(package_path, "vuln_intel")):
        raise _NotMounted(f"vuln_intel package not present: {package_path}")
    parent = os.path.abspath(package_path)
    if parent not in sys.path:
        sys.path.insert(0, parent)
    try:
        import vuln_intel.search as search
        import vuln_intel.health as health
        import vuln_intel.schema as schema
    except Exception as e:
        raise _NotMounted(f"vuln_intel import failed: {type(e).__name__}")
    return search, health, schema


def _to_dict(obj):
    import enum
    if hasattr(obj, "as_dict"):
        return obj.as_dict()
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, (list, tuple)):
        return [_to_dict(x) for x in obj]
    if hasattr(obj, "__dict__"):
        return {k: _to_dict(v) for k, v in vars(obj).items() if not k.startswith("_")}
    return obj


def make_handler(package_path: str | None = None, version_ref: str = "PR #8 @ 5215e31 / PR #1 @ 84fca76 (unmerged)"):
    """Build a gateway-contract handler bound to the VI package (read-only)."""
    path = package_path or os.getenv("CICC_VI_PACKAGE_PATH") or os.path.abspath(DEFAULT_VI_PACKAGE_PARENT)
    search, health, schema = _load_package(path)  # raises _NotMounted if absent

    def handle(payload: dict, task=None):
        from .. import domains
        op = payload.get("op", "search")
        now = schema.utcnow()
        produced_at = now.isoformat() if isinstance(now, datetime) else str(now)
        if isinstance(now, datetime) and now.tzinfo is None:
            produced_at = now.replace(tzinfo=timezone.utc).isoformat()
        try:
            if op == "search":
                import enum
                import typing
                records = []
                cls = schema.NormalizedVulnerability
                hints = typing.get_type_hints(cls)  # resolves `from __future__ import annotations` strings
                for r in payload.get("records", []):
                    if hasattr(cls, "model_validate"):  # pydantic model: coerces str enums itself
                        records.append(cls.model_validate(r))
                        continue
                    coerced = {}
                    for k, v in r.items():
                        t = hints.get(k)
                        if isinstance(v, str) and isinstance(t, type):
                            if issubclass(t, enum.Enum):
                                try:
                                    v = t(v)  # JSON carries enum values as strings
                                except ValueError:
                                    v = t(v.lower())  # their enum values are lowercase
                            elif hasattr(t, "parse") and callable(getattr(t, "parse")):
                                v = t.parse(v)  # e.g. CveId.parse("CVE-...")
                        coerced[k] = v
                    records.append(cls(**coerced))
                hits = search.search_records(
                    records, str(payload.get("query", "")),
                    kev_only=bool(payload.get("kev_only", False)),
                    limit=int(payload.get("limit", 100)))
                result = {"op": "search", "query": payload.get("query"),
                          "hits": [_to_dict(h) for h in hits], "count": len(hits)}
                confidence = 1.0  # deterministic computed search; score_kind disclosed in-band
                # honesty: Origin.is_real distinguishes LIVE source data from fixture/demo
                origins = set()
                any_live = False
                for r in records:
                    o = getattr(r, "origin", None)
                    origins.add(str(getattr(o, "value", o)))
                    any_live = any_live or bool(getattr(o, "is_real", False))
                data_origin = "live" if any_live else "non-live:" + ",".join(sorted(origins))
            elif op == "health":
                scls = schema.SourceState
                states = [scls.model_validate(st) if hasattr(scls, "model_validate") else scls(**st)
                          for st in payload.get("states", [])]
                rep = health.build_health_report(
                    states, epss_available=bool(payload.get("epss_available", False)), now=now)
                result = {"op": "health", **_to_dict(rep)}
                confidence = 1.0
            else:
                raise domains.DomainInvalid(f"vuln_intel: unknown op {op!r}")
        except domains.DomainError:
            raise
        except domains.DomainInvalid:
            raise
        except Exception as e:
            raise domains.DomainError(f"vuln_intel: handler failed ({type(e).__name__})")
        age = 0.0
        prov = {
            "source": f"vuln_intel::{op}",
            "produced_at": produced_at,
            "confidence": confidence,
            "freshness_s": age,
            "package_path": os.path.abspath(path),
            "version_ref": version_ref,
            **({"data_origin": data_origin} if op == "search" else {}),
            "task_id": getattr(task, "task_id", None),
            "idempotency_key": getattr(task, "idempotency_key", None),
        }
        return {"result": result, "provenance": prov}

    handle.__cicc_domain__ = {"kind": "vuln_intel", "package_path": os.path.abspath(path)}
    return handle
