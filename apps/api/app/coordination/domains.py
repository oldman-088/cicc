"""M35 — coordination-side domain integration support.

A domain (Threat Intelligence, Vulnerability Intelligence, frontend services)
mounts by registering a handler for its task kind:

    domains.register_domain("vuln_intel", handler, version="...", source_ref="PR #8 @ ...")

    handler(payload: dict, task) -> {"result": <json>, "provenance": {...}}

provenance must contain at least: source, produced_at, and ideally the input
fingerprint — it is persisted with the task result and exposed in /trace.

Nothing is mounted by default. When no handler is mounted for a kind, invoke()
raises DomainNotMounted and the task records a `domain_not_mounted` event —
never a fake success. All execution here is server-side coordination support;
claim labels stay with the caller (sandbox vs production).
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

_REGISTRY: dict[str, dict] = {}


class DomainNotMounted(Exception):
    pass


class DomainError(Exception):
    """Handler raised / timed out — sanitized; raw error never logged to clients."""


class DomainInvalid(Exception):
    """Handler returned a response violating the result schema."""


def register_domain(kind: str, handler, version: str, source_ref: str) -> None:
    _REGISTRY[kind] = {
        "kind": kind, "handler": handler, "version": version, "source_ref": source_ref,
        "mounted_at": datetime.now(timezone.utc).isoformat(),
    }


def unregister_domain(kind: str) -> None:
    _REGISTRY.pop(kind, None)


def mounted_domains() -> list[dict]:
    return [
        {"kind": k, "version": v["version"], "source_ref": v["source_ref"], "mounted_at": v["mounted_at"]}
        for k, v in sorted(_REGISTRY.items())
    ]


def is_mounted(kind: str) -> bool:
    return kind in _REGISTRY


def _validate_response(kind: str, resp) -> dict:
    if not isinstance(resp, dict) or "result" not in resp:
        raise DomainInvalid(f"{kind}: response must be a dict with 'result'")
    prov = resp.get("provenance")
    if not isinstance(prov, dict) or not prov.get("source") or not prov.get("produced_at"):
        raise DomainInvalid(f"{kind}: provenance must include 'source' and 'produced_at'")
    return {"result": resp["result"], "provenance": prov}


def invoke(kind: str, payload: dict, task=None) -> dict:
    """Execute the mounted domain handler for a task kind. Raises
    DomainNotMounted / DomainError / DomainInvalid — callers persist events."""
    entry = _REGISTRY.get(kind)
    if entry is None:
        raise DomainNotMounted(f"no handler mounted for kind '{kind}'")
    timeout_s = float(os.getenv("CICC_DOMAIN_INVOKE_TIMEOUT_S", "10"))
    try:
        import concurrent.futures as cf
        with cf.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(entry["handler"], payload, task)
            resp = fut.result(timeout=timeout_s)
    except cf.TimeoutError:
        raise DomainError(f"{kind}: handler timed out after {timeout_s}s")
    except (DomainNotMounted, DomainError, DomainInvalid):
        raise
    except Exception as e:  # sanitized: never leak internals
        raise DomainError(f"{kind}: handler failed ({type(e).__name__})")
    return _validate_response(kind, resp)
