"""M35/M37 — coordination-side domain integration support with evidence-based
lifecycle status.

A domain (Threat Intelligence, Vulnerability Intelligence, frontend services)
mounts by registering a handler for its task kind:

    domains.register_domain("threat_intel", handler, version="...", source_ref="PR #3 @ ...")

    handler(payload: dict, task) -> {"result": <json>, "provenance": {...}}

provenance must contain at least: source, produced_at — and SHOULD carry the
domain's own metadata (confidence, freshness, source timestamps, input
fingerprint). It is persisted with the task result and exposed in /trace.

Handler lifecycle states (evidence-based, never inferred from package
existence):
  NOT_MOUNTED         no handler registered for the kind
  MOUNTED             registered, not yet validated
  AVAILABLE           validated (callable handler, version + source_ref present), never invoked
  EXECUTION_VERIFIED  last invoke succeeded; result+provenance persisted with trace correlation
  DEGRADED            had a successful invoke before, last invoke failed
  FAILED              invokes attempted, none succeeded
  UNKNOWN             handler mounted but stats missing/inconsistent

Reliability: per-attempt timeout (CICC_DOMAIN_INVOKE_TIMEOUT_S, 10s default),
retries (CICC_DOMAIN_INVOKE_RETRIES, default 1) with short backoff — the SAME
idempotency_key is passed to the handler on every attempt, so handlers MUST be
idempotent; the gateway itself executes a given idempotency_key at most once.
Errors are sanitized (type name only, never internals).

Nothing is mounted by default. When no handler is mounted for a kind, invoke()
raises DomainNotMounted and the task records a `domain_not_mounted` event —
never a fake success. Mounting another agent's code is READ-ONLY via
load_handler_from_module (importlib from a file path); this module never
modifies domain packages. Claim labels stay with the caller (sandbox vs
production).
"""
from __future__ import annotations

import importlib.util
import os
import time
from datetime import datetime, timezone

# evidence-based lifecycle states
NOT_MOUNTED = "NOT_MOUNTED"
MOUNTED = "MOUNTED"
AVAILABLE = "AVAILABLE"
EXECUTION_VERIFIED = "EXECUTION_VERIFIED"
DEGRADED = "DEGRADED"
FAILED = "FAILED"
UNKNOWN = "UNKNOWN"
STATES = (NOT_MOUNTED, MOUNTED, AVAILABLE, EXECUTION_VERIFIED, DEGRADED, FAILED, UNKNOWN)

_REGISTRY: dict[str, dict] = {}
# observable evidence per kind: {invokes, successes, last_status, last_error, last_invoke_at}
_STATS: dict[str, dict] = {}


class DomainNotMounted(Exception):
    pass


class DomainError(Exception):
    """Handler raised / timed out — sanitized; raw error never sent to clients."""


class DomainInvalid(Exception):
    """Handler returned a response violating the result schema."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_handler(handler, version, source_ref) -> None:
    if not callable(handler):
        raise DomainInvalid("handler must be callable")
    if not isinstance(version, str) or not version:
        raise DomainInvalid("version must be a non-empty string")
    if not isinstance(source_ref, str) or not source_ref:
        raise DomainInvalid("source_ref must be a non-empty string (branch/PR/commit)")


def register_domain(kind: str, handler, version: str, source_ref: str) -> dict:
    """Register (mount) a domain handler. Validates the handler contract."""
    _validate_handler(handler, version, source_ref)
    entry = {
        "kind": kind, "handler": handler, "version": version, "source_ref": source_ref,
        "mounted_at": _now(), "validated": True,
    }
    _REGISTRY[kind] = entry
    _STATS.setdefault(kind, {"invokes": 0, "successes": 0, "last_status": None,
                             "last_error": None, "last_invoke_at": None})
    return {k: v for k, v in entry.items() if k != "handler"}


def unregister_domain(kind: str) -> bool:
    _STATS.pop(kind, None)
    return _REGISTRY.pop(kind, None) is not None


def load_handler_from_module(kind: str, module_path: str, attr: str,
                             version: str, source_ref: str) -> dict:
    """Mount a handler from a Python file WITHOUT modifying it (read-only
    import). Used to mount another agent's domain package once its branch is
    merged; a missing file simply means NOT_MOUNTED."""
    if not os.path.exists(module_path):
        raise DomainNotMounted(f"module not present: {module_path}")
    spec = importlib.util.spec_from_file_location(f"cicc_domain_{kind}", module_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    handler = getattr(mod, attr)
    return register_domain(kind, handler, version=version, source_ref=source_ref)


def mounted_domains() -> list[dict]:
    return [
        {"kind": k, "version": v["version"], "source_ref": v["source_ref"],
         "mounted_at": v["mounted_at"], "status": domain_status(k)}
        for k, v in sorted(_REGISTRY.items())
    ]


def is_mounted(kind: str) -> bool:
    return kind in _REGISTRY


def record_outcome(kind: str, ok: bool, error: str | None = None) -> None:
    """Record observable invoke evidence (called by the router per attempt
    outcome; persisted to coord_domain_stats for restart-survivable health)."""
    st = _STATS.setdefault(kind, {"invokes": 0, "successes": 0, "last_status": None,
                                  "last_error": None, "last_invoke_at": None})
    st["invokes"] += 1
    st["last_invoke_at"] = _now()
    if ok:
        st["successes"] += 1
        st["last_status"] = "ok"
        st["last_error"] = None
    else:
        st["last_status"] = "error"
        st["last_error"] = (error or "error")[:200]  # sanitized, truncated


def domain_status(kind: str) -> str:
    if not is_mounted(kind):
        return NOT_MOUNTED
    st = _STATS.get(kind)
    if st is None:
        return UNKNOWN
    if st["invokes"] == 0:
        return AVAILABLE if _REGISTRY[kind].get("validated") else MOUNTED
    if st["last_status"] == "ok":
        return EXECUTION_VERIFIED
    return DEGRADED if st["successes"] > 0 else FAILED


def all_statuses() -> dict[str, dict]:
    out = {}
    for kind in sorted(set(_REGISTRY) | set(_STATS)):
        st = _STATS.get(kind, {})
        out[kind] = {
            "status": domain_status(kind),
            "version": _REGISTRY.get(kind, {}).get("version"),
            "source_ref": _REGISTRY.get(kind, {}).get("source_ref"),
            "mounted_at": _REGISTRY.get(kind, {}).get("mounted_at"),
            "invokes": st.get("invokes", 0), "successes": st.get("successes", 0),
            "last_invoke_at": st.get("last_invoke_at"),
            "last_error": st.get("last_error"),  # sanitized already
        }
    return out


def _validate_response(kind: str, resp) -> dict:
    if not isinstance(resp, dict) or "result" not in resp:
        raise DomainInvalid(f"{kind}: response must be a dict with 'result'")
    prov = resp.get("provenance")
    if not isinstance(prov, dict) or not prov.get("source") or not prov.get("produced_at"):
        raise DomainInvalid(f"{kind}: provenance must include 'source' and 'produced_at'")
    return {"result": resp["result"], "provenance": prov}


def invoke(kind: str, payload: dict, task=None) -> dict:
    """Execute the mounted domain handler. Raises DomainNotMounted / DomainError /
    DomainInvalid. Retries with the SAME idempotency key (handlers must be
    idempotent); per-attempt timeout. Callers persist events + stats."""
    entry = _REGISTRY.get(kind)
    if entry is None:
        raise DomainNotMounted(f"no handler mounted for kind '{kind}'")
    timeout_s = float(os.getenv("CICC_DOMAIN_INVOKE_TIMEOUT_S", "10"))
    retries = int(os.getenv("CICC_DOMAIN_INVOKE_RETRIES", "1"))
    attempts = 1 + max(0, retries)
    last_exc: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            import concurrent.futures as cf
            ex = cf.ThreadPoolExecutor(max_workers=1)
            try:
                fut = ex.submit(entry["handler"], payload, task)
                resp = fut.result(timeout=timeout_s)
            finally:
                ex.shutdown(wait=False, cancel_futures=True)  # never block on a stuck handler
            return _validate_response(kind, resp)
        except cf.TimeoutError:
            last_exc = DomainError(f"{kind}: handler timed out after {timeout_s}s (attempt {attempt}/{attempts})")
        except (DomainNotMounted, DomainError, DomainInvalid) as e:
            last_exc = e
            if isinstance(e, DomainInvalid):
                break  # schema violation is not retryable
        except Exception as e:  # sanitized: never leak internals
            last_exc = DomainError(f"{kind}: handler failed ({type(e).__name__}) (attempt {attempt}/{attempts})")
        if attempt < attempts:
            time.sleep(min(0.2 * attempt, 1.0))  # short backoff
    raise last_exc  # type: ignore[misc]
