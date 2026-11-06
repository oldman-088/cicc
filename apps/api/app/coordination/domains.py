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
import threading
import time
import uuid
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
# observable evidence per kind: {invokes, successes, consecutive_failures, last_status, last_error, last_invoke_at}
_STATS: dict[str, dict] = {}


def _empty_stat() -> dict:
    return {"invokes": 0, "successes": 0, "consecutive_failures": 0,
            "last_status": None, "last_error": None, "last_invoke_at": None,
            "last_stale": False, "last_success_at": None,  # M45: process-local
            # M44 observability counters (process-local, bounded labels = kind only)
            "timeouts": 0, "retries": 0, "stale_count": 0, "skew_count": 0,
            "latency_count": 0, "latency_total_s": 0.0, "latency_max_s": 0.0, "last_latency_s": None,
            "circuit_opens": 0, "circuit_closes": 0, "probe_lease_expirations": 0}


def stale_after_s() -> float:
    """M41: staleness threshold for domain results (seconds)."""
    return float(os.getenv("CICC_DOMAIN_STALE_AFTER_S", "3600"))


def analyze_freshness(provenance: dict, now=None) -> dict:
    """M42: evidence-based freshness analysis.

    Returns {stale, age_s, clock_skew_s, basis}:
    - basis "freshness_s": explicit domain-reported freshness wins
    - basis "produced_at": age of the tz-aware produced_at (naive = UTC)
    - basis "none": no usable signal -> not stale (never silently fresh either:
      age_s is null and callers must not claim freshness)
    - clock_skew_s > 0 when produced_at is in the future (skewed clock/domain);
      future timestamps are never treated as fresh evidence, just flagged.
    """
    now = now or datetime.now(timezone.utc)
    fresh = provenance.get("freshness_s")
    if isinstance(fresh, (int, float)) and not isinstance(fresh, bool) and fresh >= 0:
        return {"stale": float(fresh) > stale_after_s(), "age_s": float(fresh),
                "clock_skew_s": 0.0, "basis": "freshness_s"}
    try:
        ts = datetime.fromisoformat(str(provenance.get("produced_at", "")).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)  # naive timestamps are UTC by contract
        age = (now - ts).total_seconds()
        skew = max(0.0, -age)
        return {"stale": age > stale_after_s(), "age_s": max(0.0, age),
                "clock_skew_s": skew, "basis": "produced_at"}
    except ValueError:
        return {"stale": False, "age_s": None, "clock_skew_s": 0.0, "basis": "none"}


def is_result_stale(provenance: dict, now=None) -> bool:
    """M41/M42: evidence-based staleness (see analyze_freshness)."""
    return analyze_freshness(provenance, now)["stale"]


def load_persisted_stats(rows: list, include_unmounted: bool = False) -> None:
    """M38: restore evidence from coord_domain_stats rows (restart persistence).
    By default only fills kinds that are currently mounted. Persisted evidence
    replaces current state only when its invoke count is strictly higher; on a
    tie, retain in-memory values so process-local metrics are not reset by reads.
    M45: include_unmounted=True (startup + metrics reads) also restores rows for
    kinds that are not mounted right now — after a restart handlers are gone
    (status stays honestly NOT_MOUNTED via domain_status) but persisted counters
    must remain visible in statuses/metrics for beta operations. The persist
    path keeps the default so a deregister really clears in-memory stats."""
    with _CIRCUIT_LOCK:
        for row in rows:
            kind = getattr(row, "kind", None)
            if kind is None or (not include_unmounted and kind not in _REGISTRY):
                continue
            cur = _STATS.get(kind)
            persisted = {"invokes": row.invokes or 0, "successes": row.successes or 0,
                         "consecutive_failures": getattr(row, "consecutive_failures", 0) or 0,
                         "last_status": row.last_status, "last_error": row.last_error,
                         "last_invoke_at": row.last_invoke_at,
                         "last_stale": bool(getattr(row, "last_stale", 0))}
            if cur is None or persisted["invokes"] > cur["invokes"]:
                merged = _empty_stat()
                merged.update({k: v for k, v in persisted.items() if v is not None})
                if cur is not None:
                    merged["consecutive_failures"] = cur.get("consecutive_failures", 0)
                    # volatile in-memory fields survive the merge (process-local
                    # fine-grained counters + mount history; see domain_metrics note)
                    for k in ("mount_count", "previous_version", "last_stale", "last_success_at",
                              "timeouts",
                              "retries", "stale_count", "skew_count", "latency_count",
                              "latency_total_s", "latency_max_s", "last_latency_s",
                              "circuit_opens", "circuit_closes", "probe_lease_expirations"):
                        if cur.get(k) is not None:
                            merged[k] = cur[k]
                    if cur["invokes"] > persisted["invokes"]:
                        merged = cur
                _STATS[kind] = merged


class DomainNotMounted(Exception):
    pass


class DomainError(Exception):
    """Handler raised / timed out — sanitized; raw error never sent to clients."""


class DomainInvalid(Exception):
    """Handler returned a response violating the result schema."""


class DomainCircuitOpen(DomainError):
    """M43: circuit breaker open after N consecutive failures — invokes are
    rejected fast (no handler execution) until the cooldown elapses."""

    code = "circuit_open"


_CIRCUIT: dict[str, dict] = {}  # kind -> process-local breaker + half-open lease
_CIRCUIT_LOCK = threading.RLock()  # atomic mount generations, breaker transitions, and outcome records


class DomainMountChanged(DomainError):
    """The admitted handler mount was replaced before its outcome was recorded."""

    code = "domain_mount_changed"


def circuit_failures_threshold() -> int:
    return int(os.getenv("CICC_DOMAIN_CIRCUIT_FAILURES", "5"))


def circuit_cooldown_s() -> float:
    return float(os.getenv("CICC_DOMAIN_CIRCUIT_COOLDOWN_S", "30"))


def circuit_probe_lease_s() -> float:
    """Maximum time a half-open probe owns the breaker before reclamation.

    Default 30s is longer than the default invocation timeout + one retry. If
    operators configure longer handler budgets, configure this lease to match.
    Expired callbacks remain valid invocation evidence for the same mount, but
    cannot close/re-arm a newer probe's breaker lease.
    """
    value = float(os.getenv("CICC_DOMAIN_CIRCUIT_PROBE_LEASE_S", "30"))
    return min(3600.0, max(0.05, value)) if value == value else 30.0


def circuit_state(kind: str) -> dict:
    with _CIRCUIT_LOCK:
        c = _CIRCUIT.get(kind, {})
        now_mono = time.monotonic()
        deadline = c.get("probe_lease_expires_at")
        remaining = max(0.0, deadline - now_mono) if deadline is not None else 0.0
        lease_active = bool(c.get("probe_inflight")) and remaining > 0
        open_now = bool(c.get("open")) and (time.time() - c.get("opened_at", 0)) < circuit_cooldown_s()
        return {"open": open_now, "opened_at": c.get("opened_at"),
                "threshold": circuit_failures_threshold(), "cooldown_s": circuit_cooldown_s(),
                "probe_inflight": lease_active,
                "probe_lease_expires_in_s": round(remaining, 3) if lease_active else None}


def _begin_invoke(kind: str, probe_state: dict | None = None,
                  mount_id: str | None = None) -> bool:
    """Admit a call; atomically verify mount ownership and lease one half-open probe.

    ``probe_state`` is request-local and carries opaque mount/lease IDs to the
    eventual outcome recorder. It is deliberately not exposed in API responses.
    """
    if probe_state is not None:
        probe_state.clear()
    with _CIRCUIT_LOCK:
        entry = _REGISTRY.get(kind)
        if entry is None:
            raise DomainNotMounted(f"no handler mounted for kind '{kind}'")
        live_mount_id = entry["_mount_id"]
        if mount_id is not None and live_mount_id != mount_id:
            raise DomainMountChanged("domain mount changed before invocation admission")
        if probe_state is not None:
            probe_state["mount_id"] = live_mount_id
            probe_state["half_open_probe"] = False
            probe_state["probe_lease_id"] = None
            probe_state["lease_expired"] = False

        c = _CIRCUIT.get(kind)
        if not c or not c.get("open"):
            return True
        if time.time() - c.get("opened_at", 0) < circuit_cooldown_s():
            return False

        now_mono = time.monotonic()
        if c.get("probe_inflight"):
            deadline = c.get("probe_lease_expires_at")
            if deadline is not None and deadline > now_mono:
                return False
            # Lease expired (or legacy state has no deadline). Reclaim it; the
            # previous handler may still finish, but its opaque ID no longer owns
            # the breaker and its late callback cannot consume the new lease.
            c["probe_inflight"] = False
            c["probe_lease_id"] = None
            c["probe_lease_expires_at"] = None
            st = _STATS.get(kind)
            if st is not None:
                st["probe_lease_expirations"] = st.get("probe_lease_expirations", 0) + 1
            if probe_state is not None:
                probe_state["lease_expired"] = True

        lease_id = uuid.uuid4().hex
        c["probe_inflight"] = True
        c["probe_lease_id"] = lease_id
        c["probe_lease_expires_at"] = now_mono + circuit_probe_lease_s()
        if probe_state is not None:
            probe_state["half_open_probe"] = True
            probe_state["probe_lease_id"] = lease_id
        return True

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
        "mounted_at": _now(), "validated": True, "_mount_id": uuid.uuid4().hex,
    }
    with _CIRCUIT_LOCK:
        prev = _REGISTRY.get(kind)
        _REGISTRY[kind] = entry
        _CIRCUIT.pop(kind, None)  # M46: a (re)mount installs a fresh handler -> fresh circuit
        st = _STATS.setdefault(kind, _empty_stat())
        st["consecutive_failures"] = 0  # do not carry the prior handler's breaker threshold into a new mount
        st["mount_count"] = st.get("mount_count", 0) + 1
        st["previous_version"] = prev["version"] if prev else None
    return {k: v for k, v in entry.items() if k not in ("handler", "_mount_id")}


def unregister_domain(kind: str) -> bool:
    with _CIRCUIT_LOCK:
        _STATS.pop(kind, None)
        _CIRCUIT.pop(kind, None)  # M46: deregistered kind carries no circuit state
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
    with _CIRCUIT_LOCK:
        return [
            {"kind": k, "version": v["version"], "source_ref": v["source_ref"],
             "mounted_at": v["mounted_at"], "status": domain_status(k)}
            for k, v in sorted(_REGISTRY.items())
        ]


def is_mounted(kind: str) -> bool:
    with _CIRCUIT_LOCK:
        return kind in _REGISTRY


def record_outcome(kind: str, ok: bool, error: str | None = None, stale: bool = False,
                   latency_s: float | None = None, attempts: int = 1,
                   timed_out: bool = False, skew: bool = False,
                   mount_id: str | None = None,
                   probe_lease_id: str | None = None,
                   outcome_state: dict | None = None) -> bool:
    """Record one handler outcome iff its mount generation is still current.

    Metrics from a callback for a replaced/deregistered mount are discarded.
    Half-open breaker transitions require the exact opaque lease ID; stale
    leases and ordinary calls admitted before the breaker opened cannot consume
    or alter the current probe. ``outcome_state`` receives an atomic transition
    description for sanitized audit persistence by the router.
    """
    if outcome_state is not None:
        outcome_state.clear()
    with _CIRCUIT_LOCK:
        current = _REGISTRY.get(kind)
        if mount_id is not None and (current is None or current.get("_mount_id") != mount_id):
            if outcome_state is not None:
                outcome_state["accepted"] = False
            return False

        st = _STATS.setdefault(kind, _empty_stat())
        st["invokes"] += 1
        st["last_invoke_at"] = _now()
        st["retries"] += max(0, attempts - 1)
        if timed_out:
            st["timeouts"] += 1
        if latency_s is not None:
            st["latency_count"] += 1
            st["latency_total_s"] = round(st.get("latency_total_s", 0.0) + latency_s, 6)
            st["latency_max_s"] = max(st.get("latency_max_s", 0.0), latency_s)
            st["last_latency_s"] = latency_s

        breaker = _CIRCUIT.get(kind, {})
        before_open = bool(breaker.get("open"))
        deadline = breaker.get("probe_lease_expires_at")
        owns_probe = bool(
            probe_lease_id is not None
            and before_open
            and breaker.get("probe_inflight")
            and breaker.get("probe_lease_id") == probe_lease_id
            and deadline is not None
            and deadline > time.monotonic()
        )
        stale_probe = probe_lease_id is not None and not owns_probe

        if ok:
            st["successes"] += 1
            st["last_status"] = "ok"
            st["last_success_at"] = _now()  # M45: last successful invocation (process-local)
            st["last_error"] = None
            st["last_stale"] = bool(stale)
            if stale:
                st["stale_count"] += 1
            if skew:
                st["skew_count"] += 1
            if before_open:
                if owns_probe:
                    _CIRCUIT[kind] = {
                        "open": False, "opened_at": None, "probe_inflight": False,
                        "probe_lease_id": None, "probe_lease_expires_at": None,
                    }
                    st["consecutive_failures"] = 0
                    st["circuit_closes"] = st.get("circuit_closes", 0) + 1
            elif not stale_probe:
                st["consecutive_failures"] = 0
        else:
            st["last_status"] = "error"
            st["last_error"] = (error or "error")[:200]  # sanitized, truncated
            if before_open:
                # Only this open circuit's current half-open lease owns a re-arm.
                if owns_probe:
                    st["consecutive_failures"] = st.get("consecutive_failures", 0) + 1
                    _CIRCUIT[kind] = {
                        "open": True, "opened_at": time.time(), "probe_inflight": False,
                        "probe_lease_id": None, "probe_lease_expires_at": None,
                    }
                    if outcome_state is not None:
                        outcome_state["probe_failed_rearmed"] = True
            elif not stale_probe:
                st["consecutive_failures"] = st.get("consecutive_failures", 0) + 1
                if st["consecutive_failures"] >= circuit_failures_threshold():
                    _CIRCUIT[kind] = {
                        "open": True, "opened_at": time.time(), "probe_inflight": False,
                        "probe_lease_id": None, "probe_lease_expires_at": None,
                    }
                    st["circuit_opens"] = st.get("circuit_opens", 0) + 1

        after_open = bool(_CIRCUIT.get(kind, {}).get("open"))
        if outcome_state is not None:
            outcome_state["accepted"] = True
            if before_open != after_open:
                outcome_state["transition"] = "OPENED" if after_open else "CLOSED"
        return True


def domain_status(kind: str) -> str:
    with _CIRCUIT_LOCK:
        if kind not in _REGISTRY:
            return NOT_MOUNTED
        st = _STATS.get(kind)
        if st is None:
            return UNKNOWN
        if st["invokes"] == 0:
            return AVAILABLE if _REGISTRY[kind].get("validated") else MOUNTED
        if st["last_status"] == "ok":
            return EXECUTION_VERIFIED
        return DEGRADED if st["successes"] > 0 else FAILED


def domain_metrics() -> dict:
    """M44/M47 metrics; labels are bounded to registered kind IDs only."""
    with _CIRCUIT_LOCK:
        out = {}
        for kind in sorted(_STATS):
            st = _STATS[kind]
            lc = st.get("latency_count", 0)
            out[kind] = {
                "invokes": st["invokes"], "successes": st["successes"],
                "failures": st["invokes"] - st["successes"],
                "success_rate": round(st["successes"] / st["invokes"], 4) if st["invokes"] else None,
                "timeouts": st.get("timeouts", 0), "retries": st.get("retries", 0),
                "stale_count": st.get("stale_count", 0), "skew_count": st.get("skew_count", 0),
                "latency": {"count": lc, "avg_s": round(st.get("latency_total_s", 0) / lc, 4) if lc else None,
                            "max_s": round(st.get("latency_max_s", 0.0), 4), "last_s": st.get("last_latency_s")},
                "circuit": {**circuit_state(kind), "opens": st.get("circuit_opens", 0),
                            "closes": st.get("circuit_closes", 0),
                            "probe_lease_expirations": st.get("probe_lease_expirations", 0)},
                "mount_count": st.get("mount_count", 0),
                "last_success_at": st.get("last_success_at"),
                "status": domain_status(kind),
            }
        return {"domains": out, "labels": ["kind"], "note": "bounded-cardinality labels (kind only); "
                "no tenant ids / tokens / payloads; latency+retry counters are process-local (restart resets them; "
                "invokes/successes persist via coord_domain_stats)"}


def all_statuses() -> dict[str, dict]:
    with _CIRCUIT_LOCK:
        out = {}
        for kind in sorted(set(_REGISTRY) | set(_STATS)):
            st = _STATS.get(kind, {})
            out[kind] = {
                "status": domain_status(kind),
                "version": _REGISTRY.get(kind, {}).get("version"),
                "source_ref": _REGISTRY.get(kind, {}).get("source_ref"),
                "mounted_at": _REGISTRY.get(kind, {}).get("mounted_at"),
                "invokes": st.get("invokes", 0), "successes": st.get("successes", 0),
                "consecutive_failures": st.get("consecutive_failures", 0),
                "last_stale": st.get("last_stale", False),
                "stale_after_s": stale_after_s(),
                "circuit": circuit_state(kind),
                "mount_count": st.get("mount_count", 0),
                "previous_version": st.get("previous_version"),
                "last_invoke_at": st.get("last_invoke_at"),
                "last_success_at": st.get("last_success_at"),
                "last_error": st.get("last_error"),
            }
        return out


def _validate_response(kind: str, resp) -> dict:
    """M38: hardened response validation — schema + parseable produced_at +
    confidence in [0,1] if present. Corrupted/missing provenance -> DomainInvalid."""
    if not isinstance(resp, dict) or "result" not in resp:
        raise DomainInvalid(f"{kind}: response must be a dict with 'result'")
    prov = resp.get("provenance")
    if not isinstance(prov, dict) or not prov.get("source") or not prov.get("produced_at"):
        raise DomainInvalid(f"{kind}: provenance must include 'source' and 'produced_at'")
    try:
        datetime.fromisoformat(str(prov["produced_at"]).replace("Z", "+00:00"))
    except ValueError:
        raise DomainInvalid(f"{kind}: provenance.produced_at is not ISO-8601")
    conf = prov.get("confidence")
    if conf is not None and (not isinstance(conf, (int, float)) or isinstance(conf, bool)
                             or not 0.0 <= conf <= 1.0):
        raise DomainInvalid(f"{kind}: provenance.confidence must be a number in [0,1]")
    fresh = prov.get("freshness_s")
    if fresh is not None and (not isinstance(fresh, (int, float)) or isinstance(fresh, bool)
                              or fresh < 0):
        raise DomainInvalid(f"{kind}: provenance.freshness_s must be a non-negative number when present")
    return {"result": resp["result"], "provenance": prov}


def invoke(kind: str, payload: dict, task=None, probe_state: dict | None = None) -> dict:
    """Execute the mounted domain handler. Raises DomainNotMounted / DomainError /
    DomainInvalid. Retries with the SAME idempotency key (handlers must be
    idempotent); per-attempt timeout. Optional ``probe_state`` is internal
    request metadata populated atomically with half-open probe admission.
    Callers persist events + stats."""
    with _CIRCUIT_LOCK:
        entry = _REGISTRY.get(kind)
        if entry is None:
            raise DomainNotMounted(f"no handler mounted for kind '{kind}'")
        mount_id = entry["_mount_id"]
    if not _begin_invoke(kind, probe_state=probe_state, mount_id=mount_id):
        raise DomainCircuitOpen(
            f"{kind}: circuit open after {circuit_failures_threshold()} consecutive failures "
            f"(cooldown {circuit_cooldown_s()}s or half-open probe already in flight)")
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
            last_exc.timed_out = True
            last_exc.attempts = attempt
        except (DomainNotMounted, DomainError, DomainInvalid) as e:
            last_exc = e
            last_exc.attempts = attempt
            if isinstance(e, DomainInvalid):
                break  # schema violation is not retryable
        except Exception as e:  # sanitized: never leak internals
            # M45: type name removed — never leak internals, not even exception class names
            last_exc = DomainError(f"{kind}: handler failed (attempt {attempt}/{attempts})")
            last_exc.attempts = attempt
        if attempt < attempts:
            time.sleep(min(0.2 * attempt, 1.0))  # short backoff
    raise last_exc  # type: ignore[misc]
