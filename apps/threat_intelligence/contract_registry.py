"""
Cross-Agent Contract Registry — proposed vs. accepted, with pinned provenance

Repository:  oldman-088/cicc   Branch: arena/28e50255-cicc (Agent 6 backup)

Why this module exists
----------------------
`integration_contracts.py` implements the Threat Intelligence *side* of several
other agents' contracts. Those contracts live on **unmerged branches**. Treating
an unmerged proposal as canonical is exactly how two agents end up shipping
incompatible shapes, so this registry pins, for every dependency:

* who owns the contract;
* the exact source commit and document it was read from;
* the version string the owner published;
* whether it is `proposed`, `accepted`, or `superseded`;
* who must approve it, and what happens if they do not.

Every entry is `proposed` unless an owner has explicitly accepted it in writing.
There is no code path that flips an entry to `accepted` from inside this
package -- acceptance must be recorded by the owner through
:func:`record_owner_acceptance`, which requires an attributable decision
reference.

The registry makes "we are building on a proposal" a queryable fact instead of
a caveat buried in prose.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

EXPERIMENTAL_DEMO_DATA_ONLY = "EXPERIMENTAL_DEMO_DATA_ONLY"

_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")
_PR_RE = re.compile(r"^oldman-088/cicc#\d+$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/\-]+$")
_PLACEHOLDER_TOKENS = {
    "pending", "tbd", "todo", "unknown", "n/a", "none", "placeholder",
    "later", "unspecified", "-", "xx", "xxx", "",
}


class ContractStatus(str, Enum):
    PROPOSED = "proposed"          # read from an unmerged branch; not agreed
    ACCEPTED = "accepted"          # owner accepted in writing, reference recorded
    SUPERSEDED = "superseded"      # replaced by a later version
    REJECTED = "rejected"          # owner declined; do not build on it


class ContractRegistryError(Exception):
    """Base error for the contract registry."""


class ContractNotAcceptedError(ContractRegistryError):
    """A caller tried to treat a proposed contract as load-bearing."""


class OwnerAcceptanceError(ContractRegistryError):
    """An acceptance was recorded without an attributable decision reference."""


def utcnow_iso() -> str:
    moment = datetime.now(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


class ContractDependency(BaseModel):
    """One external contract that Threat Intelligence code depends on."""

    model_config = ConfigDict(extra="forbid")

    contract_id: str = Field(..., min_length=1, description="Stable local id, e.g. 'agent1-coordination-v1'")
    owner_agent: str = Field(..., min_length=1, description="e.g. 'Agent 1'")
    title: str = Field(..., min_length=1)
    contract_version: str = Field(..., min_length=1, description="Version string the owner published")
    source_branch: str = Field(..., description="Branch the contract was read from")
    source_commit: str = Field(..., description="Exact commit the contract text was read at")
    source_document: str = Field(..., description="Path of the document within that commit")
    source_pull_request: Optional[str] = Field(None, description="owner/repo#number, if the contract has a PR")
    read_at: str = Field(..., description="When Agent 6 read it")

    status: ContractStatus = Field(ContractStatus.PROPOSED)
    owner_acceptance_reference: Optional[str] = Field(
        None, description="Link/issue/comment proving owner acceptance"
    )
    accepted_at: Optional[str] = Field(None)
    accepted_by: Optional[str] = Field(None)

    local_implementation: Optional[str] = Field(
        None, description="Module in this package that implements our side"
    )
    load_bearing: bool = Field(
        False,
        description="True only once status == accepted. While False, callers must "
                    "treat the shape as provisional.",
    )
    notes: Optional[str] = Field(None)
    experimental_label: Optional[str] = Field(EXPERIMENTAL_DEMO_DATA_ONLY)

    @field_validator("source_commit")
    @classmethod
    def _check_sha(cls, v: str) -> str:
        if not _COMMIT_SHA_RE.match(v.strip()):
            raise ValueError("source_commit must be a hex git SHA (7-40 chars)")
        return v.strip()

    @field_validator("source_branch")
    @classmethod
    def _check_branch(cls, v: str) -> str:
        if not _BRANCH_RE.match(v.strip()):
            raise ValueError("source_branch must be a plausible git ref name")
        return v.strip()

    @field_validator("source_pull_request")
    @classmethod
    def _check_pr(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if not _PR_RE.match(v.strip()):
            raise ValueError("source_pull_request must look like 'owner/repo#123'")
        return v.strip()

    @field_validator("load_bearing")
    @classmethod
    def _cannot_self_declare_load_bearing(cls, v: bool) -> bool:
        if v:
            raise ValueError(
                "load_bearing cannot be set at construction time; it is derived "
                "from owner acceptance via record_owner_acceptance()"
            )
        return v

    @field_validator("owner_acceptance_reference", "accepted_by")
    @classmethod
    def _no_placeholder_actor(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        cleaned = " ".join(v.split())
        if cleaned.lower() in _PLACEHOLDER_TOKENS:
            raise ValueError("acceptance fields must be specific and attributable")
        return cleaned or None

    @property
    def is_load_bearing(self) -> bool:
        """Derived: only an accepted contract may be treated as load-bearing."""
        return self.status is ContractStatus.ACCEPTED and bool(self.owner_acceptance_reference)


class ContractRegistry:
    """
    Holds the set of cross-agent contracts Threat Intelligence depends on.

    The default registry is seeded with the contracts Agent 6 actually read,
    pinned to the exact commits they were read from. All are `proposed`.
    """

    def __init__(self, dependencies: Optional[List[ContractDependency]] = None):
        self._deps: Dict[str, ContractDependency] = {}
        for dep in dependencies or []:
            self._deps[dep.contract_id] = dep

    # ------------------------------------------------------------------ reads

    def get(self, contract_id: str) -> Optional[ContractDependency]:
        return self._deps.get(contract_id)

    def all(self) -> List[ContractDependency]:
        return sorted(self._deps.values(), key=lambda d: d.contract_id)

    def by_owner(self, owner_agent: str) -> List[ContractDependency]:
        return [d for d in self.all() if d.owner_agent == owner_agent]

    def by_status(self, status: ContractStatus) -> List[ContractDependency]:
        return [d for d in self.all() if d.status is status]

    @property
    def load_bearing(self) -> List[ContractDependency]:
        return [d for d in self.all() if d.is_load_bearing]

    @property
    def provisional(self) -> List[ContractDependency]:
        """Contracts whose shape is not yet agreed. Build defensively against these."""
        return [d for d in self.all() if not d.is_load_bearing]

    # -------------------------------------------------------------- mutations

    def add(self, dependency: ContractDependency) -> ContractDependency:
        if dependency.contract_id in self._deps:
            raise ContractRegistryError(f"contract_id already registered: {dependency.contract_id}")
        self._deps[dependency.contract_id] = dependency
        return dependency

    def record_owner_acceptance(
        self,
        contract_id: str,
        *,
        accepted_by: str,
        acceptance_reference: str,
        now: Optional[str] = None,
    ) -> ContractDependency:
        """
        Record that the contract owner accepted the proposal.

        Requires an attributable actor and a real reference (issue, PR comment,
        decision record). Placeholder values are rejected, which is what keeps
        `accepted` from becoming a self-declared state.
        """
        dep = self._deps.get(contract_id)
        if dep is None:
            raise ContractRegistryError(f"Unknown contract_id: {contract_id}")

        actor = " ".join((accepted_by or "").split())
        if actor.lower() in _PLACEHOLDER_TOKENS:
            raise OwnerAcceptanceError("accepted_by must be a specific, attributable owner")

        ref = " ".join((acceptance_reference or "").split())
        if ref.lower() in _PLACEHOLDER_TOKENS:
            raise OwnerAcceptanceError(
                "acceptance_reference must point at a real decision record "
                "(issue, PR comment, or decision document)"
            )

        updated = dep.model_copy(update={
            "status": ContractStatus.ACCEPTED,
            "owner_acceptance_reference": ref,
            "accepted_by": actor,
            "accepted_at": now or utcnow_iso(),
        })
        self._deps[contract_id] = updated
        return updated

    def mark_superseded(self, contract_id: str, *, replaced_by: str) -> ContractDependency:
        dep = self._deps.get(contract_id)
        if dep is None:
            raise ContractRegistryError(f"Unknown contract_id: {contract_id}")
        if not replaced_by or replaced_by.strip().lower() in _PLACEHOLDER_TOKENS:
            raise ContractRegistryError("replaced_by must identify the successor contract")
        updated = dep.model_copy(update={
            "status": ContractStatus.SUPERSEDED,
            "notes": f"superseded by {replaced_by}",
        })
        self._deps[contract_id] = updated
        return updated

    def assert_load_bearing(self, contract_id: str) -> ContractDependency:
        """
        Gate for code that must not run against an unagreed contract.

        Raises :class:`ContractNotAcceptedError` while the contract is still a
        proposal, which makes the "not accepted yet" state impossible to ignore.
        """
        dep = self._deps.get(contract_id)
        if dep is None:
            raise ContractRegistryError(f"Unknown contract_id: {contract_id}")
        if not dep.is_load_bearing:
            raise ContractNotAcceptedError(
                f"Contract '{contract_id}' is {dep.status.value}, not accepted by "
                f"{dep.owner_agent}. Source: {dep.source_branch}@{dep.source_commit[:12]} "
                f"{dep.source_document}. Do not treat its shape as load-bearing."
            )
        return dep

    # ---------------------------------------------------------------- reports

    def summary(self) -> Dict[str, Any]:
        by_status: Dict[str, int] = {s.value: 0 for s in ContractStatus}
        for dep in self.all():
            by_status[dep.status.value] += 1
        return {
            "generated_at": utcnow_iso(),
            "total_dependencies": len(self._deps),
            "by_status": by_status,
            "load_bearing_count": len(self.load_bearing),
            "provisional_count": len(self.provisional),
            "statement": (
                "Every dependency is pinned to the exact commit it was read from. "
                "Nothing is load-bearing until its owner records acceptance."
            ),
            "dependencies": [d.model_dump(mode="json") for d in self.all()],
        }


# ============================================================================
# Seeded registry — exactly what Agent 6 read, pinned to real commits
# ============================================================================

AGENT1_COORDINATION_COMMIT = "2c6af207a08955b9990ea9d89af8fd60fed3bc91"
AGENT1_COORDINATION_BRANCH = "arena/961971ed-cicc"
AGENT1_COORDINATION_DOC = "docs/INTEGRATION_CONTRACTS.md"
AGENT1_COORDINATION_VERSION = "Contract v1.0 (M11-02)"
AGENT1_COORDINATION_PR = "oldman-088/cicc#4"

AGENT3_VULN_INTEL_COMMIT = "84fca769f78c1ebede13a22529719f0735cf1afc"
AGENT3_VULN_INTEL_BRANCH = "arena/fa0df787-cicc"
AGENT3_VULN_INTEL_DOC = "docs/vulnerability-intelligence/INTEGRATION_READINESS.md"
AGENT3_VULN_INTEL_VERSION = "verification 2026-11-05 @ 5e91ff6 (1160 tests)"
AGENT3_VULN_INTEL_PR = "oldman-088/cicc#1"

AGENT2_THREAT_INTEL_COMMIT = "1a46f704bc09207d2755fbfd5a7e8ae48b646e1b"
AGENT2_THREAT_INTEL_BRANCH = "arena/93315d2c-cicc"
AGENT2_THREAT_INTEL_PR = "oldman-088/cicc#3"

_READ_AT = "2026-11-05T00:00:00.000Z"


def default_registry() -> ContractRegistry:
    """
    The contracts Threat Intelligence actually depends on, as Agent 6 read them.

    All entries are `proposed`. Source commits were resolved with
    `git ls-remote origin refs/heads/<branch>` and the documents were read with
    `git show <branch>:<path>`; neither branch was modified.
    """
    return ContractRegistry([
        ContractDependency(
            contract_id="agent1-coordination-v1",
            owner_agent="Agent 1",
            title="Central Coordination & System Health — Coordination Contract v1.0 (25 endpoints)",
            contract_version=AGENT1_COORDINATION_VERSION,
            source_branch=AGENT1_COORDINATION_BRANCH,
            source_commit=AGENT1_COORDINATION_COMMIT,
            source_document=AGENT1_COORDINATION_DOC,
            source_pull_request=AGENT1_COORDINATION_PR,
            read_at=_READ_AT,
            local_implementation="apps/threat_intelligence/integration_contracts.py",
            notes=(
                "Agent registration, heartbeat, deregister, task submit/route/deliver/"
                "ack/start/progress/complete/fail, approvals, audit, DAG, metrics, sweep, "
                "GitHub webhook and live sync, routing rules. Our side implements the "
                "register/heartbeat/task-enqueue payloads only."
            ),
        ),
        ContractDependency(
            contract_id="agent1-ops-worker-heartbeat",
            owner_agent="Agent 1",
            title="Ops worker heartbeat (Issue #5)",
            contract_version="Issue #5 worker heartbeat",
            source_branch=AGENT1_COORDINATION_BRANCH,
            source_commit=AGENT1_COORDINATION_COMMIT,
            source_document="GitHub Issue #5",
            read_at=_READ_AT,
            local_implementation="apps/threat_intelligence/integration_contracts.py",
            notes=">=30s cadence, 120s stall threshold (4 missed beats).",
        ),
        ContractDependency(
            contract_id="agent3-vuln-intel-m1-m6",
            owner_agent="Agent 3",
            title="Vulnerability Intelligence mismatches M1-M6",
            contract_version=AGENT3_VULN_INTEL_VERSION,
            source_branch=AGENT3_VULN_INTEL_BRANCH,
            source_commit=AGENT3_VULN_INTEL_COMMIT,
            source_document=AGENT3_VULN_INTEL_DOC,
            source_pull_request=AGENT3_VULN_INTEL_PR,
            read_at=_READ_AT,
            local_implementation="apps/threat_intelligence/integration_contracts.py",
            notes=(
                "M1 KEV requiredAction (Agent 3 marks this BLOCKED pending an owner "
                "decision on KEV-layer-only vs shared record); M2 vendor advisories are "
                "not CVE aliases (BLOCKED — no upstream source in Agent 3); M3 mapping_type "
                "has four CTID values and the rollup counts exploitation only; M4 rollup key "
                "is the full identifier including sub-technique suffix; M5 sources is the "
                "deduplicated set while provenance is append-only history; M6 consulted is "
                "three-valued and must sit next to every technique count."
            ),
        ),
        ContractDependency(
            contract_id="agent3-storage-port",
            owner_agent="Agent 3",
            title="Vulnerability Intelligence storage port (host implements the SQL adapter)",
            contract_version="proposed storage port",
            source_branch=AGENT3_VULN_INTEL_BRANCH,
            source_commit=AGENT3_VULN_INTEL_COMMIT,
            source_document="docs/vulnerability-intelligence/INTEGRATION_CONTRACTS.md",
            source_pull_request=AGENT3_VULN_INTEL_PR,
            read_at=_READ_AT,
            local_implementation="apps/threat_intelligence/persistence.py",
            notes=(
                "Agent 3 states explicitly: 'the subsystem defines the storage port; the "
                "host implements it' and 'a SQL adapter needs an approved migration and "
                "lives in the host'. Our SQLite repository is a self-contained Threat "
                "Intelligence store and is NOT offered as the host SQL adapter."
            ),
        ),
        ContractDependency(
            contract_id="agent2-threat-intel-ownership",
            owner_agent="Agent 2",
            title="Threat Intelligence domain ownership and recovered module baseline",
            contract_version="PR #3 head 1a46f70",
            source_branch=AGENT2_THREAT_INTEL_BRANCH,
            source_commit=AGENT2_THREAT_INTEL_COMMIT,
            source_document="PROJECT_STATE.json, apps/threat_intelligence/*",
            source_pull_request=AGENT2_THREAT_INTEL_PR,
            read_at=_READ_AT,
            local_implementation="apps/threat_intelligence/*",
            notes=(
                "Agent 2 is the primary owner of this domain. Agent 6 recovered orphaned "
                "commits 933b29f and 805cd2b alongside 1a46f70 under explicit user "
                "authorization, on a separate branch, and has not modified Agent 2's branch."
            ),
        ),
    ])
