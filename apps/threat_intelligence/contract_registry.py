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
from typing import Any, Dict, List, Optional, Tuple

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
    """
    Contract adoption lifecycle.

    The first six are an ordered ladder; a contract may only advance one step at a time and
    each step demands its own evidence. The last two are terminal and sit off the ladder.

        PROPOSED -> ACCEPTED -> IMPLEMENTED -> MOUNTED -> EXECUTED -> VERIFIED

    Why the ladder is explicit rather than a free-form status string: "we wrote code that
    matches a proposed shape" and "the other side confirmed it works against a running host"
    are very different claims, and collapsing them is how an integration ends up believed but
    untested. Keeping them separate makes the gap between them visible.
    """

    PROPOSED = "proposed"          # read from an unmerged branch; not agreed
    ACCEPTED = "accepted"          # owner accepted in writing, reference recorded
    IMPLEMENTED = "implemented"    # our side is written and tested against the accepted shape
    MOUNTED = "mounted"            # a host has actually mounted the endpoint (host-attested)
    EXECUTED = "executed"          # a real request/response has been observed
    VERIFIED = "verified"          # the owner verified the executed behaviour
    SUPERSEDED = "superseded"      # replaced by a later version
    REJECTED = "rejected"          # owner declined; do not build on it


#: The adoption ladder, in order. Terminal states are deliberately absent.
LIFECYCLE_ORDER: Tuple["ContractStatus", ...] = (
    ContractStatus.PROPOSED,
    ContractStatus.ACCEPTED,
    ContractStatus.IMPLEMENTED,
    ContractStatus.MOUNTED,
    ContractStatus.EXECUTED,
    ContractStatus.VERIFIED,
)

#: Terminal states: a contract here cannot advance, only be replaced.
TERMINAL_STATUSES = frozenset({ContractStatus.SUPERSEDED, ContractStatus.REJECTED})

#: Identity of this package. Used to stop it attesting to things only a host can observe.
LOCAL_PACKAGE_IDENTITY = "Agent 6 (Threat Intelligence backup)"


class ContractRegistryError(Exception):
    """Base error for the contract registry."""


class ContractNotAcceptedError(ContractRegistryError):
    """A caller tried to treat a proposed contract as load-bearing."""


class OwnerAcceptanceError(ContractRegistryError):
    """An acceptance was recorded without an attributable decision reference."""


class ContractLifecycleError(ContractRegistryError):
    """A lifecycle transition was attempted out of order or without its evidence."""


class SelfAttestationError(ContractRegistryError):
    """
    This package tried to attest to something only a host or an owner can observe.

    Mounting, execution and verification all happen outside this package. Letting it record
    them itself would make an unmounted endpoint look mounted, which is precisely the failure
    mode the ladder exists to prevent.
    """


def utcnow_iso() -> str:
    moment = datetime.now(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


class ContractLifecycleEntry(BaseModel):
    """
    One recorded step in a contract's adoption.

    Every transition carries the actor who caused it, the evidence that justified it, and the
    contract's source commit at the time — so an adoption history can be audited later instead
    of being inferred from the current status alone.
    """

    model_config = ConfigDict(extra="forbid")

    from_status: ContractStatus
    to_status: ContractStatus
    actor: str = Field(..., min_length=1, description="Who caused the transition")
    evidence_reference: str = Field(
        ..., min_length=1,
        description="Where the justification lives: issue, PR comment, test run, request log",
    )
    source_commit: str = Field(..., description="Contract source commit at the time of the step")
    recorded_at: str = Field(..., description="When the step was recorded")
    note: Optional[str] = Field(None, max_length=2000)

    @field_validator("actor", "evidence_reference")
    @classmethod
    def _not_a_placeholder(cls, v: str) -> str:
        cleaned = " ".join(v.split())
        if cleaned.lower() in _PLACEHOLDER_TOKENS:
            raise ValueError("lifecycle actor and evidence must be specific and attributable")
        return cleaned


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

    # -- lifecycle beyond acceptance --------------------------------------
    # Each rung past ACCEPTED carries its own evidence field, so a reader can see exactly how
    # far a contract got and what justified each step, rather than reading one status word and
    # guessing.
    implementation_reference: Optional[str] = Field(
        None, description="Test run or module proving our side matches the accepted shape"
    )
    mounted_by: Optional[str] = Field(
        None, description="The host that mounted the endpoint. Never this package."
    )
    mount_evidence: Optional[str] = Field(
        None, description="Where the mount is observable: host config, route table, deployment ref"
    )
    execution_evidence: Optional[str] = Field(
        None, description="A real request/response record against the mounted endpoint"
    )
    verified_by: Optional[str] = Field(
        None, description="The owner who verified the executed behaviour"
    )
    verification_evidence: Optional[str] = Field(
        None, description="The owner's verification record"
    )
    lifecycle: List[ContractLifecycleEntry] = Field(
        default_factory=list,
        description="Append-only history of every transition, oldest first",
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
        """
        Derived: only a contract that reached ACCEPTED (and stayed on the ladder) may be
        treated as load-bearing.
        """
        return self.status in LIFECYCLE_ORDER[1:] and bool(self.owner_acceptance_reference)

    @property
    def is_terminal(self) -> bool:
        """A superseded or rejected contract cannot advance, only be replaced."""
        return self.status in TERMINAL_STATUSES

    @property
    def lifecycle_rung(self) -> int:
        """
        Zero-based position on the adoption ladder, or -1 for a terminal contract.

        Exposed so reports can say "3 of 5" instead of translating a status word.
        """
        try:
            return LIFECYCLE_ORDER.index(self.status)
        except ValueError:
            return -1

    @property
    def next_status(self) -> Optional[ContractStatus]:
        """The next rung, or None if the contract is terminal or fully verified."""
        rung = self.lifecycle_rung
        if rung < 0 or rung >= len(LIFECYCLE_ORDER) - 1:
            return None
        return LIFECYCLE_ORDER[rung + 1]


def _normalise_actor(value: str) -> str:
    """Lowercase and collapse whitespace so 'Agent 1' and 'agent  1' compare equal."""
    return " ".join((value or "").split()).lower()


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

        # Acceptance belongs to the contract's owner. Without this check any party - including
        # this package - could accept someone else's contract on their behalf and flip it
        # load-bearing, which is exactly the unilateral acceptance we are forbidden from doing.
        if not self._actor_matches_owner(actor, dep.owner_agent):
            raise OwnerAcceptanceError(
                f"contract '{contract_id}' is owned by {dep.owner_agent}; '{actor}' cannot accept "
                "it on their behalf. Acceptance must be recorded by the owner (or by a delegate "
                "the owner named in the acceptance reference)."
            )

        ref = " ".join((acceptance_reference or "").split())
        if ref.lower() in _PLACEHOLDER_TOKENS:
            raise OwnerAcceptanceError(
                "acceptance_reference must point at a real decision record "
                "(issue, PR comment, or decision document)"
            )

        # A rejected or superseded contract is terminal. Without this guard, recording an
        # acceptance silently resurrects it and flips it straight to load-bearing - an owner's
        # "no" would become a "yes" as a side effect of a bookkeeping call.
        if dep.is_terminal:
            raise ContractLifecycleError(
                f"contract '{contract_id}' is {dep.status.value} and cannot be accepted; "
                "register a new contract version instead"
            )
        # Acceptance is rung 0 -> 1. Re-accepting a contract already past PROPOSED would walk it
        # backwards and silently discard the later rungs it had earned.
        if dep.status is not ContractStatus.PROPOSED:
            raise ContractLifecycleError(
                f"contract '{contract_id}' is already at {dep.status.value}; acceptance applies "
                "only to a proposed contract"
            )

        stamp = now or utcnow_iso()
        entry = ContractLifecycleEntry(
            from_status=ContractStatus.PROPOSED,
            to_status=ContractStatus.ACCEPTED,
            actor=actor,
            evidence_reference=ref,
            source_commit=dep.source_commit,
            recorded_at=stamp,
        )
        updated = dep.model_copy(update={
            "status": ContractStatus.ACCEPTED,
            "owner_acceptance_reference": ref,
            "accepted_by": actor,
            "accepted_at": stamp,
            "load_bearing": True,
            "lifecycle": list(dep.lifecycle) + [entry],
        })
        self._deps[contract_id] = updated
        return updated

    # --------------------------------------------------------- lifecycle steps

    @staticmethod
    def _actor_matches_owner(actor: str, owner_agent: str) -> bool:
        """
        True when `actor` is the contract owner, optionally with a qualifier attached.

        'Agent 1' and 'Agent 1 (Central Coordination)' both speak for Agent 1; 'Agent 6' does
        not. Prefix matching on the whole owner name keeps a delegate's label working while
        still refusing a different party.
        """
        a = _normalise_actor(actor)
        o = _normalise_actor(owner_agent)
        if not a or not o:
            return False
        if a == o:
            return True
        return a.startswith(o) and a[len(o):len(o) + 1] in (" ", "(", "-", ":")

    def _require(self, contract_id: str) -> ContractDependency:
        dep = self._deps.get(contract_id)
        if dep is None:
            raise ContractRegistryError(f"Unknown contract_id: {contract_id}")
        return dep

    @staticmethod
    def _clean(value: Optional[str], *, what: str) -> str:
        cleaned = " ".join((value or "").split())
        if cleaned.lower() in _PLACEHOLDER_TOKENS:
            raise ContractLifecycleError(f"{what} must be specific and attributable")
        return cleaned

    def _refuse_self_attestation(self, actor: str, *, what: str) -> None:
        """
        Reject this package attesting to a host-side or owner-side fact.

        Mounting, execution and verification all happen somewhere this package cannot see. If
        it could record them itself, MOUNTED would come to mean "we believe a host mounted it",
        and the rung would stop meaning anything.
        """
        cleaned = " ".join((actor or "").split()).lower()
        if cleaned == LOCAL_PACKAGE_IDENTITY.lower() or cleaned.startswith("agent 6"):
            raise SelfAttestationError(
                f"{what} cannot be attested by {LOCAL_PACKAGE_IDENTITY}: this package cannot "
                "observe host mounting, real traffic, or owner verification. The attestation "
                "must come from the host or the contract owner."
            )

    def _advance(
        self,
        contract_id: str,
        *,
        expected_from: ContractStatus,
        to: ContractStatus,
        actor: str,
        evidence: str,
        updates: Dict[str, Any],
        note: Optional[str],
        now: Optional[str],
    ) -> ContractDependency:
        """
        Move a contract exactly one rung forward.

        Enforces the order: skipping a rung would let an unmounted endpoint be reported as
        executed, which is the specific dishonesty this ladder exists to prevent.
        """
        dep = self._require(contract_id)
        if dep.is_terminal:
            raise ContractLifecycleError(
                f"contract '{contract_id}' is {dep.status.value} and cannot advance"
            )
        if dep.status is not expected_from:
            raise ContractLifecycleError(
                f"contract '{contract_id}' is at {dep.status.value}; the next step is "
                f"{dep.next_status.value if dep.next_status else 'none'}, not {to.value}"
            )
        entry = ContractLifecycleEntry(
            from_status=dep.status,
            to_status=to,
            actor=self._clean(actor, what="actor"),
            evidence_reference=self._clean(evidence, what="evidence"),
            source_commit=dep.source_commit,
            recorded_at=now or utcnow_iso(),
            note=note,
        )
        merged = dict(updates)
        merged["status"] = to
        merged["lifecycle"] = list(dep.lifecycle) + [entry]
        updated = dep.model_copy(update=merged)
        self._deps[contract_id] = updated
        return updated

    def record_implementation(
        self,
        contract_id: str,
        *,
        implemented_by: str,
        implementation_reference: str,
        note: Optional[str] = None,
        now: Optional[str] = None,
    ) -> ContractDependency:
        """
        Record that our side is written and tested against the accepted shape.

        Requires prior owner acceptance: implementing against a proposal nobody accepted is how
        a codebase ends up coupled to a shape that never ships.
        """
        return self._advance(
            contract_id,
            expected_from=ContractStatus.ACCEPTED,
            to=ContractStatus.IMPLEMENTED,
            actor=implemented_by,
            evidence=implementation_reference,
            updates={"implementation_reference": self._clean(
                implementation_reference, what="implementation_reference"
            )},
            note=note,
            now=now,
        )

    def record_host_mount(
        self,
        contract_id: str,
        *,
        mounted_by: str,
        mount_evidence: str,
        note: Optional[str] = None,
        now: Optional[str] = None,
    ) -> ContractDependency:
        """
        Record that a host actually mounted the endpoint.

        This package may record the fact but may never assert it: `mounted_by` must be the host,
        and self-attestation is refused. Until a host says so, the honest state stays
        IMPLEMENTED.
        """
        self._refuse_self_attestation(mounted_by, what="host mounting")
        return self._advance(
            contract_id,
            expected_from=ContractStatus.IMPLEMENTED,
            to=ContractStatus.MOUNTED,
            actor=mounted_by,
            evidence=mount_evidence,
            updates={
                "mounted_by": self._clean(mounted_by, what="mounted_by"),
                "mount_evidence": self._clean(mount_evidence, what="mount_evidence"),
            },
            note=note,
            now=now,
        )

    def record_execution(
        self,
        contract_id: str,
        *,
        executed_by: str,
        execution_evidence: str,
        note: Optional[str] = None,
        now: Optional[str] = None,
    ) -> ContractDependency:
        """
        Record that a real request/response was observed against the mounted endpoint.

        Requires MOUNTED first: there is no such thing as executing an endpoint nobody mounted.
        """
        self._refuse_self_attestation(executed_by, what="real execution")
        return self._advance(
            contract_id,
            expected_from=ContractStatus.MOUNTED,
            to=ContractStatus.EXECUTED,
            actor=executed_by,
            evidence=execution_evidence,
            updates={
                "execution_evidence": self._clean(execution_evidence, what="execution_evidence")
            },
            note=note,
            now=now,
        )

    def record_verification(
        self,
        contract_id: str,
        *,
        verified_by: str,
        verification_evidence: str,
        note: Optional[str] = None,
        now: Optional[str] = None,
    ) -> ContractDependency:
        """
        Record that the contract owner verified the executed behaviour.

        Verification is the owner's call, not ours, so self-attestation is refused here too.
        """
        self._refuse_self_attestation(verified_by, what="owner verification")
        return self._advance(
            contract_id,
            expected_from=ContractStatus.EXECUTED,
            to=ContractStatus.VERIFIED,
            actor=verified_by,
            evidence=verification_evidence,
            updates={
                "verified_by": self._clean(verified_by, what="verified_by"),
                "verification_evidence": self._clean(
                    verification_evidence, what="verification_evidence"
                ),
            },
            note=note,
            now=now,
        )

    def mark_rejected(
        self,
        contract_id: str,
        *,
        rejected_by: str,
        rejection_reference: str,
        now: Optional[str] = None,
    ) -> ContractDependency:
        """
        Record that the owner declined the contract.

        Terminal: nothing may be built on a rejected contract, and it cannot be walked back to
        PROPOSED without registering a new version.
        """
        dep = self._require(contract_id)
        if dep.is_terminal:
            raise ContractLifecycleError(
                f"contract '{contract_id}' is already {dep.status.value}"
            )
        cleaned_actor = self._clean(rejected_by, what="rejected_by")
        cleaned_ref = self._clean(rejection_reference, what="rejection_reference")
        entry = ContractLifecycleEntry(
            from_status=dep.status,
            to_status=ContractStatus.REJECTED,
            actor=cleaned_actor,
            evidence_reference=cleaned_ref,
            source_commit=dep.source_commit,
            recorded_at=now or utcnow_iso(),
        )
        updated = dep.model_copy(update={
            "status": ContractStatus.REJECTED,
            "load_bearing": False,
            "lifecycle": list(dep.lifecycle) + [entry],
            "notes": f"rejected by {cleaned_actor}: {cleaned_ref}",
        })
        self._deps[contract_id] = updated
        return updated

    def lifecycle_for(self, contract_id: str) -> List[ContractLifecycleEntry]:
        """The recorded transitions for one contract, oldest first."""
        return list(self._require(contract_id).lifecycle)

    def at_or_beyond(self, status: ContractStatus) -> List[ContractDependency]:
        """Contracts that reached at least this rung of the ladder."""
        if status not in LIFECYCLE_ORDER:
            raise ContractRegistryError(f"{status.value} is not a lifecycle rung")
        index = LIFECYCLE_ORDER.index(status)
        return [d for d in self.all() if d.lifecycle_rung >= index]

    def mark_superseded(
        self,
        contract_id: str,
        *,
        replaced_by: str,
        superseded_by: str = "contract owner",
        now: Optional[str] = None,
    ) -> ContractDependency:
        """
        Record that a later contract version replaces this one.

        Terminal and auditable: a contract that is already rejected or superseded cannot be
        superseded again, and the replacement is written into the lifecycle history so the
        succession can be traced later instead of inferred from a notes string.
        """
        dep = self._require(contract_id)
        if not replaced_by or replaced_by.strip().lower() in _PLACEHOLDER_TOKENS:
            raise ContractRegistryError("replaced_by must identify the successor contract")
        if dep.is_terminal:
            raise ContractLifecycleError(
                f"contract '{contract_id}' is already {dep.status.value} and cannot be "
                "superseded"
            )
        successor = " ".join(replaced_by.split())
        entry = ContractLifecycleEntry(
            from_status=dep.status,
            to_status=ContractStatus.SUPERSEDED,
            actor=self._clean(superseded_by, what="superseded_by"),
            evidence_reference=f"replaced by {successor}",
            source_commit=dep.source_commit,
            recorded_at=now or utcnow_iso(),
            note=f"successor: {successor}",
        )
        updated = dep.model_copy(update={
            "status": ContractStatus.SUPERSEDED,
            "load_bearing": False,
            "lifecycle": list(dep.lifecycle) + [entry],
            "notes": f"superseded by {successor}",
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
            "lifecycle": {
                status.value: len(self.at_or_beyond(status)) for status in LIFECYCLE_ORDER
            },
            "fully_verified_count": len(self.at_or_beyond(ContractStatus.VERIFIED)),
            "terminal_count": sum(1 for d in self.all() if d.is_terminal),
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

# Backup Agent 4 (frontend) reviewed apps/threat_intelligence/integration_contracts.py at this
# exact commit and returned "ACCEPT-IN-PRINCIPLE, NOT YET ACCEPTED" with seven amendments.
AGENT6_FRONTEND_REVIEW_COMMIT = "d523ee054c4c0dd82708138c2d3dabf38752c25d"
AGENT6_FRONTEND_REVIEW_BRANCH = "arena/28e50255-cicc"
AGENT6_FRONTEND_REVIEW_PR = "oldman-088/cicc#6"
AGENT6_FRONTEND_REVIEW_REF = "oldman-088/cicc#6 (issuecomment-6657783177)"

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
            contract_id="backup-agent4-frontend-dto-v1",
            owner_agent="Backup Agent 4",
            title=(
                "Frontend Threat Intelligence DTO contract - seven amendments to "
                "integration_contracts.py"
            ),
            contract_version="frontend review of 1.0.0-proposed",
            source_branch=AGENT6_FRONTEND_REVIEW_BRANCH,
            source_commit=AGENT6_FRONTEND_REVIEW_COMMIT,
            source_document="PR #6 issuecomment-6657783177",
            source_pull_request=AGENT6_FRONTEND_REVIEW_PR,
            read_at=_READ_AT,
            local_implementation="apps/threat_intelligence/integration_contracts.py",
            notes=(
                "Backup Agent 4 reviewed at " + AGENT6_FRONTEND_REVIEW_COMMIT[:8] + " and "
                "returned ACCEPT-IN-PRINCIPLE, NOT YET ACCEPTED. All seven amendments are "
                "implemented in 1.1.0-proposed (typed entity DTOs and closed "
                "ThreatIntelEntityType; tz-aware collected_at; tenant_id removed from both "
                "frontend envelopes; typed error envelope required for 429/503 and forbidden "
                "elsewhere; nullable total_count with next_cursor authoritative; "
                "DataOrigin/VerificationMode/HostMountStatus plus age_seconds and "
                "stale_after_seconds; per-item provenance). Their condition 8 is NOT met: the "
                "contract is still proposed, nothing is mounted, and no mounted endpoint has "
                "been exercised with a real request/response. Held at PROPOSED deliberately - "
                "acceptance is the frontend owner's and Agent 2's to record, not ours."
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
