"""
Unit tests for the cross-agent contract registry.

The invariant under test: a contract read from another agent's unmerged branch
stays `proposed` and cannot become load-bearing without an attributable owner
acceptance reference. There is no way to self-declare acceptance.
"""

import pytest
from pydantic import ValidationError

from apps.threat_intelligence.contract_registry import (
    AGENT1_COORDINATION_BRANCH,
    AGENT1_COORDINATION_COMMIT,
    AGENT1_COORDINATION_DOC,
    AGENT1_COORDINATION_PR,
    AGENT1_COORDINATION_VERSION,
    AGENT3_VULN_INTEL_BRANCH,
    AGENT3_VULN_INTEL_COMMIT,
    AGENT3_VULN_INTEL_DOC,
    AGENT3_VULN_INTEL_PR,
    AGENT6_FRONTEND_REVIEW_COMMIT,
    AGENT6_FRONTEND_REVIEW_PR,
    EXPERIMENTAL_DEMO_DATA_ONLY,
    LIFECYCLE_ORDER,
    LOCAL_PACKAGE_IDENTITY,
    TERMINAL_STATUSES,
    ContractDependency,
    ContractLifecycleEntry,
    ContractLifecycleError,
    ContractNotAcceptedError,
    ContractRegistry,
    ContractRegistryError,
    ContractStatus,
    OwnerAcceptanceError,
    SelfAttestationError,
    default_registry,
    utcnow_iso,
)

A1 = "oldman-088/cicc#4 (issuecomment-987654321)"

T0 = "2026-11-05T12:00:00.000Z"


def _dep(**overrides):
    base = dict(
        contract_id="test-contract",
        owner_agent="Agent 9",
        title="Test contract",
        contract_version="v0.1",
        source_branch="arena/example-cicc",
        source_commit="abc1234567890",
        source_document="docs/TEST.md",
        read_at=T0,
    )
    base.update(overrides)
    return ContractDependency(**base)


class TestPinnedProvenance:
    """Source commits must be real, verifiable git refs."""

    def test_agent1_contract_is_pinned_to_a_real_commit(self):
        reg = default_registry()
        dep = reg.get("agent1-coordination-v1")
        assert dep is not None
        assert dep.source_commit == AGENT1_COORDINATION_COMMIT
        assert len(dep.source_commit) == 40
        assert dep.source_branch == AGENT1_COORDINATION_BRANCH
        assert dep.source_document == AGENT1_COORDINATION_DOC
        assert dep.source_pull_request == AGENT1_COORDINATION_PR
        assert dep.contract_version == AGENT1_COORDINATION_VERSION
        assert dep.owner_agent == "Agent 1"

    def test_agent3_contract_is_pinned_to_a_real_commit(self):
        dep = default_registry().get("agent3-vuln-intel-m1-m6")
        assert dep.source_commit == AGENT3_VULN_INTEL_COMMIT
        assert dep.source_branch == AGENT3_VULN_INTEL_BRANCH
        assert dep.source_document == AGENT3_VULN_INTEL_DOC
        assert dep.source_pull_request == AGENT3_VULN_INTEL_PR

    def test_every_seeded_dependency_has_full_provenance(self):
        for dep in default_registry().all():
            assert len(dep.source_commit) == 40, dep.contract_id
            assert dep.source_branch, dep.contract_id
            assert dep.source_document, dep.contract_id
            assert dep.read_at, dep.contract_id
            assert dep.owner_agent, dep.contract_id
            assert dep.experimental_label == EXPERIMENTAL_DEMO_DATA_ONLY

    def test_source_commits_exist_in_the_repository(self):
        """The pinned SHAs must be resolvable git objects, not invented strings."""
        import subprocess
        reg = default_registry()
        seen = set()
        for dep in reg.all():
            if dep.source_commit in seen:
                continue
            seen.add(dep.source_commit)
            result = subprocess.run(
                ["git", "cat-file", "-t", dep.source_commit],
                capture_output=True, text=True, cwd="/home/user/cicc",
            )
            assert result.returncode == 0, f"{dep.source_commit} is not a git object"
            assert result.stdout.strip() == "commit", f"{dep.source_commit} is not a commit"

    def test_source_branches_exist_on_origin(self):
        import subprocess
        result = subprocess.run(
            ["git", "ls-remote", "--heads", "origin"],
            capture_output=True, text=True, cwd="/home/user/cicc",
        )
        remote_heads = {line.split("refs/heads/")[1] for line in result.stdout.splitlines()
                        if "refs/heads/" in line}
        for branch in (AGENT1_COORDINATION_BRANCH, AGENT3_VULN_INTEL_BRANCH):
            assert branch in remote_heads, f"{branch} is not a real remote branch"

    def test_invalid_commit_sha_is_rejected(self):
        with pytest.raises(ValidationError):
            _dep(source_commit="not-a-sha")
        with pytest.raises(ValidationError):
            _dep(source_commit="abc123")  # too short

    def test_invalid_pr_reference_is_rejected(self):
        with pytest.raises(ValidationError):
            _dep(source_pull_request="pull request 4")
        assert _dep(source_pull_request="oldman-088/cicc#4").source_pull_request == "oldman-088/cicc#4"


class TestProposedByDefault:
    def test_every_seeded_contract_starts_proposed(self):
        reg = default_registry()
        assert reg.by_status(ContractStatus.PROPOSED) == reg.all()
        assert reg.by_status(ContractStatus.ACCEPTED) == []
        assert reg.load_bearing == []
        assert len(reg.provisional) == len(reg.all())

    def test_load_bearing_cannot_be_declared_at_construction(self):
        with pytest.raises(ValidationError) as exc:
            _dep(load_bearing=True)
        assert "record_owner_acceptance" in str(exc.value)

    def test_is_load_bearing_is_derived_not_stored(self):
        dep = _dep()
        assert dep.load_bearing is False
        assert dep.is_load_bearing is False

    def test_assert_load_bearing_blocks_proposed_contracts(self):
        reg = default_registry()
        with pytest.raises(ContractNotAcceptedError) as exc:
            reg.assert_load_bearing("agent1-coordination-v1")
        message = str(exc.value)
        assert "not accepted by Agent 1" in message
        assert AGENT1_COORDINATION_COMMIT[:12] in message
        assert AGENT1_COORDINATION_DOC in message

    def test_assert_load_bearing_rejects_unknown_ids(self):
        with pytest.raises(ContractRegistryError):
            default_registry().assert_load_bearing("nope")


class TestOwnerAcceptance:
    def test_acceptance_requires_an_attributable_owner(self):
        reg = default_registry()
        for bad in ("", "   ", "pending", "TBD", "unknown", "n/a", "none"):
            with pytest.raises(OwnerAcceptanceError):
                reg.record_owner_acceptance(
                    "agent1-coordination-v1",
                    accepted_by=bad,
                    acceptance_reference="oldman-088/cicc#4 (comment 12345)",
                )
        assert reg.get("agent1-coordination-v1").status is ContractStatus.PROPOSED

    def test_acceptance_requires_a_real_reference(self):
        reg = default_registry()
        for bad in ("", "  ", "tbd", "TODO", "placeholder", "none"):
            with pytest.raises(OwnerAcceptanceError):
                reg.record_owner_acceptance(
                    "agent1-coordination-v1",
                    accepted_by="Agent 1",
                    acceptance_reference=bad,
                )
        assert reg.get("agent1-coordination-v1").status is ContractStatus.PROPOSED

    def test_valid_acceptance_flips_status_and_enables_load_bearing(self):
        reg = default_registry()
        dep = reg.record_owner_acceptance(
            "agent1-coordination-v1",
            accepted_by="Agent 1",
            acceptance_reference="oldman-088/cicc#4 (issuecomment-987654321)",
            now=T0,
        )
        assert dep.status is ContractStatus.ACCEPTED
        assert dep.is_load_bearing is True
        assert dep.accepted_at == T0
        assert dep.accepted_by == "Agent 1"
        assert reg.assert_load_bearing("agent1-coordination-v1") is dep
        assert reg.load_bearing == [dep]
        assert len(reg.provisional) == len(reg.all()) - 1

    def test_acceptance_of_one_contract_does_not_affect_others(self):
        reg = default_registry()
        reg.record_owner_acceptance(
            "agent1-coordination-v1", accepted_by="Agent 1",
            acceptance_reference="oldman-088/cicc#4 (comment)", now=T0,
        )
        assert reg.get("agent3-vuln-intel-m1-m6").status is ContractStatus.PROPOSED
        with pytest.raises(ContractNotAcceptedError):
            reg.assert_load_bearing("agent3-vuln-intel-m1-m6")

    def test_acceptance_rejects_unknown_contract(self):
        with pytest.raises(ContractRegistryError):
            default_registry().record_owner_acceptance(
                "nope", accepted_by="Agent 1", acceptance_reference="ref"
            )

    def test_supersede_requires_a_named_successor(self):
        reg = default_registry()
        with pytest.raises(ContractRegistryError):
            reg.mark_superseded("agent1-coordination-v1", replaced_by="tbd")
        dep = reg.mark_superseded("agent1-coordination-v1", replaced_by="agent1-coordination-v2")
        assert dep.status is ContractStatus.SUPERSEDED
        assert not dep.is_load_bearing
        with pytest.raises(ContractNotAcceptedError):
            reg.assert_load_bearing("agent1-coordination-v1")


class TestRegistryOperations:
    def test_duplicate_contract_id_is_rejected(self):
        reg = ContractRegistry([_dep()])
        with pytest.raises(ContractRegistryError):
            reg.add(_dep())

    def test_owner_and_status_filters(self):
        reg = default_registry()
        assert len(reg.by_owner("Agent 1")) == 2
        assert len(reg.by_owner("Agent 3")) == 2
        assert len(reg.by_owner("Agent 2")) == 1
        assert len(reg.by_owner("Backup Agent 4")) == 1
        assert len(reg.by_status(ContractStatus.PROPOSED)) == len(reg.all())

    def test_unknown_contract_returns_none(self):
        assert default_registry().get("nope") is None

    def test_summary_reports_every_dimension(self):
        reg = default_registry()
        summary = reg.summary()
        assert summary["total_dependencies"] == 6
        assert summary["by_status"]["proposed"] == 6
        assert summary["load_bearing_count"] == 0
        assert summary["provisional_count"] == 6
        assert len(summary["dependencies"]) == 6
        assert "pinned to the exact commit" in summary["statement"]

    def test_summary_reflects_acceptance(self):
        reg = default_registry()
        reg.record_owner_acceptance(
            "agent1-coordination-v1", accepted_by="Agent 1",
            acceptance_reference="oldman-088/cicc#4 (comment)", now=T0,
        )
        summary = reg.summary()
        assert summary["by_status"]["accepted"] == 1
        assert summary["by_status"]["proposed"] == 5
        assert summary["load_bearing_count"] == 1

    def test_registry_is_deterministically_ordered(self):
        ids = [d.contract_id for d in default_registry().all()]
        assert ids == sorted(ids)

    def test_utcnow_iso_is_zulu_formatted(self):
        stamp = utcnow_iso()
        assert stamp.endswith("Z")
        assert len(stamp) == 24


class TestAgent3RequirementsPreserved:
    """
    The Agent 3 requirements the task requires us to preserve must be visible
    in the registry record, not just implied by the implementation.
    """

    def test_m1_required_action_is_recorded(self):
        notes = default_registry().get("agent3-vuln-intel-m1-m6").notes
        assert "M1 KEV requiredAction" in notes
        assert "BLOCKED pending an owner decision" in notes

    def test_m2_advisories_are_not_aliases(self):
        notes = default_registry().get("agent3-vuln-intel-m1-m6").notes
        assert "vendor advisories are not CVE aliases" in notes

    def test_m3_exploitation_only_rollup_is_recorded(self):
        notes = default_registry().get("agent3-vuln-intel-m1-m6").notes
        assert "rollup counts exploitation only" in notes
        assert "four CTID values" in notes

    def test_m4_full_sub_technique_key_is_recorded(self):
        notes = default_registry().get("agent3-vuln-intel-m1-m6").notes
        assert "full identifier including sub-technique suffix" in notes

    def test_m5_provenance_granularity_is_recorded(self):
        notes = default_registry().get("agent3-vuln-intel-m1-m6").notes
        assert "deduplicated set" in notes
        assert "append-only history" in notes

    def test_m6_tri_state_consulted_is_recorded(self):
        notes = default_registry().get("agent3-vuln-intel-m1-m6").notes
        assert "three-valued" in notes
        assert "next to every technique count" in notes

    def test_storage_port_boundary_is_recorded(self):
        notes = default_registry().get("agent3-storage-port").notes
        assert "host implements it" in notes
        assert "NOT offered as the host SQL adapter" in notes


class TestAgent1SemanticsPreserved:
    def test_heartbeat_cadence_semantics_are_recorded(self):
        dep = default_registry().get("agent1-ops-worker-heartbeat")
        assert ">=30s cadence" in dep.notes
        assert "120s stall threshold" in dep.notes

    def test_coordination_scope_is_recorded(self):
        notes = default_registry().get("agent1-coordination-v1").notes
        for capability in ("registration", "heartbeat", "deregister", "approvals",
                           "audit", "DAG", "metrics", "sweep", "webhook", "routing rules"):
            assert capability.lower() in notes.lower(), capability

    def test_we_claim_only_the_payload_surface(self):
        """We must not claim to implement the coordination service itself."""
        dep = default_registry().get("agent1-coordination-v1")
        assert "register/heartbeat/task-enqueue payloads only" in dep.notes


class TestNoCoordinationIsClaimed:
    def test_no_dependency_is_marked_accepted_in_the_seeded_registry(self):
        reg = default_registry()
        assert all(d.status is ContractStatus.PROPOSED for d in reg.all())
        assert all(d.owner_acceptance_reference is None for d in reg.all())
        assert all(d.accepted_at is None for d in reg.all())


# ==========================================================================
# Contract adoption lifecycle: PROPOSED -> ACCEPTED -> IMPLEMENTED -> MOUNTED
#                              -> EXECUTED -> VERIFIED
# ==========================================================================

HOST = "Host platform team"
REF = "oldman-088/cicc#4 (issuecomment-987654321)"


def _accepted(reg=None, cid="agent1-coordination-v1"):
    """A registry with one contract at ACCEPTED, the precondition for the rest of the ladder."""
    reg = reg or default_registry()
    reg.record_owner_acceptance(cid, accepted_by="Agent 1", acceptance_reference=REF, now=T0)
    return reg


def _walk_to(reg, cid, target):
    """
    Advance a contract to `target` with plausible evidence at each rung.

    Starts from wherever the contract already is, so it is safe to call on a registry that has
    been advanced already.
    """
    steps = {
        ContractStatus.ACCEPTED: lambda: reg.record_owner_acceptance(
            cid, accepted_by="Agent 1", acceptance_reference=REF, now=T0),
        ContractStatus.IMPLEMENTED: lambda: reg.record_implementation(
            cid, implemented_by=LOCAL_PACKAGE_IDENTITY,
            implementation_reference="pytest apps/threat_intelligence/tests -q -> 1289 passed",
            now=T0),
        ContractStatus.MOUNTED: lambda: reg.record_host_mount(
            cid, mounted_by=HOST, mount_evidence="host route table rev 7", now=T0),
        ContractStatus.EXECUTED: lambda: reg.record_execution(
            cid, executed_by=HOST, execution_evidence="request log req_abc123 -> HTTP 200",
            now=T0),
        ContractStatus.VERIFIED: lambda: reg.record_verification(
            cid, verified_by="Agent 1", verification_evidence="oldman-088/cicc#4 (c999)",
            now=T0),
    }
    current = reg.get(cid).lifecycle_rung
    for status in LIFECYCLE_ORDER[current + 1:LIFECYCLE_ORDER.index(target) + 1]:
        steps[status]()
    return reg.get(cid)


class TestLifecycleShape:
    """The ladder itself, and the derived helpers that read it."""

    def test_ladder_is_ordered_and_complete(self):
        assert [s.value for s in LIFECYCLE_ORDER] == [
            "proposed", "accepted", "implemented", "mounted", "executed", "verified",
        ]

    def test_terminal_states_sit_off_the_ladder(self):
        assert TERMINAL_STATUSES == frozenset(
            {ContractStatus.SUPERSEDED, ContractStatus.REJECTED}
        )
        for status in TERMINAL_STATUSES:
            assert status not in LIFECYCLE_ORDER

    def test_rung_and_next_status_track_the_ladder(self):
        dep = _dep()
        assert dep.lifecycle_rung == 0
        assert dep.next_status is ContractStatus.ACCEPTED
        assert dep.is_terminal is False

    def test_verified_contract_has_no_next_status(self):
        dep = _walk_to(default_registry(), "agent1-coordination-v1", ContractStatus.VERIFIED)
        assert dep.lifecycle_rung == 5
        assert dep.next_status is None

    def test_terminal_contract_reports_rung_minus_one(self):
        reg = default_registry()
        reg.mark_rejected(
            "agent3-storage-port", rejected_by="Agent 3",
            rejection_reference="oldman-088/cicc#1 (c555)", now=T0,
        )
        assert reg.get("agent3-storage-port").lifecycle_rung == -1
        assert reg.get("agent3-storage-port").next_status is None

    def test_load_bearing_survives_advancement_past_acceptance(self):
        """A contract that keeps progressing must not silently stop being load-bearing."""
        for target in LIFECYCLE_ORDER[1:]:
            dep = _walk_to(default_registry(), "agent1-coordination-v1", target)
            assert dep.is_load_bearing is True, f"{target.value} lost load-bearing"


class TestLadderOrderIsEnforced:
    """No rung may be skipped: skipping is how an unmounted endpoint gets called executed."""

    @pytest.mark.parametrize("method,kwargs", [
        ("record_implementation", dict(implemented_by="Agent 6", implementation_reference="tests")),
        ("record_host_mount", dict(mounted_by=HOST, mount_evidence="route table")),
        ("record_execution", dict(executed_by=HOST, execution_evidence="request log")),
        ("record_verification", dict(verified_by="Agent 1", verification_evidence="ref")),
    ])
    def test_cannot_advance_straight_from_proposed(self, method, kwargs):
        reg = default_registry()
        with pytest.raises(ContractLifecycleError):
            getattr(reg, method)("agent1-coordination-v1", now=T0, **kwargs)
        assert reg.get("agent1-coordination-v1").status is ContractStatus.PROPOSED

    def test_cannot_skip_from_accepted_to_mounted(self):
        reg = _accepted()
        with pytest.raises(ContractLifecycleError) as exc:
            reg.record_host_mount(
                "agent1-coordination-v1", mounted_by=HOST,
                mount_evidence="route table", now=T0,
            )
        assert "implemented" in str(exc.value)

    def test_cannot_skip_from_mounted_to_verified(self):
        reg = _accepted()
        _walk_to(reg, "agent1-coordination-v1", ContractStatus.MOUNTED)
        with pytest.raises(ContractLifecycleError) as exc:
            reg.record_verification(
                "agent1-coordination-v1", verified_by="Agent 1",
                verification_evidence="ref", now=T0,
            )
        assert "executed" in str(exc.value)

    def test_cannot_execute_an_endpoint_nobody_mounted(self):
        reg = _accepted()
        reg.record_implementation(
            "agent1-coordination-v1", implemented_by=LOCAL_PACKAGE_IDENTITY,
            implementation_reference="tests", now=T0,
        )
        with pytest.raises(ContractLifecycleError):
            reg.record_execution(
                "agent1-coordination-v1", executed_by=HOST,
                execution_evidence="request log", now=T0,
            )

    def test_implementation_requires_prior_owner_acceptance(self):
        """Implementing against an unaccepted proposal must be a recorded decision, not a default."""
        reg = default_registry()
        with pytest.raises(ContractLifecycleError):
            reg.record_implementation(
                "agent3-vuln-intel-m1-m6", implemented_by=LOCAL_PACKAGE_IDENTITY,
                implementation_reference="tests", now=T0,
            )


class TestSelfAttestationIsRefused:
    """
    This package cannot observe host mounting, real traffic, or owner verification.
    It must not be able to record them.
    """

    @pytest.mark.parametrize("actor", [
        "Agent 6",
        "Agent 6 (Threat Intelligence backup)",
        "agent 6 backup",
        "AGENT 6",
    ])
    def test_this_package_cannot_claim_host_mounting(self, actor):
        reg = _accepted()
        reg.record_implementation(
            "agent1-coordination-v1", implemented_by=LOCAL_PACKAGE_IDENTITY,
            implementation_reference="tests", now=T0,
        )
        with pytest.raises(SelfAttestationError) as exc:
            reg.record_host_mount(
                "agent1-coordination-v1", mounted_by=actor,
                mount_evidence="route table", now=T0,
            )
        assert "cannot observe host mounting" in str(exc.value)
        # the contract must not have moved
        assert reg.get("agent1-coordination-v1").status is ContractStatus.IMPLEMENTED

    def test_this_package_cannot_claim_real_execution(self):
        reg = _accepted()
        _walk_to(reg, "agent1-coordination-v1", ContractStatus.MOUNTED)
        with pytest.raises(SelfAttestationError):
            reg.record_execution(
                "agent1-coordination-v1", executed_by="Agent 6",
                execution_evidence="request log", now=T0,
            )

    def test_this_package_cannot_claim_owner_verification(self):
        reg = _accepted()
        _walk_to(reg, "agent1-coordination-v1", ContractStatus.EXECUTED)
        with pytest.raises(SelfAttestationError):
            reg.record_verification(
                "agent1-coordination-v1", verified_by=LOCAL_PACKAGE_IDENTITY,
                verification_evidence="ref", now=T0,
            )

    def test_implementation_is_the_one_rung_this_package_may_self_record(self):
        """Our own code is the one thing we can honestly attest to."""
        reg = _accepted()
        dep = reg.record_implementation(
            "agent1-coordination-v1", implemented_by=LOCAL_PACKAGE_IDENTITY,
            implementation_reference="pytest -> 1289 passed", now=T0,
        )
        assert dep.status is ContractStatus.IMPLEMENTED

    def test_a_host_may_attest_to_mounting(self):
        reg = _accepted()
        reg.record_implementation(
            "agent1-coordination-v1", implemented_by=LOCAL_PACKAGE_IDENTITY,
            implementation_reference="tests", now=T0,
        )
        dep = reg.record_host_mount(
            "agent1-coordination-v1", mounted_by=HOST,
            mount_evidence="host route table rev 7", now=T0,
        )
        assert dep.status is ContractStatus.MOUNTED
        assert dep.mounted_by == HOST
        assert dep.mount_evidence == "host route table rev 7"


class TestFullHappyPath:
    """The whole ladder, walked in order, with evidence retained at every rung."""

    def test_proposed_through_to_verified(self):
        reg = default_registry()
        cid = "agent1-coordination-v1"
        assert reg.get(cid).status is ContractStatus.PROPOSED

        _walk_to(reg, cid, ContractStatus.VERIFIED)
        dep = reg.get(cid)

        assert dep.status is ContractStatus.VERIFIED
        assert dep.is_load_bearing is True
        assert dep.is_terminal is False
        assert dep.accepted_by == "Agent 1"
        assert dep.mounted_by == HOST
        assert dep.verified_by == "Agent 1"
        assert dep.execution_evidence == "request log req_abc123 -> HTTP 200"
        assert dep.verification_evidence == "oldman-088/cicc#4 (c999)"

    def test_every_transition_is_recorded_in_order(self):
        reg = default_registry()
        _walk_to(reg, "agent1-coordination-v1", ContractStatus.VERIFIED)
        history = reg.lifecycle_for("agent1-coordination-v1")
        assert [(e.from_status, e.to_status) for e in history] == [
            (ContractStatus.PROPOSED, ContractStatus.ACCEPTED),
            (ContractStatus.ACCEPTED, ContractStatus.IMPLEMENTED),
            (ContractStatus.IMPLEMENTED, ContractStatus.MOUNTED),
            (ContractStatus.MOUNTED, ContractStatus.EXECUTED),
            (ContractStatus.EXECUTED, ContractStatus.VERIFIED),
        ]

    def test_each_entry_pins_the_source_commit_it_applied_to(self):
        """Evidence for a step is only meaningful against the contract text it judged."""
        reg = default_registry()
        _walk_to(reg, "agent1-coordination-v1", ContractStatus.VERIFIED)
        pinned = reg.get("agent1-coordination-v1").source_commit
        for entry in reg.lifecycle_for("agent1-coordination-v1"):
            assert entry.source_commit == pinned

    def test_every_entry_carries_evidence_and_actor(self):
        reg = default_registry()
        _walk_to(reg, "agent1-coordination-v1", ContractStatus.VERIFIED)
        for entry in reg.lifecycle_for("agent1-coordination-v1"):
            assert entry.actor.strip()
            assert entry.evidence_reference.strip()
            assert entry.recorded_at == T0

    def test_lifecycle_history_is_append_only(self):
        reg = default_registry()
        _walk_to(reg, "agent1-coordination-v1", ContractStatus.IMPLEMENTED)
        before = reg.lifecycle_for("agent1-coordination-v1")
        reg.record_host_mount(
            "agent1-coordination-v1", mounted_by=HOST,
            mount_evidence="route table", now=T0,
        )
        after = reg.lifecycle_for("agent1-coordination-v1")
        assert after[:len(before)] == before
        assert len(after) == len(before) + 1

    def test_lifecycle_for_unknown_contract_raises(self):
        with pytest.raises(ContractRegistryError):
            default_registry().lifecycle_for("nope")

    def test_advancing_one_contract_leaves_the_others_alone(self):
        reg = _accepted()
        _walk_to(reg, "agent1-coordination-v1", ContractStatus.VERIFIED)
        for other in reg.all():
            if other.contract_id != "agent1-coordination-v1":
                assert other.status is ContractStatus.PROPOSED
                assert other.lifecycle == []


class TestTerminalStatesAreTerminal:
    """Rejection and supersession must survive every later attempt to move the contract."""

    def test_rejected_contract_cannot_be_accepted(self):
        """Regression: acceptance used to silently resurrect a rejected contract."""
        reg = default_registry()
        reg.mark_rejected(
            "agent3-storage-port", rejected_by="Agent 3",
            rejection_reference="oldman-088/cicc#1 (c555)", now=T0,
        )
        with pytest.raises(ContractLifecycleError) as exc:
            reg.record_owner_acceptance(
                "agent3-storage-port", accepted_by="Agent 3",
                acceptance_reference="oldman-088/cicc#1 (c777)", now=T0,
            )
        assert "cannot be accepted" in str(exc.value)
        dep = reg.get("agent3-storage-port")
        assert dep.status is ContractStatus.REJECTED
        assert dep.is_load_bearing is False

    def test_superseded_contract_cannot_be_accepted(self):
        """Regression: acceptance used to silently resurrect a superseded contract."""
        reg = default_registry()
        reg.mark_superseded(
            "agent3-vuln-intel-m1-m6", replaced_by="agent3-vuln-intel-m1-m6-v2",
            superseded_by="Agent 3", now=T0,
        )
        with pytest.raises(ContractLifecycleError):
            reg.record_owner_acceptance(
                "agent3-vuln-intel-m1-m6", accepted_by="Agent 3",
                acceptance_reference=REF, now=T0,
            )
        assert reg.get("agent3-vuln-intel-m1-m6").status is ContractStatus.SUPERSEDED

    def test_rejected_contract_cannot_advance_the_ladder(self):
        reg = default_registry()
        reg.mark_rejected(
            "agent3-storage-port", rejected_by="Agent 3",
            rejection_reference="oldman-088/cicc#1 (c555)", now=T0,
        )
        with pytest.raises(ContractLifecycleError):
            reg.record_implementation(
                "agent3-storage-port", implemented_by=LOCAL_PACKAGE_IDENTITY,
                implementation_reference="tests", now=T0,
            )

    def test_a_rejected_contract_cannot_then_be_superseded(self):
        """Regression: supersession used to overwrite rejection."""
        reg = default_registry()
        reg.mark_rejected(
            "agent3-storage-port", rejected_by="Agent 3",
            rejection_reference="oldman-088/cicc#1 (c555)", now=T0,
        )
        with pytest.raises(ContractLifecycleError):
            reg.mark_superseded("agent3-storage-port", replaced_by="whatever-v2")
        assert reg.get("agent3-storage-port").status is ContractStatus.REJECTED

    def test_a_contract_cannot_be_superseded_twice(self):
        reg = default_registry()
        reg.mark_superseded(
            "agent3-vuln-intel-m1-m6", replaced_by="v2", superseded_by="Agent 3", now=T0
        )
        with pytest.raises(ContractLifecycleError):
            reg.mark_superseded(
                "agent3-vuln-intel-m1-m6", replaced_by="v3", superseded_by="Agent 3", now=T0
            )

    def test_a_contract_cannot_be_rejected_twice(self):
        reg = default_registry()
        reg.mark_rejected(
            "agent3-storage-port", rejected_by="Agent 3",
            rejection_reference="oldman-088/cicc#1 (c)", now=T0,
        )
        with pytest.raises(ContractLifecycleError):
            reg.mark_rejected(
                "agent3-storage-port", rejected_by="Agent 3",
                rejection_reference="oldman-088/cicc#1 (c2)", now=T0,
            )

    def test_rejection_drops_load_bearing_even_after_progress(self):
        reg = _accepted()
        _walk_to(reg, "agent1-coordination-v1", ContractStatus.IMPLEMENTED)
        assert reg.get("agent1-coordination-v1").is_load_bearing is True
        reg.mark_rejected(
            "agent1-coordination-v1", rejected_by="Agent 1",
            rejection_reference="oldman-088/cicc#4 (c404)", now=T0,
        )
        assert reg.get("agent1-coordination-v1").is_load_bearing is False
        with pytest.raises(ContractNotAcceptedError):
            reg.assert_load_bearing("agent1-coordination-v1")

    def test_supersession_is_recorded_in_the_history(self):
        """Regression: mark_superseded used to leave the lifecycle history empty."""
        reg = default_registry()
        reg.mark_superseded(
            "agent3-vuln-intel-m1-m6", replaced_by="agent3-vuln-intel-m1-m6-v2",
            superseded_by="Agent 3", now=T0,
        )
        history = reg.lifecycle_for("agent3-vuln-intel-m1-m6")
        assert len(history) == 1
        assert history[0].to_status is ContractStatus.SUPERSEDED
        assert "agent3-vuln-intel-m1-m6-v2" in history[0].note

    def test_superseded_contract_is_not_load_bearing(self):
        reg = _accepted()
        reg.mark_superseded(
            "agent1-coordination-v1", replaced_by="v2", superseded_by="Agent 1", now=T0
        )
        assert reg.get("agent1-coordination-v1").is_load_bearing is False


class TestAcceptanceCannotBeForgedOrRepeated:
    """Acceptance is the gate onto the ladder, so it is the gate that matters most."""

    def test_another_agent_cannot_accept_someone_elses_contract(self):
        """The owner forbade unilateral acceptance; the registry now enforces it."""
        reg = default_registry()
        for actor in ("Agent 6", "Agent 2", "Agent 3", "Backup Agent 4"):
            with pytest.raises(OwnerAcceptanceError) as exc:
                reg.record_owner_acceptance(
                    "agent1-coordination-v1", accepted_by=actor,
                    acceptance_reference=REF, now=T0,
                )
            assert "cannot accept it on their behalf" in str(exc.value)
        assert reg.get("agent1-coordination-v1").status is ContractStatus.PROPOSED

    def test_the_owner_may_accept_with_a_qualifier_in_their_name(self):
        reg = default_registry()
        dep = reg.record_owner_acceptance(
            "agent1-coordination-v1", accepted_by="Agent 1 (Central Coordination)",
            acceptance_reference=REF, now=T0,
        )
        assert dep.status is ContractStatus.ACCEPTED

    def test_owner_matching_is_case_insensitive(self):
        reg = default_registry()
        dep = reg.record_owner_acceptance(
            "agent1-coordination-v1", accepted_by="agent 1",
            acceptance_reference=REF, now=T0,
        )
        assert dep.status is ContractStatus.ACCEPTED

    def test_an_owner_may_accept_their_own_contract(self):
        reg = default_registry()
        dep = reg.record_owner_acceptance(
            "backup-agent4-frontend-dto-v1", accepted_by="Backup Agent 4",
            acceptance_reference="oldman-088/cicc#7 (c1)", now=T0,
        )
        assert dep.status is ContractStatus.ACCEPTED

    def test_a_contract_cannot_be_accepted_twice(self):
        """Regression: re-accepting used to overwrite the acceptance and discard later rungs."""
        reg = _accepted()
        _walk_to(reg, "agent1-coordination-v1", ContractStatus.IMPLEMENTED)
        with pytest.raises(ContractLifecycleError):
            reg.record_owner_acceptance(
                "agent1-coordination-v1", accepted_by="Agent 1",
                acceptance_reference="oldman-088/cicc#4 (c2)", now=T0,
            )
        dep = reg.get("agent1-coordination-v1")
        assert dep.status is ContractStatus.IMPLEMENTED
        assert dep.accepted_at == T0

    @pytest.mark.parametrize("bad", ["", "  ", "tbd", "TODO", "placeholder", "none"])
    def test_every_rung_rejects_placeholder_evidence(self, bad):
        reg = _accepted()
        with pytest.raises(ContractLifecycleError):
            reg.record_implementation(
                "agent1-coordination-v1", implemented_by=LOCAL_PACKAGE_IDENTITY,
                implementation_reference=bad, now=T0,
            )
        assert reg.get("agent1-coordination-v1").status is ContractStatus.ACCEPTED

    @pytest.mark.parametrize("bad", ["", "   ", "unknown", "n/a"])
    def test_every_rung_rejects_placeholder_actor(self, bad):
        reg = _accepted()
        with pytest.raises(ContractLifecycleError):
            reg.record_implementation(
                "agent1-coordination-v1", implemented_by=bad,
                implementation_reference="tests", now=T0,
            )

    def test_lifecycle_entry_model_rejects_placeholders_directly(self):
        with pytest.raises(ValidationError):
            ContractLifecycleEntry(
                from_status=ContractStatus.PROPOSED,
                to_status=ContractStatus.ACCEPTED,
                actor="tbd",
                evidence_reference="somewhere",
                source_commit="abc1234",
                recorded_at=T0,
            )


class TestFrontendContractStaysPending:
    """
    Backup Agent 4's amendments are implemented but not accepted. Their condition 8 requires a
    mounted endpoint exercised with a real request/response; that has not happened.
    """

    CID = "backup-agent4-frontend-dto-v1"

    def test_the_contract_is_registered(self):
        assert default_registry().get(self.CID) is not None

    def test_it_starts_proposed_and_not_load_bearing(self):
        dep = default_registry().get(self.CID)
        assert dep.status is ContractStatus.PROPOSED
        assert dep.is_load_bearing is False
        assert dep.lifecycle == []

    def test_it_is_pinned_to_the_commit_actually_reviewed(self):
        dep = default_registry().get(self.CID)
        assert dep.source_commit == AGENT6_FRONTEND_REVIEW_COMMIT
        assert dep.source_pull_request == AGENT6_FRONTEND_REVIEW_PR

    def test_it_records_that_acceptance_belongs_to_someone_else(self):
        dep = default_registry().get(self.CID)
        assert dep.owner_agent == "Backup Agent 4"
        assert "ACCEPT-IN-PRINCIPLE, NOT YET ACCEPTED" in dep.notes
        assert "condition 8 is NOT met" in dep.notes

    def test_agent6_cannot_accept_it_for_them(self):
        reg = default_registry()
        with pytest.raises(OwnerAcceptanceError):
            reg.record_owner_acceptance(
                self.CID, accepted_by="Agent 6",
                acceptance_reference="oldman-088/cicc#6 (c)", now=T0,
            )

    def test_no_seeded_contract_starts_accepted(self):
        for dep in default_registry().all():
            assert dep.status is ContractStatus.PROPOSED
            assert dep.is_load_bearing is False


class TestLifecycleReporting:
    """at_or_beyond and summary must describe the ladder, not just the endpoints."""

    def test_at_or_beyond_counts_contracts_that_reached_a_rung(self):
        reg = default_registry()
        _walk_to(reg, "agent1-coordination-v1", ContractStatus.VERIFIED)
        # 6 contracts total: every one of them is at least PROPOSED, and the one walked to
        # VERIFIED is still on the ladder so it still counts.
        assert len(reg.at_or_beyond(ContractStatus.PROPOSED)) == 6
        assert len(reg.at_or_beyond(ContractStatus.ACCEPTED)) == 1
        assert len(reg.at_or_beyond(ContractStatus.MOUNTED)) == 1
        assert len(reg.at_or_beyond(ContractStatus.VERIFIED)) == 1

    def test_at_or_beyond_excludes_terminal_contracts(self):
        """A rejected contract is not 'at least proposed' - it is off the ladder."""
        reg = default_registry()
        reg.mark_rejected(
            "agent3-storage-port", rejected_by="Agent 3",
            rejection_reference="oldman-088/cicc#1 (c)", now=T0,
        )
        assert len(reg.at_or_beyond(ContractStatus.PROPOSED)) == 5

    def test_at_or_beyond_rejects_a_non_rung(self):
        with pytest.raises(ContractRegistryError):
            default_registry().at_or_beyond(ContractStatus.REJECTED)

    def test_summary_exposes_the_ladder(self):
        reg = default_registry()
        _walk_to(reg, "agent1-coordination-v1", ContractStatus.VERIFIED)
        summary = reg.summary()
        assert summary["lifecycle"] == {
            "proposed": 6, "accepted": 1, "implemented": 1,
            "mounted": 1, "executed": 1, "verified": 1,
        }
        assert summary["fully_verified_count"] == 1

    def test_summary_counts_terminal_contracts(self):
        reg = default_registry()
        reg.mark_rejected(
            "agent3-storage-port", rejected_by="Agent 3",
            rejection_reference="oldman-088/cicc#1 (c)", now=T0,
        )
        assert reg.summary()["terminal_count"] == 1

    def test_a_fresh_registry_has_verified_nothing(self):
        """The honest baseline: nothing in the seeded registry has been verified by anyone."""
        summary = default_registry().summary()
        assert summary["fully_verified_count"] == 0
        assert summary["lifecycle"]["verified"] == 0
        assert summary["lifecycle"]["mounted"] == 0
        assert summary["load_bearing_count"] == 0
        assert summary["terminal_count"] == 0
