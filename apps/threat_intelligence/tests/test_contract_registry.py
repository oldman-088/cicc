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
    EXPERIMENTAL_DEMO_DATA_ONLY,
    ContractDependency,
    ContractNotAcceptedError,
    ContractRegistry,
    ContractRegistryError,
    ContractStatus,
    OwnerAcceptanceError,
    default_registry,
    utcnow_iso,
)

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
        assert len(reg.by_status(ContractStatus.PROPOSED)) == len(reg.all())

    def test_unknown_contract_returns_none(self):
        assert default_registry().get("nope") is None

    def test_summary_reports_every_dimension(self):
        reg = default_registry()
        summary = reg.summary()
        assert summary["total_dependencies"] == 5
        assert summary["by_status"]["proposed"] == 5
        assert summary["load_bearing_count"] == 0
        assert summary["provisional_count"] == 5
        assert len(summary["dependencies"]) == 5
        assert "pinned to the exact commit" in summary["statement"]

    def test_summary_reflects_acceptance(self):
        reg = default_registry()
        reg.record_owner_acceptance(
            "agent1-coordination-v1", accepted_by="Agent 1",
            acceptance_reference="oldman-088/cicc#4 (comment)", now=T0,
        )
        summary = reg.summary()
        assert summary["by_status"]["accepted"] == 1
        assert summary["by_status"]["proposed"] == 4
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
