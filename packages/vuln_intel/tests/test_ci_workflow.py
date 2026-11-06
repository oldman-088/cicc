"""The CI workflow has to be structurally valid, not merely parseable as YAML.

Three pushes in a row failed at **zero seconds** with no jobs and no annotations. The
workflow parsed fine — ``yaml.safe_load`` was happy — but it was invalid *as a workflow*:
a job had lost its ``runs-on`` key, so GitHub rejected the whole file and never queued
anything.

That failure mode is uniquely bad for this branch, because an empty check list reads as
"nothing to report" rather than "the pipeline is broken". A run that fails in four
minutes with a named job tells you where to look; a run that fails in zero seconds with
no jobs at all looks like a flake.

These tests cost milliseconds and close that hole, so validation is not left to the
`yaml` module's opinion of the syntax.
"""

from __future__ import annotations

import pathlib

import pytest

yaml = pytest.importorskip("yaml", reason="pyyaml is a test dependency")

WORKFLOW = pathlib.Path(__file__).resolve().parents[3] / ".github" / "workflows" / "vuln-intel.yml"


@pytest.fixture(scope="module")
def workflow() -> dict:
    assert WORKFLOW.exists(), f"expected the CI workflow at {WORKFLOW}"
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


class TestStructure:
    def test_it_has_a_trigger_and_jobs(self, workflow):
        # YAML 1.1 reads a bare ``on:`` key as the boolean True, so the trigger is
        # reachable under either spelling depending on the loader.
        assert "on" in workflow or True in workflow, "workflow has no trigger"
        assert workflow.get("jobs"), "workflow defines no jobs"

    @pytest.mark.parametrize("job_name", ["test", "oracle", "comparator-oracle-status",
                                          "maven-rubygems-runtime"])
    def test_every_expected_job_exists(self, workflow, job_name):
        assert job_name in workflow["jobs"], f"job {job_name!r} disappeared"

    def test_every_job_declares_a_runner_and_steps(self, workflow):
        """The exact defect that silently disabled CI: a job with no ``runs-on``.

        GitHub rejects the entire workflow in that case, so *every* job disappears and
        the failure looks like nothing ran rather than like something broke.
        """
        problems = []
        for name, job in workflow["jobs"].items():
            if "runs-on" not in job:
                problems.append(f"{name}: no runs-on")
            if not job.get("steps"):
                problems.append(f"{name}: no steps")
        assert not problems, "invalid job definition(s): " + "; ".join(problems)

    def test_every_step_has_exactly_one_action_or_command(self, workflow):
        problems = []
        for name, job in workflow["jobs"].items():
            for index, step in enumerate(job.get("steps", [])):
                has_uses, has_run = "uses" in step, "run" in step
                if not (has_uses or has_run):
                    problems.append(f"{name} step {index}: neither uses nor run")
                if has_uses and has_run:
                    problems.append(f"{name} step {index}: both uses and run")
        assert not problems, "; ".join(problems)


class TestTheOracleJobsSayWhatTheyClaim:
    def test_the_runtime_oracle_is_gating(self, workflow):
        """It was advisory while one question was unresolvable; the condition is met.

        If this ever has to go back to ``continue-on-error``, this test fails and forces
        the reason into the workflow comment rather than letting the flag reappear
        quietly.
        """
        job = workflow["jobs"]["maven-rubygems-runtime"]
        assert job.get("continue-on-error") is not True, (
            "the runtime oracle was made advisory again; record the reason and the "
            "removal condition in the workflow comment, and update B-17"
        )

    def test_the_runtime_oracle_runs_its_differential_step(self, workflow):
        runs = " ".join(
            str(step.get("run", ""))
            for step in workflow["jobs"]["maven-rubygems-runtime"]["steps"]
        )
        assert "test_version_ordering_runtime_oracle.py" in runs
        assert "generate_runtime_vectors.sh" in runs

    def test_the_facts_job_needs_no_runtime(self, workflow):
        """The gating job must not depend on a JVM or Ruby, or it can skip."""
        job = workflow["jobs"]["comparator-oracle-status"]
        text = " ".join(str(step.get("run", "")) for step in job["steps"])
        assert "test_comparator_facts.py" in text
        assert "generate_runtime_vectors.sh" not in text
